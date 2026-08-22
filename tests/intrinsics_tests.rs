//! Integration tests for the kernel intrinsics:
//! `return`, `try`/`catch`/`finally`, `parallel`, `wasm`, plus the
//! registration-time `script` language check and the reserved-name
//! policy on step type aliases.
//!
//! These exercise the public execution API (`ExecuteActionRequest` via
//! `kernel.execute()`) end-to-end against synthesized manifests,
//! mirroring the pattern in `iteration_tests.rs` / `kernel_tests.rs`.

use std::sync::Arc;

use base64::Engine as _;
use gwead::kernel::types::*;
use gwead::kernel::{Kernel, KernelConfig, KernelError};
use indexmap::IndexMap;
use serde_json::{Value, json};

mod common;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "gwead=debug".into()),
        )
        .with_test_writer()
        .try_init();
}

fn step(id: &str, step_type: &str, params: Value) -> StepDef {
    StepDef::new(id.to_string(), step_type.to_string(), params)
}

/// A top-level `let` step that also names its result as a
/// variable via `store_to_variable`.
fn let_step(id: &str, value: Value, var: &str) -> StepDef {
    {
        let mut m = StepDef::new(id.to_string(), "let".to_string(), json!({ "value": value }));
        m.store_to_variable = Some(var.to_string());
        m
    }
}

fn action(steps: Vec<StepDef>) -> Action {
    Action::new(steps)
}

fn manifest(name: &str, steps: Vec<StepDef>) -> PluginManifest {
    let mut actions = IndexMap::new();
    actions.insert("go".to_string(), action(steps));
    {
        let mut m = PluginManifest::new(name.to_string());
        m.actions = actions;
        m.permissions = vec!["network:egress:*".to_string()];
        m
    }
}

fn boot(plugins: Vec<PluginManifest>) -> Arc<Kernel> {
    init_tracing();
    let mut k = Kernel::boot(common::script_runtime_mock::trusting(
        KernelConfig::default(),
        &["lua"],
    ))
    .expect("kernel boot");
    common::script_runtime_mock::register(&mut k).expect("mock script runtime registers");
    for p in plugins {
        k.register_plugin(p).expect("register");
    }
    k.into_arc()
}

// ---------------------------------------------------------------------------
// `return`
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn return_short_circuits_action_with_value() {
    let kernel = boot(vec![manifest(
        "p",
        vec![
            step("first", "let", json!({ "value": "hi" })),
            step("ret", "return", json!({ "value": { "early": true } })),
            // This step must NOT execute — `return` short-circuits.
            step("never", "let", json!({ "value": "should not run" })),
        ],
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect("ok");

    assert_eq!(result.output, json!({"early": true}));
    assert!(result.step_results.contains_key("first"), "first step ran");
    assert!(
        !result.step_results.contains_key("never"),
        "step after `return` must not run"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn return_value_template_resolves_against_context() {
    let kernel = boot(vec![manifest(
        "p",
        vec![
            let_step("compute", json!("42"), "x"),
            step("ret", "return", json!({ "value": "{{$.vars.x}}" })),
        ],
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect("ok");

    assert_eq!(result.output, json!("42"));
}

#[tokio::test(flavor = "multi_thread")]
async fn return_with_no_value_yields_null_output() {
    let kernel = boot(vec![manifest("p", vec![step("ret", "return", json!({}))])]);
    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect("ok");
    assert_eq!(result.output, Value::Null);
}

// ---------------------------------------------------------------------------
// `try` / `catch` / `finally`
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn try_catch_recovers_from_throw_error() {
    let kernel = boot(vec![manifest(
        "p",
        vec![step(
            "guard",
            "try",
            json!({
                "try": [
                    {"id": "bad", "type": "throw_error", "params": {"code": "E_TEST", "message": "boom"}},
                ],
                "catch": [
                    {"id": "recover", "type": "let", "params": {"value": "recovered"}, "storeToVariable": "x"},
                ],
            }),
        )],
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect("ok");

    assert_eq!(
        result.variables.get("x").cloned(),
        Some(json!("recovered")),
        "catch block executed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn try_finally_runs_after_successful_try() {
    let kernel = boot(vec![manifest(
        "p",
        vec![step(
            "guard",
            "try",
            json!({
                "try": [
                    {"id": "ok", "type": "let", "params": {"value": "1"}, "storeToVariable": "a"},
                ],
                "finally": [
                    {"id": "cleanup", "type": "let", "params": {"value": "2"}, "storeToVariable": "b"},
                ],
            }),
        )],
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect("ok");

    assert_eq!(result.variables.get("a").cloned(), Some(json!("1")));
    assert_eq!(
        result.variables.get("b").cloned(),
        Some(json!("2")),
        "finally ran"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn try_finally_runs_after_catch() {
    let kernel = boot(vec![manifest(
        "p",
        vec![step(
            "guard",
            "try",
            json!({
                "try": [
                    {"id": "bad", "type": "throw_error", "params": {"code": "E_T", "message": "boom"}},
                ],
                "catch": [
                    {"id": "recovered", "type": "let", "params": {"value": "yes"}, "storeToVariable": "did_catch"},
                ],
                "finally": [
                    {"id": "fin", "type": "let", "params": {"value": "yes"}, "storeToVariable": "did_finally"},
                ],
            }),
        )],
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect("ok");

    assert_eq!(
        result.variables.get("did_catch").cloned(),
        Some(json!("yes"))
    );
    assert_eq!(
        result.variables.get("did_finally").cloned(),
        Some(json!("yes"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn try_with_empty_catch_swallows_failure_and_stores_null() {
    // Contract: a `try` with an explicit empty `catch` is the
    // optional-step idiom. The failing try body's failure is
    // swallowed; the outer try step's result is `Null` so downstream
    // `{{$steps.<id>.result}}` resolves to null (not missing).
    let kernel = boot(vec![manifest(
        "p",
        vec![
            step(
                "guard",
                "try",
                json!({
                    "try": [
                        {"id": "bad", "type": "throw_error", "params": {"code": "E_T", "message": "boom"}},
                    ],
                    "catch": []
                }),
            ),
            // A follow-on step uses the swallowed try's result.
            let_step("downstream", json!("{{$steps.guard.result}}"), "g"),
        ],
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect("empty-catch swallows the failure, action succeeds");
    assert_eq!(
        result.step_results.get("guard"),
        Some(&Value::Null),
        "outer try step's result is Null after swallowed failure"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn try_with_empty_catch_clears_plugin_error_marker() {
    // Contract: after a swallowed try body
    // that fired a `throw_error`, the `plugin_error` marker MUST
    // also be cleared on the execution state — otherwise a later
    // unrelated step's failure would be mis-attributed to the
    // swallowed throw's code/message by `step_failure_to_error`.
    let kernel = boot(vec![manifest(
        "p",
        vec![
            step(
                "swallowed_throw",
                "try",
                json!({
                    "try": [
                        {"id": "bad", "type": "throw_error", "params": {"code": "STALE", "message": "should not leak"}},
                    ],
                    "catch": []
                }),
            ),
            // This step fails with an ordinary (non-throw) error —
            // `extract` is not a registered step type here, so dispatch
            // refuses it. step_failure_to_error consults plugin_error
            // first; if the marker leaked, this failure would surface as
            // `KernelError::PluginError { code: "STALE", ... }`.
            step(
                "later_fail",
                "extract",
                json!({ "path": "$.nope", "source": "missing_source" }),
            ),
        ],
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await;
    // If the marker leaked, the error would name code="STALE".
    let err_msg = format!("{:?}", result);
    assert!(
        !err_msg.contains("STALE"),
        "swallowed plugin_error must not leak into later failure: {err_msg}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn try_without_catch_propagates_failure() {
    let kernel = boot(vec![manifest(
        "p",
        vec![step(
            "guard",
            "try",
            json!({
                "try": [
                    {"id": "bad", "type": "throw_error", "params": {"code": "E_T", "message": "boom"}},
                ],
            }),
        )],
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await;
    assert!(result.is_err(), "try without catch must propagate failure");
}

// ---------------------------------------------------------------------------
// `parallel`
// ---------------------------------------------------------------------------
//
// Branch-result aggregation and branch-variable merging are covered by
// `parallel_concurrency_tests.rs`.

#[tokio::test(flavor = "multi_thread")]
async fn parallel_empty_branches_yields_empty_array() {
    let kernel = boot(vec![manifest(
        "p",
        vec![step("fan", "parallel", json!({ "branches": [] }))],
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect("ok");

    assert_eq!(result.step_results.get("fan"), Some(&json!([])));
}

// ---------------------------------------------------------------------------
// `wasm`
// ---------------------------------------------------------------------------

/// Minimal self-contained wasm module with one exported function
/// named `run` of type `() -> ()` whose body is a no-op. Returned as
/// base64-encoded bytes ready to drop into a manifest's
/// `wasm_modules` field.
fn tiny_wasm_run_module_base64() -> String {
    let wat = r#"
        (module
          (func (export "run")
            ;; no-op
          )
        )
    "#;
    let wasm = wat::parse_str(wat).expect("WAT parse");
    base64::engine::general_purpose::STANDARD.encode(&wasm)
}

fn wasm_manifest(
    name: &str,
    modules: IndexMap<String, WasmModuleSpec>,
    steps: Vec<StepDef>,
) -> PluginManifest {
    let mut actions = IndexMap::new();
    actions.insert("go".to_string(), action(steps));
    {
        let mut m = PluginManifest::new(name.to_string());
        m.actions = actions;
        m.wasm_modules = modules;
        m
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn wasm_step_executes_registered_module() {
    let module_b64 = tiny_wasm_run_module_base64();
    let mut modules = IndexMap::new();
    modules.insert(
        "tiny".to_string(),
        WasmModuleSpec::Inline { base64: module_b64 },
    );

    let kernel = boot(vec![wasm_manifest(
        "p",
        modules,
        vec![step("exec", "wasm", json!({ "module": "tiny" }))],
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect("ok");

    // step body returns Null on success.
    assert_eq!(result.step_results.get("exec"), Some(&Value::Null));
}

#[tokio::test(flavor = "multi_thread")]
async fn wasm_step_missing_module_fails() {
    let kernel = boot(vec![wasm_manifest(
        "p",
        IndexMap::new(),
        vec![step("exec", "wasm", json!({ "module": "doesnt_exist" }))],
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await;
    assert!(result.is_err(), "missing module must fail");
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("doesnt_exist"),
        "error should name the missing module: {err_msg}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wasm_step_missing_entry_fn_fails() {
    let module_b64 = tiny_wasm_run_module_base64();
    let mut modules = IndexMap::new();
    modules.insert(
        "tiny".to_string(),
        WasmModuleSpec::Inline { base64: module_b64 },
    );

    let kernel = boot(vec![wasm_manifest(
        "p",
        modules,
        vec![step(
            "exec",
            "wasm",
            json!({ "module": "tiny", "entry": "doesnt_exist" }),
        )],
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await;
    assert!(result.is_err(), "missing entry fn must fail");
}

// ---------------------------------------------------------------------------
// Reserved-name policy + script-language validation
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn step_types_alias_rejects_reserved_intrinsic_names() {
    init_tracing();
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    let mut step_types = IndexMap::new();
    step_types.insert("parallel".to_string(), "go".to_string());
    let m = {
        let mut m = PluginManifest::new("shadow".to_string());
        m.actions = {
            let mut actions = IndexMap::new();
            actions.insert("go".to_string(), action(vec![]));
            actions
        };
        m.step_types = step_types;
        m
    };
    let err = k.register_plugin(m).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("'parallel'") && msg.contains("reserved"),
        "expected reserved-name error mentioning 'parallel': {msg}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn script_with_unsupported_language_rejected_at_register() {
    init_tracing();
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    let m = manifest(
        "p",
        vec![step(
            "code",
            "script",
            json!({ "language": "python", "source": "print('hi')" }),
        )],
    );
    let err = k.register_plugin(m).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("'python'") && msg.contains("no plugin"),
        "expected unsupported-language error: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Manifest fields end-to-end: step_type_defs
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn boot_registers_eleven_intrinsic_step_type_defs() {
    init_tracing();
    let k = Kernel::boot(KernelConfig::default()).expect("boot");
    assert_eq!(
        k.registry().step_type_def_count(),
        11,
        "exactly the 11 kernel intrinsics should be registered at boot"
    );
    for name in [
        "ifs",
        "for_each",
        "repeat",
        "invoke",
        "parallel",
        "return",
        "try",
        "wasm",
        "let",
        "script",
        "throw_error",
    ] {
        let (owner, _def) = k
            .registry()
            .get_step_type_def(name)
            .unwrap_or_else(|| panic!("intrinsic '{name}' missing from registry"));
        assert_eq!(owner, "gwead_intrinsics");
    }
    // `script` is the only intrinsic with a selector — used for
    // language routing.
    let (_, script_def) = k.registry().get_step_type_def("script").unwrap();
    assert_eq!(script_def.selector.as_deref(), Some("language"));
}

#[tokio::test(flavor = "multi_thread")]
async fn manifest_step_type_defs_register_through_register_plugin() {
    init_tracing();
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    let m = {
        let mut m = PluginManifest::new("p".to_string());
        m.step_type_defs = vec![StepTypeDef::new("p.my_custom_step".to_string())];
        m
    };
    k.register_plugin(m).expect("registers");
    let (owner, def) = k
        .registry()
        .get_step_type_def("p.my_custom_step")
        .expect("def present");
    assert_eq!(owner, "p");
    assert_eq!(def.name, "p.my_custom_step");
}

/// Ownership is in the name, so two plugins cannot collide on a step
/// type: `first.shared` and `second.shared` are two step types. What
/// IS still rejected is one plugin declaring the same name twice.
#[tokio::test(flavor = "multi_thread")]
async fn manifest_step_type_defs_are_owner_scoped() {
    init_tracing();
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    let m1 = {
        let mut m = PluginManifest::new("first".to_string());
        m.step_type_defs = vec![StepTypeDef::new("first.shared".to_string())];
        m
    };
    k.register_plugin(m1).expect("first registers");

    let m2 = {
        let mut m = PluginManifest::new("second".to_string());
        m.step_type_defs = vec![StepTypeDef::new("second.shared".to_string())];
        m
    };
    k.register_plugin(m2)
        .expect("second registers its own `second.shared`");

    let m3 = {
        let mut m = PluginManifest::new("third".to_string());
        m.step_type_defs = vec![
            StepTypeDef::new("third.twice".to_string()),
            StepTypeDef::new("third.twice".to_string()),
        ];
        m
    };
    let err = k.register_plugin(m3).unwrap_err();
    assert!(format!("{err}").contains("declared twice"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn step_type_impl_without_def_is_rejected() {
    // impl ⇒ def: a manifest that claims to implement a step type
    // with no declared StepTypeDef (not local, not an intrinsic) is
    // rejected at registration.
    init_tracing();
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    let m: PluginManifest = serde_json::from_value(json!({
        "name": "ghost",
        "stepTypeImpls": [
            {"stepType": "ghost_step", "kind": "native", "implRef": "ghost.impl"}
        ]
    }))
    .expect("manifest parses");
    let err = k.register_plugin(m).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("ghost_step") && msg.contains("StepTypeDef"),
        "missing-def error should name the step type and the contract: {msg}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn metadata_schema_cannot_declare_reserved_result_key() {
    // `result` is the value slot, not a sidecar — a metadataSchema that
    // declares it is rejected at registration.
    init_tracing();
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    let m: PluginManifest = serde_json::from_value(json!({
        "name": "reserver",
        "stepTypeDefs": [{
            "name": "reserver.bad_step",
            "metadataSchema": {
                "type": "object",
                "additionalProperties": false,
                "properties": {"result": {"type": "string"}}
            }
        }]
    }))
    .expect("manifest parses");
    let err = k.register_plugin(m).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("reserved key 'result'") && msg.contains("bad_step"),
        "reserved-result error should name the key and step type: {msg}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn standalone_spi_def_resolvable_by_subsequent_plugin() {
    init_tracing();
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    // SPI definitions register only as standalone documents —
    // top-level `name` is the role identifier; `SpiRegistry::register`
    // keys on it. Once registered, the role becomes lookup-able for
    // downstream plugins that declare `roles: ["MY_TEST_ROLE"]`.
    let spi_def = json!({
        "name": "MY_TEST_ROLE",
        "version": "1.0",
        "actions": {}
    });
    k.register_spi_from_json("MY_TEST_ROLE", &spi_def.to_string())
        .expect("standalone SPI def registers");
    // Confirm the SPI is now resolvable: a follow-up plugin can
    // declare the role without rejection.
    let m = {
        let mut m = PluginManifest::new("consumer".to_string());
        m.roles = vec!["MY_TEST_ROLE".to_string()];
        m
    };
    k.register_plugin(m)
        .expect("consumer plugin should validate against the freshly-registered SPI");
}

#[tokio::test(flavor = "multi_thread")]
async fn script_validator_recurses_into_try_subblocks() {
    init_tracing();
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    // A `script` with an unsupported language nested inside a
    // try.catch body should be caught at register_plugin time, not
    // slip through to a runtime failure.
    let m = manifest(
        "p",
        vec![step(
            "guard",
            "try",
            json!({
                "try":   [],
                "catch": [
                    {"id": "bad_script", "type": "script", "params": {"language": "python", "source": "print('hi')"}},
                ],
            }),
        )],
    );
    let err = k.register_plugin(m).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("'python'") && msg.contains("no plugin"),
        "validator must recurse into try.catch: got {msg}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn script_validator_recurses_into_parallel_branches() {
    init_tracing();
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    let m = manifest(
        "p",
        vec![step(
            "fan",
            "parallel",
            json!({
                "branches": [
                    [ {"id": "ok", "type": "set_var", "params": {"name": "x", "value": "1"}} ],
                    [
                        {"id": "bad", "type": "script", "params": {"language": "ruby", "source": "puts 'hi'"}},
                    ],
                ],
            }),
        )],
    );
    let err = k.register_plugin(m).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("'ruby'") && msg.contains("no plugin"),
        "validator must recurse into parallel branches: got {msg}"
    );
}

// ---------------------------------------------------------------------------
// `throw_error`
// ---------------------------------------------------------------------------

/// The full structured payload — code, message, AND params — survives
/// from the manifest into `KernelError::PluginError`.
/// (`manifest_lifecycle_tests` asserts codes only; the params half is
/// covered here.)
#[tokio::test(flavor = "multi_thread")]
async fn throw_error_produces_structured_kernel_error() {
    let kernel = boot(vec![manifest(
        "p",
        vec![step(
            "boom",
            "throw_error",
            json!({
                "code": "LLM_AUTH_ERROR",
                "message": "API key invalid",
                "params": {"hint": "check config"}
            }),
        )],
    )]);

    let err = kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect_err("throw_error always errors");
    match err {
        KernelError::PluginError {
            code,
            message,
            params,
        } => {
            assert_eq!(code, "LLM_AUTH_ERROR");
            assert_eq!(message, "API key invalid");
            assert_eq!(params, json!({"hint": "check config"}));
        }
        other => panic!("expected PluginError, got: {other:?}"),
    }
}
