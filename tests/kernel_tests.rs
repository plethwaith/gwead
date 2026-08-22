//! Integration tests for the Gwead wasm microkernel.
//!
//! These tests exercise the full pipeline: Kernel::boot → register_plugin →
//! plan the step DAG → execute through the host scheduler (wasm for plugin
//! wasm/script bodies) → verify output.

use gwead::kernel::types::*;
use gwead::kernel::{Kernel, KernelConfig, KernelError};
use indexmap::IndexMap;
use serde_json::{Value, json};

mod common;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "gwead=debug".into()),
        )
        .with_test_writer()
        .try_init();
}

fn boot_kernel() -> Kernel {
    init_tracing();
    let mut kernel = Kernel::boot(common::script_runtime_mock::trusting(
        KernelConfig::default(),
        &["lua"],
    ))
    .expect("kernel should boot");
    // `script` dispatch is registry-driven and
    // the kernel bundles no Lua runtime. The shared test-only mock at
    // `tests/common/script_runtime_mock.rs` registers a minimal wasm
    // module under `(script, "lua")` so tests whose actions include a
    // `script` step get dispatch to succeed without a cross-crate dep
    // on a real language runtime. Tests that exercise real language
    // semantics (running source code, observing interpreter errors, …)
    // belong with the runtime plugin, not here.
    common::script_runtime_mock::register(&mut kernel).expect("mock script runtime registers");
    // Embedder step types (`http_call`, `extract`, `log`, …) live in
    // embedder plugin crates, along with their behaviour tests. The
    // manifests registered here may still NAME such step types
    // (registration doesn't require step impls); no test in this file
    // executes one.
    // Gwead-owned SPI fixture: the kernel_tests plugins that claim
    // METADATA_PROVIDER need the role registered so registration
    // validates. Defined inline — gwead's tests must not reach into an
    // embedder's manifest files; the engine
    // depends on nothing outside itself. Same minimal shape as
    // intrinsics_tests.rs.
    kernel
        .register_spi_from_json(
            "METADATA_PROVIDER",
            r#"{
                "name": "METADATA_PROVIDER",
                "version": "1.0",
                "actions": {
                    "search": { "input": { "type": "object" }, "output": { "type": "array" } },
                    "fetch": { "input": { "type": "object" }, "output": { "type": "object" } }
                }
            }"#,
        )
        .unwrap();
    kernel
}

fn simple_manifest(name: &str, actions: IndexMap<String, Action>) -> PluginManifest {
    manifest_with_roles(name, &[], actions)
}

fn manifest_with_roles(
    name: &str,
    roles: &[&str],
    actions: IndexMap<String, Action>,
) -> PluginManifest {
    {
        let mut m = PluginManifest::new(name.to_string());
        m.roles = roles.iter().map(|s| s.to_string()).collect();
        m.actions = actions;
        m.permissions = vec![
            "network:egress:*".to_string(),
            "blobs:read:*".to_string(),
            "blobs:write:*".to_string(),
            "blobs:delete:*".to_string(),
        ];
        m
    }
}

fn step(id: &str, step_type: &str, params: Value) -> StepDef {
    StepDef::new(id.to_string(), step_type.to_string(), params)
}

fn action(steps: Vec<StepDef>) -> Action {
    Action::new(steps)
}

// ===========================================================================
// Kernel lifecycle tests
// ===========================================================================

#[test]
fn kernel_boots_successfully() {
    let _kernel = boot_kernel();
}

// ===========================================================================
// Plugin registration tests
// ===========================================================================

#[test]
fn register_plugin_with_single_action() {
    let mut kernel = boot_kernel();
    let mut actions = IndexMap::new();
    actions.insert(
        "search".to_string(),
        action(vec![step("s1", "log", json!({"message": "hello"}))]),
    );

    let manifest = simple_manifest("test_plugin", actions);
    kernel
        .register_plugin(manifest)
        .expect("registration should succeed");

    assert!(
        kernel
            .registry()
            .get_action("test_plugin", "search")
            .is_some()
    );
    assert!(
        kernel
            .registry()
            .get_action("test_plugin", "nonexistent")
            .is_none()
    );
}

#[test]
fn register_plugin_with_multiple_actions() {
    let mut kernel = boot_kernel();
    let mut actions = IndexMap::new();
    actions.insert(
        "search".to_string(),
        action(vec![step("s1", "log", json!({"message": "searching"}))]),
    );
    actions.insert(
        "fetch".to_string(),
        action(vec![step("f1", "log", json!({"message": "fetching"}))]),
    );

    let manifest = simple_manifest("multi_action", actions);
    kernel.register_plugin(manifest).unwrap();

    assert!(
        kernel
            .registry()
            .get_action("multi_action", "search")
            .is_some()
    );
    assert!(
        kernel
            .registry()
            .get_action("multi_action", "fetch")
            .is_some()
    );
}

#[test]
fn register_plugin_with_role_dispatch() {
    let mut kernel = boot_kernel();
    let mut actions = IndexMap::new();
    actions.insert(
        "search".to_string(),
        action(vec![step("s1", "log", json!({"message": "s"}))]),
    );
    actions.insert(
        "fetch".to_string(),
        action(vec![step("f1", "log", json!({"message": "f"}))]),
    );

    let manifest = manifest_with_roles("role_test", &["METADATA_PROVIDER"], actions);
    kernel.register_plugin(manifest).unwrap();

    assert_eq!(
        kernel.registry().plugins_for_role("METADATA_PROVIDER"),
        vec!["role_test".to_string()]
    );
    assert!(kernel.registry().plugins_for_role("LLM_CHAT").is_empty());
}

#[test]
fn multiple_plugins_for_same_role() {
    let mut kernel = boot_kernel();

    for name in &["plugin_a", "plugin_b"] {
        let mut actions = IndexMap::new();
        actions.insert(
            "search".to_string(),
            action(vec![step("s1", "log", json!({"message": name}))]),
        );
        actions.insert(
            "fetch".to_string(),
            action(vec![step("f1", "log", json!({"message": name}))]),
        );
        let manifest = manifest_with_roles(name, &["METADATA_PROVIDER"], actions);
        kernel.register_plugin(manifest).unwrap();
    }

    // First registered wins in registration order — the kernel's
    // registry is a catalogue, and the orchestrator (or this test)
    // picks the head of the candidate list.
    let all = kernel.registry().plugins_for_role("METADATA_PROVIDER");
    assert_eq!(all.len(), 2);
    assert_eq!(all[0], "plugin_a");
    assert!(all.contains(&"plugin_b".to_string()));
}

// ===========================================================================
// Error handling
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn execute_nonexistent_plugin_returns_not_found() {
    let kernel = boot_kernel();
    let err = kernel
        .execute("nonexistent", "search", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .unwrap_err();
    assert!(matches!(err, KernelError::NotFound(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_nonexistent_action_returns_not_found() {
    let mut kernel = boot_kernel();
    let mut actions = IndexMap::new();
    actions.insert(
        "search".to_string(),
        action(vec![step("s1", "log", json!({"message": "hi"}))]),
    );
    let manifest = simple_manifest("exists", actions);
    kernel.register_plugin(manifest).unwrap();

    let err = kernel
        .execute("exists", "nonexistent", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .unwrap_err();
    assert!(matches!(err, KernelError::NotFound(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_by_role_missing_role_returns_not_found() {
    let kernel = boot_kernel();
    let err = kernel
        .execute_by_role("NONEXISTENT_ROLE", "search", json!({}), &json!({}))
        .await
        .unwrap_err();
    assert!(matches!(err, KernelError::NotFound(_)));
}

// ===========================================================================
// DAG scheduling tests
// ===========================================================================

/// Diamond DAG: source → branch_a, source → branch_b, [a, b] → sink.
///
/// Verifies the DAG planner produces three waves (the source, the two
/// parallel branches, the sink) and that the sink sees both branch
/// results merged into its result_mapping. With `parallelWaves` off
/// (the default) the scheduler runs the middle wave's branches
/// sequentially, but the structural DAG behaviour — fan-out reads +
/// join at sink — is what this test pins.
///
/// Built on the kernel's `let` intrinsic so this pure-kernel DAG test
/// stays kernel-only. The source value 42 is a JSON number under
/// `let`, but every assertion reads concatenating templates, which
/// stringify it.
#[tokio::test(flavor = "multi_thread")]
async fn diamond_dag_two_branches_join_at_sink() {
    let mut kernel = boot_kernel();
    let mut actions = IndexMap::new();
    actions.insert(
        "diamond".to_string(),
        Action::new(vec![
            step("source", "let", json!({"value": 42})),
            step(
                "branch_a",
                "let",
                json!({"value": "{{$steps.source.result}}-A"}),
            ),
            step(
                "branch_b",
                "let",
                json!({"value": "{{$steps.source.result}}-B"}),
            ),
            step(
                "sink",
                "let",
                json!({
                    "value": "{{$steps.branch_a.result}}+{{$steps.branch_b.result}}"
                }),
            ),
        ]),
    );

    let manifest = simple_manifest("diamond_plugin", actions);
    kernel.register_plugin(manifest).expect("registration");

    let result = kernel
        .execute("diamond_plugin", "diamond", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution");

    assert_eq!(result.step_results["branch_a"], json!("42-A"));
    assert_eq!(result.step_results["branch_b"], json!("42-B"));
    assert_eq!(result.step_results["sink"], json!("42-A+42-B"));
}

// ===========================================================================
// Registry introspection tests
// ===========================================================================

#[test]
fn registry_lists_plugin_names() {
    let mut kernel = boot_kernel();

    for name in &["alpha", "beta", "gamma"] {
        let mut actions = IndexMap::new();
        actions.insert(
            "do_thing".to_string(),
            action(vec![step("s", "log", json!({"message": "hi"}))]),
        );
        kernel
            .register_plugin(simple_manifest(name, actions))
            .unwrap();
    }

    // Filter out kernel-internal plugins (the synthetic
    // `gwead_intrinsics` manifest that ships the 11 intrinsic
    // step-type defs, and the `__test_…__` script-runtime mock from
    // `boot_kernel`) so the assertion can focus on user-registered
    // plugins. The intrinsics deliberately ship behind a plugin
    // manifest of their own.
    let names: Vec<&str> = kernel
        .registry()
        .plugin_names()
        .into_iter()
        .filter(|n| !n.starts_with("__test_") && *n != "gwead_intrinsics")
        .collect();
    assert!(names.contains(&"alpha"));
    assert!(names.contains(&"beta"));
    assert!(names.contains(&"gamma"));
    assert_eq!(names.len(), 3);
}

#[test]
fn registry_lists_action_names() {
    let mut kernel = boot_kernel();
    let mut actions = IndexMap::new();
    actions.insert(
        "search".to_string(),
        action(vec![step("s", "log", json!({"message": "s"}))]),
    );
    actions.insert(
        "fetch".to_string(),
        action(vec![step("f", "log", json!({"message": "f"}))]),
    );

    kernel
        .register_plugin(simple_manifest("multi", actions))
        .unwrap();

    let action_names = kernel.registry().action_names("multi");
    assert_eq!(action_names.len(), 2);
    assert!(action_names.contains(&"search".to_string()));
    assert!(action_names.contains(&"fetch".to_string()));
}

// ===========================================================================
// result_mapping literal recursive resolution
// ===========================================================================
//
// Literal values that are arrays or objects walk recursively via
// `resolve::resolve_value`, so nested template strings inside a literal
// still get resolved — an array of objects with a templated text field
// resolves in place.

#[tokio::test(flavor = "multi_thread")]
async fn result_mapping_literal_array_with_templates_inside() {
    let mut result_mapping = IndexMap::new();
    result_mapping.insert(
        "messages".to_string(),
        json!({
            "literal": [
                {"type": "text", "text": "{{$.greeting}}"},
                {"type": "text", "text": "{{$.farewell}}"}
            ]
        }),
    );
    let action_def = {
        let mut m = Action::new(vec![]);
        m.result_mapping = result_mapping;
        m
    };

    let mut actions = IndexMap::new();
    actions.insert("run".to_string(), action_def);
    let manifest = simple_manifest("literal_array", actions);

    let mut kernel = boot_kernel();
    kernel.register_plugin(manifest).unwrap();

    let result = kernel
        .execute(
            "literal_array",
            "run",
            json!({"greeting": "hello", "farewell": "goodbye"}),
        )
        .with_config(&json!({}))
        .run()
        .await
        .unwrap();

    let messages = result.output.get("messages").unwrap().as_array().unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["type"], json!("text"));
    assert_eq!(messages[0]["text"], json!("hello"));
    assert_eq!(messages[1]["type"], json!("text"));
    assert_eq!(messages[1]["text"], json!("goodbye"));
}

#[tokio::test(flavor = "multi_thread")]
async fn result_mapping_literal_object_preserves_numeric_types() {
    let mut result_mapping = IndexMap::new();
    result_mapping.insert(
        "usage".to_string(),
        json!({
            "literal": {
                "input_tokens": "{{$.in_tok}}",
                "output_tokens": "{{$.out_tok}}"
            }
        }),
    );
    let action_def = {
        let mut m = Action::new(vec![]);
        m.result_mapping = result_mapping;
        m
    };

    let mut actions = IndexMap::new();
    actions.insert("run".to_string(), action_def);
    let manifest = simple_manifest("literal_numeric", actions);

    let mut kernel = boot_kernel();
    kernel.register_plugin(manifest).unwrap();

    let result = kernel
        .execute(
            "literal_numeric",
            "run",
            json!({"in_tok": 123, "out_tok": 456}),
        )
        .with_config(&json!({}))
        .run()
        .await
        .unwrap();

    // Numbers should round-trip as numbers via single-template preservation,
    // not get stringified to "123" / "456".
    let usage = result.output.get("usage").unwrap();
    assert_eq!(usage["input_tokens"], json!(123));
    assert_eq!(usage["output_tokens"], json!(456));
}

// ===========================================================================
// {{$secrets.*}} namespace
// ===========================================================================
//
// Secrets are pulled through `KernelConfig::secret_resolver` as a
// separate namespace from `config`. They resolve in templates exactly
// like config values but live under `{{$secrets.*}}` instead of
// `{{$config.*}}`. On-the-wire resolution/isolation tests belong with
// whichever embedder step type puts secrets on the wire; what lives
// here is the kernel-only default.

#[tokio::test(flavor = "multi_thread")]
async fn execute_action_without_resolver_defaults_to_null_namespace() {
    // A kernel with no resolver registered gives every execution a
    // Value::Null secrets namespace. Plugins that don't reference {{$secrets.*}}
    // work unchanged.
    let mut actions = IndexMap::new();
    let mut rm = IndexMap::new();
    rm.insert("greeting".to_string(), json!({"literal": "hello"}));
    actions.insert("run".to_string(), {
        let mut m = Action::new(vec![]);
        m.result_mapping = rm;
        m
    });
    let manifest = simple_manifest("no_secrets", actions);

    let mut kernel = boot_kernel();
    kernel.register_plugin(manifest).unwrap();

    let result = kernel
        .execute("no_secrets", "run", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .unwrap();

    assert_eq!(result.output["greeting"], json!("hello"));
}

#[test]
fn manifest_metadata_is_carried_opaquely() {
    // App-specific manifest data lives under the namespaced `metadata`
    // map. The kernel must parse, store, and re-serialize it verbatim
    // without interpreting any namespace.
    let mut kernel = boot_kernel();
    kernel
        .register_plugin_from_json(
            r#"{
                "name": "meta_carrier",
                "roles": [],
                "actions": {},
                "metadata": {
                    "acme": {
                        "supportedThingSlugs": ["widget"],
                        "things": [{"slug": "widget", "name": "Widget", "kind": "EXAMPLE"}]
                    },
                    "other_app": {"servers": ["example"]}
                }
            }"#,
        )
        .unwrap();

    let stored = kernel.registry().get_manifest("meta_carrier").unwrap();
    assert_eq!(
        stored.metadata["acme"]["supportedThingSlugs"],
        json!(["widget"])
    );
    assert_eq!(stored.metadata["other_app"]["servers"], json!(["example"]));

    let round_trip = serde_json::to_value(stored).unwrap();
    assert_eq!(
        round_trip["metadata"]["acme"]["things"][0]["slug"],
        json!("widget")
    );
}

/// Every guard in the `kind: "intrinsic"` registration arm rejects
/// its malformed manifest with a distinct, named error. Table-driven so a
/// future reorder/refactor of the checks can't silently drop a branch.
/// The last case is the capability boundary itself — an external manifest
/// can't supply an intrinsic body the engine didn't submit (the
/// manifest-layer backstop to the Rust-side enforcement, where external
/// crates can't name the `IntrinsicStepFn` shape because they can't name
/// `ExecutionState`).
#[test]
fn intrinsic_kind_validation_branches_each_reject_with_named_error() {
    // (label, stepTypeImpls entry, expected error substring)
    let cases = [
        (
            "missing implRef",
            r#"{"stepType": "probe.x", "kind": "intrinsic"}"#,
            "but no `implRef` field",
        ),
        (
            "wasmModule set",
            r#"{"stepType": "probe.x", "kind": "intrinsic", "implRef": "gwead.intrinsics.invoke", "wasmModule": "m"}"#,
            "also sets `wasmModule`",
        ),
        (
            "matches set",
            r#"{"stepType": "probe.x", "kind": "intrinsic", "implRef": "gwead.intrinsics.invoke", "matches": "lua"}"#,
            "with `matches` set",
        ),
        (
            "unresolved implRef",
            r#"{"stepType": "probe.x", "kind": "intrinsic", "implRef": "nope.not_real"}"#,
            "references intrinsic implRef 'nope.not_real'",
        ),
    ];

    for (label, impl_entry, want) in cases {
        let manifest = format!(
            r#"{{
                "name": "probe",
                "roles": [],
                "actions": {{}},
                "stepTypeDefs": [{{"name": "probe.x"}}],
                "stepTypeImpls": [{impl_entry}]
            }}"#
        );

        // The kernel-layer branch itself, driven via the struct entry
        // point (register_plugin), which the meta-schema doesn't guard.
        let parsed: PluginManifest = serde_json::from_str(&manifest)
            .unwrap_or_else(|e| panic!("[{label}] manifest should deserialize: {e}"));
        let mut kernel = boot_kernel();
        let err = match kernel.register_plugin(parsed) {
            Err(e) => e,
            Ok(_) => panic!("[{label}] expected registration to be rejected, but it succeeded"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains(want),
            "[{label}] error should contain {want:?}, got: {msg}"
        );

        // The JSON entry point also rejects each case — the first three
        // at the meta-schema layer, the unresolved implRef at the same
        // kernel branch as above.
        let mut kernel = boot_kernel();
        assert!(
            kernel.register_plugin_from_json(&manifest).is_err(),
            "[{label}] JSON entry point should also reject"
        );
    }
}
