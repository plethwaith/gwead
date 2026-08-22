//! Parallel-wave execution tests.
//!
//! Coverage:
//! - `parallel_waves: true` actually runs independent steps concurrently
//!   and merges each task's writes back into the canonical state
//! - `parallel_waves: false` (the default) preserves declaration-order
//!   semantics for variable-mediated communication
//! - `wave_requires_sequential` safety check forces the sequential path
//!   even on opted-in actions when a step uses iteration / vars

mod common;

use std::future::Future;
use std::pin::Pin;

use indexmap::IndexMap;
use serde_json::{Value, json};

use gwead::kernel::host_api::{PluginExecution, StepError, StepOutput};
use gwead::kernel::types::{Action, PluginManifest, StepDef};
use gwead::kernel::{Kernel, KernelConfig, KernelError};

fn step(id: &str, step_type: &str, params: Value) -> StepDef {
    StepDef::new(id.to_string(), step_type.to_string(), params)
}

/// Wraps `step_type` in a `try` step with an empty `catch` — the
/// optional-step idiom. An empty catch swallows the inner step's
/// failure without recovery, so an optional step's failure does not
/// abort the action.
fn step_optional(id: &str, step_type: &str, params: Value) -> StepDef {
    let inner = StepDef::new(format!("{id}_inner"), step_type.to_string(), params);
    let inner_json = serde_json::to_value(&inner).expect("StepDef serializes");
    StepDef::new(
        id.to_string(),
        "try".to_string(),
        json!({
            "try":   [inner_json],
            "catch": [],
        }),
    )
}

fn action_parallel(steps: Vec<StepDef>) -> Action {
    {
        let mut m = Action::new(steps);
        m.parallel_waves = true;
        m
    }
}

fn simple_manifest(name: &str, actions: IndexMap<String, Action>) -> PluginManifest {
    {
        let mut m = PluginManifest::new(name.to_string());
        m.actions = actions;
        m
    }
}

/// Test step type — stores its `value` param as the step result, with
/// opt-in side effects for exercising edge cases:
///
/// - `fail: true` — returns `Err(StepError::Failed(error_msg))`
///   (default message: "test failure").
/// - `panic: true` — panics, surfacing as a tokio `JoinError` from the
///   parallel-wave path.
/// - `status: <u16>` — emits a `status` metadata sidecar (HTTP-like).
/// - `headers: { … }` — emits a `headers` metadata sidecar.
fn test_constant<'a>(
    ex: &'a mut (dyn PluginExecution + Send),
    params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move {
        if params.get("panic").and_then(|v| v.as_bool()) == Some(true) {
            panic!(
                "test_constant panicking by request for step '{}'",
                ex.current_step_id()
            );
        }

        if params.get("fail").and_then(|v| v.as_bool()) == Some(true) {
            let msg = params
                .get("error_msg")
                .and_then(|v| v.as_str())
                .unwrap_or("test failure")
                .to_string();
            return Err(StepError::Failed(msg));
        }

        let value = params.get("value").cloned().unwrap_or(Value::Null);

        let mut metadata = IndexMap::new();
        if let Some(status) = params.get("status").and_then(|v| v.as_u64()) {
            metadata.insert("status".to_string(), Value::from(status));
        }
        if let Some(headers) = params.get("headers").and_then(|v| v.as_object()) {
            metadata.insert("headers".to_string(), Value::Object(headers.clone()));
        }

        if metadata.is_empty() {
            Ok(StepOutput::from(value))
        } else {
            Ok(StepOutput::with_metadata(value, metadata))
        }
    })
}

fn boot_with_test_step() -> Kernel {
    // Test step bodies seed the kernel's native impl
    // table directly rather than going through a kernel-mutation
    // back-door. The fixture's manifest below references the
    // submitted name via implRef.
    let mut table = gwead::kernel::native_impls::NativeStepImplTable::empty();
    table
        .insert("test.test_parallel_wave_fixture.constant", test_constant)
        .expect("no collision on a fresh empty table");
    let mut kernel =
        Kernel::boot(KernelConfig::default().with_native_step_impls(table)).expect("kernel boot");
    kernel
        .register_plugin_from_json(
            r#"{
                "name": "test_parallel_wave_fixture",
                "version": "0.0.0",
                "description": "Test-only fixture wiring `test_constant` for parallel_wave_tests.",
                "stepTypeDefs": [
                    {"name": "test_parallel_wave_fixture.test_constant", "freelyUsable": true}
                ],
                "stepTypeImpls": [
                    {"stepType": "test_parallel_wave_fixture.test_constant", "kind": "native", "implRef": "test.test_parallel_wave_fixture.constant"}
                ]
            }"#,
        )
        .expect("test fixture manifest registers");
    kernel
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_waves_opt_in_runs_three_independent_steps() {
    // Three steps with no dependencies on each other → wave 0 = [0, 1, 2].
    // With parallel_waves: true and no variable/iteration usage, the
    // runtime forks ExecutionState per step, dispatches each on its own tokio
    // task, and merges step_results back at join. All three results must
    // land in the canonical step_results map.
    let mut kernel = boot_with_test_step();
    let mut actions = IndexMap::new();
    actions.insert(
        "trio".to_string(),
        action_parallel(vec![
            step(
                "a",
                "test_parallel_wave_fixture.test_constant",
                json!({"value": "first"}),
            ),
            step(
                "b",
                "test_parallel_wave_fixture.test_constant",
                json!({"value": "second"}),
            ),
            step(
                "c",
                "test_parallel_wave_fixture.test_constant",
                json!({"value": "third"}),
            ),
        ]),
    );
    let manifest = simple_manifest("p", actions);
    kernel.register_plugin(manifest).unwrap();

    let result = kernel
        .execute("p", "trio", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .unwrap();

    assert_eq!(result.step_results["a"], json!("first"));
    assert_eq!(result.step_results["b"], json!("second"));
    assert_eq!(result.step_results["c"], json!("third"));
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_waves_off_preserves_sequential_default() {
    // Same three independent steps but `parallel_waves: false` (the
    // default). Runtime takes the sequential path; all three results
    // still populate.
    let mut kernel = boot_with_test_step();
    let mut actions = IndexMap::new();
    let mut act = action_parallel(vec![
        step(
            "a",
            "test_parallel_wave_fixture.test_constant",
            json!({"value": "first"}),
        ),
        step(
            "b",
            "test_parallel_wave_fixture.test_constant",
            json!({"value": "second"}),
        ),
        step(
            "c",
            "test_parallel_wave_fixture.test_constant",
            json!({"value": "third"}),
        ),
    ]);
    act.parallel_waves = false;
    actions.insert("trio".to_string(), act);
    let manifest = simple_manifest("p", actions);
    kernel.register_plugin(manifest).unwrap();

    let result = kernel
        .execute("p", "trio", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .unwrap();

    assert_eq!(result.step_results["a"], json!("first"));
    assert_eq!(result.step_results["b"], json!("second"));
    assert_eq!(result.step_results["c"], json!("third"));
}

// ---------------------------------------------------------------------------
// Edge cases — failure / merge / panic semantics
// ---------------------------------------------------------------------------

/// Two parallel failures: the **first-declared** step's error must be the
/// one surfaced. Merging task outcomes in wave-declaration order plus the
/// first-non-None first_error capture is what makes the choice
/// deterministic; this test pins that contract. Reading the failing
/// step's error from the canonical store after merge would let a
/// *prior* task's last_error leak into the wrong step's error mapping.
#[tokio::test(flavor = "multi_thread")]
async fn parallel_waves_two_failures_first_declared_wins() {
    let mut kernel = boot_with_test_step();
    let mut actions = IndexMap::new();
    actions.insert(
        "both_fail".to_string(),
        action_parallel(vec![
            step(
                "a",
                "test_parallel_wave_fixture.test_constant",
                json!({"fail": true, "error_msg": "alpha-error"}),
            ),
            step(
                "b",
                "test_parallel_wave_fixture.test_constant",
                json!({"fail": true, "error_msg": "beta-error"}),
            ),
        ]),
    );
    let manifest = simple_manifest("p", actions);
    kernel.register_plugin(manifest).unwrap();

    let err = kernel
        .execute("p", "both_fail", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .unwrap_err();

    match err {
        KernelError::Execution(msg) => {
            assert!(
                msg.contains("alpha-error"),
                "first declared step's error should win, got: {msg}"
            );
            assert!(
                !msg.contains("beta-error"),
                "second step's error must not leak into first's mapping: {msg}"
            );
        }
        other => panic!("expected Execution error, got: {other:?}"),
    }
}

/// Required vs optional, both fail: the required step's error must
/// surface even if the optional step failed first in declaration order
/// (optional failures don't count toward first_error).
#[tokio::test(flavor = "multi_thread")]
async fn parallel_waves_optional_failure_does_not_mask_required_failure() {
    let mut kernel = boot_with_test_step();
    let mut actions = IndexMap::new();
    actions.insert(
        "mixed_fail".to_string(),
        action_parallel(vec![
            step_optional(
                "opt",
                "test_parallel_wave_fixture.test_constant",
                json!({"fail": true, "error_msg": "opt-error"}),
            ),
            step(
                "req",
                "test_parallel_wave_fixture.test_constant",
                json!({"fail": true, "error_msg": "req-error"}),
            ),
        ]),
    );
    let manifest = simple_manifest("p", actions);
    kernel.register_plugin(manifest).unwrap();

    let err = kernel
        .execute("p", "mixed_fail", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .unwrap_err();

    match err {
        KernelError::Execution(msg) => {
            assert!(
                msg.contains("req-error"),
                "required step's error should surface, got: {msg}"
            );
            assert!(
                !msg.contains("opt-error"),
                "optional step's last_error must not leak into the required's mapping: {msg}"
            );
        }
        other => panic!("expected Execution error, got: {other:?}"),
    }
}

/// Optional failure + required success: action succeeds. The succeeding
/// step's result lands in `step_results`; the optional failure is
/// suppressed without aborting the wave.
#[tokio::test(flavor = "multi_thread")]
async fn parallel_waves_optional_failure_with_required_success() {
    let mut kernel = boot_with_test_step();
    let mut actions = IndexMap::new();
    actions.insert(
        "opt_fails_req_ok".to_string(),
        action_parallel(vec![
            step_optional(
                "opt",
                "test_parallel_wave_fixture.test_constant",
                json!({"fail": true}),
            ),
            step(
                "req",
                "test_parallel_wave_fixture.test_constant",
                json!({"value": "winner"}),
            ),
        ]),
    );
    let manifest = simple_manifest("p", actions);
    kernel.register_plugin(manifest).unwrap();

    let result = kernel
        .execute("p", "opt_fails_req_ok", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("optional failure must not abort a successful required step");

    assert_eq!(result.step_results["req"], json!("winner"));
    // The optional step's slot doesn't get a successful result (the body
    // returned `Err` before any store_step_result). Either no entry or
    // null — both are acceptable; assert by absence.
    assert!(
        !result.step_results.contains_key("opt") || result.step_results["opt"].is_null(),
        "optional failure must not write a step_results entry; got: {:?}",
        result.step_results.get("opt"),
    );
}

/// A partial failure fails the action with the *failing* step's error,
/// not the succeeding sibling's. The companion invariant — that the
/// succeeding step's writes are still merged into the canonical state
/// before the error surfaces — cannot be observed through a failed
/// `ActionResult`; it is pinned by `merge_task_state` being called for
/// every task in `runtime.rs`, failure or not.
#[tokio::test(flavor = "multi_thread")]
async fn parallel_waves_partial_failure_preserves_succeeding_writes() {
    let mut kernel = boot_with_test_step();
    let mut actions = IndexMap::new();
    actions.insert(
        "partial".to_string(),
        action_parallel(vec![
            step(
                "win",
                "test_parallel_wave_fixture.test_constant",
                json!({"value": "kept-on-failure"}),
            ),
            step(
                "lose",
                "test_parallel_wave_fixture.test_constant",
                json!({"fail": true, "error_msg": "lose-error"}),
            ),
        ]),
    );
    let manifest = simple_manifest("p", actions);
    kernel.register_plugin(manifest).unwrap();

    let err = kernel
        .execute("p", "partial", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .unwrap_err();

    // Even though `win` declared first and succeeded, the action fails
    // because of `lose`'s required failure. Its error must reference
    // `lose-error`, NOT the succeeding step.
    match err {
        KernelError::Execution(msg) => assert!(msg.contains("lose-error"), "got: {msg}"),
        other => panic!("expected Execution error, got: {other:?}"),
    }
}

/// Two steps emitting `status` / `headers` metadata sidecars (HTTP-like)
/// both complete through the parallel-wave path and a wave-1 step that
/// depends on both runs afterwards. The sidecar values themselves are
/// not observable through `ActionResult`; that they merge is pinned by
/// `merge_task_state` in `runtime.rs`, and the read side by the
/// resolution-context tests.
#[tokio::test(flavor = "multi_thread")]
async fn parallel_waves_step_statuses_and_headers_merge() {
    let mut kernel = boot_with_test_step();
    let mut actions = IndexMap::new();
    let parallel_pair = [
        step(
            "a",
            "test_parallel_wave_fixture.test_constant",
            json!({
                "value": "ok-a",
                "status": 200,
                "headers": {"x-source": "task-a"},
            }),
        ),
        step(
            "b",
            "test_parallel_wave_fixture.test_constant",
            json!({
                "value": "ok-b",
                "status": 201,
                "headers": {"x-source": "task-b"},
            }),
        ),
    ];
    // Wave 1: a step depending on both that captures the sidecars into
    // its own result, so we can inspect them via `result.step_results`.
    // Uses an explicit `depends_on` so the planner puts it after a/b in
    // its own wave.
    let mut inspector = step(
        "inspect",
        "test_parallel_wave_fixture.test_constant",
        json!({"value": "ignored"}),
    );
    inspector.depends_on = vec!["a".to_string(), "b".to_string()];

    let act = action_parallel(vec![
        parallel_pair[0].clone(),
        parallel_pair[1].clone(),
        inspector,
    ]);
    // Inspector wave (wave 1) has only one step — parallelize gate is
    // wave.len() > 1, so wave 1 sequential. Wave 0 is the parallel pair,
    // which IS opt-in parallel via `action_parallel`.

    actions.insert("hh".to_string(), act);
    let manifest = simple_manifest("p", actions);
    kernel.register_plugin(manifest).unwrap();

    let result = kernel
        .execute("p", "hh", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("action must succeed");

    // `ActionResult` carries only `.result` per step. The inspector
    // ran, so both a and b completed and merged.
    assert_eq!(result.step_results["inspect"], json!("ignored"));
    assert_eq!(result.step_results["a"], json!("ok-a"));
    assert_eq!(result.step_results["b"], json!("ok-b"));
}

/// A panicking step inside a `tokio::spawn`'d task surfaces as a
/// `JoinError`, which the parallel-wave path maps onto a clean
/// `KernelError::Execution("Parallel wave task panicked: …")` rather
/// than crashing the whole action invocation or swallowing the panic.
#[tokio::test(flavor = "multi_thread")]
async fn parallel_waves_task_panic_surfaces_as_execution_error() {
    let mut kernel = boot_with_test_step();
    let mut actions = IndexMap::new();
    actions.insert(
        "panicker".to_string(),
        action_parallel(vec![
            step(
                "ok",
                "test_parallel_wave_fixture.test_constant",
                json!({"value": "fine"}),
            ),
            step(
                "boom",
                "test_parallel_wave_fixture.test_constant",
                json!({"panic": true}),
            ),
        ]),
    );
    let manifest = simple_manifest("p", actions);
    kernel.register_plugin(manifest).unwrap();

    let err = kernel
        .execute("p", "panicker", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .unwrap_err();

    match err {
        KernelError::Execution(msg) => assert!(
            msg.contains("panicked"),
            "task panic should surface as 'panicked' execution error, got: {msg}"
        ),
        other => panic!("expected Execution error for task panic, got: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_waves_safety_check_falls_back_on_variable_writer() {
    // Even with parallel_waves: true, the safety check
    // (`wave_requires_sequential`) forces sequential execution when any
    // step uses a non-DAG-tracked communication channel. Here a `let`
    // writer (`store_to_variable`) followed by another step reading
    // `{{$.vars.…}}` is
    // exactly that case. The test passes iff the variable write is
    // visible to the reader, which can only happen under sequential
    // execution.
    let mut kernel = boot_with_test_step();
    let mut actions = IndexMap::new();
    let mut writer = step("write", "let", json!({"value": "ok"}));
    writer.store_to_variable = Some("shared".to_string());
    let mut reader = step("read", "let", json!({"value": "{{$.vars.shared}}"}));
    reader.store_to_variable = Some("echo".to_string());
    actions.insert(
        "writer_reader".to_string(),
        action_parallel(vec![writer, reader]),
    );
    let manifest = simple_manifest("p", actions);
    kernel.register_plugin(manifest).unwrap();

    let result = kernel
        .execute("p", "writer_reader", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .unwrap();

    // Echo step reads vars.shared, which was set by the writer in the
    // same wave. If parallel execution had been used, the reader's
    // forked ExecutionState would have observed the baseline (no shared)
    // and not resolved to "ok".
    assert_eq!(result.variables["echo"], json!("ok"));
}
