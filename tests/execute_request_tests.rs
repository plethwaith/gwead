//! Direct unit tests for [`ExecuteActionRequest`] — the builder behind
//! [`Kernel::execute`].
//!
//! Integration sites exercise the happy path; this suite pins the
//! behaviours that are easy to regress on:
//!
//! - Terminal-vs-setter incompatibilities reject loudly instead of
//!   silently dropping caller-supplied state.
//! - `into_*()` terminals require the kernel to have been wrapped via
//!   [`Kernel::into_arc`] (they upgrade `self_weak` to clone an
//!   `Arc<Kernel>` into the spawned task).
//! - `into_continuous_handle` drives multiple iterations and exits
//!   promptly on cancellation.

#![allow(unused_crate_dependencies)]

mod common;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use gwead::kernel::host_api::{PluginExecution, StepError, StepOutput};
use gwead::kernel::types::*;
use gwead::kernel::{Kernel, KernelConfig, KernelError};
use indexmap::IndexMap;
use serde_json::{Value, json};

/// Minimal step body: echo `params` as the step output. Lets us
/// register a simple `noop` step type without depending on intrinsic
/// step bodies that have richer surface (`ifs`, `for_each`, etc.).
fn noop_step<'a>(
    _ex: &'a mut (dyn PluginExecution + Send),
    params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    let payload = params.clone();
    Box::pin(async move { Ok(StepOutput::from(payload)) })
}

const NOOP_MANIFEST: &str = r#"{
    "name": "test_execute_request_fixture",
    "version": "0.0.0",
    "description": "Wires the noop step body for the ExecuteActionRequest builder tests.",
    "stepTypeDefs": [
        {"name": "test_execute_request_fixture.noop", "freelyUsable": true}
    ],
    "stepTypeImpls": [
        {"stepType": "test_execute_request_fixture.noop", "kind": "native", "implRef": "test.test_execute_request_fixture.noop"}
    ]
}"#;

fn boot_kernel() -> Kernel {
    let mut native_step_impls = gwead::kernel::native_impls::NativeStepImplTable::empty();
    native_step_impls
        .insert("test.test_execute_request_fixture.noop", noop_step)
        .expect("no collision on fresh table");
    let mut kernel =
        Kernel::boot(KernelConfig::default().with_native_step_impls(native_step_impls))
            .expect("kernel boots");
    kernel
        .register_plugin_from_json(NOOP_MANIFEST)
        .expect("noop fixture registers");
    kernel
}

fn step(id: &str, step_type: &str, params: Value) -> StepDef {
    StepDef::new(id.to_string(), step_type.to_string(), params)
}

fn long_running_step(id: &str, step_type: &str, params: Value) -> StepDef {
    {
        let mut m = StepDef::new(id.to_string(), step_type.to_string(), params);
        m.long_running = true;
        m
    }
}

fn make_action(steps: Vec<StepDef>, continuous: bool, dataflow: bool, interval_ms: u64) -> Action {
    {
        let mut m = Action::new(steps);
        m.continuous = continuous;
        m.interval_ms = interval_ms;
        m.dataflow = dataflow;
        m
    }
}

fn manifest(name: &str, actions: IndexMap<String, Action>) -> PluginManifest {
    {
        let mut m = PluginManifest::new(name.to_string());
        m.actions = actions;
        m
    }
}

fn fresh_streams() -> gwead::kernel::streams::SharedStreamRegistry {
    Arc::new(std::sync::Mutex::new(
        gwead::kernel::streams::StreamRegistry::new(),
    ))
}

// ---------------------------------------------------------------------------
// Terminal-vs-setter compatibility.
// `with_streams()` is meaningful only for `.run()`; on the spawn-path
// terminals it errors loudly so a misuse surfaces immediately.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn into_dataflow_handle_rejects_with_streams() {
    let mut actions = IndexMap::new();
    actions.insert(
        "pipeline".to_string(),
        make_action(
            vec![long_running_step(
                "a",
                "test_execute_request_fixture.noop",
                json!({"v": 1}),
            )],
            false,
            true, // dataflow
            0,
        ),
    );
    let mut k = boot_kernel();
    k.register_plugin(manifest("p", actions)).unwrap();
    let kernel = k.into_arc();

    let err = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .with_streams(fresh_streams())
        .into_dataflow_handle()
        .err()
        .expect("with_streams + into_dataflow_handle must reject");

    assert!(
        matches!(err, KernelError::Validation(ref m) if m.contains("into_dataflow_handle")),
        "expected Validation error mentioning the terminal, got: {err:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn into_continuous_handle_rejects_with_streams() {
    let mut actions = IndexMap::new();
    actions.insert(
        "loop".to_string(),
        make_action(
            vec![step(
                "a",
                "test_execute_request_fixture.noop",
                json!({"v": 1}),
            )],
            true, // continuous
            false,
            10,
        ),
    );
    let mut k = boot_kernel();
    k.register_plugin(manifest("p", actions)).unwrap();
    let kernel = k.into_arc();

    let err = kernel
        .execute("p", "loop", json!({}))
        .with_config(&json!({}))
        .with_streams(fresh_streams())
        .into_continuous_handle()
        .err()
        .expect("with_streams + into_continuous_handle must reject");

    assert!(
        matches!(err, KernelError::Validation(ref m) if m.contains("into_continuous_handle")),
        "expected Validation error mentioning the terminal, got: {err:?}",
    );
}

// ---------------------------------------------------------------------------
// Spawn-path terminals require Kernel::into_arc; .run() does not.
// Tests use plain `Arc::new(k)` which deliberately does NOT seed
// `self_weak`, so the `arc()` helper inside the builder returns Err.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn into_dataflow_handle_errors_when_kernel_not_into_arcd() {
    let mut actions = IndexMap::new();
    actions.insert(
        "pipeline".to_string(),
        make_action(
            vec![long_running_step(
                "a",
                "test_execute_request_fixture.noop",
                json!({"v": 1}),
            )],
            false,
            true,
            0,
        ),
    );
    let mut k = boot_kernel();
    k.register_plugin(manifest("p", actions)).unwrap();
    // Deliberately wrap with plain `Arc::new` — `self_weak` stays empty.
    let kernel = Arc::new(k);

    let err = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .into_dataflow_handle()
        .err()
        .expect("spawn-path terminal must require into_arc");

    assert!(
        matches!(err, KernelError::Execution(ref m) if m.contains("into_arc")),
        "expected Execution error mentioning into_arc, got: {err:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn into_continuous_handle_errors_when_kernel_not_into_arcd() {
    let mut actions = IndexMap::new();
    actions.insert(
        "loop".to_string(),
        make_action(
            vec![step(
                "a",
                "test_execute_request_fixture.noop",
                json!({"v": 1}),
            )],
            true,
            false,
            10,
        ),
    );
    let mut k = boot_kernel();
    k.register_plugin(manifest("p", actions)).unwrap();
    let kernel = Arc::new(k);

    let err = kernel
        .execute("p", "loop", json!({}))
        .with_config(&json!({}))
        .into_continuous_handle()
        .err()
        .expect("spawn-path terminal must require into_arc");

    assert!(
        matches!(err, KernelError::Execution(ref m) if m.contains("into_arc")),
        "expected Execution error mentioning into_arc, got: {err:?}",
    );
}

// ---------------------------------------------------------------------------
// `into_continuous_handle` drives multiple iterations and
// exits promptly when the caller-supplied cancel fires. The token is
// threaded into each iteration's `.run()` (via `with_cancel`), so the
// loop body checks cancellation between iterations and a long
// iteration could observe the cancel mid-action.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn into_continuous_handle_drives_iterations_and_exits_on_cancel() {
    let mut actions = IndexMap::new();
    actions.insert(
        "loop".to_string(),
        make_action(
            vec![step(
                "tick",
                "test_execute_request_fixture.noop",
                json!({"label": "iter"}),
            )],
            true,
            false,
            5, // small inter-iteration interval
        ),
    );
    let mut k = boot_kernel();
    k.register_plugin(manifest("p", actions)).unwrap();
    let kernel = k.into_arc();

    let mut handle = kernel
        .execute("p", "loop", json!({}))
        .with_config(&json!({}))
        .into_continuous_handle()
        .expect("continuous handle");

    // Collect at least three iterations so we know the loop is
    // actually driving, not just emitting once.
    let mut iterations = 0usize;
    for _ in 0..3 {
        let item = tokio::time::timeout(Duration::from_millis(500), handle.events.recv())
            .await
            .expect("iteration arrives within budget");
        let result = item.expect("channel still open").expect("iteration ok");
        // Each iteration produces some output (the action's
        // result-mapping is empty, so output is JSON null — we just
        // verify the channel ticked once).
        let _ = result;
        iterations += 1;
    }
    assert_eq!(iterations, 3);

    handle.shutdown().await.expect("driver task joins cleanly");
}
