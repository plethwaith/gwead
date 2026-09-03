//! Integration tests for wasm resource limits.
//!
//! Fuel and memory caps apply to the script-runtime wasm sub-instance
//! the `script` step type spawns (and to a `wasm` step's module). The
//! wallclock timeout wraps
//! the entire action future regardless of which step type is in play.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use gwead::kernel::host_api::{PluginErrorPayload, PluginExecution, StepError, StepOutput};
use gwead::kernel::types::*;
use gwead::kernel::{Kernel, KernelConfig, KernelError, RuntimeLimits};
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

fn boot_with_limits(limits: RuntimeLimits, manifests: Vec<PluginManifest>) -> Arc<Kernel> {
    boot_with_config(KernelConfig::default().with_limits(limits), manifests)
}

fn boot_with_config(config: KernelConfig, manifests: Vec<PluginManifest>) -> Arc<Kernel> {
    init_tracing();
    let mut config = common::script_runtime_mock::trusting(config, &["lua"]);
    // Seed the test-only `sleep_async` impl into the
    // table before boot. Manifest below declares it via
    // `kind: "native"` so the kernel wires it through the standard
    // path.
    config
        .native_step_impls
        .insert(
            "test.test_resource_limits_fixture.sleep_async",
            sleep_async_step,
        )
        .expect("no collision on a fresh table");
    config
        .native_step_impls
        .insert(
            "test.test_resource_limits_fixture.fail_on_cancel",
            fail_on_cancel_step,
        )
        .expect("no collision on a fresh table");
    let mut k = Kernel::boot(config).expect("kernel boot");
    common::script_runtime_mock::register(&mut k).expect("mock script runtime registers");
    k.register_plugin_from_json(
        r#"{
            "name": "test_resource_limits_fixture",
            "version": "0.0.0",
            "description": "Wires `sleep_async` for the wallclock-timeout tests — real async work that's preemptable by tokio::time::timeout.",
            "stepTypeDefs": [
                {"name": "test_resource_limits_fixture.sleep_async", "freelyUsable": true},
                {"name": "test_resource_limits_fixture.fail_on_cancel", "freelyUsable": true}
            ],
            "stepTypeImpls": [
                {"stepType": "test_resource_limits_fixture.sleep_async", "kind": "native", "implRef": "test.test_resource_limits_fixture.sleep_async"},
                {"stepType": "test_resource_limits_fixture.fail_on_cancel", "kind": "native", "implRef": "test.test_resource_limits_fixture.fail_on_cancel"}
            ]
        }"#,
    )
    .expect("resource_limits test fixture registers");
    for m in manifests {
        k.register_plugin(m).expect("registration");
    }
    k.into_arc()
}

/// Test-only step type: awaits `tokio::time::sleep(params.sleep_ms)`
/// and returns. Used by the wallclock-timeout decision-tree
/// tests so the action future has something async to suspend on
/// when the timer fires.
fn sleep_async_step<'a>(
    _ex: &'a mut (dyn PluginExecution + Send),
    params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move {
        let sleep_ms = params.get("sleep_ms").and_then(|v| v.as_u64()).unwrap_or(0);
        tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
        Ok(StepOutput::from(json!({ "slept_ms": sleep_ms })))
    })
}

/// Test-only step type modelling an embedder's host step that races
/// its work against the cancellation token and, when the token fires,
/// answers with its *own* error rather than `KernelError::Cancelled`.
/// `params.shape` picks the error: `"thrown"` is a structured
/// `PluginError` with code `host_cancelled` (an embedder's cancel
/// code), `"failed"` a plain `Execution` failure whose message merely
/// mentions cancellation (the flattened nested-`invoke` shape).
fn fail_on_cancel_step<'a>(
    ex: &'a mut (dyn PluginExecution + Send),
    params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    let cancel = ex.cancel_token();
    Box::pin(async move {
        let sleep_ms = params.get("sleep_ms").and_then(|v| v.as_u64()).unwrap_or(0);
        let shape = params
            .get("shape")
            .and_then(|v| v.as_str())
            .unwrap_or("thrown");
        tokio::select! {
            _ = cancel.cancelled() => Err(match shape {
                "failed" => StepError::Failed("host step cancelled by token".to_string()),
                _ => StepError::Thrown(PluginErrorPayload {
                    code: "host_cancelled".to_string(),
                    message: "host step observed the cancellation token".to_string(),
                    params: json!({}),
                }),
            }),
            _ = tokio::time::sleep(Duration::from_millis(sleep_ms)) => {
                Ok(StepOutput::from(json!({ "slept_ms": sleep_ms })))
            }
        }
    })
}

fn step(id: &str, step_type: &str, params: Value) -> StepDef {
    StepDef::new(id.to_string(), step_type.to_string(), params)
}

fn action(steps: Vec<StepDef>) -> Action {
    Action::new(steps)
}

// ---------------------------------------------------------------------------
// Wallclock-timeout decision tree
// ---------------------------------------------------------------------------

/// Helper: build a manifest with one action and the requested
/// settings.
fn manifest_with_action(name: &str, action_name: &str, action: Action) -> PluginManifest {
    let mut actions = IndexMap::new();
    actions.insert(action_name.to_string(), action);
    {
        let mut m = PluginManifest::new(name.to_string());
        m.actions = actions;
        m
    }
}

/// An action that declares its own `wallclock_timeout_ms` wins over
/// the deployment default. Here the default is generous (10 s)
/// but the action declares a tight 80 ms cap. The action's
/// `sleep_async` step runs for 500 ms — far longer than its
/// declared cap — and the wrapper trips an `ExecutionTimeout`.
#[tokio::test(flavor = "multi_thread")]
async fn per_action_wallclock_override_wins_over_deployment_default() {
    let mut a = action(vec![step(
        "sleep",
        "test_resource_limits_fixture.sleep_async",
        json!({ "sleep_ms": 500u64 }),
    )]);
    a.wallclock_timeout_ms = Some(80);
    let kernel = boot_with_limits(
        RuntimeLimits::default().with_default_wallclock_timeout(Duration::from_secs(10)),
        vec![manifest_with_action("p", "go", a)],
    );

    let err = kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect_err("declared cap < step sleep must trip ExecutionTimeout");
    match err {
        KernelError::ExecutionTimeout { timeout_ms } => {
            assert_eq!(
                timeout_ms, 80,
                "the action's declared cap must be the one applied"
            );
        }
        other => panic!("expected ExecutionTimeout, got: {other:?}"),
    }
}

/// The `defaultWallclockTimeoutMs` settings key
/// overrides `KernelConfig::limits.default_wallclock_timeout`. Boot with a
/// generous 10s `RuntimeLimits` default and a 100 ms settings
/// override; an action without its own declaration inherits the
/// 100 ms cap.
#[tokio::test(flavor = "multi_thread")]
async fn settings_override_kernel_config_default() {
    let cfg = KernelConfig::default()
        .with_limits(
            RuntimeLimits::default().with_default_wallclock_timeout(Duration::from_secs(10)),
        )
        .with_settings(json!({ "defaultWallclockTimeoutMs": 100 }));
    let a = action(vec![step(
        "sleep",
        "test_resource_limits_fixture.sleep_async",
        json!({ "sleep_ms": 500u64 }),
    )]);
    let kernel = boot_with_config(cfg, vec![manifest_with_action("p", "go", a)]);

    let err = kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect_err("settings cap < step sleep must trip ExecutionTimeout");
    match err {
        KernelError::ExecutionTimeout { timeout_ms } => {
            assert_eq!(
                timeout_ms, 100,
                "the wallclockTimeoutMs setting must override the KernelConfig default"
            );
        }
        other => panic!("expected ExecutionTimeout, got: {other:?}"),
    }
}

/// A `dataflow: true` action with no `wallclock_timeout_ms`
/// declaration runs uncapped. The deployment default is set to 100 ms
/// (well under the action's sleep), but no `ExecutionTimeout`
/// fires because the dataflow branch of the decision tree returns
/// `None` and `with_wallclock_timeout` skips the wrapper.
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_action_with_no_declaration_runs_uncapped() {
    let mut a = action(vec![]);
    a.dataflow = true;
    // Dataflow validation requires ≥1 `long_running` step.
    a.steps.push({
        let mut m = StepDef::new(
            "sleep".to_string(),
            "test_resource_limits_fixture.sleep_async".to_string(),
            json!({ "sleep_ms": 300u64 }),
        );
        m.long_running = true;
        m
    });
    let kernel = boot_with_limits(
        RuntimeLimits::default().with_default_wallclock_timeout(Duration::from_millis(100)),
        vec![manifest_with_action("p", "go", a)],
    );

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect(
            "dataflow with no declared cap must run uncapped despite a tight deployment default",
        );
    assert_eq!(result.step_results["sleep"]["slept_ms"], json!(300));
}

/// A `dataflow: true` action that explicitly declares its own
/// `wallclock_timeout_ms` IS capped at that value. Manifests that
/// genuinely want a hard kill on a dataflow pipeline (e.g.
/// "transcoding should never take more than 2 hours") opt in
/// through this field.
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_action_honours_explicit_declaration() {
    let mut a = action(vec![{
        let mut m = StepDef::new(
            "sleep".to_string(),
            "test_resource_limits_fixture.sleep_async".to_string(),
            json!({ "sleep_ms": 500u64 }),
        );
        m.long_running = true;
        m
    }]);
    a.dataflow = true;
    a.wallclock_timeout_ms = Some(80);
    let kernel = boot_with_limits(
        RuntimeLimits::default(),
        vec![manifest_with_action("p", "go", a)],
    );

    let err = kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect_err("declared cap on dataflow action must still apply");
    match err {
        KernelError::ExecutionTimeout { timeout_ms } => {
            assert_eq!(timeout_ms, 80);
        }
        other => panic!("expected ExecutionTimeout, got: {other:?}"),
    }
}

/// Per-action override AND settings override are both
/// configured; the action declaration must win. Locks in
/// precedence against a future refactor that quietly inverts it.
#[tokio::test(flavor = "multi_thread")]
async fn per_action_override_beats_settings_override() {
    let mut a = action(vec![step(
        "sleep",
        "test_resource_limits_fixture.sleep_async",
        json!({ "sleep_ms": 500u64 }),
    )]);
    a.wallclock_timeout_ms = Some(80);
    // Settings push the default to 300 ms — generous enough that the
    // action would COMPLETE under it. But the action's 80 ms
    // declaration wins, so the run still trips.
    let cfg = KernelConfig::default().with_settings(json!({ "defaultWallclockTimeoutMs": 300 }));
    let kernel = boot_with_config(cfg, vec![manifest_with_action("p", "go", a)]);

    let err = kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect_err("per-action declaration must win even when settings is generous");
    match err {
        KernelError::ExecutionTimeout { timeout_ms } => {
            assert_eq!(
                timeout_ms, 80,
                "the action's declared 80 ms must win over the deployment's 300 ms"
            );
        }
        other => panic!("expected ExecutionTimeout, got: {other:?}"),
    }
}

/// The dataflow-handle path uses `effective_wallclock_timeout` the
/// same way the single-shot path does, but it spawns onto a tokio
/// task rather than awaiting inline. This test exercises that
/// branch directly: the deployment default is tight (100 ms), the dataflow
/// action's `sleep_async` runs 300 ms, and the handle's result
/// resolves cleanly without `ExecutionTimeout` because the
/// auto-uncap kicks in.
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_handle_path_observes_auto_uncap() {
    let mut a = action(vec![{
        let mut m = StepDef::new(
            "sleep".to_string(),
            "test_resource_limits_fixture.sleep_async".to_string(),
            json!({ "sleep_ms": 300u64 }),
        );
        m.long_running = true;
        m
    }]);
    a.dataflow = true;
    let kernel = boot_with_limits(
        RuntimeLimits::default().with_default_wallclock_timeout(Duration::from_millis(100)),
        vec![manifest_with_action("p", "pipeline", a)],
    );

    let handle = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .into_dataflow_handle()
        .expect("handle returned");

    let result = handle
        .result
        .await
        .expect("result delivered")
        .expect("dataflow with no declared cap must NOT trip the 100 ms deployment default");
    assert_eq!(result.step_results["sleep"]["slept_ms"], json!(300));
}

/// `wallclock_timeout_ms: 0` would intuitively read as "no cap"
/// but actually produces `Duration::from_millis(0)` and instant
/// timeout. `register_plugin` rejects it with a clear error so
/// the mistake surfaces at install time, not at first invocation.
#[tokio::test(flavor = "multi_thread")]
async fn register_rejects_zero_wallclock_timeout() {
    use gwead::kernel::Kernel;
    let mut a = action(vec![step("noop", "log", json!({"message": "hi"}))]);
    a.wallclock_timeout_ms = Some(0);
    let m = manifest_with_action("p", "go", a);

    let mut k = Kernel::boot(common::script_runtime_mock::trusting(
        KernelConfig::default(),
        &["lua"],
    ))
    .expect("kernel boot");
    let err = k
        .register_plugin(m)
        .expect_err("zero wallclock_timeout_ms should be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("wallclock_timeout_ms")
            && (msg.contains("0") || msg.contains("zero") || msg.contains("invalid")),
        "expected validation error explaining zero is invalid; got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Scheduler-level cancellation
// ---------------------------------------------------------------------------

/// The wave scheduler polls the cancellation token BETWEEN steps, so a
/// cancelled action stops even when every step body ignores the token.
/// The `sleep_async` step here never checks `cancel`; firing the token
/// mid-first-step must still prevent the second step from running.
#[tokio::test(flavor = "multi_thread")]
async fn cancellation_stops_wave_scheduler_between_steps() {
    let kernel = boot_with_limits(
        RuntimeLimits::default(),
        vec![manifest_with_action(
            "p",
            "go",
            action(vec![
                step(
                    "first",
                    "test_resource_limits_fixture.sleep_async",
                    json!({ "sleep_ms": 200u64 }),
                ),
                step(
                    "second",
                    "test_resource_limits_fixture.sleep_async",
                    json!({ "sleep_ms": 0u64 }),
                ),
            ]),
        )],
    );

    let cancel = tokio_util::sync::CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        trigger.cancel();
    });

    let err = kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .with_cancel(cancel)
        .run()
        .await
        .expect_err("cancelled action must not run to completion");
    match err {
        KernelError::Cancelled { at_step } => {
            assert_eq!(at_step, "second", "scheduler stops before the next step");
        }
        other => panic!("expected KernelError::Cancelled, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Deadline vs caller cancel: what the wrapper reports
// ---------------------------------------------------------------------------

/// Build the one-step `fail_on_cancel` action used by the remap tests.
fn fail_on_cancel_action(shape: &str, sleep_ms: u64, wallclock_ms: Option<u64>) -> Action {
    let mut a = action(vec![step(
        "host",
        "test_resource_limits_fixture.fail_on_cancel",
        json!({ "sleep_ms": sleep_ms, "shape": shape }),
    )]);
    a.wallclock_timeout_ms = wallclock_ms;
    a
}

/// The watchdog fires the token; the host step answers with a
/// structured `PluginError` carrying its own cancellation code. The
/// caller must still see `ExecutionTimeout`: the deadline is what
/// stopped the action, whatever shape the stop took on the way out.
/// (Gwead issue #1 — before the fix the `PluginError` passed through
/// and read as a caller-requested cancel.)
#[tokio::test(flavor = "multi_thread")]
async fn deadline_remaps_structured_step_error_to_execution_timeout() {
    let kernel = boot_with_limits(
        RuntimeLimits::default(),
        vec![manifest_with_action(
            "p",
            "go",
            fail_on_cancel_action("thrown", 5_000, Some(80)),
        )],
    );

    let err = kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect_err("declared cap < step sleep must trip the deadline");
    match err {
        KernelError::ExecutionTimeout { timeout_ms } => assert_eq!(timeout_ms, 80),
        other => panic!("expected ExecutionTimeout, got: {other:?}"),
    }
}

/// Same as above with the plain-failure shape: a step whose error is
/// an ordinary `Execution` message mentioning cancellation (the
/// flattened nested-`invoke` shape) is also the watchdog's doing.
#[tokio::test(flavor = "multi_thread")]
async fn deadline_remaps_plain_step_failure_to_execution_timeout() {
    let kernel = boot_with_limits(
        RuntimeLimits::default(),
        vec![manifest_with_action(
            "p",
            "go",
            fail_on_cancel_action("failed", 5_000, Some(80)),
        )],
    );

    let err = kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect_err("declared cap < step sleep must trip the deadline");
    match err {
        KernelError::ExecutionTimeout { timeout_ms } => assert_eq!(timeout_ms, 80),
        other => panic!("expected ExecutionTimeout, got: {other:?}"),
    }
}

/// The mirror image: the *caller* fires the token well inside the
/// deadline. The step's own error must pass through untouched — the
/// remap is keyed on the watchdog having fired, not on the token.
#[tokio::test(flavor = "multi_thread")]
async fn caller_cancel_leaves_step_error_untouched() {
    let kernel = boot_with_limits(
        RuntimeLimits::default(),
        vec![manifest_with_action(
            "p",
            "go",
            fail_on_cancel_action("thrown", 5_000, Some(10_000)),
        )],
    );

    let cancel = tokio_util::sync::CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        trigger.cancel();
    });

    let err = kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .with_cancel(cancel)
        .run()
        .await
        .expect_err("caller cancel must not run to completion");
    match err {
        KernelError::PluginError { code, .. } => assert_eq!(code, "host_cancelled"),
        other => panic!("expected the step's own PluginError, got: {other:?}"),
    }
}

/// Dataflow with a step that answers the token with its own error.
/// The deadline arms two mechanisms at the same instant and either
/// may win: the outer timeout drops the scheduler mid-flight (its own
/// terminal emit never runs), or the watchdog's cancel lets the step
/// fail, the scheduler emit its own `PipelineCompleted { ok: false }`,
/// and the wrapper remap the `Err`. Either way the caller must see
/// `ExecutionTimeout` and the handle must deliver exactly ONE
/// terminator — the substitute emit is for a dropped future only, not
/// for any `ExecutionTimeout` result.
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_deadline_answered_by_step_emits_one_terminator() {
    let mut a = action(vec![{
        let mut m = step(
            "host",
            "test_resource_limits_fixture.fail_on_cancel",
            json!({ "sleep_ms": 5_000u64, "shape": "thrown" }),
        );
        m.long_running = true;
        m
    }]);
    a.dataflow = true;
    a.wallclock_timeout_ms = Some(80);
    let kernel = boot_with_limits(
        RuntimeLimits::default(),
        vec![manifest_with_action("p", "pipeline", a)],
    );

    let mut handle = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .into_dataflow_handle()
        .expect("handle returned");

    let err = handle
        .result
        .await
        .expect("result delivered")
        .expect_err("declared cap on dataflow action must still apply");
    match err {
        KernelError::ExecutionTimeout { timeout_ms } => assert_eq!(timeout_ms, 80),
        other => panic!("expected ExecutionTimeout, got: {other:?}"),
    }

    // Every sender is gone once the pipeline task exits, so the drain
    // ends on channel close; the outer timeout is a hang guard only.
    let mut terminators = 0;
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(ev) = handle.events.recv().await {
            if let gwead::kernel::DataflowEvent::PipelineCompleted { ok } = ev {
                assert!(!ok, "a deadline-stopped pipeline is not ok");
                terminators += 1;
            }
        }
    })
    .await
    .expect("events channel closes after the pipeline task exits");
    assert_eq!(terminators, 1, "exactly one PipelineCompleted per pipeline");
}

// ---------------------------------------------------------------------------
// Limits configurable via KernelConfig
// ---------------------------------------------------------------------------

#[test]
fn runtime_limits_default_is_generous() {
    // Sanity-check the default constants. If we ever tighten the
    // defaults this test fails loudly so we explicitly confirm the
    // change is intentional.
    let d = RuntimeLimits::default();
    assert!(d.fuel_budget >= 100_000_000);
    assert!(d.max_memory_bytes >= 16 * 1024 * 1024);
    assert!(d.default_wallclock_timeout >= Duration::from_secs(30));
}
