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
    boot_with_config_and_json(config, manifests, &[])
}

fn boot_with_config_and_json(
    config: KernelConfig,
    manifests: Vec<PluginManifest>,
    json_manifests: &[&str],
) -> Arc<Kernel> {
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
    config
        .native_step_impls
        .insert(
            "test.test_resource_limits_fixture.report_deadline",
            report_deadline_step,
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
                {"name": "test_resource_limits_fixture.fail_on_cancel", "freelyUsable": true},
                {"name": "test_resource_limits_fixture.report_deadline", "freelyUsable": true}
            ],
            "stepTypeImpls": [
                {"stepType": "test_resource_limits_fixture.sleep_async", "kind": "native", "implRef": "test.test_resource_limits_fixture.sleep_async"},
                {"stepType": "test_resource_limits_fixture.fail_on_cancel", "kind": "native", "implRef": "test.test_resource_limits_fixture.fail_on_cancel"},
                {"stepType": "test_resource_limits_fixture.report_deadline", "kind": "native", "implRef": "test.test_resource_limits_fixture.report_deadline"}
            ]
        }"#,
    )
    .expect("resource_limits test fixture registers");
    for m in manifests {
        k.register_plugin(m).expect("registration");
    }
    for j in json_manifests {
        k.register_plugin_from_json(j).expect("registration");
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
/// its work against the cancellation token. `params.shape` picks what
/// it answers the token with: `"cancelled"` is the typed
/// `StepError::Cancelled`; `"thrown"` a structured `PluginError` with
/// code `host_cancelled` and `"failed"` a plain failure whose message
/// merely mentions cancellation — the two ways a step can misreport
/// its own cancellation.
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
                "cancelled" => StepError::Cancelled,
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

/// Test-only step type that reports what the invocation it runs in
/// knows about its own wallclock deadline: whether it has one, and
/// how much of it is left. `remaining_ms` is `null` when uncapped.
fn report_deadline_step<'a>(
    ex: &'a mut (dyn PluginExecution + Send),
    _params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    let deadline = ex.wallclock_deadline();
    Box::pin(async move {
        let remaining_ms = deadline.map(|d| {
            d.saturating_duration_since(tokio::time::Instant::now())
                .as_millis() as u64
        });
        Ok(StepOutput::from(json!({
            "has_deadline": deadline.is_some(),
            "remaining_ms": remaining_ms,
        })))
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

/// The watchdog fires the token; the host step answers with the typed
/// `StepError::Cancelled`. The caller sees `ExecutionTimeout`: the
/// deadline is what stopped the action. (Gwead issue #1.)
#[tokio::test(flavor = "multi_thread")]
async fn deadline_remaps_typed_cancellation_to_execution_timeout() {
    let kernel = boot_with_limits(
        RuntimeLimits::default(),
        vec![manifest_with_action(
            "p",
            "go",
            fail_on_cancel_action("cancelled", 5_000, Some(80)),
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

/// A step that answers the token with a `PluginError` of its own is
/// reporting a failure, and a failure after the deadline is passed
/// through as what it says it is: the kernel does not guess that a
/// structured error "really meant" cancellation. The typed variant is
/// how a step says so.
#[tokio::test(flavor = "multi_thread")]
async fn deadline_passes_through_a_structured_error_that_is_not_typed_as_cancellation() {
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
        .expect_err("the step fails once the token fires");
    match err {
        KernelError::PluginError { code, .. } => assert_eq!(code, "host_cancelled"),
        other => panic!("expected the step's own PluginError, got: {other:?}"),
    }
}

/// Same for a plain failure whose message happens to mention
/// cancellation: text is not a type.
#[tokio::test(flavor = "multi_thread")]
async fn deadline_passes_through_a_plain_failure() {
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
        .expect_err("the step fails once the token fires");
    match err {
        KernelError::Execution(msg) => assert!(msg.contains("cancelled by token"), "{msg}"),
        other => panic!("expected the step's own Execution error, got: {other:?}"),
    }
}

/// `try` must not catch a cancellation. With an empty `catch` the
/// step's failure would be swallowed and the action would report
/// `Ok`; a typed cancellation escapes the `try` and the deadline is
/// reported.
#[tokio::test(flavor = "multi_thread")]
async fn try_does_not_swallow_a_typed_cancellation() {
    let mut a = action(vec![step(
        "guarded",
        "try",
        json!({
            "try": [{
                "id": "host",
                "type": "test_resource_limits_fixture.fail_on_cancel",
                "params": { "sleep_ms": 5_000u64, "shape": "cancelled" }
            }],
            "catch": []
        }),
    )]);
    a.wallclock_timeout_ms = Some(80);
    let kernel = boot_with_limits(
        RuntimeLimits::default(),
        vec![manifest_with_action("p", "go", a)],
    );

    let err = kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect_err("a cancelled step inside try must not be swallowed");
    match err {
        KernelError::ExecutionTimeout { timeout_ms } => assert_eq!(timeout_ms, 80),
        other => panic!("expected ExecutionTimeout, got: {other:?}"),
    }
}

/// Caller and callee manifests for the invoke-chain tests. The callee
/// races a host step against its token; the caller's `go` invokes it.
fn invoke_chain_manifests(callee_action: &str) -> [String; 2] {
    let callee = String::from(
        r#"{
            "name": "callee",
            "actions": {
                "go": {
                    "steps": [{"id": "host", "type": "test_resource_limits_fixture.fail_on_cancel",
                                "params": {"sleep_ms": 5000, "shape": "cancelled"}}]
                },
                "boom": {
                    "steps": [{"id": "bad", "type": "throw_error",
                                "params": {"code": "E_CALLEE", "message": "nope"}}]
                },
                "relay": {
                    "dataflow": true,
                    "steps": [{"id": "host", "type": "test_resource_limits_fixture.fail_on_cancel",
                                "params": {"sleep_ms": 5000, "shape": "cancelled"}, "longRunning": true}]
                }
            }
        }"#,
    );
    let caller = format!(
        r#"{{
            "name": "caller",
            "permissions": ["invoke:plugin:callee"],
            "actions": {{
                "go": {{
                    "wallclockTimeoutMs": 80,
                    "steps": [{{"id": "call", "type": "invoke",
                                "params": {{"plugin": "callee", "action": "{callee_action}", "input": {{}}}}}}]
                }},
                "go_uncapped": {{
                    "wallclockTimeoutMs": 10000,
                    "steps": [{{"id": "call", "type": "invoke",
                                "params": {{"plugin": "callee", "action": "{callee_action}", "input": {{}}}}}}]
                }}
            }}
        }}"#
    );
    [callee, caller]
}

/// The caller's deadline fires; its token propagates to the callee,
/// whose host step answers with the typed cancellation. The callee
/// resolves `Cancelled`, the `invoke` step carries that up as the
/// caller's own cancellation, and the caller's wrapper reports the
/// deadline — no flattening to text anywhere on the way.
#[tokio::test(flavor = "multi_thread")]
async fn callers_deadline_through_an_invoked_callee_is_execution_timeout() {
    let [callee, caller] = invoke_chain_manifests("go");
    let kernel = boot_with_config_and_json(
        KernelConfig::default().with_limits(RuntimeLimits::default()),
        vec![],
        &[&callee, &caller],
    );

    let err = kernel
        .execute("caller", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect_err("the caller's cap must trip");
    match err {
        KernelError::ExecutionTimeout { timeout_ms } => assert_eq!(timeout_ms, 80),
        other => panic!("expected ExecutionTimeout, got: {other:?}"),
    }
}

/// A callee's own failure reaches the caller intact: `CalleeFailed`
/// names the step and the callee, and `source` is the callee's
/// structured error, so the caller can branch on its code.
#[tokio::test(flavor = "multi_thread")]
async fn callee_failure_reaches_the_caller_typed() {
    let [callee, caller] = invoke_chain_manifests("boom");
    let kernel = boot_with_config_and_json(
        KernelConfig::default().with_limits(RuntimeLimits::default()),
        vec![],
        &[&callee, &caller],
    );

    let err = kernel
        .execute("caller", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect_err("the callee throws");
    let text = err.to_string();
    match err {
        KernelError::CalleeFailed {
            step_id,
            plugin,
            action,
            source,
        } => {
            assert_eq!(
                (step_id.as_str(), plugin.as_str(), action.as_str()),
                ("call", "callee", "boom")
            );
            match &*source {
                KernelError::PluginError { code, .. } => assert_eq!(code, "E_CALLEE"),
                other => panic!("expected the callee's PluginError as source, got: {other:?}"),
            }
        }
        other => panic!("expected CalleeFailed, got: {other:?}"),
    }
    assert!(
        text.contains("step 'call' → callee.boom failed: Plugin error E_CALLEE: nope"),
        "the message keeps the flattened shape a catch handler reads: {text}"
    );
}

/// The mirror image: the *caller* fires the token well inside the
/// deadline. The typed cancellation must stay `Cancelled` — the remap
/// is keyed on the watchdog having fired, not on the token. (The shape
/// must be one the remap would otherwise claim, or the test pins
/// nothing.)
#[tokio::test(flavor = "multi_thread")]
async fn caller_cancel_stays_cancelled() {
    let kernel = boot_with_limits(
        RuntimeLimits::default(),
        vec![manifest_with_action(
            "p",
            "go",
            fail_on_cancel_action("cancelled", 5_000, Some(10_000)),
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
        KernelError::Cancelled { at_step } => assert_eq!(at_step, "host"),
        other => panic!("expected Cancelled, got: {other:?}"),
    }
}

/// A `parallel` branch's step answers the deadline with the typed
/// cancellation. The branch task must carry it out as the `parallel`
/// step's own error rather than a failed branch, so the action reports
/// the deadline.
#[tokio::test(flavor = "multi_thread")]
async fn deadline_inside_a_parallel_branch_is_execution_timeout() {
    let mut a = action(vec![step(
        "fan",
        "parallel",
        json!({ "branches": [[{
            "id": "host",
            "type": "test_resource_limits_fixture.fail_on_cancel",
            "params": { "sleep_ms": 5_000u64, "shape": "cancelled" }
        }]] }),
    )]);
    a.wallclock_timeout_ms = Some(80);
    let kernel = boot_with_limits(
        RuntimeLimits::default(),
        vec![manifest_with_action("p", "go", a)],
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

/// The same swallow `try` must not perform, one nesting level down: a
/// cancelled step inside a `parallel` inside a `try` with an empty
/// `catch`. The caller's cancel must surface as `Cancelled`, not as an
/// `Ok` from the swallowed branch failure.
#[tokio::test(flavor = "multi_thread")]
async fn try_does_not_swallow_a_cancellation_inside_a_parallel_branch() {
    let a = action(vec![step(
        "guarded",
        "try",
        json!({
            "try": [{
                "id": "fan",
                "type": "parallel",
                "params": { "branches": [[{
                    "id": "host",
                    "type": "test_resource_limits_fixture.fail_on_cancel",
                    "params": { "sleep_ms": 5_000u64, "shape": "cancelled" }
                }]] }
            }],
            "catch": []
        }),
    )]);
    let kernel = boot_with_limits(
        RuntimeLimits::default(),
        vec![manifest_with_action("p", "go", a)],
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
        .expect_err("a cancelled branch inside try must not be swallowed");
    match err {
        KernelError::Cancelled { at_step } => assert_eq!(at_step, "host"),
        other => panic!("expected Cancelled, got: {other:?}"),
    }
}

/// A callee failure inside a `parallel` branch keeps its type: the
/// branch state's callee marker merges back so the `parallel` step
/// reports `CalleeFailed`, not the flattened string.
#[tokio::test(flavor = "multi_thread")]
async fn callee_failure_inside_a_parallel_branch_stays_typed() {
    let [callee, _] = invoke_chain_manifests("boom");
    let caller = r#"{
        "name": "caller",
        "permissions": ["invoke:plugin:callee"],
        "actions": {
            "go": {
                "steps": [{"id": "fan", "type": "parallel", "params": {"branches": [[
                    {"id": "call", "type": "invoke",
                     "params": {"plugin": "callee", "action": "boom", "input": {}}}
                ]]}}]
            }
        }
    }"#;
    let kernel = boot_with_config_and_json(
        KernelConfig::default().with_limits(RuntimeLimits::default()),
        vec![],
        &[&callee, caller],
    );

    let err = kernel
        .execute("caller", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect_err("the callee throws");
    match err {
        KernelError::CalleeFailed { source, .. } => match &*source {
            KernelError::PluginError { code, .. } => assert_eq!(code, "E_CALLEE"),
            other => panic!("expected the callee's PluginError as source, got: {other:?}"),
        },
        other => panic!("expected CalleeFailed, got: {other:?}"),
    }
}

/// The pipeline's deadline fires the pipeline's own token, which the
/// handle exposes, and leaves a token the caller shared untouched.
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_deadline_fires_the_handle_token_not_the_callers() {
    let mut a = action(vec![{
        let mut m = step(
            "sleep",
            "test_resource_limits_fixture.sleep_async",
            json!({ "sleep_ms": 5_000u64 }),
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

    let shared = tokio_util::sync::CancellationToken::new();
    let mut handle = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .with_cancel(shared.clone())
        .into_dataflow_handle()
        .expect("handle returned");
    let observed = handle.cancel_token();

    let err = handle
        .result
        .await
        .expect("result delivered")
        .expect_err("declared cap must trip");
    assert!(matches!(
        err,
        KernelError::ExecutionTimeout { timeout_ms: 80 }
    ));
    assert!(
        observed.is_cancelled(),
        "the handle's token observes the deadline"
    );
    assert!(
        !shared.is_cancelled(),
        "the caller's shared token is not this pipeline's to fire"
    );
    // Drain so the pipeline task's terminator is accounted for.
    while handle.events.recv().await.is_some() {}
}

/// The wind-down contract belongs to the handle path only. A dataflow
/// action driven through `run()` has no events channel and no handle;
/// a caller cancel there is `Err(Cancelled)` like any other action,
/// not an `Ok` whose output is the pre-provisioned stream handle id.
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_via_run_caller_cancel_is_cancelled() {
    let mut a = action(vec![{
        let mut m = step(
            "host",
            "test_resource_limits_fixture.fail_on_cancel",
            json!({ "sleep_ms": 5_000u64, "shape": "cancelled" }),
        );
        m.long_running = true;
        m
    }]);
    a.dataflow = true;
    let kernel = boot_with_limits(
        RuntimeLimits::default(),
        vec![manifest_with_action("p", "pipeline", a)],
    );

    let cancel = tokio_util::sync::CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        trigger.cancel();
    });

    let err = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .with_cancel(cancel)
        .run()
        .await
        .expect_err("a cancelled dataflow through run() is not a success");
    match err {
        KernelError::Cancelled { at_step } => assert_eq!(at_step, "host"),
        other => panic!("expected Cancelled, got: {other:?}"),
    }
}

/// Same through an `invoke`: a wave action whose step invokes a
/// dataflow callee, cancelled by the caller, is the caller's own
/// `Cancelled` — not an `Ok` from the callee's wind-down.
#[tokio::test(flavor = "multi_thread")]
async fn invoked_dataflow_callee_caller_cancel_is_cancelled() {
    let [callee, caller] = invoke_chain_manifests("relay");
    let kernel = boot_with_config_and_json(
        KernelConfig::default().with_limits(RuntimeLimits::default()),
        vec![],
        &[&callee, &caller],
    );

    let cancel = tokio_util::sync::CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        trigger.cancel();
    });

    let err = kernel
        .execute("caller", "go_uncapped", json!({}))
        .with_config(&Value::Null)
        .with_cancel(cancel)
        .run()
        .await
        .expect_err("a cancelled callee is the caller's cancellation");
    match err {
        KernelError::Cancelled { at_step } => assert_eq!(at_step, "call"),
        other => panic!("expected Cancelled, got: {other:?}"),
    }
}

/// The streaming handle holds the pipeline's child token too.
#[tokio::test(flavor = "multi_thread")]
async fn streaming_dataflow_deadline_fires_the_handle_token_not_the_callers() {
    let mut a = action(vec![{
        let mut m = step(
            "sleep",
            "test_resource_limits_fixture.sleep_async",
            json!({ "sleep_ms": 5_000u64 }),
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

    let shared = tokio_util::sync::CancellationToken::new();
    let handle = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .with_cancel(shared.clone())
        .into_dataflow_streaming_handle()
        .expect("streaming handle returned");
    let observed = handle.cancel_token();

    let err = handle
        .result
        .await
        .expect("result delivered")
        .expect_err("declared cap must trip");
    assert!(matches!(
        err,
        KernelError::ExecutionTimeout { timeout_ms: 80 }
    ));
    assert!(
        observed.is_cancelled(),
        "the handle's token observes the deadline"
    );
    assert!(
        !shared.is_cancelled(),
        "the caller's shared token is not this pipeline's to fire"
    );
}

/// A cancellation that reaches the dataflow scheduler as an `Err` —
/// here from a `try` wrapping the host step, whose escape turns the
/// step's `false` into `Err(Cancelled)` — winds down the same way as
/// the marker shape.
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_caller_cancel_through_a_try_resolves_ok() {
    let mut a = action(vec![{
        let mut m = step(
            "guarded",
            "try",
            json!({
                "try": [{
                    "id": "host",
                    "type": "test_resource_limits_fixture.fail_on_cancel",
                    "params": { "sleep_ms": 5_000u64, "shape": "cancelled" }
                }],
                "catch": []
            }),
        );
        m.long_running = true;
        m
    }]);
    a.dataflow = true;
    let kernel = boot_with_limits(
        RuntimeLimits::default(),
        vec![manifest_with_action("p", "pipeline", a)],
    );

    let handle = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .into_dataflow_handle()
        .expect("handle returned");
    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.cancel();
    handle
        .result
        .await
        .expect("result delivered")
        .expect("a caller cancel resolves Ok with partial results");
}

/// Branch failure precedence: the first failed branch in declaration
/// order is the `parallel` step's failure, even when a later branch
/// failed with a marker the error mapper would otherwise prefer.
#[tokio::test(flavor = "multi_thread")]
async fn first_failed_parallel_branch_wins_over_a_later_typed_one() {
    let [callee, _] = invoke_chain_manifests("boom");
    let caller = r#"{
        "name": "caller",
        "permissions": ["invoke:plugin:callee"],
        "actions": {
            "go": {
                "steps": [{"id": "fan", "type": "parallel", "params": {"branches": [
                    [{"id": "plain", "type": "throw_error",
                      "params": {"code": "E_FIRST", "message": "first"}}],
                    [{"id": "call", "type": "invoke",
                      "params": {"plugin": "callee", "action": "boom", "input": {}}}]
                ]}}]
            }
        }
    }"#;
    let kernel = boot_with_config_and_json(
        KernelConfig::default().with_limits(RuntimeLimits::default()),
        vec![],
        &[&callee, caller],
    );

    let err = kernel
        .execute("caller", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect_err("both branches fail");
    match err {
        KernelError::PluginError { code, .. } => assert_eq!(code, "E_FIRST"),
        other => panic!("expected the first branch's PluginError, got: {other:?}"),
    }
}

/// The `Err` arm of the wind-down gate: a cancellation reaching the
/// scheduler as `Err(Cancelled)` from a `try` is still `Cancelled`
/// through `run()`, where there is no handle contract.
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_via_run_caller_cancel_through_a_try_is_cancelled() {
    let mut a = action(vec![{
        let mut m = step(
            "guarded",
            "try",
            json!({
                "try": [{
                    "id": "host",
                    "type": "test_resource_limits_fixture.fail_on_cancel",
                    "params": { "sleep_ms": 5_000u64, "shape": "cancelled" }
                }],
                "catch": []
            }),
        );
        m.long_running = true;
        m
    }]);
    a.dataflow = true;
    let kernel = boot_with_limits(
        RuntimeLimits::default(),
        vec![manifest_with_action("p", "pipeline", a)],
    );

    let cancel = tokio_util::sync::CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        trigger.cancel();
    });

    let err = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .with_cancel(cancel)
        .run()
        .await
        .expect_err("a cancelled dataflow through run() is not a success");
    match err {
        KernelError::Cancelled { at_step } => assert_eq!(at_step, "host"),
        other => panic!("expected Cancelled, got: {other:?}"),
    }
}

/// A handle-driven dataflow parent whose producer invokes a dataflow
/// callee, cancelled by the caller. The callee has no events channel
/// and resolves `Cancelled`; the `invoke` step carries that up typed;
/// the parent is on the handle path and winds down: `Ok`, a
/// `StepCompleted { ok: false }` for the invoke step, no `StepFailed`,
/// and `PipelineCompleted { ok: false }` last.
#[tokio::test(flavor = "multi_thread")]
async fn handle_driven_dataflow_parent_invoking_a_dataflow_callee_winds_down() {
    let [callee, _] = invoke_chain_manifests("relay");
    let caller = r#"{
        "name": "caller",
        "permissions": ["invoke:plugin:callee"],
        "actions": {
            "pipeline": {
                "dataflow": true,
                "steps": [{"id": "call", "type": "invoke", "longRunning": true,
                           "params": {"plugin": "callee", "action": "relay", "input": {}}}]
            }
        }
    }"#;
    let kernel = boot_with_config_and_json(
        KernelConfig::default().with_limits(RuntimeLimits::default()),
        vec![],
        &[&callee, caller],
    );

    let mut handle = kernel
        .execute("caller", "pipeline", json!({}))
        .with_config(&json!({}))
        .into_dataflow_handle()
        .expect("handle returned");
    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.cancel();

    handle
        .result
        .await
        .expect("result delivered")
        .expect("a caller cancel on the handle path resolves Ok");

    let mut sequence = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(ev) = handle.events.recv().await {
            use gwead::kernel::DataflowEvent::*;
            match ev {
                StepCompleted { step_id, ok } => sequence.push(format!("completed:{step_id}:{ok}")),
                StepFailed { step_id, error } => {
                    panic!("no StepFailed on wind-down: {step_id}: {error}")
                }
                PipelineCompleted { ok } => sequence.push(format!("pipeline:{ok}")),
                _ => {}
            }
        }
    })
    .await
    .expect("events channel closes after the pipeline task exits");
    assert_eq!(sequence, ["completed:call:false", "pipeline:false"]);
}

// ---------------------------------------------------------------------------
// Callee wallclock budget
// ---------------------------------------------------------------------------

/// Caller and callee manifests for the callee-budget tests.
///
/// The callee offers `probe` (a dataflow action whose one long-running
/// step reports the deadline it runs under), `probe_plain` (the same
/// report from an ordinary action), `slow` (declares an 80 ms cap and
/// then ignores the token for 5 s) and `patient` (declares a generous
/// cap and ignores the token for 5 s). Each caller action invokes one
/// of them from under a different budget.
fn callee_budget_manifests() -> [&'static str; 2] {
    let callee = r#"{
        "name": "callee",
        "actions": {
            "probe": {
                "dataflow": true,
                "steps": [{"id": "report", "type": "test_resource_limits_fixture.report_deadline",
                            "params": {}, "longRunning": true}]
            },
            "probe_plain": {
                "steps": [{"id": "report", "type": "test_resource_limits_fixture.report_deadline",
                            "params": {}}]
            },
            "slow": {
                "wallclockTimeoutMs": 80,
                "steps": [{"id": "nap", "type": "test_resource_limits_fixture.sleep_async",
                            "params": {"sleep_ms": 5000}}]
            },
            "patient": {
                "wallclockTimeoutMs": 10000,
                "steps": [{"id": "nap", "type": "test_resource_limits_fixture.sleep_async",
                            "params": {"sleep_ms": 5000}}]
            }
        }
    }"#;
    let caller = r#"{
        "name": "caller",
        "permissions": ["invoke:plugin:callee"],
        "actions": {
            "probe_after_work": {
                "wallclockTimeoutMs": 10000,
                "steps": [
                    {"id": "work", "type": "test_resource_limits_fixture.sleep_async",
                     "params": {"sleep_ms": 100}},
                    {"id": "call", "type": "invoke",
                     "params": {"plugin": "callee", "action": "probe", "input": {}}}
                ]
            },
            "probe_from_pipeline": {
                "dataflow": true,
                "steps": [{"id": "call", "type": "invoke", "longRunning": true,
                            "params": {"plugin": "callee", "action": "probe", "input": {}}}]
            },
            "plain_probe_from_pipeline": {
                "dataflow": true,
                "steps": [{"id": "call", "type": "invoke", "longRunning": true,
                            "params": {"plugin": "callee", "action": "probe_plain", "input": {}}}]
            },
            "slow_under_ten_seconds": {
                "wallclockTimeoutMs": 10000,
                "steps": [{"id": "call", "type": "invoke",
                            "params": {"plugin": "callee", "action": "slow", "input": {}}}]
            },
            "slow_caught": {
                "wallclockTimeoutMs": 10000,
                "steps": [{"id": "guard", "type": "try", "params": {
                    "try": [{"id": "call", "type": "invoke",
                             "params": {"plugin": "callee", "action": "slow", "input": {}}}],
                    "catch": [{"id": "recovered", "type": "let",
                               "params": {"value": "{{$.error}}"}}]
                }}]
            },
            "patient_under_eighty_ms": {
                "wallclockTimeoutMs": 80,
                "steps": [{"id": "call", "type": "invoke",
                            "params": {"plugin": "callee", "action": "patient", "input": {}}}]
            }
        }
    }"#;
    [callee, caller]
}

fn boot_callee_budget() -> Arc<Kernel> {
    let [callee, caller] = callee_budget_manifests();
    boot_with_config_and_json(
        KernelConfig::default().with_limits(RuntimeLimits::default()),
        vec![],
        &[callee, caller],
    )
}

/// The decision tree's own two automatic cases, seen from inside the
/// action: a top-level action under the deployment default has a
/// deadline, and a top-level dataflow action with no declaration has
/// none. These are the baselines the callee tests below differ from.
#[tokio::test(flavor = "multi_thread")]
async fn top_level_invocation_reports_its_deadline() {
    let probe = |dataflow: bool| {
        let mut a = action(vec![{
            let mut m = step(
                "report",
                "test_resource_limits_fixture.report_deadline",
                json!({}),
            );
            m.long_running = dataflow;
            m
        }]);
        a.dataflow = dataflow;
        a
    };
    let kernel = boot_with_limits(
        RuntimeLimits::default().with_default_wallclock_timeout(Duration::from_secs(10)),
        vec![
            manifest_with_action("plain", "go", probe(false)),
            manifest_with_action("pipeline", "go", probe(true)),
        ],
    );

    let plain = kernel
        .execute("plain", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("runs");
    assert_eq!(plain.output["has_deadline"], json!(true));
    let remaining = plain.output["remaining_ms"].as_u64().expect("a number");
    assert!(
        (5_000..=10_000).contains(&remaining),
        "a top-level action under a 10 s default sees roughly that budget: {remaining}"
    );

    let pipeline = kernel
        .execute("pipeline", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("runs");
    assert_eq!(pipeline.output["has_deadline"], json!(false));
    assert_eq!(pipeline.output["remaining_ms"], Value::Null);
}

/// A dataflow callee that declares nothing does not get the top-level
/// dataflow uncap: it runs under whatever its caller has left. The
/// caller spends 100 ms of its 10 s before invoking, so the callee sees
/// a budget below 10 s.
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_callee_inherits_the_callers_remaining_budget() {
    let kernel = boot_callee_budget();

    let result = kernel
        .execute("caller", "probe_after_work", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect("both actions complete");
    let report = &result.step_results["call"];
    assert_eq!(report["has_deadline"], json!(true), "report: {report}");
    let remaining = report["remaining_ms"].as_u64().expect("a number");
    assert!(
        (5_000..=9_900).contains(&remaining),
        "the callee's budget is the caller's 10 s less the 100 ms already spent: {remaining}"
    );
}

/// A callee of an uncapped caller — a top-level dataflow pipeline with
/// no declaration and no operator ceiling — has no budget to inherit,
/// and declares nothing itself, so it runs uncapped too.
#[tokio::test(flavor = "multi_thread")]
async fn callee_of_an_uncapped_caller_is_uncapped() {
    let kernel = boot_callee_budget();

    let mut handle = kernel
        .execute("caller", "probe_from_pipeline", json!({}))
        .with_config(&json!({}))
        .into_dataflow_handle()
        .expect("handle returned");
    let result = handle
        .result
        .await
        .expect("result delivered")
        .expect("pipeline completes");
    while let Some(ev) = handle.events.recv().await {
        if let gwead::kernel::DataflowEvent::PipelineCompleted { ok } = ev {
            assert!(ok);
        }
    }
    let report = &result.step_results["call"];
    assert_eq!(report["has_deadline"], json!(false), "report: {report}");
    assert_eq!(report["remaining_ms"], Value::Null);
}

/// The other half of the uncapped-caller rule: with no budget to
/// inherit, a callee is bounded as it would be at top level. A plain
/// callee therefore gets the deployment default (60 s here), which is
/// what the same action would get if it were run directly.
#[tokio::test(flavor = "multi_thread")]
async fn plain_callee_of_an_uncapped_caller_gets_the_deployment_default() {
    let kernel = boot_callee_budget();

    let mut handle = kernel
        .execute("caller", "plain_probe_from_pipeline", json!({}))
        .with_config(&json!({}))
        .into_dataflow_handle()
        .expect("handle returned");
    let result = handle
        .result
        .await
        .expect("result delivered")
        .expect("pipeline completes");
    while handle.events.recv().await.is_some() {}
    let report = &result.step_results["call"];
    assert_eq!(report["has_deadline"], json!(true), "report: {report}");
    let remaining = report["remaining_ms"].as_u64().expect("a number");
    assert!(
        (30_000..=60_000).contains(&remaining),
        "the deployment default of 60 s applies: {remaining}"
    );
}

/// A callee's own `wallclockTimeoutMs` is enforced by a watchdog of
/// its own, whoever invokes it. The callee declares 80 ms and ignores
/// the token; the caller has ten seconds. The callee is dropped at its
/// cap and the caller sees that as the callee's failure — typed, and
/// long before the caller's own deadline.
#[tokio::test(flavor = "multi_thread")]
async fn callee_declared_cap_applies_under_a_longer_caller() {
    let kernel = boot_callee_budget();

    let started = std::time::Instant::now();
    let err = kernel
        .execute("caller", "slow_under_ten_seconds", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect_err("the callee's cap trips");
    let elapsed = started.elapsed();
    match err {
        KernelError::CalleeFailed {
            step_id,
            plugin,
            action,
            source,
        } => {
            assert_eq!(
                (step_id.as_str(), plugin.as_str(), action.as_str()),
                ("call", "callee", "slow")
            );
            match &*source {
                KernelError::ExecutionTimeout { timeout_ms } => assert_eq!(*timeout_ms, 80),
                other => panic!("expected the callee's ExecutionTimeout as source, got: {other:?}"),
            }
        }
        other => panic!("expected CalleeFailed, got: {other:?}"),
    }
    assert!(
        elapsed < Duration::from_secs(2),
        "the callee's own backstop ended it, not the caller's 10 s: {elapsed:?}"
    );
}

/// The callee's deadline fires a child of the caller's token, so it
/// is a failed step in the caller and nothing more: a `try` around the
/// invoke catches it, the handler sees the callee's error, and the
/// caller completes — it was never cancelled.
#[tokio::test(flavor = "multi_thread")]
async fn callee_deadline_is_a_step_failure_the_caller_can_catch() {
    let kernel = boot_callee_budget();

    let started = std::time::Instant::now();
    let result = kernel
        .execute("caller", "slow_caught", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect("the caller catches its callee's deadline and completes");
    let recovered = result.step_results["recovered"]
        .as_str()
        .expect("the handler stored the error text");
    assert!(
        recovered.contains("callee.slow failed")
            && recovered.contains("wallclock timeout exceeded (80 ms)"),
        "the handler sees the callee's deadline: {recovered}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the callee was ended at its 80 ms cap"
    );
}

/// The other direction of the clamp: a callee cannot outlive its
/// caller by declaring more. The callee asks for ten seconds; the
/// caller has 80 ms; the caller's deadline is what fires.
#[tokio::test(flavor = "multi_thread")]
async fn callee_cannot_outlive_its_caller_by_declaring_more() {
    let kernel = boot_callee_budget();

    let err = kernel
        .execute("caller", "patient_under_eighty_ms", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect_err("the caller's cap trips");
    match err {
        KernelError::ExecutionTimeout { timeout_ms } => assert_eq!(timeout_ms, 80),
        other => panic!("expected the caller's ExecutionTimeout, got: {other:?}"),
    }
}

/// Caller manifest for the finally-supersedes tests: each action's
/// `try` body throws, and its `finally` runs a `parallel` whose one
/// branch fails in a different way.
fn finally_parallel_caller() -> &'static str {
    r#"{
        "name": "caller",
        "permissions": ["invoke:plugin:callee"],
        "actions": {
            "thrown": {
                "steps": [{"id": "guarded", "type": "try", "params": {
                    "try": [{"id": "body", "type": "throw_error",
                             "params": {"code": "E_TRY", "message": "from the try body"}}],
                    "finally": [{"id": "fan", "type": "parallel", "params": {"branches": [
                        [{"id": "fin", "type": "throw_error",
                          "params": {"code": "E_FIN", "message": "from finally"}}]
                    ]}}]
                }}]
            },
            "callee": {
                "steps": [{"id": "guarded", "type": "try", "params": {
                    "try": [{"id": "body", "type": "throw_error",
                             "params": {"code": "E_TRY", "message": "from the try body"}}],
                    "finally": [{"id": "fan", "type": "parallel", "params": {"branches": [
                        [{"id": "call", "type": "invoke",
                          "params": {"plugin": "callee", "action": "boom", "input": {}}}]
                    ]}}]
                }}]
            }
        }
    }"#
}

/// A `parallel` inside a `finally` supersedes the failure the `try`
/// body left behind, the way a direct step in the `finally` does: the
/// merge must take the first failed branch's markers over whatever the
/// canonical state already held. Here the branch throws.
#[tokio::test(flavor = "multi_thread")]
async fn parallel_in_finally_supersedes_the_try_bodys_failure_with_a_thrown_error() {
    let [callee, _] = invoke_chain_manifests("boom");
    let kernel = boot_with_config_and_json(
        KernelConfig::default().with_limits(RuntimeLimits::default()),
        vec![],
        &[&callee, finally_parallel_caller()],
    );

    let err = kernel
        .execute("caller", "thrown", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect_err("the finally's branch throws");
    match err {
        KernelError::PluginError { code, .. } => assert_eq!(code, "E_FIN"),
        other => panic!("expected the finally branch's PluginError, got: {other:?}"),
    }
}

/// Same, with the branch's failure being a callee's: the typed error
/// must survive the merge too.
#[tokio::test(flavor = "multi_thread")]
async fn parallel_in_finally_supersedes_the_try_bodys_failure_with_a_callee_error() {
    let [callee, _] = invoke_chain_manifests("boom");
    let kernel = boot_with_config_and_json(
        KernelConfig::default().with_limits(RuntimeLimits::default()),
        vec![],
        &[&callee, finally_parallel_caller()],
    );

    let err = kernel
        .execute("caller", "callee", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect_err("the finally's branch callee throws");
    match err {
        KernelError::CalleeFailed { source, .. } => match &*source {
            KernelError::PluginError { code, .. } => assert_eq!(code, "E_CALLEE"),
            other => panic!("expected the callee's PluginError as source, got: {other:?}"),
        },
        other => panic!("expected CalleeFailed, got: {other:?}"),
    }
}

/// A dataflow step that answers the *caller's* cancel with the typed
/// cancellation gets the handle's documented contract: `Ok` with
/// whatever was written and `PipelineCompleted { ok: false }`, not an
/// error.
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_caller_cancel_with_typed_cancellation_resolves_ok() {
    let mut a = action(vec![{
        let mut m = step(
            "host",
            "test_resource_limits_fixture.fail_on_cancel",
            json!({ "sleep_ms": 5_000u64, "shape": "cancelled" }),
        );
        m.long_running = true;
        m
    }]);
    a.dataflow = true;
    let kernel = boot_with_limits(
        RuntimeLimits::default(),
        vec![manifest_with_action("p", "pipeline", a)],
    );

    let mut handle = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .into_dataflow_handle()
        .expect("handle returned");
    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.cancel();

    handle
        .result
        .await
        .expect("result delivered")
        .expect("a caller cancel resolves Ok with partial results");

    let mut saw_not_ok_terminator = false;
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(ev) = handle.events.recv().await {
            match ev {
                gwead::kernel::DataflowEvent::PipelineCompleted { ok } => {
                    saw_not_ok_terminator = !ok;
                }
                gwead::kernel::DataflowEvent::StepFailed { step_id, .. } => {
                    panic!("a cancelled step is not a failed one: {step_id}");
                }
                _ => {}
            }
        }
    })
    .await
    .expect("events channel closes after the pipeline task exits");
    assert!(saw_not_ok_terminator);
}

/// Dataflow with a step that answers the token with the typed
/// cancellation. The watchdog fires first and the backstop only after
/// its grace window, so the step winds down, the scheduler emits its
/// own `PipelineCompleted { ok: false }` and resolves `Ok` with partial
/// results, and the wrapper turns that `Ok` into `ExecutionTimeout`.
/// The handle must deliver exactly ONE terminator: the substitute emit
/// is for a dropped future only, not for any `ExecutionTimeout`
/// result. (Keying the substitute on the result delivers two here.)
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_deadline_answered_by_step_emits_one_terminator() {
    let mut a = action(vec![{
        let mut m = step(
            "host",
            "test_resource_limits_fixture.fail_on_cancel",
            json!({ "sleep_ms": 5_000u64, "shape": "cancelled" }),
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
