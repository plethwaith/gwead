//! Cancellation reaches inside control-flow bodies.
//!
//! The scheduler polls the cancellation token between top-level
//! steps, and the nested executors — `run_try`, `run_ifs`,
//! `run_iteration` (backing both `for_each` and `repeat`), and each
//! `run_parallel` branch — must poll it too rather than calling
//! `run_step` blindly. Without those polls a manifest that put its
//! work inside a loop or a `try`, which is the normal shape for
//! long-running work, would be uncancellable, and would return `Ok`
//! rather than `Cancelled` after running every step to completion.
//!
//! The same polls are what make the wallclock backstop work.
//! `with_wallclock_timeout` wraps a `tokio::time::timeout`, which
//! cannot preempt a future that never returns `Pending`; a `repeat`
//! body of pure `let` steps never yields, so without the polls
//! neither the kernel's deadline nor a caller's own
//! `tokio::time::timeout` could fire, and a `repeat` of millions of
//! iterations would run to completion pinning a worker throughout.
//!
//! Each test below runs a large body, cancels partway, and asserts the
//! action stops promptly *and reports `Cancelled`* — reporting success
//! after a cancel is its own bug, since a caller cannot then tell
//! "cancelled" from "completed".

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use gwead::kernel::native_impls::NativeStepImplTable;
use gwead::kernel::types::{Action, PluginManifest};
use gwead::kernel::{Kernel, KernelConfig, KernelError, PluginExecution, StepError, StepOutput};
use gwead::serde_json::{Value, json};
use indexmap::IndexMap;
use tokio_util::sync::CancellationToken;

/// Test-only step type that sleeps for a few milliseconds.
///
/// A `let` step is far too fast to test cancellation with: 2000 of
/// them complete in under 4 ms, so the run finishes before any
/// realistic cancel could fire and the test would pass against a
/// kernel that never polls. This gives each step enough duration that
/// an unpolled body demonstrably overruns the cancel.
///
/// It deliberately does NOT check the token itself — the point is that
/// the *scheduler* stops the action between steps even when every
/// individual body ignores cancellation.
fn slow_step<'a>(
    _ex: &'a mut (dyn PluginExecution + Send),
    _params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move {
        tokio::time::sleep(Duration::from_millis(STEP_MS)).await;
        Ok(StepOutput::from(json!(true)))
    })
}

/// Per-step duration. `BODY_STEPS * STEP_MS` is the uncancelled
/// runtime, which must be comfortably above `MUST_RETURN_WITHIN`.
const STEP_MS: u64 = 5;

/// 400 x 5 ms = ~2 s uncancelled, so a prompt return is unambiguous
/// rather than a timing coincidence.
const BODY_STEPS: usize = 400;
const CANCEL_AFTER: Duration = Duration::from_millis(200);
/// A polled body returns within one step of the cancel (~205 ms), but
/// CI machines are noisy. An unpolled body runs the full ~2 s, so this
/// still separates polled from unpolled by ~2.5x.
const MUST_RETURN_WITHIN: Duration = Duration::from_millis(800);

fn noop_step(id: &str) -> serde_json::Value {
    json!({"id": id, "type": "cancellation_fixture.slow"})
}

fn body_steps() -> Vec<serde_json::Value> {
    (0..BODY_STEPS)
        .map(|i| noop_step(&format!("s{i}")))
        .collect()
}

fn action_from(steps: serde_json::Value) -> Action {
    serde_json::from_value(json!({"steps": steps})).expect("action deserialises")
}

fn boot(action: Action) -> Arc<Kernel> {
    let mut impls = NativeStepImplTable::empty();
    impls
        .insert("test.cancellation_fixture.slow", slow_step)
        .expect("fresh table");
    let mut k =
        Kernel::boot(KernelConfig::default().with_native_step_impls(impls)).expect("kernel boots");
    k.register_plugin_from_json(
        r#"{
            "name": "cancellation_fixture",
            "version": "0.0.0",
            "description": "Wires the test-only `slow` step type.",
            "stepTypeDefs": [{"name": "cancellation_fixture.slow", "freelyUsable": true}],
            "stepTypeImpls": [
                {"stepType": "cancellation_fixture.slow", "kind": "native",
                 "implRef": "test.cancellation_fixture.slow"}
            ]
        }"#,
    )
    .expect("fixture registers");

    let mut actions = IndexMap::new();
    actions.insert("go".to_string(), action);
    let manifest = {
        let mut m = PluginManifest::new("p".to_string());
        m.permissions = vec!["step_type:cancellation_fixture.slow".to_string()];
        m.actions = actions;
        m
    };
    k.register_plugin(manifest).expect("registers");
    k.into_arc()
}

/// Run `action`, firing the cancel token after [`CANCEL_AFTER`].
/// Returns how long the run took and what it produced.
async fn run_cancelled(action: Action) -> (Duration, Result<(), KernelError>) {
    run_cancelled_with(action, json!({})).await
}

async fn run_cancelled_with(
    action: Action,
    input: serde_json::Value,
) -> (Duration, Result<(), KernelError>) {
    let kernel = boot(action);
    let cancel = CancellationToken::new();
    let fired = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(CANCEL_AFTER).await;
        fired.cancel();
    });

    let started = Instant::now();
    let result = kernel
        .execute("p", "go", input)
        .with_config(&json!({}))
        .with_cancel(cancel)
        .run()
        .await;
    (started.elapsed(), result.map(|_| ()))
}

fn assert_cancelled_promptly(label: &str, elapsed: Duration, result: Result<(), KernelError>) {
    match result {
        Err(KernelError::Cancelled { .. }) => {}
        other => panic!(
            "{label}: expected Cancelled after {elapsed:?}, got {other:?} — \
             a run that ignores the token and reports success is \
             indistinguishable from one that finished normally"
        ),
    }
    assert!(
        elapsed < MUST_RETURN_WITHIN,
        "{label}: took {elapsed:?}, which means the token was not polled \
         inside the body"
    );
}

/// Baseline: the top-level path. If this regresses, the nested cases
/// below are testing nothing.
#[tokio::test(flavor = "multi_thread")]
async fn top_level_steps_honour_cancellation() {
    let (elapsed, result) = run_cancelled(action_from(json!(body_steps()))).await;
    assert_cancelled_promptly("top-level", elapsed, result);
}

#[tokio::test(flavor = "multi_thread")]
async fn repeat_body_honours_cancellation() {
    let action = action_from(
        json!([{"id": "loop", "type": "repeat", "params": {"count": BODY_STEPS, "steps": [noop_step("body")]}}]),
    );
    let (elapsed, result) = run_cancelled(action).await;
    assert_cancelled_promptly("repeat", elapsed, result);
}

#[tokio::test(flavor = "multi_thread")]
async fn for_each_body_honours_cancellation() {
    // `for_each` takes a DSL `path` selecting the array, so the items
    // come in as action input rather than inline.
    let action = action_from(
        json!([{"id": "loop", "type": "for_each", "params": {"path": "$input.items", "steps": [noop_step("body")]}}]),
    );
    let items: Vec<usize> = (0..BODY_STEPS).collect();
    let (elapsed, result) = run_cancelled_with(action, json!({"items": items})).await;
    assert_cancelled_promptly("for_each", elapsed, result);
}

#[tokio::test(flavor = "multi_thread")]
async fn try_body_honours_cancellation() {
    let action = action_from(
        json!([{"id": "t", "type": "try", "params": {"try": body_steps(), "catch": []}}]),
    );
    let (elapsed, result) = run_cancelled(action).await;
    assert_cancelled_promptly("try", elapsed, result);
}

#[tokio::test(flavor = "multi_thread")]
async fn if_branch_honours_cancellation() {
    let action = action_from(
        json!([{"id": "i", "type": "ifs", "params": {"ifs": [{"test": "true", "then": body_steps()}]}}]),
    );
    let (elapsed, result) = run_cancelled(action).await;
    assert_cancelled_promptly("ifs", elapsed, result);
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_branches_honour_cancellation() {
    // Step ids must be unique ACROSS branches — branches merge into
    // one result keyspace.
    let branch = |b: usize| -> Vec<serde_json::Value> {
        (0..BODY_STEPS / 4)
            .map(|i| noop_step(&format!("b{b}_{i}")))
            .collect()
    };
    let action = action_from(
        json!([{"id": "par", "type": "parallel", "params": {"branches": [branch(0), branch(1), branch(2), branch(3)]}}]),
    );
    let (elapsed, result) = run_cancelled(action).await;
    assert_cancelled_promptly("parallel", elapsed, result);
}

/// Anti-over-cancellation companion: with no token fired, every shape
/// above must still run to completion. Without this the tests could be
/// satisfied by a kernel that cancels everything unconditionally.
#[tokio::test(flavor = "multi_thread")]
async fn an_uncancelled_nested_body_still_completes() {
    let action = action_from(
        json!([{"id": "loop", "type": "repeat", "params": {"count": 10, "steps": [noop_step("body")]}}]),
    );
    let kernel = boot(action);
    kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("a run with no cancel must complete normally");
}
