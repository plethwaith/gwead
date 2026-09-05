//! Step results are the only unbounded host allocation a manifest
//! controls, and they compose.
//!
//! A step may reference an earlier result more than once, so a chain of
//! `let` steps holding `"{{$steps.prev.result}}{{$steps.prev.result}}"`
//! doubles per line: two dozen such lines reach over a hundred
//! megabytes in a fraction of a second, a few more reach terabytes,
//! and nothing in registration objects.
//!
//! Nothing else catches it. No wasm limit applies, because nothing runs
//! in wasm — this is host-side `serde_json`. The wallclock does not
//! apply either: the attack is fast, not slow. That combination is why
//! it gets its own bound rather than leaning on an existing one.
//!
//! The budget is cumulative. Capping a single value would still leave
//! as many values as the manifest has steps, and it is the total the
//! host has to hold.

use gwead::kernel::{Kernel, KernelConfig, KernelError, RuntimeLimits};
use serde_json::{Value, json};

/// `lines` steps, each doubling the previous one's result.
fn doubling_chain(lines: usize) -> String {
    let mut steps =
        vec![json!({"id": "s0", "type": "let", "params": {"value": "AAAAAAAAAAAAAAAA"}})];
    for i in 1..lines {
        steps.push(
            json!({"id": format!("s{i}"), "type": "let", "params": {"value": format!(
                "{{{{$steps.s{prev}.result}}}}{{{{$steps.s{prev}.result}}}}",
                prev = i - 1
            )}}),
        );
    }
    let last = format!("s{}", lines - 1);
    json!({
        "name": "p",
        "actions": { "go": {
            "steps": steps,
            "resultMapping": { "out": { "path": "$", "source": last } }
        } }
    })
    .to_string()
}

/// Register `manifest` under `limits` and run its `go` action.
async fn run_manifest(manifest: &str, limits: RuntimeLimits) -> Result<Value, KernelError> {
    let mut k = Kernel::boot(KernelConfig::default().with_limits(limits)).expect("boot");
    k.register_plugin_from_json(manifest)
        .expect("the manifest is well-formed; the budget is a runtime bound");
    k.into_arc()
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .map(|r| r.output)
}

async fn run_chain(lines: usize, limits: RuntimeLimits) -> Result<Value, KernelError> {
    run_manifest(&doubling_chain(lines), limits).await
}

/// The invocation ended on the budget, with the limit it ran under and
/// an attempted size past it.
fn assert_budget_error(err: KernelError, limit: usize) -> usize {
    match err {
        KernelError::StepResultsLimitExceeded {
            limit_bytes,
            attempted_bytes,
        } => {
            assert_eq!(limit_bytes, limit);
            assert!(attempted_bytes > limit, "{attempted_bytes}");
            attempted_bytes
        }
        other => panic!("expected StepResultsLimitExceeded, got: {other:?}"),
    }
}

/// A refused result ends the invocation with the typed error. It does
/// not return an output missing the step, which would be a silent
/// wrong answer in the budget's place.
#[tokio::test(flavor = "multi_thread")]
async fn a_doubling_chain_is_stopped_by_the_budget() {
    let started = std::time::Instant::now();
    let err = run_chain(24, RuntimeLimits::default())
        .await
        .expect_err("24 doublings from 16 bytes is 134 MB");
    assert_budget_error(err, RuntimeLimits::default().max_step_results_bytes);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the budget bites while the chain is still cheap, which is the \
         point — this attack is fast, so no timeout would have caught it"
    );
}

/// The bound is the *total*, not one value: a chain that stays under
/// the cap per step but sums past it is still refused. A per-value cap
/// would have let this through.
#[tokio::test(flavor = "multi_thread")]
async fn the_budget_is_cumulative_across_steps() {
    // Each step here is ~1 MiB; twelve of them exceed a 4 MiB budget
    // while no single one comes close.
    let chunk = "x".repeat(1024 * 1024);
    let mut steps = Vec::new();
    for i in 0..12 {
        steps.push(json!({"id": format!("s{i}"), "type": "let", "params": {"value": chunk}}));
    }
    let manifest = json!({
        "name": "p",
        "actions": { "go": {
            "steps": steps,
            "resultMapping": { "out": { "path": "$", "source": "s0" } }
        } }
    })
    .to_string();

    let err = run_manifest(
        &manifest,
        RuntimeLimits::default().with_max_step_results_bytes(4 * 1024 * 1024),
    )
    .await
    .expect_err("twelve 1 MiB results do not fit in 4 MiB");
    assert_budget_error(err, 4 * 1024 * 1024);
}

/// Ordinary manifests must not notice. The default is 64 MiB; a chain
/// that stays well inside it runs untouched.
#[tokio::test(flavor = "multi_thread")]
async fn an_ordinary_chain_is_unaffected() {
    let output = run_chain(12, RuntimeLimits::default())
        .await
        .expect("12 doublings from 16 bytes is 64 KiB");
    assert_eq!(
        output["out"].as_str().map(str::len),
        Some(16 * 2usize.pow(11))
    );
}

/// Raising the budget is the escape hatch for an action that
/// legitimately holds a lot, and the error message names it.
#[tokio::test(flavor = "multi_thread")]
async fn the_budget_is_the_operators_to_set() {
    let limits = RuntimeLimits::default().with_max_step_results_bytes(1024);
    let err = run_chain(12, limits)
        .await
        .expect_err("64 KiB over 1 KiB")
        .to_string();
    assert!(
        err.contains("max_step_results_bytes"),
        "the message names the knob: {err}"
    );

    run_chain(
        12,
        RuntimeLimits::default().with_max_step_results_bytes(1024 * 1024),
    )
    .await
    .expect("the same chain fits once the operator allows it");
}

// ---------------------------------------------------------------------------
// Catchability
// ---------------------------------------------------------------------------
//
// The budget is the kernel's cap, not the manifest's logic, so a
// violation is not a step failure a `try` may recover from: it ends the
// invocation the way a cancellation does, in every nesting. A handler
// that caught it would see a refused result and carry on as if the step
// had run.

/// The budget the catchability tests run under.
const GUARDED_BUDGET: usize = 1024;

/// A `let` four times the guarded budget.
fn over_budget_let() -> Value {
    json!({"id": "big", "type": "let", "params": {"value": "x".repeat(4 * GUARDED_BUDGET)}})
}

/// `body` inside a `try` whose handler would recover from any ordinary
/// failure.
fn guarded(body: Value) -> Value {
    json!({
        "id": "guarded",
        "type": "try",
        "params": {
            "try": [body],
            "catch": [{"id": "recovered", "type": "let", "params": {"value": "swallowed"}}]
        }
    })
}

/// Run one step as the whole action, under [`GUARDED_BUDGET`]. A
/// dataflow action needs a long-running producer to be one; a tiny
/// `let` serves, and is charged well inside the budget.
async fn run_guarded(step: Value, dataflow: bool) -> Result<Value, KernelError> {
    let mut steps = vec![step];
    if dataflow {
        steps.push(
            json!({"id": "prod", "type": "let", "params": {"value": "p"}, "longRunning": true}),
        );
    }
    let manifest = json!({
        "name": "p",
        "actions": { "go": {
            "dataflow": dataflow,
            "steps": steps,
            "resultMapping": { "out": { "path": "$", "source": "guarded" } }
        } }
    })
    .to_string();
    run_manifest(
        &manifest,
        RuntimeLimits::default().with_max_step_results_bytes(GUARDED_BUDGET),
    )
    .await
}

/// The refused value was charged in full: the attempted size is at
/// least the payload, not merely past the limit.
fn assert_guarded_error(err: KernelError) {
    let attempted = assert_budget_error(err, GUARDED_BUDGET);
    assert!(attempted >= 4 * GUARDED_BUDGET, "{attempted}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_budget_violation_escapes_try() {
    let err = run_guarded(guarded(over_budget_let()), false)
        .await
        .expect_err("a resource cap is not catchable");
    assert_guarded_error(err);
}

/// Inside a `parallel` branch the violation reaches the `try` through
/// the branch join rather than the step directly.
#[tokio::test(flavor = "multi_thread")]
async fn a_budget_violation_inside_a_parallel_branch_escapes_try() {
    let err = run_guarded(
        guarded(json!({
            "id": "fan",
            "type": "parallel",
            "params": {"branches": [[over_budget_let()]]}
        })),
        false,
    )
    .await
    .expect_err("a resource cap is not catchable through a parallel branch either");
    assert_guarded_error(err);
}

/// Inside a loop body it reaches the `try` through the iteration.
#[tokio::test(flavor = "multi_thread")]
async fn a_budget_violation_inside_a_loop_escapes_try() {
    let err = run_guarded(
        guarded(json!({
            "id": "loop",
            "type": "repeat",
            "params": {"count": 1, "steps": [over_budget_let()]}
        })),
        false,
    )
    .await
    .expect_err("a resource cap is not catchable through a loop either");
    assert_guarded_error(err);
}

/// Inside a taken `ifs` branch it reaches the `try` through the branch.
#[tokio::test(flavor = "multi_thread")]
async fn a_budget_violation_inside_an_ifs_branch_escapes_try() {
    let err = run_guarded(
        guarded(json!({
            "id": "route",
            "type": "ifs",
            "params": {"ifs": [{"test": "true", "then": [over_budget_let()]}]}
        })),
        false,
    )
    .await
    .expect_err("a resource cap is not catchable through an ifs branch either");
    assert_guarded_error(err);
}

/// Under the dataflow scheduler the `try` runs inside a spawned task,
/// and the task's error is the pipeline's.
#[tokio::test(flavor = "multi_thread")]
async fn a_budget_violation_in_a_dataflow_task_escapes_try() {
    let err = run_guarded(guarded(over_budget_let()), true)
        .await
        .expect_err("a resource cap is not catchable inside a dataflow task either");
    assert_guarded_error(err);
}

/// An error that ends the invocation unwinds past `finally` as well,
/// as a cancellation does: a `finally` that would otherwise supersede
/// the failure with its own thrown error never runs, and the budget
/// error is what comes out. (`finally` after a failed step is pinned
/// in `intrinsics_tests`.)
#[tokio::test(flavor = "multi_thread")]
async fn a_budget_violation_skips_finally() {
    let err = run_guarded(
        json!({
            "id": "guarded",
            "type": "try",
            "params": {
                "try": [over_budget_let()],
                "finally": [{"id": "cleanup", "type": "throw_error", "params": {"code": "E_FINALLY", "message": "ran"}}]
            }
        }),
        false,
    )
    .await
    .expect_err("the invocation ends on the budget");
    assert_guarded_error(err);
}
