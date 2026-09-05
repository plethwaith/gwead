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

async fn run_chain(lines: usize, limits: RuntimeLimits) -> Result<Value, String> {
    let mut k = Kernel::boot(KernelConfig::default().with_limits(limits)).expect("boot");
    k.register_plugin_from_json(&doubling_chain(lines))
        .expect("a doubling chain is a well-formed manifest; the budget is a runtime bound");
    let arc = k.into_arc();
    arc.execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .map(|r| r.output)
        .map_err(|e| e.to_string())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_doubling_chain_is_stopped_by_the_budget() {
    let started = std::time::Instant::now();
    let err = run_chain(24, RuntimeLimits::default())
        .await
        .expect_err("24 doublings from 16 bytes is 134 MB");
    assert!(
        err.contains("Step results exceeded"),
        "stopped for the stated reason: {err}"
    );
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

    let mut k = Kernel::boot(
        KernelConfig::default()
            .with_limits(RuntimeLimits::default().with_max_step_results_bytes(4 * 1024 * 1024)),
    )
    .expect("boot");
    k.register_plugin_from_json(&manifest).expect("registers");
    let arc = k.into_arc();
    let err = arc
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect_err("twelve 1 MiB results do not fit in 4 MiB")
        .to_string();
    assert!(err.contains("Step results exceeded"), "{err}");
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
    let err = run_chain(12, limits).await.expect_err("64 KiB over 1 KiB");
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

/// A step whose result was refused must **fail**, not report success
/// with a missing result. Otherwise the budget would install a silent
/// wrong answer in its place.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_result_fails_its_step_rather_than_vanishing() {
    let err = run_chain(24, RuntimeLimits::default())
        .await
        .expect_err("over budget");
    assert!(
        !err.is_empty(),
        "the action errors; it does not return an output missing the step"
    );
}

// ---------------------------------------------------------------------------
// Catchability
// ---------------------------------------------------------------------------

/// The over-budget `let` wrapped as `body` inside a `try` whose handler
/// would otherwise recover, under a 1 KiB budget.
async fn run_guarded(body: Value) -> Result<Value, KernelError> {
    let manifest = json!({
        "name": "p",
        "actions": { "go": {
            "steps": [{
                "id": "guarded",
                "type": "try",
                "params": {
                    "try": [body],
                    "catch": [{"id": "recovered", "type": "let", "params": {"value": "swallowed"}}]
                }
            }],
            "resultMapping": { "out": { "path": "$", "source": "guarded" } }
        } }
    })
    .to_string();
    let mut k = Kernel::boot(
        KernelConfig::default()
            .with_limits(RuntimeLimits::default().with_max_step_results_bytes(1024)),
    )
    .expect("boot");
    k.register_plugin_from_json(&manifest).expect("registers");
    k.into_arc()
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .map(|r| r.output)
}

fn over_budget_let() -> Value {
    json!({"id": "big", "type": "let", "params": {"value": "x".repeat(4096)}})
}

fn assert_budget_error(err: KernelError) {
    match err {
        KernelError::StepResultsLimitExceeded {
            limit_bytes,
            attempted_bytes,
        } => {
            assert_eq!(limit_bytes, 1024);
            assert!(attempted_bytes > 1024, "{attempted_bytes}");
        }
        other => panic!("expected StepResultsLimitExceeded, got: {other:?}"),
    }
}

/// The budget is the kernel's cap, not the manifest's logic, so a
/// violation is not a step failure a `try` may recover from: it ends
/// the invocation the way a cancellation does. A handler that caught it
/// would see a refused result and carry on as if the step had run.
#[tokio::test(flavor = "multi_thread")]
async fn a_budget_violation_escapes_try() {
    let err = run_guarded(over_budget_let())
        .await
        .expect_err("a resource cap is not catchable");
    assert_budget_error(err);
}

/// The same violation inside a `parallel` branch inside the `try`
/// escapes identically. Catchability must not depend on nesting.
#[tokio::test(flavor = "multi_thread")]
async fn a_budget_violation_inside_a_parallel_branch_escapes_try() {
    let err = run_guarded(json!({
        "id": "fan",
        "type": "parallel",
        "params": {"branches": [[over_budget_let()]]}
    }))
    .await
    .expect_err("a resource cap is not catchable through a parallel branch either");
    assert_budget_error(err);
}
