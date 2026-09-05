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

use std::future::Future;
use std::pin::Pin;
use std::sync::{LazyLock, Mutex};

use gwead::kernel::host_api::{PluginExecution, StepError, StepOutput};
use gwead::kernel::native_impls::NativeStepImplTable;
use gwead::kernel::{Kernel, KernelConfig, KernelError, RuntimeLimits};
use serde_json::{Value, json};

mod common;

/// Marks the `record` fixture step has been reached with. Tests in
/// this binary run concurrently, so each uses a mark of its own.
static RECORDED: LazyLock<Mutex<Vec<String>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Test-only step that records `params.mark`. The one way to observe
/// from outside whether a `finally` body ran, since an invocation that
/// errors returns no step results.
fn record_step<'a>(
    _ex: &'a mut (dyn PluginExecution + Send),
    params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move {
        let mark = params["mark"]
            .as_str()
            .expect("record needs a mark")
            .to_string();
        RECORDED.lock().expect("recorder not poisoned").push(mark);
        Ok(StepOutput::from(json!(true)))
    })
}

fn recorded(mark: &str) -> bool {
    RECORDED
        .lock()
        .expect("recorder not poisoned")
        .iter()
        .any(|m| m == mark)
}

fn record(id: &str, mark: &str) -> Value {
    json!({"id": id, "type": "budget_fixture.record", "params": {"mark": mark}})
}

/// A kernel under `limits` with the recorder step and a `script`
/// runtime for language `spin` that runs until its fuel is gone.
fn boot(limits: RuntimeLimits) -> Kernel {
    let mut impls = NativeStepImplTable::empty();
    impls
        .insert("test.budget_fixture.record", record_step)
        .expect("fresh table");
    let config = common::script_runtime_mock::trusting(
        KernelConfig::default()
            .with_limits(limits)
            .with_native_step_impls(impls),
        &["spin"],
    );
    let mut k = Kernel::boot(config).expect("boot");
    k.register_plugin_from_json(
        r#"{
            "name": "budget_fixture",
            "version": "0.0.0",
            "description": "Wires the test-only `record` step type.",
            "stepTypeDefs": [{"name": "budget_fixture.record", "freelyUsable": true}],
            "stepTypeImpls": [
                {"stepType": "budget_fixture.record", "kind": "native",
                 "implRef": "test.budget_fixture.record"}
            ]
        }"#,
    )
    .expect("fixture registers");
    common::script_runtime_mock::register_spinning_for_language(&mut k, "spin")
        .expect("spinning runtime registers");
    k
}

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

/// Register `manifests` under `limits` and run plugin `p`'s `go`.
async fn run_manifests(manifests: &[&str], limits: RuntimeLimits) -> Result<Value, KernelError> {
    let mut k = boot(limits);
    for manifest in manifests {
        k.register_plugin_from_json(manifest)
            .expect("the manifest is well-formed; the budget is a runtime bound");
    }
    k.into_arc()
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .map(|r| r.output)
}

async fn run_manifest(manifest: &str, limits: RuntimeLimits) -> Result<Value, KernelError> {
    run_manifests(&[manifest], limits).await
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
/// as a cancellation does. The recorder in `finally` is never reached,
/// and the budget error is what comes out. (`finally` after a failed
/// step is pinned in `intrinsics_tests`, and below for a fuel trip.)
#[tokio::test(flavor = "multi_thread")]
async fn a_budget_violation_skips_finally() {
    const MARK: &str = "a_budget_violation_skips_finally";
    let err = run_guarded(
        json!({
            "id": "guarded",
            "type": "try",
            "params": {
                "try": [over_budget_let()],
                "finally": [record("cleanup", MARK)]
            }
        }),
        false,
    )
    .await
    .expect_err("the invocation ends on the budget");
    assert_guarded_error(err);
    assert!(
        !recorded(MARK),
        "finally must not run after the budget ends the invocation"
    );
}

// ---------------------------------------------------------------------------
// The other caps fail their step
// ---------------------------------------------------------------------------
//
// Fuel and memory belong to one wasm sub-instance, so a trip is that
// step's failure: a `try` may catch it, and `finally` runs in full.

/// A `script` step whose runtime spins until the fuel meter traps.
fn spinning_script() -> Value {
    json!({"id": "spin", "type": "script", "params": {"language": "spin", "source": ""}})
}

/// Limits under which the spin trips quickly.
fn small_fuel() -> RuntimeLimits {
    RuntimeLimits::default().with_fuel_budget(10_000)
}

fn assert_fuel_error(err: KernelError) {
    match err {
        KernelError::FuelExhausted { budget, detail } => {
            assert_eq!(budget, 10_000);
            assert!(detail.contains("step 'spin'"), "{detail}");
        }
        other => panic!("expected FuelExhausted, got: {other:?}"),
    }
}

/// Uncaught, a fuel trip is typed. Pins the recorded marker and its
/// conversion, which no other test in the suite reaches.
#[tokio::test(flavor = "multi_thread")]
async fn a_fuel_trip_is_typed() {
    let manifest = json!({
        "name": "p",
        "actions": { "go": { "steps": [spinning_script()] } }
    })
    .to_string();
    let err = run_manifest(&manifest, small_fuel())
        .await
        .expect_err("the spin exhausts 10k units");
    assert_fuel_error(err);
}

/// A fuel trip is a failed step, and a `try` recovers from it.
#[tokio::test(flavor = "multi_thread")]
async fn a_fuel_trip_is_a_failed_step_a_try_can_catch() {
    let manifest = json!({
        "name": "p",
        "actions": { "go": {
            "steps": [guarded(spinning_script())],
            "resultMapping": { "out": { "path": "$", "source": "guarded" } }
        } }
    })
    .to_string();
    let out = run_manifest(&manifest, small_fuel())
        .await
        .expect("the handler recovers from the callee's fuel trip");
    assert_eq!(out["out"], json!("swallowed"));
}

/// With no `catch`, the failure propagates after `finally` has run —
/// all of it. The marker the trip left behind must not fail the first
/// `finally` step to succeed and skip the rest.
#[tokio::test(flavor = "multi_thread")]
async fn a_fuel_trip_runs_finally_in_full() {
    const FIRST: &str = "a_fuel_trip_runs_finally_in_full/first";
    const SECOND: &str = "a_fuel_trip_runs_finally_in_full/second";
    let manifest = json!({
        "name": "p",
        "actions": { "go": { "steps": [{
            "id": "guarded",
            "type": "try",
            "params": {
                "try": [spinning_script()],
                "finally": [record("first", FIRST), record("second", SECOND)]
            }
        }] } }
    })
    .to_string();
    let err = run_manifest(&manifest, small_fuel())
        .await
        .expect_err("no catch, so the fuel trip propagates");
    assert_fuel_error(err);
    assert!(recorded(FIRST), "the first finally step ran");
    assert!(
        recorded(SECOND),
        "the second finally step ran: the first one's success was not turned into a failure"
    );
}

// ---------------------------------------------------------------------------
// Across an invoke boundary
// ---------------------------------------------------------------------------
//
// The budget is per invocation. A callee that exceeds its own has
// failed, from the caller's side, and the caller's `try` may catch it
// as it may catch a callee's deadline.

fn callee_over_budget() -> String {
    json!({
        "name": "callee",
        "actions": { "go": { "steps": [over_budget_let()] } }
    })
    .to_string()
}

fn caller(step: Value) -> String {
    json!({
        "name": "p",
        "permissions": ["invoke:plugin:callee"],
        "actions": { "go": {
            "steps": [step],
            "resultMapping": { "out": { "path": "$", "source": "guarded" } }
        } }
    })
    .to_string()
}

fn invoke_callee() -> Value {
    json!({"id": "call", "type": "invoke", "params": {"plugin": "callee", "action": "go", "input": {}}})
}

#[tokio::test(flavor = "multi_thread")]
async fn a_callees_budget_violation_is_a_failed_step_in_the_caller() {
    let err = run_manifests(
        &[&callee_over_budget(), &caller(invoke_callee())],
        RuntimeLimits::default().with_max_step_results_bytes(GUARDED_BUDGET),
    )
    .await
    .expect_err("the callee's violation fails the caller's invoke step");
    match err {
        KernelError::CalleeFailed {
            step_id,
            plugin,
            action,
            source,
        } => {
            assert_eq!(
                (step_id.as_str(), plugin.as_str(), action.as_str()),
                ("call", "callee", "go")
            );
            assert!(
                matches!(*source, KernelError::StepResultsLimitExceeded { limit_bytes, .. } if limit_bytes == GUARDED_BUDGET),
                "the callee's error keeps its type: {source:?}"
            );
        }
        other => panic!("expected CalleeFailed, got: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_callees_budget_violation_is_catchable_by_the_caller() {
    let out = run_manifests(
        &[&callee_over_budget(), &caller(guarded(invoke_callee()))],
        RuntimeLimits::default().with_max_step_results_bytes(GUARDED_BUDGET),
    )
    .await
    .expect("the caller's handler recovers from its callee's violation");
    assert_eq!(out["out"], json!("swallowed"));
}
