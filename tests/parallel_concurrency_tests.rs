//! Integration tests for concurrent `parallel` branch execution.
//!
//! The `parallel` intrinsic spawns one tokio task per branch on a forked
//! `ExecutionState` and merges branch writes back on join. These tests
//! prove the concurrency (wall-clock), the merge semantics (results /
//! variables visible downstream, declaration-order result array), the
//! failure and `return` rules, and the register-time rejection of
//! cross-branch step-id collisions.
//!
//! A test-local native `sleep_ms` step type (seeded via
//! `KernelConfig::native_step_impls`) provides the deliberate latency a
//! bare kernel otherwise has no way to express.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use gwead::kernel::native_impls::NativeStepImplTable;
use gwead::kernel::{Kernel, KernelConfig, KernelError, PluginExecution, StepError, StepOutput};
use serde_json::{Value, json};

/// Native step body behind `p.sleep_ms`: `{"params": {"ms": N}}` sleeps N
/// milliseconds and returns `{"slept_ms": N}`.
fn step_sleep_ms<'a>(
    _ex: &'a mut (dyn PluginExecution + Send),
    params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move {
        let ms = params.get("ms").and_then(|v| v.as_u64()).unwrap_or(0);
        tokio::time::sleep(Duration::from_millis(ms)).await;
        Ok(StepOutput::from(json!({ "slept_ms": ms })))
    })
}

/// Boot a kernel with the `sleep_ms` impl seeded and register the given
/// manifest JSON.
fn boot_with(manifest: Value) -> Arc<Kernel> {
    let mut impls = NativeStepImplTable::empty();
    impls
        .insert("gwead-tests.p.sleep_ms", step_sleep_ms)
        .expect("no collision in empty table");
    let mut kernel =
        Kernel::boot(KernelConfig::default().with_native_step_impls(impls)).expect("kernel boots");
    kernel
        .register_plugin_from_json(&manifest.to_string())
        .expect("manifest registers");
    kernel.into_arc()
}

/// Manifest skeleton declaring the `sleep_ms` native step type and one
/// `go` action with the given steps.
fn manifest_with(steps: Value) -> Value {
    json!({
        "name": "p",
        "version": "0.0.1",
        "stepTypeDefs": [
            { "name": "p.sleep_ms" }
        ],
        "stepTypeImpls": [
            { "stepType": "p.sleep_ms", "kind": "native", "implRef": "gwead-tests.p.sleep_ms" }
        ],
        "actions": { "go": { "steps": steps } }
    })
}

async fn run(kernel: &Arc<Kernel>) -> Result<gwead::kernel::types::ActionResult, KernelError> {
    kernel
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_branches_run_concurrently() {
    // Two branches, each sleeping 500ms. Sequential execution takes
    // ≥1000ms; concurrent ≈500ms. The 850ms threshold leaves headroom
    // for CI scheduling jitter while staying unambiguously below the
    // sequential floor.
    let kernel = boot_with(manifest_with(json!([
        {"id": "fan", "type": "parallel", "params": {"branches": [
                [ {"id": "s1", "type": "p.sleep_ms", "params": {"ms": 500}} ],
                [ {"id": "s2", "type": "p.sleep_ms", "params": {"ms": 500}} ],
            ]}}
    ])));

    let t0 = Instant::now();
    let result = run(&kernel).await.expect("ok");
    let elapsed = t0.elapsed();

    assert!(
        elapsed < Duration::from_millis(850),
        "two 500ms branches took {elapsed:?} — branches did not run concurrently"
    );
    assert_eq!(
        result.step_results.get("fan"),
        Some(&json!([{ "slept_ms": 500 }, { "slept_ms": 500 }]))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_merges_branch_writes_into_downstream_state() {
    // Branch writes (step results AND variables) must be visible after
    // the parallel step, exactly as if the branches had run
    // sequentially. Downstream consumption goes through `$vars` —
    // the planner rejects `$steps.<branch-inner-id>` references at
    // register time (branch steps aren't top-level DAG nodes; `$vars`
    // is the documented no-edge bridge out of nested blocks).
    let kernel = boot_with(manifest_with(json!([
        {"id": "fan", "type": "parallel", "params": {"branches": [
                [ {"id": "a1", "type": "let", "params": {"value": "alpha"}, "storeToVariable": "va"} ],
                [
                    {"id": "b1", "type": "let", "params": {"value": 1}},
                    {"id": "b2", "type": "let", "params": {"value": "beta"}, "storeToVariable": "vb"},
                ],
            ]}},
        {"id": "after", "type": "let", "params": {"value": "{{$vars.va}}/{{$vars.vb}}"}}
    ])));

    let result = run(&kernel).await.expect("ok");

    // Parallel's own result: each branch's last step result, in
    // declaration order.
    assert_eq!(
        result.step_results.get("fan"),
        Some(&json!(["alpha", "beta"]))
    );
    // Branch-internal step results merged into canonical state.
    assert_eq!(result.step_results.get("a1"), Some(&json!("alpha")));
    assert_eq!(result.step_results.get("b1"), Some(&json!(1)));
    assert_eq!(result.step_results.get("b2"), Some(&json!("beta")));
    // Variables too.
    assert_eq!(result.variables.get("va"), Some(&json!("alpha")));
    assert_eq!(result.variables.get("vb"), Some(&json!("beta")));
    // And a downstream step consumes them via $vars.
    assert_eq!(result.step_results.get("after"), Some(&json!("alpha/beta")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_results_keep_declaration_order_regardless_of_finish_order() {
    // Branch 0 finishes LAST (it sleeps); the result array must still
    // be in declaration order, not completion order.
    let kernel = boot_with(manifest_with(json!([
        {"id": "fan", "type": "parallel", "params": {"branches": [
                [
                    {"id": "slow_nap", "type": "p.sleep_ms", "params": {"ms": 300}},
                    {"id": "slow_val", "type": "let", "params": {"value": "slow"}},
                ],
                [ {"id": "fast_val", "type": "let", "params": {"value": "fast"}} ],
            ]}}
    ])));

    let result = run(&kernel).await.expect("ok");
    assert_eq!(
        result.step_results.get("fan"),
        Some(&json!(["slow", "fast"]))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_empty_branch_yields_null_slot() {
    let kernel = boot_with(manifest_with(json!([
        {"id": "fan", "type": "parallel", "params": {"branches": [
                [],
                [ {"id": "v", "type": "let", "params": {"value": 7}} ],
            ]}}
    ])));

    let result = run(&kernel).await.expect("ok");
    assert_eq!(result.step_results.get("fan"), Some(&json!([null, 7])));
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_branch_failure_fails_the_step() {
    let kernel = boot_with(manifest_with(json!([
        {"id": "fan", "type": "parallel", "params": {"branches": [
                [ {"id": "boom", "type": "throw_error", "params": {"code": "BRANCH_BOOM", "message": "branch failed"}} ],
                [ {"id": "ok_branch", "type": "let", "params": {"value": "fine"}} ],
            ]}}
    ])));

    let err = run(&kernel)
        .await
        .expect_err("branch failure fails the action");
    match err {
        KernelError::PluginError { code, .. } => assert_eq!(code, "BRANCH_BOOM"),
        other => panic!("expected PluginError from throw_error, got: {other}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn return_from_branch_unwinds_the_action() {
    let kernel = boot_with(manifest_with(json!([
        {"id": "fan", "type": "parallel", "params": {"branches": [
                [ {"id": "early", "type": "return", "params": {"value": { "early": true }}} ],
            ]}},
        // Must NOT run — the branch `return` unwinds the whole action.
        {"id": "never", "type": "let", "params": {"value": "nope"}}
    ])));

    let result = run(&kernel).await.expect("ok");
    assert_eq!(result.output, json!({ "early": true }));
    assert!(
        !result.step_results.contains_key("never"),
        "step after a returning parallel must not run"
    );
}

// ---------------------------------------------------------------------------
// Register-time cross-branch step-id collision rejection
// ---------------------------------------------------------------------------

fn register_err(manifest: Value) -> String {
    let mut kernel = Kernel::boot(KernelConfig::default()).expect("kernel boots");
    let err = kernel
        .register_plugin_from_json(&manifest.to_string())
        .expect_err("registration must be rejected");
    err.to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn cross_branch_step_id_collision_rejected_at_register_time() {
    let msg = register_err(json!({
        "name": "p",
        "version": "0.0.1",
        "actions": { "go": { "steps": [
            {"id": "fan", "type": "parallel", "params": {"branches": [
                    [ {"id": "dup", "type": "let", "params": {"value": 1}} ],
                    [ {"id": "dup", "type": "let", "params": {"value": 2}} ],
                ]}}
        ] } }
    }));
    assert!(
        msg.contains("'dup'") && msg.contains("branch"),
        "expected cross-branch collision error naming 'dup': {msg}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn nested_cross_branch_collision_rejected_at_register_time() {
    // The colliding id sits inside branch 1's nested `ifs[].then` body —
    // nested steps write `step_results` slots too, so they count.
    let msg = register_err(json!({
        "name": "p",
        "version": "0.0.1",
        "actions": { "go": { "steps": [
            {"id": "fan", "type": "parallel", "params": {"branches": [
                    [ {"id": "x", "type": "let", "params": {"value": 1}} ],
                    [ {"id": "wrap", "type": "ifs", "params": {"ifs": [ { "test": "true", "then": [
                            {"id": "x", "type": "let", "params": {"value": 2}}
                        ] } ]}} ],
                ]}}
        ] } }
    }));
    assert!(
        msg.contains("'x'") && msg.contains("branch"),
        "expected nested cross-branch collision error naming 'x': {msg}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_ids_within_one_branch_are_not_a_cross_branch_collision() {
    // Within-branch duplicates are a different concern;
    // the cross-branch check must not reject them.
    let mut kernel = Kernel::boot(KernelConfig::default()).expect("kernel boots");
    kernel
        .register_plugin_from_json(
            &json!({
                "name": "p",
                "version": "0.0.1",
                "actions": { "go": { "steps": [
                    {"id": "fan", "type": "parallel", "params": {"branches": [
                            [
                                {"id": "twice", "type": "let", "params": {"value": 1}},
                                {"id": "twice", "type": "let", "params": {"value": 2}},
                            ],
                            [ {"id": "other", "type": "let", "params": {"value": 3}} ],
                        ]}}
                ] } }
            })
            .to_string(),
        )
        .expect("within-branch duplicate is not this check's concern");
}

#[tokio::test(flavor = "multi_thread")]
async fn step_shaped_data_literals_are_not_collisions() {
    // Entity-shaped payloads carry `id` + `type` too. The collector
    // walks the StepDef grammar's
    // step-list keys, not every map value — so identical step-shaped
    // *data* in two branches must not read as a collision, even when
    // it also collides with a real step id in the other branch.
    let mut kernel = Kernel::boot(KernelConfig::default()).expect("kernel boots");
    kernel
        .register_plugin_from_json(
            &json!({
                "name": "p",
                "version": "0.0.1",
                "actions": { "go": { "steps": [
                    {"id": "fan", "type": "parallel", "params": {"branches": [
                            [
                                // Real step id "x" in branch 0...
                                {"id": "x", "type": "let", "params": {"value": { "id": "node-1", "type": "book" }}}
                            ],
                            [
                                // ...and branch 1 carries payloads whose
                                // `id`s collide with both branch 0's step
                                // id AND its payload id. Neither is a step.
                                {"id": "y", "type": "let", "params": {"value": { "id": "x", "type": "book" }}},
                                {"id": "z", "type": "let", "params": {"value": { "id": "node-1", "type": "book" }}}
                            ],
                        ]}}
                ] } }
            })
            .to_string(),
        )
        .expect("step-shaped data literals must not register as step ids");
}

// ---------------------------------------------------------------------------
// Cross-branch storeToVariable collisions
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn cross_branch_store_to_variable_collision_rejected_at_register_time() {
    // The branch merge keeps only NEW variables, so two branches
    // introducing the same new variable would be a join-order race —
    // same shape as the step-id collision, same register-time answer.
    let msg = register_err(json!({
        "name": "p",
        "version": "0.0.1",
        "actions": { "go": { "steps": [
            {"id": "fan", "type": "parallel", "params": {"branches": [
                    [ {"id": "a", "type": "let", "params": {"value": 1}, "storeToVariable": "shared"} ],
                    [ {"id": "b", "type": "let", "params": {"value": 2}, "storeToVariable": "shared"} ],
                ]}}
        ] } }
    }));
    assert!(
        msg.contains("'shared'") && msg.contains("storeToVariable"),
        "expected cross-branch storeToVariable collision error naming 'shared': {msg}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn nested_cross_branch_store_to_variable_collision_rejected() {
    // The colliding write sits inside branch 1's nested `try` body —
    // nested steps' storeToVariable writes merge too, so they count.
    let msg = register_err(json!({
        "name": "p",
        "version": "0.0.1",
        "actions": { "go": { "steps": [
            {"id": "fan", "type": "parallel", "params": {"branches": [
                    [ {"id": "a", "type": "let", "params": {"value": 1}, "storeToVariable": "v"} ],
                    [ {"id": "wrap", "type": "try", "params": {"try": [
                            {"id": "b", "type": "let", "params": {"value": 2}, "storeToVariable": "v"}
                        ]}} ],
                ]}}
        ] } }
    }));
    assert!(
        msg.contains("'v'") && msg.contains("storeToVariable"),
        "expected nested cross-branch storeToVariable collision error: {msg}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn same_store_to_variable_within_one_branch_is_legal() {
    // Sequential overwrite within a branch has no concurrency; only
    // cross-branch introduction is the race. Distinct variables across
    // branches stay legal too (the merge test above runs them).
    let mut kernel = Kernel::boot(KernelConfig::default()).expect("kernel boots");
    kernel
        .register_plugin_from_json(
            &json!({
                "name": "p",
                "version": "0.0.1",
                "actions": { "go": { "steps": [
                    {"id": "fan", "type": "parallel", "params": {"branches": [
                            [
                                {"id": "a1", "type": "let", "params": {"value": 1}, "storeToVariable": "v"},
                                {"id": "a2", "type": "let", "params": {"value": 2}, "storeToVariable": "v"},
                            ],
                            [ {"id": "b", "type": "let", "params": {"value": 3}, "storeToVariable": "w"} ],
                        ]}}
                ] } }
            })
            .to_string(),
        )
        .expect("within-branch overwrite and distinct cross-branch variables are legal");
}
