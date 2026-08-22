//! Integration tests for the `for_each` and `repeat` step types.
//!
//! `for_each` iterates a list; `repeat` iterates a count. `repeat`
//! shares the foreach state machine and reuses
//! `next_foreach` / `end_foreach`, with a dedicated `begin_repeat` that
//! pushes a counted item source (indices `0..count`, produced on demand).

mod common;

use std::sync::Arc;

use gwead::kernel::types::*;
use gwead::kernel::{Kernel, KernelConfig};
use indexmap::IndexMap;
use serde_json::{Value, json};

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "gwead=debug".into()),
        )
        .with_test_writer()
        .try_init();
}

fn boot_with(manifests: Vec<PluginManifest>) -> Arc<Kernel> {
    init_tracing();
    let mut k = Kernel::boot(KernelConfig::default()).expect("kernel should boot");
    for m in manifests {
        k.register_plugin(m).expect("registration");
    }
    k.into_arc()
}

fn step(id: &str, step_type: &str, params: Value) -> StepDef {
    StepDef::new(id.to_string(), step_type.to_string(), params)
}

/// A top-level `let` step that also names its result as a
/// variable via `store_to_variable`.
fn let_step(id: &str, value: Value, var: &str) -> StepDef {
    {
        let mut m = StepDef::new(id.to_string(), "let".to_string(), json!({ "value": value }));
        m.store_to_variable = Some(var.to_string());
        m
    }
}

fn action(steps: Vec<StepDef>) -> Action {
    Action::new(steps)
}

fn one_action(name: &str, steps: Vec<StepDef>) -> IndexMap<String, Action> {
    let mut m = IndexMap::new();
    m.insert(name.to_string(), action(steps));
    m
}

fn manifest(name: &str, actions: IndexMap<String, Action>) -> PluginManifest {
    {
        let mut m = PluginManifest::new(name.to_string());
        m.actions = actions;
        m.permissions = vec![
            "network:egress:*".to_string(),
            "blobs:read:*".to_string(),
            "blobs:write:*".to_string(),
            "blobs:delete:*".to_string(),
            // Cross-plugin dispatch is default-deny; the iteration
            // fixtures drive `invoke` steps at other plugins.
            "invoke:plugin:*".to_string(),
            "invoke:role:*".to_string(),
        ];
        m
    }
}

// ---------------------------------------------------------------------------
// `repeat`
// ---------------------------------------------------------------------------

/// Run `repeat` three times with an inline `count`. The inner step
/// captures the current iteration via `{{$item}}`.
///
/// What we can actually observe: a downstream step reading the
/// variable updated by an inner `let` sees the value from the
/// *last* iteration.
#[tokio::test(flavor = "multi_thread")]
async fn repeat_runs_inner_steps_count_times() {
    let kernel = boot_with(vec![manifest(
        "p",
        one_action(
            "go",
            vec![
                step(
                    "loop",
                    "repeat",
                    json!({
                        "count": 3,
                        "steps": [
                            {"id": "rec", "type": "let", "params": {"value": "{{$item}}"}, "storeToVariable": "last_iter"}
                        ]
                    }),
                ),
                let_step("echo_final", json!("{{$.vars.last_iter}}"), "out"),
            ],
        ),
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution");

    // After 3 iterations the inner `let` has captured {{$item}} → 2
    // for the last iteration. `let` preserves JSON types on a lone
    // template — the item is a NUMBER.
    assert_eq!(result.variables["last_iter"], json!(2));
    assert_eq!(result.step_results["echo_final"], json!(2));
}

/// Count provided as a string template that resolves to an integer
/// against the resolution context (here, an input field).
#[tokio::test(flavor = "multi_thread")]
async fn repeat_count_template_resolves() {
    let kernel = boot_with(vec![manifest(
        "p",
        one_action(
            "go",
            vec![step(
                "loop",
                "repeat",
                json!({
                    "count": "{{$.iterations}}",
                    "steps": [{"id": "tick", "type": "let", "params": {"value": "{{$item}}"}, "storeToVariable": "last"}]
                }),
            )],
        ),
    )]);

    let result = kernel
        .execute("p", "go", json!({"iterations": 5}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution");

    assert_eq!(result.variables["last"], json!(4));
}

/// `count = 0` runs the body zero times and the step's result is the
/// empty array (matches for_each's "empty source" contract).
#[tokio::test(flavor = "multi_thread")]
async fn repeat_zero_count_runs_no_iterations() {
    let kernel = boot_with(vec![manifest(
        "p",
        one_action(
            "go",
            vec![step(
                "loop",
                "repeat",
                json!({"count": 0, "steps": [
                    {"id": "x", "type": "set_var", "params": {"name": "ran", "value": true}}
                ]}),
            )],
        ),
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution");

    assert!(
        !result.variables.contains_key("ran"),
        "inner step should not have run",
    );
    assert_eq!(result.step_results["loop"], json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn repeat_rejects_negative_count() {
    let kernel = boot_with(vec![manifest(
        "p",
        one_action(
            "go",
            vec![step("loop", "repeat", json!({"count": -3, "steps": []}))],
        ),
    )]);

    let err = kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect_err("negative count should error");
    let msg = format!("{err}");
    assert!(
        msg.contains("non-negative"),
        "expected non-negative-integer error: {msg}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn repeat_rejects_non_numeric_count() {
    let kernel = boot_with(vec![manifest(
        "p",
        one_action(
            "go",
            vec![step(
                "loop",
                "repeat",
                json!({"count": "not-a-number", "steps": []}),
            )],
        ),
    )]);

    let err = kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect_err("non-numeric string should error");
    let msg = format!("{err}");
    assert!(
        msg.contains("did not parse") || msg.contains("integer or a template"),
        "expected parse error: {msg}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn repeat_rejects_object_count() {
    let kernel = boot_with(vec![manifest(
        "p",
        one_action(
            "go",
            vec![step(
                "loop",
                "repeat",
                json!({"count": {"nope": true}, "steps": []}),
            )],
        ),
    )]);

    let err = kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect_err("object count should error");
    assert!(format!("{err}").contains("integer or a template"));
}

/// Nested repeats: outer loops 3 times, inner loops 2 times — the
/// inner-most step captures the outer item. After execution the
/// outer-iteration var should be 2 (last outer item).
#[tokio::test(flavor = "multi_thread")]
async fn repeat_nests() {
    let kernel = boot_with(vec![manifest(
        "p",
        one_action(
            "go",
            vec![step(
                "outer",
                "repeat",
                json!({
                    "count": 3,
                    "steps": [{"id": "inner", "type": "repeat", "params": {"count": 2, "steps": [{"id": "inner_rec", "type": "let", "params": {"value": "{{$item}}"}, "storeToVariable": "inner_item"}]}}]
                }),
            )],
        ),
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution");

    // The innermost iteration sees the inner repeat's item (0 or 1) —
    // last one is 1. `let` preserves the item's NUMBER type.
    assert_eq!(result.variables["inner_item"], json!(1));
}

// ---------------------------------------------------------------------------
// `for_each`
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn for_each_iterates_array_items() {
    let kernel = boot_with(vec![manifest(
        "p",
        one_action(
            "go",
            vec![
                // Seed an array as the first step's result.
                step("seed", "let", json!({"value": [10, 20, 30]})),
                step(
                    "iter",
                    "for_each",
                    json!({
                        "path": "$steps.seed.result",
                        "steps": [{"id": "remember", "type": "let", "params": {"value": "{{$item}}"}, "storeToVariable": "last_item"}]
                    }),
                ),
            ],
        ),
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution");

    assert_eq!(result.variables["last_item"], json!(30));
}

// ---------------------------------------------------------------------------
// Cycle detection walks into `repeat`
// ---------------------------------------------------------------------------

/// Two plugins with a cycle whose only static edge passes through a
/// `repeat` body. The cycle-walker (invoke.rs::collect_edges) must
/// recurse into `repeat.steps` the same way it does for `for_each`.
#[test]
fn cycle_through_repeat_body_rejected() {
    init_tracing();
    let mut k = Kernel::boot(KernelConfig::default()).expect("kernel boot");

    // a.x's `repeat` body invokes b.y.
    k.register_plugin(manifest(
        "a",
        one_action(
            "x",
            vec![step(
                "loop",
                "repeat",
                json!({
                    "count": 1,
                    "steps": [{"id": "call_b", "type": "invoke", "params": {"plugin": "b", "action": "y"}}]
                }),
            )],
        ),
    ))
    .expect("a registers (b doesn't exist yet — no cycle)");

    // b.y invokes a.x — closes the cycle through a.x's repeat body.
    let err = k
        .register_plugin(manifest(
            "b",
            one_action(
                "y",
                vec![step(
                    "back",
                    "invoke",
                    json!({"plugin": "a", "action": "x"}),
                )],
            ),
        ))
        .expect_err("cycle through repeat should be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("cycle") || msg.contains("Cycle"),
        "expected cycle error: {msg}",
    );
}

// ---------------------------------------------------------------------------
// `repeat ... until` — early exit semantics
// ---------------------------------------------------------------------------

/// `until` evaluates after the body runs, so it executes at least once
/// even when `until` is already true on entry — classic do-until.
#[tokio::test(flavor = "multi_thread")]
async fn repeat_until_runs_body_at_least_once() {
    let kernel = boot_with(vec![manifest(
        "p",
        one_action(
            "go",
            vec![step(
                "loop",
                "repeat",
                json!({
                    "count": 5,
                    "until": "true",
                    "steps": [{"id": "tick", "type": "let", "params": {"value": "{{$item}}"}, "storeToVariable": "iter"}]
                }),
            )],
        ),
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution");

    // Body ran once (iter=0), then `until=true` short-circuited.
    assert_eq!(result.variables["iter"], json!(0));
}

/// `until` referencing an inner-step result. `$steps.tick.result` is
/// `{{$item}}` resolved by `let` (type-preserving — a NUMBER), so once
/// it equals the target the loop exits before consuming the full
/// `count`.
#[tokio::test(flavor = "multi_thread")]
async fn repeat_until_exits_when_inner_result_truthy() {
    let kernel = boot_with(vec![manifest(
        "p",
        one_action(
            "go",
            vec![step(
                "loop",
                "repeat",
                json!({
                    // Generous safety cap — the test verifies `until`
                    // shortens execution well before this is hit.
                    "count": 10,
                    // Exit on iteration 2 (third iteration, 0-indexed).
                    "until": "$steps.tick.result == 2",
                    "steps": [{"id": "tick", "type": "let", "params": {"value": "{{$item}}"}, "storeToVariable": "iter"}]
                }),
            )],
        ),
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution");

    // Loop exited after iter=2 (third iteration).
    assert_eq!(result.variables["iter"], json!(2));
}

/// When `until` never becomes truthy within `count` iterations, the
/// loop exits via the safety cap — `count` remains the cap.
#[tokio::test(flavor = "multi_thread")]
async fn repeat_until_falls_back_to_count_cap() {
    let kernel = boot_with(vec![manifest(
        "p",
        one_action(
            "go",
            vec![step(
                "loop",
                "repeat",
                json!({
                    "count": 3,
                    "until": "false",
                    "steps": [{"id": "tick", "type": "let", "params": {"value": "{{$item}}"}, "storeToVariable": "iter"}]
                }),
            )],
        ),
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution");

    // Three iterations: 0, 1, 2 — last write wins.
    assert_eq!(result.variables["iter"], json!(2));
}

/// `for_each` does not honor `until` even when present in params —
/// it's a `repeat`-only feature. The expression is ignored without
/// error so a manifest that accidentally includes it doesn't break.
#[tokio::test(flavor = "multi_thread")]
async fn for_each_ignores_until_clause() {
    let kernel = boot_with(vec![manifest(
        "p",
        one_action(
            "go",
            vec![
                step("seed", "let", json!({"value": [1, 2, 3]})),
                step(
                    "iter",
                    "for_each",
                    json!({
                        "path": "$steps.seed.result",
                        // `until` is meaningless for for_each — ignored.
                        "until": "true",
                        "steps": [{"id": "remember", "type": "let", "params": {"value": "{{$item}}"}, "storeToVariable": "last"}]
                    }),
                ),
            ],
        ),
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution");

    // All three items processed despite `until: true`.
    assert_eq!(result.variables["last"], json!(3));
}

// ---------------------------------------------------------------------------
// `collect` — for_each / repeat result aggregation
// ---------------------------------------------------------------------------

/// `for_each` with `collect` produces an array of inner-step results as
/// the outer step's own result. Lets downstream consumers read the
/// accumulated values via `$steps.<id>.result` like any other step.
#[tokio::test(flavor = "multi_thread")]
async fn for_each_collect_assembles_inner_results() {
    let kernel = boot_with(vec![manifest(
        "p",
        one_action(
            "go",
            vec![
                step("seed", "let", json!({"value": [1, 2, 3]})),
                step(
                    "iter",
                    "for_each",
                    json!({
                        "path": "$steps.seed.result",
                        "collect": "$steps.double.result",
                        "steps": [{"id": "double", "type": "let", "params": {"value": "{{$item}}{{$item}}"}}]
                    }),
                ),
                // Move the for_each result into a variable so the test
                // can assert against it (the action's output defaults
                // to the last step's result).
                let_step("capture", json!("{{$steps.iter.result}}"), "results"),
            ],
        ),
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution");

    // `{{$item}}{{$item}}` is a concatenating template, so each render
    // is still a string: 1→"11", 2→"22", 3→"33". The capture step's
    // lone `{{$steps.iter.result}}` template preserves the JSON array
    // type under `let`.
    assert_eq!(result.variables["results"], json!(["11", "22", "33"]));
}

/// `for_each` over an empty array with `collect` produces an empty array
/// — no iterations, but the outer step still has a result.
#[tokio::test(flavor = "multi_thread")]
async fn for_each_collect_empty_input_produces_empty_array() {
    let kernel = boot_with(vec![manifest(
        "p",
        one_action(
            "go",
            vec![
                step("seed", "let", json!({"value": []})),
                step(
                    "iter",
                    "for_each",
                    json!({
                        "path": "$steps.seed.result",
                        "collect": "$steps.double.result",
                        "steps": [{"id": "double", "type": "let", "params": {"value": "{{$item}}"}}]
                    }),
                ),
                let_step("capture", json!("{{$steps.iter.result}}"), "results"),
            ],
        ),
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution");

    // Empty array — `let` captures it type-preserved.
    assert_eq!(result.variables["results"], json!([]));
}

/// `repeat` with `collect` accumulates one value per iteration. Combine
/// with `until` to terminate early; collected length reflects the actual
/// iteration count, not `count`.
#[tokio::test(flavor = "multi_thread")]
async fn repeat_collect_with_until_yields_actual_iteration_count() {
    let kernel = boot_with(vec![manifest(
        "p",
        one_action(
            "go",
            vec![
                step(
                    "loop",
                    "repeat",
                    json!({
                        "count": 10,
                        "until": "$steps.tick.result == 2",
                        "collect": "$steps.tick.result",
                        "steps": [{"id": "tick", "type": "let", "params": {"value": "{{$item}}"}, "storeToVariable": "iter"}]
                    }),
                ),
                let_step("capture", json!("{{$steps.loop.result}}"), "results"),
            ],
        ),
    )]);

    let result = kernel
        .execute("p", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution");

    // Loop exits after iter=2 → three iterations collected (0, 1, 2),
    // and NOT a fourth. `let` preserves the items' NUMBER type and the
    // capture step's lone template keeps the array un-stringified.
    assert_eq!(result.variables["results"], json!([0, 1, 2]));
}

// ---------------------------------------------------------------------------
// Inner-step result clearing across iterations
// ---------------------------------------------------------------------------

/// When an inner step's failure is swallowed on iteration N+1 after
/// succeeding on iteration N,
/// downstream templates in iteration N+1 must not see iteration N's
/// stale value. Concretely: `for_each` over two items where an inner
/// `invoke` (wrapped in a `try` with an empty catch — the
/// optional-step idiom) succeeds
/// for the first item and fails for the second; the per-iteration
/// `collect` expression must produce N's value for the first iteration
/// and `null` (not N's value again) for the second.
#[tokio::test(flavor = "multi_thread")]
async fn for_each_clears_inner_step_results_between_iterations() {
    // `target` plugin: action `ok` succeeds and returns a marker.
    // No `fail` action exists, so an invoke targeting it errors at
    // dispatch time — the shape a try-wrapped dispatch step has to
    // survive.
    let target = manifest(
        "target",
        one_action(
            "ok",
            vec![step("marker", "let", json!({"value": "succeeded"}))],
        ),
    );

    let driver = manifest(
        "driver",
        one_action(
            "go",
            vec![
                step("seed", "let", json!({"value": ["ok", "fail"]})),
                step(
                    "iter",
                    "for_each",
                    json!({
                        "path": "$steps.seed.result",
                        "collect": "$steps.try.result",
                        "steps": [{"id": "try", "type": "try", "params": {"try": [{"id": "try_inner", "type": "invoke", "params": {"plugin": "target", "action": "{{$item}}", "input": {}}}], "catch": []}}]
                    }),
                ),
                let_step("capture", json!("{{$steps.iter.result}}"), "results"),
            ],
        ),
    );

    let kernel = boot_with(vec![target, driver]);

    let result = kernel
        .execute("driver", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution");

    // Iter 1 (action="ok") succeeded — `try.result` is the child
    // action's output. Iter 2 (action="fail") errored — with
    // clear-on-iteration-start, iter 2's `try.result` is null,
    // not iter 1's stale success value. The capture step's lone
    // template keeps the collected array un-stringified under `let`.
    let captured = result
        .variables
        .get("results")
        .and_then(|v| v.as_array())
        .expect("results var is an array");
    assert_eq!(captured.len(), 2, "one collected value per iteration");
    assert!(
        !captured[0].is_null(),
        "first iteration's value should be a non-null result, got {captured:?}"
    );
    assert!(
        captured[1].is_null(),
        "second iteration's value should be null (inner results are cleared at the top of each iteration), got {captured:?}"
    );
}
