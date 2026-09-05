//! The step-results budget is cumulative across *every* path that
//! produces a result — not just the sequential one.
//!
//! `store_step_result` is the sequential charging funnel. Three other
//! paths produce results, and each must be charged too:
//!
//! 1. **Parallel merges.** `merge_task_state` (parallel waves, and the
//!    dataflow scheduler) and `merge_parallel_branch_state`. Each fork
//!    checks the budget against its *own* copy of the byte counter, so
//!    a merge that inserted into the canonical `step_results` directly
//!    would let N branches merge back N x budget while the canonical
//!    counter still read zero — and, with the counter then permanently
//!    under-counting, would weaken the bound for every later sequential
//!    step too.
//! 2. **The `collect` accumulator.** One value per iteration into a host
//!    `Vec`. If only the post-loop store looked at the budget, peak
//!    memory would be `count x item size` and the loop could exhaust
//!    memory before reaching the check.
//! 3. **`parallel` fan-out width.** Each branch forks the whole
//!    `ExecutionState` including `step_results`.
//!
//! All three share a shape: a budget enforced where results are
//! *stored* but not where they are *accumulated or copied* is no
//! budget. The merges route through the same charging funnel, the
//! accumulator is charged as it grows, and the width is capped.

use gwead::kernel::{DataflowEvent, Kernel, KernelConfig, RuntimeLimits};
use serde_json::{Value, json};

const MIB: usize = 1024 * 1024;

async fn run(manifest: &str, limits: RuntimeLimits) -> Result<Value, String> {
    let mut k = Kernel::boot(KernelConfig::default().with_limits(limits)).expect("boot");
    k.register_plugin_from_json(manifest)
        .expect("the manifest is well-formed; the budget is a runtime bound");
    k.into_arc()
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .map(|r| r.output)
        .map_err(|e| e.to_string())
}

/// Six branches each holding a 3 MiB intermediate, under an 8 MiB
/// budget. The same 18 MiB done sequentially is refused; it must be
/// refused through a parallel merge too, with the canonical counter
/// reflecting what the branches produced.
#[tokio::test(flavor = "multi_thread")]
async fn parallel_branches_are_charged_when_they_merge() {
    let branch = |i: usize| {
        json!([
            {"id": format!("big{i}"), "type": "let", "params": {"value": "x".repeat(3 * MIB)}},
            {"id": format!("tiny{i}"), "type": "let", "params": {"value": "done"}}
        ])
    };
    let manifest = json!({
        "name": "p",
        "actions": {"go": {
            "steps": [{"id": "fan", "type": "parallel", "params": {"branches": (0..6).map(branch).collect::<Vec<_>>()}}],
            "resultMapping": {"out": {"path": "$", "source": "fan"}}
        }}
    })
    .to_string();

    let err = run(
        &manifest,
        RuntimeLimits::default().with_max_step_results_bytes(8 * MIB),
    )
    .await
    .expect_err("18 MiB of branch results do not fit in 8 MiB");
    assert!(err.contains("Step results exceeded"), "{err}");
}

/// The wave scheduler (`parallelWaves`) is the third join, and the
/// only one outside `run_step`. Two independent steps share a wave;
/// each fits an 8 MiB budget in its own fork and the merged total does
/// not. Without the check after the merge the action resolves `Ok`
/// with the second result missing.
#[tokio::test(flavor = "multi_thread")]
async fn wave_tasks_are_charged_when_they_merge() {
    let manifest = json!({
        "name": "p",
        "actions": {"go": {
            "parallelWaves": true,
            "steps": [
                {"id": "a", "type": "let", "params": {"value": "x".repeat(5 * MIB)}},
                {"id": "b", "type": "let", "params": {"value": "y".repeat(5 * MIB)}}
            ],
            "resultMapping": {"out": {"path": "$", "source": "b"}}
        }}
    })
    .to_string();

    let err = run(
        &manifest,
        RuntimeLimits::default().with_max_step_results_bytes(8 * MIB),
    )
    .await
    .expect_err("10 MiB of merged wave results do not fit in 8 MiB");
    assert!(err.contains("Step results exceeded"), "{err}");
}

/// The dataflow scheduler merges through the same funnel and must
/// raise the same refusal. Two independent steps each fit an 8 MiB
/// budget in their own forks; their merged total does not. A join that
/// merged the second and carried on would resolve the pipeline `Ok`
/// with that step's result missing. (The tiny long-running `let` is
/// what makes the action a dataflow one.)
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_tasks_are_charged_when_they_merge() {
    let manifest = json!({
        "name": "p",
        "actions": {"go": {
            "dataflow": true,
            "steps": [
                {"id": "prod", "type": "let", "params": {"value": "p"}, "longRunning": true},
                {"id": "a", "type": "let", "params": {"value": "x".repeat(5 * MIB)}},
                {"id": "b", "type": "let", "params": {"value": "y".repeat(5 * MIB)}}
            ],
            "resultMapping": {"out": {"path": "$", "source": "b"}}
        }}
    })
    .to_string();

    let err = run(
        &manifest,
        RuntimeLimits::default().with_max_step_results_bytes(8 * MIB),
    )
    .await
    .expect_err("10 MiB of merged task results do not fit in 8 MiB");
    assert!(err.contains("Step results exceeded"), "{err}");
}

/// On the handle path the step whose merge tripped the budget gets one
/// lifecycle event, `StepFailed` carrying the budget error — not a
/// `StepCompleted` for the body and then a `StepFailed` for the merge.
#[tokio::test(flavor = "multi_thread")]
async fn a_dataflow_merge_that_trips_the_budget_reports_one_event_for_the_step() {
    let manifest = json!({
        "name": "p",
        "actions": {"go": {
            "dataflow": true,
            "steps": [
                {"id": "prod", "type": "let", "params": {"value": "p"}, "longRunning": true},
                {"id": "a", "type": "let", "params": {"value": "x".repeat(5 * MIB)}},
                {"id": "b", "type": "let", "params": {"value": "y".repeat(5 * MIB)}}
            ]
        }}
    })
    .to_string();
    let mut k = Kernel::boot(
        KernelConfig::default()
            .with_limits(RuntimeLimits::default().with_max_step_results_bytes(8 * MIB)),
    )
    .expect("boot");
    k.register_plugin_from_json(&manifest).expect("registers");
    let handle = k
        .into_arc()
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .into_dataflow_handle()
        .expect("a dataflow action hands back a handle");

    let events_task = tokio::spawn(async move {
        let mut events = handle.events;
        let mut out = Vec::new();
        while let Some(e) = events.recv().await {
            out.push(e);
        }
        out
    });
    let err = handle
        .result
        .await
        .expect("result delivered")
        .expect_err("10 MiB of merged task results do not fit in 8 MiB")
        .to_string();
    assert!(err.contains("Step results exceeded"), "{err}");
    let events = events_task.await.expect("events task did not panic");

    // Whichever of `a` and `b` merged second is the one that tripped.
    let failed: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            DataflowEvent::StepFailed { step_id, error } => {
                assert!(error.contains("Step results exceeded"), "{error}");
                Some(step_id.as_str())
            }
            _ => None,
        })
        .collect();
    assert_eq!(failed.len(), 1, "one step failed: {events:?}");
    let completed_too = events.iter().any(|e| {
        matches!(e,
        DataflowEvent::StepCompleted { step_id, .. } if step_id == failed[0])
    });
    assert!(
        !completed_too,
        "the failed step must not also have completed: {events:?}"
    );
    assert!(
        matches!(
            events.last(),
            Some(DataflowEvent::PipelineCompleted { ok: false })
        ),
        "{events:?}"
    );
}

/// The counter must not be left under-counting after a merge. If the
/// canonical total still read ~0 after the branches merged, a subsequent
/// sequential step would be admitted, so the leak would weaken the
/// bound for the *rest* of the action, not just the parallel part.
#[tokio::test(flavor = "multi_thread")]
async fn a_merge_leaves_the_counter_accurate_for_later_steps() {
    let manifest = json!({
        "name": "p",
        "actions": {"go": {
            "steps": [
                // Each branch ENDS with a tiny value, so the parallel
                // step's own result array stays small and the only
                // thing under test is the merged intermediates. Ending
                // each branch with the 3 MiB value would charge 6 MiB
                // through the ordinary funnel and make the test pass
                // regardless of merge accounting.
                {"id": "fan", "type": "parallel", "params": {"branches": [
                    [{"id": "b0", "type": "let", "params": {"value": "x".repeat(3 * MIB)}},
                     {"id": "t0", "type": "let", "params": {"value": "done"}}],
                    [{"id": "b1", "type": "let", "params": {"value": "y".repeat(3 * MIB)}},
                     {"id": "t1", "type": "let", "params": {"value": "done"}}]
                ]}},
                // Alone this fits the 8 MiB budget. After 6 MiB of
                // merged branch results it must not.
                {"id": "after", "type": "let", "params": {"value": "z".repeat(4 * MIB)}}
            ],
            "resultMapping": {"out": {"path": "$", "source": "after"}}
        }}
    })
    .to_string();

    let err = run(
        &manifest,
        RuntimeLimits::default().with_max_step_results_bytes(8 * MIB),
    )
    .await
    .expect_err("6 MiB merged + 4 MiB sequential exceeds 8 MiB");
    assert!(err.contains("Step results exceeded"), "{err}");
}

/// Same shape, comfortably inside the budget: parallel work is not
/// broken, only bounded.
#[tokio::test(flavor = "multi_thread")]
async fn parallel_branches_within_budget_still_run() {
    let manifest = json!({
        "name": "p",
        "actions": {"go": {
            "steps": [{"id": "fan", "type": "parallel", "params": {"branches": [
                [{"id": "b0", "type": "let", "params": {"value": "a"}}],
                [{"id": "b1", "type": "let", "params": {"value": "b"}}]
            ]}}],
            "resultMapping": {"out": {"path": "$", "source": "fan"}}
        }}
    })
    .to_string();
    run(&manifest, RuntimeLimits::default())
        .await
        .expect("two tiny branches are nowhere near 64 MiB");
}

/// The accumulator is charged as it grows. 200k iterations x ~1 KiB is
/// ~200 MB if built in full; under a 1 MiB budget it must stop after
/// roughly a thousand, which is the difference between a bounded failure
/// and an exhausted host.
#[tokio::test(flavor = "multi_thread")]
async fn the_collect_accumulator_is_charged_as_it_grows() {
    let manifest = json!({
        "name": "p",
        "actions": {"go": {
            "steps": [{"id": "loop", "type": "repeat", "params": {"count": 200_000, "steps": [{"id": "big", "type": "let", "params": {"value": "x".repeat(1024)}}], "collect": "$steps.big.result"}}],
            "resultMapping": {"out": {"path": "$", "source": "loop"}}
        }}
    })
    .to_string();

    let started = std::time::Instant::now();
    let err = run(
        &manifest,
        RuntimeLimits::default().with_max_step_results_bytes(MIB),
    )
    .await
    .expect_err("~200 MB of collected items do not fit in 1 MiB");
    let elapsed = started.elapsed();

    assert!(err.contains("Step results exceeded"), "{err}");
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "stopped near the budget rather than after building the whole \
         accumulator: {elapsed:?}"
    );
}

/// A `collect` that fits is untouched.
#[tokio::test(flavor = "multi_thread")]
async fn a_modest_collect_still_works() {
    let manifest = json!({
        "name": "p",
        "actions": {"go": {
            "steps": [{"id": "loop", "type": "repeat", "params": {"count": 3, "steps": [{"id": "i", "type": "let", "params": {"value": "{{$item}}"}}], "collect": "$steps.i.result"}}],
            "resultMapping": {"out": {"path": "$", "source": "loop"}}
        }}
    })
    .to_string();
    let out = run(&manifest, RuntimeLimits::default())
        .await
        .expect("three small items");
    assert_eq!(out["out"], json!([0, 1, 2]));
}

/// Fan-out width is bounded, because each branch forks the whole
/// execution state and the clones are charged by nothing.
#[tokio::test(flavor = "multi_thread")]
async fn parallel_fan_out_width_is_capped() {
    let branches: Vec<Value> = (0..200)
        .map(|i| json!([{"id": format!("b{i}"), "type": "let", "params": {"value": 1}}]))
        .collect();
    let manifest = json!({
        "name": "p",
        "actions": {"go": {
            "steps": [{"id": "fan", "type": "parallel", "params": {"branches": branches}}],
            "resultMapping": {"out": {"path": "$", "source": "fan"}}
        }}
    })
    .to_string();

    let err = run(&manifest, RuntimeLimits::default())
        .await
        .expect_err("200 branches exceeds the default 64");
    assert!(err.contains("exceeds the 64-branch limit"), "{err}");
    assert!(
        err.contains("max_parallel_branches"),
        "the message names the knob: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_width_cap_is_the_operators_to_raise() {
    let branches: Vec<Value> = (0..200)
        .map(|i| json!([{"id": format!("b{i}"), "type": "let", "params": {"value": 1}}]))
        .collect();
    let manifest = json!({
        "name": "p",
        "actions": {"go": {
            "steps": [{"id": "fan", "type": "parallel", "params": {"branches": branches}}],
            "resultMapping": {"out": {"path": "$", "source": "fan"}}
        }}
    })
    .to_string();
    run(
        &manifest,
        RuntimeLimits::default().with_max_parallel_branches(256),
    )
    .await
    .expect("raised the cap, the fan-out runs");
}
