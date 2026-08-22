//! `repeat` iterates a count, not a materialised list.
//!
//! If `host_begin_repeat` did `(0..count).map(Value::from).collect()` behind
//! a single `count > i32::MAX` guard, a one-line manifest could ask for
//! ~2.1 billion `Value`s — tens of gigabytes — in one synchronous
//! `collect`.
//!
//! Three separate bounds all miss it, which is why it is easy to
//! overlook:
//!
//! - `max_step_results_bytes` charges step *results*. This is scratch
//!   state, so it is never charged.
//! - The wasm limits govern guest memory. Nothing here runs in wasm.
//! - The wallclock watchdog fires a cancellation token that the loop
//!   polls between iterations — but the allocation happens *before* the
//!   first iteration and never yields, so there is nothing to poll.
//!
//! `count` is template-resolved, so it can arrive from `$input`.
//!
//! A counted loop needs an index, not a vector. `host_begin_repeat` stores the bound
//! and produces item *i* on demand, which turns an unbounded allocation
//! into eight bytes and moves the failure mode from "host dies" to
//! "action hits its deadline".

use std::time::{Duration, Instant};

use gwead::kernel::{Kernel, KernelConfig, RuntimeLimits};
use serde_json::{Value, json};

fn repeat_manifest(count: u64) -> String {
    json!({
        "name": "p",
        "actions": {"go": {
            "steps": [{"id": "loop", "type": "repeat", "params": {"count": count, "steps": [{"id": "i", "type": "let", "params": {"value": "{{$item}}"}}]}}],
            "resultMapping": {"out": {"path": "$", "source": "loop"}}
        }}
    })
    .to_string()
}

/// A test that can only exist once the setup is O(1): with a
/// materialised list, running it takes the machine down.
///
/// Two billion iterations under a 200 ms operator ceiling. A
/// materialising `repeat` would allocate ~2e9 `Value`s before the first
/// iteration, and the deadline could not fire, because a synchronous
/// `collect` never yields. With O(1) setup the action dies on time
/// instead of on memory.
#[tokio::test(flavor = "multi_thread")]
async fn a_two_billion_count_is_bounded_by_the_deadline_not_by_memory() {
    let mut k = Kernel::boot(KernelConfig::default().with_limits(
        RuntimeLimits::default().with_max_wallclock_timeout(Duration::from_millis(200)),
    ))
    .expect("boot");
    k.register_plugin_from_json(&repeat_manifest(2_000_000_000))
        .expect("registers");
    let arc = k.into_arc();

    let started = Instant::now();
    let err = arc
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect_err("two billion iterations cannot finish in 200 ms");
    let elapsed = started.elapsed();

    assert!(
        err.to_string().contains("wallclock timeout"),
        "stopped by the deadline, not by an allocation failure: {err}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the count is never expanded, so setup is O(1): {elapsed:?}"
    );
}

/// `{{$item}}` binds the iteration index.
#[tokio::test(flavor = "multi_thread")]
async fn the_item_binding_still_counts_from_zero() {
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    k.register_plugin_from_json(
        &json!({
            "name": "p",
            "actions": {"go": {
                "steps": [{"id": "loop", "type": "repeat", "params": {"count": 4, "steps": [{"id": "i", "type": "let", "params": {"value": "{{$item}}"}}], "collect": "$steps.i.result"}}],
                "resultMapping": {"out": {"path": "$", "source": "loop"}}
            }}
        })
        .to_string(),
    )
    .expect("registers");
    let out = k
        .into_arc()
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect("runs");
    assert_eq!(
        out.output["out"],
        json!([0, 1, 2, 3]),
        "items are the indices, produced on demand rather than up front, and \
         still numbers"
    );
}

/// A zero count still runs the body zero times and produces an empty
/// collection — the boundary the range representation is most likely to
/// get wrong.
#[tokio::test(flavor = "multi_thread")]
async fn a_zero_count_runs_nothing() {
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    k.register_plugin_from_json(&repeat_manifest(0))
        .expect("registers");
    let out = k
        .into_arc()
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect("an empty loop is not an error");
    assert_eq!(out.output["out"], json!([]));
}

/// `for_each` iterates a real list — the other arm of the same enum,
/// and the one that borrows rather than synthesises.
#[tokio::test(flavor = "multi_thread")]
async fn for_each_over_a_real_list_is_unaffected() {
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    k.register_plugin_from_json(
        &json!({
            "name": "p",
            "actions": {"go": {
                "steps": [
                    {"id": "seed", "type": "let", "params": {"value": ["x", "y", "z"]}},
                    {"id": "loop", "type": "for_each", "params": {"path": "$steps.seed.result", "steps": [{"id": "i", "type": "let", "params": {"value": "got-{{$item}}"}}], "collect": "$steps.i.result"}}
                ],
                "resultMapping": {"out": {"path": "$", "source": "loop"}}
            }}
        })
        .to_string(),
    )
    .expect("registers");
    let out = k
        .into_arc()
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect("runs");
    assert_eq!(out.output["out"], json!(["got-x", "got-y", "got-z"]));
}
