//! Integration tests for continuous-action execution.
//!
//! Continuous actions run their DAG in a loop, emitting one ActionResult
//! per iteration on a channel until cancelled or the receiver is
//! dropped. Real source step types (folder watchers, webhook listeners,
//! queue consumers) are downstream of this kernel API; these tests use
//! the plain `let` intrinsic to exercise the driver itself.

mod common;

use std::sync::Arc;
use std::time::Duration;

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
    let mut k = Kernel::boot(KernelConfig::default()).expect("kernel boot");
    for m in manifests {
        k.register_plugin(m).expect("registration");
    }
    k.into_arc()
}

fn step(id: &str, step_type: &str, params: Value) -> StepDef {
    StepDef::new(id.to_string(), step_type.to_string(), params)
}

fn continuous_action(steps: Vec<StepDef>, interval_ms: u64) -> Action {
    {
        let mut m = Action::new(steps);
        m.continuous = true;
        m.interval_ms = interval_ms;
        m
    }
}

fn single_shot_action(steps: Vec<StepDef>) -> Action {
    Action::new(steps)
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
        ];
        m
    }
}

// ---------------------------------------------------------------------------
// Happy path: receive a few iterations, then cancel
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn driver_emits_iterations_until_cancel() {
    let mut actions = IndexMap::new();
    actions.insert(
        "loop".to_string(),
        continuous_action(
            vec![step("tick", "let", json!({"value": 1}))],
            5, // small interval so we collect quickly
        ),
    );
    let kernel = boot_with(vec![manifest("p", actions)]);

    let mut handle = kernel
        .execute("p", "loop", json!({}))
        .with_config(&json!({}))
        .into_continuous_handle()
        .expect("start continuous");

    // Collect at least 3 iterations; that proves the loop runs and the
    // result channel is wired up.
    let mut collected = 0;
    for _ in 0..3 {
        let event = tokio::time::timeout(Duration::from_secs(2), handle.events.recv())
            .await
            .expect("receive before timeout")
            .expect("driver sent a result");
        assert!(event.is_ok(), "iteration should succeed: {:?}", event.err());
        collected += 1;
    }
    assert_eq!(collected, 3);

    // Shut down and ensure the driver actually exits within a
    // reasonable window.
    tokio::time::timeout(Duration::from_secs(2), handle.shutdown())
        .await
        .expect("driver should exit on cancel")
        .expect("join did not panic");
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn cancel_token_stops_the_loop() {
    let mut actions = IndexMap::new();
    actions.insert(
        "loop".to_string(),
        // Long interval so the driver is mostly sleeping — proves
        // cancel interrupts the sleep rather than waiting for it.
        continuous_action(vec![step("tick", "let", json!({"value": 1}))], 10_000),
    );
    let kernel = boot_with(vec![manifest("p", actions)]);

    let mut handle = kernel
        .execute("p", "loop", json!({}))
        .with_config(&json!({}))
        .into_continuous_handle()
        .expect("start");

    // Receive the first iteration (no sleep before the first call).
    let first = tokio::time::timeout(Duration::from_secs(1), handle.events.recv())
        .await
        .expect("first event arrives quickly")
        .expect("driver sent a result");
    assert!(first.is_ok());

    // Cancel and confirm shutdown completes well under the 10s
    // interval — proves the select! between sleep and cancel works.
    let start = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(2), handle.shutdown())
        .await
        .expect("cancel cuts the sleep short")
        .expect("join clean");
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "cancel should preempt long sleep — took {:?}",
        elapsed,
    );
}

// ---------------------------------------------------------------------------
// Drop receiver exits cleanly
// ---------------------------------------------------------------------------

/// Dropping the whole handle (events + cancel token + join) drops the
/// events receiver, so the driver's next `tx.send()` fails and the loop
/// exits. There is no public signal to wait on, so this only checks
/// that nothing hangs.
#[tokio::test(flavor = "multi_thread")]
async fn dropping_handle_stops_the_driver() {
    let mut actions = IndexMap::new();
    actions.insert(
        "loop".to_string(),
        continuous_action(vec![step("tick", "let", json!({"value": 1}))], 1),
    );
    let kernel = boot_with(vec![manifest("p", actions)]);

    // Start, let it run for a moment so the loop is actually
    // iterating, then drop the handle.
    let handle = kernel
        .execute("p", "loop", json!({}))
        .with_config(&json!({}))
        .into_continuous_handle()
        .expect("start");
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(handle);

    // No public signal to wait on, so verify by absence-of-hang:
    // the test process must exit cleanly. A short sleep gives the
    // driver task a chance to observe the channel close and exit.
    // If the driver leaks, the test framework will still cleanly
    // wind down on shutdown — this assertion is mostly belt-and-
    // braces.
    tokio::time::sleep(Duration::from_millis(100)).await;
}

// ---------------------------------------------------------------------------
// Validation: non-continuous action rejected
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn non_continuous_action_rejected() {
    let mut actions = IndexMap::new();
    actions.insert(
        "one_shot".to_string(),
        single_shot_action(vec![step("tick", "let", json!({"value": 1}))]),
    );
    let kernel = boot_with(vec![manifest("p", actions)]);

    let err = kernel
        .execute("p", "one_shot", json!({}))
        .with_config(&json!({}))
        .into_continuous_handle()
        .err()
        .expect("non-continuous action should be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("not marked continuous"),
        "expected validation message: {msg}",
    );
}

// ---------------------------------------------------------------------------
// Unknown action rejected
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn unknown_action_rejected() {
    let kernel = boot_with(vec![manifest("p", IndexMap::new())]);
    let err = kernel
        .execute("p", "nope", json!({}))
        .with_config(&json!({}))
        .into_continuous_handle()
        .err()
        .expect("unknown action should be rejected");
    assert!(format!("{err}").contains("not registered"));
}

/// `shutdown()` must not hang when the caller stopped draining events.
///
/// The driver's `tx.send().await` blocks once the bounded events
/// channel fills, so that send must race the cancellation token —
/// otherwise `shutdown()` (cancel, then join) would wait forever on a
/// task parked in a send cancellation could not interrupt. "Stop
/// reading, then shut down" is a perfectly reasonable thing for an
/// integrator to do.
///
/// The outer timeout is the assertion: a non-racing send hangs rather
/// than fails.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_completes_when_events_are_not_drained() {
    let mut actions = IndexMap::new();
    actions.insert(
        "loop".to_string(),
        continuous_action(vec![step("tick", "let", json!({"value": 1}))], 0),
    );
    let kernel = boot_with(vec![manifest("p", actions)]);

    let handle = kernel
        .execute("p", "loop", json!({}))
        .with_config(&json!({}))
        .into_continuous_handle()
        .expect("continuous handle");

    // Let the driver fill the bounded channel and block on send. The
    // channel holds 8; a zero-interval loop fills it near-instantly.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    tokio::time::timeout(std::time::Duration::from_secs(5), handle.shutdown())
        .await
        .expect("shutdown must not hang on an undrained events channel")
        .expect("driver task joins cleanly");
}
