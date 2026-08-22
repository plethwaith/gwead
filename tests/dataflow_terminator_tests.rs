//! `PipelineCompleted` is delivered once, and awaiting the result never
//! depends on draining the events channel.
//!
//! The scheduler emits the terminator itself on every path it
//! completes, including an ordinary step failure (which emits *and*
//! returns `Err`). The dataflow drivers therefore add one only on the
//! wallclock-timeout path, where the scheduler future was dropped
//! before it could emit. A driver that emitted on every `Err` would
//! deliver two, contradicting the at-most-once contract.
//!
//! The driver's emit also must not be a raw `send().await` on the
//! bounded events channel: with a full, undrained channel that would
//! block forever, so `result_tx` would never fire and `handle.result`
//! would never resolve — the exact "await the result without draining
//! events" hang `emit_terminal_event` exists to prevent. The driver
//! goes through `emit_terminal_event`, which try-sends and only then
//! spawns.

use std::time::Duration;

use gwead::kernel::{DataflowEvent, Kernel, KernelConfig, RuntimeLimits};
use serde_json::{Value, json};

/// A dataflow action whose single long-running step fails.
fn failing_pipeline() -> String {
    json!({
        "name": "p",
        "actions": {"go": {
            "dataflow": true,
            "steps": [{"id": "boom", "type": "throw_error", "params": {"code": "NOPE", "message": "deliberate"}, "longRunning": true}],
            "resultMapping": {"out": {"path": "$", "source": "boom"}}
        }}
    })
    .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failing_pipeline_emits_the_terminator_once() {
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    k.register_plugin_from_json(&failing_pipeline())
        .expect("registers");
    let arc = k.into_arc();

    let handle = arc
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .into_dataflow_handle()
        .expect("spawns");

    let mut events = handle.events;
    let _ = handle.result.await;

    let mut terminators = 0;
    while let Ok(ev) = tokio::time::timeout(Duration::from_millis(200), events.recv()).await {
        match ev {
            Some(DataflowEvent::PipelineCompleted { .. }) => terminators += 1,
            Some(_) => {}
            None => break,
        }
    }
    assert_eq!(
        terminators, 1,
        "the scheduler emits on its own failure paths; the driver must not \
         emit a second one"
    );
}

/// A caller may await the result without draining events. The channel
/// is bounded, so a driver that awaited a send on a full one would park
/// forever.
#[tokio::test(flavor = "multi_thread")]
async fn the_result_resolves_without_draining_events() {
    let mut k = Kernel::boot(
        KernelConfig::default()
            .with_limits(RuntimeLimits::default().with_dataflow_events_capacity(1)),
    )
    .expect("boot");
    k.register_plugin_from_json(&failing_pipeline())
        .expect("registers");
    let arc = k.into_arc();

    let handle = arc
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .into_dataflow_handle()
        .expect("spawns");

    // Deliberately never touch `handle.events`, and keep it alive so the
    // channel stays full rather than closing.
    let _events = handle.events;
    let resolved = tokio::time::timeout(Duration::from_secs(5), handle.result).await;
    assert!(
        resolved.is_ok(),
        "handle.result must resolve with a full, undrained events channel"
    );
}
