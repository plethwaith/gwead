//! Streaming-dataflow scheduler tests.
//!
//! Exercises [`gwead::kernel::Kernel`]'s dataflow path: actions marked
//! `dataflow: true` run every step concurrently as its own tokio task,
//! long-running producer steps stream chunks through pre-provisioned
//! writable→readable pipes, and downstream consumers loop on
//! `stream_read` until EOF. Tests use two custom host step types
//! (`dataflow_producer`, `dataflow_consumer`) to keep the surface
//! self-contained — no Lua, no wasm boundary, just the runtime
//! plumbing.

use std::future::Future;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::time::{Duration, Instant};

use indexmap::IndexMap;
use serde_json::{Value, json};

use gwead::kernel::host_api::{PluginExecution, StepError, StepOutput};
use gwead::kernel::streams::{self, STREAM_EOF, StreamId};
use gwead::kernel::types::{Action, PluginManifest, StepDef};
use gwead::kernel::{DataflowEvent, Kernel, KernelConfig, KernelError};

mod common;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn long_running_step(id: &str, step_type: &str, params: Value) -> StepDef {
    {
        let mut m = StepDef::new(id.to_string(), step_type.to_string(), params);
        m.long_running = true;
        m
    }
}

fn step_deps(id: &str, step_type: &str, params: Value, deps: &[&str]) -> StepDef {
    {
        let mut m = StepDef::new(id.to_string(), step_type.to_string(), params);
        m.depends_on = deps.iter().map(|s| s.to_string()).collect();
        m
    }
}

fn dataflow_action(steps: Vec<StepDef>) -> Action {
    {
        let mut m = Action::new(steps);
        m.dataflow = true;
        m
    }
}

fn simple_manifest(name: &str, actions: IndexMap<String, Action>) -> PluginManifest {
    {
        let mut m = PluginManifest::new(name.to_string());
        m.actions = actions;
        m
    }
}

// ---------------------------------------------------------------------------
// Test step types: a long-running producer and a stream consumer.
// ---------------------------------------------------------------------------

/// Long-running producer: looks up its pre-provisioned writable from
/// `state.dataflow_outputs`, writes `chunk_count` chunks of `chunk_size`
/// bytes (filled with `chunk_byte`), then closes the writable to signal
/// EOF. Honours the action's cancellation token: a fire aborts the loop
/// after the current chunk.
///
/// Params:
/// - `chunk_count` (u64, default 10) — how many chunks to write
/// - `chunk_size` (u64, default 64) — bytes per chunk
/// - `chunk_byte` (u64, default 0x41 = 'A') — fill byte (low byte taken)
/// - `produce_delay_ms` (u64, default 0) — async sleep between chunks
///   (useful for ordering / backpressure tests)
fn dataflow_producer<'a>(
    ex: &'a mut (dyn PluginExecution + Send),
    params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move {
        let chunk_count = params
            .get("chunk_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(10);
        let chunk_size = params
            .get("chunk_size")
            .and_then(|v| v.as_u64())
            .unwrap_or(64) as usize;
        let chunk_byte = params
            .get("chunk_byte")
            .and_then(|v| v.as_u64())
            .unwrap_or(0x41) as u8;
        let produce_delay = params
            .get("produce_delay_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let step_id = ex.current_step_id().to_string();
        let writable: StreamId = match ex.dataflow_outputs().get(&step_id).copied() {
            Some(id) => id,
            None => {
                return Err(StepError::Failed(format!(
                    "dataflow_producer: no pre-provisioned writable for '{step_id}'"
                )));
            }
        };
        let streams_arc = ex.streams().clone();
        let cancel = ex.cancel_token();
        let chunk: Vec<u8> = vec![chunk_byte; chunk_size];
        let mut produced: u64 = 0;
        for _ in 0..chunk_count {
            if cancel.is_cancelled() {
                break;
            }
            if produce_delay > 0 {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(produce_delay)) => {}
                    _ = cancel.cancelled() => break,
                }
            }
            let n = streams::write_async_shared(&streams_arc, writable, &chunk, &cancel).await;
            if n < 0 {
                // The receiver was dropped (consumer side gone), or a
                // parked write was released by the token — surface as
                // a graceful exit rather than a hard error so
                // cancellation tests see a clean shutdown.
                break;
            }
            produced += 1;
        }
        // Close the writable side so the wrapped receiver sees EOF and
        // every downstream consumer's `stream_read` returns `STREAM_EOF`.
        streams::lock_shared(&streams_arc).close_handle(writable);
        Ok(StepOutput::from(json!({
            "produced_chunks": produced,
            "chunk_size": chunk_size,
            "cancelled": cancel.is_cancelled(),
        })))
    })
}

/// Variant of `dataflow_producer` that also emits `StepProgress`
/// telemetry every chunk so tests can assert the
/// sidechannel actually carries step-body-emitted events.
fn dataflow_producer_with_progress<'a>(
    ex: &'a mut (dyn PluginExecution + Send),
    params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move {
        let chunk_count = params
            .get("chunk_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(5);
        let chunk_size = params
            .get("chunk_size")
            .and_then(|v| v.as_u64())
            .unwrap_or(8) as usize;
        let chunk_byte = params
            .get("chunk_byte")
            .and_then(|v| v.as_u64())
            .unwrap_or(0x46) as u8;
        let step_id = ex.current_step_id().to_string();
        let writable: StreamId = match ex.dataflow_outputs().get(&step_id).copied() {
            Some(id) => id,
            None => {
                return Err(StepError::Failed("no pre-provisioned writable".to_string()));
            }
        };
        let streams_arc = ex.streams().clone();
        let cancel = ex.cancel_token();
        let chunk: Vec<u8> = vec![chunk_byte; chunk_size];
        let mut bytes_written: u64 = 0;
        for _ in 0..chunk_count {
            let n = streams::write_async_shared(&streams_arc, writable, &chunk, &cancel).await;
            if n < 0 {
                break;
            }
            bytes_written += n as u64;
            ex.emit_progress(&step_id, json!({ "bytes_written": bytes_written }));
        }
        streams::lock_shared(&streams_arc).close_handle(writable);
        Ok(StepOutput::from(
            json!({ "produced_chunks": chunk_count, "bytes": bytes_written }),
        ))
    })
}

/// Stream consumer: reads from `params.source` (the producer step id, whose
/// handle is in `step_results[source]` — possibly overridden by a fan-out
/// branch) until EOF. Accumulates the byte count, chunk count, and first
/// byte seen. Optional `read_throttle_ms` sleeps between reads to simulate
/// a slow consumer (for the backpressure test).
fn dataflow_consumer<'a>(
    ex: &'a mut (dyn PluginExecution + Send),
    params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move {
        let source_id = params
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let read_throttle = params
            .get("read_throttle_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let step_id = ex.current_step_id().to_string();
        // Resolve the upstream handle, honouring fan-out branch overrides.
        let handle: StreamId = match resolve_handle(ex, &source_id) {
            Some(h) => h,
            None => {
                return Err(StepError::Failed(format!(
                    "dataflow_consumer '{step_id}': no readable handle from source '{source_id}'"
                )));
            }
        };
        let streams_arc = ex.streams().clone();
        let cancel = ex.cancel_token();
        let mut buf = vec![0u8; 1024];
        let mut total_bytes: u64 = 0;
        let mut chunks: u64 = 0;
        let mut first_byte: Option<u8> = None;
        loop {
            if cancel.is_cancelled() {
                break;
            }
            let n = streams::read_async_shared(&streams_arc, handle, &mut buf).await;
            if n == STREAM_EOF {
                break;
            }
            if n < 0 {
                return Err(StepError::Failed(format!(
                    "dataflow_consumer '{step_id}': stream_read returned {n}"
                )));
            }
            let read = n as usize;
            if read > 0 && first_byte.is_none() {
                first_byte = Some(buf[0]);
            }
            total_bytes += read as u64;
            chunks += 1;
            if read_throttle > 0 {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(read_throttle)) => {}
                    _ = cancel.cancelled() => break,
                }
            }
        }
        Ok(StepOutput::from(json!({
            "total_bytes": total_bytes,
            "chunks": chunks,
            "first_byte": first_byte.map(|b| b as u64),
            "cancelled": cancel.is_cancelled(),
        })))
    })
}

fn resolve_handle(ex: &(dyn PluginExecution + Send), source_id: &str) -> Option<StreamId> {
    let value = ex.step_result(source_id)?;
    let n = value.as_u64()?;
    NonZeroU32::new(n as u32)
}

/// Long-running step that panics from inside its task. Used by the
/// dataflow panic-surfacing test (matches the parallel-wave panic
/// pattern in `tests/parallel_wave_tests.rs`).
fn dataflow_panicker<'a>(
    ex: &'a mut (dyn PluginExecution + Send),
    _params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move {
        let step_id = ex.current_step_id().to_string();
        panic!("dataflow_panicker panicking by request for step '{step_id}'");
    })
}

/// Test-only step-type impls seeded into the native impl table —
/// the kernel's route for supplying Rust step impls. The companion
/// manifest [`DATAFLOW_TEST_FIXTURE_MANIFEST`] declares the
/// `kind: "native"` impl entries the kernel resolves against the
/// seeded table.
fn seed_dataflow_test_impls(table: &mut gwead::kernel::native_impls::NativeStepImplTable) {
    table
        .insert("test.test_dataflow_fixture.producer", dataflow_producer)
        .expect("no collision on fresh table");
    table
        .insert(
            "test.test_dataflow_fixture.producer_with_progress",
            dataflow_producer_with_progress,
        )
        .expect("no collision on fresh table");
    table
        .insert("test.test_dataflow_fixture.consumer", dataflow_consumer)
        .expect("no collision on fresh table");
    table
        .insert("test.test_dataflow_fixture.panicker", dataflow_panicker)
        .expect("no collision on fresh table");
}

const DATAFLOW_TEST_FIXTURE_MANIFEST: &str = r#"{
    "name": "test_dataflow_fixture",
    "version": "0.0.0",
    "description": "Wires the four dataflow_tests step bodies (producer, producer_with_progress, consumer, panicker) for the streaming/dataflow scheduler tests.",
    "stepTypeDefs": [
        {"name": "test_dataflow_fixture.dataflow_producer",               "freelyUsable": true},
        {"name": "test_dataflow_fixture.dataflow_producer_with_progress", "freelyUsable": true},
        {"name": "test_dataflow_fixture.dataflow_consumer",               "freelyUsable": true},
        {"name": "test_dataflow_fixture.dataflow_panicker",               "freelyUsable": true}
    ],
    "stepTypeImpls": [
        {"stepType": "test_dataflow_fixture.dataflow_producer",               "kind": "native", "implRef": "test.test_dataflow_fixture.producer"},
        {"stepType": "test_dataflow_fixture.dataflow_producer_with_progress", "kind": "native", "implRef": "test.test_dataflow_fixture.producer_with_progress"},
        {"stepType": "test_dataflow_fixture.dataflow_consumer",               "kind": "native", "implRef": "test.test_dataflow_fixture.consumer"},
        {"stepType": "test_dataflow_fixture.dataflow_panicker",               "kind": "native", "implRef": "test.test_dataflow_fixture.panicker"}
    ]
}"#;

fn boot_kernel() -> Kernel {
    boot_kernel_with_limits(gwead::kernel::RuntimeLimits::default())
}

/// [`boot_kernel`], but with the write-until-refused guest (see
/// `script_runtime_mock::build_write_until_refused_wasm_bytes`) as the
/// `(script, "lua")` runtime, for tests that park a real wasm guest
/// inside `stream_write`.
fn boot_kernel_with_write_until_refused_guest() -> Kernel {
    let mut native_step_impls = gwead::kernel::native_impls::NativeStepImplTable::empty();
    seed_dataflow_test_impls(&mut native_step_impls);
    let mut kernel = Kernel::boot(common::script_runtime_mock::trusting(
        KernelConfig::default().with_native_step_impls(native_step_impls),
        &["lua"],
    ))
    .expect("kernel boot");
    common::script_runtime_mock::register_module_for_language(
        &mut kernel,
        "lua",
        common::script_runtime_mock::build_write_until_refused_wasm_bytes(),
    )
    .expect("write-until-refused guest registers");
    kernel
        .register_plugin_from_json(DATAFLOW_TEST_FIXTURE_MANIFEST)
        .expect("dataflow test fixture registers");
    kernel
}

fn boot_kernel_with_limits(limits: gwead::kernel::RuntimeLimits) -> Kernel {
    let mut native_step_impls = gwead::kernel::native_impls::NativeStepImplTable::empty();
    seed_dataflow_test_impls(&mut native_step_impls);
    let mut kernel = Kernel::boot(common::script_runtime_mock::trusting(
        KernelConfig::default()
            .with_native_step_impls(native_step_impls)
            .with_limits(limits),
        &["lua"],
    ))
    .expect("kernel boot");
    // Register the shared test-only mock
    // script runtime so `(script, "lua")` dispatches in tests that
    // include a `script` step. Lua-semantic tests belong with the
    // runtime plugin, not here.
    common::script_runtime_mock::register(&mut kernel).expect("mock script runtime registers");
    kernel
        .register_plugin_from_json(DATAFLOW_TEST_FIXTURE_MANIFEST)
        .expect("dataflow test fixture registers");
    kernel
}

// ---------------------------------------------------------------------------
// Pipeline E2E: producer + two parallel consumers
// ---------------------------------------------------------------------------

/// Transcoding-shaped pipeline: one long-running producer writing many
/// chunks of a known fill byte, two consumers (remux + thumbnail-extract
/// surrogates) each draining the full byte sequence concurrently via a
/// fan-out tee. Both consumer step_results must report the full payload;
/// the producer's step_results must report `produced_chunks` and that it
/// finished without cancellation. A single `ActionResult` carries all
/// three sets of per-step results.
#[tokio::test(flavor = "multi_thread")]
async fn pipeline_producer_with_two_concurrent_consumers() {
    let mut kernel = boot_kernel();
    let chunk_count: u64 = 50;
    let chunk_size: u64 = 64;
    let chunk_byte: u64 = 0x42; // 'B' — distinguishable from default
    let expected_bytes = chunk_count * chunk_size;

    let action = dataflow_action(vec![
        long_running_step(
            "producer",
            "test_dataflow_fixture.dataflow_producer",
            json!({
                "chunk_count": chunk_count,
                "chunk_size": chunk_size,
                "chunk_byte": chunk_byte,
            }),
        ),
        step_deps(
            "remux",
            "test_dataflow_fixture.dataflow_consumer",
            json!({ "source": "producer" }),
            &["producer"],
        ),
        step_deps(
            "thumbnail",
            "test_dataflow_fixture.dataflow_consumer",
            json!({ "source": "producer" }),
            &["producer"],
        ),
    ]);
    let mut actions = IndexMap::new();
    actions.insert("pipeline".to_string(), action);
    kernel
        .register_plugin(simple_manifest("p", actions))
        .unwrap();

    let result = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("pipeline completes");

    // Producer's step_results report what it actually wrote.
    let producer = &result.step_results["producer"];
    assert_eq!(producer["produced_chunks"], json!(chunk_count));
    assert_eq!(producer["cancelled"], json!(false));

    // Both consumers see the full stream — same byte count, same first byte.
    for consumer_id in ["remux", "thumbnail"] {
        let consumer = &result.step_results[consumer_id];
        assert_eq!(
            consumer["total_bytes"],
            json!(expected_bytes),
            "consumer '{consumer_id}' did not drain the full payload: {consumer}"
        );
        assert_eq!(
            consumer["first_byte"],
            json!(chunk_byte),
            "consumer '{consumer_id}' did not see the producer's fill byte"
        );
        assert_eq!(consumer["cancelled"], json!(false));
    }
}

/// Single-consumer variant — exercises the no-fan-out branch of the
/// pre-flight provisioner. The lone consumer reads the main readable
/// directly through `step_results[<producer>]` with no
/// `active_fanout_overrides` in play.
#[tokio::test(flavor = "multi_thread")]
async fn pipeline_single_consumer_skips_fanout() {
    let mut kernel = boot_kernel();
    let chunk_count: u64 = 20;
    let chunk_size: u64 = 32;
    let expected_bytes = chunk_count * chunk_size;

    let action = dataflow_action(vec![
        long_running_step(
            "producer",
            "test_dataflow_fixture.dataflow_producer",
            json!({
                "chunk_count": chunk_count,
                "chunk_size": chunk_size,
                "chunk_byte": 0x43, // 'C'
            }),
        ),
        step_deps(
            "drain",
            "test_dataflow_fixture.dataflow_consumer",
            json!({ "source": "producer" }),
            &["producer"],
        ),
    ]);
    let mut actions = IndexMap::new();
    actions.insert("pipeline".to_string(), action);
    kernel
        .register_plugin(simple_manifest("p", actions))
        .unwrap();

    let result = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("pipeline completes");

    assert_eq!(
        result.step_results["drain"]["total_bytes"],
        json!(expected_bytes)
    );
    assert_eq!(result.step_results["drain"]["first_byte"], json!(0x43));
}

// ---------------------------------------------------------------------------
// Backpressure: a slow consumer paces the producer
// ---------------------------------------------------------------------------

/// One slow consumer (high `read_throttle_ms`) holds back its fan-out
/// branch; the bounded per-branch channel (capacity 16) fills, the
/// forwarder blocks on `send().await`, and the producer can't get
/// further ahead than that buffer. The pipeline still completes —
/// every chunk eventually drains and both consumers see the full
/// payload — but the slow consumer's wall time is the lower bound on
/// total runtime.
///
/// Verification: the *total* runtime is at least the slow consumer's
/// own minimum (chunk_count * throttle_ms), which only holds if
/// backpressure actually couples producer pace to slow consumer pace.
/// Without backpressure the producer would race ahead, the fast
/// consumer would finish quickly, and the slow consumer would still
/// take ~chunk_count * throttle_ms — so this isn't a tight test of
/// "buffer bounded" so much as a no-deadlock + finish-correctly check
/// for the streaming-fanout-with-slow-consumer scenario.
#[tokio::test(flavor = "multi_thread")]
async fn slow_consumer_backpressures_without_deadlock() {
    let mut kernel = boot_kernel();
    let chunk_count: u64 = 30;
    let chunk_size: u64 = 64;
    let expected_bytes = chunk_count * chunk_size;

    let action = dataflow_action(vec![
        long_running_step(
            "producer",
            "test_dataflow_fixture.dataflow_producer",
            json!({
                "chunk_count": chunk_count,
                "chunk_size": chunk_size,
                "chunk_byte": 0x44, // 'D'
            }),
        ),
        step_deps(
            "fast",
            "test_dataflow_fixture.dataflow_consumer",
            json!({ "source": "producer" }),
            &["producer"],
        ),
        step_deps(
            "slow",
            "test_dataflow_fixture.dataflow_consumer",
            json!({
                "source": "producer",
                "read_throttle_ms": 5,
            }),
            &["producer"],
        ),
    ]);
    let mut actions = IndexMap::new();
    actions.insert("pipeline".to_string(), action);
    kernel
        .register_plugin(simple_manifest("p", actions))
        .unwrap();

    let start = Instant::now();
    let result = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("pipeline completes without deadlock under backpressure");
    let elapsed = start.elapsed();

    // Both consumers drained the full payload — no buffer truncation.
    for c in ["fast", "slow"] {
        assert_eq!(
            result.step_results[c]["total_bytes"],
            json!(expected_bytes),
            "consumer '{c}' did not drain the full payload"
        );
        assert_eq!(result.step_results[c]["cancelled"], json!(false));
    }

    // Total runtime ≥ chunk_count * 5ms (the slow consumer's accumulated
    // sleep). Generous lower bound — covers scheduling jitter while still
    // detecting a "consumer skipped reads" regression where slow finishes
    // instantly.
    let min_expected = Duration::from_millis(chunk_count * 5 / 2);
    assert!(
        elapsed >= min_expected,
        "pipeline finished in {elapsed:?}, expected ≥ {min_expected:?} from slow consumer's throttle"
    );
}

// ---------------------------------------------------------------------------
// Cancellation teardown
// ---------------------------------------------------------------------------

/// External cancellation tears the pipeline down within a bounded
/// timeout. The producer is configured to write a million chunks with
/// a per-chunk async delay so that, absent cancellation, the action
/// would run far longer than the test's tolerance. Firing the token
/// before any consumer has finished must unblock every spawned task
/// (the producer's select! observes `cancel.cancelled()`, every
/// consumer's read loop checks `cancel.is_cancelled()` between reads
/// and observes the producer's writable closing as the wrapping
/// receiver hits EOF). The action returns within the timeout and the
/// step_results report `cancelled: true`.
#[tokio::test(flavor = "multi_thread")]
async fn external_cancellation_tears_pipeline_down_promptly() {
    let mut kernel = boot_kernel();

    let action = dataflow_action(vec![
        long_running_step(
            "producer",
            "test_dataflow_fixture.dataflow_producer",
            json!({
                "chunk_count": 1_000_000_u64,
                "chunk_size": 16_u64,
                "chunk_byte": 0x45_u64, // 'E'
                "produce_delay_ms": 5_u64,
            }),
        ),
        step_deps(
            "drain",
            "test_dataflow_fixture.dataflow_consumer",
            json!({ "source": "producer" }),
            &["producer"],
        ),
    ]);
    let mut actions = IndexMap::new();
    actions.insert("pipeline".to_string(), action);
    kernel
        .register_plugin(simple_manifest("p", actions))
        .unwrap();

    let kernel = kernel.into_arc();
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();
    // Fire cancellation after a short delay — long enough that the
    // producer has spun up its loop, short enough that millions of
    // chunks definitely haven't streamed through.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(40)).await;
        cancel_clone.cancel();
    });

    let start = Instant::now();
    let result = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .with_cancel(cancel)
        .run()
        .await
        .expect("cancelled pipeline still returns a clean ActionResult");
    let elapsed = start.elapsed();

    // Bounded tear-down: ≤ 1 second total. Generous for CI jitter while
    // still detecting "the pipeline ignored the cancel and ran to
    // completion" (which would take many minutes at 5ms × 1M chunks).
    assert!(
        elapsed < Duration::from_secs(1),
        "pipeline failed to tear down within 1s after cancel; took {elapsed:?}"
    );

    // The producer recorded that it noticed cancellation.
    let producer = &result.step_results["producer"];
    assert_eq!(producer["cancelled"], json!(true));
    // It produced FAR fewer than 1M chunks before tear-down.
    let produced = producer["produced_chunks"].as_u64().unwrap_or(0);
    assert!(
        produced < 1_000_000,
        "expected cancel to halt producer well below the 1M target; got {produced} chunks"
    );
}

// ---------------------------------------------------------------------------
// Validation: invalid flag combinations rejected at register_plugin
// ---------------------------------------------------------------------------

/// An action cannot be both `dataflow: true` and `continuous: true` —
/// dataflow IS the long-running form. Setting both is a register-time
/// validation error.
#[tokio::test(flavor = "multi_thread")]
async fn register_rejects_dataflow_and_continuous_together() {
    let mut kernel = boot_kernel();
    let mut action = dataflow_action(vec![long_running_step(
        "p",
        "test_dataflow_fixture.dataflow_producer",
        json!({"chunk_count": 1}),
    )]);
    action.continuous = true;
    let mut actions = IndexMap::new();
    actions.insert("bad".to_string(), action);
    let err = kernel
        .register_plugin(simple_manifest("p", actions))
        .expect_err("register_plugin should reject dataflow + continuous");
    let msg = format!("{err}");
    assert!(
        msg.contains("dataflow") && msg.contains("continuous"),
        "expected error to mention both flags; got: {msg}"
    );
}

/// A step task that panics surfaces as
/// `KernelError::Execution("Dataflow task panicked: …")` — matches
/// the parallel-wave path's panic semantics. The action does not
/// crash or swallow the panic; subscribers on a `DataflowHandle`
/// see `PipelineCompleted { ok: false }` and the result oneshot
/// resolves `Err(_)`.
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_task_panic_surfaces_as_execution_error() {
    let mut kernel = boot_kernel();
    let mut actions = IndexMap::new();
    actions.insert(
        "panicker".to_string(),
        dataflow_action(vec![long_running_step(
            "boom",
            "test_dataflow_fixture.dataflow_panicker",
            json!({}),
        )]),
    );
    kernel
        .register_plugin(simple_manifest("p", actions))
        .unwrap();

    let err = kernel
        .execute("p", "panicker", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect_err("dataflow_panicker should surface as an execution error");
    match err {
        KernelError::Execution(msg) => assert!(
            msg.contains("panicked"),
            "task panic should surface as 'panicked' execution error, got: {msg}"
        ),
        other => panic!("expected Execution error for task panic, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// DataflowHandle + per-chunk sidechannel
// ---------------------------------------------------------------------------

fn count_event_kinds(events: &[DataflowEvent]) -> (usize, usize, usize, usize, usize) {
    let mut started = 0;
    let mut completed = 0;
    let mut failed = 0;
    let mut progress = 0;
    let mut pipeline_completed = 0;
    for e in events {
        match e {
            DataflowEvent::StepStarted { .. } => started += 1,
            DataflowEvent::StepCompleted { .. } => completed += 1,
            DataflowEvent::StepFailed { .. } => failed += 1,
            DataflowEvent::StepProgress { .. } => progress += 1,
            DataflowEvent::PipelineCompleted { .. } => pipeline_completed += 1,
            // DataflowEvent is #[non_exhaustive]; kinds this counter
            // doesn't know about just aren't counted.
            _ => {}
        }
    }
    (started, completed, failed, progress, pipeline_completed)
}

/// Drain every event from a `DataflowHandle::events` receiver into a
/// `Vec`. Returns when the channel closes (the scheduler has dropped
/// every sender via task tear-down + canonical-state drop).
async fn drain_events(
    mut events: tokio::sync::mpsc::Receiver<DataflowEvent>,
) -> Vec<DataflowEvent> {
    let mut out = Vec::new();
    while let Some(e) = events.recv().await {
        out.push(e);
    }
    out
}

/// A successful pipeline emits exactly one `StepStarted` and one
/// `StepCompleted{ok: true}` per step, plus one final
/// `PipelineCompleted{ok: true}`. No `StepFailed`. The `result`
/// receiver resolves to the same `ActionResult` the direct
/// `execute_action` path produces.
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_handle_emits_step_lifecycle_and_pipeline_completion() {
    let chunk_count: u64 = 10;
    let chunk_size: u64 = 16;
    let kernel = {
        let mut k = boot_kernel();
        let mut actions = IndexMap::new();
        actions.insert(
            "pipeline".to_string(),
            dataflow_action(vec![
                long_running_step(
                    "producer",
                    "test_dataflow_fixture.dataflow_producer",
                    json!({
                        "chunk_count": chunk_count,
                        "chunk_size": chunk_size,
                        "chunk_byte": 0x50,
                    }),
                ),
                step_deps(
                    "consumer",
                    "test_dataflow_fixture.dataflow_consumer",
                    json!({ "source": "producer" }),
                    &["producer"],
                ),
            ]),
        );
        k.register_plugin(simple_manifest("p", actions)).unwrap();
        k.into_arc()
    };

    let handle = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .into_dataflow_handle()
        .expect("handle returned for a dataflow action");

    // Drain events + await result in parallel; the result resolves
    // when the scheduler returns from `execute_dag`, the events
    // channel closes shortly after when the canonical ExecutionState
    // drops its sender.
    let events_task = tokio::spawn(drain_events(handle.events));
    let result = handle.result.await.expect("result delivered").expect("ok");
    let events = events_task.await.expect("events task did not panic");

    // Result mirrors the direct path: both consumer step_results
    // recorded and produced_chunks matches the requested count.
    assert_eq!(
        result.step_results["producer"]["produced_chunks"],
        json!(chunk_count)
    );
    assert_eq!(
        result.step_results["consumer"]["total_bytes"],
        json!(chunk_count * chunk_size)
    );

    let (started, completed, failed, _progress, pipeline_completed) = count_event_kinds(&events);
    assert_eq!(started, 2, "one StepStarted per step (producer + consumer)");
    assert_eq!(completed, 2, "one StepCompleted per step on success");
    assert_eq!(failed, 0, "no StepFailed on a successful pipeline");
    assert_eq!(pipeline_completed, 1, "exactly one PipelineCompleted");
    // Ordering invariant: every StepStarted precedes any
    // PipelineCompleted, and PipelineCompleted is last.
    assert!(
        matches!(
            events.last(),
            Some(DataflowEvent::PipelineCompleted { ok: true })
        ),
        "PipelineCompleted{{ok: true}} should be the final event; got {:?}",
        events.last()
    );
}

/// `StepProgress` emitted by step bodies via
/// [`ExecutionState::emit_progress`] flows through the same channel.
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_handle_carries_step_progress_events() {
    let kernel = {
        let mut k = boot_kernel();
        let mut actions = IndexMap::new();
        actions.insert(
            "pipeline".to_string(),
            dataflow_action(vec![
                long_running_step(
                    "producer",
                    "test_dataflow_fixture.dataflow_producer_with_progress",
                    json!({ "chunk_count": 5, "chunk_size": 8, "chunk_byte": 0x46 }),
                ),
                step_deps(
                    "consumer",
                    "test_dataflow_fixture.dataflow_consumer",
                    json!({ "source": "producer" }),
                    &["producer"],
                ),
            ]),
        );
        k.register_plugin(simple_manifest("p", actions)).unwrap();
        k.into_arc()
    };

    let handle = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .into_dataflow_handle()
        .expect("handle");

    let events_task = tokio::spawn(drain_events(handle.events));
    let _ = handle.result.await.expect("delivered").expect("ok");
    let events = events_task.await.unwrap();

    let progress: Vec<&DataflowEvent> = events
        .iter()
        .filter(|e| matches!(e, DataflowEvent::StepProgress { .. }))
        .collect();
    assert_eq!(
        progress.len(),
        5,
        "one StepProgress per chunk written; got {progress:?}"
    );
    // Progress values should be monotonically increasing
    let mut last_bytes: u64 = 0;
    for e in &progress {
        if let DataflowEvent::StepProgress { step_id, payload } = e {
            assert_eq!(step_id, "producer");
            let bytes = payload["bytes_written"].as_u64().unwrap();
            assert!(
                bytes > last_bytes,
                "bytes_written must be monotonic: {bytes} after {last_bytes}"
            );
            last_bytes = bytes;
        }
    }
}

/// External cancellation through the handle fires the same
/// CancellationToken plumbed into every step task; the scheduler
/// emits PipelineCompleted{ok: false} and the result receiver
/// resolves with the producer's tolerated cancellation.
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_handle_cancel_terminates_and_marks_pipeline_failed() {
    let kernel = {
        let mut k = boot_kernel();
        let mut actions = IndexMap::new();
        actions.insert(
            "pipeline".to_string(),
            dataflow_action(vec![
                long_running_step(
                    "producer",
                    "test_dataflow_fixture.dataflow_producer",
                    json!({
                        "chunk_count": 1_000_000_u64,
                        "chunk_size": 8_u64,
                        "produce_delay_ms": 3_u64,
                    }),
                ),
                step_deps(
                    "consumer",
                    "test_dataflow_fixture.dataflow_consumer",
                    json!({ "source": "producer" }),
                    &["producer"],
                ),
            ]),
        );
        k.register_plugin(simple_manifest("p", actions)).unwrap();
        k.into_arc()
    };

    let handle = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .into_dataflow_handle()
        .expect("handle");

    // Hand the cancel out to a separate task so we can fire it
    // mid-flight without dropping the events receiver.
    let cancel_token = handle.cancel_token();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        cancel_token.cancel();
    });

    let start = Instant::now();
    let events_task = tokio::spawn(drain_events(handle.events));
    let result = handle.result.await.expect("delivered").expect("ok");
    let elapsed = start.elapsed();
    let events = events_task.await.unwrap();

    assert!(
        elapsed < Duration::from_secs(1),
        "cancel via handle should tear down within 1s; took {elapsed:?}"
    );
    assert_eq!(result.step_results["producer"]["cancelled"], json!(true));

    // Cooperative cancellation surfaces through `PipelineCompleted`
    // with `ok: false`: every step returned a normal `Ok(true)` (so
    // the result oneshot resolves `Ok(_)` and `step_results` is
    // preserved), but the run did NOT complete normally. Asserting
    // the exact `ok: false` rather than "some PipelineCompleted
    // event exists" — the latter would pass even when cancellation
    // was silently treated as success.
    let pipeline_completed = events
        .iter()
        .find_map(|e| match e {
            DataflowEvent::PipelineCompleted { ok } => Some(*ok),
            _ => None,
        })
        .expect("PipelineCompleted should fire after cancellation");
    assert!(
        !pipeline_completed,
        "cancelled run must report `PipelineCompleted {{ ok: false }}` so callers \
         can distinguish a cancelled pipeline from a clean completion"
    );
}

/// Dropping the events receiver mid-pipeline must not kill the
/// pipeline — the scheduler keeps running and the result still
/// resolves cleanly. (Per `DataflowHandle` docs.)
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_handle_pipeline_survives_dropped_events_receiver() {
    let kernel = {
        let mut k = boot_kernel();
        let mut actions = IndexMap::new();
        actions.insert(
            "pipeline".to_string(),
            dataflow_action(vec![
                long_running_step(
                    "producer",
                    "test_dataflow_fixture.dataflow_producer",
                    json!({ "chunk_count": 20_u64, "chunk_size": 32_u64, "chunk_byte": 0x51_u64 }),
                ),
                step_deps(
                    "consumer",
                    "test_dataflow_fixture.dataflow_consumer",
                    json!({ "source": "producer" }),
                    &["producer"],
                ),
            ]),
        );
        k.register_plugin(simple_manifest("p", actions)).unwrap();
        k.into_arc()
    };

    let handle = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .into_dataflow_handle()
        .expect("handle");

    // Drop the events receiver immediately. Scheduler's emit_event
    // helper uses try_send which fails silently on a closed channel
    // — pipeline must still complete.
    drop(handle.events);

    let result = handle
        .result
        .await
        .expect("result delivered even with no events listener");
    let ok = result.expect("pipeline succeeded");
    assert_eq!(ok.step_results["producer"]["produced_chunks"], json!(20));
    assert_eq!(ok.step_results["consumer"]["total_bytes"], json!(20 * 32));
}

/// Contract: awaiting `handle.result` WITHOUT draining
/// `handle.events` must not deadlock, even when the bounded events
/// channel is full. If the terminal `PipelineCompleted` were delivered
/// via an inline `send().await`, a full buffer would hang the
/// scheduler — and therefore `handle.result` — forever. Natural usage
/// (result-only callers) has to be safe, so the terminator is handed
/// to a detached sender task instead.
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_result_resolves_without_events_drain_on_full_channel() {
    let kernel = {
        // Capacity 1: the very first lifecycle event fills the buffer,
        // so the terminal event can't possibly fit at emit time.
        let mut k = boot_kernel_with_limits(
            gwead::kernel::RuntimeLimits::default().with_dataflow_events_capacity(1),
        );
        let mut actions = IndexMap::new();
        actions.insert(
            "pipeline".to_string(),
            dataflow_action(vec![
                long_running_step(
                    "producer",
                    "test_dataflow_fixture.dataflow_producer",
                    json!({ "chunk_count": 8_u64, "chunk_size": 16_u64, "chunk_byte": 0x52_u64 }),
                ),
                step_deps(
                    "consumer",
                    "test_dataflow_fixture.dataflow_consumer",
                    json!({ "source": "producer" }),
                    &["producer"],
                ),
            ]),
        );
        k.register_plugin(simple_manifest("p", actions)).unwrap();
        k.into_arc()
    };

    let handle = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .into_dataflow_handle()
        .expect("handle");

    // Hold the events receiver open (channel stays full) but never
    // read from it until the result has resolved.
    let mut events = handle.events;

    let result = tokio::time::timeout(std::time::Duration::from_secs(10), handle.result)
        .await
        .expect("result must resolve without an events drain — deadlock regression")
        .expect("result delivered");
    let ok = result.expect("pipeline succeeded");
    assert_eq!(ok.step_results["producer"]["produced_chunks"], json!(8));

    // The terminator is still delivered reliably once the receiver
    // catches up — draining now must surface exactly one
    // PipelineCompleted.
    let mut pipeline_completed = 0;
    while let Some(ev) = events.recv().await {
        if matches!(ev, DataflowEvent::PipelineCompleted { .. }) {
            pipeline_completed += 1;
        }
    }
    assert_eq!(
        pipeline_completed, 1,
        "PipelineCompleted must survive a full buffer via the detached sender"
    );
}

/// `into_dataflow_handle` against an action without
/// `dataflow: true` is a Validation error — analogous to
/// `into_continuous_handle` against a non-continuous action.
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_handle_rejects_non_dataflow_action() {
    let mut k = boot_kernel();
    let mut actions = IndexMap::new();
    let mut action = dataflow_action(vec![]);
    action.dataflow = false; // strip the flag — should reject
    actions.insert("ordinary".to_string(), action);
    k.register_plugin(simple_manifest("p", actions)).unwrap();
    let kernel = k.into_arc();
    let result = kernel
        .execute("p", "ordinary", json!({}))
        .with_config(&json!({}))
        .into_dataflow_handle();
    let err = match result {
        Ok(_) => panic!("non-dataflow action should be rejected at handle creation"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("not marked dataflow") || msg.contains("dataflow"),
        "expected validation error mentioning dataflow; got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Validation: invalid flag combinations rejected at register_plugin
// ---------------------------------------------------------------------------

/// `long_running: true` is only meaningful inside a dataflow action.
/// A non-dataflow action with a long-running step is a register-time
/// validation error — surfaces a misconfigured manifest immediately
/// rather than silently scheduling the step on the wave path where the
/// flag does nothing.
#[tokio::test(flavor = "multi_thread")]
async fn register_rejects_long_running_outside_dataflow() {
    let mut kernel = boot_kernel();
    let mut action = dataflow_action(vec![long_running_step(
        "p",
        "test_dataflow_fixture.dataflow_producer",
        json!({"chunk_count": 1}),
    )]);
    action.dataflow = false; // strip the dataflow flag — now invalid
    let mut actions = IndexMap::new();
    actions.insert("bad".to_string(), action);
    let err = kernel
        .register_plugin(simple_manifest("p", actions))
        .expect_err("register_plugin should reject long_running outside dataflow");
    let msg = format!("{err}");
    assert!(
        msg.contains("long_running") && msg.contains("dataflow"),
        "expected error to mention long_running + dataflow; got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// DataflowStreamingHandle (live action output via pre-allocated
// caller-side writable)
// ---------------------------------------------------------------------------

/// The streaming handle exposes the producer step's output as a live
/// `ReadableSource` the caller can drain while the action runs. This
/// is the entry point an SSE or chunked-transfer endpoint uses to
/// relay a plugin's output to a remote client. End-to-end
/// invariant: total bytes drained from `output` equals what the
/// producer wrote, and the action's `result` resolves with that
/// step's `produced_chunks` count visible in `step_results`.
#[tokio::test(flavor = "multi_thread")]
async fn streaming_handle_exposes_live_producer_output() {
    use futures::StreamExt;

    let chunk_count: u64 = 25;
    let chunk_size: u64 = 32;
    let chunk_byte: u64 = 0x53; // 'S'
    let expected_bytes = (chunk_count * chunk_size) as usize;

    let kernel = {
        let mut k = boot_kernel();
        let mut actions = IndexMap::new();
        actions.insert(
            "pipeline".to_string(),
            dataflow_action(vec![long_running_step(
                "producer",
                "test_dataflow_fixture.dataflow_producer",
                json!({
                    "chunk_count": chunk_count,
                    "chunk_size": chunk_size,
                    "chunk_byte": chunk_byte,
                    "produce_delay_ms": 1,
                }),
            )]),
        );
        k.register_plugin(simple_manifest("p", actions)).unwrap();
        k.into_arc()
    };

    let handle = kernel
        .execute("p", "pipeline", json!({}))
        .with_config(&json!({}))
        .with_exec_ctx(gwead::kernel::ExecutionContext::default())
        .into_dataflow_streaming_handle()
        .expect("streaming handle for dataflow action");

    let gwead::kernel::DataflowStreamingHandle {
        mut output,
        events: _events,
        result,
        ..
    } = handle;

    // Drain the producer's bytes off the caller-owned readable while
    // the action is still running. `output.next()` returns `None` when
    // the producer closes its writable at end-of-action.
    let mut drained: Vec<u8> = Vec::with_capacity(expected_bytes);
    while let Some(item) = output.next().await {
        let bytes = item.expect("clean read from streaming output");
        drained.extend_from_slice(&bytes);
    }

    assert_eq!(
        drained.len(),
        expected_bytes,
        "drained byte count must equal producer's total write",
    );
    assert!(
        drained.iter().all(|&b| b == chunk_byte as u8),
        "every byte should match the producer's configured fill byte",
    );

    let action_result = result.await.expect("delivered").expect("ok");
    assert_eq!(
        action_result.step_results["producer"]["produced_chunks"],
        json!(chunk_count)
    );
    assert_eq!(
        action_result.step_results["producer"]["cancelled"],
        json!(false)
    );
}

/// Non-dataflow action: streaming handle rejects at creation time, same
/// as `into_dataflow_handle`.
#[tokio::test(flavor = "multi_thread")]
async fn streaming_handle_rejects_non_dataflow_action() {
    let mut k = boot_kernel();
    let mut action = dataflow_action(vec![]);
    action.dataflow = false;
    let mut actions = IndexMap::new();
    actions.insert("ordinary".to_string(), action);
    k.register_plugin(simple_manifest("p", actions)).unwrap();
    let kernel = k.into_arc();

    let result = kernel
        .execute("p", "ordinary", json!({}))
        .with_config(&json!({}))
        .with_exec_ctx(gwead::kernel::ExecutionContext::default())
        .into_dataflow_streaming_handle();
    let err = match result {
        Ok(_) => panic!("non-dataflow action must be rejected"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("not marked dataflow"),
        "expected dataflow-validation error, got: {msg}"
    );
}

/// Long-running step with in-action consumers: ambiguous output
/// destination (sibling vs. caller). Reject — same constraint as
/// `io.invoke_streaming`.
#[tokio::test(flavor = "multi_thread")]
async fn streaming_handle_rejects_long_running_with_in_action_consumers() {
    let mut k = boot_kernel();
    let mut actions = IndexMap::new();
    actions.insert(
        "split".to_string(),
        dataflow_action(vec![
            long_running_step(
                "producer",
                "test_dataflow_fixture.dataflow_producer",
                json!({ "chunk_count": 1, "chunk_size": 1, "chunk_byte": 0x41 }),
            ),
            step_deps(
                "sibling",
                "test_dataflow_fixture.dataflow_consumer",
                json!({ "source": "producer" }),
                &["producer"],
            ),
        ]),
    );
    k.register_plugin(simple_manifest("p", actions)).unwrap();
    let kernel = k.into_arc();

    let result = kernel
        .execute("p", "split", json!({}))
        .with_config(&json!({}))
        .with_exec_ctx(gwead::kernel::ExecutionContext::default())
        .into_dataflow_streaming_handle();
    let err = match result {
        Ok(_) => panic!("producer with in-action consumers is ambiguous for streaming"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("in-action consumer"),
        "expected in-action-consumer rejection, got: {msg}"
    );
}

/// Cancel propagates: firing the handle's cancel token aborts the
/// producer mid-stream. Asserts the producer's step body observed the
/// cancel token (`cancelled: true` in step_results) and fewer than
/// `chunk_count` chunks were actually produced. Verifies the same
/// cooperative-cancel contract on the streaming entry point that
/// `DataflowHandle::cancel` provides on the non-streaming sibling.
#[tokio::test(flavor = "multi_thread")]
async fn streaming_handle_cancel_propagates_into_producer() {
    use futures::StreamExt;

    let kernel = {
        let mut k = boot_kernel();
        let mut actions = IndexMap::new();
        actions.insert(
            "slow".to_string(),
            dataflow_action(vec![long_running_step(
                "producer",
                "test_dataflow_fixture.dataflow_producer",
                json!({
                    "chunk_count": 1000,
                    "chunk_size": 16,
                    "chunk_byte": 0x43,
                    "produce_delay_ms": 5,
                }),
            )]),
        );
        k.register_plugin(simple_manifest("p", actions)).unwrap();
        k.into_arc()
    };

    let mut handle = kernel
        .execute("p", "slow", json!({}))
        .with_config(&json!({}))
        .with_exec_ctx(gwead::kernel::ExecutionContext::default())
        .into_dataflow_streaming_handle()
        .expect("handle");

    // Read a few chunks to ensure the producer is actually running,
    // then fire the cancel token — the producer's body races
    // `cancel.cancelled()` against `sleep(produce_delay_ms)` in its
    // loop and exits cleanly.
    let mut read_chunks = 0;
    while let Some(item) = handle.output.next().await {
        let _ = item.expect("clean read");
        read_chunks += 1;
        if read_chunks >= 3 {
            break;
        }
    }
    assert!(
        read_chunks > 0,
        "should have drained at least one chunk before cancelling"
    );
    handle.cancel();

    // Drain anything remaining on the output (producer may emit a few
    // more in-flight chunks before observing cancel on its next race).
    while let Some(item) = handle.output.next().await {
        let _ = item.expect("clean read during shutdown");
    }

    let action_result = handle.result.await.expect("delivered").expect("ok");
    let produced = action_result.step_results["producer"]["produced_chunks"]
        .as_u64()
        .expect("u64");
    let cancelled = action_result.step_results["producer"]["cancelled"]
        .as_bool()
        .expect("bool");
    assert!(cancelled, "producer should record cancelled=true");
    assert!(
        produced < 1000,
        "cancel should abort the producer well before all 1000 chunks; got {produced}"
    );
}

/// A consumer that holds its readable open but never reads leaves the
/// producer parked on a full channel, inside `stream_write`, where it
/// cannot poll its token. Cancelling the handle must still end the
/// pipeline: the parked write is released with `STREAM_CANCELLED`,
/// the producer stops, and the result arrives. Before the backstop
/// this hung forever — the `timeout` is what turns that into a
/// failure.
#[tokio::test(flavor = "multi_thread")]
async fn cancel_releases_a_producer_parked_on_a_stalled_consumer() {
    let kernel = {
        let mut k = boot_kernel();
        let mut actions = IndexMap::new();
        actions.insert(
            "relay".to_string(),
            dataflow_action(vec![long_running_step(
                "producer",
                "test_dataflow_fixture.dataflow_producer",
                json!({ "chunk_count": 100_000, "chunk_size": 16 }),
            )]),
        );
        k.register_plugin(simple_manifest("p", actions)).unwrap();
        k.into_arc()
    };

    let handle = kernel
        .execute("p", "relay", json!({}))
        .with_config(&json!({}))
        .with_exec_ctx(gwead::kernel::ExecutionContext::default())
        .into_dataflow_streaming_handle()
        .expect("handle");

    // Long enough for the producer to fill the channel and park. The
    // output is deliberately held open and never read.
    tokio::time::sleep(Duration::from_millis(100)).await;
    handle.cancel();

    let action_result = tokio::time::timeout(Duration::from_secs(5), handle.result)
        .await
        .expect("the cancel reaches the parked writer and the pipeline ends")
        .expect("delivered")
        .expect("ok");
    let produced = action_result.step_results["producer"]["produced_chunks"]
        .as_u64()
        .expect("u64");
    assert!(
        action_result.step_results["producer"]["cancelled"]
            .as_bool()
            .expect("bool"),
        "the producer stopped because it was cancelled"
    );
    assert!(
        produced < 100_000,
        "the producer stopped at the channel's capacity, not the end: {produced}"
    );
    drop(handle.output);
}

/// The same stall with a real wasm guest: the guest loops on the
/// `stream_write` import and parks there once the channel is full.
/// Cancelling the handle releases the import with `STREAM_CANCELLED`,
/// which the guest reports as its result — the code a relay guest
/// keys its shutdown on.
#[tokio::test(flavor = "multi_thread")]
async fn cancel_releases_a_wasm_guest_parked_in_stream_write() {
    let kernel = {
        let mut k = boot_kernel_with_write_until_refused_guest();
        let mut actions = IndexMap::new();
        actions.insert(
            "relay".to_string(),
            dataflow_action(vec![long_running_step(
                "producer",
                "script",
                json!({ "language": "lua", "source": "-- writes until refused" }),
            )]),
        );
        k.register_plugin(simple_manifest("p", actions)).unwrap();
        k.into_arc()
    };

    let handle = kernel
        .execute("p", "relay", json!({}))
        .with_config(&json!({}))
        .with_exec_ctx(gwead::kernel::ExecutionContext::default())
        .into_dataflow_streaming_handle()
        .expect("handle");

    tokio::time::sleep(Duration::from_millis(100)).await;
    handle.cancel();

    let action_result = tokio::time::timeout(Duration::from_secs(5), handle.result)
        .await
        .expect("the cancel reaches the guest parked in stream_write")
        .expect("delivered")
        .expect("ok");
    assert_eq!(
        action_result.step_results["producer"],
        json!("cancelled"),
        "the guest's parked write returned STREAM_CANCELLED"
    );
    drop(handle.output);
}
