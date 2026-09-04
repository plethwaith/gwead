//! Streaming-dataflow scheduler for actions marked `dataflow: true`.
//!
//! # The shape that doesn't fit the wave scheduler
//!
//! [`super::runtime::WasmRuntime::execute_dag`] is wave-based: it runs the DAG
//! one topological layer at a time, optionally fanning a wave across tokio
//! tasks and serialising across waves. That model works for actions
//! whose steps either return discrete values or hand off a fully-buffered
//! stream to the next wave. It does *not* work for:
//!
//! - **Long-running source steps** — an ffmpeg producer, a speech-to-text
//!   model, a message-queue consumer — whose task lifetime spans the entire
//!   pipeline rather than a single wave iteration.
//! - **Stage-to-stage backpressure inside one DAG run** — the producer must
//!   pace itself off the slowest downstream consumer while *all* downstream
//!   consumers are draining concurrently. Wave-by-wave execution gates the
//!   consumer side behind the producer's wave completion.
//!
//! The dataflow scheduler addresses both by giving every step its own tokio
//! task, pre-provisioning the readable stream handles long-running producers
//! will fill, and joining everything at pipeline termination into a single
//! [`ActionResult`].
//!
//! # What starts when
//!
//! A step is spawned as soon as its **value** dependencies are satisfied — a
//! dependency on a long-running producer is not one of those, because the
//! producer's handle exists before any task spawns. In practice that means
//! every stage of a streaming pipeline starts at t=0, exactly as if nothing
//! were gated, since a pipeline wired through streams has no value
//! dependencies in it.
//!
//! A dependency on an *ordinary* step is different: its result is a value
//! that does not exist until it has run. Such a step waits, and is forked
//! from the canonical state after its dependency merges. Spawning it eagerly
//! would make `{{$steps.a.result}}` resolve to `""` under `dataflow: true`
//! while the same manifest yields `42` in wave mode.
//! [`super::dag::DagPlan::deps`] carries both declared `dependsOn` edges and
//! the ones inferred from template references, so both gate the spawn.
//!
//! # Pre-flight stream provisioning
//!
//! Before any task is spawned, the scheduler walks
//! [`super::types::Action::steps`] and, for every step marked
//! [`super::types::StepDef::long_running`]:
//!
//! 1. Registers a [`Writable`]+receiver pair on the shared stream registry —
//!    the producer's "output handle", reachable from inside the producer step
//!    body via `ExecutionState::dataflow_outputs`.
//! 2. Wraps the receiver as a [`ReadableSource`] and registers it as a
//!    readable on the same registry — the "main readable handle".
//! 3. Stashes the main readable id into `step_results[<producer.id>]` so
//!    every downstream consumer's resolution surface sees
//!    `steps.<producer>.result` = handle from the moment the consumer task
//!    starts running.
//! 4. If the producer has more than one consumer in
//!    [`super::dag::DagPlan::consumers`], installs streaming fan-out on the
//!    main readable via
//!    [`super::streams::StreamRegistry::fan_out_readable_streaming`]. Each
//!    consumer's task gets its own branch handle via
//!    `ExecutionState::active_fanout_overrides`.
//!
//! [`Writable`]: super::streams::StreamDirection::Writable
//! [`ReadableSource`]: super::streams::ReadableSource
//!
//! # Cooperative cancellation
//!
//! The action's [`tokio_util::sync::CancellationToken`] (pulled from
//! [`super::runtime::InvocationContext::cancel`], with a fresh
//! never-cancelled token when the caller didn't supply one) is cloned into
//! every spawned task's `ExecutionState`. Step bodies that hold open a stream
//! source race `state.cancel.cancelled()` against their producer loop's
//! next item; a fire of the token unblocks every consumer's `stream_read`
//! via the mpsc-channel forwarder dropping its senders.
//!
//! The scheduler itself does NOT `abort_all` on cancel — it just drains
//! `joinset.join_next()` to completion. Step bodies observe the token and
//! exit cleanly so they can write a final `step_results` slot reflecting
//! why they stopped. A misbehaving step type that ignores `cancel` would
//! hang the action indefinitely — by default a dataflow action has NO
//! wallclock backstop (streaming pipelines legitimately run
//! minutes-to-days). Manifests that want a hard cap declare
//! `wallclockTimeoutMs` explicitly; see `Action::wallclock_timeout_ms`
//! for the precedence rules.
//!
//! The first task error short-circuits the same way: the scheduler fires
//! the cancel token internally so still-running tasks tear down through
//! the same path. Cooperative cancellation is reported through
//! [`super::DataflowEvent::PipelineCompleted`] with `ok: false`; the
//! action's `Result<ActionResult, KernelError>` still resolves `Ok(_)`
//! and carries the partial `step_results`, so callers can introspect
//! how each step exited.
//!
//! # Single ActionResult
//!
//! Unlike [`ExecuteActionRequest::into_continuous_handle`](super::execute_request::ExecuteActionRequest::into_continuous_handle) (which emits one
//! `ActionResult` per loop iteration), the dataflow scheduler emits exactly
//! one `ActionResult` at pipeline termination — every long-running stage's
//! final state is in `step_results`; chunks themselves flow through the
//! stream registry, not the action's return value.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use tokio::task::JoinSet;
use wasmtime::{Linker, Store};

use super::KernelError;
use super::dag::DagPlan;
use super::exec_context::ExecutionContext;
use super::host_api::{self, ExecutionState, ExecutionStateParams};
use super::runtime::{InvocationContext, WasmRuntime};
use super::streams::{ReadableSource, StreamId};
use super::types::{Action, ActionResult, StepDef};

/// Per-task tuple yielded by the JoinSet on the dataflow path: the step
/// index (informational), the step definition, the step's terminal
/// `Store<ExecutionState>` (so its writes can be merged back into the canonical
/// state), and the task body's run result. Aliased to keep the JoinSet
/// declaration readable (clippy::type_complexity).
type DataflowTaskResult = (
    usize,
    StepDef,
    Store<ExecutionState>,
    Result<bool, KernelError>,
);

/// Entry point invoked by [`super::runtime::WasmRuntime::execute_dag`] when
/// the action is marked `dataflow: true`.
///
/// Signature mirrors `execute_dag` so the dispatch gate can hand its args
/// through unchanged.
#[allow(clippy::too_many_arguments)]
pub(super) async fn execute_dag_dataflow(
    runtime: &WasmRuntime,
    plugin_name: &str,
    action: &Action,
    plan: &DagPlan,
    input: Value,
    config: &Value,
    secrets: &Value,
    script_runtimes: std::sync::Arc<
        std::collections::HashMap<String, std::sync::Arc<wasmtime::Module>>,
    >,
    exec_ctx: ExecutionContext,
    ctx: InvocationContext,
    limits: super::RuntimeLimits,
) -> Result<ActionResult, KernelError> {
    let drain_streams = ctx.drain_streams;
    let pre_allocated_outputs = ctx.pre_allocated_outputs.clone();

    // Build the canonical ExecutionState. `ctx.cancel = None` would yield a
    // never-cancelled token via `ExecutionState::new` — but the dataflow path
    // needs a token the scheduler can also fire on first error, so allocate
    // one up front when the caller didn't supply one.
    let cancel = ctx.cancel.clone().unwrap_or_default();

    let dataflow_events = ctx.dataflow_events.clone();
    let mut canonical_state = ExecutionState::new(ExecutionStateParams {
        plugin_name: plugin_name.to_string(),
        action: action.clone(),
        input,
        config: config.clone(),
        secrets: secrets.clone(),
        script_runtimes,
        engine: runtime.engine().clone(),
        exec_ctx,
        streams: ctx.streams,
        invoke_depth: ctx.invoke_depth,
        dispatch_depth: ctx.dispatch_depth,
        kernel: ctx.kernel,
        trigger: ctx.trigger,
        secret_resolver: ctx.secret_resolver,
        limits: limits.clone(),
        deadline: ctx.deadline,
        cancel: Some(cancel.clone()),
        dataflow_events: dataflow_events.clone(),
        step_type_access: ctx.step_type_access.clone(),
    });

    // Pre-flight: provision a writable+readable pipe (and fan-out branches
    // when multi-consumer) for every long-running producer. Sets
    // step_results[producer_id] to the main readable handle so consumer
    // resolution surfaces resolve `steps.<producer>.result` immediately.
    //
    // A pre-flight failure resolves the pipeline like any other error:
    // with its terminator, since the handle is already in the caller's
    // hands and nothing later would emit one.
    let engine = runtime.engine().clone();
    let prepared = provision_dataflow_streams(
        &mut canonical_state,
        action,
        plan,
        pre_allocated_outputs.as_ref(),
    )
    .and_then(|fanout_branches| {
        // Linker setup — same registration path as the wave scheduler.
        let mut linker = Linker::new(&engine);
        host_api::register_kernel_services(&mut linker)?;
        runtime.register_linker_imports(&mut linker)?;
        Ok((fanout_branches, Arc::new(linker)))
    });
    let (fanout_branches, linker) = match prepared {
        Ok(prepared) => prepared,
        Err(e) => {
            emit_terminal_event(
                dataflow_events.as_ref(),
                super::DataflowEvent::PipelineCompleted { ok: false },
            )
            .await;
            if drain_streams && canonical_state.invoke_depth == 0 {
                super::streams::lock_shared(&canonical_state.streams).drain();
            }
            return Err(e);
        }
    };

    // Each task gets a forked `ExecutionState` clone (the stream registry,
    // `dataflow_outputs`, cancel token, and events sender are all
    // refcount-shared so forking is cheap). Consumer-side branch overrides
    // are baked into each forked state before spawn.
    //
    // The scheduler emits `StepStarted` immediately before spawning and
    // (later) `StepCompleted` / `StepFailed` immediately after joining;
    // step bodies can emit their own `StepProgress` events via
    // `ExecutionState::emit_progress`.
    //
    // # Which steps start immediately, and which wait
    //
    // It is tempting to spawn every step at once, on the reasoning that
    // dataflow consumers synchronise through stream reads. That holds for
    // a dependency on a **long-running** producer: its handle is
    // pre-provisioned above, so `steps.<producer>.result` resolves from the
    // moment any consumer task starts.
    //
    // It does not hold for a dependency on an ordinary step, whose result
    // is a *value* that exists only once it has run. Spawned eagerly, such
    // a step would read the dependency out of a state snapshot taken
    // before the dependency executed and get `""` — the same manifest
    // that yields `42` in wave mode would yield `""` here,
    // deterministically, with no error. A silent wrong answer, which is
    // worse than a loud one.
    //
    // So a step waits for exactly its non-long-running dependencies, and
    // is spawned from a fresh clone of the canonical state once they have
    // merged. Steps with no dependencies, or only long-running ones, still
    // all start at t=0 — the streaming pipeline shape is untouched, because
    // that is the shape with no value dependencies in it.
    let baseline_variables = canonical_state.variables.clone();
    let step_count = action.steps.len();
    let mut canonical_store = Store::new(&engine, canonical_state);
    let mut joinset: JoinSet<DataflowTaskResult> = JoinSet::new();

    // Count of dependencies each step is still waiting on. Long-running
    // deps are never counted: they are satisfied before the first spawn and
    // do not "complete" until pipeline end, so counting them would deadlock
    // every consumer of a producer — the exact pipeline this scheduler
    // exists to run.
    let mut awaiting: Vec<usize> = (0..step_count)
        .map(|i| {
            plan.deps[i]
                .iter()
                .filter(|&&d| !action.steps[d].long_running)
                .count()
        })
        .collect();
    let mut spawned = vec![false; step_count];

    for idx in 0..step_count {
        if awaiting[idx] == 0 {
            spawn_dataflow_step(SpawnArgs {
                joinset: &mut joinset,
                engine: &engine,
                linker: &linker,
                canonical: canonical_store.data(),
                action,
                plan,
                fanout_branches: &fanout_branches,
                dataflow_events: dataflow_events.as_ref(),
                step_idx: idx,
            });
            spawned[idx] = true;
        }
    }

    // Drive the joinset to completion. Cancellation is **cooperative**:
    // step bodies observe `state.cancel.is_cancelled()` (or race
    // `cancel.cancelled()` in a `tokio::select!`) and return cleanly,
    // which lets them write a final `step_results` slot reflecting why
    // they exited. The scheduler does NOT `abort_all` on cancel — that
    // would kill tasks mid-`write_async` and leave torn state. A
    // misbehaving step type that ignores `cancel` would hang the
    // action indefinitely. The only hard backstop is the action's own
    // `wallclockTimeoutMs`, and a dataflow action declaring none has
    // NO automatic cap by design, so the backstop only exists when the
    // manifest asks for it.
    //
    // The first task error short-circuits the same way: fire the
    // token so still-running tasks observe it, then drain the
    // joinset to give them time to exit cleanly.
    let mut first_error: Option<KernelError> = None;
    while !joinset.is_empty() {
        tokio::select! {
            Some(joined) = joinset.join_next() => {
                let (step_idx, step, task_store, run_result) = match joined {
                    Ok(j) => j,
                    Err(je) if je.is_cancelled() => continue,
                    Err(je) => {
                        // A panicked step task must still emit the
                        // terminator before returning; otherwise an
                        // events subscriber keyed on
                        // `PipelineCompleted` waits for channel-close
                        // or forever. `handle.result` resolves `Err`
                        // either way, but the two consumers must agree
                        // about whether the pipeline has ended.
                        emit_terminal_event(
                            dataflow_events.as_ref(),
                            super::DataflowEvent::PipelineCompleted { ok: false },
                        )
                        .await;
                        if drain_streams && canonical_store.data().invoke_depth == 0 {
                            super::streams::lock_shared(&canonical_store.data().streams).drain();
                        }
                        return Err(KernelError::Execution(format!(
                            "Dataflow task panicked: {je}"
                        )));
                    }
                };
                let task_state = task_store.into_data();
                let body_ok = matches!(run_result, Ok(true));
                // Only a pipeline driven through a handle has the
                // wind-down contract: the caller is listening for
                // `PipelineCompleted` and inspects per-step state. The
                // `run()`, `invoke` and role-dispatch paths have no
                // events channel and no such contract, so there the
                // step's own answer decides: a step that stops with
                // `StepError::Cancelled` fails the pipeline with
                // `Cancelled` like any other action, while a step that
                // answers the token with an `Ok` (the `cancelled`
                // sidecar idiom) keeps its `Ok` and the pipeline
                // resolves `Ok` with the sidecars for the caller to
                // inspect, as `run()` on a dataflow action always has.
                let winding_down = cancel.is_cancelled() && dataflow_events.is_some();
                let candidate_error = match run_result {
                    // A step that stopped on the pipeline's own cancel
                    // is winding down, not failing. The handle's
                    // contract for a cancel is `Ok` with whatever was
                    // written plus `PipelineCompleted { ok: false }`,
                    // whether the step said so with a `cancelled`
                    // sidecar on an `Ok` or with `StepError::Cancelled`.
                    // (Under the wallclock deadline the wrapper turns
                    // that `Ok` into `ExecutionTimeout`.)
                    Err(KernelError::Cancelled { .. }) if winding_down => None,
                    Ok(false) if task_state.cancelled && winding_down => None,
                    Err(e) => Some(e),
                    Ok(true) => None,
                    // Any failure in the dataflow scheduler
                    // propagates; manifest-side recovery uses
                    // `try.catch`.
                    Ok(false) => Some(super::runtime::step_failure_to_error(&task_state, &step)),
                };
                // Emit the per-step lifecycle event. `StepFailed` carries
                // the textual error so a UI can show it without waiting
                // for the pipeline-final ActionResult; `StepCompleted`
                // carries `ok`: `true` for a normal finish, `false` for
                // a step that wound down on the pipeline's own cancel.
                // Any failure is reported as `StepFailed` instead.
                match &candidate_error {
                    Some(err) => emit_event(
                        dataflow_events.as_ref(),
                        super::DataflowEvent::StepFailed {
                            step_id: step.id.clone(),
                            error: err.to_string(),
                        },
                    ),
                    None => emit_event(
                        dataflow_events.as_ref(),
                        super::DataflowEvent::StepCompleted {
                            step_id: step.id.clone(),
                            ok: body_ok,
                        },
                    ),
                }
                super::runtime::merge_task_state(
                    &mut canonical_store,
                    task_state,
                    &step.id,
                    &baseline_variables,
                );
                if first_error.is_none() && candidate_error.is_some() {
                    first_error = candidate_error;
                    // Fire the cancel token so every still-running
                    // step body observes it cooperatively and exits
                    // on its next `is_cancelled()` check. The
                    // `cancel.is_cancelled()` branch at the end of
                    // this function then marks the pipeline as
                    // `ok: false` whether or not any individual step
                    // returned an error.
                    cancel.cancel();
                }

                // Release anything that was waiting on this step's value.
                // A long-running step never satisfies a value dependency
                // (nothing counted it), and once the pipeline is failing or
                // cancelled nothing new starts — a step whose dependency
                // failed must not run on a stale snapshot of it.
                if !step.long_running && first_error.is_none() && !cancel.is_cancelled() {
                    for &consumer_idx in &plan.consumers[step_idx] {
                        awaiting[consumer_idx] = awaiting[consumer_idx].saturating_sub(1);
                        if awaiting[consumer_idx] == 0 && !spawned[consumer_idx] {
                            spawn_dataflow_step(SpawnArgs {
                                joinset: &mut joinset,
                                engine: &engine,
                                linker: &linker,
                                // Freshly cloned *after* the merge above, so
                                // this task sees the dependency's result.
                                canonical: canonical_store.data(),
                                action,
                                plan,
                                fanout_branches: &fanout_branches,
                                dataflow_events: dataflow_events.as_ref(),
                                step_idx: consumer_idx,
                            });
                            spawned[consumer_idx] = true;
                        }
                    }
                }
            }
        }
    }

    if let Some(err) = first_error {
        emit_terminal_event(
            dataflow_events.as_ref(),
            super::DataflowEvent::PipelineCompleted { ok: false },
        )
        .await;
        // Drain the registry on cancellation too — every leaked sender /
        // source is freed before the call returns. Without it, a cancelled
        // pipeline could keep a forwarder task alive on an `Arc<StreamState>`
        // even after the action errors.
        if drain_streams && canonical_store.data().invoke_depth == 0 {
            super::streams::lock_shared(&canonical_store.data().streams).drain();
        }
        return Err(err);
    }

    // Cooperative cancellation reaches this branch with no `first_error`
    // — every step's body honoured the token and returned `Ok(true)`.
    // The pipeline did NOT complete normally though, so we mark
    // `PipelineCompleted { ok: false }`. The action's `ActionResult`
    // still resolves `Ok(_)` so callers can inspect `step_results` to
    // see how each step exited (a step type that honours the token can
    // record how it exited in its own result). Surfacing cancellation
    // through the events channel (rather than via `KernelError`) matches
    // the contract documented on `DataflowHandle::cancel`.
    let cancelled = cancel.is_cancelled();

    // Every step should have run by now. A step left unspawned with no
    // error and no cancellation means its dependency never resolved, which
    // `build_plan` rejects cycles to make impossible — so reaching here is
    // a scheduler bug, and dropping the steps silently would be precisely
    // the silent failure this scheduler must not have. Say so instead.
    if !cancelled {
        let never_ran: Vec<&str> = (0..step_count)
            .filter(|&i| !spawned[i])
            .map(|i| action.steps[i].id.as_str())
            .collect();
        if !never_ran.is_empty() {
            emit_terminal_event(
                dataflow_events.as_ref(),
                super::DataflowEvent::PipelineCompleted { ok: false },
            )
            .await;
            if drain_streams && canonical_store.data().invoke_depth == 0 {
                super::streams::lock_shared(&canonical_store.data().streams).drain();
            }
            return Err(KernelError::Execution(format!(
                "Dataflow scheduler bug: step(s) [{}] never became runnable, but the \
                 pipeline neither failed nor was cancelled. Their dependencies were \
                 never satisfied.",
                never_ran.join(", ")
            )));
        }
    }

    let state = canonical_store.data();
    let action_result = ActionResult {
        output: state.collect_output(),
        variables: state.variables.clone(),
        step_results: state.step_results.clone(),
    };

    emit_terminal_event(
        dataflow_events.as_ref(),
        super::DataflowEvent::PipelineCompleted { ok: !cancelled },
    )
    .await;

    if drain_streams && state.invoke_depth == 0 {
        super::streams::lock_shared(&state.streams).drain();
    }

    Ok(action_result)
}

/// Arguments to [`spawn_dataflow_step`]. A struct rather than a long
/// parameter list so the two call sites — initial spawn and
/// dependency-release spawn — read identically and can't drift.
struct SpawnArgs<'a> {
    joinset: &'a mut JoinSet<DataflowTaskResult>,
    engine: &'a wasmtime::Engine,
    linker: &'a Arc<Linker<ExecutionState>>,
    /// The canonical state to fork from. For a step released by a
    /// dependency this must be read *after* that dependency merged, or the
    /// fork won't contain the value the step is waiting for.
    canonical: &'a ExecutionState,
    action: &'a Action,
    plan: &'a DagPlan,
    fanout_branches: &'a HashMap<usize, Vec<StreamId>>,
    dataflow_events: Option<&'a tokio::sync::mpsc::Sender<super::DataflowEvent>>,
    step_idx: usize,
}

/// Fork the canonical state, bake in this step's fan-out branch
/// overrides, and spawn the step's task.
fn spawn_dataflow_step(args: SpawnArgs<'_>) {
    let SpawnArgs {
        joinset,
        engine,
        linker,
        canonical,
        action,
        plan,
        fanout_branches,
        dataflow_events,
        step_idx,
    } = args;
    let step = action.steps[step_idx].clone();
    emit_event(
        dataflow_events,
        super::DataflowEvent::StepStarted {
            step_id: step.id.clone(),
        },
    );
    let mut task_state = canonical.clone();
    super::runtime::populate_fanout_overrides_on_state(
        &mut task_state,
        plan,
        action,
        step_idx,
        fanout_branches,
    );
    let mut task_store = Store::new(engine, task_state);
    let linker = linker.clone();
    joinset.spawn(async move {
        let result = super::runtime::run_step(&linker, &mut task_store, &step, step_idx).await;
        (step_idx, step, task_store, result)
    });
}

/// Best-effort emit for lifecycle + progress events. Drops the event
/// when the sidechannel is `None` (non-`DataflowHandle` invocations)
/// or when the receiver's bounded buffer is full — telemetry never
/// gates pipeline progress.
fn emit_event(
    sender: Option<&tokio::sync::mpsc::Sender<super::DataflowEvent>>,
    event: super::DataflowEvent,
) {
    if let Some(s) = sender {
        let _ = s.try_send(event);
    }
}

/// Reliable emit for the single `PipelineCompleted` event that the
/// `DataflowHandle` contract promises fires exactly once. Reliability
/// comes from a detached `send().await` on a cloned sender — the event
/// can't be dropped by a full buffer the way `try_send` would drop it —
/// but the send is NOT awaited inline. Awaiting it inline would make
/// pipeline completion depend on the events receiver draining: a caller
/// who awaits `handle.result` without consuming `handle.events` (natural
/// usage) would deadlock forever once a burst of step events filled the
/// bounded channel. The detached task delivers the terminator whenever
/// the receiver catches up, and exits when the receiver is dropped —
/// the same "pipeline survives a dropped events receiver" property as
/// the best-effort path.
pub(super) async fn emit_terminal_event(
    sender: Option<&tokio::sync::mpsc::Sender<super::DataflowEvent>>,
    event: super::DataflowEvent,
) {
    if let Some(s) = sender {
        // Fast path: buffer has room (or the receiver is gone) —
        // done synchronously, no task spawned.
        match s.try_send(event) {
            Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
                let s = s.clone();
                tokio::spawn(async move {
                    let _ = s.send(event).await;
                });
            }
        }
    }
}

/// Walk the action's steps; for every long-running producer, register a
/// writable+receiver pipe on the shared stream registry, wrap the receiver
/// as a readable source, and (if multi-consumer) install streaming fan-out.
///
/// Side effects on `state`:
/// - Mutates `state.streams` (via the shared `Arc<Mutex<…>>` registry).
/// - Sets `state.step_results[<producer.id>]` to the main readable handle.
/// - Replaces `state.dataflow_outputs` with a fresh `Arc<HashMap>` mapping
///   producer step id → writable handle.
///
/// Returns the `step_idx → branch_ids` map (analogous to the wave scheduler's
/// `fanout_branches`) that the caller plugs through
/// [`super::runtime::populate_fanout_overrides_on_state`] for each spawned
/// consumer task.
fn provision_dataflow_streams(
    state: &mut ExecutionState,
    action: &Action,
    plan: &DagPlan,
    pre_allocated: Option<&HashMap<String, StreamId>>,
) -> Result<HashMap<usize, Vec<StreamId>>, KernelError> {
    let mut outputs: HashMap<String, StreamId> = HashMap::new();
    let mut fanout: HashMap<usize, Vec<StreamId>> = HashMap::new();

    for (idx, step) in action.steps.iter().enumerate() {
        if !step.long_running {
            continue;
        }
        let consumers = &plan.consumers[idx];

        // `io.invoke_streaming` path: a parent invocation may pre-
        // allocate a writable for one of the callee's long-running
        // steps. When that's the case the parent already owns the
        // readable side (in its own registry) — we just use the
        // supplied writable for this step's `dataflow_outputs`
        // entry and skip the in-action readable/fanout wiring.
        // Constraint enforced at the invoke-streaming call site:
        // the pre-allocated step must have zero in-action consumers.
        if let Some(&writable_id) = pre_allocated.and_then(|m| m.get(step.id.as_str())) {
            if !consumers.is_empty() {
                return Err(KernelError::Validation(format!(
                    "io.invoke_streaming: step '{}' has {} in-action consumer(s); \
                     pre-allocated output is only valid when consumers is empty",
                    step.id,
                    consumers.len(),
                )));
            }
            outputs.insert(step.id.clone(), writable_id);
            if state.first_step_id.is_none() {
                state.first_step_id = Some(step.id.clone());
            }
            continue;
        }

        // Step 1: register the writable+receiver pair. Hold the registry
        // lock only for the registry-level insert.
        let (writable_id, receiver) = {
            let mut reg = super::streams::lock_shared(&state.streams);
            reg.register_writable(
                "application/octet-stream",
                super::streams::STREAM_FANOUT_CAPACITY,
            )
        };

        // Step 2: wrap the receiver as a ReadableSource via futures::stream::unfold.
        // The unfolded stream resolves to None when the writable sender's
        // refcount drops to zero — i.e. when the producer drops its handle —
        // signalling EOF to downstream consumers naturally.
        // Fused: a consumer that takes this source out of the registry polls
        // it directly, and an `Unfold` panics if polled past its end. Reads
        // through the registry are guarded separately, in `read_async`, and
        // that guard also covers sources an embedder registers unfused — so
        // neither guard makes the other redundant.
        let recv_source: ReadableSource = Box::pin(futures::StreamExt::fuse(
            futures::stream::unfold(receiver, |mut rx| async move {
                rx.recv().await.map(|item| (item, rx))
            }),
        ));

        // Step 3: register the readable. Reads against this handle drain
        // chunks the producer pushed via `stream_write` on `writable_id`.
        let main_readable_id = {
            let mut reg = super::streams::lock_shared(&state.streams);
            reg.register_readable("application/octet-stream", recv_source)
        };

        outputs.insert(step.id.clone(), writable_id);
        // Pre-write the producer's step_results slot. Consumers resolve
        // `steps.<producer>.result` immediately — there is no race where a
        // consumer task starts running before the slot is populated.
        state
            .step_results
            .insert(step.id.clone(), Value::from(u32::from(main_readable_id)));
        // Track that the producer has been "seen" by the planner's first-
        // step-id heuristic so default-source resolution still works.
        if state.first_step_id.is_none() {
            state.first_step_id = Some(step.id.clone());
        }

        // Step 4: multi-consumer → install streaming fan-out on the main
        // readable. Branches are handed out to consumers via
        // `active_fanout_overrides` at spawn time. Single-consumer producers
        // don't need a tee — the lone consumer reads `main_readable_id`
        // directly through `step_results[<producer.id>]`.
        if consumers.len() > 1 {
            let branches = {
                let mut reg = super::streams::lock_shared(&state.streams);
                reg.fan_out_readable_streaming(
                    main_readable_id,
                    consumers.len(),
                    super::streams::STREAM_FANOUT_CAPACITY,
                )
                .map_err(|e| {
                    KernelError::Execution(format!(
                        "Dataflow fan-out setup failed for long-running producer '{}': {e}",
                        step.id
                    ))
                })?
            };
            fanout.insert(idx, branches);
        }
    }

    state.dataflow_outputs = Arc::new(outputs);
    Ok(fanout)
}
