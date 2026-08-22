//! Fluent builder for plugin-action invocation.
//!
//! A single entry point — [`Kernel::execute`] — and a builder that
//! carries the optional knobs (`config`, `cancel`,
//! `exec_ctx`, `streams`). Terminal verbs select the execution shape:
//!
//! - [`ExecuteActionRequest::run`] — single-shot await, returns `ActionResult`.
//! - [`ExecuteActionRequest::into_dataflow_handle`] — spawn a streaming-dataflow
//!   pipeline, return a [`DataflowHandle`] for events/result/cancel.
//! - [`ExecuteActionRequest::into_dataflow_streaming_handle`] — same shape
//!   plus a live byte stream from the action's single long-running step.
//! - [`ExecuteActionRequest::into_continuous_handle`] — drive a
//!   `continuous: true` action on a loop and return a
//!   [`ContinuousHandle`].
//!
//! All invocation flows through `kernel.execute(...)...run()/into_*()`.

use std::sync::Arc;

use serde_json::Value;
use tokio_util::sync::CancellationToken;

use super::secrets::SecretResolver;
use super::{
    ContinuousHandle, DataflowHandle, DataflowStreamingHandle, Kernel, KernelError,
    exec_context::ExecutionContext, runtime::InvocationContext, streams::SharedStreamRegistry,
    types::ActionResult, with_wallclock_timeout,
};

/// `Value::Null` as a `'static` reference so the builder can default
/// `config` without forcing every caller to write
/// `.with_config(&Value::Null)`.
static NULL_VALUE: Value = Value::Null;

/// Fluent builder produced by [`Kernel::execute`].
///
/// Borrows the kernel for the lifetime of the chain. Terminal verbs
/// that spawn tokio tasks (`into_dataflow_handle`,
/// `into_continuous_handle`, `into_dataflow_streaming_handle`) upgrade
/// the kernel's `Kernel::self_weak` back-reference to clone an
/// `Arc<Kernel>` into the spawned task — they require the kernel to
/// have been wrapped via [`Kernel::into_arc`] and return
/// [`KernelError::Execution`] otherwise. Plain
/// [`ExecuteActionRequest::run`] needs no Arc for actions that don't
/// internally `invoke` or `dispatch_role` other plugins; actions that
/// do still reach for `kernel.self_weak` via the runtime and require
/// the kernel to be wrapped.
pub struct ExecuteActionRequest<'a> {
    kernel: &'a Kernel,
    plugin_name: &'a str,
    action_name: &'a str,
    input: Value,
    config: &'a Value,
    cancel: Option<CancellationToken>,
    exec_ctx: Option<ExecutionContext>,
    streams: Option<SharedStreamRegistry>,
}

impl<'a> ExecuteActionRequest<'a> {
    pub(crate) fn new(
        kernel: &'a Kernel,
        plugin_name: &'a str,
        action_name: &'a str,
        input: Value,
    ) -> Self {
        Self {
            kernel,
            plugin_name,
            action_name,
            input,
            config: &NULL_VALUE,
            cancel: None,
            exec_ctx: None,
            streams: None,
        }
    }

    fn arc(&self) -> Result<Arc<Kernel>, KernelError> {
        self.kernel
            .self_weak
            .get()
            .and_then(|w| w.upgrade())
            .ok_or_else(|| {
                KernelError::Execution(
                    "Kernel::execute(...).into_*() requires a kernel constructed via \
                     Kernel::into_arc; .run() works without it for actions that don't \
                     invoke or dispatch_role other plugins"
                        .to_string(),
                )
            })
    }

    /// The config namespace the action sees as `{{$config.*}}`.
    /// Default is `Value::Null`.
    pub fn with_config(mut self, config: &'a Value) -> Self {
        self.config = config;
        self
    }

    /// The resolver this request's invocation tree pulls through: the
    /// kernel's registered one, or none. There is deliberately no
    /// per-request way to supply credentials — see
    /// [`secrets`](super::secrets) for why one spelling is the point.
    fn secret_resolver(&self) -> Option<Arc<dyn SecretResolver>> {
        self.kernel.secret_resolver().cloned()
    }

    /// External cancellation token. Cancelling tears down a
    /// long-running pipeline; the action resolves with whatever final
    /// state the merged task produces.
    pub fn with_cancel(mut self, cancel: CancellationToken) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// Opaque [`ExecutionContext`] blob. The kernel carries it through
    /// every dispatch site without introspecting it; embedders own the
    /// schema (a multi-tenant embedder might use `tenantId` /
    /// `membershipId` keys, for example). Required by embedder step
    /// types whose bodies need an invocation scope.
    pub fn with_exec_ctx(mut self, exec_ctx: ExecutionContext) -> Self {
        self.exec_ctx = Some(exec_ctx);
        self
    }

    /// Caller-provided stream handle table. The runtime will **not**
    /// drain it on exit — the caller owns its lifetime. Lets an embedder
    /// gateway seed a request-body stream before running and extract a
    /// response-body stream after.
    ///
    /// # This grants the whole table
    ///
    /// Every execution otherwise gets its own table, so a handle names
    /// nothing outside the execution that minted it. Passing a table in
    /// deliberately overrides that: the action runs *against your
    /// table*, and every stream in it is reachable by handle from the
    /// plugin's steps — including any script step, whose interpreter is
    /// supplied by whichever plugin owns the `(script, <language>)`
    /// slot. Handles are small integers from a counter starting at 1,
    /// so nothing needs guessing.
    ///
    /// That is the API's purpose rather than a defect — you are handing
    /// the action your streams — but it means the table is the unit of
    /// granting. **Pass a table scoped to this one call**, holding only
    /// the streams this action should reach:
    ///
    /// ```ignore
    /// // Good: a fresh table holding exactly the request body.
    /// let table: SharedStreamRegistry = Default::default();
    /// let body = lock_shared(&table).register_readable("application/json", source);
    /// kernel.execute(plugin, action, input).with_streams(table.clone()).run().await?;
    ///
    /// // Bad: a long-lived table accumulating other requests' streams,
    /// // every one of which this plugin can now read and close.
    /// ```
    ///
    /// To hand over a stream that already lives in another table, move
    /// it: [`StreamRegistry::take`](crate::kernel::streams::StreamRegistry::take)
    /// there, [`adopt`](crate::kernel::streams::StreamRegistry::adopt)
    /// here.
    pub fn with_streams(mut self, streams: SharedStreamRegistry) -> Self {
        self.streams = Some(streams);
        self
    }

    /// Run the action synchronously and await the result.
    ///
    /// Honours every combination of `config` / `cancel` /
    /// `exec_ctx` / `streams`. The `streams` setting flips `drain_streams` to
    /// `false` so the caller can extract handles after the action
    /// returns.
    pub async fn run(self) -> Result<ActionResult, KernelError> {
        let kernel = self.kernel;
        let registration = kernel
            .registry
            .get_action(self.plugin_name, self.action_name)
            .ok_or_else(|| {
                KernelError::NotFound(format!(
                    "No action '{}' on plugin '{}'",
                    self.action_name, self.plugin_name
                ))
            })?;

        let secret_resolver = self.secret_resolver();
        let mut ctx = InvocationContext::top_level(kernel.self_weak.get().cloned());
        // One token per invocation, so the wallclock watchdog has
        // something to fire. When the caller supplied a token this is a
        // *child* of it: the caller's cancel still reaches us, but our
        // deadline expiring does not reach back and tear down whatever
        // else they were using that token for.
        let invocation_cancel = match &self.cancel {
            Some(caller) => caller.child_token(),
            None => CancellationToken::new(),
        };
        ctx.cancel = Some(invocation_cancel.clone());
        ctx.step_type_access = kernel.step_type_access_for(self.plugin_name);
        if let Some(streams) = self.streams {
            ctx.streams = Some(streams);
            ctx.drain_streams = false;
        }

        let exec_ctx = self.exec_ctx.unwrap_or_default();
        let secrets = kernel
            .pull_secrets(self.plugin_name, secret_resolver.as_ref(), &exec_ctx)
            .await?;
        ctx.secret_resolver = secret_resolver;

        let fut = kernel.runtime.execute_dag(
            self.plugin_name,
            &registration.action,
            &registration.plan,
            self.input,
            self.config,
            &secrets,
            kernel.script_runtimes(),
            exec_ctx,
            ctx,
            kernel.limits.clone(),
        );
        with_wallclock_timeout(
            fut,
            kernel.effective_wallclock_timeout(&registration.action),
            invocation_cancel,
        )
        .await
    }

    /// Spawn a streaming-dataflow pipeline and return a
    /// [`DataflowHandle`]. The action **must** declare
    /// `dataflow: true` in its manifest.
    ///
    /// When [`Self::with_exec_ctx`] was not called the action runs under
    /// `ExecutionContext::default()`.
    ///
    /// Incompatible with [`Self::with_streams`] — the dataflow handle
    /// owns the action's stream registry (the runtime allocates a fresh
    /// one internally so the registry's `Drop` releases on pipeline
    /// teardown). Setting both errors at the terminal rather than
    /// silently dropping the caller-supplied registry.
    pub fn into_dataflow_handle(self) -> Result<DataflowHandle, KernelError> {
        let registration = self
            .kernel
            .registry
            .get_action(self.plugin_name, self.action_name)
            .ok_or_else(|| {
                KernelError::NotFound(format!(
                    "Action {}.{} not registered",
                    self.plugin_name, self.action_name
                ))
            })?;
        if !registration.action.dataflow {
            return Err(KernelError::Validation(format!(
                "Action {}.{} is not marked dataflow; \
                 use Kernel::execute(...).run() for single-shot calls",
                self.plugin_name, self.action_name
            )));
        }
        if self.streams.is_some() {
            return Err(KernelError::Validation(
                "with_streams() is not compatible with into_dataflow_handle(); \
                 the dataflow pipeline owns its own stream registry"
                    .to_string(),
            ));
        }

        let (events_tx, events_rx) =
            tokio::sync::mpsc::channel(self.kernel.limits.dataflow_events_capacity);
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let secret_resolver = self.secret_resolver();
        let kernel = self.arc()?;
        let cancel = self.cancel.unwrap_or_default();
        let driver_cancel = cancel.clone();
        let plugin_owned = self.plugin_name.to_string();
        let action_owned = self.action_name.to_string();
        let config_owned = self.config.clone();
        let exec_ctx_owned = self.exec_ctx.unwrap_or_default();

        // Per-action wallclock decision. Dataflow actions with no
        // declared `wallclock_timeout_ms` run uncapped and rely on
        // cooperative cancellation via the action's `CancellationToken`.
        let wallclock_timeout = self
            .kernel
            .effective_wallclock_timeout(&registration.action);
        let join = tokio::spawn(async move {
            let mut ctx = InvocationContext::top_level(Some(Arc::downgrade(&kernel)));
            ctx.step_type_access = kernel.step_type_access_for(&plugin_owned);
            // The handle's own token *is* this invocation's cancel
            // handle, so the wallclock watchdog fires exactly what
            // `DataflowHandle::cancel` fires — no child needed.
            let watchdog_cancel = driver_cancel.clone();
            ctx.cancel = Some(driver_cancel);
            let events_tx_for_timeout = events_tx.clone();
            ctx.dataflow_events = Some(events_tx);
            ctx.secret_resolver = secret_resolver.clone();

            let registration = match kernel.registry.get_action(&plugin_owned, &action_owned) {
                Some(r) => r,
                None => {
                    let _ = result_tx.send(Err(KernelError::NotFound(format!(
                        "Action {plugin_owned}.{action_owned} not registered"
                    ))));
                    return;
                }
            };
            let secrets = match kernel
                .pull_secrets(&plugin_owned, secret_resolver.as_ref(), &exec_ctx_owned)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    let _ = result_tx.send(Err(e));
                    return;
                }
            };

            let fut = kernel.runtime.execute_dag(
                &plugin_owned,
                &registration.action,
                &registration.plan,
                self.input,
                &config_owned,
                &secrets,
                kernel.script_runtimes(),
                exec_ctx_owned,
                ctx,
                kernel.limits.clone(),
            );
            let result = with_wallclock_timeout(fut, wallclock_timeout, watchdog_cancel).await;
            // A wallclock timeout drops the scheduler future mid-flight,
            // so the scheduler's own terminal emit never runs. Without
            // this, an events subscriber keyed on `PipelineCompleted`
            // would wait forever on a timed-out pipeline even though
            // `handle.result` had resolved `Err`.
            //
            // **Only on the timeout path.** Guarding on `result.is_err()`
            // would be wrong: an ordinary step failure emits the
            // terminator *and* returns `Err`, so every failing pipeline
            // would deliver two. And a raw `send().await` on the bounded
            // channel would mean that on a full, undrained events channel
            // the second one blocks forever, so `result_tx` never fires
            // and `handle.result` never resolves: precisely the hang
            // `emit_terminal_event` exists to prevent.
            if matches!(result, Err(super::KernelError::ExecutionTimeout { .. })) {
                super::runtime_dataflow::emit_terminal_event(
                    Some(&events_tx_for_timeout),
                    super::DataflowEvent::PipelineCompleted { ok: false },
                )
                .await;
            }
            let _ = result_tx.send(result);
        });

        Ok(DataflowHandle {
            events: events_rx,
            result: result_rx,
            cancel,
            join,
        })
    }

    /// Spawn a streaming-dataflow pipeline whose single long-running
    /// step's output flows back to the caller as a live byte stream.
    /// Used by SSE / chunked-transfer endpoints that need to relay
    /// bytes to a client before the action completes.
    ///
    /// The action MUST be `dataflow: true` and have exactly one
    /// `long_running` step with zero in-action consumers. The same
    /// constraints govern `io.invoke_streaming` so the two seams stay
    /// behaviorally consistent.
    ///
    /// Incompatible with [`Self::with_streams`] — this terminal must
    /// allocate its own registry so it can register the producer's
    /// writable side internally and expose the matching readable as
    /// `output`. Setting both errors at the terminal rather than
    /// silently dropping the caller-supplied registry.
    pub fn into_dataflow_streaming_handle(self) -> Result<DataflowStreamingHandle, KernelError> {
        let registration = self
            .kernel
            .registry
            .get_action(self.plugin_name, self.action_name)
            .ok_or_else(|| {
                KernelError::NotFound(format!(
                    "Action {}.{} not registered",
                    self.plugin_name, self.action_name
                ))
            })?;
        if !registration.action.dataflow {
            return Err(KernelError::Validation(format!(
                "Action {}.{} is not marked dataflow; \
                 use Kernel::execute(...).run() for single-shot calls",
                self.plugin_name, self.action_name
            )));
        }
        if self.streams.is_some() {
            return Err(KernelError::Validation(
                "with_streams() is not compatible with into_dataflow_streaming_handle(); \
                 the terminal allocates its own registry to expose the producer's output"
                    .to_string(),
            ));
        }

        let mut long_running_steps: Vec<&str> = Vec::new();
        for (idx, step) in registration.action.steps.iter().enumerate() {
            if step.long_running {
                if !registration.plan.consumers[idx].is_empty() {
                    return Err(KernelError::Validation(format!(
                        "into_dataflow_streaming_handle: \
                         action {}.{} long-running step '{}' \
                         has in-action consumer(s); the output must flow to the \
                         caller, not a sibling step",
                        self.plugin_name, self.action_name, step.id
                    )));
                }
                long_running_steps.push(step.id.as_str());
            }
        }
        let producer_step_id = match long_running_steps.as_slice() {
            [one] => (*one).to_string(),
            [] => {
                return Err(KernelError::Validation(format!(
                    "into_dataflow_streaming_handle: \
                     action {}.{} declares `dataflow: true` \
                     but has no `long_running` step — nothing to stream from",
                    self.plugin_name, self.action_name
                )));
            }
            many => {
                return Err(KernelError::Validation(format!(
                    "into_dataflow_streaming_handle: \
                     action {}.{} has {} long-running steps ({}); \
                     exactly one is required so the caller's stream destination \
                     is unambiguous",
                    self.plugin_name,
                    self.action_name,
                    many.len(),
                    many.join(", ")
                )));
            }
        };

        let streams = Arc::new(std::sync::Mutex::new(super::streams::StreamRegistry::new()));
        let (writable_id, receiver) = {
            let mut reg = super::streams::lock_shared(&streams);
            reg.register_writable(
                "application/octet-stream",
                super::streams::STREAM_FANOUT_CAPACITY,
            )
        };
        let output: super::streams::ReadableSource =
            Box::pin(futures::stream::unfold(receiver, |mut rx| async move {
                rx.recv().await.map(|item| (item, rx))
            }));

        let mut pre_allocated = std::collections::HashMap::new();
        pre_allocated.insert(producer_step_id, writable_id);

        let (events_tx, events_rx) =
            tokio::sync::mpsc::channel(self.kernel.limits.dataflow_events_capacity);
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let secret_resolver = self.secret_resolver();
        let kernel = self.arc()?;
        let cancel = self.cancel.unwrap_or_default();
        let driver_cancel = cancel.clone();
        let plugin_owned = self.plugin_name.to_string();
        let action_owned = self.action_name.to_string();
        let config_owned = self.config.clone();
        let exec_ctx_owned = self.exec_ctx.unwrap_or_default();

        let wallclock_timeout = self
            .kernel
            .effective_wallclock_timeout(&registration.action);
        let join = tokio::spawn(async move {
            let ctx = InvocationContext {
                step_type_access: kernel.step_type_access_for(&plugin_owned),
                streams: Some(streams),
                invoke_depth: 0,
                dispatch_depth: 0,
                kernel: kernel.self_weak.get().cloned(),
                trigger: None,
                drain_streams: true,
                cancel: Some(driver_cancel.clone()),
                dataflow_events: Some(events_tx.clone()),
                pre_allocated_outputs: Some(pre_allocated),
                secret_resolver: secret_resolver.clone(),
            };
            let watchdog_cancel = driver_cancel;
            let events_tx_for_timeout = events_tx;

            let registration = match kernel.registry.get_action(&plugin_owned, &action_owned) {
                Some(r) => r,
                None => {
                    let _ = result_tx.send(Err(KernelError::NotFound(format!(
                        "Action {plugin_owned}.{action_owned} not registered"
                    ))));
                    return;
                }
            };
            let secrets = match kernel
                .pull_secrets(&plugin_owned, secret_resolver.as_ref(), &exec_ctx_owned)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    let _ = result_tx.send(Err(e));
                    return;
                }
            };

            let fut = kernel.runtime.execute_dag(
                &plugin_owned,
                &registration.action,
                &registration.plan,
                self.input,
                &config_owned,
                &secrets,
                kernel.script_runtimes(),
                exec_ctx_owned,
                ctx,
                kernel.limits.clone(),
            );
            let result = with_wallclock_timeout(fut, wallclock_timeout, watchdog_cancel).await;
            // A wallclock timeout drops the scheduler future mid-flight,
            // so the scheduler's own terminal emit never runs. Without
            // this, an events subscriber keyed on `PipelineCompleted`
            // would wait forever on a timed-out pipeline even though
            // `handle.result` had resolved `Err`.
            //
            // **Only on the timeout path.** Guarding on `result.is_err()`
            // would be wrong: an ordinary step failure emits the
            // terminator *and* returns `Err`, so every failing pipeline
            // would deliver two. And a raw `send().await` on the bounded
            // channel would mean that on a full, undrained events channel
            // the second one blocks forever, so `result_tx` never fires
            // and `handle.result` never resolves: precisely the hang
            // `emit_terminal_event` exists to prevent.
            if matches!(result, Err(super::KernelError::ExecutionTimeout { .. })) {
                super::runtime_dataflow::emit_terminal_event(
                    Some(&events_tx_for_timeout),
                    super::DataflowEvent::PipelineCompleted { ok: false },
                )
                .await;
            }
            let _ = result_tx.send(result);
        });

        Ok(DataflowStreamingHandle {
            output,
            events: events_rx,
            result: result_rx,
            cancel,
            join,
        })
    }

    /// Drive a `continuous: true` action on a loop and return a
    /// [`ContinuousHandle`]. The driver emits one `ActionResult` per
    /// iteration on the handle's `events` channel; between iterations
    /// it sleeps `action.interval_ms` milliseconds.
    ///
    /// Per-iteration invocations honour `with_config`,
    /// `with_exec_ctx`, and `with_cancel` — the cancellation token is
    /// threaded into each iteration's `.run()` so an in-flight action
    /// observes the cancel and can tear itself down cooperatively
    /// (rather than waiting for the current iteration's full body to
    /// return before the loop checks again).
    ///
    /// Cancel semantics: firing the token signals the loop and the
    /// in-flight iteration. The current iteration unwinds via the
    /// runtime's cancellation seams; the loop exits before the next
    /// iteration starts. Sleeps between iterations race against the
    /// cancel and short-circuit.
    ///
    /// Incompatible with [`Self::with_streams`] — continuous loops
    /// don't have a stable per-iteration stream identity. Setting both
    /// errors at the terminal rather than silently dropping the
    /// caller-supplied registry.
    pub fn into_continuous_handle(self) -> Result<ContinuousHandle, KernelError> {
        let registration = self
            .kernel
            .registry
            .get_action(self.plugin_name, self.action_name)
            .ok_or_else(|| {
                KernelError::NotFound(format!(
                    "Action {}.{} not registered",
                    self.plugin_name, self.action_name
                ))
            })?;
        if !registration.action.continuous {
            return Err(KernelError::Validation(format!(
                "Action {}.{} is not marked continuous; \
                 use Kernel::execute(...).run() for single-shot calls",
                self.plugin_name, self.action_name
            )));
        }
        if self.streams.is_some() {
            return Err(KernelError::Validation(
                "with_streams() is not compatible with into_continuous_handle(); \
                 continuous loops don't have a stable per-iteration stream identity"
                    .to_string(),
            ));
        }
        let interval = std::time::Duration::from_millis(registration.action.interval_ms);

        // Bounded so a caller that stops draining applies backpressure
        // to the loop instead of growing an unbounded queue of results.
        // `ContinuousHandle::events` documents the drain obligation;
        // the send below races cancellation so failing to drain costs
        // throughput rather than deadlocking `shutdown()`.
        const CONTINUOUS_EVENTS_CAPACITY: usize = 8;
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<ActionResult, KernelError>>(
            CONTINUOUS_EVENTS_CAPACITY,
        );
        let kernel = self.arc()?;
        let cancel = self.cancel.unwrap_or_default();
        let driver_cancel = cancel.clone();
        let plugin_owned = self.plugin_name.to_string();
        let action_owned = self.action_name.to_string();
        let input_owned = self.input;
        let config_owned = self.config.clone();
        let exec_ctx_owned = self.exec_ctx.unwrap_or_default();

        let join = tokio::spawn(async move {
            loop {
                if driver_cancel.is_cancelled() {
                    break;
                }
                let iter_input = input_owned.clone();
                let iter_result = kernel
                    .execute(&plugin_owned, &action_owned, iter_input)
                    .with_config(&config_owned)
                    .with_exec_ctx(exec_ctx_owned.clone())
                    .with_cancel(driver_cancel.clone())
                    .run()
                    .await;
                // Race the send against cancellation. `tx.send().await`
                // blocks once the bounded channel is full, and the
                // channel is small — so without the race a caller that
                // stops draining `events` and then calls `shutdown()`
                // would hang forever: `shutdown` cancels and then awaits
                // this task, which would be parked in a send that
                // cancellation cannot interrupt. "Stop reading, then
                // shut down" is a reasonable thing for a caller to do,
                // so it must not hang.
                tokio::select! {
                    biased;
                    () = driver_cancel.cancelled() => break,
                    res = tx.send(iter_result) => {
                        if res.is_err() {
                            // Receiver dropped — nobody is listening,
                            // so exit rather than buffer indefinitely.
                            break;
                        }
                    }
                }
                if interval.is_zero() {
                    tokio::task::yield_now().await;
                    continue;
                }
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = driver_cancel.cancelled() => break,
                }
            }
        });

        Ok(ContinuousHandle {
            events: rx,
            cancel,
            join,
        })
    }
}
