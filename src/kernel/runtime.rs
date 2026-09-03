//! wasmtime runtime — Engine, Linker, and host-side DAG execution.
//!
//! The runtime is the bridge between the kernel and wasmtime. It:
//! - Creates the wasmtime Engine (shared, thread-safe)
//! - Sets up the Linker with host import functions (kernel services +
//!   per-step-type host functions)
//! - Executes an action's DAG plan by looking up step-type host functions
//!   on the Linker and invoking them in topological order
//!
//! Orchestration lives on the host: with true DAG semantics (parallel
//! branches, fan-out), the Linker-registered step type host functions are
//! dispatched directly via `Linker::get` → `Func` → `typed::call`.
//! Script-runtime interpreter modules (registered by embedder plugins)
//! are wasm-based and loaded by the kernel for use by the `script` step
//! type.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, LazyLock};

use indexmap::IndexMap;
use regex::Regex;
use serde_json::Value;
use wasmtime::{Engine, Linker, Module, Store};

use super::KernelError;
use super::dag::DagPlan;
use super::exec_context::ExecutionContext;
use super::host_api::{self, ExecutionState, ExecutionStateParams};
use super::streams::StreamId;
use super::types::{Action, ActionResult, StepDef};

/// Per-invocation context for [`WasmRuntime::execute_dag`].
///
/// Bundles the "who's calling and into what" fields of an action
/// invocation: the stream handle table to run against, the recursion
/// depth, the cancellation token, and a back-reference to the owning
/// kernel so the `invoke` step type can dispatch into another action.
///
/// Top-level callers use [`InvocationContext::top_level`]; a nested
/// `invoke` builds a child context that inherits the parent's depth and
/// cancel token but gets a stream table of its own.
#[derive(Clone, Default)]
pub struct InvocationContext {
    /// Stream registry to run against. `None` triggers fresh
    /// allocation — the case for top-level and nested-`invoke`
    /// executions alike; a caller-owned table is `Some`.
    pub streams: Option<std::sync::Arc<std::sync::Mutex<super::streams::StreamRegistry>>>,
    /// Invoke recursion depth — 0 at top level, parent+1 in a child.
    pub invoke_depth: u32,
    /// Event-dispatch cascade depth — 0 at top level, parent+1 when
    /// the kernel's event dispatcher fires a subscribed action.
    /// Independent of `invoke_depth` because the two depths track
    /// different shapes of recursion (explicit `invoke` calls vs.
    /// event-driven dispatches). Hard cap enforced inside
    /// [`super::Kernel::dispatch_event`].
    pub dispatch_depth: u32,
    /// Weak back-reference to the kernel. `None` disables the `invoke`
    /// step type for this invocation.
    pub kernel: Option<std::sync::Weak<super::Kernel>>,
    /// Triggering event payload, exposed to step DSL as
    /// `$trigger.*` and `{{$trigger.*}}`. `Some(arc)` only when the
    /// invocation was initiated by the event dispatcher. The `Arc`
    /// lets the dispatcher fan one payload out to N subscribers as N
    /// refcount bumps rather than N deep clones of an immutable JSON
    /// tree.
    pub trigger: Option<std::sync::Arc<Value>>,
    /// Whether the runtime should drain the stream registry after the
    /// action finishes. `true` for kernel-allocated registries (the
    /// kernel owns cleanup); `false` when the caller supplied the
    /// registry and wants to inspect or extract its handles after the
    /// action returns — an embedder that pulls a body stream handle out
    /// of the result after the action completes relies on this.
    pub drain_streams: bool,
    /// External cancellation surface. `None` means "no
    /// external cancel" — the runtime makes a fresh never-cancelled
    /// token internally. `Some(token)` is the form
    /// `execute_action_with_cancel` and the streaming-dataflow paths
    /// use to let an outside caller terminate a long-running
    /// pipeline. Token clones are cheap (`Arc` bumps) so every forked
    /// `ExecutionState` carries the same logical signal.
    pub cancel: Option<tokio_util::sync::CancellationToken>,
    /// Telemetry sidechannel for the dataflow scheduler.
    /// `Some(sender)` only when the invocation was started via
    /// [`ExecuteActionRequest::into_dataflow_handle`](super::execute_request::ExecuteActionRequest::into_dataflow_handle); in that
    /// case the dataflow scheduler emits step-lifecycle events
    /// (`StepStarted`, `StepCompleted`, `StepFailed`,
    /// `PipelineCompleted`) and step bodies can emit `StepProgress`
    /// via `ExecutionState::emit_progress`. `None` everywhere else.
    pub dataflow_events: Option<tokio::sync::mpsc::Sender<super::DataflowEvent>>,
    /// Pre-allocated writable handles for specific long-running step
    /// IDs. When `Some`, the dataflow scheduler in
    /// `provision_dataflow_streams` uses the supplied handle for that
    /// step's output instead of allocating a fresh writable + receiver
    /// pair. The companion readable side is owned by the caller of
    /// `execute_action_invoked_streaming` — that's the API that wires
    /// a child action's stream output back to a parent action via
    /// `io.invoke_streaming`.
    ///
    /// Constraint: a step covered by this map must have no in-action
    /// downstream consumers, because the scheduler skips registering
    /// a readable for it (the readable side lives in the parent's
    /// stream registry, not this action's step_results). The
    /// invoke-streaming entry point validates this at call time.
    pub pre_allocated_outputs: Option<std::collections::HashMap<String, super::streams::StreamId>>,
    /// Which step types this invocation may run, resolved by the kernel
    /// before the invocation starts. See
    /// [`super::host_api::StepTypeAccess`] for why the decision is
    /// carried rather than looked up. Defaults to deny-all-non-reserved,
    /// so a construction site that forgets it fails closed.
    pub step_type_access: super::host_api::StepTypeAccess,
    /// The resolver this invocation tree pulls credentials through —
    /// the kernel's configured one. Inherited by every child invocation
    /// so an `invoke` callee asks the same source the caller did.
    /// `None` means no credentials exist and every execution sees
    /// `Null`.
    pub secret_resolver: Option<std::sync::Arc<dyn super::secrets::SecretResolver>>,
}

impl InvocationContext {
    /// Context for a top-level (kernel-initiated) invocation. Fresh
    /// streams, depth 0, kernel back-ref populated when available, no
    /// trigger payload, drain on exit (kernel owns cleanup).
    pub fn top_level(kernel: Option<std::sync::Weak<super::Kernel>>) -> Self {
        Self {
            streams: None,
            invoke_depth: 0,
            dispatch_depth: 0,
            kernel,
            trigger: None,
            drain_streams: true,
            cancel: None,
            dataflow_events: None,
            pre_allocated_outputs: None,
            step_type_access: Default::default(),
            secret_resolver: None,
        }
    }
}

/// Type alias for trait-based step type functions.
///
/// The uniform shape every step type uses: bodies take
/// `&mut dyn PluginExecution` and a raw params [`Value`] (the step's
/// `params` object straight from the manifest), and return
/// `Result<StepOutput, StepError>`. Sync bodies just don't `.await`;
/// the engine drives every step through the same async path.
///
/// The wasmtime-side adapter (the closure built in
/// `WasmRuntime::register_linker_imports`) handles step lookup,
/// `store_to_variable` mirroring, [`StepOutput::metadata`](super::host_api::StepOutput::metadata) routing into
/// the sidecar maps, and [`StepError`](super::host_api::StepError) → engine i32 translation — step
/// bodies never touch that machinery directly.
pub type StepFn = for<'a> fn(
    &'a mut (dyn super::host_api::PluginExecution + Send),
    &'a serde_json::Value,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<super::host_api::StepOutput, super::host_api::StepError>,
            > + Send
            + 'a,
    >,
>;

/// Type alias for **kernel-internal** ("intrinsic") step bodies.
///
/// Identical to [`StepFn`] except the first argument is the concrete
/// `&mut ExecutionState` rather than the narrow `&mut dyn PluginExecution`
/// plugin surface. The kernel steps that legitimately need engine
/// internals — `invoke` (by-name kernel dispatch), `wasm` (the wasmtime
/// `Engine` and module registry), `script` (the `script_runtimes`
/// registry and resource-violation marker), and the alias dispatcher —
/// take this shape so they reach those fields directly instead of
/// recovering the concrete type via a runtime downcast.
///
/// External plugin crates can't name `ExecutionState` (it's `pub(crate)`),
/// so this signature is unreachable outside the engine. That's what makes
/// the kernel/plugin capability split compiler-enforced rather than a
/// doc-only convention.
pub(crate) type IntrinsicStepFn = for<'a> fn(
    &'a mut ExecutionState,
    &'a serde_json::Value,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<super::host_api::StepOutput, super::host_api::StepError>,
            > + Send
            + 'a,
    >,
>;

/// A registered step body — either a host-pluggable [`StepFn`]
/// (the narrow `&mut dyn PluginExecution` surface every external plugin
/// and the genuinely-pluggable intrinsics `throw_error` / `let` use) or
/// a kernel-internal [`IntrinsicStepFn`] (concrete `&mut ExecutionState`,
/// for steps that need engine internals). The wasmtime adapter
/// ([`dispatch_trait_step_core`]) hands each body the right first
/// argument; every other cross-cutting service is identical.
#[derive(Clone, Copy)]
pub(crate) enum StepBody {
    Plugin(StepFn),
    Intrinsic(IntrinsicStepFn),
}

/// Adapter wrapping the trait-based step type shape into
/// wasmtime's `Caller<'_, ExecutionState>` callback shape.
///
/// One closure per registered trait step type is too much; instead the
/// linker closure delegates to this fn, parameterised by the step body
/// pointer. Centralising the wrapping here means every step type
/// observes identical `store_to_variable` mirroring, metadata routing,
/// and StepError translation semantics.
///
/// All the cross-cutting logic lives in [`dispatch_trait_step_core`] so
/// it can be exercised by direct unit tests without spinning up a
/// wasmtime store; this fn is the thin `Caller` adapter.
async fn dispatch_trait_step<'a>(
    mut caller: wasmtime::Caller<'a, ExecutionState>,
    step_index: i32,
    body: StepBody,
) -> i32 {
    dispatch_trait_step_core(caller.data_mut(), step_index as usize, body).await
}

/// Pure-`&mut ExecutionState` core of the wasmtime adapter. Split out
/// of [`dispatch_trait_step`] so it can be unit-tested without a
/// `wasmtime::Caller`. Every cross-cutting concern shared by step
/// bodies lives here:
///
/// - Step lookup + bounds check on `step_index`
/// - `current_step_idx` cursor set/clear around the trait dispatch
/// - `StepOutput` writeback: stores `value` under `step.id`, routes
///   every `metadata` entry into `step_metadata[step.id]` after
///   validating each key against the step type's `metadataSchema`
///   allow-list, mirrors result into `step.store_to_variable` when set
/// - `StepError::Failed` → sets `last_error`, returns 0. Failure
///   propagates unconditionally; manifest authors wrap with
///   `{type: "try", catch: []}` for swallow semantics.
/// - `StepError::Thrown` → sets `plugin_error` + `last_error` and
///   returns 0. A surrounding `try.catch` body can recover.
async fn dispatch_trait_step_core(
    state: &mut ExecutionState,
    step_index: usize,
    body: StepBody,
) -> i32 {
    use super::host_api::{StepError, StepOutput};

    let (step_id, step_type, step_store_to_variable, params) =
        match state.action.steps.get(step_index) {
            Some(s) => (
                s.id.clone(),
                s.step_type.clone(),
                s.store_to_variable.clone(),
                s.params.clone(),
            ),
            None => {
                state.last_error = Some(format!("Step index {step_index} out of bounds"));
                return 0;
            }
        };

    state.current_step_idx = Some(step_index);

    // A body another plugin ships runs with *its owner's* view of
    // secrets. Pull it now — subject = the owner, executing plugin =
    // this execution — through the invocation's resolver, narrowed to
    // what the owner declared. The resolver is told which of those
    // keys the owner marked overridable, so an embedder can answer
    // with this level's value for exactly those. A failed pull fails
    // the step: running a credentialed body without its credential is
    // a wrong answer, not a degraded one.
    //
    // `body_secrets` is what `ex.secrets()` returns for the duration;
    // `state.secrets` (the caller's) stays in place for param
    // resolution, so the caller's deliberate `{{$secrets.x}}` delegation
    // still works. Cleared unconditionally after, including on error.
    if let Some(owner) = state.step_type_access.body_owner(&step_type).cloned() {
        let pulled = match &state.secret_resolver {
            Some(resolver) => {
                super::secrets::pull(
                    resolver.as_ref(),
                    &owner.identity,
                    &state.plugin_name,
                    &owner.declared_keys,
                    &owner.overridable_keys,
                    &state.exec_ctx,
                )
                .await
            }
            None => Ok(Value::Null),
        };
        match pulled {
            Ok(view) => state.body_secrets = Some(view),
            Err(e) => {
                state.current_step_idx = None;
                state.last_error = Some(format!(
                    "step '{step_id}' ({step_type}): could not resolve the body owner's \
                     secrets: {e}"
                ));
                return 0;
            }
        }
    }

    // Typed failure markers belong to one dispatch. A guest that saw a
    // nested dispatch fail, handled it, and carried on must not have
    // that dispatch's markers attributed to a later failure.
    state.cancelled = false;
    state.callee_error = None;

    let result = match body {
        // Host-pluggable bodies see only the narrow plugin surface.
        StepBody::Plugin(func) => {
            let exec: &mut (dyn super::host_api::PluginExecution + Send) = state;
            func(exec, &params).await
        }
        // Kernel-internal bodies take the concrete state directly — no
        // downcast; the capability split lives in the type.
        StepBody::Intrinsic(func) => func(state, &params).await,
    };

    state.body_secrets = None;
    state.current_step_idx = None;

    match result {
        Ok(StepOutput { value, metadata }) => {
            state.store_step_result(&step_id, value);

            // Route every metadata entry generically into `step_metadata`.
            // The producing step type's `metadataSchema` is the
            // allow-list: a key outside it fails the step. `status` /
            // `headers` carry no kernel privilege — they're just the keys
            // `http_call` declares. Keys surface flat as
            // `{{$steps.<id>.<key>}}`.
            //
            // A `None` allow-list fails **open** (routes unconstrained), by
            // design: in real execution `register_plugin`'s impl⇒def check
            // guarantees every executable step type has a registered def, so
            // `None` only arises for hand-built test states with no kernel
            // handle. Fail-closed here would instead break those tests for no
            // safety gain.
            if !metadata.is_empty() {
                if let Some(allowed) = state.declared_metadata_keys(&step_type)
                    && let Some(bad) = metadata.keys().find(|k| !allowed.contains(k.as_str()))
                {
                    let declared: Vec<&str> = allowed.iter().map(String::as_str).collect();
                    let msg = format!(
                        "step '{step_id}' (type '{step_type}') emitted undeclared metadata \
                         key '{bad}'; metadataSchema declares: {declared:?}"
                    );
                    tracing::warn!(
                        step_id = %step_id,
                        metadata_key = %bad,
                        "undeclared step metadata key"
                    );
                    state.last_error = Some(msg);
                    return 0;
                }
                let entry = state.step_metadata.entry(step_id.clone()).or_default();
                for (k, v) in metadata {
                    entry.insert(k, v);
                }
            }

            // store_to_variable mirrors the stored step result into a
            // named variable. Read back from step_results so the
            // variable picks up the post-`store_step_result` value
            // rather than a local copy.
            if let Some(var_name) = step_store_to_variable {
                let val = state
                    .step_results
                    .get(&step_id)
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                state.variables.insert(var_name, val);
            }
            1
        }
        Err(StepError::Failed(msg)) => {
            // Any failure propagates unconditionally. Manifest authors
            // who want swallow semantics wrap the step in
            // `{type: "try", try: [step], catch: []}` — `run_try`'s
            // empty-catch path handles the swallow.
            tracing::warn!(step_id = %step_id, error = %msg, "Step failed");
            state.last_error = Some(msg);
            0
        }
        Err(StepError::Thrown(payload)) => {
            // throw_error semantics — promote to PluginError on the
            // runtime side. Populate `last_error` too so a `try.catch`
            // handler reads the formatted message via `{{$.error}}`.
            let formatted = if payload.message.is_empty() {
                format!("PluginError {}", payload.code)
            } else {
                format!("PluginError {}: {}", payload.code, payload.message)
            };
            state.plugin_error = Some(payload);
            state.last_error = Some(formatted);
            0
        }
        Err(StepError::Cancelled) => {
            // Not a failure: the step stopped because the invocation
            // was cancelled. The marker makes `step_failure_to_error`
            // report `Cancelled` and keeps `try` from catching it.
            tracing::debug!(step_id = %step_id, "Step stopped on cancellation");
            state.last_error = Some(format!("step '{step_id}' cancelled"));
            state.cancelled = true;
            0
        }
        Err(StepError::Callee {
            plugin,
            action,
            source,
        }) => {
            let msg = format!("step '{step_id}' → {plugin}.{action} failed: {source}");
            tracing::warn!(step_id = %step_id, error = %msg, "Step failed");
            state.last_error = Some(msg);
            state.callee_error = Some(host_api::CalleeError {
                plugin,
                action,
                source,
            });
            0
        }
    }
}

/// The wasmtime runtime wrapper.
pub struct WasmRuntime {
    engine: Engine,
    /// Step types registered for linker dispatch — host-pluggable
    /// [`StepFn`] bodies and kernel-internal [`IntrinsicStepFn`] bodies,
    /// carried uniformly as [`StepBody`] and replayed on every fresh
    /// Linker in `execute()`.
    additional_imports: Vec<(String, StepBody)>,
}

impl WasmRuntime {
    /// Create a new wasm runtime with the engine configured for
    /// fuel-based instruction metering.
    ///
    /// The runtime starts with an empty
    /// `additional_imports` table — the five body-shaped kernel
    /// intrinsics (`throw_error`, `let`, `script`, `invoke`, `wasm`)
    /// self-register via `inventory::submit!` and are wired into the
    /// runtime by `Kernel::boot`'s call to `load_manifest_internal` on
    /// `intrinsics.json`, same path any external plugin's step bodies
    /// take.
    pub fn new() -> Result<Self, KernelError> {
        // `consume_fuel(true)` switches the engine into a mode where
        // every wasm instruction consumes one unit of fuel from the
        // Store. Guest modules — the interpreter behind a `script` step
        // and the module behind a `wasm` step — are the only code that
        // consumes fuel; host step bodies dispatched through the linker
        // run pure Rust and aren't metered. The kernel sets a
        // per-invocation budget on each guest store via
        // `RuntimeLimits::fuel_budget`.
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        // (wasmtime supports async unconditionally — `Config::async_support`
        // is a deprecated no-op, so no explicit opt-in here.)
        let engine = Engine::new(&config)
            .map_err(|e| KernelError::Runtime(format!("Failed to construct wasm engine: {e}")))?;
        Ok(Self {
            engine,
            additional_imports: Vec::new(),
        })
    }

    /// Register a trait-shape step type. Body takes
    /// `&mut dyn PluginExecution` and the step's raw params object, returns
    /// `Result<StepOutput, StepError>`. The wasmtime-side adapter
    /// handles every cross-cutting concern for step bodies: step
    /// lookup, `store_to_variable` binding, metadata sidecar routing,
    /// structured error mapping.
    pub fn register_trait_step_type(&mut self, name: &str, func: StepFn) {
        self.upsert_import(format!("step_{name}"), StepBody::Plugin(func));
    }

    /// Register a kernel-internal ("intrinsic") step body. Same
    /// linker-dispatch path as [`Self::register_trait_step_type`], but
    /// the body receives the concrete `&mut ExecutionState` instead of
    /// the narrow `&mut dyn PluginExecution`. `pub(crate)` because only
    /// the engine itself ships bodies that need engine internals
    /// (`invoke`, `wasm`, `script`, the alias dispatcher); external
    /// plugins always register through the plugin [`StepFn`] path.
    pub(crate) fn register_intrinsic_step_type(&mut self, name: &str, func: IntrinsicStepFn) {
        self.upsert_import(format!("step_{name}"), StepBody::Intrinsic(func));
    }

    /// Insert-or-replace an import by name. Replacement (not push)
    /// matters: `register_linker_imports` replays this table onto a
    /// fresh `Linker` on EVERY `execute_dag`, and a duplicate name
    /// makes `func_wrap_async` error — so a re-registered step type
    /// (hot reload) would otherwise poison all subsequent execution
    /// for every plugin. Cross-plugin duplicate claims are rejected
    /// earlier, at manifest registration, where the conflicting party
    /// can be named.
    fn upsert_import(&mut self, import_name: String, body: StepBody) {
        if let Some(slot) = self
            .additional_imports
            .iter_mut()
            .find(|(name, _)| *name == import_name)
        {
            slot.1 = body;
        } else {
            self.additional_imports.push((import_name, body));
        }
    }

    /// Remove a step type's linker import. Called when the owning
    /// manifest is unloaded so the name becomes claimable again.
    pub(crate) fn remove_step_type(&mut self, name: &str) {
        let import_name = format!("step_{name}");
        self.additional_imports
            .retain(|(existing, _)| *existing != import_name);
    }

    /// Replay every registered trait step type onto a fresh
    /// [`Linker`]. Used by both [`Self::execute_dag`] and the dataflow
    /// scheduler — same dispatch shape, same wrapping rule,
    /// so the linker-build path lives in one place.
    pub(super) fn register_linker_imports(
        &self,
        linker: &mut Linker<ExecutionState>,
    ) -> Result<(), KernelError> {
        for (import_name, body) in &self.additional_imports {
            let body = *body;
            linker
                .func_wrap_async(
                    crate::kernel::abi::ABI_MODULE,
                    import_name,
                    move |caller: wasmtime::Caller<'_, ExecutionState>, (arg,): (i32,)| {
                        Box::new(dispatch_trait_step(caller, arg, body))
                    },
                )
                .map_err(|e| {
                    KernelError::Runtime(format!("Failed to register {import_name}: {e}"))
                })?;
        }
        Ok(())
    }

    /// Load a wasm module from bytes.
    pub fn load_module(&self, wasm_bytes: &[u8]) -> Result<Module, KernelError> {
        Module::new(&self.engine, wasm_bytes)
            .map_err(|e| KernelError::Runtime(format!("Failed to load wasm module: {e}")))
    }

    /// Execute an action via its precomputed DAG plan.
    ///
    /// Creates a fresh Store + ExecutionState per invocation (isolation guarantee),
    /// links every registered host function on the Linker, then iterates the
    /// plan's topological waves. Each step's host function is invoked
    /// directly through wasmtime's `Linker::get` → `Func::typed::call`
    /// dispatch — no wasm module instantiation per action, no compiled
    /// orchestrator. Registered script-runtime wasm modules are still
    /// loaded into ExecutionState for the `script` step type to use.
    ///
    /// In-wave parallelism ships behind the action's
    /// `parallel_waves: true` flag, which this same function
    /// implements: each step in a wave runs in its own task over a
    /// cloned `ExecutionState`, and the writes merge back in
    /// declaration order. With the flag off, the plan runs
    /// wave-by-wave with steps in declaration order.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_dag(
        &self,
        plugin_name: &str,
        action: &Action,
        plan: &DagPlan,
        input: Value,
        config: &Value,
        secrets: &Value,
        script_runtimes: std::sync::Arc<std::collections::HashMap<String, std::sync::Arc<Module>>>,
        exec_ctx: ExecutionContext,
        ctx: InvocationContext,
        limits: super::RuntimeLimits,
    ) -> Result<ActionResult, KernelError> {
        // Streaming-dataflow actions take a different scheduling path:
        // every step runs as its own tokio task from the start,
        // long-running producers stay alive until their stream closes, and
        // a single ActionResult is emitted at pipeline termination. The
        // wave-based path below handles the default `dataflow: false`
        // case.
        if action.dataflow {
            return super::runtime_dataflow::execute_dag_dataflow(
                self,
                plugin_name,
                action,
                plan,
                input,
                config,
                secrets,
                script_runtimes,
                exec_ctx,
                ctx,
                limits,
            )
            .await;
        }

        // Capture the drain flag before `ctx` is moved into `ExecutionState`.
        // For nested `invoke` calls the parent owns the registry; only
        // top-level kernel-allocated registries get drained here. A
        // caller that supplies its own registry with
        // `drain_streams: false` keeps its handles alive so it can
        // `take_readable` a body handle out of `output` afterward.
        let drain_streams = ctx.drain_streams;
        let execution_state = ExecutionState::new(ExecutionStateParams {
            plugin_name: plugin_name.to_string(),
            action: action.clone(),
            input,
            config: config.clone(),
            secrets: secrets.clone(),
            script_runtimes,
            engine: self.engine.clone(),
            exec_ctx,
            streams: ctx.streams,
            invoke_depth: ctx.invoke_depth,
            dispatch_depth: ctx.dispatch_depth,
            kernel: ctx.kernel,
            trigger: ctx.trigger,
            step_type_access: ctx.step_type_access,
            secret_resolver: ctx.secret_resolver,
            limits: limits.clone(),
            cancel: ctx.cancel,
            dataflow_events: ctx.dataflow_events,
        });
        let mut store = Store::new(&self.engine, execution_state);

        let mut linker = Linker::new(&self.engine);
        host_api::register_kernel_services(&mut linker)?;
        // Every body is registered through `func_wrap_async`; a
        // synchronous body simply returns an immediately-ready future,
        // so nothing needs `block_in_place`. The dataflow scheduler
        // reuses this same registration helper.
        self.register_linker_imports(&mut linker)?;

        // Pre-allocated fan-out branches per producer step index. Populated
        // lazily after a stream-producing step with >1 consumers executes;
        // each later consumer of that producer pops the next branch handle
        // and uses it in place of the original producer handle.
        let mut fanout_branches: HashMap<usize, Vec<StreamId>> = HashMap::new();

        // Linker is functionally immutable after registration; share via
        // Arc so parallel-wave tasks can each hold a reference
        // without rebuilding their own linker.
        let linker = Arc::new(linker);

        for wave in &plan.waves {
            // Parallel-wave gate. Three conditions must hold:
            //   1. The wave actually has > 1 step.
            //   2. The action opts in via `parallel_waves`. Manifests
            //      routinely carry declaration-order dependencies the
            //      DAG planner doesn't track — extract/transform
            //      `source: "<step>"` fields, variable reads/writes,
            //      iteration semantics — so the default is the safe
            //      sequential path.
            //   3. Even in an opted-in action, the safety check forces
            //      var/iteration steps sequential, since those are
            //      definitely not parallel-safe.
            let parallelize =
                wave.len() > 1 && action.parallel_waves && !wave_requires_sequential(wave, action);

            if !parallelize {
                for &step_idx in wave {
                    let step = &action.steps[step_idx];

                    // Scheduler-level cancellation poll. Step bodies
                    // observe the token cooperatively DURING a step;
                    // this check is what stops the action BETWEEN
                    // steps, so cancellation works even when every
                    // individual step body ignores the token.
                    if store.data().cancel.is_cancelled() {
                        return Err(KernelError::Cancelled {
                            at_step: step.id.clone(),
                        });
                    }

                    // If any of this step's deps were fan-out producers, install
                    // a per-consumer override on ExecutionState so resolution sees
                    // this consumer's private branch handle. Producer's
                    // `step_results` slot is left intact.
                    set_active_fanout_overrides(
                        &mut store,
                        plan,
                        action,
                        step_idx,
                        &fanout_branches,
                    );

                    let ok = run_step(&linker, &mut store, step, step_idx).await?;
                    if !ok {
                        return Err(step_failure_to_error(store.data(), step));
                    }

                    // If this step produced a stream handle and has multiple
                    // consumers, convert the producer into N fan-out branches
                    // so each consumer sees the same byte sequence on its own
                    // backpressured queue.
                    maybe_install_fanout(
                        &mut store,
                        plan,
                        step_idx,
                        &action.steps[step_idx].id,
                        action,
                        &mut fanout_branches,
                    )
                    .await?;

                    // `return` intrinsic early-exit. Stops the
                    // wave loop the moment any step raised the signal;
                    // the outer per-wave loop also checks before
                    // starting the next wave.
                    if store.data().return_signal.is_some() {
                        break;
                    }
                }
                if store.data().return_signal.is_some() {
                    break;
                }
            } else {
                // Parallel-wave path. Each step in the wave runs
                // on its own tokio task, with its own `Store` wrapping a
                // forked clone of the canonical `ExecutionState`. After every
                // task joins, the per-task writes (step result, status,
                // headers, new variables, errors) are merged back into the
                // canonical state. Steps within a wave have no DAG
                // dependency on each other, so each task writes to its own
                // disjoint slot in `step_results` and contention only
                // surfaces on the shared `streams` registry (already
                // serialised via `Arc<Mutex<…>>`).
                // Same scheduler-level cancellation poll as the
                // sequential path, checked once per wave before any
                // task spawns.
                if store.data().cancel.is_cancelled() {
                    let first = wave
                        .first()
                        .map(|&i| action.steps[i].id.clone())
                        .unwrap_or_default();
                    return Err(KernelError::Cancelled { at_step: first });
                }
                let baseline_variables = store.data().variables.clone();
                // A `JoinSet` (not `Vec<JoinHandle>`) for the same
                // reason as `run_parallel`: dropping this future
                // — caller cancellation,
                // or the `?` on a join panic below — aborts the
                // still-running wave tasks instead of leaking them
                // detached on the runtime.
                type WaveOutcome = (
                    usize,
                    StepDef,
                    Store<ExecutionState>,
                    Result<bool, KernelError>,
                );
                let mut joinset: tokio::task::JoinSet<(usize, WaveOutcome)> =
                    tokio::task::JoinSet::new();
                for (slot, &step_idx) in wave.iter().enumerate() {
                    let mut task_state = store.data().clone();
                    // Install this consumer's fan-out overrides directly on
                    // the forked state before handing it to the task.
                    populate_fanout_overrides_on_state(
                        &mut task_state,
                        plan,
                        action,
                        step_idx,
                        &fanout_branches,
                    );
                    let mut task_store = Store::new(&self.engine, task_state);
                    let linker = linker.clone();
                    let step = action.steps[step_idx].clone();
                    joinset.spawn(async move {
                        let run_result = run_step(&linker, &mut task_store, &step, step_idx).await;
                        (slot, (step_idx, step, task_store, run_result))
                    });
                }
                // Collect in completion order, then merge in WAVE
                // (declaration) order — the first-non-None error rule
                // and the merge sequence must not depend on which task
                // happened to finish first.
                let mut slots: Vec<Option<WaveOutcome>> = Vec::new();
                slots.resize_with(wave.len(), || None);
                // Cancel arm: a token fired mid-wave must not be
                // invisible. Checking once before spawning and then
                // joining unconditionally would let every in-flight
                // step run to completion and return `Ok`, so a caller
                // could not tell "cancelled mid-wave" from "completed
                // normally". Dropping the `JoinSet` on this path aborts
                // the still-running tasks rather than leaking them.
                let cancel = store.data().cancel.clone();
                loop {
                    let joined = tokio::select! {
                        biased;
                        () = cancel.cancelled() => {
                            let first = wave
                                .first()
                                .map(|&i| action.steps[i].id.clone())
                                .unwrap_or_default();
                            return Err(KernelError::Cancelled { at_step: first });
                        }
                        joined = joinset.join_next() => joined,
                    };
                    let Some(joined) = joined else { break };
                    let (slot, outcome) =
                        joined.map_err(|e| join_error("Parallel wave task", &e))?;
                    slots[slot] = Some(outcome);
                }
                // Merge every task's writes before surfacing errors so
                // the canonical state holds the union of partial work
                // even when one task failed.
                let mut first_error: Option<KernelError> = None;
                for outcome in slots {
                    let (step_idx, step, task_store, run_result) =
                        outcome.expect("every wave slot joined exactly once");
                    // Extract the task's ExecutionState BEFORE merging so we can
                    // compute this step's failure error from the task's own
                    // `last_error` / `plugin_error` / `resource_violation`
                    // instead of from the canonical state — which a prior
                    // task may have written to via the first-non-None merge
                    // rule, leading the wrong step's error to win otherwise.
                    let task_state = task_store.into_data();
                    let candidate_error = match run_result {
                        Err(e) => Some(e),
                        Ok(true) => None,
                        Ok(false) => Some(step_failure_to_error(&task_state, &step)),
                    };
                    merge_task_state(&mut store, task_state, &step.id, &baseline_variables);
                    if first_error.is_none() && candidate_error.is_some() {
                        first_error = candidate_error;
                    }
                    let _ = step_idx;
                }
                if let Some(err) = first_error {
                    return Err(err);
                }
                if let Some(err) = merge_over_budget(store.data()) {
                    return Err(err);
                }
                // Post-merge: install fan-outs for producers in this wave.
                // Walks the canonical store (which now holds every task's
                // step_results write) so `maybe_install_fanout` reads the
                // producer's handle from the correct slot.
                for &step_idx in wave {
                    maybe_install_fanout(
                        &mut store,
                        plan,
                        step_idx,
                        &action.steps[step_idx].id,
                        action,
                        &mut fanout_branches,
                    )
                    .await?;
                }
                // `return` intrinsic early-exit on the parallel-wave
                // side. A task that raised the signal had it
                // merged into canonical state above; the wave loop
                // exits here so no later wave runs.
                if store.data().return_signal.is_some() {
                    break;
                }
            }
        }

        let state = store.data();
        // `return` intrinsic short-circuits the normal collect_output
        // path: the explicit return value (if any) becomes the action's
        // output, ignoring `results_path` / `result_mapping` semantics.
        let output = match state.return_signal.as_ref() {
            Some(v) => v.clone(),
            None => state.collect_output(),
        };
        let action_result = ActionResult {
            output,
            variables: state.variables.clone(),
            step_results: state.step_results.clone(),
        };

        // Post-exec cleanup: release every stream still live in the
        // registry. If a script forgot to close a readable stream, or
        // exited mid-loop with a writable sender still holding an HTTP
        // body receiver, dropping the registry closes the socket and
        // unblocks the consumer. Without this, leaked connections or
        // mpsc senders would outlive the invocation that owned them.
        //
        // Skipped when the caller supplied the registry — they need
        // the handles alive after the action returns. Also skipped on
        // `invoke`-nested calls where the parent owns the registry.
        if drain_streams && store.data().invoke_depth == 0 {
            super::streams::lock_shared(&store.data().streams).drain();
        }

        Ok(action_result)
    }

    /// Get a reference to the wasmtime engine (for module compilation).
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}

/// Dispatch a single step.
///
/// `for_each` and `repeat` get host-side loop control here — their
/// begin/next/end host functions manage iteration state, and the inner
/// steps (declared in the step's `params.steps` array) execute once per
/// iteration. Every other step type is a direct host function
/// lookup-and-call.
///
/// Failure handling lives in the `try` step type.
/// `run_step` itself just returns `Ok(false)` on failure; a surrounding
/// `try.catch` body (if any) recovers via `run_try`.
///
/// Returns an explicitly boxed `Send` future rather than using `async
/// fn`: `run_parallel` tokio-spawns tasks that recursively call
/// `run_step`, and with an inferred (opaque) return type the compiler's
/// Send-inference cycles on itself — `run_step`'s Send-ness would
/// depend on `run_parallel`'s, which depends on the spawned block's,
/// which depends on `run_step`'s. Declaring the boxed `dyn Future +
/// Send` type breaks the cycle: each body is checked against the
/// *declared* type instead of recursing through inference.
pub(super) fn run_step<'a>(
    linker: &'a Arc<Linker<ExecutionState>>,
    store: &'a mut Store<ExecutionState>,
    step: &'a StepDef,
    step_idx: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, KernelError>> + Send + 'a>> {
    Box::pin(async move {
        let body_ok = match step.step_type.as_str() {
            "for_each" => run_foreach(linker, store, step, step_idx).await?,
            "repeat" => run_repeat(linker, store, step, step_idx).await?,
            "ifs" => run_ifs(linker, store, step, step_idx).await?,
            "return" => run_return(store, step)?,
            "try" => run_try(linker, store, step, step_idx).await?,
            "parallel" => run_parallel(linker, store, step).await?,
            _ => {
                // Capability gate on the direct path, matching the one
                // on the alias path. Without it a plugin declaring
                // nothing could name another plugin's native step type
                // and run its body — across a namespace boundary at
                // that.
                //
                // The decision was resolved by the kernel at invocation
                // setup, so this works on a kernel that was never
                // wrapped in an `Arc`. The back-reference is consulted
                // only to name the owner in the refusal.
                let Some(key) = store
                    .data()
                    .step_type_access
                    .resolve(&step.step_type)
                    .map(str::to_string)
                else {
                    let caller = store.data().plugin_name.clone();
                    let reason = match store.data().kernel.clone().and_then(|w| w.upgrade()) {
                        Some(kernel) => kernel.explain_step_type_refusal(&caller, &step.step_type),
                        None => format!(
                            "plugin '{caller}' may not use step type '{}'. Add \
                             \"step_type:{}\" to this manifest's `permissions`, or have the \
                             defining plugin mark its `stepTypeDefs` entry \"freelyUsable\": true",
                            step.step_type, step.step_type
                        ),
                    };
                    store.data_mut().last_error = Some(reason.clone());
                    return Err(KernelError::Validation(reason));
                };
                // The import is keyed by the RESOLVED step type — two
                // namespaces' `vault.sign` are two imports.
                let import_name = format!("step_{key}");
                let ret = call_host_fn(linker, store, &import_name, step_idx as i32).await?;
                ret != 0
            }
        };

        // A resource cap tripped *while the body was succeeding* still
        // fails the step. `store_step_result` is the case: it refuses
        // an over-budget result and records the violation, but the body
        // that called it has already returned `true`. Without this the
        // step would report success while its result silently did not
        // exist.
        //
        // Checked here rather than in each body because `run_step` is
        // the single funnel every step type passes through, including
        // the control-flow intrinsics that recurse back into it.
        if body_ok && store.data().resource_violation.is_some() {
            return Ok(false);
        }

        // The `try` step type is the only failure-handling primitive: a
        // step that failed simply returns false, and the surrounding
        // `try.catch` body (if any) recovers via `run_try`.
        Ok(body_ok)
    })
}

async fn run_foreach(
    linker: &Arc<Linker<ExecutionState>>,
    store: &mut Store<ExecutionState>,
    step: &StepDef,
    step_idx: usize,
) -> Result<bool, KernelError> {
    run_iteration(linker, store, step, step_idx, "begin_foreach").await
}

/// `repeat` — runs the inner-step block `params.count` times.
/// Shares iteration state with `for_each` via [`super::host_api::ForEachState`]:
/// `host_begin_repeat` pushes a counted item source (indices `0..count`,
/// produced on demand) onto the same foreach stack, so the `next_foreach` / `end_foreach`
/// host functions drive the loop without any duplicated control logic.
/// The current iteration index is reachable in inner-step params as
/// `{{$item}}`.
async fn run_repeat(
    linker: &Arc<Linker<ExecutionState>>,
    store: &mut Store<ExecutionState>,
    step: &StepDef,
    step_idx: usize,
) -> Result<bool, KernelError> {
    run_iteration(linker, store, step, step_idx, "begin_repeat").await
}

/// Cancellation poll for a nested control-flow body.
///
/// The scheduler polls the token between top-level steps, and the
/// nested executors — `run_try`, `run_ifs`, `run_iteration` (backing
/// both `for_each` and `repeat`), and each `run_parallel` branch —
/// must poll it too rather than calling `run_step` directly. Without
/// those polls a manifest that put its work inside a loop or a `try`,
/// which is the normal shape for long-running work, would be
/// uncancellable, and would report `Ok` rather than `Cancelled` after
/// running to completion.
///
/// It would also disable the wallclock backstop.
/// `tokio::time::timeout` cannot preempt a future that never returns
/// `Pending`; a `repeat` body of pure `let` steps never yields, so
/// neither the kernel's own deadline nor a caller's
/// `tokio::time::timeout` could fire. Without the polls a `repeat` of
/// millions of such iterations cannot be cancelled or timed out at
/// all: it runs to completion pinning a worker thread, then returns
/// `Ok`.
///
/// **This function is also what makes the wallclock deadline work.**
/// The polls alone do not enforce the deadline — nothing in a
/// non-yielding loop observes elapsed time.
/// [`super::with_wallclock_timeout`] therefore arms a watchdog task
/// that fires the invocation's token at the deadline, and the checks
/// here are what observe it. Removing a poll would break the deadline
/// as well as `cancel`.
fn check_cancelled(store: &Store<ExecutionState>, step_id: &str) -> Result<(), KernelError> {
    if store.data().cancel.is_cancelled() {
        return Err(KernelError::Cancelled {
            at_step: step_id.to_string(),
        });
    }
    Ok(())
}

/// After a step returned `false`: if it stopped on the cancellation
/// token rather than failing, propagate `Cancelled` instead of letting
/// the enclosing intrinsic treat it as a failure. `try` in particular
/// must not catch a cancellation — the handler would run under a token
/// that has already fired, and the action would report a swallowed
/// error where the caller cancelled it or its deadline expired.
fn escape_if_cancelled(store: &Store<ExecutionState>, step_id: &str) -> Result<(), KernelError> {
    if store.data().cancelled {
        return Err(KernelError::Cancelled {
            at_step: step_id.to_string(),
        });
    }
    Ok(())
}

/// Execute a `try` intrinsic step.
///
/// Shape:
///
/// ```jsonc
/// {
///   "type": "try",
///   "id": "guard",
///   "params": {
///     "try":     [<step>, ...],   // body
///     "catch":   [<step>, ...],   // runs on body failure; sees {{$.error}}
///     "finally": [<step>, ...]    // always runs after try (and catch)
///   }
/// }
/// ```
///
/// Execution rules:
///
/// 1. Splice `try` steps onto `action.steps`, execute them sequentially.
/// 2. If any body step fails, push the error message onto `error_stack`
///    so the `catch` body sees `{{$.error}}`, splice `catch` onto
///    `action.steps`, execute it. If `catch` itself fails, the whole
///    `try` step fails — that error is what propagates after `finally`
///    runs.
/// 3. Regardless of try/catch outcome, splice `finally` onto
///    `action.steps` and execute it. A `finally` step failure aborts
///    the action (and supersedes any prior failure).
/// 4. The `try` step's own result composes as follows: try success →
///    last try step result; catch recovery → last catch step result;
///    empty-catch swallow → `Null`; unrecovered failure → no result
///    (caller sees the step failed).
///
/// This is the only failure-handling primitive in the manifest
/// format: manifest authors wrap with
/// `{type: "try", try: [step], catch: []}` for swallow semantics or
/// `catch: [...handlers...]` for explicit recovery.
async fn run_try(
    linker: &Arc<Linker<ExecutionState>>,
    store: &mut Store<ExecutionState>,
    step: &StepDef,
    _step_idx: usize,
) -> Result<bool, KernelError> {
    fn array_to_steps(arr: Option<&Value>) -> Vec<StepDef> {
        arr.and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| StepDef::from_inner_value(v).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    let try_steps = array_to_steps(step.params.get("try"));
    // PRESENCE of the catch field (even when empty) signals "handle
    // the failure here." Absence means failure propagates.
    // `{type: "try", try: [step], catch: []}` swallows the step's
    // failure with no recovery body.
    let catch_present = step.params.get("catch").is_some();
    let catch_steps = array_to_steps(step.params.get("catch"));
    let finally_steps = array_to_steps(step.params.get("finally"));

    // === Try block ===
    let mut last_try_result: Option<Value> = None;
    let try_ok = if try_steps.is_empty() {
        true
    } else {
        let inner_offset = store.data().action.steps.len();
        store
            .data_mut()
            .action
            .steps
            .extend(try_steps.iter().cloned());

        let res: Result<bool, KernelError> = async {
            for (i, inner) in try_steps.iter().enumerate() {
                let absolute_idx = inner_offset + i;
                check_cancelled(store, &inner.id)?;
                let ok = run_step(linker, store, inner, absolute_idx).await?;
                if !ok {
                    escape_if_cancelled(store, &inner.id)?;
                    return Ok(false);
                }
                last_try_result = store.data().step_results.get(&inner.id).cloned();
                if store.data().return_signal.is_some() {
                    break;
                }
            }
            Ok(true)
        }
        .await;

        store.data_mut().action.steps.truncate(inner_offset);
        res?
    };

    // Early-exit on `return` — skip catch + finally and unwind.
    if store.data().return_signal.is_some() {
        return Ok(true);
    }

    // === Catch block ===
    //
    // Catch runs only when try failed. Three sub-cases when try failed:
    //
    // 1. `catch` field absent → propagate failure. The step had no
    //    handler declared.
    // 2. `catch` field present but empty array → swallow failure,
    //    recover with no result.
    // 3. `catch` field non-empty → run the handlers; recover if all
    //    succeed, propagate if catch itself fails.
    let mut last_catch_result: Option<Value> = None;
    let mut catch_failed = false;
    if !try_ok {
        if !catch_present {
            // Case 1 — no catch declared, failure propagates.
            catch_failed = true;
        } else if catch_steps.is_empty() {
            // Case 2 — explicit empty catch swallows the failure.
            // Clear ALL failure markers so a subsequent step's
            // failure isn't mis-attributed to the swallowed one. The
            // markers (last_error, plugin_error, resource_violation)
            // are step-scoped state; recovery means the originating
            // step is done and its failure context shouldn't leak.
            let state = store.data_mut();
            state.last_error = None;
            state.plugin_error = None;
            state.resource_violation = None;
            state.callee_error = None;
        } else {
            // Case 3 — run the catch body.
            let err_msg = store
                .data()
                .last_error
                .clone()
                .unwrap_or_else(|| format!("step '{}' failed", step.id));
            store.data_mut().error_stack.push(err_msg);
            // Clear ALL failure markers from the swallowed try
            // failure so a catch step (or any subsequent step) that
            // doesn't itself fail doesn't leave them hanging around
            // to be mis-attributed by `step_failure_to_error` on a
            // later real failure. The catch body still sees the
            // formatted message via `{{$.error}}` (pushed onto
            // error_stack just above) without needing the raw
            // markers to stay populated.
            let state = store.data_mut();
            state.last_error = None;
            state.plugin_error = None;
            state.resource_violation = None;
            state.callee_error = None;

            let inner_offset = store.data().action.steps.len();
            store
                .data_mut()
                .action
                .steps
                .extend(catch_steps.iter().cloned());

            let res: Result<bool, KernelError> = async {
                for (i, inner) in catch_steps.iter().enumerate() {
                    let absolute_idx = inner_offset + i;
                    check_cancelled(store, &inner.id)?;
                    let ok = run_step(linker, store, inner, absolute_idx).await?;
                    if !ok {
                        escape_if_cancelled(store, &inner.id)?;
                        return Ok(false);
                    }
                    last_catch_result = store.data().step_results.get(&inner.id).cloned();
                    if store.data().return_signal.is_some() {
                        break;
                    }
                }
                Ok(true)
            }
            .await;

            store.data_mut().action.steps.truncate(inner_offset);
            let _ = store.data_mut().error_stack.pop();
            catch_failed = !res?;
        }
    }

    // === Finally block (always runs, unless `return` already fired) ===
    if !finally_steps.is_empty() && store.data().return_signal.is_none() {
        let inner_offset = store.data().action.steps.len();
        store
            .data_mut()
            .action
            .steps
            .extend(finally_steps.iter().cloned());

        let res: Result<bool, KernelError> = async {
            for (i, inner) in finally_steps.iter().enumerate() {
                let absolute_idx = inner_offset + i;
                check_cancelled(store, &inner.id)?;
                let ok = run_step(linker, store, inner, absolute_idx).await?;
                if !ok {
                    escape_if_cancelled(store, &inner.id)?;
                    return Ok(false);
                }
                if store.data().return_signal.is_some() {
                    break;
                }
            }
            Ok(true)
        }
        .await;

        store.data_mut().action.steps.truncate(inner_offset);
        // Finally-block failure supersedes any prior try/catch outcome.
        if !res? {
            return Ok(false);
        }
    }

    // Compose the `try` step's own result:
    //   - successful try → last try step's result
    //   - recovered catch (non-empty body) → last catch step's result
    //   - recovered empty catch (swallow form) → store Null so
    //     downstream `{{$steps.<id>.result}}` resolves to null rather
    //     than missing.
    //   - unrecovered failure → no result (caller sees `try` step failed)
    if !catch_failed {
        let composed = last_catch_result.or(last_try_result);
        let value = composed.unwrap_or(Value::Null);
        store.data_mut().store_step_result(&step.id, value);
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Execute a `parallel` intrinsic step.
///
/// Shape:
///
/// ```jsonc
/// {
///   "type": "parallel",
///   "id": "fan_out",
///   "params": {
///     "branches": [
///       [<step>, <step>, ...],   // branch 0
///       [<step>, ...],           // branch 1
///       [<step>]                 // branch 2
///     ]
///   }
/// }
/// ```
///
/// Branches execute **concurrently**: each branch gets its own
/// tokio task with a forked `ExecutionState` (the wave-fork
/// pattern), and the per-branch writes merge back into the canonical
/// state after every task joins. Branches therefore do NOT see each
/// other's step results or variables mid-flight — cross-branch
/// step-id collisions are rejected at `register_plugin` time so each
/// branch's writes land in a disjoint keyspace.
///
/// Semantic guarantees:
///
/// - The parallel step's own result is a JSON array of each branch's
///   last step result, in declaration order. Tasks are collected in
///   completion order but merged in declaration order, so nothing
///   observable depends on which branch finishes first.
/// - Any branch step failure fails the parallel step. Every branch
///   runs to completion before the failure surfaces, and completed
///   branches' writes are merged before the error propagates,
///   mirroring the wave loop.
/// - `return` from inside a branch unwinds the whole parallel step;
///   first-raiser-in-declaration-order wins the signal merge. A later
///   branch still runs even when an earlier branch returned, and a
///   later branch's *failure* still fails the step — "any failure
///   fails the step" beats the return signal.
/// - After the step completes, branch step results / statuses /
///   headers are visible downstream. Variables follow the
///   added-vs-inherited rule — see [`merge_parallel_branch_state`].
async fn run_parallel(
    linker: &Arc<Linker<ExecutionState>>,
    store: &mut Store<ExecutionState>,
    step: &StepDef,
) -> Result<bool, KernelError> {
    let branches: Vec<Vec<StepDef>> = step
        .params
        .get("branches")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|branch| {
                    branch
                        .as_array()
                        .map(|steps| {
                            steps
                                .iter()
                                .filter_map(|v| StepDef::from_inner_value(v).ok())
                                .collect::<Vec<StepDef>>()
                        })
                        .unwrap_or_default()
                })
                .collect()
        })
        .unwrap_or_default();

    if branches.is_empty() {
        store
            .data_mut()
            .store_step_result(&step.id, serde_json::Value::Array(Vec::new()));
        return Ok(true);
    }

    // Baselines for the join-merge: anything a branch task adds beyond
    // these snapshots is a branch write that needs merging back.
    let baseline_variables = store.data().variables.clone();
    let baseline_step_ids: std::collections::HashSet<String> =
        store.data().step_results.keys().cloned().collect();
    let engine = store.engine().clone();

    // One tokio task per non-empty branch, each on a forked
    // ExecutionState with the branch's steps spliced onto its own
    // action.steps copy (host fns address steps by absolute index).
    // A `JoinSet` (not `Vec<JoinHandle>`) so dropping this future —
    // join panic below, caller cancellation, anything — aborts the
    // still-running branches instead of leaking them detached.
    // `None` slots keep empty branches in
    // declaration order so the result array lines up.
    type BranchOutcome = (
        ExecutionState,
        Option<serde_json::Value>,
        bool,
        Option<KernelError>,
    );
    let branch_count = branches.len();
    // Width cap. Each branch forks the entire `ExecutionState`, so an
    // uncapped fan-out multiplies transient host memory by the branch
    // count with nothing charging for it — the clones are not step
    // results and are not wasm, so neither existing bound applies.
    let max_branches = store.data().limits.max_parallel_branches;
    if branch_count > max_branches {
        return Err(KernelError::Validation(format!(
            "parallel step '{}': {branch_count} branches exceeds the \
             {max_branches}-branch limit. Each branch forks the whole execution \
             state, so width multiplies host memory; raise \
             RuntimeLimits::max_parallel_branches if this fan-out is intended",
            step.id
        )));
    }
    let mut joinset: tokio::task::JoinSet<(usize, BranchOutcome)> = tokio::task::JoinSet::new();
    let mut slots: Vec<Option<BranchOutcome>> = Vec::with_capacity(branch_count);
    slots.resize_with(branch_count, || None);
    let mut spawned: Vec<bool> = vec![false; branch_count];
    for (branch_idx, branch_steps) in branches.into_iter().enumerate() {
        if branch_steps.is_empty() {
            continue;
        }
        spawned[branch_idx] = true;
        let mut task_state = store.data().clone();
        let inner_offset = task_state.action.steps.len();
        task_state.action.steps.extend(branch_steps.iter().cloned());
        let linker = Arc::clone(linker);
        let engine = engine.clone();
        joinset.spawn(async move {
            let mut task_store = Store::new(&engine, task_state);
            let mut last_result: Option<serde_json::Value> = None;
            let mut branch_ok = true;
            let mut run_err: Option<KernelError> = None;
            for (i, inner) in branch_steps.iter().enumerate() {
                let absolute_idx = inner_offset + i;
                if let Err(e) = check_cancelled(&task_store, &inner.id) {
                    branch_ok = false;
                    run_err = Some(e);
                    break;
                }
                match run_step(&linker, &mut task_store, inner, absolute_idx).await {
                    Ok(true) => {
                        last_result = task_store.data().step_results.get(&inner.id).cloned();
                        // `return` from inside a branch — stop this
                        // branch; the signal merges back on join and
                        // unwinds the outer loop.
                        if task_store.data().return_signal.is_some() {
                            break;
                        }
                    }
                    Ok(false) => {
                        branch_ok = false;
                        // A cancelled step is an error for the whole
                        // `parallel`, not a failed branch: carried in
                        // `run_err` so it escapes the enclosing `try`
                        // the same way a top-level cancellation does.
                        run_err = escape_if_cancelled(&task_store, &inner.id).err();
                        break;
                    }
                    Err(e) => {
                        branch_ok = false;
                        run_err = Some(e);
                        break;
                    }
                }
            }
            (
                branch_idx,
                (task_store.into_data(), last_result, branch_ok, run_err),
            )
        });
    }

    // Collect in completion order (JoinSet), then merge in DECLARATION
    // order from the slots — merge order is observable via the
    // first-non-None error/signal rules and must not depend on which
    // branch finished first. A join panic propagates via `?`, which
    // drops the JoinSet and aborts the remaining branches.
    while let Some(joined) = joinset.join_next().await {
        let (branch_idx, outcome) = joined.map_err(|e| join_error("Parallel branch task", &e))?;
        slots[branch_idx] = Some(outcome);
    }

    let mut branch_results: Vec<serde_json::Value> = Vec::with_capacity(branch_count);
    let mut any_branch_failed = false;
    let mut first_error: Option<KernelError> = None;
    for (branch_idx, slot) in slots.into_iter().enumerate() {
        let Some((task_state, last_result, branch_ok, run_err)) = slot else {
            debug_assert!(!spawned[branch_idx], "spawned branch must have joined");
            branch_results.push(serde_json::Value::Null);
            continue;
        };
        merge_parallel_branch_state(store, task_state, &baseline_step_ids, &baseline_variables);
        if !branch_ok {
            any_branch_failed = true;
        }
        if first_error.is_none() {
            first_error = run_err;
        }
        branch_results.push(last_result.unwrap_or(serde_json::Value::Null));
    }

    if let Some(err) = first_error {
        return Err(err);
    }
    if let Some(err) = merge_over_budget(store.data()) {
        return Err(err);
    }

    store
        .data_mut()
        .store_step_result(&step.id, serde_json::Value::Array(branch_results));

    if any_branch_failed {
        Ok(false)
    } else {
        Ok(true)
    }
}

/// Merge a parallel branch task's writes back into the canonical state.
/// Sibling of [`merge_task_state`], which merges exactly one
/// known step slot per wave task; a branch task instead writes an
/// arbitrary set of slots (its own steps, plus nested control-flow
/// steps spliced at runtime), so the merge is diff-against-baseline:
/// every `step_results` / `step_metadata` key absent
/// from the pre-spawn snapshot is a branch write. Cross-branch key
/// collisions can't occur — `register_plugin` rejects duplicate step
/// ids across branches.
///
/// Variables follow the same added-vs-inherited rule as the wave merge:
/// only variables a branch **introduced** merge back. A branch write to
/// a variable that existed before the parallel step is deliberately
/// discarded — under concurrency, honoring it would be a join-order
/// race, and deterministic-but-lossy beats racy. Two branches using the same
/// `storeToVariable` can't reach this merge: `validate_step_shapes`
/// rejects the collision at register time, mirroring the
/// step-id check above.
///
/// Error fields and the `return` signal take first-non-`None` in merge
/// (declaration) order.
fn merge_parallel_branch_state(
    canonical: &mut Store<ExecutionState>,
    task_state: ExecutionState,
    baseline_step_ids: &std::collections::HashSet<String>,
    baseline_variables: &IndexMap<String, Value>,
) {
    let canonical_state = canonical.data_mut();

    // Charged through the same funnel as every other result — see
    // `merge_task_state` for why results must not be inserted directly.
    for (k, v) in &task_state.step_results {
        if !baseline_step_ids.contains(k) {
            canonical_state.store_step_result(k, v.clone());
        }
    }
    for (k, v) in &task_state.step_metadata {
        if !baseline_step_ids.contains(k) {
            canonical_state.step_metadata.insert(k.clone(), v.clone());
        }
    }
    if canonical_state.first_step_id.is_none() {
        canonical_state.first_step_id = task_state.first_step_id;
    }

    for (k, v) in &task_state.variables {
        if !baseline_variables.contains_key(k) {
            canonical_state.variables.insert(k.clone(), v.clone());
        }
    }

    if task_state.last_error.is_some() && canonical_state.last_error.is_none() {
        canonical_state.last_error = task_state.last_error;
    }
    if task_state.plugin_error.is_some() && canonical_state.plugin_error.is_none() {
        canonical_state.plugin_error = task_state.plugin_error;
    }
    if task_state.resource_violation.is_some() && canonical_state.resource_violation.is_none() {
        canonical_state.resource_violation = task_state.resource_violation;
    }
    // `cancelled` is deliberately not merged: a cancelled branch is
    // carried as the `parallel` step's own error, and the flag would
    // otherwise outlive the `try` resets that clear every other marker.
    if task_state.callee_error.is_some() && canonical_state.callee_error.is_none() {
        canonical_state.callee_error = task_state.callee_error;
    }
    if task_state.return_signal.is_some() && canonical_state.return_signal.is_none() {
        canonical_state.return_signal = task_state.return_signal;
    }
}

/// Execute a `return` intrinsic step.
///
/// Resolves the optional `value` param against the current template
/// context, stores it as the step's own result (so downstream
/// `{{$steps.<id>.result}}` references still resolve), and raises
/// [`ExecutionState::return_signal`]. Every wave-loop and inner-block
/// loop in the runtime polls that flag after each `run_step` call and
/// exits cleanly when set; `execute_dag` uses the captured value as
/// the action's output in place of the normal `collect_output` flow.
///
/// Sync (no `linker` arg needed) — just a state mutation. Returning
/// `Ok(true)` keeps the surrounding loop's "step succeeded" contract;
/// the actual early-exit happens via the signal check the next time
/// around the loop, not via this fn's return value.
fn run_return(store: &mut Store<ExecutionState>, step: &StepDef) -> Result<bool, KernelError> {
    let ctx = store.data().resolution_context();
    let raw_value = step
        .params
        .get("value")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let resolved = crate::domain::resolve::resolve_value(&raw_value, &ctx);

    let state = store.data_mut();
    state.store_step_result(&step.id, resolved.clone());
    state.return_signal = Some(resolved);
    Ok(true)
}

/// `ifs` step type. Multi-branch conditional driven by DSL
/// expressions, shaped like a `match`: the first branch whose `test`
/// evaluates to a truthy value runs its `then` array. A branch with no
/// `test` always matches, so an "else" is just a final untested
/// branch (validation requires it to be last). No branch → no-op.
///
/// Conditions are parsed via [`crate::dsl::parse_expression`] and
/// evaluated against the action's full resolution context (input,
/// steps, config, secrets, vars). The DSL natively supports
/// `==`/`!=`, `&&`/`||`, and the ordered comparisons
/// (`<`, `<=`, `>`, `>=`, numeric operands only) that make a `test` of
/// `"status >= 400"` work cleanly.
async fn run_ifs(
    linker: &Arc<Linker<ExecutionState>>,
    store: &mut Store<ExecutionState>,
    step: &StepDef,
    _step_idx: usize,
) -> Result<bool, KernelError> {
    // Evaluate each branch's test in order. The host borrows `step`'s
    // params from the action — `then` arrays stay JSON values until
    // we pick the matching branch. Manifest validation guarantees
    // `ifs` is present and that an untested branch is last.
    let ifs_arr = match step.params.get("ifs").and_then(|v| v.as_array()).cloned() {
        Some(arr) => arr,
        None => return Ok(true),
    };

    let mut chosen_branch: Option<Vec<serde_json::Value>> = None;
    for branch in &ifs_arr {
        // No `test` (omitted or null) is the always-true "else" branch.
        let matched = match branch.get("test").and_then(|v| v.as_str()) {
            Some(cond_str) => eval_if_condition(store.data(), cond_str)?,
            None => true,
        };
        if matched {
            if let Some(then_arr) = branch.get("then").and_then(|v| v.as_array()) {
                chosen_branch = Some(then_arr.clone());
            } else {
                chosen_branch = Some(Vec::new());
            }
            break;
        }
    }
    let inner_array = chosen_branch.unwrap_or_default();

    let inner_steps: Vec<StepDef> = inner_array
        .iter()
        .filter_map(|v| StepDef::from_inner_value(v).ok())
        .collect();

    if inner_steps.is_empty() {
        return Ok(true);
    }

    // Splice inner steps onto action.steps the same way iteration
    // does so host step fns find their step definitions by absolute
    // index.
    let inner_offset = store.data().action.steps.len();
    store
        .data_mut()
        .action
        .steps
        .extend(inner_steps.iter().cloned());

    let body_result: Result<bool, KernelError> = async {
        for (inner_idx, inner) in inner_steps.iter().enumerate() {
            let absolute_idx = inner_offset + inner_idx;
            check_cancelled(store, &inner.id)?;
            let ok = run_step(linker, store, inner, absolute_idx).await?;
            if !ok {
                escape_if_cancelled(store, &inner.id)?;
                return Ok(false);
            }
            // `return` early-exit from inside a chosen branch.
            if store.data().return_signal.is_some() {
                break;
            }
        }
        Ok(true)
    }
    .await;

    store.data_mut().action.steps.truncate(inner_offset);
    body_result
}

/// Evaluate an `ifs` branch's `test` string as a DSL expression
/// against the current `ExecutionState` resolution context. Truthiness
/// is delegated to [`crate::dsl::is_truthy`] — the same rule the DSL's
/// own `!`/`&&`/`||` operators use, so `cond` and `!cond` always negate
/// each other.
///
/// Builds an `IndexMap` of wrapped step results (`{result, …metadata}`)
/// so `steps.<id>.<metadata key>` resolves correctly inside conditions;
/// the resolution context's plain JSON Map can't be fed directly to
/// the DSL evaluator.
fn eval_if_condition(state: &ExecutionState, condition: &str) -> Result<bool, KernelError> {
    let value = eval_dsl_expression(state, condition, "ifs step")?;
    Ok(crate::dsl::is_truthy(&value))
}

/// Evaluate a DSL expression against the current `ExecutionState` and return
/// the raw [`Value`]. Used by `ifs` branch tests (further coerced to
/// `bool`), `until` clauses, and `collect` accumulators on
/// `for_each` / `repeat`. Builds the same wrapped step-results map +
/// `EvalContext` as `eval_if_condition` so all evaluations see a
/// consistent view of `$steps.X.{result, …metadata}`.
fn eval_dsl_expression(
    state: &ExecutionState,
    expression: &str,
    context_label: &str,
) -> Result<Value, KernelError> {
    use crate::dsl::{self, EvalContext};
    let expr = dsl::parse_expression(expression).map_err(|e| {
        KernelError::Execution(format!(
            "{context_label}: expression '{expression}' parse error: {e}"
        ))
    })?;
    let steps_map = state.build_dsl_steps_view();
    let vars_value = state.vars_as_value();
    let trigger_value = state.trigger.as_deref().cloned();
    let item = state
        .foreach_stack
        .last()
        .and_then(|f| f.current_value.as_ref());
    let eval_ctx = EvalContext {
        input: Some(&state.input),
        steps: Some(&steps_map),
        config: Some(&state.config),
        secrets: Some(&state.secrets),
        trigger: trigger_value.as_ref(),
        vars: Some(&vars_value),
        item,
        implicit_source: None,
    };
    Ok(dsl::eval_expression(&expr, &eval_ctx))
}

/// Shared driver for `for_each` and `repeat`. Reads the inner-step
/// block, calls `begin_fn` to push iteration state, then loops over
/// `next_foreach` / `end_foreach` — both of which work uniformly
/// against the foreach_stack regardless of which begin pushed it.
///
/// Host step functions look up their step definition via
/// `state.action.steps[step_index]`. Inner steps live in
/// `step.params.steps`, not in the host's action steps list, so before
/// we run them we splice them onto `action.steps` and dispatch each
/// inner step by its absolute index in that extended list. After the
/// loop completes we truncate back, leaving ExecutionState's view of the
/// action unchanged for any caller higher in the stack. Nested
/// iterations (a `repeat` inside a `for_each` inside a `repeat`) nest
/// cleanly because each layer extends and truncates within its own
/// scope.
async fn run_iteration(
    linker: &Arc<Linker<ExecutionState>>,
    store: &mut Store<ExecutionState>,
    step: &StepDef,
    step_idx: usize,
    begin_fn: &str,
) -> Result<bool, KernelError> {
    let inner_steps: Vec<StepDef> = step
        .params
        .get("steps")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| StepDef::from_inner_value(v).ok())
                .collect()
        })
        .unwrap_or_default();

    let count = call_host_fn(linker, store, begin_fn, step_idx as i32).await?;
    if count < 0 {
        // `begin_*` host functions return -1 on bad input (with
        // `last_error` set on ExecutionState). Surface that as an
        // execution error rather than treating it as zero iterations.
        let state = store.data();
        let msg = state
            .last_error
            .clone()
            .unwrap_or_else(|| format!("{begin_fn} returned negative count"));
        return Err(KernelError::Execution(msg));
    }

    let inner_offset = store.data().action.steps.len();
    store
        .data_mut()
        .action
        .steps
        .extend(inner_steps.iter().cloned());

    // `until` (repeat only) — DSL expression evaluated after each
    // iteration body. When truthy, exit before the next iteration.
    // `count` continues to act as a safety cap.
    let until_expr: Option<String> = if begin_fn == "begin_repeat" {
        step.params
            .get("until")
            .and_then(|v| v.as_str())
            .map(str::to_string)
    } else {
        None
    };

    // `collect` (for_each + repeat) — DSL expression evaluated after
    // each iteration body. The value is pushed onto a per-loop
    // accumulator; once the loop exits, the outer step's result is
    // set to the assembled array so downstream consumers can read
    // `$steps.<id>.result` as a normal step output.
    let collect_expr: Option<String> = step
        .params
        .get("collect")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let mut collected: Vec<Value> = Vec::new();
    // Running size of `collected`, for the budget guard below.
    let mut collected_bytes: usize = 0;

    // Inner-step IDs to clear at the top of each iteration. Without
    // this, a step that doesn't run on iteration N+1 (a step inside an
    // `ifs` branch not taken this time, a `try` body that failed
    // early, etc.) leaves iteration N's value in `step_results` and
    // downstream templates resolve to the stale prior value. Clearing
    // at the top — not the bottom — preserves the last iteration's
    // step_results for outer-scope reads after the loop exits (the
    // result_mapping pattern).
    let inner_ids: Vec<String> = inner_steps.iter().map(|s| s.id.clone()).collect();

    let body_result: Result<bool, KernelError> = async {
        if count > 0 {
            loop {
                let has_item = call_host_fn(linker, store, "next_foreach", step_idx as i32).await?;
                if has_item == 0 {
                    break;
                }
                // Clear immediate inner-step results from the previous
                // iteration before running the body. See `inner_ids`
                // comment above for the rationale.
                {
                    let state = store.data_mut();
                    for id in &inner_ids {
                        state.step_results.shift_remove(id);
                        state.step_metadata.shift_remove(id);
                    }
                }
                let mut inner_returned = false;
                for (inner_idx, inner) in inner_steps.iter().enumerate() {
                    let absolute_idx = inner_offset + inner_idx;
                    check_cancelled(store, &inner.id)?;
                    let ok = run_step(linker, store, inner, absolute_idx).await?;
                    if !ok {
                        escape_if_cancelled(store, &inner.id)?;
                        return Ok(false);
                    }
                    // `return` from inside an iteration body exits the
                    // entire iteration loop, not just the current pass
                    // through inner steps.
                    if store.data().return_signal.is_some() {
                        inner_returned = true;
                        break;
                    }
                }
                if inner_returned {
                    break;
                }
                // Collect THIS iteration's value (if requested) before
                // checking `until`, so even the terminating iteration's
                // result lands in the accumulator.
                if let Some(expr) = collect_expr.as_deref() {
                    let value = eval_dsl_expression(store.data(), expr, "collect")?;
                    // Charge the accumulator as it grows, not when it is
                    // finally stored. `collect` pushes one value per
                    // iteration into a host `Vec`; checking only at the
                    // post-loop `store_step_result` would let peak memory
                    // reach `count x item size` with nothing watching.
                    //
                    // Counted against what is already committed, so the
                    // guard tightens as an action fills its budget
                    // rather than granting every loop a fresh one.
                    collected_bytes =
                        collected_bytes.saturating_add(host_api::approx_value_bytes(&value));
                    let limit = store.data().limits.max_step_results_bytes;
                    let committed = store.data().step_results_bytes;
                    let projected = committed.saturating_add(collected_bytes);
                    if projected > limit {
                        return Err(KernelError::StepResultsLimitExceeded {
                            limit_bytes: limit,
                            attempted_bytes: projected,
                        });
                    }
                    collected.push(value);
                }
                // Check `until` AFTER inner steps so the body always runs
                // at least once per iteration (do-until semantics). Inner
                // step results are still in `step_results` here because
                // they're written by the run_step calls above and not
                // truncated until the entire iteration tears down.
                if let Some(expr) = until_expr.as_deref()
                    && eval_if_condition(store.data(), expr)?
                {
                    break;
                }
            }
        }
        Ok(true)
    }
    .await;

    // Restore action.steps regardless of how the body exited so
    // outer iteration frames and end_foreach see the same view they
    // started with.
    store.data_mut().action.steps.truncate(inner_offset);

    let ok = body_result?;
    if !ok {
        // Pop the iteration state we pushed so a downstream end_foreach
        // on the next level doesn't accidentally see ours. Body failure
        // also short-circuits the action.
        let _ = store.data_mut().foreach_stack.pop();
        return Ok(false);
    }

    call_host_fn(linker, store, "end_foreach", step_idx as i32).await?;

    // Surface the collected array as the outer step's result so
    // downstream consumers can read `$steps.<id>.result`. Only writes
    // when `collect` was set — without it, the result `end_foreach`
    // stored (an empty array) stands.
    if collect_expr.is_some() {
        store
            .data_mut()
            .store_step_result(&step.id, Value::Array(collected));
    }

    Ok(true)
}

/// Detect whether step `step_idx` just produced a stream handle that needs
/// fan-out, and if so convert it to N branches keyed by consumer order.
///
/// The fan-out helpers return `Err` only for invariant violations
/// (non-readable producer or `n_branches == 0`). The guards above —
/// `consumers.len() >= 2` and the readable-and-open check — make both
/// impossible at this call site, so an `Err` here is a kernel bug rather
/// than a recoverable condition. Mapped to a hard `KernelError` instead
/// of a warning so it surfaces the next time someone restructures the
/// call site, rather than producing a misleading log line and silent
/// data loss on the consumer side (the producer's source is already
/// consumed by the time the helper returns).
async fn maybe_install_fanout(
    store: &mut Store<ExecutionState>,
    plan: &DagPlan,
    step_idx: usize,
    step_id: &str,
    action: &Action,
    fanout: &mut HashMap<usize, Vec<StreamId>>,
) -> Result<(), KernelError> {
    let consumers = &plan.consumers[step_idx];
    if consumers.len() < 2 {
        return Ok(());
    }
    let state = store.data();
    // step_results entries written by stream-producing step types are
    // positive u32 handles encoded as JSON numbers; the chain
    // `Number → u64 → u32 → NonZeroU32` only matches that exact shape
    // and ignores everything else (negative ints, floats, strings,
    // bools, missing entries). Final guard against a stale or invalid
    // handle is the `streams.get(handle).is_readable()` check below.
    let handle_int = match state.step_results.get(step_id) {
        Some(Value::Number(n)) => n.as_u64(),
        _ => None,
    };
    let Some(handle) = handle_int
        .and_then(|v| u32::try_from(v).ok())
        .and_then(NonZeroU32::new)
    else {
        return Ok(());
    };
    {
        let streams = super::streams::lock_shared(&state.streams);
        if !streams
            .get(handle)
            .map(|s| s.is_readable() && !s.is_closed())
            .unwrap_or(false)
        {
            return Ok(());
        }
    }

    let streams_arc = store.data().streams.clone();
    // Streaming fan-out (`fan_out_readable_streaming`) requires
    // concurrent consumers; the parallel-wave path (`parallel_waves: true`)
    // guarantees that. Under sequential within-wave execution,
    // the forwarder would fill the first consumer's channel and block
    // waiting for the second consumer to drain — deadlock. So the
    // eager-drain variant stays the choice for the sequential path,
    // and it's an async free function (`fan_out_readable_shared`) so
    // the source-drain `.await` runs with the registry mutex released.
    let branches = if action.parallel_waves {
        // Shared default capacity — see
        // [`super::streams::STREAM_FANOUT_CAPACITY`] for the rationale
        // (shared so wave + dataflow paths stay in lockstep).
        super::streams::lock_shared(&streams_arc).fan_out_readable_streaming(
            handle,
            consumers.len(),
            super::streams::STREAM_FANOUT_CAPACITY,
        )
    } else {
        super::streams::fan_out_readable_shared(&streams_arc, handle, consumers.len()).await
    };
    let branches = branches.map_err(|e| {
        KernelError::Execution(format!(
            "Internal: stream fan-out setup failed for step '{step_id}': {e}"
        ))
    })?;
    fanout.insert(step_idx, branches);
    Ok(())
}

/// Matches a variable reference the DAG planner doesn't track. The only
/// surface form that resolves is `$vars.<ident>` — inside a
/// `{{$vars.x}}` template or as a bare DSL path reachable from ordinary
/// step params via `eval_path` (e.g. `path: "$vars.x"`) — and
/// `VARS_DSL_RE` catches both, since the `$vars.` token sits inside the
/// braces. `VARS_TMPL_RE` additionally matches the bare `{{ vars.… }}`
/// spelling, which never resolves. Any match must force a
/// variable-mediated wave sequential.
static VARS_TMPL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{\{\s*vars\.").unwrap());
static VARS_DSL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\$vars\.").unwrap());

/// Whether `wave` should fall back to sequential execution because it
/// contains a step with side effects the DAG planner doesn't track.
///
/// The DAG planner only follows `$steps.<id>` / `{{$steps.<id>}}` refs.
/// Variables (`{{$vars.X}}` / `$vars.X` reads + `store_to_variable`
/// writes) and iteration step types (`for_each`, `repeat`, `ifs`) carry
/// communication channels the planner can't see, so parallelizing such a
/// wave would break the implicit declaration-order semantics manifests
/// rely on.
///
/// This is conservative: a wave that *could* be parallelized but happens
/// to contain a `store_to_variable` writer whose value isn't read by
/// anyone else in the wave still falls back. A planner that tracked
/// variable reads/writes as edges could relax this.
///
/// **Load-bearing for the `$vars` no-edge contract.** `$vars.<name>`
/// deliberately creates no DAG dependency edge (see `dsl::ast::Root::Vars`),
/// so a `$vars` reader's writer-before-reader ordering comes *entirely*
/// from this sequential fallback: the writer always forces its own wave
/// sequential and waves run in declaration order. Any planner change
/// that relaxes this fallback must add variable read/write edges
/// *before* dropping the blanket writer/iteration fallback here —
/// otherwise `$vars` readers can intermittently read null once their
/// wave parallelizes.
fn wave_requires_sequential(wave: &[usize], action: &Action) -> bool {
    wave.iter().any(|&idx| {
        let step = &action.steps[idx];
        if step.store_to_variable.is_some() {
            return true;
        }
        // A variable *writer* is caught above (`store_to_variable`, which
        // `let` uses); these are the iteration / control-flow step types
        // whose inner blocks carry channels the planner can't see.
        if matches!(step.step_type.as_str(), "for_each" | "repeat" | "ifs") {
            return true;
        }
        params_references_vars(&step.params)
    })
}

/// Recursively scan a JSON value for any variable reference inside string
/// leaves — `$vars.…` (bare or inside a `{{…}}` template), plus the
/// bare `{{vars.…}}` spelling. Returns `true` on the first match.
fn params_references_vars(value: &Value) -> bool {
    match value {
        Value::String(s) => VARS_TMPL_RE.is_match(s) || VARS_DSL_RE.is_match(s),
        Value::Array(arr) => arr.iter().any(params_references_vars),
        Value::Object(map) => map.values().any(params_references_vars),
        _ => false,
    }
}

#[cfg(test)]
mod vars_sequential_guard_tests {
    //! `params_references_vars` must catch a `$vars` reference in *either*
    //! surface form so `wave_requires_sequential` keeps forcing
    //! variable-mediated waves sequential — the writer-before-reader
    //! ordering the `$vars` no-DAG-edge contract depends on.
    use super::params_references_vars;
    use serde_json::json;

    #[test]
    fn detects_template_and_dsl_vars_refs() {
        // Template form.
        assert!(params_references_vars(&json!({ "x": "{{vars.paths}}" })));
        // DSL form — bare `$vars` in a structural param like a
        // `for_each.path`, which a `{{vars.…}}`-only regex would miss.
        assert!(params_references_vars(&json!({ "path": "$vars.paths" })));
        // Nested inside arrays / objects.
        assert!(params_references_vars(&json!({ "a": ["$vars.y"] })));
    }

    #[test]
    fn ignores_non_vars_refs() {
        assert!(!params_references_vars(
            &json!({ "path": "$steps.seed.result" })
        ));
        assert!(!params_references_vars(
            &json!({ "x": "{{steps.foo.result}}" })
        ));
        assert!(!params_references_vars(&json!({ "x": "no refs here" })));
    }
}

/// Map a `JoinError` from a parallel branch/wave task into a
/// `KernelError`, distinguishing a task panic from cancellation —
/// `JoinError::Cancelled` isn't a panic and saying "panicked" for it
/// would point debugging at the wrong place. Used by both
/// `run_parallel` and `execute_dag`'s parallel-wave loop.
fn join_error(what: &str, join_err: &tokio::task::JoinError) -> KernelError {
    if join_err.is_panic() {
        KernelError::Execution(format!("{what} panicked: {join_err}"))
    } else {
        KernelError::Execution(format!("{what} was cancelled: {join_err}"))
    }
}

/// A budget tripped while merging a finished task's results into the
/// canonical state.
///
/// `store_step_result` refuses the value and records the violation, but
/// by then the task has already returned success — so, exactly as on the
/// sequential path, something after the fact has to turn that into a
/// failed action. Dropping the value and carrying on would be a silent
/// wrong answer.
///
/// Only `StepResultsLimit` is considered: it is the only violation a
/// merge itself can raise. A violation the *task* raised has already
/// failed that task through `run_step`.
fn merge_over_budget(state: &ExecutionState) -> Option<KernelError> {
    match state.resource_violation.clone() {
        Some(host_api::ResourceViolation::StepResultsLimit {
            limit_bytes,
            attempted_bytes,
        }) => Some(KernelError::StepResultsLimitExceeded {
            limit_bytes,
            attempted_bytes,
        }),
        _ => None,
    }
}

/// Map a failed step's `ExecutionState` scratch fields into the matching
/// structured `KernelError` variant. Used by both the sequential and
/// parallel-wave paths so the error mapping rule lives in one place.
///
/// Order matters: a resource-cap violation, a cancellation, a failed
/// callee and a structured `throw_error` payload all wrap richer
/// information than the generic `Execution(string)` form, so callers
/// can branch on the variant instead of parsing strings.
pub(super) fn step_failure_to_error(state: &ExecutionState, step: &StepDef) -> KernelError {
    if let Some(violation) = state.resource_violation.clone() {
        return match violation {
            host_api::ResourceViolation::FuelExhausted { budget } => {
                let detail = state
                    .last_error
                    .clone()
                    .unwrap_or_else(|| format!("step '{}'", step.id));
                KernelError::FuelExhausted { budget, detail }
            }
            host_api::ResourceViolation::MemoryLimit { bytes } => {
                KernelError::MemoryLimitExceeded { limit_bytes: bytes }
            }
            host_api::ResourceViolation::StepResultsLimit {
                limit_bytes,
                attempted_bytes,
            } => KernelError::StepResultsLimitExceeded {
                limit_bytes,
                attempted_bytes,
            },
        };
    }
    if state.cancelled {
        return KernelError::Cancelled {
            at_step: step.id.clone(),
        };
    }
    if let Some(callee) = state.callee_error.clone() {
        return KernelError::CalleeFailed {
            step_id: step.id.clone(),
            plugin: callee.plugin,
            action: callee.action,
            source: callee.source,
        };
    }
    if let Some(payload) = state.plugin_error.clone() {
        return KernelError::PluginError {
            code: payload.code,
            message: payload.message,
            params: payload.params,
        };
    }
    let msg = state
        .last_error
        .clone()
        .unwrap_or_else(|| format!("Step '{}' failed", step.id));
    KernelError::Execution(msg)
}

/// Compute the fan-out branch overrides for `step_idx` and write them
/// directly onto a free-standing `ExecutionState`. Sibling to
/// [`set_active_fanout_overrides`] which mutates through a `Store`;
/// used by the parallel-wave path so each forked ExecutionState carries its
/// consumer's branch handles before being handed to a spawned task.
pub(super) fn populate_fanout_overrides_on_state(
    state: &mut ExecutionState,
    plan: &DagPlan,
    action: &Action,
    step_idx: usize,
    fanout: &HashMap<usize, Vec<StreamId>>,
) {
    let mut overrides: HashMap<String, u32> = HashMap::new();
    for &dep_idx in &plan.deps[step_idx] {
        let Some(branches) = fanout.get(&dep_idx) else {
            continue;
        };
        let Some(pos) = plan.consumers[dep_idx].iter().position(|&c| c == step_idx) else {
            continue;
        };
        if pos >= branches.len() {
            continue;
        }
        let branch_id: u32 = branches[pos].into();
        let producer_id = action.steps[dep_idx].id.clone();
        overrides.insert(producer_id, branch_id);
    }
    state.active_fanout_overrides = overrides;
}

/// Merge the writes a parallel-wave task made to its forked `ExecutionState`
/// back into the canonical state. Each task is responsible for **one**
/// step at `step_id` and writes to that single slot in `step_results`
/// (and optional sidecar `step_metadata`); it may
/// also have appended to `variables` via `store_to_variable`, or set
/// per-step error fields. Since wave members have no DAG dependency on
/// each other, the per-step `step_results` slots are disjoint and the
/// merge is straight insertion.
///
/// `baseline_variables` is a snapshot of `variables` taken before the
/// wave dispatched, so we can detect which variable entries the task
/// added vs. inherited from before. Errors take first-non-`None` wins
/// across tasks — see [`step_failure_to_error`] for how those map to
/// the action's `KernelError`.
pub(super) fn merge_task_state(
    canonical: &mut Store<ExecutionState>,
    task_state: ExecutionState,
    step_id: &str,
    baseline_variables: &IndexMap<String, Value>,
) {
    let canonical_state = canonical.data_mut();

    // Through `store_step_result`, not a direct insert. A forked task
    // checks the budget against its *own* copy of the byte counter, so a
    // direct insert here would let N parallel members merge back
    // N x budget while the canonical counter still read zero — and,
    // with the counter then permanently under-counting, would weaken
    // the bound for every later sequential step too. Routing through
    // the one charging funnel is what keeps "cumulative" true.
    if let Some(result) = task_state.step_results.get(step_id) {
        canonical_state.store_step_result(step_id, result.clone());
    }
    if let Some(meta) = task_state.step_metadata.get(step_id) {
        canonical_state
            .step_metadata
            .insert(step_id.to_string(), meta.clone());
    }

    for (k, v) in &task_state.variables {
        if !baseline_variables.contains_key(k) {
            canonical_state.variables.insert(k.clone(), v.clone());
        }
    }

    if task_state.last_error.is_some() && canonical_state.last_error.is_none() {
        canonical_state.last_error = task_state.last_error;
    }
    if task_state.plugin_error.is_some() && canonical_state.plugin_error.is_none() {
        canonical_state.plugin_error = task_state.plugin_error;
    }
    if task_state.resource_violation.is_some() && canonical_state.resource_violation.is_none() {
        canonical_state.resource_violation = task_state.resource_violation;
    }
    // `return` intrinsic signal: first task to raise
    // the signal wins, same first-non-None rule as the failure fields.
    // The outer wave loop's post-merge check breaks out of dispatch
    // once any task in the wave returned.
    if task_state.return_signal.is_some() && canonical_state.return_signal.is_none() {
        canonical_state.return_signal = task_state.return_signal;
    }
}

/// Install the per-consumer fan-out branch override map onto ExecutionState
/// before dispatching step `step_idx`. For each dep `d_idx` of the step
/// that has a fan-out plan, the consumer's slot in
/// `plan.consumers[d_idx]` determines which branch handle to expose as
/// `steps.<producer>.result` for *this* step's resolution surface.
///
/// This does **not** mutate `step_results[<producer_id>]` — the
/// producer's original handle stays in its slot. Resolution checks
/// `active_fanout_overrides` first via
/// [`ExecutionState::effective_step_result`] / [`ExecutionState::step_results_view_with_overrides`]
/// and falls back to `step_results` for non-overridden keys. That
/// decouples the per-consumer view from a shared mutable slot, which is
/// what lets concurrent consumers in the same wave each carry their own
/// override map without racing on the producer's `step_results` entry.
///
/// Consumer order in `plan.consumers[dep_idx]` is the manifest declaration
/// order, so "nth consumer gets nth branch" stability is preserved.
fn set_active_fanout_overrides(
    store: &mut Store<ExecutionState>,
    plan: &DagPlan,
    action: &Action,
    step_idx: usize,
    fanout: &HashMap<usize, Vec<StreamId>>,
) {
    let mut overrides: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for &dep_idx in &plan.deps[step_idx] {
        let Some(branches) = fanout.get(&dep_idx) else {
            continue;
        };
        let Some(pos) = plan.consumers[dep_idx].iter().position(|&c| c == step_idx) else {
            continue;
        };
        if pos >= branches.len() {
            continue;
        }
        let branch_id: u32 = branches[pos].into();
        let producer_id = action.steps[dep_idx].id.clone();
        overrides.insert(producer_id, branch_id);
    }
    store.data_mut().active_fanout_overrides = overrides;
}

/// Resolve a host function on the linker and invoke it via wasmtime's
/// async entry point. Every step type registered through
/// [`WasmRuntime::register_trait_step_type`] (and the kernel helpers in
/// [`super::host_api::register_kernel_services`]) is wrapped as async at
/// registration time, so the store is in async-required mode
/// and a sync `TypedFunc::call` would error. `call_async` routes through
/// `Store::on_fiber`, parking the wasm execution on a separate native
/// stack and allowing host fn bodies to await without blocking the
/// tokio worker thread.
async fn call_host_fn(
    linker: &Linker<ExecutionState>,
    store: &mut Store<ExecutionState>,
    import_name: &str,
    arg: i32,
) -> Result<i32, KernelError> {
    // `Linker::get` returns `Result`; a missing import maps to a clear
    // Runtime error.
    let extern_val = linker
        .get(&mut *store, crate::kernel::abi::ABI_MODULE, import_name)
        .map_err(|_| {
            KernelError::Runtime(format!("Host function '{import_name}' not registered"))
        })?;
    let func = extern_val.into_func().ok_or_else(|| {
        KernelError::Runtime(format!("'{import_name}' is registered but not a function"))
    })?;
    let typed = func
        .typed::<i32, i32>(&*store)
        .map_err(|e| KernelError::Runtime(format!("'{import_name}' has wrong signature: {e}")))?;
    typed
        .call_async(store, arg)
        .await
        .map_err(|e| KernelError::Execution(format!("Host fn '{import_name}' trapped: {e}")))
}

#[cfg(test)]
mod dispatch_trait_step_tests {
    //! Focused unit tests for [`dispatch_trait_step_core`] — the
    //! pure-`&mut ExecutionState` half of the wasmtime adapter. Every
    //! cross-cutting concern shared by step bodies (step lookup,
    //! `store_to_variable` mirroring, metadata sidecar routing,
    //! StepError mapping) lives there, and these tests pin its
    //! contract without depending on a real step type body.
    //!
    //! The tests exercise the adapter directly rather than through a
    //! full kernel invocation, so they catch a change to the
    //! writeback rules in isolation.
    use std::future::Future;
    use std::pin::Pin;

    use indexmap::IndexMap;
    use serde_json::{Value, json};

    use super::super::host_api::{
        ExecutionState, ExecutionStateParams, PluginErrorPayload, PluginExecution, StepError,
        StepOutput,
    };
    use super::super::types::{Action, PluginManifest, StepDef, StepTypeDef};
    use super::StepBody;
    use crate::kernel::exec_context::ExecutionContext;
    use crate::kernel::{Kernel, KernelConfig, RuntimeLimits};

    /// Build a minimal [`ExecutionState`] for adapter tests. The wasm
    /// engine and limits are real (cheap to construct) but
    /// no step type body that touches the network or storage runs in
    /// these tests, so nothing here depends on how such a body would behave.
    ///
    /// `kernel` is the weak handle dispatch uses to resolve a step type's
    /// `metadataSchema` allow-list. `None` (the common case) leaves
    /// metadata routing unconstrained; the metadata-enforcement tests pass
    /// a real handle from [`kernel_with_meta_probe`].
    fn fresh_state_with_kernel(
        step: StepDef,
        kernel: Option<std::sync::Weak<Kernel>>,
    ) -> ExecutionState {
        let mut action: Action = serde_json::from_value(json!({ "steps": [] })).unwrap();
        action.steps.push(step);

        // wasmtime supports async unconditionally
        // (`Config::async_support` is a deprecated no-op). We
        // enable fuel consumption to mirror production engine config.
        let engine = wasmtime::Engine::new(wasmtime::Config::new().consume_fuel(true)).unwrap();

        ExecutionState::new(ExecutionStateParams {
            plugin_name: "test_plugin".to_string(),
            step_type_access: Default::default(),
            action,
            input: Value::Null,
            config: Value::Null,
            secrets: Value::Null,
            secret_resolver: None,
            script_runtimes: std::sync::Arc::new(std::collections::HashMap::new()),
            engine,
            exec_ctx: ExecutionContext::default(),
            streams: None,
            invoke_depth: 0,
            dispatch_depth: 0,
            kernel,
            trigger: None,
            limits: RuntimeLimits::default(),
            cancel: None,
            dataflow_events: None,
        })
    }

    fn fresh_state(step: StepDef) -> ExecutionState {
        fresh_state_with_kernel(step, None)
    }

    fn step(id: &str) -> StepDef {
        serde_json::from_value(json!({ "id": id, "type": "noop" })).unwrap()
    }

    fn typed_step(id: &str, step_type: &str) -> StepDef {
        serde_json::from_value(json!({ "id": id, "type": step_type })).unwrap()
    }

    /// Boot a kernel registering a `meta_probe` step type whose
    /// `metadataSchema` allows exactly one key, `tokens_used` (closed).
    /// Returned as an owned `Arc` so the test holds it alive while a weak
    /// handle on the state resolves the def. Only the def is needed — no
    /// impl — because the test supplies the step body directly.
    fn kernel_with_meta_probe() -> std::sync::Arc<Kernel> {
        let def = StepTypeDef {
            name: "probe_plugin.meta_probe".to_string(),
            freely_usable: false,
            input_schema: None,
            output_schema: None,
            metadata_schema: Some(json!({
                "type": "object",
                "additionalProperties": false,
                "properties": { "tokens_used": { "type": "integer" } }
            })),
            selector: None,
            references: Vec::new(),
        };
        let manifest = PluginManifest {
            name: "probe_plugin".to_string(),
            step_type_defs: vec![def],
            ..PluginManifest::default()
        };
        let mut kernel = Kernel::boot(KernelConfig::default()).expect("kernel boots");
        kernel
            .register_plugin(manifest)
            .expect("probe plugin registers");
        kernel.into_arc()
    }

    /// Body that returns `Ok(StepOutput::from(value))` — the "happy
    /// path" all successful steps take.
    fn ok_body(value: Value) -> StepBody {
        // A fn pointer can't capture, so the value is threaded through
        // a thread_local the body reads back.
        thread_local! {
            static OK_VALUE: std::cell::RefCell<Value> = const { std::cell::RefCell::new(Value::Null) };
        }
        OK_VALUE.with(|cell| *cell.borrow_mut() = value);

        fn body<'a>(
            _ex: &'a mut (dyn PluginExecution + Send),
            _params: &'a Value,
        ) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
            Box::pin(async move {
                let v = OK_VALUE.with(|cell| cell.borrow().clone());
                Ok(StepOutput::from(v))
            })
        }
        StepBody::Plugin(body)
    }

    fn ok_with_metadata_body(value: Value, metadata: IndexMap<String, Value>) -> StepBody {
        thread_local! {
            static OK_VALUE: std::cell::RefCell<Value> = const { std::cell::RefCell::new(Value::Null) };
            static OK_META: std::cell::RefCell<IndexMap<String, Value>> = std::cell::RefCell::new(IndexMap::new());
        }
        OK_VALUE.with(|cell| *cell.borrow_mut() = value);
        OK_META.with(|cell| *cell.borrow_mut() = metadata);

        fn body<'a>(
            _ex: &'a mut (dyn PluginExecution + Send),
            _params: &'a Value,
        ) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
            Box::pin(async move {
                let v = OK_VALUE.with(|cell| cell.borrow().clone());
                let m = OK_META.with(|cell| cell.borrow().clone());
                Ok(StepOutput::with_metadata(v, m))
            })
        }
        StepBody::Plugin(body)
    }

    fn failed_body(msg: &'static str) -> StepBody {
        thread_local! {
            static MSG: std::cell::RefCell<&'static str> = const { std::cell::RefCell::new("") };
        }
        MSG.with(|cell| *cell.borrow_mut() = msg);

        fn body<'a>(
            _ex: &'a mut (dyn PluginExecution + Send),
            _params: &'a Value,
        ) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
            Box::pin(async move {
                let m = MSG.with(|cell| *cell.borrow());
                Err(StepError::Failed(m.to_string()))
            })
        }
        StepBody::Plugin(body)
    }

    fn thrown_body(code: &'static str, message: &'static str) -> StepBody {
        thread_local! {
            static CODE: std::cell::RefCell<&'static str> = const { std::cell::RefCell::new("") };
            static MESSAGE: std::cell::RefCell<&'static str> = const { std::cell::RefCell::new("") };
        }
        CODE.with(|cell| *cell.borrow_mut() = code);
        MESSAGE.with(|cell| *cell.borrow_mut() = message);

        fn body<'a>(
            _ex: &'a mut (dyn PluginExecution + Send),
            _params: &'a Value,
        ) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
            Box::pin(async move {
                let c = CODE.with(|cell| *cell.borrow());
                let m = MESSAGE.with(|cell| *cell.borrow());
                Err(StepError::Thrown(PluginErrorPayload {
                    code: c.to_string(),
                    message: m.to_string(),
                    params: Value::Null,
                }))
            })
        }
        StepBody::Plugin(body)
    }

    #[tokio::test]
    async fn ok_stores_value_and_returns_1() {
        let mut state = fresh_state(step("s0"));
        let rc = super::dispatch_trait_step_core(&mut state, 0, ok_body(json!({"hello": "world"})))
            .await;
        assert_eq!(rc, 1);
        assert_eq!(
            state.step_results.get("s0").cloned(),
            Some(json!({"hello": "world"}))
        );
        // No metadata → no sidecars.
        assert!(state.step_metadata.is_empty());
        // No throw → no plugin_error, no last_error.
        assert!(state.plugin_error.is_none());
        assert!(state.last_error.is_none());
    }

    #[tokio::test]
    async fn failed_sets_last_error_and_returns_0() {
        // Every failure propagates; manifest authors wrap with `try`
        // for swallow semantics.
        let mut state = fresh_state(step("s0"));
        let rc = super::dispatch_trait_step_core(&mut state, 0, failed_body("io error")).await;
        assert_eq!(rc, 0);
        assert_eq!(state.last_error.as_deref(), Some("io error"));
        assert!(state.step_results.get("s0").is_none());
        assert!(state.plugin_error.is_none());
    }

    #[tokio::test]
    async fn thrown_sets_plugin_error_and_last_error() {
        let mut state = fresh_state(step("s0"));
        let rc = super::dispatch_trait_step_core(&mut state, 0, thrown_body("E_BAD", "nope")).await;
        assert_eq!(rc, 0);
        let pe = state.plugin_error.as_ref().expect("plugin_error set");
        assert_eq!(pe.code, "E_BAD");
        assert_eq!(pe.message, "nope");
        // last_error is also populated so a `try.catch` handler reads
        // the formatted message via `{{$.error}}`.
        assert_eq!(state.last_error.as_deref(), Some("PluginError E_BAD: nope"));
        // step_results stays empty — no fake-success null stored.
        assert!(state.step_results.get("s0").is_none());
    }

    #[tokio::test]
    async fn metadata_routes_generically_into_step_metadata() {
        // With no kernel handle the allow-list is unconstrained, so every
        // emitted key — status, headers, and an arbitrary custom one —
        // lands flat in `step_metadata[step_id]`. Routing keeps the
        // raw `Value` (a number for status, an object for headers), no
        // typed down/up-conversion.
        let mut state = fresh_state(step("s0"));
        let mut meta = IndexMap::new();
        meta.insert("status".to_string(), json!(204));
        meta.insert(
            "headers".to_string(),
            json!({ "content-type": "application/json", "etag": "abc" }),
        );
        meta.insert("custom_sidecar".to_string(), json!({"nested": true}));
        let rc = super::dispatch_trait_step_core(
            &mut state,
            0,
            ok_with_metadata_body(json!({"ok": true}), meta),
        )
        .await;
        assert_eq!(rc, 1);
        let sidecars = state.step_metadata.get("s0").expect("sidecars stored");
        assert_eq!(sidecars.get("status"), Some(&json!(204)));
        assert_eq!(
            sidecars.get("headers"),
            Some(&json!({ "content-type": "application/json", "etag": "abc" }))
        );
        assert_eq!(
            sidecars.get("custom_sidecar"),
            Some(&json!({"nested": true}))
        );
    }

    #[tokio::test]
    async fn declared_metadata_key_surfaces_flat() {
        // A step type whose metadataSchema declares `tokens_used` may emit
        // it; it lands in step_metadata and resolves flat as
        // `{{$steps.<id>.tokens_used}}`.
        let arc = kernel_with_meta_probe();
        let mut state = fresh_state_with_kernel(
            typed_step("s0", "probe_plugin.meta_probe"),
            Some(std::sync::Arc::downgrade(&arc)),
        );
        // The metadata allow-list is looked up by the step type's
        // RESOLVED key, which the kernel decides at invocation setup.
        state.step_type_access = arc.step_type_access_for("probe_plugin");
        let mut meta = IndexMap::new();
        meta.insert("tokens_used".to_string(), json!(42));
        let rc = super::dispatch_trait_step_core(
            &mut state,
            0,
            ok_with_metadata_body(json!("payload"), meta),
        )
        .await;
        assert_eq!(rc, 1);
        assert_eq!(
            state
                .step_metadata
                .get("s0")
                .and_then(|m| m.get("tokens_used")),
            Some(&json!(42))
        );
        // Surfaces flat under the step id in the resolution context.
        let ctx = state.resolution_context();
        assert_eq!(
            ctx.pointer("/steps/s0/tokens_used"),
            Some(&json!(42)),
            "declared sidecar resolves as steps.s0.tokens_used"
        );
        assert_eq!(ctx.pointer("/steps/s0/result"), Some(&json!("payload")));
    }

    #[tokio::test]
    async fn undeclared_metadata_key_fails_step() {
        // The metadataSchema is closed (additionalProperties:false), so a
        // key it doesn't declare fails the step rather than being silently
        // dropped.
        let arc = kernel_with_meta_probe();
        let mut state = fresh_state_with_kernel(
            typed_step("s0", "probe_plugin.meta_probe"),
            Some(std::sync::Arc::downgrade(&arc)),
        );
        // The metadata allow-list is looked up by the step type's
        // RESOLVED key, which the kernel decides at invocation setup.
        state.step_type_access = arc.step_type_access_for("probe_plugin");
        let mut meta = IndexMap::new();
        meta.insert("surprise".to_string(), json!("xyz"));
        let rc = super::dispatch_trait_step_core(
            &mut state,
            0,
            ok_with_metadata_body(json!("payload"), meta),
        )
        .await;
        assert_eq!(rc, 0, "undeclared metadata key fails the step");
        let err = state.last_error.as_deref().expect("last_error set");
        assert!(
            err.contains("undeclared metadata key 'surprise'"),
            "error names the offending key: {err}"
        );
        // Nothing routed — the whole emission is rejected.
        assert!(state.step_metadata.get("s0").is_none());
    }

    #[tokio::test]
    async fn store_to_variable_mirrors_step_result() {
        let mut s = step("s0");
        s.store_to_variable = Some("myvar".to_string());
        let mut state = fresh_state(s);
        let rc = super::dispatch_trait_step_core(&mut state, 0, ok_body(json!({"k": "v"}))).await;
        assert_eq!(rc, 1);
        assert_eq!(
            state.variables.get("myvar").cloned(),
            Some(json!({"k": "v"}))
        );
    }

    #[tokio::test]
    async fn out_of_bounds_step_index_sets_last_error() {
        let mut state = fresh_state(step("s0"));
        let rc =
            super::dispatch_trait_step_core(&mut state, 99, ok_body(json!("never runs"))).await;
        assert_eq!(rc, 0);
        assert!(
            state
                .last_error
                .as_deref()
                .is_some_and(|m| m.contains("out of bounds"))
        );
    }

    #[tokio::test]
    async fn current_step_idx_cleared_after_dispatch() {
        let mut state = fresh_state(step("s0"));
        assert!(state.current_step_idx.is_none());
        let _ = super::dispatch_trait_step_core(&mut state, 0, ok_body(Value::Null)).await;
        assert!(
            state.current_step_idx.is_none(),
            "cursor must clear so kernel-service helpers see None"
        );
    }

    // ── `$vars` root in structural positions ─────────────────────────────
    //
    // `$vars` must resolve in structural positions — `ifs[].test`,
    // `for_each.path`, `collect`, `until` — not only in `{{ }}`
    // templates. Those positions build their `EvalContext` via
    // `eval_path` / `eval_dsl_expression`; these tests pin that both
    // expose `$vars`, which is the bridge that lets an `ifs` branch hand
    // a list to an outer `for_each`. (Template-side `$vars` is covered
    // in `domain::resolve`.)

    /// `eval_path` powers `for_each.path` (`host_begin_foreach`).
    #[test]
    fn eval_path_resolves_vars_root() {
        let mut state = fresh_state(step("s0"));
        state.set_variable("paths".to_string(), json!(["a.jpg", "b.jpg"]));
        assert_eq!(
            state.eval_path("$vars.paths", None),
            json!(["a.jpg", "b.jpg"]),
            "for_each.path must reach a variable via $vars"
        );
    }

    /// `eval_dsl_expression` powers `ifs` tests and `collect`/`until`.
    #[test]
    fn eval_dsl_expression_resolves_vars_root() {
        let mut state = fresh_state(step("s0"));
        state.set_variable("flag".to_string(), json!("ready"));
        assert_eq!(
            super::eval_dsl_expression(&state, "$vars.flag", "test").unwrap(),
            json!("ready"),
            "ifs / collect / until must reach a variable via $vars"
        );
    }
}
