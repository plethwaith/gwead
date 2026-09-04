//! Host API — the kernel's host-function surface.
//!
//! Host functions are the kernel's ABI surface: the runtime dispatches
//! every step body through one, and guest modules (the interpreter
//! behind a `script` step, the module behind a `wasm` step) import the
//! stream and kernel-service functions. All data handling (template
//! resolution, JSON extraction, variable binding) lives here in the
//! host.
//!
//! The host state (`ExecutionState`) lives in wasmtime's `Store<T>` and is
//! accessible from every host function. Each action invocation gets its own
//! `ExecutionState` — there is no shared mutable state between invocations.
//!
//! Host functions receive step indices (i32) as parameters. They look up the
//! step definition and its parameters from the host state, execute the step
//! type logic, and store the result back in the host state.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use indexmap::IndexMap;
use serde_json::Value;
use wasmtime::{Engine, Linker};

use super::KernelError;
use super::exec_context::ExecutionContext;
use super::native_impls::IntrinsicStepImplEntry;
use super::types::{Action, ActionResult};
use crate::domain::resolve;
use crate::dsl::{self, EvalContext};

// ---------------------------------------------------------------------------
// Host state
// ---------------------------------------------------------------------------

/// Per-invocation state accessible from host functions via `Store<ExecutionState>`.
///
/// `Clone` is implemented so the runtime can fork one ExecutionState per step in a
/// parallel wave. Heavy shared fields (`engine`,
/// `script_runtimes`, `streams`, `kernel`, `trigger`) clone
/// via internal `Arc` reference bumps; per-task scratch fields
/// (`step_results`, `variables`, `last_error`, …) are deep-copied so each
/// task observes an isolated view that the parent merges back at join.
#[derive(Clone)]
pub(crate) struct ExecutionState {
    /// Name of the plugin whose action is currently executing. Set by
    /// the runtime when it builds ExecutionState for an invocation. Host
    /// step functions look up this plugin's permission set in the
    /// kernel registry before they touch an external surface.
    pub(crate) plugin_name: String,
    /// The action being executed (owns the step definitions).
    pub(crate) action: Action,
    /// The action's input value.
    pub(crate) input: Value,
    /// The config namespace the action sees as `{{$config.*}}`.
    pub(crate) config: Value,
    /// Plugin secrets (`{{$secrets.<name>}}`). Kept in a separate namespace
    /// from `config` so they can be redacted in audit logs, encrypted at
    /// rest, and never accidentally leak through the config surface.
    pub(crate) secrets: Value,
    /// Variable bindings (`{{$vars.<name>}}`).
    pub(crate) variables: IndexMap<String, Value>,
    /// Per-step results (`{{$steps.<id>.result}}`).
    pub(crate) step_results: IndexMap<String, Value>,
    /// Per-step sidecar metadata, keyed by step id then metadata
    /// key. Populated generically from [`StepOutput::metadata`] by
    /// [`super::runtime::dispatch_trait_step_core`] — the kernel routes
    /// every key here without knowing what it means. Surfaces flat as
    /// `{{$steps.<id>.<key>}}` via [`Self::resolution_context`] /
    /// [`Self::build_dsl_steps_view`], so `http_call`'s `status` (a
    /// number) and `headers` (an object) resolve as `{{$steps.<id>.status}}`
    /// / `{{$steps.<id>.headers.<name>}}`. The producing step type's `metadataSchema`
    /// (on its [`super::types::StepTypeDef`]) is the allow-list of permitted
    /// keys — see [`Self::declared_metadata_keys`]; dispatch fails a step
    /// that emits anything outside it.
    pub(crate) step_metadata: IndexMap<String, IndexMap<String, Value>>,
    /// ID of the first step (for default source resolution).
    pub(crate) first_step_id: Option<String>,
    /// Script-runtime wasm modules resolved from the registry at
    /// invocation time. Keyed by selector value (`language` for
    /// the `script` step type), so `step_script` does an O(1) lookup
    /// per invocation without needing a kernel weak ref. The map is
    /// snapshotted at ExecutionState construction; later registry
    /// changes don't affect in-flight invocations — matching the
    /// freeze-at-invocation semantics for every other resolved input
    /// the parent action carries.
    pub(crate) script_runtimes: std::sync::Arc<HashMap<String, std::sync::Arc<wasmtime::Module>>>,
    /// wasmtime engine reference (needed to instantiate sub-modules).
    pub(crate) engine: Engine,
    /// Opaque execution context. Carried through every dispatch
    /// site without the kernel introspecting it — embedders own the
    /// schema. Not merged into `resolution_context()` so plugin
    /// templates can't reach it via `{{context.*}}`.
    pub(crate) exec_ctx: ExecutionContext,
    /// Last error message (set by failed steps).
    pub(crate) last_error: Option<String>,
    /// Set when a wasm sub-instance (the interpreter behind a `script`
    /// step, or a `wasm` step's module) hits a resource cap. The runtime checks this after a failing
    /// step to map into the appropriate
    /// [`super::KernelError::FuelExhausted`] /
    /// [`super::KernelError::MemoryLimitExceeded`] variant rather
    /// than the generic `Execution(string)`.
    pub(crate) resource_violation: Option<ResourceViolation>,
    /// Running total of [`Self::step_results`] in approximate host
    /// bytes, maintained by [`Self::store_step_result`] so the budget
    /// check is O(new value) rather than O(everything stored) per step.
    pub(crate) step_results_bytes: usize,
    /// Set when a step explicitly threw a structured error via
    /// `throw_error`. The runtime maps this onto
    /// [`super::KernelError::PluginError`] in preference to the
    /// generic `Execution(string)` so embedder callers can
    /// branch on the code field.
    pub(crate) plugin_error: Option<PluginErrorPayload>,
    /// Set when the step stopped on the invocation's cancellation token
    /// ([`StepError::Cancelled`]). Read by `step_failure_to_error`
    /// ahead of every marker but a resource violation: a cancelled step
    /// is not a failed one, and `try` does not catch it.
    pub(crate) cancelled: bool,
    /// Set when a nested invocation the step made failed
    /// ([`StepError::Callee`]): the callee's own error, intact, for
    /// [`super::KernelError::CalleeFailed`].
    pub(crate) callee_error: Option<CalleeError>,
    /// forEach iteration state stack (for nested forEach).
    pub(crate) foreach_stack: Vec<ForEachState>,
    /// Active error-handler payloads. Pushed by the runtime before
    /// dispatching a `try` step's `catch` body, popped when the body
    /// finishes — nested so a try-inside-try handler can still read
    /// its own `{{$.error}}` without losing the outer one. The top of
    /// the stack feeds the `{{$.error}}` binding in
    /// [`Self::resolution_context`].
    pub(crate) error_stack: Vec<String>,
    /// Byte-stream registry for this invocation. Opaque handles owned
    /// by the host; plugins call `stream_read` / `stream_write` /
    /// `stream_close` against them. See `kernel/streams.rs`.
    ///
    /// Wrapped in `Arc<Mutex<…>>` so the tasks a parallel wave or the
    /// dataflow scheduler forks from one execution all share that
    /// execution's table. A nested `invoke` does **not** inherit it —
    /// the callee gets a table of its own, and a stream crosses only by
    /// an explicit [`StreamRegistry::take`](super::streams::StreamRegistry::take)
    /// / [`adopt`](super::streams::StreamRegistry::adopt) move (see
    /// `Kernel::execute_action_invoked`). The registry-wide lock is held
    /// only for handle lookup; per-stream state has its own lock (see
    /// `streams::StreamState`), so parallel-wave tasks don't contend.
    pub(crate) streams: super::streams::SharedStreamRegistry,
    /// Recursion depth for `invoke` chains. Incremented before
    /// dispatching the child action and checked against
    /// [`super::INVOKE_MAX_DEPTH`] to catch by-role cycles that the
    /// structural registration-time check can't see.
    pub(crate) invoke_depth: u32,
    /// Event-dispatch cascade depth. Independent of `invoke_depth`
    /// because the two track different recursion shapes. Checked by
    /// [`super::Kernel::dispatch_event`] against the cascade cap so a
    /// plugin-A → event → plugin-B → event → plugin-A chain terminates.
    pub(crate) dispatch_depth: u32,
    /// Weak handle back to the kernel that owns this invocation, used
    /// only by the `invoke` step type. `None` when the kernel was
    /// constructed without [`super::Kernel::into_arc`] — code that
    /// never calls `invoke` keeps working.
    pub(crate) kernel: Option<std::sync::Weak<super::Kernel>>,
    /// Per-invocation resource limits. Plumbed through so
    /// `step_script` can apply fuel + memory caps to the interpreter
    /// sub-instance it spawns. The action-level wallclock timeout
    /// uses this too, but is enforced by the kernel around the
    /// `execute_dag` await rather than from inside host fns.
    pub(crate) limits: super::RuntimeLimits,
    /// Triggering event payload — `Some` only for invocations
    /// dispatched by [`super::Kernel::dispatch_event`]. Exposed to
    /// step DSL as `$trigger` / `{{$trigger.*}}`. `Arc` so the
    /// dispatcher can fan one payload out to many subscribers
    /// without per-subscriber deep clones.
    pub(crate) trigger: Option<std::sync::Arc<Value>>,
    /// Fan-out branch overrides for the currently-executing step.
    /// Maps producer step id → branch stream handle. Populated by the
    /// runtime immediately before dispatching a step whose dependencies
    /// include a stream-producing producer with multiple consumers; the
    /// override redirects `$steps.<producer>.result` / `{{$steps.<producer>.result}}`
    /// references to the consumer's private branch handle without
    /// mutating the shared `step_results` slot.
    ///
    /// **Why a per-step override map, not a `step_results` rewrite.**
    /// Overwriting `step_results[<producer>]` with each consumer's
    /// branch handle before dispatch would race the instant two
    /// consumers in the same DAG wave run concurrently — both would
    /// observe the same overwritten handle (or a torn write). Keeping
    /// the producer's original handle in `step_results` and expressing
    /// branch selection as a *per-consumer overlay* avoids the race;
    /// parallel-wave execution relies on per-task overrides without
    /// touching the slot semantics.
    pub(crate) active_fanout_overrides: HashMap<String, u32>,
    /// Cancellation surface for long-running step types.
    /// Always present so step bodies can race their work against
    /// `state.cancel.cancelled()` without `Option` gymnastics; on
    /// invocations that have no external cancel signal (the common
    /// case — every single-shot `execute_action` call), the kernel
    /// allocates a fresh never-cancelled token. Cloning is cheap (an
    /// `Arc` bump) so the parallel-wave + dataflow paths that fork
    /// `ExecutionState` per spawned task carry the same logical token into
    /// every task.
    pub(crate) cancel: tokio_util::sync::CancellationToken,
    /// The end of this invocation's wallclock budget, if it has one.
    /// `None` is an uncapped invocation. See
    /// [`super::runtime::InvocationContext::deadline`].
    pub(crate) deadline: Option<tokio::time::Instant>,
    /// Pre-provisioned writable output stream handles for long-running
    /// producer steps in a streaming-dataflow action.
    ///
    /// Mapped by producer step id → writable `StreamId`. Populated
    /// once, before the dataflow scheduler spawns step tasks; long-
    /// running step bodies look up their slot here to discover where
    /// to push chunks. Empty for non-dataflow actions. The shared
    /// `Arc` lets every forked task observe the same map without
    /// merging it back at join.
    pub(crate) dataflow_outputs: std::sync::Arc<HashMap<String, super::streams::StreamId>>,
    /// Telemetry sidechannel for the streaming-dataflow scheduler.
    /// `Some(sender)` when the action was started via
    /// [`ExecuteActionRequest::into_dataflow_handle`](super::execute_request::ExecuteActionRequest::into_dataflow_handle); `None`
    /// otherwise — including in the wave-scheduled path where event
    /// emission is undefined.
    ///
    /// Step bodies push progress events via
    /// [`Self::emit_progress`]; the scheduler itself emits
    /// step-lifecycle events. Bounded channel, `try_send` on full
    /// drops the event rather than blocking the emitter, so progress
    /// emission is always a constant-time no-await op safe to call
    /// from inside a hot loop.
    pub(crate) dataflow_events: Option<tokio::sync::mpsc::Sender<super::DataflowEvent>>,
    /// Index of the step the runtime adapter is currently dispatching.
    /// Set by the trait-based dispatch wrapper before each step body
    /// runs; consulted by `PluginExecution::current_step_id`. `None` outside
    /// step dispatch (kernel-service helpers, default-constructed state).
    pub(crate) current_step_idx: Option<usize>,
    /// Early-exit signal carried by the `return` intrinsic step type.
    /// `Some(value)` is set by `run_return` when a
    /// step of type `"return"` executes; every wave-loop and inner-
    /// block loop in the runtime polls this after each `run_step` call
    /// and exits cleanly when set. The captured `Value` becomes the
    /// action's output, overriding the normal `collect_output` flow.
    /// `None` outside an active return.
    pub(crate) return_signal: Option<Value>,
    /// Which step types this execution may run. Resolved by the kernel
    /// at invocation setup; consulted by `runtime::run_step` on the
    /// direct dispatch path. See [`StepTypeAccess`].
    pub(crate) step_type_access: StepTypeAccess,
    /// The secrets view a *foreign* step body sees through
    /// [`PluginExecution::secrets`] while it runs — the body owner's
    /// bag, set by the dispatcher around the call and cleared after.
    /// `None` outside such a body, when `secrets()` is the execution's
    /// own. Deliberately separate from `secrets` so that
    /// [`ExecutionState::resolution_context`] keeps resolving the
    /// caller's params against the caller's bag: `"key":
    /// "{{$secrets.privateKey}}"` is deliberate delegation and must keep
    /// working; the ambient handle is what must not leak.
    pub(crate) body_secrets: Option<Value>,
    /// The resolver this invocation tree pulls credentials through.
    /// See [`super::runtime::InvocationContext::secret_resolver`].
    pub(crate) secret_resolver: Option<std::sync::Arc<dyn super::secrets::SecretResolver>>,
}

/// Which step types one invocation is allowed to run.
///
/// # Why this is precomputed rather than checked against the registry
///
/// The obvious implementation asks the kernel at each step. It cannot:
/// `Kernel::execute(..).run()` is documented to work on a kernel that was
/// never wrapped via [`Kernel::into_arc`](super::Kernel::into_arc), and
/// such an execution holds no back-reference to consult. Requiring an
/// `Arc` would have made a security gate break a documented affordance
/// for every action using a native step type — pushing the cost onto
/// embedders to save the kernel a little plumbing.
///
/// So the *decision* is resolved once, by the kernel, while it still has
/// itself in hand, and travels with the invocation. Checking is then a
/// set lookup that cannot fail for want of a reference — which also
/// means there is no "no kernel available" branch for a future caller to
/// get wrong.
///
/// Reserved intrinsics are not in the set; they are answered before it
/// is consulted (see [`RESERVED_STEP_TYPE_NAMES`]).
///
/// [`Default`] is **deny everything non-reserved**, so a construction
/// site that forgets to populate it fails closed and shows up as a
/// denied step rather than an open door.
#[derive(Debug, Clone, Default)]
pub struct StepTypeAccess {
    /// Written step type name → the registry key it resolves to for
    /// this invocation. A plugin-defined name (`vault.sign`) resolves
    /// its owner segment along the executing plugin's ancestor chain,
    /// nearest first, so a tenant's own `vault` shadows the global one
    /// for that tenant's steps — resolution is by the *executing*
    /// plugin, decided once here and carried. Kernel names map to
    /// themselves. Absence means "not allowed".
    allowed: std::sync::Arc<std::collections::HashMap<String, String>>,
    /// For each allowed step type whose body another plugin ships:
    /// who, and what secrets that plugin declared. Keyed by the
    /// *written* name. See [`BodyOwner`].
    body_owners: std::sync::Arc<std::collections::HashMap<String, BodyOwner>>,
}

/// The plugin that ships a step type's body, as the step dispatcher
/// needs it to pull the body's own view of secrets.
///
/// A native or plugin-defined step body runs *inside the calling
/// plugin's execution* but is code the owner wrote. `ex.secrets()` in
/// that body must be the owner's bag, not the caller's — otherwise a
/// single granted `step_type:` would hand the body the caller's entire
/// credential bundle, which the body could simply return as its step
/// result. Resolved at invocation setup with the allow set, for the
/// same reason: the decision must not depend on a kernel
/// back-reference existing at step time.
#[derive(Debug, Clone)]
pub(crate) struct BodyOwner {
    pub(crate) identity: String,
    pub(crate) declared_keys: Vec<String>,
    pub(crate) overridable_keys: Vec<String>,
}

impl StepTypeAccess {
    pub(crate) fn new(
        allowed: std::collections::HashMap<String, String>,
        body_owners: std::collections::HashMap<String, BodyOwner>,
    ) -> Self {
        Self {
            allowed: std::sync::Arc::new(allowed),
            body_owners: std::sync::Arc::new(body_owners),
        }
    }

    /// The registry key a written step type name resolves to for this
    /// invocation, if it may be used at all. Reserved intrinsics
    /// resolve to themselves.
    pub(crate) fn resolve<'a>(&'a self, step_type: &'a str) -> Option<&'a str> {
        if let Some(reserved) = RESERVED_STEP_TYPE_NAMES.iter().find(|r| **r == step_type) {
            return Some(reserved);
        }
        self.allowed.get(step_type).map(String::as_str)
    }

    /// The foreign owner of `step_type`'s body, if it is not the
    /// executing plugin's own. `None` for the plugin's own step types,
    /// for kernel intrinsics (`script` hosts the caller's code and
    /// `wasm` runs the caller's own module — both correctly see the
    /// execution's view), and for aliases (which dispatch into the
    /// owner's *action*, which pulls its own secrets on entry).
    pub(crate) fn body_owner(&self, step_type: &str) -> Option<&BodyOwner> {
        self.body_owners.get(step_type)
    }
}

/// Captured trap kind for a sub-instance that exceeded its
/// [`super::RuntimeLimits`] cap.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ResourceViolation {
    FuelExhausted {
        budget: u64,
    },
    MemoryLimit {
        bytes: usize,
    },
    /// Cumulative step-result bytes exceeded
    /// [`RuntimeLimits::max_step_results_bytes`](super::RuntimeLimits::max_step_results_bytes),
    /// recorded when a step's result is refused rather than stored.
    StepResultsLimit {
        limit_bytes: usize,
        attempted_bytes: usize,
    },
}

/// Approximate the host bytes a step result holds.
///
/// Approximate on purpose: the exact figure would need to walk every
/// `serde_json` allocation header, and the budget exists to stop a
/// doubling chain, not to bill anyone. Strings and keys are counted at
/// their real length; containers carry a small per-element charge so a
/// deeply nested structure of empty arrays cannot look free.
pub(super) fn approx_value_bytes(value: &Value) -> usize {
    /// Rough per-node overhead — a `Value` discriminant plus whatever
    /// the container spends tracking one element.
    const NODE_OVERHEAD: usize = 16;
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => NODE_OVERHEAD,
        Value::String(s) => NODE_OVERHEAD + s.len(),
        Value::Array(items) => NODE_OVERHEAD + items.iter().map(approx_value_bytes).sum::<usize>(),
        Value::Object(fields) => {
            NODE_OVERHEAD
                + fields
                    .iter()
                    .map(|(k, v)| NODE_OVERHEAD + k.len() + approx_value_bytes(v))
                    .sum::<usize>()
        }
    }
}

/// Payload from a `throw_error` step. The runtime promotes this
/// to a [`super::KernelError::PluginError`] when it surfaces.
#[derive(Debug, Clone)]
pub struct PluginErrorPayload {
    pub code: String,
    pub message: String,
    pub params: Value,
}

/// A failed nested invocation, held on the execution state between the
/// step that made it and the scheduler's error mapping.
#[derive(Debug, Clone)]
pub(crate) struct CalleeError {
    pub plugin: String,
    pub action: String,
    pub source: std::sync::Arc<super::KernelError>,
}

/// Where a loop's items come from.
///
/// `for_each` iterates a list that already exists. `repeat` iterates a
/// *count*, and a counted loop needs an index, not a vector:
/// materialising `(0..count)` as a `Vec<Value>` would let a one-line
/// manifest ask for billions of values in one synchronous allocation —
/// uncharged by `max_step_results_bytes` (which bills step *results*,
/// not scratch state), unpreemptable by the wallclock watchdog (a
/// synchronous allocation never yields), and reachable from `$input`,
/// since `count` is template-resolved.
///
/// `Count` stores the bound and produces item *i* on demand, so a
/// huge count costs eight bytes and fails on time rather than on
/// memory.
#[derive(Debug, Clone)]
pub enum ForEachItems {
    /// `for_each` — a list the manifest supplied.
    Values(Vec<Value>),
    /// `repeat` — item *i* is the integer *i*, never materialised.
    Count(u64),
}

impl ForEachItems {
    pub fn len(&self) -> usize {
        match self {
            Self::Values(v) => v.len(),
            // Callers cap `count` well below `i32::MAX` before
            // constructing this, so the cast cannot truncate.
            Self::Count(n) => *n as usize,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The item at `idx`, or `None` past the end. Owned: a counted range
    /// has nothing to borrow.
    pub fn item_at(&self, idx: usize) -> Option<Value> {
        match self {
            Self::Values(v) => v.get(idx).cloned(),
            Self::Count(n) if (idx as u64) < *n => Some(Value::from(idx)),
            Self::Count(_) => None,
        }
    }
}

/// State for an active forEach iteration.
#[derive(Clone)]
pub struct ForEachState {
    /// Where the items come from. See [`ForEachItems`].
    pub items: ForEachItems,
    /// The item at [`Self::current`], materialised by `next_foreach`.
    ///
    /// Held rather than recomputed because the three readers all want a
    /// `&Value` for the resolution context, and a counted range has no
    /// stored value to borrow.
    pub current_value: Option<Value>,
    /// Position of the *next* item to consume. `next_foreach` reads
    /// this, then advances. Use [`Self::current`] for the index of
    /// the item the body is currently working on.
    pub index: usize,
    /// Index of the item the inner step body is currently processing,
    /// or `None` before the first / after the last iteration. Set by
    /// `next_foreach` immediately before it advances `index`. The
    /// resolution context reads `items[current]` to bind `{{$item}}`,
    /// which is why the two indices are tracked separately — using
    /// `index` directly would expose the *next* item to inner steps,
    /// or `None` once iteration finishes.
    pub current: Option<usize>,
    /// The loop step's own result, stored by `end_foreach`. Nothing
    /// pushes to it, so a loop without `collect` ends with an empty
    /// array; `collect` overwrites the slot after the loop.
    pub results: Vec<Value>,
}

/// Parameters for constructing an `ExecutionState`.
pub struct ExecutionStateParams {
    pub(crate) plugin_name: String,
    pub action: Action,
    pub input: Value,
    pub config: Value,
    pub secrets: Value,
    /// Script-runtime wasm modules resolved from the registry, keyed
    /// by selector value (e.g. `"lua"` for `language: "lua"`). Builders
    /// get this via `Kernel::script_runtimes`.
    pub script_runtimes: std::sync::Arc<HashMap<String, std::sync::Arc<wasmtime::Module>>>,
    pub engine: Engine,
    pub exec_ctx: ExecutionContext,
    /// Stream registry. `None` makes the runtime allocate a fresh one —
    /// the top-level default, and what every nested `invoke` callee
    /// gets. `Some(table)` is for a caller that owns the table the
    /// action must run against: an embedder seeding a request body
    /// through `ExecuteActionRequest::with_streams`, or the
    /// `io.invoke_streaming` path handing a callee the one writable it
    /// is meant to produce into.
    pub streams: Option<super::streams::SharedStreamRegistry>,
    /// Initial recursion depth — 0 for top-level, parent+1 for an
    /// `invoke`-dispatched child.
    pub invoke_depth: u32,
    /// Initial event-dispatch cascade depth — 0 for top-level, parent+1
    /// for an event-dispatched action.
    pub dispatch_depth: u32,
    /// Weak back-ref to the owning kernel. Populated when a kernel
    /// wrapped via [`super::Kernel::into_arc`] dispatches an action;
    /// otherwise `None`.
    pub kernel: Option<std::sync::Weak<super::Kernel>>,
    /// Triggering event payload for an event-dispatched action.
    pub trigger: Option<std::sync::Arc<Value>>,
    /// Per-invocation resource limits.
    pub limits: super::RuntimeLimits,
    /// Cancellation token for long-running step types.
    /// `None` means "no external cancel signal" — the kernel allocates
    /// a fresh never-cancelled token so the field on `ExecutionState` is
    /// always populated. Pass `Some(token)` to expose cancellation to
    /// step bodies inside a dataflow pipeline.
    pub cancel: Option<tokio_util::sync::CancellationToken>,
    /// The end of the invocation's wallclock budget; `None` when it
    /// runs uncapped. See [`super::runtime::InvocationContext::deadline`].
    pub deadline: Option<tokio::time::Instant>,
    /// Telemetry sidechannel sender. `Some` only on
    /// invocations dispatched through
    /// [`ExecuteActionRequest::into_dataflow_handle`](super::execute_request::ExecuteActionRequest::into_dataflow_handle).
    pub dataflow_events: Option<tokio::sync::mpsc::Sender<super::DataflowEvent>>,
    /// Step types this invocation may run — see [`StepTypeAccess`].
    pub step_type_access: StepTypeAccess,
    /// Resolver the invocation tree pulls credentials through — see
    /// [`super::runtime::InvocationContext::secret_resolver`].
    pub secret_resolver: Option<std::sync::Arc<dyn super::secrets::SecretResolver>>,
}

// ---------------------------------------------------------------------------
// Step output / error — return shape for the trait-based step type API
// ---------------------------------------------------------------------------

/// What a step type's body returns. `value` becomes
/// `{{$steps.<id>.result}}`; `metadata` entries become
/// `{{$steps.<id>.<key>}}` sidecars (HTTP `status` / `headers`, etc.).
///
/// The kernel automatically stores the output under the current
/// step's id — step types never call a `store_step_result` API and
/// cannot overwrite each others' slots.
///
/// `StepOutput` is `pub`: it is the return shape of the trait-based
/// step type signature — `async fn(&mut dyn PluginExecution, &Value)
/// -> Result<StepOutput, StepError>` — produced by kernel intrinsics
/// and external step type authors alike.
#[derive(Debug, Clone, Default)]
pub struct StepOutput {
    /// Main payload. Resolved as `{{$steps.<id>.result}}` by downstream
    /// steps and as `$steps.<id>.result` by DSL paths.
    pub value: Value,
    /// Sidecar metadata. Each entry surfaces as `{{$steps.<id>.<key>}}`
    /// — e.g. `status: 200` for HTTP step types, `headers: {…}`. Empty
    /// for the common case; `From<Value>` constructs it that way.
    pub metadata: IndexMap<String, Value>,
}

impl From<Value> for StepOutput {
    fn from(value: Value) -> Self {
        Self {
            value,
            metadata: IndexMap::new(),
        }
    }
}

impl StepOutput {
    /// Build an output with sidecar metadata in one call. Convenient for
    /// step types whose return shape is always payload + a fixed set of
    /// sidecars (HTTP, blob storage).
    pub fn with_metadata(value: Value, metadata: IndexMap<String, Value>) -> Self {
        Self { value, metadata }
    }
}

/// What a step type's body returns on failure. Carried by
/// `Err(StepError)` from the trait-based step type fn.
///
/// `Failed(msg)` is the catch-all "step couldn't complete" path that
/// surfaces as [`super::KernelError::Execution`]. `Thrown(payload)`
/// is the `throw_error` step: a deliberate structured failure
/// the engine promotes to [`super::KernelError::PluginError`] so
/// callers can branch on `code`/`message`/`params`. `Cancelled` is a
/// step that observed the invocation's cancellation token and stopped;
/// it is not a failure, and `try` does not catch it. `Callee` is a
/// nested invocation that failed, with the callee's error intact.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum StepError {
    /// Generic execution failure. Surfaces as
    /// [`super::KernelError::Execution`].
    Failed(String),
    /// Structured plugin error (the `throw_error` step type).
    /// Promoted to [`super::KernelError::PluginError`].
    Thrown(PluginErrorPayload),
    /// The step observed [`PluginExecution::cancel_token`] and stopped
    /// on it. Promoted to [`super::KernelError::Cancelled`], which the
    /// kernel's wallclock watchdog then reports as
    /// [`super::KernelError::ExecutionTimeout`] when the deadline is
    /// what fired the token. A step that races IO against the token
    /// returns this — not a `Failed` or `Thrown` of its own — so the
    /// stop keeps its meaning on the way out.
    Cancelled,
    /// A nested invocation the step made failed: an `invoke` step's
    /// callee, or an action a native step dispatched by role. Promoted
    /// to [`super::KernelError::CalleeFailed`] with `source` intact, so
    /// a caller can branch on a callee's `PluginError` code or see that
    /// it timed out. Shared rather than boxed because `StepError` is
    /// `Clone` and kernel errors are not.
    Callee {
        plugin: String,
        action: String,
        source: std::sync::Arc<super::KernelError>,
    },
}

impl StepError {
    /// Map a callee's error onto the calling step's error, keeping it
    /// typed. A cancelled callee means the caller was cancelled: a
    /// callee runs under a child of the caller's token, which only the
    /// caller's cancel or deadline fires — the callee's own watchdog
    /// reports `ExecutionTimeout`, not `Cancelled`. Everything else is
    /// the callee's own failure.
    pub fn from_callee(plugin: &str, action: &str, err: super::KernelError) -> Self {
        match err {
            super::KernelError::Cancelled { .. } => StepError::Cancelled,
            source => StepError::Callee {
                plugin: plugin.to_string(),
                action: action.to_string(),
                source: std::sync::Arc::new(source),
            },
        }
    }
}

impl std::fmt::Display for StepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StepError::Failed(msg) => write!(f, "{msg}"),
            StepError::Thrown(p) => write!(f, "{}: {}", p.code, p.message),
            StepError::Cancelled => write!(f, "cancelled"),
            StepError::Callee {
                plugin,
                action,
                source,
            } => write!(f, "{plugin}.{action} failed: {source}"),
        }
    }
}

impl std::error::Error for StepError {}

// ---------------------------------------------------------------------------
// PluginExecution trait — opaque public handle
// ---------------------------------------------------------------------------

/// The six invocation-context values that always travel together when
/// dispatching a child action through [`super::Kernel::dispatch_role_inner`].
///
/// Lives here so both [`super::Kernel::dispatch_role`]'s `&dyn PluginExecution`
/// wrapper and the [`PluginExecution::dispatch_role`] trait default method can
/// construct one via [`PluginExecution::dispatch_snapshot`] and pass it into
/// the kernel-side inner — one snapshot site, one struct, no parallel
/// six-argument lists drifting apart.
///
/// `pub(crate)` because external callers shouldn't construct one
/// directly; the snapshot is "what a `PluginExecution` knows about its
/// invocation," not data the embedder hands in.
pub(crate) struct DispatchSnapshot {
    pub caller_plugin: String,
    pub caller_config: Value,
    pub secret_resolver: Option<std::sync::Arc<dyn super::secrets::SecretResolver>>,
    pub exec_ctx: ExecutionContext,
    pub invoke_depth: u32,
    pub cancel: tokio_util::sync::CancellationToken,
    pub deadline: Option<tokio::time::Instant>,
}

impl DispatchSnapshot {
    /// Capture the invocation-context values from a `PluginExecution`
    /// in one place. Both [`super::Kernel::dispatch_role`] and the
    /// [`PluginExecution::dispatch_role`] default impl call this so the
    /// snapshot logic doesn't drift between the two entry points.
    ///
    /// Generic over `E: PluginExecution + ?Sized` so the trait default impl
    /// can pass `self` (a `&Self` of the impl type) without an
    /// explicit `&dyn PluginExecution` coercion.
    pub(crate) fn capture<E: PluginExecution + ?Sized>(ex: &E) -> Self {
        Self {
            caller_plugin: ex.plugin_name().to_string(),
            caller_config: ex.config().clone(),
            secret_resolver: ex.secret_resolver().cloned(),
            exec_ctx: ex.exec_ctx().clone(),
            invoke_depth: ex.invoke_depth(),
            cancel: ex.cancel_token(),
            deadline: ex.wallclock_deadline(),
        }
    }
}

/// Public-facing handle into an action's per-invocation state. Step type
/// implementations operate against `&mut dyn PluginExecution`; the underlying
/// `ExecutionState` struct (and its fields) stays a kernel-private
/// implementation detail.
///
/// The trait is the documented surface external step authors (host
/// applications, plugin runtimes) program against. Step type
/// signatures use it, and the underlying struct is sealed so this is
/// the only way in.
///
/// # Sealed
///
/// **This trait cannot be implemented outside this crate.** It has a
/// private supertrait, so the only impl is the kernel's own
/// `ExecutionState`. Step type authors *call* this trait through the
/// `&mut dyn PluginExecution` their body receives; they never
/// implement it.
///
/// The seal is what makes the surface safe to evolve. A prose warning
/// that the trait is provisional would not stop anyone, and a plugin
/// author who implemented it — to mock an execution state while
/// unit-testing a native step body, say — would be broken by every
/// method the kernel added. Sealing replaces that warning with a
/// compiler check: adding a method, moving one onto an extension
/// trait, or narrowing a signature is a change to callers we can
/// measure, not a change to an unknown population of implementers.
///
/// What it costs: you cannot write your own `PluginExecution` to mock
/// out the kernel in tests. Exercise native step bodies through a real
/// [`Kernel`](super::Kernel) with a fixture manifest instead — that is
/// how the kernel's own step-body tests are written, and it exercises
/// the resolution and permission paths a mock would skip.
///
/// Doctests compile as downstream crates, which is what lets the seal
/// be tested at all. The seal rests on `sealed::Sealed` being
/// unnameable outside this crate, so that is what this pins — widen
/// the module's visibility and the snippet starts compiling, failing
/// the test:
///
/// ```compile_fail
/// use gwead::kernel::host_api::sealed::Sealed;
/// fn f<T: Sealed>() {}
/// ```
///
/// (That `PluginExecution` keeps `Sealed` as a supertrait is enforced
/// by the signature below.)
///
/// Engine internals (the wasmtime `Engine`, the kernel back-ref, the
/// `script_runtimes` module table) are deliberately NOT on the trait —
/// intrinsic step bodies reach them through the concrete
/// `ExecutionState` instead, which external crates cannot name. That
/// capability split is enforced by the type system, not by convention.
///
/// # Borrow asymmetry on read methods
///
/// [`Self::step_result`] returns owned `Option<Value>` because it
/// synthesizes through fan-out override application; the value may be
/// a freshly-built `Value` not resident in any owned slot.
/// [`Self::iteration_item`], [`Self::trigger`], [`Self::get_variable`],
/// and the other readers return `Option<&Value>` because they map onto
/// a stable underlying slot. Step type authors who need an owned
/// `Value` from a borrowed reader call `.cloned()`; consumers who want
/// to avoid that clone should expect the borrow form everywhere except
/// `step_result`.
pub trait PluginExecution: sealed::Sealed + Send {
    // ----- identity -----

    /// Name of the plugin whose action is currently executing.
    fn plugin_name(&self) -> &str;

    /// id of the step currently executing. Set by the runtime adapter
    /// before each step body runs; used by step bodies for logging and
    /// as part of structured error context.
    fn current_step_id(&self) -> &str;

    /// `type` of the step currently executing — the step type name from
    /// the manifest. Needed by the alias dispatcher (one body registered
    /// under many alias names; this is how it discovers which one).
    fn current_step_type(&self) -> &str;

    // ----- read-only inputs -----

    /// The action's input payload (`{{$input.*}}` resolution root).
    fn input(&self) -> &Value;

    /// The config namespace the action sees as `{{$config.*}}`.
    fn config(&self) -> &Value;

    /// The secrets this step body may use, as pulled through the
    /// invocation's [`SecretResolver`](super::secrets::SecretResolver)
    /// and narrowed to the declaring manifest's `usesSecrets` — see
    /// [`super::secrets`].
    ///
    /// **Whose** secrets: the plugin that *ships this body*. A plugin's
    /// own step sees its own bag. A native step type used from another
    /// plugin's action sees the bag of the plugin that defined the step
    /// type — never the calling plugin's — so holding a `step_type:`
    /// grant is not holding the caller's credentials. The caller
    /// delegates a secret deliberately, by resolving it into a param
    /// (`"key": "{{$secrets.privateKey}}"`), and that keeps working
    /// because params resolve against the caller's own bag.
    ///
    /// Kept separate from `config` so audit logs can redact the whole
    /// namespace without per-field knowledge.
    fn secrets(&self) -> &Value;

    /// The resolver this invocation tree pulls credentials through,
    /// inherited by every child invocation a step body starts. `None`
    /// means no credentials exist for this tree. Step bodies have no
    /// reason to call this; it exists so the `invoke`, alias and role
    /// dispatch paths hand a callee the same source the caller had.
    fn secret_resolver(&self) -> Option<&std::sync::Arc<dyn super::secrets::SecretResolver>>;

    /// Trigger payload for actions invoked through
    /// [`crate::kernel::Kernel::dispatch_event`]. `None` outside event
    /// dispatch.
    fn trigger(&self) -> Option<&Value>;

    // ----- variables (read/write) -----

    /// Read a variable written with [`Self::set_variable`].
    fn get_variable(&self, name: &str) -> Option<&Value>;

    /// Write a variable. Visible as `{{$vars.<name>}}` in subsequent
    /// steps of the same action.
    fn set_variable(&mut self, name: String, value: Value);

    // ----- per-step results -----

    /// The result a previous step in this action stored under `step_id`,
    /// with any active fan-out branch override applied.
    fn step_result(&self, step_id: &str) -> Option<Value>;

    /// Look up the result of a named source step, or the first step when
    /// `source` is `None`. Used by the implicit-source `$.foo` path form
    /// in `extract` / `transform` step types, where `source:` names the
    /// implicit root.
    fn get_source_result(&self, source: Option<&str>) -> Option<Value>;

    // ----- iteration / error context -----

    /// The current item of the innermost active `for_each` iteration,
    /// or `None` outside one.
    fn iteration_item(&self) -> Option<&Value>;

    /// The most recent entry on the engine's error stack — the
    /// `{{$.error}}` binding fed to step bodies executing inside a
    /// `catch` handler. `None` when the stack is
    /// empty (no handler has been pushed). Outside handler scope
    /// nothing pushes the stack, so callers in non-handler bodies
    /// naturally see `None`; the engine does not enforce that scope
    /// separately.
    fn caught_error(&self) -> Option<&str>;

    // ----- DSL helpers + template resolution -----

    /// Resolve a DSL path string (`steps.foo.result.bar`,
    /// `config.endpoint`, `input.query`, …) against the current
    /// resolution context.
    fn eval_path(&self, path: &str) -> Value;

    /// Extended DSL eval that uses `source` as the implicit root for
    /// implicit-source `$.foo` paths. Rooted references (`$input`, `$steps.<id>`,
    /// `$config`, `$trigger`) bypass `source` entirely. Used by
    /// `extract` / `transform` step types.
    fn eval_path_with_source(&self, path: &str, source: Option<&Value>) -> Value;

    /// Build the full `{{template}}` resolution context — merges
    /// input/config/secrets/vars/steps/foreach-item/trigger into a
    /// single `Value::Object` step bodies feed to
    /// [`Self::resolve_template`] / [`Self::resolve_value_with`].
    fn resolution_context(&self) -> Value;

    /// Resolve a `{{template}}` string against the supplied context.
    fn resolve_template(&self, template: &str, ctx: &Value) -> String;

    /// Recursively resolve any [`Value`] (strings via template, arrays
    /// and objects via field-by-field recursion) against the supplied
    /// context.
    fn resolve_value_with(&self, value: &Value, ctx: &Value) -> Value;

    // ----- capability checks — advisory -----
    //
    // These two are the only *advisory* entries on this trait: the
    // kernel ships no HTTP client and no blob store, so it has no
    // boundary of its own to gate and never calls either one. They
    // exist so an embedder's I/O step type can consult the manifest.
    //
    // They are provisional because of their *shape*: asking permission
    // is a remembered check, and remembered checks get forgotten — a
    // step type that never calls these has ambient authority and looks
    // exactly like one that called them and was allowed. A shape with
    // nothing to remember (a step type handed an egress client already
    // scoped to its plugin's declared hosts) is the sort of thing this
    // sealed trait leaves room for without breaking anyone.

    /// Returns `Ok(())` if the executing plugin has
    /// `network:egress:<host>`. Fails closed: when no kernel back-ref
    /// is available to consult the permission set (a kernel never
    /// wrapped via `Kernel::into_arc`), the check DENIES rather than
    /// silently granting.
    ///
    /// # Advisory
    ///
    /// **The kernel never calls this.** If your step type performs
    /// network I/O it must call this itself and refuse on `Err` — a
    /// grant nobody checks restricts nothing, and nothing in the engine
    /// will notice that you didn't. Provisional in shape; see the note
    /// above this group of methods.
    fn check_network_egress(&self, host: &str) -> Result<(), String>;

    /// Returns `Ok(())` if the executing plugin has `blobs:<op>:<key>`.
    /// Same fail-closed no-kernel-back-ref behaviour as
    /// [`Self::check_network_egress`].
    ///
    /// # Advisory
    ///
    /// Unenforced by the kernel, on the same terms as
    /// [`Self::check_network_egress`].
    fn check_blobs(&self, op: super::permissions::BlobOp, key: &str) -> Result<(), String>;

    // ----- runtime resource access -----
    //
    // These accessors expose shared per-invocation resources without
    // exposing `ExecutionState` itself; the struct is sealed, so the
    // trait is the only way in.

    /// Per-invocation byte-stream registry. Step types that produce or
    /// consume streams clone this `Arc<Mutex<...>>` for use inside
    /// async blocks.
    fn streams(&self) -> &super::streams::SharedStreamRegistry;

    /// Take a readable stream out of the registry (e.g. for proxying
    /// it into an outbound HTTP body). Returns `(content_type, source)`
    /// when the handle is live.
    fn take_readable_stream(
        &mut self,
        handle: std::num::NonZeroU32,
    ) -> Option<(String, super::streams::ReadableSource)>;

    /// Opaque execution context. Embedder-supplied blob; the
    /// kernel never introspects it.
    fn exec_ctx(&self) -> &super::exec_context::ExecutionContext;

    /// Pre-provisioned writable output streams for long-running
    /// producer steps in a streaming-dataflow action.
    fn dataflow_outputs(&self) -> &std::sync::Arc<HashMap<String, super::streams::StreamId>>;

    /// Recursion depth for nested `invoke` chains. Used by the
    /// `invoke` step body to enforce [`INVOKE_MAX_DEPTH`].
    fn invoke_depth(&self) -> u32;

    /// Event-dispatch cascade depth.
    fn dispatch_depth(&self) -> u32;

    /// Per-invocation resource limits.
    fn limits(&self) -> super::RuntimeLimits;

    // ----- telemetry -----

    /// Best-effort streaming-dataflow progress emission.
    /// Drops on a full bounded channel — never blocks.
    fn emit_progress(&self, step_id: &str, payload: Value);

    /// Cancellation token observed by long-running step bodies. Step
    /// types that wait on IO should race their work against this token
    /// so callers can tear down cleanly.
    fn cancel_token(&self) -> tokio_util::sync::CancellationToken;

    /// The end of this invocation's wallclock budget, if it has one:
    /// the action's own `wallclockTimeoutMs`, the deployment default,
    /// or — for a callee — whatever its caller had left, all clamped by
    /// the operator ceiling (`Kernel::effective_wallclock_timeout`).
    /// The token fires then, and a step still running a short grace
    /// later is dropped. `None` is an uncapped invocation. A step body
    /// that waits on IO can bound that wait to the remaining budget
    /// instead of discovering the deadline only when the token fires.
    fn wallclock_deadline(&self) -> Option<tokio::time::Instant>;

    /// Dispatch to whichever plugin is bound to `role`, calling
    /// `action` with `input`.
    ///
    /// This is the standard seam plugin step bodies use to call other
    /// plugins through the SPI surface — the trait exposes no direct
    /// kernel handle. Implemented by `ExecutionState` (the sole impl —
    /// the trait is sealed), which reaches the kernel back-ref through internal
    /// state that is not on this trait.
    ///
    /// # Requires an `invoke:` grant
    ///
    /// **Default-deny.** The calling plugin's manifest must carry
    /// `invoke:role:<role>` (or `invoke:role:*`), and the plugin the
    /// orchestrator *resolves* to must also be covered — a role grant
    /// covers whichever plugin fills the role, but a redirect out of
    /// one is re-checked against `invoke:plugin:`. Without a grant
    /// this returns [`KernelError::Validation`] naming the missing
    /// permission.
    ///
    /// The check is not optional: if this surface reached dispatch
    /// without it, a native step body would be a laundering path
    /// around every `invoke:` grant in the system.
    ///
    /// # What the callee sees
    ///
    /// It gets its **own** stream registry — a callee cannot name a
    /// handle in its caller's table, so pass data as input, not as a
    /// handle. It inherits `invoke_depth` (so the recursion cap
    /// applies), exec_ctx, a *child* of the cancel token (this
    /// invocation's cancel reaches it; nothing it fires reaches this
    /// invocation), and this invocation's remaining wallclock budget as
    /// its bound (see [`Self::wallclock_deadline`]).
    ///
    /// Callee config comes from the
    /// [`DispatchOrchestrator`](super::dispatch::DispatchOrchestrator);
    /// the kernel-shipped
    /// [`DefaultOrchestrator`](super::dispatch::DefaultOrchestrator)
    /// passes the **caller's** config namespace straight through. An
    /// embedder that needs per-callee config supplies an orchestrator
    /// that fills it in. Callee secrets are not the orchestrator's to
    /// give: the callee pulls its own through this invocation's
    /// [`SecretResolver`](super::secrets::SecretResolver), narrowed to
    /// its manifest's `usesSecrets`.
    ///
    /// Returns [`KernelError::Execution`] if this `PluginExecution`
    /// was constructed without a kernel back-ref (i.e. the kernel
    /// wasn't wrapped via [`super::Kernel::into_arc`]); plugins
    /// running under normal kernel dispatch never hit this case.
    ///
    /// `hints` is opaque to the kernel; the embedder's
    /// [`super::dispatch::DispatchOrchestrator`] inspects it during
    /// selection (e.g. `{"region": "eu"}` to nudge a
    /// METADATA_PROVIDER orchestrator, `{"tier": "fast"}` for an
    /// LLM role). Pass `Value::Null` when no hint applies.
    fn dispatch_role(
        &self,
        role: &str,
        action: &str,
        input: Value,
        hints: Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, KernelError>> + Send + 'static>>;
}

/// Seals [`PluginExecution`]. `Sealed` is reachable only from inside
/// this crate, so no downstream crate can name it, and therefore none
/// can implement `PluginExecution` — see that trait's "Sealed"
/// section for why. Adding an impl here is a deliberate act; the
/// kernel has exactly one.
mod sealed {
    pub trait Sealed {}
    impl Sealed for super::ExecutionState {}
}

// Kernel step bodies that need engine internals (`invoke`, `wasm`,
// `script`, the alias dispatcher) register as `runtime::IntrinsicStepFn`
// and receive a concrete `&mut ExecutionState` directly (see
// `runtime::StepBody`). The kernel/plugin capability split is
// compiler-enforced rather than resting on a runtime downcast — the
// narrow `PluginExecution` trait does not carry `: Any`, and external
// crates can't name the `pub(crate)` `ExecutionState`.

impl PluginExecution for ExecutionState {
    fn plugin_name(&self) -> &str {
        &self.plugin_name
    }

    fn current_step_id(&self) -> &str {
        match self.current_step_idx {
            Some(idx) => self
                .action
                .steps
                .get(idx)
                .map(|s| s.id.as_str())
                .unwrap_or(""),
            None => "",
        }
    }

    fn current_step_type(&self) -> &str {
        match self.current_step_idx {
            Some(idx) => self
                .action
                .steps
                .get(idx)
                .map(|s| s.step_type.as_str())
                .unwrap_or(""),
            None => "",
        }
    }

    fn input(&self) -> &Value {
        &self.input
    }

    fn config(&self) -> &Value {
        &self.config
    }

    fn secrets(&self) -> &Value {
        self.body_secrets.as_ref().unwrap_or(&self.secrets)
    }

    fn secret_resolver(&self) -> Option<&std::sync::Arc<dyn super::secrets::SecretResolver>> {
        self.secret_resolver.as_ref()
    }

    fn trigger(&self) -> Option<&Value> {
        self.trigger.as_deref()
    }

    fn get_variable(&self, name: &str) -> Option<&Value> {
        self.variables.get(name)
    }

    fn set_variable(&mut self, name: String, value: Value) {
        self.variables.insert(name, value);
    }

    fn step_result(&self, step_id: &str) -> Option<Value> {
        self.effective_step_result(step_id)
    }

    fn get_source_result(&self, source: Option<&str>) -> Option<Value> {
        ExecutionState::get_source_result(self, source).cloned()
    }

    fn iteration_item(&self) -> Option<&Value> {
        self.foreach_stack.last()?.current_value.as_ref()
    }

    fn caught_error(&self) -> Option<&str> {
        self.error_stack.last().map(|s| s.as_str())
    }

    fn eval_path(&self, path: &str) -> Value {
        Self::eval_path(self, path, None)
    }

    fn eval_path_with_source(&self, path: &str, source: Option<&Value>) -> Value {
        Self::eval_path(self, path, source)
    }

    fn resolution_context(&self) -> Value {
        Self::resolution_context(self)
    }

    fn resolve_template(&self, template: &str, ctx: &Value) -> String {
        resolve::resolve(template, ctx)
    }

    fn resolve_value_with(&self, value: &Value, ctx: &Value) -> Value {
        resolve::resolve_value(value, ctx)
    }

    fn check_network_egress(&self, host: &str) -> Result<(), String> {
        Self::check_network_egress(self, host)
    }

    fn check_blobs(&self, op: super::permissions::BlobOp, key: &str) -> Result<(), String> {
        Self::check_blobs(self, op, key)
    }

    fn streams(&self) -> &super::streams::SharedStreamRegistry {
        &self.streams
    }

    fn take_readable_stream(
        &mut self,
        handle: std::num::NonZeroU32,
    ) -> Option<(String, super::streams::ReadableSource)> {
        let mut streams = super::streams::lock_shared(&self.streams);
        streams.take_readable(handle)
    }

    fn exec_ctx(&self) -> &super::exec_context::ExecutionContext {
        &self.exec_ctx
    }

    fn dataflow_outputs(&self) -> &std::sync::Arc<HashMap<String, super::streams::StreamId>> {
        &self.dataflow_outputs
    }

    fn invoke_depth(&self) -> u32 {
        self.invoke_depth
    }

    fn dispatch_depth(&self) -> u32 {
        self.dispatch_depth
    }

    fn limits(&self) -> super::RuntimeLimits {
        self.limits.clone()
    }

    fn emit_progress(&self, step_id: &str, payload: Value) {
        Self::emit_progress(self, step_id, payload);
    }

    fn cancel_token(&self) -> tokio_util::sync::CancellationToken {
        self.cancel.clone()
    }

    fn wallclock_deadline(&self) -> Option<tokio::time::Instant> {
        self.deadline
    }

    fn dispatch_role(
        &self,
        role: &str,
        action: &str,
        input: Value,
        hints: Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, KernelError>> + Send + 'static>> {
        let kernel_opt = self.kernel.as_ref().and_then(|w| w.upgrade());
        let snapshot = DispatchSnapshot::capture(self);
        let role = role.to_string();
        let action = action.to_string();
        Box::pin(async move {
            let kernel = kernel_opt.ok_or_else(|| {
                KernelError::Execution(
                    "PluginExecution::dispatch_role requires a kernel constructed via \
                     Kernel::into_arc; this `PluginExecution` has no kernel back-ref"
                        .to_string(),
                )
            })?;
            kernel
                .dispatch_role_inner(role, action, input, hints, snapshot)
                .await
        })
    }
}

impl ExecutionState {
    pub fn new(params: ExecutionStateParams) -> Self {
        Self {
            plugin_name: params.plugin_name,
            action: params.action,
            input: params.input,
            config: params.config,
            secrets: params.secrets,
            variables: IndexMap::new(),
            step_results: IndexMap::new(),
            step_metadata: IndexMap::new(),
            first_step_id: None,
            script_runtimes: params.script_runtimes,
            engine: params.engine,
            exec_ctx: params.exec_ctx,
            last_error: None,
            resource_violation: None,
            step_results_bytes: 0,
            step_type_access: params.step_type_access,
            body_secrets: None,
            secret_resolver: params.secret_resolver,
            plugin_error: None,
            cancelled: false,
            callee_error: None,
            foreach_stack: Vec::new(),
            error_stack: Vec::new(),
            // `Arc<Mutex<StreamRegistry>>` is the `SharedStreamRegistry`
            // shape the rest of the kernel uses.
            streams: params.streams.unwrap_or_else(|| {
                std::sync::Arc::new(std::sync::Mutex::new(super::streams::StreamRegistry::new()))
            }),
            invoke_depth: params.invoke_depth,
            dispatch_depth: params.dispatch_depth,
            kernel: params.kernel,
            trigger: params.trigger,
            limits: params.limits,
            active_fanout_overrides: HashMap::new(),
            cancel: params.cancel.unwrap_or_default(),
            deadline: params.deadline,
            dataflow_outputs: std::sync::Arc::new(HashMap::new()),
            dataflow_events: params.dataflow_events,
            current_step_idx: None,
            return_signal: None,
        }
    }

    /// Emit a [`super::DataflowEvent::StepProgress`] event to the
    /// pipeline's telemetry sidechannel. No-op when the action wasn't
    /// started via
    /// [`ExecuteActionRequest::into_dataflow_handle`](super::execute_request::ExecuteActionRequest::into_dataflow_handle)
    /// (the common case). Uses `try_send`, so a full channel drops the event
    /// rather than blocking — telemetry never gates pipeline
    /// progress.
    ///
    /// `step_id` is the id of the step calling this; step bodies
    /// know their own id via
    /// `state.action.steps[step_index].id.as_str()` (the host fn
    /// dispatch always passes the current step index in as an
    /// argument).
    pub fn emit_progress(&self, step_id: &str, payload: Value) {
        if let Some(sender) = &self.dataflow_events {
            let _ = sender.try_send(super::DataflowEvent::StepProgress {
                step_id: step_id.to_string(),
                payload,
            });
        }
    }

    /// Per-consumer view of `steps.<id>.result`. Returns the active fan-out
    /// branch handle when one is set for `step_id`; otherwise the value
    /// stored in [`Self::step_results`]. Used by the resolution surfaces so
    /// consumer steps see their private branch handle without disturbing
    /// the producer's shared slot.
    pub fn effective_step_result(&self, step_id: &str) -> Option<Value> {
        if let Some(&branch) = self.active_fanout_overrides.get(step_id) {
            return Some(Value::from(branch));
        }
        self.step_results.get(step_id).cloned()
    }

    /// Materialise a `step_results` view with [`Self::active_fanout_overrides`]
    /// applied. Returns `None` when no overrides are active (the common path),
    /// so callers can pass `&self.step_results` through directly and skip the
    /// clone.
    pub fn step_results_view_with_overrides(&self) -> Option<IndexMap<String, Value>> {
        if self.active_fanout_overrides.is_empty() {
            return None;
        }
        Some(
            self.step_results
                .iter()
                .map(|(k, v)| {
                    let value = if let Some(&branch) = self.active_fanout_overrides.get(k) {
                        Value::from(branch)
                    } else {
                        v.clone()
                    };
                    (k.clone(), value)
                })
                .collect(),
        )
    }

    /// The set of metadata keys the step type `step_type` is permitted to
    /// emit, per its [`super::types::StepTypeDef`] `metadataSchema`.
    ///
    /// - `Some(set)` when the def resolves — an *empty* set means the def
    ///   declares no `metadataSchema`, so emitting any sidecar is an error
    ///   (closed by default).
    /// - `None` when the step type has no registered def, or this state
    ///   carries no kernel handle (hand-built test states). Callers treat
    ///   `None` as "no constraint" — `register_plugin`'s impl⇒def check
    ///   guarantees every executable step type has a def, so in real
    ///   execution `None` only means "no kernel context".
    ///
    /// Resolved from the registry per dispatch rather than stamped onto the
    /// step at registration, because nested steps (inside `for_each` / `ifs` bodies)
    /// are parsed fresh at runtime and never carry a registration-time stamp —
    /// going through the registry covers top-level and nested steps alike.
    ///
    /// ## The allow-list is the flat `.properties` key-set
    ///
    /// The allow-list is **exactly** the top-level
    /// `metadataSchema.properties` key-set:
    /// - `additionalProperties` is **not** read — a schema setting it `true`
    ///   to mean "open metadata" is still enforced as closed.
    /// - the schema must be a **flat object schema**; `$ref` / `allOf` /
    ///   `oneOf` have no top-level `.properties`, so they collapse to an
    ///   empty allow-list (every emitted key rejected).
    /// - emitted values are routed **verbatim** — no per-key type
    ///   check.
    pub(crate) fn declared_metadata_keys(
        &self,
        step_type: &str,
    ) -> Option<std::collections::BTreeSet<String>> {
        let kernel = self.kernel.as_ref()?.upgrade()?;
        let key = self.step_type_access.resolve(step_type)?;
        let (_, def) = kernel.registry().get_step_type_def(key)?;
        // Allow-list = the schema's top-level property keys. See the
        // doc-comment's "flat .properties key-set" note for why
        // `additionalProperties` and `$ref`/`allOf`/`oneOf` aren't honored.
        let keys = def
            .metadata_schema
            .as_ref()
            .and_then(|schema| schema.get("properties"))
            .and_then(|props| props.as_object())
            .map(|props| props.keys().cloned().collect())
            .unwrap_or_default();
        Some(keys)
    }

    /// Build the DSL `$steps` view: each step id maps to
    /// `{ result, ...metadata }` so paths like
    /// `$steps.foo.result.bar` resolve uniformly across `ifs`/`until`
    /// conditions, `collect` accumulators, and `for_each.path`. Without
    /// this wrapping, `for_each.path` would resolve `$steps.foo.result` to the
    /// raw payload and `.result.bar` would lookup-fail with `null` —
    /// silently breaking iteration. Active fan-out branch overrides
    /// are layered on first so a consumer inside a fan-out
    /// sees the branch handle rather than the producer's shared slot.
    pub fn build_dsl_steps_view(&self) -> Value {
        let base = self.step_results_view_with_overrides();
        let source: &IndexMap<String, Value> = base.as_ref().unwrap_or(&self.step_results);
        let mut wrapped = serde_json::Map::new();
        for (id, result_value) in source {
            let mut obj = serde_json::Map::new();
            // Sidecar metadata surfaces flat as `steps.<id>.<key>`.
            // Inserted before `result` so the value slot always wins if a
            // step type ever declared a `result` metadata key.
            if let Some(meta) = self.step_metadata.get(id) {
                for (k, v) in meta {
                    obj.insert(k.clone(), v.clone());
                }
            }
            obj.insert("result".to_string(), result_value.clone());
            wrapped.insert(id.clone(), Value::Object(obj));
        }
        Value::Object(wrapped)
    }

    /// Build the `vars` namespace — `store_to_variable` values — as a
    /// JSON object for the DSL's `$vars.*` root. Shared by
    /// the template resolution context and the structural-position
    /// `EvalContext` builders (`eval_path`, `eval_dsl_expression`) so a
    /// variable resolves identically in `{{...}}` templates and in
    /// `ifs` / `for_each.path` / `collect` / `until`.
    pub(crate) fn vars_as_value(&self) -> Value {
        Value::Object(
            self.variables
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        )
    }

    /// Build the template resolution context — merges input, config, vars,
    /// and step results into a single object for `{{template}}` resolution.
    pub fn resolution_context(&self) -> Value {
        let mut ctx = serde_json::Map::new();

        // Merge top-level input fields
        if let Some(obj) = self.input.as_object() {
            for (k, v) in obj {
                ctx.insert(k.clone(), v.clone());
            }
        }

        // Config namespace
        ctx.insert("config".to_string(), self.config.clone());

        // Secrets namespace — separate from config so plugin templates can
        // reference `{{$secrets.api_key}}` without secrets leaking into the
        // `{{$config.*}}` namespace or audit logs that redact based on namespace.
        ctx.insert("secrets".to_string(), self.secrets.clone());

        // Variables namespace
        ctx.insert("vars".to_string(), self.vars_as_value());

        // Steps namespace. Each entry exposes `.result` (the step's
        // primary value) plus any sidecar metadata the step emitted,
        // flattened under the step id — e.g. `http_call`'s
        // `.status` and `.headers`. Step types that emit no metadata
        // expose only `.result`, so `{{$steps.foo.status}}` resolves to
        // nothing — the template engine treats that as falsy, which is
        // what the `ifs` step branches off.
        //
        // When [`Self::active_fanout_overrides`] has an entry for a step,
        // its `.result` is the consumer's branch handle rather than the
        // producer's shared slot value.
        let steps: serde_json::Map<String, Value> = self
            .step_results
            .iter()
            .map(|(k, v)| {
                let result_value = if let Some(&branch) = self.active_fanout_overrides.get(k) {
                    Value::from(branch)
                } else {
                    v.clone()
                };
                let mut step_obj = serde_json::Map::new();
                // Sidecar metadata first; `result` overlaid last so the
                // value slot always wins.
                if let Some(meta) = self.step_metadata.get(k) {
                    for (mk, mv) in meta {
                        step_obj.insert(mk.clone(), mv.clone());
                    }
                }
                step_obj.insert("result".to_string(), result_value);
                (k.clone(), Value::Object(step_obj))
            })
            .collect();
        ctx.insert("steps".to_string(), Value::Object(steps));

        // forEach / repeat item (if in a loop). The current-iteration
        // index is `foreach.current`, NOT `foreach.index` — see
        // [`ForEachState`] for the split.
        if let Some(foreach) = self.foreach_stack.last()
            && let Some(item) = foreach.current_value.as_ref()
        {
            ctx.insert("item".to_string(), item.clone());
        }

        // Active error payload (inside a `try` step's `catch` body). The
        // string form mirrors how step types surface failures via
        // `last_error` — handlers can read it for retry / logging /
        // fallback decisions. Nested handlers each see their own
        // failure on the stack top.
        if let Some(msg) = self.error_stack.last() {
            ctx.insert("error".to_string(), Value::String(msg.clone()));
        }

        // Triggering event payload — `Some` only when this action was
        // dispatched by the kernel's event dispatcher. One
        // unavoidable deep clone of the payload into the resolution
        // context map; sibling subscribers each pay this independently
        // but the dispatcher-level fan-out is refcount-only via Arc.
        if let Some(trigger) = self.trigger.as_deref() {
            ctx.insert("trigger".to_string(), trigger.clone());
        }

        Value::Object(ctx)
    }

    /// Get the result for a named source step, or the first step if source is None.
    pub fn get_source_result(&self, source: Option<&str>) -> Option<&Value> {
        match source {
            Some(s) => self.step_results.get(s),
            None => self
                .first_step_id
                .as_ref()
                .and_then(|id| self.step_results.get(id)),
        }
    }

    /// Evaluate a DSL reference against host state.
    ///
    /// Implicit-source `$.foo` paths use `implicit_source` (looked up
    /// from the step's `source:` field) as the implicit root.
    /// Rooted references (`$input`, `$steps.<id>`, `$config`, `$trigger`)
    /// bypass `implicit_source` entirely and resolve against the
    /// execution state directly.
    pub fn eval_path(&self, path: &str, implicit_source: Option<&Value>) -> Value {
        match dsl::parse_reference(path) {
            Ok(reference) => {
                // Wrapped step view: `$steps.<id>.result.<path>` is the
                // step's primary value, plus any sidecar metadata the
                // step type declared (an HTTP step's `status` /
                // `headers`, say). Same shape `eval_dsl_expression`
                // uses for `ifs`/`until`/`collect`, so manifest authors
                // get one consistent syntax across templates,
                // conditionals, and `path:` extraction. Fan-out
                // overrides are layered in by `build_dsl_steps_view`
                // itself.
                //
                let steps_value: Value = self.build_dsl_steps_view();
                let vars_value: Value = self.vars_as_value();
                let item = self
                    .foreach_stack
                    .last()
                    .and_then(|f| f.current_value.as_ref());
                let ctx = EvalContext {
                    input: Some(&self.input),
                    steps: Some(&steps_value),
                    config: Some(&self.config),
                    secrets: Some(&self.secrets),
                    trigger: self.trigger.as_deref(),
                    vars: Some(&vars_value),
                    item,
                    implicit_source,
                };
                dsl::eval_reference(&reference, &ctx)
            }
            Err(e) => {
                tracing::debug!("DSL parse error for '{path}': {e}");
                Value::Null
            }
        }
    }

    /// Capability check helper. Returns `Ok(())` if the
    /// executing plugin has `network:egress:<host>`, or `Err(reason)`
    /// suitable for assignment to `last_error`. Fails CLOSED when the
    /// kernel back-ref isn't available: a check that can't consult the
    /// permission set must deny, not silently grant — the alternative
    /// turns "kernel dropped mid-flight" into an every-capability
    /// bypass. Callers that need capability checks must run against a
    /// kernel wrapped via `Kernel::into_arc`.
    ///
    /// # Advisory
    ///
    /// The kernel has no call site for this and cannot tell a step type
    /// that consulted it from one that never did. Step bodies reach it
    /// through [`PluginExecution::check_network_egress`]; the note there
    /// explains why the shape is provisional.
    pub fn check_network_egress(&self, host: &str) -> Result<(), String> {
        let Some(kernel) = self.kernel.as_ref().and_then(|w| w.upgrade()) else {
            return Err(format!(
                "cannot verify network:egress:{host}: no kernel back-reference \
                 (kernel not wrapped via Kernel::into_arc, or already dropped) — \
                 failing closed"
            ));
        };
        let perms = kernel
            .registry()
            .permissions_for(&self.plugin_name)
            .to_vec();
        if super::permissions::check_network_egress(&perms, host).is_granted() {
            Ok(())
        } else {
            Err(format!(
                "plugin '{}' lacks network:egress:{} permission",
                self.plugin_name, host
            ))
        }
    }

    /// Capability check helper. Returns `Ok(())` if the
    /// executing plugin has `blobs:<op>:<key>`, or `Err(reason)`.
    /// Same fail-closed no-kernel-back-ref behaviour as
    /// [`Self::check_network_egress`].
    ///
    /// # Advisory
    ///
    /// Unenforced, on the same terms as [`Self::check_network_egress`].
    pub fn check_blobs(&self, op: super::permissions::BlobOp, key: &str) -> Result<(), String> {
        let Some(kernel) = self.kernel.as_ref().and_then(|w| w.upgrade()) else {
            return Err(format!(
                "cannot verify blobs:{op}:{key}: no kernel back-reference \
                 (kernel not wrapped via Kernel::into_arc, or already dropped) — \
                 failing closed"
            ));
        };
        let perms = kernel
            .registry()
            .permissions_for(&self.plugin_name)
            .to_vec();
        let op_label = format!("{op}");
        if super::permissions::check_blobs(&perms, op, key).is_granted() {
            Ok(())
        } else {
            Err(format!(
                "plugin '{}' lacks blobs:{}:{} permission",
                self.plugin_name, op_label, key
            ))
        }
    }

    /// Record a step's result (and track the first step), subject to
    /// [`RuntimeLimits::max_step_results_bytes`](super::RuntimeLimits::max_step_results_bytes).
    ///
    /// # Why there is a budget here
    ///
    /// Step results are the only unbounded host-side allocation a
    /// manifest controls, and they compose: a step may reference an
    /// earlier result twice, so a chain of `let` steps holding
    /// `"{{$steps.prev.result}}{{$steps.prev.result}}"` doubles per
    /// line: two dozen such lines reach over a hundred megabytes in a
    /// fraction of a second, and a few more reach terabytes. No wasm
    /// limit sees this — nothing runs in wasm — and no wallclock
    /// catches it, because it is fast.
    ///
    /// The budget is cumulative rather than per-value: capping one
    /// result still leaves `n` of them, and it is the total the host
    /// has to hold. Overshoot is bounded by one value, since the check
    /// runs after the value exists.
    ///
    /// Over budget, the result is **not stored** and a
    /// [`ResourceViolation::StepResultsLimit`] is recorded;
    /// [`super::runtime::run_step`] turns that into a failed step on
    /// the way out. Refusing to store is what makes the bound real —
    /// recording a marker and keeping the value would cap the error
    /// message, not the memory.
    pub fn store_step_result(&mut self, step_id: &str, value: Value) {
        if self.first_step_id.is_none() {
            self.first_step_id = Some(step_id.to_string());
        }
        let limit = self.limits.max_step_results_bytes;
        let incoming = approx_value_bytes(&value);
        let replaced = self
            .step_results
            .get(step_id)
            .map(approx_value_bytes)
            .unwrap_or(0);
        let projected = self
            .step_results_bytes
            .saturating_sub(replaced)
            .saturating_add(incoming);
        if projected > limit {
            self.resource_violation = Some(ResourceViolation::StepResultsLimit {
                limit_bytes: limit,
                attempted_bytes: projected,
            });
            return;
        }
        self.step_results_bytes = projected;
        self.step_results.insert(step_id.to_string(), value);
    }

    /// Collect the action's output using results_path and result_mapping.
    pub fn collect_output(&self) -> Value {
        // If there's a result_mapping, apply it
        if !self.action.result_mapping.is_empty() {
            return self.apply_result_mapping();
        }

        // If there's a results_path, extract from step results
        if let Some(path) = &self.action.results_path {
            let source = self.get_source_result(None);
            return self.eval_path(path, source);
        }

        // Default: return the last step's result
        self.step_results
            .values()
            .last()
            .cloned()
            .unwrap_or(Value::Null)
    }

    /// Apply the action's result_mapping to produce the output.
    fn apply_result_mapping(&self) -> Value {
        let ctx = self.resolution_context();
        let mut output = serde_json::Map::new();

        for (key, spec) in &self.action.result_mapping {
            let value = self.extract_field_value(spec, &ctx);
            output.insert(key.clone(), value);
        }

        Value::Object(output)
    }

    /// Extract a field value from a result mapping spec.
    /// Supports: {literal: "..."}, {template: "..."}, {path: "$..", source?, fallback?}.
    ///
    /// `transforms` is intentionally NOT supported here. Composing
    /// transforms over a result_mapping field belongs in the flow —
    /// manifests compose a `transform` step before or after the
    /// action's result-collection pass instead of embedding transforms
    /// inline. The kernel knows only the four primitives
    /// (literal/template/path/fallback) needed to wire dataflow.
    fn extract_field_value(&self, spec: &Value, ctx: &Value) -> Value {
        match spec {
            Value::Object(obj) => {
                // Literal value — strings go through flat string
                // interpolation. Arrays and objects recurse via
                // `resolve_value` so nested templates are still resolved
                // (an array of objects with a templated text field
                // resolves in place).
                if let Some(lit) = obj.get("literal") {
                    return match lit {
                        Value::String(s) => Value::String(resolve::resolve(s, ctx)),
                        other => resolve::resolve_value(other, ctx),
                    };
                }

                // Template value
                if let Some(tmpl) = obj.get("template").and_then(|v| v.as_str()) {
                    return Value::String(resolve::resolve(tmpl, ctx));
                }

                // DSL path extraction. Implicit-source paths (`$.foo` with
                // optional `source:` field) flow through the implicit-source root;
                // rooted paths (`$input`, `$steps.<id>`, `$config`, `$trigger`)
                // resolve against host state directly.
                if let Some(path) = obj.get("path").and_then(|v| v.as_str()) {
                    let source = obj.get("source").and_then(|v| v.as_str());
                    let source_data = self.get_source_result(source);
                    let value = self.eval_path(path, source_data);

                    if value.is_null()
                        && let Some(fallback) = obj.get("fallback")
                    {
                        return self.extract_field_value(fallback, ctx);
                    }

                    return value;
                }

                // Nested object — recurse
                let mut nested = serde_json::Map::new();
                for (k, v) in obj {
                    nested.insert(k.clone(), self.extract_field_value(v, ctx));
                }
                Value::Object(nested)
            }
            other => other.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Host import registration
// ---------------------------------------------------------------------------

// The body-shaped kernel intrinsics submit themselves into the
// `inventory` slices the boot-time tables walk. They split by capability:
//
// - `throw_error` and `let` are genuine plugins — implementable through
//   the public `PluginExecution` surface alone — so they submit as
//   [`NativeStepImplEntry`] and the intrinsics manifest references them
//   with `kind: "native"`, the same path any external plugin's native
//   step bodies take.
// - `invoke` and `wasm` need engine internals, so they submit as
//   [`IntrinsicStepImplEntry`] (concrete `&mut ExecutionState`) and the
//   manifest references them with `kind: "intrinsic"`. External crates
//   can't name `ExecutionState`, so they can't supply these.
//
// `script` is also `kind: "intrinsic"`, but its submission lives next to
// its impl in `super::script_runtime_host` rather than here. The six
// control-flow intrinsics (ifs, for_each, repeat, return, try, parallel)
// are dispatched directly inside `runtime.rs` — not through this seam at
// all — because they manipulate control flow rather than executing as
// step bodies.
//
// Naming uses the reserved `gwead.*` namespace per the
// [`super::native_impls`] module docs: only the gwead crate itself
// submits names with this prefix.
inventory::submit! {
    super::native_impls::NativeStepImplEntry::kernel("gwead.intrinsics.throw_error", step_throw_error)
}

inventory::submit! {
    IntrinsicStepImplEntry {
        name: "gwead.intrinsics.invoke",
        impl_: step_invoke,
    }
}

inventory::submit! {
    IntrinsicStepImplEntry {
        name: "gwead.intrinsics.wasm",
        impl_: step_wasm,
    }
}

inventory::submit! {
    super::native_impls::NativeStepImplEntry::kernel("gwead.intrinsics.let", step_let)
}

/// Register kernel-internal services on the wasmtime Linker.
///
/// These are distinct from step types: control-flow helpers (`step_success`,
/// `begin_foreach`, `next_foreach`, `end_foreach`, `begin_repeat`) that
/// the runtime's iteration drivers call by name regardless of which
/// step types an action uses. They are registered directly rather than
/// through a manifest — they're part of the kernel/wasm ABI, not a
/// plugin surface.
pub(crate) fn register_kernel_services(
    linker: &mut Linker<ExecutionState>,
) -> Result<(), KernelError> {
    // Each helper is registered via `func_wrap_async` so the resulting
    // store is in async-required mode, matching the step type registrations
    // in `WasmRuntime::execute_dag`. Bodies are synchronous and return
    // immediately-ready futures.
    linker
        .func_wrap_async(
            crate::kernel::abi::ABI_MODULE,
            "step_success",
            |caller: wasmtime::Caller<'_, ExecutionState>, (arg,): (i32,)| {
                let result = host_step_success(caller, arg);
                Box::new(async move { result })
            },
        )
        .map_err(|e| KernelError::Runtime(format!("Failed to register step_success: {e}")))?;

    linker
        .func_wrap_async(
            crate::kernel::abi::ABI_MODULE,
            "begin_foreach",
            |caller: wasmtime::Caller<'_, ExecutionState>, (arg,): (i32,)| {
                let result = host_begin_foreach(caller, arg);
                Box::new(async move { result })
            },
        )
        .map_err(|e| KernelError::Runtime(format!("Failed to register begin_foreach: {e}")))?;

    linker
        .func_wrap_async(
            crate::kernel::abi::ABI_MODULE,
            "next_foreach",
            |caller: wasmtime::Caller<'_, ExecutionState>, (arg,): (i32,)| {
                let result = host_next_foreach(caller, arg);
                Box::new(async move { result })
            },
        )
        .map_err(|e| KernelError::Runtime(format!("Failed to register next_foreach: {e}")))?;

    linker
        .func_wrap_async(
            crate::kernel::abi::ABI_MODULE,
            "end_foreach",
            |caller: wasmtime::Caller<'_, ExecutionState>, (arg,): (i32,)| {
                let result = host_end_foreach(caller, arg);
                Box::new(async move { result })
            },
        )
        .map_err(|e| KernelError::Runtime(format!("Failed to register end_foreach: {e}")))?;

    // `repeat` reuses next_foreach / end_foreach — only its
    // begin function is unique.
    linker
        .func_wrap_async(
            crate::kernel::abi::ABI_MODULE,
            "begin_repeat",
            |caller: wasmtime::Caller<'_, ExecutionState>, (arg,): (i32,)| {
                let result = host_begin_repeat(caller, arg);
                Box::new(async move { result })
            },
        )
        .map_err(|e| KernelError::Runtime(format!("Failed to register begin_repeat: {e}")))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Step type host functions
// ---------------------------------------------------------------------------

/// Execute a `throw_error` step — produces a structured plugin
/// error. Resolves templates inside `code`, `message`, and
/// `params`, returns [`StepError::Thrown`]. The adapter promotes
/// the payload to [`ExecutionState::plugin_error`], which the
/// runtime surfaces as [`super::KernelError::PluginError`] so
/// callers can branch on `code`.
fn step_throw_error<'a>(
    ex: &'a mut (dyn PluginExecution + Send),
    params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move {
        let ctx = ex.resolution_context();
        let code = params
            .get("code")
            .and_then(|v| v.as_str())
            .map(|s| ex.resolve_template(s, &ctx))
            .unwrap_or_else(|| "PLUGIN_ERROR".to_string());
        let message = params
            .get("message")
            .and_then(|v| v.as_str())
            .map(|s| ex.resolve_template(s, &ctx))
            .unwrap_or_default();
        let params_resolved = params
            .get("params")
            .map(|v| ex.resolve_value_with(v, &ctx))
            .unwrap_or(Value::Null);

        Err(StepError::Thrown(PluginErrorPayload {
            code,
            message,
            params: params_resolved,
        }))
    })
}

/// Execute a `let` step — the kernel's value-origination
/// primitive. Resolves `value` against the resolution context
/// (templates, `$vars`, prior `$steps.<id>`, `$config`, …) and returns
/// it as the step's result; the `store_to_variable` field then
/// names it as a variable if the author wants one
/// (`{type: "let", value: …, storeToVariable: "x"}`).
///
/// Value origination only touches kernel-internal execution state, so it
/// belongs in the kernel; naming stays the `store_to_variable` path, so
/// there's one variable-write path rather than two. `value` is resolved
/// recursively with type preservation (a lone `{{…}}` keeps its JSON
/// type; nested templates in objects/arrays resolve in place), matching
/// `invoke`'s `input` handling. Trait-shape (dispatched via the `_ =>`
/// arm in `run_step`), so it picks up `store_to_variable` mirroring from
/// `dispatch_trait_step_core` for free — unlike the control-flow
/// intrinsics, which don't.
fn step_let<'a>(
    ex: &'a mut (dyn PluginExecution + Send),
    params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move {
        let ctx = ex.resolution_context();
        let value = params
            .get("value")
            .map(|v| ex.resolve_value_with(v, &ctx))
            .unwrap_or(Value::Null);
        Ok(StepOutput::from(value))
    })
}

/// Recursion cap for `invoke` chains. Catches by-role cycles that the
/// structural registration-time check can't see, plus deeply nested but
/// legitimate compositions that almost certainly indicate a manifest bug.
pub const INVOKE_MAX_DEPTH: u32 = 16;

/// The kernel's step types — the names that are always permitted
/// without a grant and always resolve to themselves.
///
/// The *reservation* is wider than this list: every dot-free name is
/// the kernel's, whether or not it appears here, because plugin-defined
/// step types are `<plugin>.<name>` by grammar
/// ([`identity::validate_step_type_name`](super::identity::validate_step_type_name)).
/// This list is therefore not what keeps a plugin from squatting a
/// future intrinsic — the shape does that — it is the set the step
/// dispatcher treats as always-allowed.
///
/// Covers all 11 kernel intrinsics: the six control-flow intrinsics
/// (`ifs`, `for_each`, `repeat`, `parallel`, `return`, `try`) — defs
/// with no body, dispatched directly inside `runtime.rs` — plus the
/// five body-shaped intrinsics (`script`,
/// `throw_error`, `invoke`, `wasm`, `let`) wired declaratively via
/// `inventory::submit!` and the intrinsics manifest. Single source of
/// truth for the names a plugin manifest's `step_types` aliases cannot
/// take over.
pub const RESERVED_STEP_TYPE_NAMES: &[&str] = &[
    "ifs",
    "for_each",
    "repeat",
    "parallel",
    "return",
    "try",
    "script",
    "throw_error",
    "invoke",
    "wasm",
    "let",
];

/// Execute an `invoke` step — dispatch into another plugin's action by
/// plugin name or SPI role and store the resulting output as this step's
/// result.
///
/// Recognized params (mutually exclusive between `plugin` and `role`):
///
/// ```jsonc
/// {
///   "type": "invoke",
///   "id": "probe",
///   "params": {
///     "plugin": "ffprobe",     // OR `"role": "METADATA_PROVIDER"`
///     "action": "analyze",
///     "input": { /* JSON value, resolved against the parent ctx */ }
///   }
/// }
/// ```
///
/// `input` is template-resolved against the parent's resolution
/// context just like any other step's params, so prior step results
/// flow through naturally. The child runs against its own stream
/// handle table — a handle number from the parent means nothing there,
/// so pass data as input rather than as a handle (see
/// `Kernel::execute_action_invoked`). Recursion is capped at
/// [`INVOKE_MAX_DEPTH`].
fn step_invoke<'a>(
    ex: &'a mut ExecutionState,
    params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move {
        let step_id = ex.current_step_id().to_string();

        // Recursion cap. Hit before any real work so a cycle errors cheaply.
        if ex.invoke_depth() >= INVOKE_MAX_DEPTH {
            return Err(StepError::Failed(format!(
                "invoke recursion cap ({}) exceeded at step '{}'",
                INVOKE_MAX_DEPTH, step_id
            )));
        }

        let kernel = match ex.kernel.clone().and_then(|w| w.upgrade()) {
            Some(k) => k,
            None => {
                return Err(StepError::Failed(
                    "invoke step requires a kernel constructed via Kernel::into_arc; \
                     this kernel was never wrapped"
                        .to_string(),
                ));
            }
        };

        // Resolve target: exactly one of `plugin` or `role` must be
        // set. All three fields (`plugin`, `role`, `action`) flow
        // through the template engine so plugin authors can pick the
        // target dynamically from a prior step's result.
        let ctx = ex.resolution_context();
        let resolve_field = |key: &str| -> Option<String> {
            let raw = params.get(key)?;
            let resolved = resolve::resolve_value(raw, &ctx);
            resolved.as_str().map(str::to_string)
        };
        let plugin_field = resolve_field("plugin");
        let role_field = resolve_field("role");
        let action_name = match resolve_field("action") {
            Some(a) => a,
            None => {
                return Err(StepError::Failed(format!(
                    "invoke step '{step_id}' missing required `action`"
                )));
            }
        };

        // Build the dispatch request the orchestrator will consume;
        // by-role selection is the orchestrator's job.
        let (plugin_field, role_field) = match (plugin_field, role_field) {
            (Some(_), Some(_)) => {
                return Err(StepError::Failed(format!(
                    "invoke step '{step_id}' specifies both `plugin` and `role`; use exactly one"
                )));
            }
            (None, None) => {
                return Err(StepError::Failed(format!(
                    "invoke step '{step_id}' specifies neither `plugin` nor `role`"
                )));
            }
            (p, r) => (p, r),
        };

        // Resolve `input` against the parent's context. Templates inside
        // `input` may reference `{{$steps.<id>.result}}`, `$steps.<id>`,
        // `{{$config.*}}`, `{{$vars.*}}`, etc. — all flow naturally.
        let raw_input = params.get("input").cloned().unwrap_or(Value::Null);
        let resolved_input = ex.resolve_value_with(&raw_input, &ctx);
        // Optional manifest-level dispatch hints. `invoke` steps that
        // need to nudge an orchestrator's selection (e.g.
        // `hints: {region: "eu"}`) declare the blob in the
        // step params; missing means `Value::Null`. Templates flow
        // through the same resolution as `input`.
        let raw_hints = params.get("hints").cloned().unwrap_or(Value::Null);
        let resolved_hints = ex.resolve_value_with(&raw_hints, &ctx);

        let caller_plugin = ex.plugin_name().to_string();

        // A `plugin` reference resolves along the caller's ancestor
        // chain — own namespace first, then root. A no-op in root; in a
        // namespaced embedder the thing that lets two tenants ship the
        // identical manifest while each reaches their own plugin, and
        // lets either reach a global one it has no local shadow for.
        // `role` is not resolved here: role fulfilment is selected by
        // the orchestrator and bounded by containment.
        let plugin_field = match plugin_field {
            Some(raw) => Some(
                kernel
                    .resolve_plugin_reference(&caller_plugin, &raw)
                    .map_err(|e| StepError::Failed(format!("invoke step '{step_id}': {e}")))?,
            ),
            None => None,
        };

        let parent_depth = ex.invoke_depth();
        let config = ex.config().clone();
        let secret_resolver = ex.secret_resolver().cloned();
        let exec_ctx = ex.exec_ctx().clone();
        let parent_cancel = ex.cancel_token();
        let parent_deadline = ex.wallclock_deadline();

        let request = match (&plugin_field, &role_field) {
            (Some(p), None) => super::dispatch::DispatchRequest::ByPlugin {
                plugin: p.as_str(),
                action: &action_name,
                input: &resolved_input,
                hints: &resolved_hints,
            },
            (None, Some(r)) => super::dispatch::DispatchRequest::ByRole {
                role: r.as_str(),
                action: &action_name,
                input: &resolved_input,
                hints: &resolved_hints,
            },
            _ => unreachable!("validated above"),
        };
        // Capability gate before any selection work — a plugin needs an
        // `invoke:*` grant to dispatch outside itself.
        if let Err(reason) = kernel.check_invoke_grant(&caller_plugin, &request) {
            return Err(StepError::Failed(format!(
                "invoke step '{step_id}': {reason}"
            )));
        }
        let plan = match kernel
            .prepare_dispatch_via_orchestrator(
                request.clone(),
                &exec_ctx,
                Some(&caller_plugin),
                &config,
            )
            .await
        {
            Ok(p) => p,
            Err(super::KernelError::NotFound(m)) => {
                // Dedicated error wording for unbound roles.
                if let Some(r) = role_field.as_deref() {
                    return Err(StepError::Failed(format!(
                        "invoke step '{step_id}' role '{r}' has no registered plugin"
                    )));
                }
                return Err(StepError::Failed(format!("invoke step '{step_id}': {m}")));
            }
            Err(e) => {
                return Err(StepError::Failed(format!(
                    "invoke step '{step_id}' dispatch policy: {e}"
                )));
            }
        };
        // Re-authorise against what the orchestrator actually chose.
        // The gate above judged the request; a custom orchestrator can
        // resolve it somewhere else entirely, including out of a
        // self-invoke that needed no grant at all.
        if let Err(reason) =
            kernel.authorize_resolved_dispatch(&caller_plugin, &request, &plan, None)
        {
            return Err(StepError::Failed(format!(
                "invoke step '{step_id}': {reason}"
            )));
        }
        tracing::info!(
            plugin = %plan.plugin,
            action = %plan.action,
            "invoke: dispatching with orchestrator-resolved config namespace"
        );

        match kernel
            .execute_action_invoked(
                &plan.plugin,
                &plan.action,
                resolved_input,
                &plan.config,
                secret_resolver,
                &exec_ctx,
                parent_depth,
                Some(parent_cancel),
                parent_deadline,
            )
            .await
        {
            Ok(action_result) => Ok(StepOutput::from(action_result.output)),
            Err(e) => Err(StepError::from_callee(&plan.plugin, &plan.action, e)),
        }
    })
}

/// Store data + resource limiter for the `wasm` step type's
/// sub-instance.
///
/// Pairs the linear-memory cap pulled from
/// [`super::RuntimeLimits::max_memory_bytes`] with the
/// [`wasmtime::ResourceLimiter`] surface so a wasm module that calls
/// `memory.grow` in a loop traps cleanly via `Trap::OOM` instead of
/// OOMing the host process. The `script` step type wires this exact
/// pattern via `ScriptRuntimeStoreData`; the wasm step does it standalone.
struct WasmStoreLimits {
    budget: super::resource_budget::ResourceBudget,
}

super::resource_budget::impl_budget_limiter!(WasmStoreLimits, budget);

/// Execute a `wasm` intrinsic step.
///
/// Shape:
///
/// ```jsonc
/// {
///   "type": "wasm",
///   "id": "compute",
///   "params": {
///     "module": "my_module",   // required — must match a
///                              // `wasm_modules` entry on this plugin's
///                              // manifest
///     "entry":  "run"          // optional — defaults to "run"
///   }
/// }
/// ```
///
/// Looks up the pre-compiled `Arc<Module>` keyed by
/// `(plugin_name, module)` from the kernel registry (populated at
/// `register_plugin` time from `manifest.wasm_modules`), instantiates
/// in a fresh `Store<()>` with an empty linker, and calls the entry
/// function typed `() -> ()`. Returns `Value::Null` on success.
///
/// The entry function ABI is fixed: no args, no return value, no host
/// imports. Modules must be self-contained (typically compiled with
/// `--target wasm32-unknown-unknown`).
fn step_wasm<'a>(
    ex: &'a mut ExecutionState,
    params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move {
        let module_name = match params.get("module").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => {
                return Err(StepError::Failed(
                    "wasm step missing required 'module' field".into(),
                ));
            }
        };
        let entry = params
            .get("entry")
            .and_then(|v| v.as_str())
            .unwrap_or("run")
            .to_string();

        let kernel = match ex.kernel.clone().and_then(|w| w.upgrade()) {
            Some(k) => k,
            None => {
                return Err(StepError::Failed(
                    "wasm step requires a kernel constructed via Kernel::into_arc; \
                     this kernel was never wrapped"
                        .into(),
                ));
            }
        };

        let plugin = ex.plugin_name().to_string();
        let module = match kernel
            .registry()
            .get_plugin_wasm_module(&plugin, &module_name)
        {
            Some(m) => m,
            None => {
                return Err(StepError::Failed(format!(
                    "wasm step: no module named '{module_name}' registered for plugin \
                     '{plugin}'; check the manifest's wasm_modules field"
                )));
            }
        };

        let engine = ex.engine.clone();
        let limits = ex.limits();
        // Store data is a `WasmStoreLimits` that doubles as the
        // wasmtime `ResourceLimiter` — fuel covers CPU, the limiter
        // covers `memory.grow`. A wasm module that tries to allocate
        // past the per-invocation memory cap traps cleanly via
        // `Trap::OOM` instead of OOMing the host process. Mirrors the
        // model `ScriptRuntimeStoreData` uses for the `script` step type.
        let mut store = wasmtime::Store::new(
            &engine,
            WasmStoreLimits {
                budget: crate::kernel::resource_budget::ResourceBudget::new(&limits),
            },
        );
        store.limiter(|state| state as &mut dyn wasmtime::ResourceLimiter);
        // The shared engine is configured with `consume_fuel(true)` so
        // every store derived from it must be allocated fuel before
        // execution — otherwise even a no-op function traps with
        // `OutOfFuel` on its first instruction. Use the per-invocation
        // fuel budget that bounds `script` interpreter sub-instances;
        // the value suits general-purpose wasm. The yield
        // interval keeps a CPU-bound module from pinning its tokio
        // worker for the whole budget — same rationale as the script
        // runtime's store setup.
        let _ = store.set_fuel(limits.fuel_budget);
        let _ = store
            .fuel_async_yield_interval(Some(super::script_runtime_host::FUEL_ASYNC_YIELD_INTERVAL));
        let linker = wasmtime::Linker::<WasmStoreLimits>::new(&engine);

        let instance = linker
            .instantiate_async(&mut store, &module)
            .await
            .map_err(|e| {
                StepError::Failed(format!(
                    "wasm step: module '{module_name}' instantiation failed: {e}"
                ))
            })?;

        let entry_fn = instance
            .get_typed_func::<(), ()>(&mut store, &entry)
            .map_err(|e| {
                StepError::Failed(format!(
                    "wasm step: module '{module_name}' has no `() -> ()` export named \
                     '{entry}': {e}"
                ))
            })?;

        entry_fn.call_async(&mut store, ()).await.map_err(|e| {
            // Name the resource cap when one tripped — the bare trap
            // display is just a wasm backtrace with no indication that
            // the failure was the fuel meter rather than module logic.
            // Memory-cap denials don't need the same treatment:
            // `memory.grow` returns -1 to the module rather than
            // trapping, so whatever trap follows is the module's own.
            if matches!(
                e.downcast_ref::<wasmtime::Trap>(),
                Some(wasmtime::Trap::OutOfFuel)
            ) {
                // Keep `{e}` — the trap display carries the wasm
                // backtrace, i.e. WHERE execution was when the meter
                // ran dry, which a module author debugging a near-miss
                // budget wants.
                StepError::Failed(format!(
                    "wasm step: module '{module_name}' exhausted its fuel budget \
                     ({} units) during '{entry}': {e}",
                    limits.fuel_budget
                ))
            } else {
                StepError::Failed(format!(
                    "wasm step: module '{module_name}' trapped during '{entry}': {e}"
                ))
            }
        })?;

        Ok(StepOutput::from(Value::Null))
    })
}

/// Execute a plugin-supplied step type alias — dispatch into the plugin's
/// declared action with the step's params resolved as the action input.
///
/// Registered once per alias name on the runtime's linker via the same
/// pathway the built-ins use, so `run_step` dispatches it through the
/// same `step_<alias>` import shape as every other body. The
/// alias → (plugin, action) lookup is in the kernel's
/// [`super::PluginRegistry`].
///
/// Step shape (consumer manifest):
///
/// ```jsonc
/// {
///   "type": "sigv4.sign",         // alias declared by plugin `sigv4`
///   "id": "signed",
///   "params": {
///     "key": "$steps.foo.result", // step params flow as the action input
///     "data": "..."               // no `input` wrapper needed
///   }
/// }
/// ```
///
/// Behaviourally equivalent to `{"type":"invoke","params":{"plugin":
/// "<provider>","action":"<target>","input":{<params>}}}`. Recursion is capped by the
/// same [`INVOKE_MAX_DEPTH`] counter, so an alias cycle terminates the
/// same way a by-role one does.
pub(crate) fn step_alias_dispatch<'a>(
    ex: &'a mut ExecutionState,
    params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move {
        let step_id = ex.current_step_id().to_string();

        // Recursion cap. Hit before any real work so a cycle errors cheaply.
        if ex.invoke_depth() >= INVOKE_MAX_DEPTH {
            return Err(StepError::Failed(format!(
                "invoke recursion cap ({}) exceeded at alias step '{}'",
                INVOKE_MAX_DEPTH, step_id
            )));
        }

        let kernel = match ex.kernel.clone().and_then(|w| w.upgrade()) {
            Some(k) => k,
            None => {
                return Err(StepError::Failed(format!(
                    "alias step '{step_id}' requires a kernel constructed via \
                     Kernel::into_arc; this kernel was never wrapped"
                )));
            }
        };

        let step_type = ex.current_step_type().to_string();
        // The written alias resolved to its registry key along the
        // caller's chain — decided at invocation setup, like every step
        // type. `run_step` already refused anything unresolvable.
        let Some(key) = ex.step_type_access.resolve(&step_type).map(str::to_string) else {
            return Err(StepError::Failed(format!(
                "alias step '{step_id}' resolves to unknown step type '{step_type}'"
            )));
        };

        // Resolve the alias to (plugin, action). The registry is a
        // catalogue; aliases hold at most one candidate (duplicates are
        // rejected at registration).
        let (plugin_name, action_name) = match kernel
            .registry()
            .step_type_alias_candidates(&key)
            .into_iter()
            .next()
        {
            Some(pair) => pair,
            None => {
                return Err(StepError::Failed(format!(
                    "alias step '{step_id}' resolves to unknown step type '{step_type}'"
                )));
            }
        };

        // All step params flow as the action's input — alias steps don't
        // use an `input` wrapper. Template references inside the params
        // resolve against the parent ctx just like any other step's params.
        let ctx = ex.resolution_context();
        let resolved_input = ex.resolve_value_with(params, &ctx);

        let caller_plugin = ex.plugin_name().to_string();
        let parent_depth = ex.invoke_depth();
        let config = ex.config().clone();
        let secret_resolver = ex.secret_resolver().cloned();
        let exec_ctx = ex.exec_ctx().clone();
        let parent_cancel = ex.cancel_token();
        let parent_deadline = ex.wallclock_deadline();

        // Capability gate: an alias step dispatches into the impl
        // plugin's action, so using one against another plugin
        // requires the `step_type:<alias>` grant. Aliases the caller
        // itself registered need no grant.
        if plugin_name != caller_plugin
            && !super::permissions::check_step_type(
                kernel.registry().permissions_for(&caller_plugin),
                &step_type,
            )
            .is_granted()
        {
            return Err(StepError::Failed(format!(
                "alias step '{step_id}': plugin '{caller_plugin}' lacks \
                 step_type:{step_type} permission (add it to the manifest's \
                 `permissions` list)"
            )));
        }

        // Alias resolution itself stays in the registry — the alias
        // table is a structural data query
        // (`step_type_alias_candidates`). Selection of which plugin
        // backs the resolved `(plugin, action)` pair happens in the
        // orchestrator below as a ByPlugin dispatch.
        let alias_request = super::dispatch::DispatchRequest::ByPlugin {
            plugin: &plugin_name,
            action: &action_name,
            input: &resolved_input,
            // Alias steps inherit no per-call hints — the alias
            // name itself is the entire selection signal. Authors who
            // want to nudge orchestrator policy use a plain `invoke`
            // step with a `hints` block.
            hints: &Value::Null,
        };
        let plan = match kernel
            .prepare_dispatch_via_orchestrator(
                alias_request.clone(),
                &exec_ctx,
                Some(&caller_plugin),
                &config,
            )
            .await
        {
            Ok(p) => p,
            Err(e) => {
                return Err(StepError::Failed(format!(
                    "alias step '{step_id}' ('{step_type}') dispatch policy: {e}"
                )));
            }
        };
        // `step_type:<alias>` above authorised dispatch to the alias
        // OWNER. If the orchestrator resolved somewhere else, that
        // redirect is an ordinary cross-plugin invoke and needs an
        // `invoke:` grant — otherwise the alias grant would be a
        // laundering path around the invoke gate.
        if let Err(reason) = kernel.authorize_resolved_dispatch(
            &caller_plugin,
            &alias_request,
            &plan,
            Some(&plugin_name),
        ) {
            return Err(StepError::Failed(format!(
                "alias step '{step_id}' ('{step_type}'): {reason}"
            )));
        }
        match kernel
            .execute_action_invoked(
                &plan.plugin,
                &plan.action,
                resolved_input,
                &plan.config,
                secret_resolver,
                &exec_ctx,
                parent_depth,
                Some(parent_cancel),
                parent_deadline,
            )
            .await
        {
            Ok(action_result) => Ok(StepOutput::from(action_result.output)),
            Err(e) => Err(StepError::from_callee(&plan.plugin, &plan.action, e)),
        }
    })
}

// ---------------------------------------------------------------------------
// Kernel service host functions (control flow helpers)
// ---------------------------------------------------------------------------

/// Check if the last step at the given index succeeded (has a non-null result).
fn host_step_success(caller: wasmtime::Caller<'_, ExecutionState>, step_index: i32) -> i32 {
    let step_index = step_index as usize;
    let state = caller.data();

    let succeeded = state
        .action
        .steps
        .get(step_index)
        .and_then(|step| state.step_results.get(&step.id))
        .is_some_and(|v| !v.is_null());
    i32::from(succeeded)
}

/// Begin a forEach iteration. Extracts items from the source and pushes
/// a new ForEachState onto the stack. Returns the number of items (0 = skip).
fn host_begin_foreach(mut caller: wasmtime::Caller<'_, ExecutionState>, step_index: i32) -> i32 {
    let step_index = step_index as usize;
    let state = caller.data();

    let step = match state.action.steps.get(step_index) {
        Some(s) => s.clone(),
        None => return 0,
    };

    let path = step
        .params
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("$");
    let source = step.params.get("source").and_then(|v| v.as_str());
    let source_data = state.get_source_result(source);

    let items = match state.eval_path(path, source_data) {
        Value::Array(arr) => arr,
        Value::Null => vec![],
        // An empty object is how a Lua-style runtime serializes an
        // empty table — it can't distinguish `[]` from `{}`. For
        // for_each that means "no items", so don't spuriously run a
        // single iteration over `{}`.
        Value::Object(m) if m.is_empty() => vec![],
        single => vec![single],
    };

    let count = items.len() as i32;
    let state = caller.data_mut();
    state.foreach_stack.push(ForEachState {
        items: ForEachItems::Values(items),
        index: 0,
        current: None,
        current_value: None,
        results: Vec::new(),
    });

    count
}

/// Advance to the next forEach item. Returns 1 if there's an item to process,
/// 0 if iteration is complete. Sets `current` so `{{$item}}` resolves to the
/// item the body will see, then advances `index` past it.
fn host_next_foreach(mut caller: wasmtime::Caller<'_, ExecutionState>, _step_index: i32) -> i32 {
    let state = caller.data_mut();

    if let Some(foreach) = state.foreach_stack.last_mut() {
        if foreach.index < foreach.items.len() {
            foreach.current = Some(foreach.index);
            foreach.current_value = foreach.items.item_at(foreach.index);
            foreach.index += 1;
            1
        } else {
            foreach.current = None;
            foreach.current_value = None;
            0
        }
    } else {
        0
    }
}

/// End a forEach iteration. Pops the state and stores collected results.
fn host_end_foreach(mut caller: wasmtime::Caller<'_, ExecutionState>, step_index: i32) -> i32 {
    let step_index = step_index as usize;
    let state = caller.data_mut();

    let step_id = match state.action.steps.get(step_index) {
        Some(s) => s.id.clone(),
        None => return 0,
    };

    if let Some(foreach) = state.foreach_stack.pop() {
        state.store_step_result(&step_id, Value::Array(foreach.results));
    }

    1
}

/// Begin a `repeat` iteration. Reads the loop bound from
/// `params.count` (template-resolved against the parent context if given
/// as a string) and pushes a [`ForEachState`] onto the stack whose
/// items are the indices `0..count`, produced on demand rather than
/// materialised. The current iteration number is then reachable from
/// the manifest as `{{$item}}`, reusing the same binding `for_each`
/// already exposes.
///
/// Returns the loop count on success, -1 on a malformed `count` (with
/// `last_error` set), 0 when the step index is out of range.
/// Sharing [`ForEachState`] (and therefore the existing `next_foreach` /
/// `end_foreach` host fns) means `repeat` needs only this one host
/// function plus a [`crate::kernel::runtime::run_step`] dispatch entry —
/// no parallel iteration state machine.
pub(crate) fn host_begin_repeat(
    mut caller: wasmtime::Caller<'_, ExecutionState>,
    step_index: i32,
) -> i32 {
    let step_index = step_index as usize;
    let state = caller.data();

    let step = match state.action.steps.get(step_index) {
        Some(s) => s.clone(),
        None => return 0,
    };

    // `count` can be an inline integer or a string template
    // (`{{$config.iterations}}`) that resolves to one. Anything else
    // is a manifest authoring bug.
    let raw_count = step.params.get("count").cloned().unwrap_or(Value::Null);
    let ctx = state.resolution_context();
    let resolved = resolve::resolve_value(&raw_count, &ctx);

    let count = match resolved {
        Value::Number(n) if n.is_u64() => n.as_u64().unwrap_or(0),
        Value::Number(n) if n.is_i64() => match n.as_i64() {
            Some(v) if v >= 0 => v as u64,
            _ => {
                let state = caller.data_mut();
                state.last_error = Some(format!(
                    "repeat step '{}': count must be a non-negative integer",
                    step.id
                ));
                return -1;
            }
        },
        Value::String(s) => match s.parse::<u64>() {
            Ok(v) => v,
            Err(_) => {
                let state = caller.data_mut();
                state.last_error = Some(format!(
                    "repeat step '{}': count string '{s}' did not parse as a \
                     non-negative integer",
                    step.id
                ));
                return -1;
            }
        },
        other => {
            let state = caller.data_mut();
            state.last_error = Some(format!(
                "repeat step '{}': count must be an integer or a template \
                 resolving to one; got {other:?}",
                step.id
            ));
            return -1;
        }
    };

    // Refuse a count past `i32::MAX` rather than casting it: the return
    // type is `i32`, and a runaway count is a manifest bug better
    // failed visibly than silently truncated.
    if count > i32::MAX as u64 {
        let state = caller.data_mut();
        state.last_error = Some(format!(
            "repeat step '{}': count {count} exceeds i32::MAX — refuse to expand",
            step.id
        ));
        return -1;
    }

    // Stores the bound, not the range. Expanding it would be a
    // one-line denial of service — see [`ForEachItems`].
    let returned = count as i32;
    let state = caller.data_mut();
    state.foreach_stack.push(ForEachState {
        items: ForEachItems::Count(count),
        index: 0,
        current: None,
        current_value: None,
        results: Vec::new(),
    });
    returned
}
