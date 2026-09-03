//! Gwead wasm microkernel — the core of the plugin engine.
//!
//! The kernel is a small Rust host that:
//! 1. Registers plugins by SPI role + name
//! 2. Validates declarative JSON manifests and plans each action's
//!    steps into a DAG
//! 3. Executes actions with a host-side scheduler that dispatches step
//!    bodies in topological order
//! 4. Runs wasm — plugin `wasm`-kind step bodies and script-runtime
//!    interpreter modules — through wasmtime
//!
//! Step types are host-provided functions registered via the wasmtime Linker.
//! From a wasm module's perspective they're imports.

pub mod abi;
pub mod dag;
pub mod dispatch;
#[cfg(test)]
mod dispatch_role_tests;
#[cfg(test)]
mod dispatch_tests;
pub mod exec_context;
pub mod execute_request;
pub mod host_api;
pub mod identity;
pub mod invoke;
mod manifest_schema;
pub mod native_impls;
pub mod permissions;
pub mod registry;
pub(crate) mod resource_budget;
pub mod runtime;
pub mod runtime_dataflow;
pub mod script_runtime_host;
pub mod secrets;
pub mod streams;
pub mod types;

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, Weak};

use serde_json::Value;
use tracing;
use wasmtime::Module;

use self::types::StepDef;

use self::dispatch::{DispatchContext, DispatchOrchestrator, DispatchPlan, DispatchRequest};
use self::registry::PluginRegistry;
use self::runtime::WasmRuntime;
use self::secrets::SecretResolver;
use self::types::{Action, ActionResult, PluginManifest};
use crate::spi::loader::SpiRegistry;
use crate::spi::validator;

// Embedder concerns (storage, tenancy, identity) live outside the
// kernel; the opaque [`ExecutionContext`] is the only embedder-defined
// value the kernel carries.
pub use self::exec_context::ExecutionContext;

// Re-exports for host-provided step types. Plugin authors implement
// step type bodies against the [`PluginExecution`] trait, submit them
// via `inventory::submit!` with a `NativeStepImplEntry`, and declare
// `kind: "native"` impl entries in their manifest. See
// [`self::native_impls`] for the full pattern.
pub use self::host_api::{PluginExecution, StepError, StepOutput};

/// Every step-type def and impl a manifest declares, validated and
/// resolved, ready for an infallible commit.
///
/// This type exists so `Kernel::register_plugin` can do all of its
/// rejecting before any of its mutating — see the comment above the
/// `prepare_step_types` call for why the split matters.
struct PreparedStepTypes {
    defs: Vec<self::types::StepTypeDef>,
    impls: Vec<PreparedStepImpl>,
}

/// One `stepTypeImpls` entry with its reference already resolved: a
/// wasm module name known to be declared by the same manifest, or a
/// concrete function pointer pulled out of the native / intrinsic
/// table. Nothing here can fail to install.
enum PreparedStepImpl {
    Wasm {
        step_type: String,
        matches: Option<String>,
        wasm_module: String,
    },
    Native {
        step_type: String,
        body: self::native_impls::NativeStepImpl,
    },
    Intrinsic {
        step_type: String,
        body: self::native_impls::IntrinsicStepImpl,
    },
}

/// One entry in a `Kernel::dispatch_event` result vector.
///
/// Wraps the underlying `ActionResult` with the `(plugin, action)`
/// identity that produced it so callers (e.g. the embedder's event
/// dispatcher) can log per-subscriber failures with
/// names rather than indices.
#[derive(Debug)]
pub struct DispatchedActionResult {
    pub plugin: String,
    pub action: String,
    pub result: Result<ActionResult, KernelError>,
}

/// Handle to a continuous action started via
/// [`ExecuteActionRequest::into_continuous_handle`](execute_request::ExecuteActionRequest::into_continuous_handle).
///
/// The kernel drives the action's DAG in a loop on a spawned tokio
/// task, sending one [`Result<ActionResult, KernelError>`] per
/// iteration to `events`.
///
/// # Termination
///
/// The loop terminates when, and only when:
///
/// - [`Self::cancel`] (or [`Self::shutdown`]) is invoked, or
/// - the receiver end of `events` is dropped, so the kernel can no
///   longer send — it exits cleanly rather than buffering
///   indefinitely.
///
/// **An error does not stop it.** A permanently failing action emits
/// `Err` every `interval_ms` forever. There is no notion of an
/// "unrecoverable" failure that stops the loop on its own — an
/// integrator expecting auto-stop hot-loops on a broken action.
/// Decide what counts as fatal yourself, and cancel.
///
/// # You must drain `events`
///
/// The channel is bounded (8 results). Once it fills, the driver
/// blocks in its send and no further iterations run — that is
/// deliberate backpressure, not a bug. The send races the cancel
/// token, so [`Self::shutdown`] still completes promptly on an
/// undrained channel instead of hanging forever.
///
/// Use [`Self::shutdown`] to cancel and await the driver task in one
/// call when the caller wants ordered cleanup; otherwise call
/// `cancel()` then drop the events receiver.
pub struct ContinuousHandle {
    /// Per-iteration results. One entry per DAG run. The sender
    /// closes when the driver exits.
    pub events: tokio::sync::mpsc::Receiver<Result<ActionResult, KernelError>>,
    cancel: tokio_util::sync::CancellationToken,
    join: tokio::task::JoinHandle<()>,
}

impl ContinuousHandle {
    /// Signal the driver to stop. Returns immediately — the driver
    /// finishes the current iteration before exiting. Call
    /// [`Self::shutdown`] to wait for that.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Cancel and await the driver. Resolves once the loop has
    /// exited; any remaining buffered events stay in `self.events`
    /// for the caller to drain after this completes.
    pub async fn shutdown(self) -> Result<(), tokio::task::JoinError> {
        self.cancel.cancel();
        self.join.await
    }

    /// The underlying [`tokio_util::sync::CancellationToken`]. Clone
    /// it into other tasks that should observe shutdown — e.g., a
    /// long-poll http_call can hand its receiver a
    /// `tokio::select! { _ = token.cancelled() => break, item = source.next() => ... }`
    /// race.
    pub fn cancel_token(&self) -> tokio_util::sync::CancellationToken {
        self.cancel.clone()
    }
}

/// Telemetry event emitted by a streaming-dataflow pipeline.
///
/// The scheduler emits coarse lifecycle events (`StepStarted`,
/// `StepCompleted`, `StepFailed`, `PipelineCompleted`); step bodies
/// can emit fine-grained `StepProgress` via
/// `ExecutionState::emit_progress` to report bytes-throughput,
/// items-processed, or any other domain-specific payload.
///
/// Delivered through [`DataflowHandle::events`] — bounded mpsc channel
/// with `try_send` semantics. A slow receiver drops events rather than
/// blocking the producer; telemetry is best-effort, not load-bearing.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DataflowEvent {
    /// A step task has been spawned and started executing.
    StepStarted { step_id: String },
    /// A step task has finished normally; `ok` is `true`. A failure
    /// is reported as [`Self::StepFailed`] instead.
    StepCompleted { step_id: String, ok: bool },
    /// A step task failed in a way the scheduler did NOT tolerate.
    /// Pipeline tear-down is in progress.
    StepFailed { step_id: String, error: String },
    /// Step-body-emitted progress. `payload` is whatever the step
    /// chooses to report — typically a JSON object like
    /// `{ "bytes_written": 12345 }`. Order within a single step
    /// matches the order of `emit_progress` calls; ordering across
    /// concurrent steps is not guaranteed.
    StepProgress { step_id: String, payload: Value },
    /// The pipeline has terminated. `ok = true` only when the pipeline
    /// completed normally (every step returned success and the cancel
    /// token never fired); `false` on a step error, an unrecoverable
    /// failure, or cooperative cancellation. Note that `ok: false`
    /// does NOT imply [`DataflowHandle::result`] resolves `Err(_)` —
    /// cooperative cancellation surfaces here as `ok: false` while
    /// the result still carries an `Ok(ActionResult)` so callers can
    /// inspect per-step state (typically `step_results[<step>]`
    /// records why the step exited).
    ///
    /// # Delivery
    ///
    /// Delivered at most once per handle, on a best-effort basis that
    /// survives a full channel: `try_send` first, and on failure a
    /// detached task that awaits capacity. It is deliberately *not* a
    /// `send().await` on the scheduler's own task — blocking the
    /// scheduler on a full channel would deadlock it against the
    /// subscriber that drains it.
    ///
    /// It covers the panic and wallclock-timeout paths as well as the
    /// ordinary exit: a panicked step task and a timeout that drops the
    /// scheduler future mid-flight both still emit it. Otherwise
    /// `result` would resolve `Err` while a subscriber keyed on this
    /// event waited for channel-close or forever.
    ///
    /// **Do not treat it as guaranteed.** If the events receiver is
    /// dropped, or the process is killed, nothing arrives. Treat
    /// channel-close as terminal too.
    PipelineCompleted { ok: bool },
}

/// Handle to a streaming-dataflow pipeline started via
/// [`ExecuteActionRequest::into_dataflow_handle`](execute_request::ExecuteActionRequest::into_dataflow_handle).
///
/// Analogous to [`ContinuousHandle`] but for the dataflow form: the
/// pipeline is one DAG run that may span many seconds while a
/// long-running producer streams bytes, so the caller gets two
/// channels — a stream of telemetry events ([`Self::events`]) for
/// progress UIs, and a one-shot [`Self::result`] that resolves with
/// the final [`ActionResult`] at pipeline termination.
///
/// The pipeline terminates when:
/// - every step task completes (normal success)
/// - a step task fails unrecoverably (the scheduler fires the cancel
///   token to tear down the rest)
/// - [`Self::cancel`] is invoked
/// - the events receiver is dropped — scheduler keeps running, only
///   the telemetry stream goes away (the pipeline's final
///   `ActionResult` still resolves through `result`)
///
/// # Dropping this handle DETACHES the pipeline — it does not cancel it
///
/// `join` is a plain [`tokio::task::JoinHandle`] and `cancel` is a
/// token *clone*; dropping a clone does not fire the token. So
/// dropping the handle leaves the whole task tree running with nobody
/// listening. Combined with dataflow's deliberate lack of a default
/// wallclock cap, dropping the handle of a never-EOF producer leaks a
/// permanently running pipeline.
///
/// Call [`Self::cancel`] or [`Self::shutdown`] before letting the
/// handle go. If you want drop to tear down, hold the token from
/// [`Self::cancel_token`] in a guard of your own.
pub struct DataflowHandle {
    /// Per-event telemetry stream. Bounded; full-channel sends are
    /// dropped rather than blocking the scheduler / step bodies.
    pub events: tokio::sync::mpsc::Receiver<DataflowEvent>,
    /// The pipeline's final [`ActionResult`]. Resolves once at
    /// termination. Sender drops afterward, so a second `.await`
    /// after the first reply has been taken returns `Err(RecvError)`.
    pub result: tokio::sync::oneshot::Receiver<Result<ActionResult, KernelError>>,
    cancel: tokio_util::sync::CancellationToken,
    join: tokio::task::JoinHandle<()>,
}

impl DataflowHandle {
    /// Signal the pipeline to tear down. Returns immediately —
    /// cancellation is **cooperative**: every step body holds a
    /// clone of this token in its `ExecutionState` and observes it via
    /// `state.cancel.is_cancelled()` (or `tokio::select! {
    /// _ = state.cancel.cancelled() => break, _ = io_work => ... }`).
    /// Once every step exits, [`Self::result`] resolves with an
    /// `Ok(ActionResult)` carrying whatever `step_results` were
    /// written before tear-down (typically including a
    /// `cancelled: true` sidecar per step). The events channel
    /// emits a final [`DataflowEvent::PipelineCompleted`] with
    /// `ok: false` to distinguish a cancelled run from a clean
    /// completion.
    ///
    /// Misbehaving step types that ignore the token would hang the
    /// pipeline indefinitely — a dataflow action that declares no
    /// `wallclock_timeout_ms` has NO automatic backstop (streaming
    /// pipelines legitimately run minutes-to-days; see
    /// `Action::wallclock_timeout_ms` for the precedence rules).
    /// Manifests that want a hard kill declare the cap explicitly.
    /// See [`Self::shutdown`] for "cancel and await the driver" in
    /// one call.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Clone of the underlying cancellation token. Useful for
    /// handing the same token into other async layers (HTTP request
    /// cancellation, parent `select!` arms, etc.) so they all tear
    /// down on a single signal.
    pub fn cancel_token(&self) -> tokio_util::sync::CancellationToken {
        self.cancel.clone()
    }

    /// Cancel and await the driver task. The events / result
    /// receivers stay valid for the caller to drain afterward.
    pub async fn shutdown(self) -> Result<(), tokio::task::JoinError> {
        self.cancel.cancel();
        self.join.await
    }
}

/// Handle to a streaming-output dataflow pipeline started via
/// [`ExecuteActionRequest::into_dataflow_streaming_handle`](execute_request::ExecuteActionRequest::into_dataflow_streaming_handle).
///
/// Differs from [`DataflowHandle`] in one significant way: the action's
/// single long-running producer step writes to a caller-owned writable,
/// and the matching readable side is exposed up front as
/// [`Self::output`]. The caller drains `output` while the pipeline
/// runs, enabling HTTP-side relay (SSE, chunked transfer) of the
/// producer's bytes to a remote client.
///
/// [`Self::events`], [`Self::result`], [`Self::cancel`], and
/// [`Self::shutdown`] carry the same semantics as their
/// `DataflowHandle` counterparts — **including that dropping this
/// handle detaches the pipeline rather than cancelling it**.
///
/// # You must drain `output` to EOF
///
/// This is an obligation, not a usage suggestion. The fan-out pipe
/// behind `output` is bounded at
/// [`STREAM_FANOUT_CAPACITY`](self::streams::STREAM_FANOUT_CAPACITY)
/// chunks. An undrained `output` blocks the producer's `stream_write`,
/// which means [`Self::result`] never resolves — and a dataflow action
/// has no default wallclock backstop, so nothing breaks the stall.
/// Drain it, or cancel.
pub struct DataflowStreamingHandle {
    /// Live readable for the action's long-running producer step. EOF
    /// resolves when the producer drops its writable handle — typically
    /// at pipeline termination (success, error, or cancel).
    ///
    /// Must be drained to EOF — see the type-level docs.
    pub output: self::streams::ReadableSource,
    /// Per-event telemetry stream. Bounded; full-channel sends are
    /// dropped rather than blocking the scheduler / step bodies.
    pub events: tokio::sync::mpsc::Receiver<DataflowEvent>,
    /// The pipeline's final [`ActionResult`]. Resolves once at
    /// termination. Useful for surfacing `resultMapping` fields the
    /// caller wants to include in a terminating in-band event (an id
    /// the client needs after the stream ends, say).
    pub result: tokio::sync::oneshot::Receiver<Result<ActionResult, KernelError>>,
    cancel: tokio_util::sync::CancellationToken,
    join: tokio::task::JoinHandle<()>,
}

impl DataflowStreamingHandle {
    /// Signal the pipeline to tear down. Cooperative cancellation —
    /// every step body holds a clone of this token. See
    /// [`DataflowHandle::cancel`] for the full contract.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Clone of the underlying cancellation token. Useful for handing
    /// the same token into other async layers (HTTP request
    /// cancellation, parent `select!` arms, etc.) so they all tear
    /// down on a single signal.
    pub fn cancel_token(&self) -> tokio_util::sync::CancellationToken {
        self.cancel.clone()
    }

    /// Cancel and await the driver task. The `output` / `events` /
    /// `result` channels stay valid for the caller to drain
    /// afterward.
    pub async fn shutdown(self) -> Result<(), tokio::task::JoinError> {
        self.cancel.cancel();
        self.join.await
    }
}

/// Hard cap on event-dispatch cascade depth.
///
/// Mirrors [`host_api::INVOKE_MAX_DEPTH`] but tracks a different
/// recursion shape: explicit `invoke` calls (`invoke_depth`) versus
/// event-driven cascades (`dispatch_depth`). Both can coexist in the
/// same execution chain.
///
/// When `Kernel::dispatch_event` is called with `parent_dispatch_depth`
/// already at the cap, it logs a warning and returns an empty result
/// — the current action finishes but its outgoing events don't
/// propagate, terminating event-driven cycles cleanly.
pub const DISPATCH_MAX_DEPTH: u32 = 16;

/// One entry of [`KernelConfig::trusted_step_type_providers`]: a plugin
/// identity the embedder trusts to fill a kernel-defined step-type slot.
///
/// A newtype rather than a bare `String` so the entry can grow —
/// a selector restriction, an expiry, an audit label — without a
/// breaking change to `KernelConfig`'s public field. `#[non_exhaustive]`;
/// build with [`TrustedProvider::new`] or the
/// [`trusting_step_type_provider`](KernelConfig::trusting_step_type_provider)
/// builders.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TrustedProvider {
    /// The plugin's qualified identity — `name` in root,
    /// `namespace/name` otherwise.
    pub identity: String,
}

impl TrustedProvider {
    pub fn new(identity: impl Into<String>) -> Self {
        Self {
            identity: identity.into(),
        }
    }
}

/// One entry of [`KernelConfig::native_impl_bindings`]: an embedder's
/// authorisation for `binder` to run the native body `impl_ref`, which
/// another plugin ships.
///
/// A struct rather than a `(String, String)` tuple for the same reason
/// as [`TrustedProvider`]: the pair is the minimum, not the ceiling.
/// `#[non_exhaustive]`; build with [`NativeImplBinding::new`] or
/// [`allowing_native_impl_binding`](KernelConfig::allowing_native_impl_binding).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NativeImplBinding {
    /// Qualified identity of the plugin doing the binding.
    pub binder: String,
    /// The exact `implRef` being bound — no wildcards.
    pub impl_ref: String,
}

impl NativeImplBinding {
    pub fn new(binder: impl Into<String>, impl_ref: impl Into<String>) -> Self {
        Self {
            binder: binder.into(),
            impl_ref: impl_ref.into(),
        }
    }
}

/// The operator half of the kernel's own two-key native-impl binding
/// rule, seeded into every kernel at boot.
///
/// Native-impl ownership keys on an `implRef`'s middle segment, and
/// `intrinsics` is not `gwead_intrinsics`, so the engine's own manifest
/// does not qualify for the free (same-owner) path. It is authorised
/// explicitly instead: these entries are the operator grant, and the
/// matching `bind:native_impl:` permissions in
/// `resources/manifests/intrinsics.json` are the manifest half. Holding
/// the engine to its own rule keeps the boot path from becoming an
/// unguarded door, and makes that manifest a worked example of the
/// pattern.
///
/// Only the `native`-kind intrinsics appear here. The `intrinsic` kind
/// resolves against a separate table containing nothing but the
/// engine's own submissions, so it needs no ownership rule.
const INTRINSIC_NATIVE_BINDINGS: &[(&str, &str)] = &[
    ("gwead_intrinsics", "gwead.intrinsics.throw_error"),
    ("gwead_intrinsics", "gwead.intrinsics.let"),
];

/// The Gwead microkernel.
///
/// ## Hot-reload coordination
///
/// All lifecycle entry points ([`Self::load_manifest`],
/// [`Self::unload_manifest`], [`Self::reload_manifest`],
/// [`Self::register_plugin`], etc.) take `&mut self`. Every
/// invocation path ([`Self::execute`] and friends) takes
/// `&self` — typically through an `Arc<Kernel>` because alias
/// dispatch, parallel-wave scheduling, and the invoke step type all
/// hold the kernel across `.await` points.
///
/// The borrow checker therefore enforces a hard separation:
/// **lifecycle mutations cannot overlap with any in-flight
/// invocation**. The "reject in-flight" policy falls out for free.
///
/// **What an embedder must do** to mutate manifests after the
/// kernel is in production use (post-`into_arc`):
///
/// 1. **Boot-swap**: build a fresh `Kernel`, load every manifest
///    into it, and atomically swap the `Arc<Kernel>` reference the
///    request handlers see. The simplest pattern; old invocations
///    drain naturally as their `Arc` clones drop.
/// 2. **Lock around the kernel**: hold the kernel inside an
///    `Arc<tokio::sync::RwLock<Kernel>>`. Invocations take a read
///    lock for the entire `.await` chain; the lifecycle path takes
///    a write lock that the runtime blocks until every read lock
///    is released. Every invocation site has to participate in the
///    lock — this is not transparent.
///
/// (1) has the lightest coupling and is the recommended pattern for
/// production hot-reload.
pub struct Kernel {
    runtime: WasmRuntime,
    registry: PluginRegistry,
    spi_registry: SpiRegistry,
    /// Per-invocation resource caps. Plumbed through to the
    /// wasm runtime for fuel + memory enforcement on script-runtime
    /// sub-stores, and to `execute_dag` for the action-level wallclock
    /// timeout.
    limits: RuntimeLimits,
    /// Native step-type implementations submitted by plugin crates via
    /// the `inventory` crate. Manifest `stepTypeImpls`
    /// entries with `kind: "native"` resolve their `implRef` against
    /// this table at `register_plugin` time. Empty by default — kernels
    /// booted without compiling in any plugin crates can still load
    /// manifests, they just can't reference native impls.
    native_step_impls: self::native_impls::NativeStepImplTable,
    /// Kernel-internal step bodies — `invoke`, `wasm`, `script`,
    /// and the per-alias dispatcher. Manifest `stepTypeImpls` entries
    /// with `kind: "intrinsic"` resolve their `implRef` against this
    /// table at `register_plugin` time. Never embedder-supplied; built
    /// from the inventory slice at boot. These bodies take a concrete
    /// `&mut ExecutionState` because they need engine internals the
    /// public plugin surface doesn't expose.
    intrinsic_step_impls: self::native_impls::IntrinsicStepImplTable,
    /// Dispatch orchestrator. Always populated — boot
    /// promotes `KernelConfig::dispatch_orchestrator = None` to
    /// [`dispatch::default_orchestrator`] so dispatch sites never
    /// have to branch on presence.
    dispatch_orchestrator: Arc<dyn DispatchOrchestrator>,
    /// Embedder-registered secret resolver, if any. `None` means no
    /// execution in this kernel has credentials. See
    /// [`Self::pull_secrets`].
    secret_resolver: Option<Arc<dyn SecretResolver>>,
    /// Plugins the embedder authorises to supply implementations
    /// behind step types they did not define. Copied from
    /// [`KernelConfig::trusted_step_type_providers`] at boot; consulted
    /// by [`Self::check_step_type_impl_claim`]. Empty by default.
    trusted_step_type_providers: Vec<TrustedProvider>,
    /// `(binder identity, implRef)` pairs authorised to bind a native
    /// body another plugin ships. Copied from
    /// [`KernelConfig::native_impl_bindings`] at boot and consulted by
    /// [`Self::check_native_impl_binding`].
    ///
    /// Seeded at boot with the kernel's own entries for the intrinsics
    /// manifest — see [`INTRINSIC_NATIVE_BINDINGS`]. The engine
    /// satisfies this rule the same way an embedder does rather than
    /// skipping it: a boot path that bypassed the check would be one
    /// more door with no guard, and the intrinsics manifest doubles as
    /// the worked example of the two-key pattern.
    native_impl_bindings: Vec<NativeImplBinding>,
    /// Embedder permission categories a manifest may name. Copied from
    /// [`KernelConfig::app_permission_categories`] at boot, after their
    /// names have been checked, and consulted by every registration
    /// through [`permissions::parse_manifest_permissions`].
    ///
    /// The kernel never enforces one of these grants. It only refuses
    /// to store a grant nobody claims to understand.
    app_permission_categories: Vec<permissions::AppPermissionCategory>,
    /// Back-reference to the `Arc<Kernel>` that owns us.
    ///
    /// Populated by [`Kernel::into_arc`]. Used by the `invoke` step type
    /// to dispatch into another plugin's action without taking a
    /// permanent strong reference (which would cycle through `ExecutionState`
    /// and prevent `Drop`). Empty before `into_arc` is called — code
    /// that never uses `invoke` works without the wrap.
    self_weak: OnceLock<Weak<Self>>,
    /// Counter for [`ManifestHandle`] issuance. Incremented
    /// once per [`Self::load_manifest`] call. Wraps at u64 max in
    /// theory but in practice an embedder loads dozens of manifests
    /// over its lifetime.
    next_manifest_id: u64,
    /// Bookkeeping for every manifest currently registered via
    /// [`Self::load_manifest`]. Lets
    /// [`Self::unload_manifest`] / [`Self::reload_manifest`] resolve
    /// a handle back to the manifest's identity and original payload
    /// without re-parsing JSON.
    ///
    /// Manifests registered via the direct `register_plugin*` /
    /// `register_spi_from_json` entry points don't appear here — they
    /// have no handle, so they're unreachable through the lifecycle
    /// API. Embedders that want hot-reload route their loads through
    /// `load_manifest`.
    loaded_manifests: HashMap<ManifestHandle, ManifestRecord>,
    /// For each SPI role, the set of manifest handles whose plugin
    /// claims to fulfil that role. Built from `manifest.roles`
    /// at load time and consulted by [`Self::unload_manifest`] to
    /// reject unloading an SPI def while any plugin still depends on
    /// it.
    spi_role_users: HashMap<String, std::collections::HashSet<ManifestHandle>>,
    /// Owner of each step-type linker import (`step type name →
    /// plugin`). Covers native impls, intrinsic impls, and alias
    /// dispatchers — everything that lands in the runtime's
    /// `additional_imports` table. Registration consults this map to
    /// reject a second plugin claiming a live step type (two impls
    /// under one name would otherwise "register successfully" and
    /// detonate at first execution); unload releases the claims so
    /// hot reload can re-register cleanly.
    step_import_owners: HashMap<String, String>,
}

/// Internal lifecycle bookkeeping per loaded manifest.
#[derive(Debug, Clone)]
struct ManifestRecord {
    /// Identifier of the manifest in its registry. For
    /// [`ManifestKind::SpiDef`] this is the role name (the key
    /// [`SpiRegistry`] uses). For [`ManifestKind::Plugin`] this is the
    /// plugin name (the key [`PluginRegistry`] uses).
    ///
    /// For a plugin this is the **qualified** identity, so it is
    /// directly comparable with registry keys.
    identifier: String,
    /// The namespace this manifest was loaded into; `""` for root.
    ///
    /// Retained so [`Kernel::reload_manifest`] re-registers into the
    /// same namespace it loaded from. Without it a reload would silently
    /// relocate a plugin to root — changing its identity, orphaning
    /// every grant that named it, and (in a multi-tenant embedder)
    /// promoting a tenant's plugin into the embedder's own space.
    namespace: String,
    /// The original document, retained so [`Kernel::reload_manifest`]
    /// can rebuild registry state if a new manifest fails to register.
    payload: ManifestPayload,
    /// Set true for kernel-supplied manifests that must not be
    /// unloaded or reloaded — most notably the intrinsic step type
    /// defs loaded at boot (`gwead_intrinsics`). With this flag no
    /// handle, however obtained, can remove the def for
    /// `script`/`throw_error`/etc. mid-flight.
    immutable: bool,
}

#[derive(Debug, Clone)]
enum ManifestPayload {
    /// Original SPI def JSON. Retained verbatim because
    /// [`SpiRegistry::register`] takes JSON.
    SpiDef(String),
    /// Parsed plugin manifest. Retained because
    /// [`Kernel::register_plugin`] takes a [`PluginManifest`] and
    /// re-parsing would risk surface divergence between the originally
    /// loaded shape and the snapshot.
    Plugin(Box<PluginManifest>),
}

// ---------------------------------------------------------------------------
// Manifest lifecycle
// ---------------------------------------------------------------------------

/// Opaque handle to a manifest loaded via [`Kernel::load_manifest`].
/// Embedders store these — typically in a `HashMap<file_path,
/// ManifestHandle>` for file-system manifests or
/// `HashMap<(tenant_id, plugin_id), ManifestHandle>` for end-user-
/// authored plugins — so they can later call [`Kernel::unload_manifest`]
/// or [`Kernel::reload_manifest`].
///
/// Internally a `u64` counter. Treated as opaque by callers; comparison
/// and hashing work but the integer value carries no semantic meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ManifestHandle(u64);

/// A pending manifest load: what to load, and into which namespace.
///
/// Returned by [`Kernel::load_manifest`]. Nothing happens until
/// [`register`](Self::register) is called — hence the `#[must_use]`.
/// A chain that quietly registers nothing would be exactly the class of
/// silent failure the kernel refuses everywhere else.
///
/// A builder rather than an extra parameter because load time is where
/// per-load facts belong — a namespace today, and anything else a load
/// has to say about itself — without new entry points or a growing
/// argument list. It also matches the
/// `execute(...).with_config(...).run()` shape.
#[must_use = "a manifest load does nothing until `.register()` is called"]
pub struct ManifestLoad<'k, 'j> {
    kernel: &'k mut Kernel,
    json: &'j str,
    namespace: String,
}

impl<'k, 'j> ManifestLoad<'k, 'j> {
    /// Register into `namespace` instead of the root namespace.
    ///
    /// The plugin's identity becomes `<namespace>/<manifest name>`. The
    /// manifest document is **not** modified or re-serialized: the
    /// tenant-authored bytes that were uploaded are the bytes that run,
    /// so content hashing, caching, and signature checks stay valid and
    /// error messages quote names the author actually wrote.
    ///
    /// Two plugins with the same manifest name in different namespaces
    /// are two different plugins, and neither can name itself into a
    /// namespace it was not given — the manifest name grammar rejects
    /// the separator.
    ///
    /// Namespaces are flat: `""` is root, anything
    /// else obeys the identifier grammar. Passing `""` is the same as
    /// not calling this at all.
    pub fn in_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = namespace.into();
        self
    }

    /// Perform the load, returning the handle for later
    /// [`unload`](Kernel::unload_manifest) / [`reload`](Kernel::reload_manifest).
    pub fn register(self) -> Result<ManifestHandle, KernelError> {
        let Self {
            kernel,
            json,
            namespace,
        } = self;
        kernel.load_manifest_internal(json, &namespace, false)
    }
}

/// Coarse classification of a manifest document: SPI definition vs
/// plugin. The result [`Kernel::manifest_kind`] surfaces to callers
/// who want to peek without loading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManifestKind {
    /// JSON declares an SPI contract (top-level `actions` map whose
    /// action values declare `input`/`output` schemas, no `steps`).
    SpiDef,
    /// JSON declares a plugin (`actions[*].steps`).
    Plugin,
}

/// What [`Kernel::load_manifest`] discovered the JSON to be. Carries
/// the parsed payload along with the [`ManifestKind`] discriminant.
#[derive(Debug)]
enum ClassifiedManifest {
    /// SPI definition. `role` is the JSON's top-level `name`.
    SpiDef { role: String },
    /// Plugin manifest.
    Plugin(Box<self::types::PluginManifest>),
}

impl ClassifiedManifest {
    fn kind(&self) -> ManifestKind {
        match self {
            ClassifiedManifest::SpiDef { .. } => ManifestKind::SpiDef,
            ClassifiedManifest::Plugin(_) => ManifestKind::Plugin,
        }
    }
}

/// Classify a manifest JSON by shape. The discriminator is the shape
/// of values inside the top-level `actions` map (if present): SPI defs
/// declare `input`/`output` schemas; plugins declare `steps`.
fn classify_manifest(json: &str) -> Result<ClassifiedManifest, KernelError> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| KernelError::Validation(format!("manifest is not valid JSON: {e}")))?;

    let actions_obj = value.get("actions").and_then(|a| a.as_object());

    // No top-level `actions` map — two sub-cases:
    //   1. has any of `stepTypeDefs` / `wasmModules` → the
    //      extension-only plugin form, contributing extension-point
    //      declarations only (lets `intrinsics.json` and a
    //      wasm-module-only manifest route through `load_manifest`)
    //   2. otherwise: rejected as unrecognised
    if actions_obj.is_none() {
        let has_extension_blocks = ["stepTypeDefs", "wasmModules", "stepTypeImpls"]
            .iter()
            .any(|k| value.get(k).is_some());
        if has_extension_blocks {
            manifest_schema::validate_plugin_manifest(&value).map_err(KernelError::Validation)?;
            let manifest: self::types::PluginManifest =
                serde_json::from_value(value).map_err(|e| {
                    KernelError::Validation(format!("manifest fails PluginManifest parse: {e}"))
                })?;
            return Ok(ClassifiedManifest::Plugin(Box::new(manifest)));
        }
        return Err(KernelError::Validation(
            "manifest is not a recognized shape: no top-level `actions`, \
             and no `stepTypeDefs`/`wasmModules`"
                .to_string(),
        ));
    }

    let actions = actions_obj.unwrap();
    let any_action_has_steps = actions.values().any(|v| v.get("steps").is_some());

    if any_action_has_steps {
        manifest_schema::validate_plugin_manifest(&value).map_err(KernelError::Validation)?;
        let manifest: self::types::PluginManifest = serde_json::from_value(value).map_err(|e| {
            KernelError::Validation(format!("manifest fails PluginManifest parse: {e}"))
        })?;
        Ok(ClassifiedManifest::Plugin(Box::new(manifest)))
    } else {
        manifest_schema::validate_spi_definition(&value).map_err(KernelError::Validation)?;
        let role = value
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                KernelError::Validation(
                    "SPI definition manifest missing top-level `name` field".to_string(),
                )
            })?
            .to_string();
        Ok(ClassifiedManifest::SpiDef { role })
    }
}

/// Per-invocation resource limits for wasm execution.
///
/// Caps the independent failure modes a buggy or hostile plugin can
/// produce: CPU loops, unbounded allocation, indefinite hangs, and
/// host-side result growth. Fuel and memory apply to wasm executions
/// (the interpreter behind a `script` step and the module behind a
/// `wasm` step); the wallclock cap applies to the entire action; the
/// step-result and parallel-width caps bound memory the host holds on
/// the action's behalf.
///
/// Defaults are deliberately generous so ordinary plugins never notice
/// them — fuel and memory only matter for plugins that actually run wasm,
/// and the timeout is longer than any individual step's natural
/// duration. Embedders that need tighter limits override via
/// [`KernelConfig`].
///
/// # Construction
///
/// `#[non_exhaustive]`: build from [`Default`] and the `with_*`
/// setters rather than a struct literal.
///
/// ```
/// use gwead::kernel::RuntimeLimits;
/// use std::time::Duration;
///
/// let limits = RuntimeLimits::default()
///     .with_fuel_budget(50_000_000)
///     .with_default_wallclock_timeout(Duration::from_secs(5));
/// ```
///
/// Every resource the kernel learns to cap is another field here.
/// Without `non_exhaustive` each would be a semver-major for anyone
/// who ever wrote a literal.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct RuntimeLimits {
    /// Wasm fuel budget per guest invocation (a `script` interpreter
    /// run or a `wasm` step). Each instruction consumes 1 unit.
    /// Exhaustion produces [`KernelError::FuelExhausted`]. Default:
    /// 1_000_000_000 (1 B — large enough to stream a
    /// multi-hundred-megabyte payload through a script transform,
    /// small enough that a CPU-bound tight
    /// loop trips it within a few seconds before the wallclock
    /// timeout fires).
    pub fuel_budget: u64,
    /// Maximum bytes a wasm store may hold in linear memory, summed
    /// across **every** memory in that store. Wasm pages are 64 KiB;
    /// checked on `memory.grow` and on a memory's declared initial
    /// size. Default: 64 MiB.
    ///
    /// This is a store-wide total, not a per-memory cap. A module
    /// declaring 100 memories gets this budget between them, not 100
    /// copies of it — a per-memory cap would let such a module commit
    /// 100x the budget without a trap.
    pub max_memory_bytes: usize,
    /// Maximum table elements a wasm store may hold, summed across
    /// **every** table in that store. Tables hold references, not
    /// payload bytes, but each element still commits host memory — an
    /// unbounded `table.grow` loop is host-RSS exhaustion that
    /// `max_memory_bytes` never sees. Checked on `table.grow` and on a
    /// table's declared initial size, for both the script runtime and
    /// the `wasm` step type. Default: 65_536 (~1 MiB of host memory if
    /// fully committed).
    ///
    /// Store-wide total, not per-table — same reasoning as
    /// [`Self::max_memory_bytes`].
    pub max_table_elements: usize,
    /// Maximum wasm **instances** a single store may hold.
    ///
    /// wasmtime's own default is 10,000. Default here: 32 — far above
    /// what a script interpreter or a `wasm` step module needs, far
    /// below anything that matters for host RSS.
    pub max_instances: usize,
    /// Maximum **tables** a single store may hold. wasmtime's default
    /// is 10,000. Default here: 64.
    ///
    /// Note that [`Self::max_table_elements`] is a store-wide total
    /// across every table, so this count is a second line of defence
    /// rather than the primary bound.
    pub max_tables: usize,
    /// Maximum **memories** a single store may hold. wasmtime's
    /// default is 10,000. Default here: 16.
    ///
    /// As with tables, [`Self::max_memory_bytes`] is the store-wide
    /// total; this bounds the object count.
    pub max_memories: usize,
    /// Wallclock deadline for an entire action invocation
    /// (`execute_dag`). Wraps the action's `.await` in
    /// `tokio::time::timeout`. Default: 60 s.
    ///
    /// This is a **default**, not a ceiling — a manifest that declares
    /// its own `wallclockTimeoutMs` replaces it in either direction. For
    /// a bound a manifest cannot talk its way past, see
    /// [`Self::max_wallclock_timeout`].
    pub default_wallclock_timeout: std::time::Duration,
    /// Hard ceiling on any action's wallclock deadline. **Default:
    /// `None`** — no ceiling.
    ///
    /// [`Self::default_wallclock_timeout`] is what an action gets when it asks
    /// for nothing. It bounds nothing, because an action can ask: a
    /// manifest declaring `wallclockTimeoutMs: 86400000` runs for a day
    /// against a 60-second operator default, and one declaring
    /// `dataflow: true` runs unbounded. Both are the subject asserting
    /// its own authority, which is the pattern every other gate in this
    /// kernel refuses — `provide:`, `bind:` and the namespace rules all
    /// exist because a manifest's say-so is not an authorisation.
    ///
    /// Set this and the manifest may still *lower* its deadline —
    /// asking for less is never an escalation — but not raise it past
    /// the ceiling, and `dataflow: true` is capped at it as well.
    ///
    /// Left `None` deliberately: a streaming pipeline legitimately runs
    /// for days, and a kernel that shipped a ceiling by default would
    /// break exactly the workload the dataflow scheduler exists for. The
    /// operator knows which of their actions are pipelines; the kernel
    /// does not.
    pub max_wallclock_timeout: Option<std::time::Duration>,
    /// Maximum branches one `parallel` step may fan out to. Default: 64.
    ///
    /// Branch count comes from the manifest, and each branch forks the
    /// whole `ExecutionState` — including `step_results`. Unbounded, a
    /// manifest that filled its result budget and then fanned out would
    /// hold roughly `branches x budget` in transient host memory, none
    /// of it charged: the clones are not step results, so
    /// [`Self::max_step_results_bytes`] never sees them, and they are
    /// not wasm, so no wasm limit applies either.
    ///
    /// Capping the width bounds the product. It does not make the clone
    /// free — a wide fan-out over a large result set is still expensive.
    /// The bound is the bound: `max_parallel_branches x
    /// max_step_results_bytes` is the worst case, and both are yours to
    /// set.
    ///
    /// 64 is far above what a hand-authored `parallel` step uses and far
    /// below what it takes to matter.
    pub max_parallel_branches: usize,
    /// Cumulative cap on the host bytes one invocation's step results
    /// may hold. Default: 64 MiB — the same figure as
    /// [`Self::max_memory_bytes`], because it bounds the same resource
    /// from the other side.
    ///
    /// Step results are the only unbounded host allocation a manifest
    /// controls, and they compose. A chain of `let` steps each holding
    /// `"{{$steps.prev.result}}{{$steps.prev.result}}"` doubles per
    /// line: two dozen such lines reach over a hundred megabytes in a
    /// fraction of a second, a few more reach terabytes, and
    /// registration raises no objection. No wasm limit applies — nothing runs in
    /// wasm — and no wallclock catches it, because it is fast rather
    /// than slow.
    ///
    /// Cumulative rather than per-value: capping one result still
    /// leaves as many of them as the manifest has steps, and the total
    /// is what the host has to hold. Exceeding it fails the step with
    /// [`KernelError::StepResultsLimitExceeded`].
    pub max_step_results_bytes: usize,
    /// Capacity of the bounded events channel exposed by
    /// [`DataflowHandle::events`]. Bigger means more lifecycle and
    /// progress events buffered before `try_send` starts dropping.
    ///
    /// The `PipelineCompleted` terminator is delivered on a
    /// best-effort basis that survives a full channel: `try_send`
    /// first, and on failure a detached task that awaits capacity. It
    /// is not, however, unconditional — see
    /// [`DataflowEvent::PipelineCompleted`] for the paths that skip it
    /// entirely.
    ///
    /// Default: 64 — generous for typical pipelines, tunable for
    /// monitoring UIs that need more headroom.
    pub dataflow_events_capacity: usize,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            fuel_budget: 1_000_000_000,
            max_memory_bytes: 64 * 1024 * 1024,
            max_table_elements: 65_536,
            max_instances: 32,
            max_tables: 64,
            max_memories: 16,
            default_wallclock_timeout: std::time::Duration::from_secs(60),
            max_wallclock_timeout: None,
            max_step_results_bytes: 64 * 1024 * 1024,
            max_parallel_branches: 64,
            dataflow_events_capacity: 64,
        }
    }
}

impl RuntimeLimits {
    /// Set [`Self::fuel_budget`].
    #[must_use]
    pub fn with_fuel_budget(mut self, units: u64) -> Self {
        self.fuel_budget = units;
        self
    }

    /// Set [`Self::max_memory_bytes`].
    #[must_use]
    pub fn with_max_memory_bytes(mut self, bytes: usize) -> Self {
        self.max_memory_bytes = bytes;
        self
    }

    /// Set [`Self::max_table_elements`].
    #[must_use]
    pub fn with_max_table_elements(mut self, elements: usize) -> Self {
        self.max_table_elements = elements;
        self
    }

    /// Set [`Self::max_instances`].
    #[must_use]
    pub fn with_max_instances(mut self, instances: usize) -> Self {
        self.max_instances = instances;
        self
    }

    /// Set [`Self::max_tables`].
    #[must_use]
    pub fn with_max_tables(mut self, tables: usize) -> Self {
        self.max_tables = tables;
        self
    }

    /// Set [`Self::max_memories`].
    #[must_use]
    pub fn with_max_memories(mut self, memories: usize) -> Self {
        self.max_memories = memories;
        self
    }

    /// Set [`Self::default_wallclock_timeout`].
    #[must_use]
    pub fn with_default_wallclock_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.default_wallclock_timeout = timeout;
        self
    }

    /// Set [`Self::max_parallel_branches`].
    #[must_use]
    pub fn with_max_parallel_branches(mut self, branches: usize) -> Self {
        self.max_parallel_branches = branches;
        self
    }

    /// Set [`Self::max_step_results_bytes`].
    #[must_use]
    pub fn with_max_step_results_bytes(mut self, bytes: usize) -> Self {
        self.max_step_results_bytes = bytes;
        self
    }

    /// Set [`Self::max_wallclock_timeout`] — the ceiling a manifest
    /// cannot raise itself past, including via `dataflow: true`.
    #[must_use]
    pub fn with_max_wallclock_timeout(mut self, ceiling: std::time::Duration) -> Self {
        self.max_wallclock_timeout = Some(ceiling);
        self
    }

    /// Set [`Self::dataflow_events_capacity`].
    #[must_use]
    pub fn with_dataflow_events_capacity(mut self, capacity: usize) -> Self {
        self.dataflow_events_capacity = capacity;
        self
    }
}

/// Configuration for kernel initialization.
///
/// The `settings` field accepts an arbitrary JSON object the embedder
/// sources however it likes — a config file, a settings table, an
/// environment variable. The kernel reads its configuration from that
/// object, with struct fields as fallbacks when a key is absent, so
/// operators can retune a live deployment without a code change.
///
/// Recognized settings keys:
/// - `defaultWallclockTimeoutMs` (u64) — default action wall-clock timeout
///   for actions that declare no `wallclockTimeoutMs` of their own.
///   Overrides [`RuntimeLimits::default_wallclock_timeout`] when present.
///
/// Network egress policy is not a kernel concern: the kernel ships no
/// HTTP client and carries no opinion about which hosts are reachable.
///
/// # Construction
///
/// `#[non_exhaustive]`: build from [`Default`] and the `with_*`
/// setters rather than a struct literal.
///
/// ```
/// use gwead::kernel::{Kernel, KernelConfig, RuntimeLimits};
///
/// let kernel = Kernel::boot(
///     KernelConfig::default()
///         .with_limits(RuntimeLimits::default().with_fuel_budget(50_000_000)),
/// )?;
/// # Ok::<(), gwead::kernel::KernelError>(())
/// ```
#[derive(Default)]
#[non_exhaustive]
pub struct KernelConfig {
    /// Native step-type implementations submitted by plugin crates via
    /// `inventory::submit!`. Typically built once at
    /// host bootstrap via
    /// [`self::native_impls::NativeStepImplTable::discover`]. Default
    /// is empty — kernels with no plugin crates compiled in get
    /// `NativeStepImplTable::empty()` implicitly.
    pub native_step_impls: self::native_impls::NativeStepImplTable,
    /// An optional settings object from the embedder. When provided,
    /// the kernel reads configuration from it (e.g.
    /// `defaultWallclockTimeoutMs`). Struct fields serve as fallbacks
    /// for missing keys.
    pub settings: Option<serde_json::Value>,
    /// Per-invocation resource limits. See [`RuntimeLimits`].
    pub limits: RuntimeLimits,
    /// Dispatch policy hook: the seam the kernel offers for plugin
    /// selection + per-callee config resolution. When `None`, the
    /// kernel falls back to [`dispatch::DefaultOrchestrator`]
    /// (first-match by role, caller-namespace config). Embedders that
    /// need app-shaped policy — per-tenant selection, per-discriminator
    /// filtering — register their own implementation here.
    ///
    /// Secrets are **not** this hook's business; they are pulled
    /// through [`Self::secret_resolver`].
    pub dispatch_orchestrator: Option<Arc<dyn DispatchOrchestrator>>,
    /// Where the kernel pulls plugin credentials from. See
    /// [`secrets`] for the model and the two rules the kernel enforces
    /// on every answer.
    ///
    /// **Default: `None`**, meaning no execution in this kernel sees any
    /// secrets — `{{$secrets.*}}` resolves empty everywhere. When
    /// `Some`, every execution — the invoked plugin, an `invoke`
    /// callee, a role dispatch, an event subscriber — asks the resolver
    /// for its own secrets, narrowed to its manifest's `usesSecrets`.
    ///
    /// This is the only way credentials enter the kernel. There is no
    /// per-request bag: a single-plugin embedder registers a
    /// [`secrets::StaticSecretResolver`] here, and the deployment that
    /// needs a vault registers its own. One spelling, so "where do
    /// this kernel's secrets come from" has exactly one place to look.
    pub secret_resolver: Option<Arc<dyn SecretResolver>>,
    /// Plugins permitted to supply the implementation behind a
    /// **kernel-defined** step type — that means `script`, whose
    /// `(script, <language>)` slots hold the interpreter wasm module
    /// every plugin's script steps of that language execute inside.
    ///
    /// **Default: empty**, which means no plugin may claim such a slot
    /// and `script` steps have no runtime until you opt one in. Naming
    /// a plugin here is the act of trusting it with that position.
    ///
    /// The kernel bundles no script runtime. A language runtime is an
    /// ordinary plugin manifest the embedder loads — one whose
    /// `stepTypeImpls` claims `(script, <language>)`. Any
    /// `{type: "script", language: "lua"}` step on a kernel with no
    /// such runtime fails with a structured "no script runtime
    /// registered for language 'lua'" error from `step_script`.
    ///
    /// Slot claims are gated here rather than granted first-come,
    /// first-served because the slot is a position of trust. Without
    /// the gate, a manifest declaring no permissions and no actions
    /// could claim `(script, "lua")`, and from then on every other
    /// plugin's Lua step would run inside its module — which receives
    /// that plugin's resolution context and a parent context naming
    /// the victim, so it could both read the victim's data and
    /// dispatch under the victim's identity. Load order would be the
    /// only thing deciding who won, and a legitimate runtime loading
    /// second would fail with an error blaming *itself*.
    ///
    /// The plugin must **also** declare
    /// `provide:step_type:<type>[:<selector>]` in its manifest. The
    /// declaration makes the claim auditable in the manifest an
    /// operator reviews; this list is what actually authorises it.
    /// Both are required, and the error messages distinguish "did not
    /// ask" from "asked and is not trusted".
    ///
    /// Plugin-defined step types are unaffected: a plugin may always
    /// implement a step type it defined itself, without appearing
    /// here. The rule lives in `Kernel::check_step_type_impl_claim`.
    ///
    /// # Entries are qualified identities
    ///
    /// Each entry is a plugin **identity**, not a manifest name: bare
    /// `"lua_rt"` for the root namespace, `"tenant42/lua_rt"` for a
    /// namespaced one. Root entries are bare names with no separator.
    ///
    /// # How strong this guarantee is
    ///
    /// Exactly as strong as the embedder's control over which manifest
    /// lands in which namespace — and no stronger. A manifest cannot
    /// choose its own namespace (the name grammar rejects the
    /// separator), so a plugin loaded into `tenant42` can never match a
    /// root-namespace entry however it names itself. That is what makes
    /// naming a *namespaced* plugin here safe.
    ///
    /// Within a single namespace, names are still first-come: if an
    /// embedder loads a manifest it did not author into the **root**
    /// namespace, that manifest can call itself `lua_rt` and inherit
    /// whatever trust the entry `"lua_rt"` carries. Root is therefore
    /// only sound for manifests the embedder itself ships. Load
    /// anything you did not author with
    /// [`in_namespace`](ManifestLoad::in_namespace).
    pub trusted_step_type_providers: Vec<TrustedProvider>,

    /// Cross-plugin native-impl bindings the embedder authorises, as
    /// `(binder identity, implRef)` pairs.
    ///
    /// **Default: empty.** A plugin may always bind a native body it
    /// owns — one whose `<plugin>` segment is its own local name — so
    /// the ordinary case needs nothing here. This list exists for the
    /// case where one plugin deliberately runs a body another plugin
    /// shipped.
    ///
    /// This is the operator half of a two-key rule. The binder must
    /// *also* declare `bind:native_impl:<implRef>` in its manifest.
    /// The declaration makes the claim greppable in the document an
    /// operator reviews; this list is what actually authorises it.
    /// Both name the exact body — no wildcards — so an entry cannot
    /// widen beyond the one binding it was written for.
    ///
    /// The owner check matters because `implRef` resolution is
    /// otherwise a single flat lookup. Without it, a plugin declaring
    /// no permissions at all could point `implRef` at
    /// `myapp.vault.sign` and execute a privileged body it did not
    /// own, having satisfied `provide:step_type:` legitimately for a
    /// step type it defined itself. The two axes are orthogonal: which
    /// slot am I filling, and whose body am I binding. Both are
    /// checked.
    ///
    /// The binder is named by **identity**, so a namespaced plugin
    /// cannot satisfy an entry written for a root-namespace one.
    pub native_impl_bindings: Vec<NativeImplBinding>,

    /// Embedder-defined permission categories this kernel accepts in a
    /// manifest.
    ///
    /// **Default: empty**, which means no `acme.*`-style permission
    /// loads at all. Every dot-namespaced category a manifest names
    /// must appear here or the plugin is rejected.
    ///
    /// The kernel does not enforce these grants — it cannot; they mean
    /// something only inside the embedder. What it enforces is that
    /// each one is addressed to a category somebody has heard of. A
    /// category the embedder does not recognise is a grant that matches
    /// nothing for the life of the deployment, and it looks identical
    /// to a correctly-denied one at every point after load. `evets` for
    /// `events` is a typo the kernel cannot see and the embedder can.
    ///
    /// This is the same shape as the dot-free reservation on the kernel
    /// side, and the same shape as the glob reservation: refuse the
    /// grant whose meaning nobody can vouch for, at the one moment
    /// somebody is still reading the manifest.
    ///
    /// Categories may also constrain their own values — see
    /// [`AppPermissionCategory::with_validator`](permissions::AppPermissionCategory::with_validator).
    ///
    /// ```
    /// use gwead::kernel::{Kernel, KernelConfig};
    ///
    /// let kernel = Kernel::boot(
    ///     KernelConfig::default()
    ///         .defining_app_permission_category("acme.events")
    ///         .defining_app_permission_category("acme.audit"),
    /// )?;
    /// # Ok::<(), gwead::kernel::KernelError>(())
    /// ```
    pub app_permission_categories: Vec<permissions::AppPermissionCategory>,
}

impl KernelConfig {
    /// Set [`Self::native_step_impls`].
    #[must_use]
    pub fn with_native_step_impls(
        mut self,
        table: self::native_impls::NativeStepImplTable,
    ) -> Self {
        self.native_step_impls = table;
        self
    }

    /// Set [`Self::settings`].
    #[must_use]
    pub fn with_settings(mut self, settings: serde_json::Value) -> Self {
        self.settings = Some(settings);
        self
    }

    /// Set [`Self::limits`].
    #[must_use]
    pub fn with_limits(mut self, limits: RuntimeLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Set [`Self::dispatch_orchestrator`].
    #[must_use]
    pub fn with_dispatch_orchestrator(
        mut self,
        orchestrator: Arc<dyn DispatchOrchestrator>,
    ) -> Self {
        self.dispatch_orchestrator = Some(orchestrator);
        self
    }

    /// Set [`Self::secret_resolver`].
    #[must_use]
    pub fn with_secret_resolver(mut self, resolver: Arc<dyn SecretResolver>) -> Self {
        self.secret_resolver = Some(resolver);
        self
    }

    /// Trust a **root-namespace** plugin as a step-type provider.
    ///
    /// `plugin` is the manifest name, which in the root namespace is
    /// also the identity. For a namespaced plugin use
    /// [`Self::trusting_step_type_provider_in`] — passing
    /// `"tenant42/lua_rt"` here works, but writing the namespace and
    /// name separately is harder to get subtly wrong.
    ///
    /// See [`Self::trusted_step_type_providers`] for the limits of what
    /// trusting a root-namespace name actually guarantees.
    #[must_use]
    pub fn trusting_step_type_provider(mut self, plugin: impl Into<String>) -> Self {
        self.trusted_step_type_providers
            .push(TrustedProvider::new(plugin));
        self
    }

    /// Trust the plugin named `plugin` **within `namespace`** as a
    /// step-type provider.
    ///
    /// The pair is composed into the same qualified identity the
    /// registry keys on, so this cannot be satisfied by a manifest in
    /// any other namespace no matter what it calls itself.
    #[must_use]
    pub fn trusting_step_type_provider_in(
        mut self,
        namespace: impl AsRef<str>,
        plugin: impl AsRef<str>,
    ) -> Self {
        self.trusted_step_type_providers
            .push(TrustedProvider::new(self::identity::qualify(
                namespace.as_ref(),
                plugin.as_ref(),
            )));
        self
    }

    /// Authorise `binder` to bind the native body `impl_ref`, which
    /// some other plugin ships.
    ///
    /// `binder` is a plugin **identity** — a bare name in the root
    /// namespace, `namespace/name` otherwise. Unnecessary for a plugin
    /// binding its own bodies.
    ///
    /// The binder's manifest must also carry
    /// `bind:native_impl:<impl_ref>`; see
    /// [`Self::native_impl_bindings`] for why both halves exist.
    #[must_use]
    pub fn allowing_native_impl_binding(
        mut self,
        binder: impl Into<String>,
        impl_ref: impl Into<String>,
    ) -> Self {
        self.native_impl_bindings
            .push(NativeImplBinding::new(binder, impl_ref));
        self
    }

    /// Declare an embedder permission category, accepting any value.
    ///
    /// The name must be dot-namespaced — dot-free names are the
    /// kernel's — and is checked at [`Kernel::boot`], not here, so a
    /// builder chain stays infallible.
    ///
    /// Declaring the same category twice replaces the earlier entry, so
    /// the last call in a chain is the one that takes effect.
    #[must_use]
    pub fn defining_app_permission_category(self, name: impl Into<String>) -> Self {
        self.defining_app_permission_category_as(permissions::AppPermissionCategory::new(name))
    }

    /// Declare an embedder permission category built elsewhere —
    /// typically one carrying a value validator.
    ///
    /// ```
    /// use gwead::kernel::KernelConfig;
    /// use gwead::kernel::permissions::AppPermissionCategory;
    ///
    /// let config = KernelConfig::default().defining_app_permission_category_as(
    ///     AppPermissionCategory::new("acme.events").with_validator(|value| {
    ///         value
    ///             .strip_prefix("publish:")
    ///             .filter(|topic| !topic.is_empty())
    ///             .map(|_| ())
    ///             .ok_or_else(|| "expected publish:<topic>".to_string())
    ///     }),
    /// );
    /// ```
    #[must_use]
    pub fn defining_app_permission_category_as(
        mut self,
        category: permissions::AppPermissionCategory,
    ) -> Self {
        self.app_permission_categories
            .retain(|existing| existing.name() != category.name());
        self.app_permission_categories.push(category);
        self
    }

    /// Replace [`Self::trusted_step_type_providers`] wholesale.
    #[must_use]
    pub fn with_trusted_step_type_providers(
        mut self,
        plugins: impl IntoIterator<Item = TrustedProvider>,
    ) -> Self {
        self.trusted_step_type_providers = plugins.into_iter().collect();
        self
    }
}

impl Kernel {
    /// Boot the kernel with the given configuration.
    ///
    /// When `config.settings` is provided, its values take precedence
    /// over the struct fields.
    pub fn boot(config: KernelConfig) -> Result<Self, KernelError> {
        let runtime = WasmRuntime::new()?;
        let registry = PluginRegistry::new();
        // The kernel ships zero SPI definitions — role contracts are
        // application-shaped. Embedders register them at startup via
        // [`Self::register_spi_from_json`] before any plugin manifest
        // that references those roles can validate.
        let spi_registry = SpiRegistry::new();

        // Deployment default wallclock timeout. The settings key
        // overrides `KernelConfig::limits.default_wallclock_timeout` so
        // operators can tune the default without code changes; the
        // hardcoded 60 s default applies otherwise. This default is the
        // value applied to non-dataflow actions that don't declare
        // their own `wallclock_timeout_ms`; see
        // [`Kernel::effective_wallclock_timeout`] for the decision tree.
        //
        // Malformed values warn and fall through to the default. `0` is
        // also rejected: it would intuitively mean "no automatic cap"
        // but actually produces `Duration::from_millis(0)` and instant
        // timeouts. Operators who want no automatic cap leave the key
        // absent (or set `null`); a manifest opts out per-action with
        // `dataflow: true`.
        let mut limits = config.limits.clone();
        if let Some(v) = config
            .settings
            .as_ref()
            .and_then(|s| s.get("defaultWallclockTimeoutMs"))
        {
            match v.as_u64() {
                Some(0) => tracing::warn!(
                    "Gwead kernel: settings.defaultWallclockTimeoutMs=0 is invalid \
                     (would trip ExecutionTimeout immediately); ignoring. \
                     Use `null`/absent for no cap on dataflow actions."
                ),
                Some(ms) => {
                    limits.default_wallclock_timeout = std::time::Duration::from_millis(ms);
                    tracing::info!(
                        wallclock_timeout_ms = ms,
                        "Gwead kernel: default wallclock timeout loaded from settings"
                    );
                }
                None => tracing::warn!(
                    value = %v,
                    "Gwead kernel: settings.defaultWallclockTimeoutMs has wrong type \
                     (expected unsigned integer in milliseconds); \
                     falling back to KernelConfig default"
                ),
            }
        }

        tracing::info!(spi_count = spi_registry.len(), "Gwead kernel booted");
        // Top up the embedder-supplied native-impl table with any
        // inventory submissions the embedder didn't explicitly call
        // `discover()` for — most importantly, gwead's own
        // `gwead.intrinsics.*` impls, which the intrinsics manifest's
        // dispatch is wired through. Entries the embedder already
        // placed (test fixture seeds, an explicit `discover()` call)
        // win; this is insert-if-absent. See
        // `NativeStepImplTable::ensure_from_inventory`.
        let mut native_step_impls = config.native_step_impls;
        native_step_impls
            .ensure_from_inventory()
            .map_err(|e| KernelError::Boot(format!("native step impls: {e}")))?;
        // Kernel-internal step bodies are never embedder-supplied —
        // build the table straight from the inventory slice.
        let intrinsic_step_impls = self::native_impls::IntrinsicStepImplTable::discover()
            .map_err(|e| KernelError::Boot(format!("intrinsic step impls: {e}")))?;
        let dispatch_orchestrator = config
            .dispatch_orchestrator
            .unwrap_or_else(self::dispatch::default_orchestrator);

        // Check the embedder's declared permission categories before
        // any manifest can be measured against them. A category no
        // manifest could ever name — dot-free, or carrying a character
        // the name grammar forbids — is the same never-matching grant
        // this mechanism exists to catch, pointing the other way, and
        // boot is the last moment anyone is looking.
        for category in &config.app_permission_categories {
            permissions::validate_app_category_name(category.name()).map_err(|e| {
                KernelError::Boot(format!("KernelConfig::app_permission_categories: {e}"))
            })?;
        }
        let mut kernel = Self {
            runtime,
            registry,
            spi_registry,
            limits,
            native_step_impls,
            intrinsic_step_impls,
            dispatch_orchestrator,
            secret_resolver: config.secret_resolver,
            trusted_step_type_providers: config.trusted_step_type_providers,
            // Kernel entries first, then the embedder's. The engine's
            // own bindings are not embedder-removable: `KernelConfig`
            // can only add.
            native_impl_bindings: INTRINSIC_NATIVE_BINDINGS
                .iter()
                .map(|(binder, impl_ref)| NativeImplBinding::new(*binder, *impl_ref))
                .chain(config.native_impl_bindings)
                .collect(),
            app_permission_categories: config.app_permission_categories,
            self_weak: OnceLock::new(),
            next_manifest_id: 1,
            loaded_manifests: HashMap::new(),
            spi_role_users: HashMap::new(),
            step_import_owners: HashMap::new(),
        };

        // Register the 11 intrinsic step type definitions.
        // The defs ship as a JSON manifest loaded through the same
        // registration path any embedder uses — uniform-registration
        // invariant: even gwead's own intrinsics go through
        // `load_manifest_internal`. The five body-shaped intrinsics'
        // implementations are also wired through the manifest: each
        // `step_*` fn `inventory::submit!`s itself, and the manifest's
        // `stepTypeImpls` block resolves those submissions via the
        // standard `kind: "native"` / `kind: "intrinsic"` paths. The
        // six control-flow intrinsics (ifs, for_each, repeat,
        // parallel, return, try) are dispatched directly inside
        // `runtime.rs` because they manipulate control flow rather
        // than executing as step bodies.
        //
        // The intrinsics manifest is marked `immutable: true` —
        // `unload_manifest` / `reload_manifest` reject the resulting
        // handle. The handle is also dropped on the floor here, so
        // no external surface can request its removal; the immutable
        // flag is belt-and-braces so that no handle, however obtained,
        // can.
        //
        // Self-use of `load_manifest_internal` carries one
        // constraint: if that entry point ever requires external context
        // (tenant ID, permissions, lifecycle hooks the kernel can't
        // supply itself), this boot path needs a private
        // `load_intrinsics` shim that bypasses the external-context
        // requirements.
        kernel
            .load_manifest_internal(
                include_str!("../../resources/manifests/intrinsics.json"),
                // Root namespace. The intrinsic step types (`ifs`,
                // `invoke`, `script`, …) are referenced by every plugin
                // in every namespace, so they have to live in the one
                // space all of them can name.
                "",
                true,
            )
            .map_err(|e| KernelError::Boot(format!("intrinsics manifest: {e}")))?;

        // Plugins (sigv4, storage backends, script runtimes, capability
        // plugins, …) are not auto-registered here. The embedder calls
        // `register_plugin_from_json` / `load_manifest` for each plugin
        // manifest, in dependency order (SPI defs → plugins that claim
        // those roles → plugins that depend on those plugins).

        Ok(kernel)
    }

    /// Wrap this kernel in `Arc` and seed the internal self-reference used
    /// by the `invoke` step type for recursive dispatch and by the
    /// builder's spawn-path terminals (`into_dataflow_handle`,
    /// `into_continuous_handle`, `into_dataflow_streaming_handle`).
    ///
    /// Call after all `register_plugin` / `load_manifest` calls are done.
    /// Kernels that never need `invoke` and only call
    /// [`Kernel::execute(...).run()`](Self::execute) can use plain
    /// `Arc::new(kernel)` instead, but any spawn-path terminal will fail
    /// at runtime if `self_weak` isn't populated.
    pub fn into_arc(self) -> Arc<Self> {
        let arc = Arc::new(self);
        // `into_arc` consumes `self`, so a given `Kernel` value can only
        // run this code once — there's exactly one `Arc<Kernel>` per
        // kernel value, and `self_weak` is populated at construction
        // time. The `let _ = …set(…)` shape is defensive against the
        // `OnceLock` API rather than a real reachable case.
        let _ = arc.self_weak.set(Arc::downgrade(&arc));
        arc
    }

    /// Register an SPI definition from its JSON source.
    ///
    /// Embedders call this at startup for each SPI def file in their
    /// manifests directory before registering any plugin that claims
    /// the role. Ordering matters: plugin validation (in
    /// [`Self::register_plugin`]) enforces an SPI's action contract
    /// strictly — a plugin missing a required action is rejected — but
    /// ONLY when the SPI def is already registered. A role with no
    /// registered def is a `tracing::warn` and the plugin loads anyway
    /// (roles double as ad-hoc dispatch labels, so an unknown role is
    /// not proof of error). Load SPI defs first or their contracts are
    /// never checked.
    ///
    /// **Prefer [`Self::load_manifest`]** — it classifies the JSON and
    /// routes to this method or [`Self::register_plugin`]
    /// automatically. This entry point serves callers that have
    /// already done the classification.
    pub fn register_spi_from_json(&mut self, role: &str, json: &str) -> Result<(), KernelError> {
        // A role name is the SPI registry key and appears verbatim in
        // `invoke:role:<name>` grants, so it obeys the same grammar as
        // every other kernel-global identifier.
        self::identity::validate_name(self::identity::NameKind::Role, role)
            .map_err(|e| KernelError::Validation(e.to_string()))?;
        let value: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| KernelError::Validation(format!("manifest is not valid JSON: {e}")))?;
        manifest_schema::validate_spi_definition(&value).map_err(KernelError::Validation)?;

        // The `role` argument is the registry key; the document's own
        // `name` is what an operator reads. If they were not compared, a
        // definition could be filed under a key it does not answer to:
        // `register_spi_from_json("LLM_CHAT", storage_json)` would
        // register cleanly, and from then on `invoke:role:LLM_CHAT`
        // grants would dispatch against a contract nobody reading either
        // file would predict. Same never-matching-grant family as the permission
        // reservations, one level up — except this one silently matches
        // the *wrong* thing rather than nothing.
        // `name` is `required` in the SPI meta-schema, which has already
        // run, so the absent case is unreachable rather than tolerated.
        let declared = value.get("name").and_then(|v| v.as_str()).unwrap_or(role);
        if declared != role {
            return Err(KernelError::Validation(format!(
                "SPI definition declares name '{declared}' but was registered under role \
                 '{role}'. The two must agree — the role is the key that \
                 'invoke:role:' grants name, and the document is what an operator reads."
            )));
        }

        self.spi_registry.register(role, json)
    }

    /// Classify a manifest JSON without registering it. Useful for
    /// embedders that need to bucket files by kind before calling
    /// [`Self::load_manifest`] in dependency order — an embedder's
    /// loader uses it to land SPI defs before plugins. Same classification
    /// rules as `load_manifest`; this is the read-only peek.
    ///
    /// The full validation + parse runs here (classification requires
    /// it) but the result is discarded; load_manifest re-runs it when
    /// the caller comes back to actually load.
    pub fn manifest_kind(json: &str) -> Result<ManifestKind, KernelError> {
        classify_manifest(json).map(|c| c.kind())
    }

    /// Load a manifest JSON — the unified entry point. Classifies the
    /// document by shape (SPI def vs plugin) and routes to the
    /// matching internal registration path.
    /// Returns an opaque [`ManifestHandle`] the embedder stores to
    /// later call [`Self::unload_manifest`] / [`Self::reload_manifest`].
    ///
    /// Classification keys:
    /// - top-level `actions` map AND no action with `steps` → SPI def
    /// - top-level `actions` map AND ≥1 action with `steps` → plugin
    ///   (the actions-map form)
    /// - no top-level `actions` AND has `stepTypeDefs` /
    ///   `wasmModules` → plugin contributing extension declarations
    ///   only (the extension-only form, e.g. `intrinsics.json`)
    ///
    /// Embedders are responsible for cross-file ordering: SPI defs
    /// must land before any plugin that references their role —
    /// contracts of defs that aren't registered yet are silently
    /// unchecked (the unknown role only warns; see
    /// [`Self::register_spi_from_json`]).
    ///
    /// # Namespacing
    ///
    /// Returns a builder; nothing is registered until
    /// [`register`](ManifestLoad::register) is called:
    ///
    /// ```no_run
    /// # use gwead::kernel::{Kernel, KernelConfig};
    /// # fn f(kernel: &mut Kernel, json: &str) -> Result<(), gwead::kernel::KernelError> {
    /// // Root namespace — identity is the manifest's own name.
    /// kernel.load_manifest(json).register()?;
    ///
    /// // Namespaced — identity is `tenant42/<manifest name>`.
    /// kernel.load_manifest(json).in_namespace("tenant42").register()?;
    /// # Ok(()) }
    /// ```
    ///
    /// Loading without a namespace gives the plugin its manifest name
    /// as its identity. Use [`in_namespace`](ManifestLoad::in_namespace)
    /// for manifests the embedder did not author: it is what stops two
    /// authors colliding on one name, and what stops a manifest naming
    /// itself into [`KernelConfig::trusted_step_type_providers`].
    pub fn load_manifest<'k, 'j>(&'k mut self, json: &'j str) -> ManifestLoad<'k, 'j> {
        ManifestLoad {
            kernel: self,
            json,
            namespace: String::new(),
        }
    }

    /// Internal loader variant that lets the boot path mark its
    /// manifests immutable. External callers always get
    /// `immutable = false` via [`Self::load_manifest`].
    fn load_manifest_internal(
        &mut self,
        json: &str,
        namespace: &str,
        immutable: bool,
    ) -> Result<ManifestHandle, KernelError> {
        let mut record = self.register_classified_manifest(json, namespace, immutable)?;
        record.immutable = immutable;
        let handle = ManifestHandle(self.next_manifest_id);
        self.next_manifest_id = self.next_manifest_id.saturating_add(1);
        self.track_manifest(handle, record);
        Ok(handle)
    }

    /// Classify, register, and return the bookkeeping record for one
    /// manifest. Shared between [`Self::load_manifest`] and
    /// [`Self::reload_manifest`]; doesn't touch `loaded_manifests` or
    /// `spi_role_users` so callers can decide whether to commit the
    /// record under a fresh handle (load) or under the existing one
    /// (reload).
    fn register_classified_manifest(
        &mut self,
        json: &str,
        namespace: &str,
        kernel_owned: bool,
    ) -> Result<ManifestRecord, KernelError> {
        match classify_manifest(json)? {
            ClassifiedManifest::SpiDef { role } => {
                // A role is an identity like a plugin: defined into a
                // namespace, keyed by its qualified name, and resolved
                // along a referring plugin's ancestor chain. A tenant
                // defining `LLM_CHAT` owns `tenant/LLM_CHAT`, which
                // shadows the global contract for that tenant's plugins
                // and is invisible to everyone else — it cannot claim,
                // redefine or capture the embedder's `LLM_CHAT`.
                self::identity::validate_namespace(namespace)
                    .map_err(|e| KernelError::Validation(e.to_string()))?;
                let key = self::identity::qualify(namespace, &role);
                self.spi_registry.register(&key, json)?;
                Ok(ManifestRecord {
                    identifier: key,
                    namespace: namespace.to_string(),
                    payload: ManifestPayload::SpiDef(json.to_string()),
                    immutable: false,
                })
            }
            ClassifiedManifest::Plugin(manifest) => {
                // Snapshot BEFORE registration, so the retained payload
                // still carries the author's local name. `register_plugin_in`
                // rewrites `name` into the qualified identity, and a
                // rollback re-registers this snapshot under the record's
                // namespace — re-qualifying an already-qualified name
                // would be a bug, and the name grammar makes it a loud
                // one rather than a silent double prefix.
                let snapshot = manifest.clone();
                self.register_plugin_in_as(namespace, *manifest, kernel_owned)?;
                Ok(ManifestRecord {
                    identifier: self::identity::qualify(namespace, &snapshot.name),
                    namespace: namespace.to_string(),
                    payload: ManifestPayload::Plugin(snapshot),
                    immutable: false,
                })
            }
        }
    }

    /// Commit a successfully-registered record to the lifecycle index
    /// under `handle`. Populates `loaded_manifests` and, for plugin
    /// records, indexes each claimed SPI role into `spi_role_users`.
    fn track_manifest(&mut self, handle: ManifestHandle, record: ManifestRecord) {
        if let ManifestPayload::Plugin(ref manifest) = record.payload {
            for key in self.role_keys_for(&record.namespace, &manifest.roles) {
                self.spi_role_users.entry(key).or_default().insert(handle);
            }
        }
        self.loaded_manifests.insert(handle, record);
    }

    /// The qualified role keys a plugin in `namespace` binds to for the
    /// bare role names it declares: the nearest defined contract up the
    /// chain, or the plugin's own namespace when none is defined.
    /// Deduplicated, declaration order.
    fn role_keys_for(&self, namespace: &str, roles: &[String]) -> Vec<String> {
        let mut keys = Vec::new();
        for role in roles {
            let key = self
                .spi_registry
                .resolve(namespace, role)
                .map(|(key, _)| key)
                .unwrap_or_else(|| self::identity::qualify(namespace, role));
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        keys
    }

    /// Drop a manifest's lifecycle bookkeeping after the registry-side
    /// removal has succeeded. Removes the handle from every
    /// `spi_role_users` bucket and prunes any that emptied — including
    /// SPI-def buckets that already happened to be empty, so the
    /// invariant "no empty buckets" holds after every lifecycle call.
    fn untrack_manifest(&mut self, handle: ManifestHandle) {
        // Remove by handle across every bucket rather than recomputing
        // the keys: a definition loaded or unloaded since this plugin
        // registered could make the recomputation land elsewhere.
        for set in self.spi_role_users.values_mut() {
            set.remove(&handle);
        }
        self.spi_role_users.retain(|_, set| !set.is_empty());
    }

    /// Unload a loaded manifest by handle.
    ///
    /// For a plugin record: scrubs every registry slice the plugin
    /// touched at registration (actions, manifests, roles,
    /// subscriptions, invoke edges, step-type aliases, step-type defs,
    /// step-type impls, permissions, wasm modules). For an SPI def
    /// record: rejects if any plugin currently claims the role (the
    /// dependent's identifier is named in the error), otherwise drops
    /// the SPI definition.
    ///
    /// **In-flight invocations are not waited on.** The borrow checker
    /// enforces this implicitly: `&mut self` here cannot coexist with
    /// the `&self` borrows held by in-flight `execute_action*` futures.
    /// Embedders running hot-reload against a live `Arc<Kernel>` must
    /// serialize through their own lock (e.g. `Arc<RwLock<Kernel>>`)
    /// and quiesce in-flight calls.
    pub fn unload_manifest(&mut self, handle: ManifestHandle) -> Result<(), KernelError> {
        // Peek first so a rejection (immutable, or further down the
        // path) leaves the lifecycle index unchanged.
        let immutable = self
            .loaded_manifests
            .get(&handle)
            .map(|r| r.immutable)
            .unwrap_or(false);
        if immutable {
            return Err(KernelError::Validation(format!(
                "ManifestHandle({}) is kernel-immutable (intrinsic step types or other boot-required manifest); cannot unload",
                handle.0
            )));
        }

        let record = self.loaded_manifests.remove(&handle).ok_or_else(|| {
            KernelError::NotFound(format!(
                "ManifestHandle({}) not loaded (already unloaded, or never registered via load_manifest)",
                handle.0
            ))
        })?;

        match &record.payload {
            ManifestPayload::SpiDef(_) => {
                if let Some(users) = self.spi_role_users.get(&record.identifier)
                    && !users.is_empty()
                {
                    // Restore so the handle stays valid — unload was a
                    // no-op from the caller's perspective.
                    let dependents: Vec<String> = users
                        .iter()
                        .filter_map(|h| self.loaded_manifests.get(h).map(|r| r.identifier.clone()))
                        .collect();
                    let role = record.identifier.clone();
                    self.loaded_manifests.insert(handle, record);
                    return Err(KernelError::Validation(format!(
                        "Cannot unload SPI def '{role}' — still claimed by plugin(s): {}",
                        dependents.join(", ")
                    )));
                }
                if !self.spi_registry.unregister(&record.identifier) {
                    // Out-of-sync between lifecycle index and SPI
                    // registry — should never happen, but if it does
                    // the index is now the wrong-leaning truth so
                    // surface clearly rather than silently succeed.
                    return Err(KernelError::Runtime(format!(
                        "Lifecycle index drift: SPI def '{}' was tracked but missing from SPI registry",
                        record.identifier
                    )));
                }
            }
            ManifestPayload::Plugin(m) => {
                let removed = self.registry.unregister_plugin(&record.identifier);
                if !removed {
                    return Err(KernelError::Runtime(format!(
                        "Lifecycle index drift: plugin '{}' was tracked but missing from plugin registry",
                        record.identifier
                    )));
                }
                self.release_step_imports(&record.identifier, m);
            }
        }
        // Single bookkeeping pass after the registry-side removal —
        // matches the order `reload_manifest` uses.
        self.untrack_manifest(handle);

        Ok(())
    }

    /// Atomically replace a loaded manifest with new JSON.
    ///
    /// Sequence:
    /// 1. Resolve the handle to the currently-loaded record.
    /// 2. Unregister the old manifest (registry scrub + lifecycle
    ///    bookkeeping).
    /// 3. Try to register the new JSON.
    /// 4. On register failure, re-register the original manifest from
    ///    the retained snapshot and surface the original error. The
    ///    handle stays valid and continues to point at the old
    ///    manifest in either outcome.
    ///
    /// **Caveats**: the rollback step assumes re-registering the
    /// retained payload succeeds (it succeeded once already, against
    /// a registry state we restored to). Reloading an SPI def is
    /// allowed even when plugins depend on it — the new def is
    /// applied without revalidating dependents; tightening an SPI
    /// contract beyond what dependent plugins satisfy is the
    /// embedder's responsibility to catch. A `tracing::warn!` fires
    /// on SPI reload with non-empty `spi_role_users` so operations
    /// can notice the timing.
    pub fn reload_manifest(
        &mut self,
        handle: ManifestHandle,
        new_json: &str,
    ) -> Result<(), KernelError> {
        // Same immutable peek as `unload_manifest`: reject before
        // touching the lifecycle index so the kernel-required
        // manifests can't be swapped out.
        let immutable = self
            .loaded_manifests
            .get(&handle)
            .map(|r| r.immutable)
            .unwrap_or(false);
        if immutable {
            return Err(KernelError::Validation(format!(
                "ManifestHandle({}) is kernel-immutable (intrinsic step types or other boot-required manifest); cannot reload",
                handle.0
            )));
        }

        let old_record = self.loaded_manifests.remove(&handle).ok_or_else(|| {
            KernelError::NotFound(format!(
                "ManifestHandle({}) not loaded (cannot reload an unknown handle)",
                handle.0
            ))
        })?;

        // Drop registry-side state for the old manifest. Symmetric
        // drift detection with `unload_manifest` — if the lifecycle
        // index claimed an entry the registry doesn't have, surface
        // it before `register_classified_manifest` runs against a
        // half-consistent state. SPI reload doesn't dep-check, but
        // warns when dependents exist so the silent-contract-change
        // failure mode is visible to operations (see method-level
        // docs).
        match &old_record.payload {
            ManifestPayload::SpiDef(_) => {
                if let Some(users) = self.spi_role_users.get(&old_record.identifier)
                    && !users.is_empty()
                {
                    let dependents: Vec<String> = users
                        .iter()
                        .filter_map(|h| self.loaded_manifests.get(h).map(|r| r.identifier.clone()))
                        .collect();
                    tracing::warn!(
                        role = %old_record.identifier,
                        dependents = ?dependents,
                        "Reloading SPI def with active dependents — \
                         contract changes are not revalidated against \
                         existing plugins; verify dependent behaviour \
                         out-of-band",
                    );
                }
                if !self.spi_registry.unregister(&old_record.identifier) {
                    // Restore lifecycle entry so the handle stays
                    // valid; drift surfaces loudly instead of letting
                    // a half-consistent state proceed into register.
                    self.loaded_manifests.insert(handle, old_record);
                    return Err(KernelError::Runtime(format!(
                        "Lifecycle index drift: SPI def '{}' was tracked but missing from SPI registry",
                        self.loaded_manifests[&handle].identifier
                    )));
                }
            }
            ManifestPayload::Plugin(m) => {
                if !self.registry.unregister_plugin(&old_record.identifier) {
                    self.loaded_manifests.insert(handle, old_record);
                    return Err(KernelError::Runtime(format!(
                        "Lifecycle index drift: plugin '{}' was tracked but missing from plugin registry",
                        self.loaded_manifests[&handle].identifier
                    )));
                }
                // Release the old registration's linker imports so the
                // replacement (or the rollback) can re-claim them —
                // without this, re-registering a plugin with a native
                // step type errors on the duplicate import name inside
                // `register_linker_imports` on EVERY subsequent
                // `execute_dag`, for every plugin.
                self.release_step_imports(&old_record.identifier, m);
            }
        }
        // Drift checks have passed — release the lifecycle bookkeeping
        // for the role mappings. Order matches `unload_manifest`:
        // registry scrub first, then bookkeeping.
        self.untrack_manifest(handle);

        // The replacement lands in the namespace the handle was loaded
        // into. A reload is a swap of contents, never a relocation:
        // re-registering into root would change the plugin's identity
        // behind every grant that named it, and in a multi-tenant
        // embedder would promote a tenant's plugin into the embedder's
        // own space.
        let namespace = old_record.namespace.clone();
        match self.register_classified_manifest(new_json, &namespace, false) {
            Ok(new_record) => {
                self.track_manifest(handle, new_record);
                Ok(())
            }
            Err(register_err) => {
                // Restore the original. The retained payload registered
                // cleanly once already against the same registry shape,
                // so re-registration is expected to succeed; if it
                // doesn't, the embedder sees a chained error that
                // names both the new-JSON failure and the rollback
                // failure.
                //
                // The snapshot holds the author's *local* name, so the
                // rollback re-qualifies through the same path the
                // original load took.
                let rollback = match &old_record.payload {
                    ManifestPayload::SpiDef(json) => {
                        self.spi_registry.register(&old_record.identifier, json)
                    }
                    ManifestPayload::Plugin(manifest) => {
                        self.register_plugin_in(&namespace, (**manifest).clone())
                    }
                };
                match rollback {
                    Ok(()) => {
                        // Re-track so the handle remains valid against
                        // the restored old record.
                        self.track_manifest(handle, old_record);
                        Err(register_err)
                    }
                    Err(rollback_err) => Err(KernelError::Runtime(format!(
                        "reload failed and rollback also failed — kernel state is \
                         inconsistent. original error: {register_err}. rollback error: {rollback_err}"
                    ))),
                }
            }
        }
    }

    /// Register a plugin with the kernel. Validates the manifest against SPI
    /// definitions (a registered contract is enforced; an unknown role only
    /// warns — see [`Self::register_spi_from_json`]) and builds a DAG
    /// execution plan per action.
    ///
    /// Each action's step graph is validated for unique ids,
    /// resolvable references, and acyclic shape, then layered into topological
    /// waves. The plan is stored in the registry and consumed by
    /// [`WasmRuntime::execute_dag`] at invocation time.
    ///
    /// Registers into the **root namespace**, so the plugin's identity
    /// is exactly its manifest name. This is the right entry point for
    /// an embedder that supplies its own manifests. An embedder loading
    /// manifests it did not author — a multi-tenant host, say — wants
    /// [`Self::load_manifest`] with
    /// [`in_namespace`](ManifestLoad::in_namespace) instead, so that two
    /// authors choosing the same name cannot collide and neither can
    /// name itself into a trust list.
    pub fn register_plugin(&mut self, manifest: PluginManifest) -> Result<(), KernelError> {
        self.register_plugin_in("", manifest)
    }

    /// [`Self::register_plugin_in_as`] for an embedder-supplied
    /// manifest: this wrapper passes `kernel_owned = false`. Only the
    /// engine's own intrinsics manifest at boot passes `true`, which
    /// makes it the one manifest allowed to declare dot-free (kernel)
    /// step type names.
    pub(crate) fn register_plugin_in(
        &mut self,
        namespace: &str,
        manifest: PluginManifest,
    ) -> Result<(), KernelError> {
        self.register_plugin_in_as(namespace, manifest, false)
    }

    /// Register a plugin into `namespace` — the one path every
    /// registration entry point funnels through.
    ///
    /// This is where a manifest-declared *local name* becomes an
    /// authenticated *identity*, and it is deliberately the only such
    /// place. Several separate registration surfaces would mean several
    /// chances to forget a gate; identity gets one surface so there is
    /// one thing to audit.
    ///
    /// The order matters:
    ///
    /// 1. Validate the namespace (embedder-supplied) and every name the
    ///    manifest declares (author-supplied), while the name is still
    ///    the author's own.
    /// 2. Qualify. From here `manifest.name` **is** the identity, and
    ///    everything downstream — the registry key, `step_import_owners`,
    ///    error messages, `permissions_for` lookups — keys on it without
    ///    knowing namespaces exist. In the root namespace the
    ///    qualification is a true no-op, so root-namespace code never
    ///    sees a separator.
    /// 3. Resolve the manifest's own references relative to its
    ///    namespace, so `invoke:plugin:billing` written by a plugin in
    ///    `tenant42` means `tenant42/billing`.
    ///
    /// Step 1 preceding step 2 is what makes embedder-authenticated
    /// identity hold: the name grammar rejects the separator, so a
    /// manifest cannot pre-qualify itself into another namespace, and a
    /// re-registration of an already-qualified snapshot fails loudly
    /// rather than producing `tenant42/tenant42/billing`.
    fn register_plugin_in_as(
        &mut self,
        namespace: &str,
        mut manifest: PluginManifest,
        kernel_owned: bool,
    ) -> Result<(), KernelError> {
        self::identity::validate_namespace(namespace)
            .map_err(|e| KernelError::Validation(e.to_string()))?;

        // Format version, on the struct path. The JSON path's meta-schema
        // already pins `formatVersion` to the supported value; a struct
        // built in code skips the schema, so without this a
        // `register_plugin(PluginManifest { format_version: Some(2), … })`
        // would be accepted and misread by a kernel that knows only v1.
        if let Some(v) = manifest.format_version
            && v != self::types::SUPPORTED_FORMAT_VERSION
        {
            return Err(KernelError::Validation(format!(
                "Plugin '{}': formatVersion {v} is not supported by this kernel \
                 (supports {})",
                manifest.name,
                self::types::SUPPORTED_FORMAT_VERSION
            )));
        }

        // Name grammar, before anything uses a name as a key. Every
        // identifier validated here is a kernel-global lookup key, a
        // wasm linker import name, or a substring of a permission
        // string — so an unconstrained one is an ambiguity in the
        // grammar rather than a cosmetic issue. See `identity` for the
        // two live cases (`*` and `:`) and for why the namespace
        // separator is reserved.
        validate_manifest_names(&manifest, kernel_owned).map_err(KernelError::Validation)?;

        // `usesSecrets`: a key declared twice is ambiguous once the
        // entries can disagree about `overridable` — refuse it rather
        // than pick one. And only the level that owns a key may mark
        // it overridable, for the levels below. At depth two that is
        // root only — a tenant has nobody below it to offer an override
        // to, and letting it mark keys anyway would be a claim the
        // kernel cannot honour.
        {
            let mut seen = std::collections::HashSet::new();
            if let Some(dup) = manifest
                .uses_secrets
                .iter()
                .find(|d| !seen.insert(d.key.as_str()))
            {
                return Err(KernelError::Validation(format!(
                    "Plugin '{}': `usesSecrets` declares '{}' more than once",
                    manifest.name, dup.key
                )));
            }
        }
        if !namespace.is_empty()
            && let Some(marked) = manifest.uses_secrets.iter().find(|d| d.overridable)
        {
            return Err(KernelError::Validation(format!(
                "Plugin '{}': `usesSecrets` marks '{}' overridable, which only a \
                 root-namespace manifest may do (this one is loaded into namespace \
                 '{namespace}'). Only the level that owns a secret may mark it overridable \
                 by the levels below it",
                manifest.name, marked.key
            )));
        }

        let manifest_local_name = manifest.name.clone();
        manifest.name = self::identity::qualify(namespace, &manifest.name);
        let plugin_name = manifest.name.clone();

        // Duplicate-plugin detection. `PluginRegistry::register_manifest`
        // would silently overwrite, leaving the previous registration's
        // runtime imports and lifecycle records dangling. Replacement is
        // a first-class operation — `reload_manifest` — not a side
        // effect of re-registering a name.
        if self.registry.get_manifest(&plugin_name).is_some() {
            return Err(KernelError::Validation(format!(
                "Plugin '{plugin_name}' is already registered. Reload it via \
                 `reload_manifest` (for manifests loaded through `load_manifest`) \
                 or unload it first"
            )));
        }

        // Validate against SPI definitions: a registered contract is
        // enforced, an unknown role only warns.
        let validation = validator::validate_manifest(&manifest, namespace, &self.spi_registry);
        for warning in &validation.warnings {
            tracing::warn!(plugin = %plugin_name, "{warning}");
        }
        if !validation.is_valid() {
            let errors: Vec<String> = validation.errors.iter().map(|e| e.to_string()).collect();
            return Err(KernelError::Validation(format!(
                "Plugin '{}' failed SPI validation: {}",
                plugin_name,
                errors.join("; ")
            )));
        }

        // Validate the manifest's permission set. Default-deny
        // means an empty list grants nothing; malformed entries reject
        // the plugin outright so authoring mistakes surface at install
        // time, not at first http_call. The parsed list is stored in
        // the registry below alongside the actions.
        //
        // `parse_manifest_permissions`, not `parse_permission_list`:
        // the second checks only the kernel's own categories and lets
        // any dot-namespaced one through unexamined. Every registration
        // funnels through here, so this one call site is the whole
        // enforcement of the embedder-category rule.
        let parsed_permissions = permissions::parse_manifest_permissions(
            &manifest.permissions,
            &self.app_permission_categories,
        )
        .map_err(|e| {
            KernelError::Validation(format!(
                "Plugin '{plugin_name}': permission parse error: {e}"
            ))
        })?;

        // Grant targets are stored as the manifest wrote them — bare
        // local names — and resolved along the declaring plugin's
        // ancestor chain at check time, by the same walk a reference
        // resolves through (`Self::resolve_plugin_reference`). Resolving
        // at load would freeze the answer against the registry as it
        // was then; resolving at check time keeps grant and reference
        // pointing at the same plugin whatever has loaded since.

        // Validate step-type aliases. Fast-fail before any state
        // mutation — alias bugs are common authoring mistakes and we
        // want a clear rejection rather than a partially-registered
        // plugin.
        for (alias, target_action) in &manifest.step_types {
            validate_step_type_alias(alias, &manifest_local_name, kernel_owned)
                .map_err(|e| KernelError::Validation(format!("Plugin '{plugin_name}': {e}")))?;
            if !manifest.actions.contains_key(target_action) {
                return Err(KernelError::Validation(format!(
                    "Plugin '{plugin_name}': step_types alias '{alias}' targets \
                     action '{target_action}' which is not defined in this plugin"
                )));
            }
            if let Some(existing) = self
                .registry
                .step_type_alias_candidates(&self::registry::PluginRegistry::step_type_key(
                    &plugin_name,
                    alias,
                ))
                .into_iter()
                .next()
            {
                return Err(KernelError::Validation(format!(
                    "Plugin '{plugin_name}': step_types alias '{alias}' already \
                     registered by plugin '{}' (action '{}')",
                    existing.0, existing.1
                )));
            }
        }

        // Cross-plugin step-type conflict detection, BEFORE any state
        // mutation. Everything that will land in the runtime's linker
        // import table — native impls, intrinsic impls, alias
        // dispatchers — must be unclaimed or already ours; two live
        // implementations of one step type would silently shadow each
        // other in dispatch. Checking the whole set up front means the
        // later claim inserts can't fail halfway through registration.
        {
            let mut pending_imports: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            let impl_names = manifest
                .step_type_impls
                .iter()
                // `wasm`-kind impls route through selector dispatch
                // (e.g. `script` + `matches`), not the linker table —
                // many plugins legitimately share that step type name.
                .filter(|decl| !matches!(decl.kind, types::StepTypeImplKind::Wasm))
                .map(|decl| decl.step_type.as_str());
            for name in impl_names.chain(manifest.step_types.keys().map(String::as_str)) {
                let key = self::registry::PluginRegistry::step_type_key(&plugin_name, name);
                if let Some(owner) = self.step_import_owners.get(&key)
                    && owner != &plugin_name
                {
                    return Err(KernelError::Validation(format!(
                        "Plugin '{plugin_name}': step type '{name}' is already \
                         implemented by plugin '{owner}' — unload '{owner}' first \
                         or rename the step type"
                    )));
                }
                if !pending_imports.insert(key) {
                    return Err(KernelError::Validation(format!(
                        "Plugin '{plugin_name}': step type '{name}' is declared \
                         more than once in this manifest (stepTypeImpls entries \
                         and step_types aliases share one namespace)"
                    )));
                }
            }
        }

        // Streaming-dataflow consistency checks. The
        // flags form a small invariant:
        //
        //   1. an action is *either* dataflow or continuous, not both
        //   2. `long_running: true` is only meaningful when the parent
        //      action is dataflow
        //   3. a dataflow action needs ≥1 long_running step — without
        //      one the scheduler pre-provisions no streams and the
        //      action is semantically a parallel-wave action wearing
        //      the wrong flag.
        for (action_name, action) in &manifest.actions {
            if action.dataflow && action.continuous {
                return Err(KernelError::Validation(format!(
                    "Plugin '{plugin_name}' action '{action_name}': \
                     action cannot be both `dataflow: true` and `continuous: true` — \
                     dataflow IS the long-running form"
                )));
            }
            if action.dataflow && !action.steps.iter().any(|s| s.long_running) {
                return Err(KernelError::Validation(format!(
                    "Plugin '{plugin_name}' action '{action_name}': \
                     action is `dataflow: true` but no step is marked \
                     `long_running: true` — a dataflow action needs at \
                     least one long-running producer for the scheduler \
                     to provision streams against"
                )));
            }
            if !action.dataflow {
                for step in &action.steps {
                    if step.long_running {
                        return Err(KernelError::Validation(format!(
                            "Plugin '{plugin_name}' action '{action_name}': \
                             step '{}' is marked `long_running: true` but the action \
                             is not `dataflow: true` — long_running is only meaningful \
                             in a streaming-dataflow action",
                            step.id
                        )));
                    }
                }
            }
            // `wallclock_timeout_ms: 0` would intuitively read as "no
            // cap" but actually produces `Duration::from_millis(0)`
            // and instant `ExecutionTimeout`. Reject loud so authors
            // catch it at install time, not at first invocation.
            if let Some(0) = action.wallclock_timeout_ms {
                return Err(KernelError::Validation(format!(
                    "Plugin '{plugin_name}' action '{action_name}': \
                     `wallclock_timeout_ms: 0` is invalid (would trip \
                     ExecutionTimeout immediately). Omit the field or set \
                     `null` to fall through to the deployment default; mark the \
                     action `dataflow: true` for the uncapped variant"
                )));
            }
        }

        // Plan-build + DAG validation per action.
        let mut planned: Vec<(String, Action, dag::DagPlan)> =
            Vec::with_capacity(manifest.actions.len());
        for (action_name, action) in &manifest.actions {
            let plan = self::dag::build_plan(action).map_err(|e| {
                KernelError::Validation(format!(
                    "Plugin '{plugin_name}' action '{action_name}': {e}"
                ))
            })?;
            planned.push((action_name.clone(), action.clone(), plan));
        }

        // Step shape validation. Walk every step in
        // every action — including nested bodies (for_each / repeat /
        // ifs / try / parallel) — and reject:
        //
        // - `script` step instances whose `language` field references
        //   a runtime the kernel has no implementation for.
        // - Malformed or wrongly-typed nested step bodies.
        for (action_name, action) in &manifest.actions {
            validate_step_shapes(
                action_name,
                &action.steps,
                &self.registry,
                &manifest.step_type_impls,
            )
            .map_err(|e| KernelError::Validation(format!("Plugin '{plugin_name}': {e}")))?;
        }

        // wasm_modules compilation. Decode each
        // declared module and compile it via the runtime's wasm
        // engine; cache the resulting `Arc<Module>` on the registry
        // keyed by `(plugin, module_name)` so the `wasm` step type's
        // body can instantiate cheaply per invocation.
        //
        // Path-based modules are rejected: the kernel has no
        // manifest-resource-directory resolver, so only the inline
        // form is loadable.
        use base64::Engine as _;
        let mut compiled_wasm: Vec<(String, std::sync::Arc<Module>)> = Vec::new();
        for (module_name, spec) in &manifest.wasm_modules {
            let bytes = match spec {
                types::WasmModuleSpec::Inline { base64 } => {
                    base64::engine::general_purpose::STANDARD
                        .decode(base64)
                        .map_err(|e| {
                            KernelError::Validation(format!(
                                "Plugin '{plugin_name}' wasm_module '{module_name}': base64 \
                             decode failed: {e}"
                            ))
                        })?
                }
                types::WasmModuleSpec::Path { .. } => {
                    return Err(KernelError::Validation(format!(
                        "Plugin '{plugin_name}' wasm_module '{module_name}': path-based \
                         wasm modules are not supported by this kernel; use the base64-inline form"
                    )));
                }
            };
            let module = Module::new(self.runtime.engine(), &bytes).map_err(|e| {
                KernelError::Validation(format!(
                    "Plugin '{plugin_name}' wasm_module '{module_name}': compile failed: {e}"
                ))
            })?;
            compiled_wasm.push((module_name.clone(), std::sync::Arc::new(module)));
        }

        // Structural cycle detection across all by-plugin invokes and
        // plugin-supplied step-type aliases. By-role invokes and
        // unresolved aliases aren't statically resolvable and rely on
        // the runtime depth cap (host_api::INVOKE_MAX_DEPTH).
        //
        // The resolver consults both the registry (for aliases already
        // registered by prior plugins) and this plugin's own
        // pending `step_types` map (for cycles within the new plugin's
        // own actions). Without the local pass, a plugin that exposes
        // action A via alias `foo` and has another action B that calls
        // `{"type":"foo"}` would skip the edge during this plugin's own
        // registration check.
        let mut new_edges: Vec<self::invoke::InvokeEdge> = Vec::new();
        let registry = &self.registry;
        let local_aliases = &manifest.step_types;
        let local_plugin_name = &plugin_name;
        let resolver = |alias: &str| -> Option<(String, String)> {
            if let Some(local) = local_aliases.get(alias) {
                return Some((local_plugin_name.clone(), local.clone()));
            }
            // A written alias resolves along this plugin's chain, the
            // same way `step_type_access_for` will resolve it at run
            // time — nearest namespace first.
            if !alias.contains(self::identity::STEP_TYPE_SEPARATOR) {
                return None;
            }
            self::identity::ancestor_namespaces(self::identity::namespace_of(local_plugin_name))
                .find_map(|ns| {
                    registry
                        .step_type_alias_candidates(&self::identity::qualify(ns, alias))
                        .into_iter()
                        .next()
                })
        };
        for (action_name, action, _) in &planned {
            let edges =
                self::invoke::collect_edges(&plugin_name, action_name, action, &resolver)
                    .map_err(|e| KernelError::Validation(format!("Plugin '{plugin_name}': {e}")))?;
            new_edges.extend(edges);
        }
        // Declarative cross-plugin references. A step
        // type def can declare `references: [{plugin, action}]` —
        // top-level key names in the step's params that hold the
        // target plugin + action. The walker resolves them at
        // registration time, rejects unknown targets, and emits
        // edges for cycle detection alongside the hardcoded invoke
        // walker above.
        let local_step_type_defs: std::collections::HashMap<String, types::StepTypeDef> = manifest
            .step_type_defs
            .iter()
            .map(|d| (d.name.clone(), d.clone()))
            .collect();
        let local_action_names: std::collections::HashSet<String> =
            manifest.actions.keys().cloned().collect();
        let def_resolver = |step_type: &str| -> Option<types::StepTypeDef> {
            local_step_type_defs.get(step_type).cloned().or_else(|| {
                self.registry
                    .get_step_type_def(step_type)
                    .map(|(_, d)| d.clone())
            })
        };
        let plugin_exists = |name: &str| -> bool {
            name == plugin_name.as_str() || self.registry.get_manifest(name).is_some()
        };
        let action_exists = |target_plugin: &str, target_action: &str| -> bool {
            if target_plugin == plugin_name.as_str() {
                return local_action_names.contains(target_action);
            }
            self.registry
                .get_action(target_plugin, target_action)
                .is_some()
        };
        for (action_name, action, _) in &planned {
            let declared = self::invoke::collect_declared_references(
                &plugin_name,
                action_name,
                action,
                &def_resolver,
                &plugin_exists,
                &action_exists,
            )
            .map_err(|e| KernelError::Validation(format!("Plugin '{plugin_name}': {e}")))?;
            new_edges.extend(declared);
        }
        self::invoke::check_acyclic(self.registry.invoke_edges(), &new_edges)
            .map_err(|e| KernelError::Validation(format!("Plugin '{plugin_name}': {e}")))?;

        // ─── Last fallible step: resolve step type defs and impls ───
        //
        // Everything below this call is an infallible commit. That
        // ordering rules out a whole class of bug: validation that
        // runs *after* mutation has already begun, returning `Err`
        // with no rollback.
        //
        // What that would produce is a **ghost plugin** — not in the
        // registry and holding no `ManifestHandle`, so it could never
        // be unloaded, yet owning its step type names against all
        // comers, with its actions still executing and no permission
        // set ever stored. It would also defeat `reload_manifest`'s
        // rollback: re-registering the retained old manifest would
        // collide with the failed attempt's leftovers and land in the
        // "kernel state is inconsistent" terminal branch, destroying a
        // healthy plugin.
        //
        // `prepare_step_types` does every check and resolves every
        // impl reference to a concrete function pointer, so the commit
        // below has nothing left to reject. Keep it that way: a new
        // `?` after this line reintroduces the ghost-plugin failure.
        let prepared = self.prepare_step_types(&manifest, &parsed_permissions)?;

        for (action_name, action, plan) in planned {
            self.registry
                .register_action(&plugin_name, &action_name, action, plan);
        }
        // Wasm modules — install after action registration so the
        // `wasm` step type body's registry lookup sees them at
        // first-action-invocation time.
        for (module_name, module) in compiled_wasm {
            self.registry
                .register_plugin_wasm_module(&plugin_name, &module_name, module);
        }

        // ─── Commit. Nothing below may fail. ───
        //
        // `prepare_step_types` above rejected every invalid shape and
        // resolved every impl reference, so each call here is a plain
        // insert into a slot the pre-flight proved is free.

        for def in prepared.defs {
            self.registry.commit_step_type_def(&plugin_name, def);
        }
        for entry in prepared.impls {
            match entry {
                PreparedStepImpl::Wasm {
                    step_type,
                    matches,
                    wasm_module,
                } => {
                    self.registry.commit_step_type_impl(
                        &plugin_name,
                        &step_type,
                        matches.as_deref(),
                        &wasm_module,
                    );
                }
                PreparedStepImpl::Native { step_type, body } => {
                    // Native impls route through the same wasmtime
                    // linker path `register_trait_step_type` uses: the
                    // step type's registry KEY becomes the linker import
                    // name (`step_<key>`), so two namespaces' `vault.sign`
                    // get two imports. The manifest entry is the
                    // declarative front-end to that registration.
                    let key =
                        self::registry::PluginRegistry::step_type_key(&plugin_name, &step_type);
                    self.step_import_owners
                        .insert(key.clone(), plugin_name.clone());
                    self.runtime.register_trait_step_type(&key, body);
                }
                PreparedStepImpl::Intrinsic { step_type, body } => {
                    let key =
                        self::registry::PluginRegistry::step_type_key(&plugin_name, &step_type);
                    self.step_import_owners
                        .insert(key.clone(), plugin_name.clone());
                    self.runtime.register_intrinsic_step_type(&key, body);
                }
            }
        }

        self.registry.extend_invoke_edges(new_edges);

        // Register manifest and SPI role mappings. Subscriptions and
        // step-type aliases drive their own dedicated dispatch indices
        // (`PluginRegistry::subscriptions` and `step_type_aliases`).
        self.registry.register_manifest(&manifest);
        // A fulfilment binds to the nearest *defined* contract up the
        // plugin's chain — its tenant's `LLM_CHAT` if the tenant defined
        // one, else the global one — and to the plugin's own namespace
        // when nothing on the chain defines it (unknown role, warned
        // above). Selection then finds it by walking the caller's chain
        // the same way; see `Self::role_candidates`.
        for key in self.role_keys_for(namespace, &manifest.roles) {
            self.registry.register_role(&key, &plugin_name);
        }

        // Store the parsed permission set so host step functions can
        // look it up by plugin name at runtime. Stored after
        // SPI validation succeeds so a half-registered plugin doesn't
        // leave stale permissions behind.
        self.registry
            .set_permissions(&plugin_name, parsed_permissions);

        // Step-type alias registration. Each alias is published
        // both in the registry (for cycle detection + introspection) and
        // as a host import on the runtime under the alias name. The
        // dispatcher fn is shared across all aliases; it pulls the
        // (plugin, action) pair out of the registry at execution time
        // via the kernel back-ref.
        //
        // Infallible: alias validity, registry conflicts, and
        // within-manifest duplicates were all rejected in the
        // pre-flight block above, so this claim cannot lose a race it
        // has already won.
        for (alias, target_action) in &manifest.step_types {
            self.registry
                .commit_step_type_alias(alias, &plugin_name, target_action);
            let key = self::registry::PluginRegistry::step_type_key(&plugin_name, alias);
            self.step_import_owners
                .insert(key.clone(), plugin_name.clone());
            self.runtime
                .register_intrinsic_step_type(&key, host_api::step_alias_dispatch);
        }

        // Subscription index: event_type → (plugin, action)*. Walked
        // by `Kernel::dispatch_event` at event-firing time. The
        // subscriber index is global; see `dispatch_event` for why
        // events are not namespace-scoped.
        for (action_name, action) in &manifest.actions {
            for event_type in &action.subscribes_to {
                self.registry
                    .register_subscription(event_type, &plugin_name, action_name);
            }
        }

        tracing::info!(
            plugin = %plugin_name,
            roles = ?manifest.roles,
            actions = ?manifest.actions.keys().collect::<Vec<_>>(),
            "Plugin registered"
        );
        Ok(())
    }

    /// Validate every `stepTypeDefs` and `stepTypeImpls` entry in a
    /// manifest and resolve each impl reference to something the
    /// commit phase can install without failing.
    ///
    /// Takes `&self`: this function must not mutate, because its whole
    /// purpose is to be the last thing that can say no.
    fn prepare_step_types(
        &self,
        manifest: &PluginManifest,
        parsed_permissions: &[permissions::Permission],
    ) -> Result<PreparedStepTypes, KernelError> {
        let plugin_name = manifest.name.as_str();
        let mut defs = Vec::with_capacity(manifest.step_type_defs.len());
        // Def names this manifest contributes. Impl entries resolve
        // against these as well as the registry, since a manifest
        // normally ships a def and its impl together.
        let mut local_defs: std::collections::HashSet<&str> = std::collections::HashSet::new();

        for def in &manifest.step_type_defs {
            // `result` is reserved — it's the value slot
            // (`{{$steps.<id>.result}}`), not a sidecar. A metadataSchema
            // that declared it would shadow the step's value in the
            // resolution view.
            if let Some(props) = def
                .metadata_schema
                .as_ref()
                .and_then(|schema| schema.get("properties"))
                .and_then(|props| props.as_object())
                && props.contains_key("result")
            {
                return Err(KernelError::Validation(format!(
                    "Plugin '{plugin_name}': step type '{}' metadataSchema declares the \
                     reserved key 'result' — that is the value slot \
                     (`{{{{$steps.<id>.result}}}}`), not a metadata sidecar",
                    def.name
                )));
            }
            if let Some((existing, _)) =
                self.registry
                    .get_step_type_def(&self::registry::PluginRegistry::step_type_key(
                        plugin_name,
                        &def.name,
                    ))
            {
                return Err(KernelError::Validation(format!(
                    "Plugin '{plugin_name}': step_type_defs entry '{}' already \
                     registered by plugin '{existing}'",
                    def.name
                )));
            }
            if !local_defs.insert(def.name.as_str()) {
                return Err(KernelError::Validation(format!(
                    "Plugin '{plugin_name}': step_type_defs entry '{}' is declared \
                     twice in this manifest",
                    def.name
                )));
            }
            defs.push(def.clone());
        }

        let mut impls = Vec::with_capacity(manifest.step_type_impls.len());
        // Slots claimed by earlier entries of this same manifest, so
        // two entries fighting over one slot is caught here rather
        // than by the second `commit` silently overwriting the first.
        let mut local_slots: std::collections::HashSet<(&str, Option<&str>)> =
            std::collections::HashSet::new();

        for impl_decl in &manifest.step_type_impls {
            let step_type = impl_decl.step_type.as_str();
            let matches = impl_decl.matches.as_deref();

            // impl ⇒ def: every step type an impl claims must have a
            // declared contract, resolved against this manifest's own
            // defs ∪ the boot-time intrinsics ∪ earlier plugins' defs.
            //
            // Ordering constraint: a def shipped by a *later*-registered
            // plugin is not visible. A manifest whose impl references a
            // def in a sibling manifest must be registered after that
            // sibling.
            let defines_locally = local_defs.contains(step_type);
            if !defines_locally
                && self
                    .registry
                    .get_step_type_def(&self::registry::PluginRegistry::step_type_key(
                        plugin_name,
                        step_type,
                    ))
                    .is_none()
            {
                return Err(KernelError::Validation(format!(
                    "Plugin '{plugin_name}': step_type_impls entry for '{step_type}' has no \
                     StepTypeDef — every step type must declare a contract. Add a \
                     `stepTypeDefs` entry named '{step_type}' to this manifest (or reference an \
                     intrinsic / already-registered def)."
                )));
            }

            self.check_step_type_impl_claim(
                plugin_name,
                step_type,
                matches,
                defines_locally,
                parsed_permissions,
            )?;

            if !local_slots.insert((step_type, matches)) {
                let m_desc = matches
                    .map(|s| format!(" (matches: '{s}')"))
                    .unwrap_or_default();
                return Err(KernelError::Validation(format!(
                    "Plugin '{plugin_name}': step_type_impls entry for \
                     '{step_type}'{m_desc} is declared twice in this manifest"
                )));
            }

            impls.push(match impl_decl.kind {
                types::StepTypeImplKind::Wasm => {
                    let Some(wasm_module) = impl_decl.wasm_module.as_deref() else {
                        return Err(KernelError::Validation(format!(
                            "Plugin '{plugin_name}': step_type_impls entry for '{step_type}' \
                             has kind: \"wasm\" but no `wasmModule` field"
                        )));
                    };
                    if impl_decl.impl_ref.is_some() {
                        return Err(KernelError::Validation(format!(
                            "Plugin '{plugin_name}': step_type_impls entry for '{step_type}' \
                             has kind: \"wasm\" but also sets `implRef` — fields \
                             are mutually exclusive"
                        )));
                    }
                    if !manifest.wasm_modules.contains_key(wasm_module) {
                        return Err(KernelError::Validation(format!(
                            "Plugin '{plugin_name}': step_type_impls entry for '{step_type}' \
                             references wasm_module '{wasm_module}' which isn't declared in \
                             this manifest's `wasm_modules`"
                        )));
                    }
                    if let Some((existing_plugin, existing_module)) =
                        self.registry.step_type_impl_owner(
                            &self::registry::PluginRegistry::step_type_key(plugin_name, step_type),
                            matches,
                        )
                    {
                        let m_desc = matches
                            .map(|s| format!(" (matches: '{s}')"))
                            .unwrap_or_default();
                        return Err(KernelError::Validation(format!(
                            "Plugin '{plugin_name}': step_type_impls entry for \
                             '{step_type}'{m_desc} already registered by plugin \
                             '{existing_plugin}' (wasm_module '{existing_module}')"
                        )));
                    }
                    PreparedStepImpl::Wasm {
                        step_type: step_type.to_string(),
                        matches: matches.map(String::from),
                        wasm_module: wasm_module.to_string(),
                    }
                }
                types::StepTypeImplKind::Native => {
                    let impl_ref = Self::require_impl_ref(plugin_name, impl_decl, "native")?;
                    // Whose body is this? Checked before resolution, so
                    // an unauthorised binding is refused whether or not
                    // the reference happens to exist.
                    self.check_native_impl_binding(
                        plugin_name,
                        step_type,
                        impl_ref,
                        parsed_permissions,
                    )?;
                    let body = self.native_step_impls.get(impl_ref).ok_or_else(|| {
                        KernelError::Validation(format!(
                            "Plugin '{plugin_name}': step_type_impls entry for \
                             '{step_type}' references native implRef '{impl_ref}' which \
                             no plugin crate submitted via inventory::submit!. \
                             Check that the providing crate is compiled into \
                             the host binary and uses the same name string"
                        ))
                    })?;
                    PreparedStepImpl::Native {
                        step_type: step_type.to_string(),
                        body,
                    }
                }
                types::StepTypeImplKind::Intrinsic => {
                    let impl_ref = Self::require_impl_ref(plugin_name, impl_decl, "intrinsic")?;
                    // Intrinsic bodies are kernel-internal: only the
                    // engine's own `gwead.intrinsics.*` submissions are
                    // in this table, so an external manifest that sets
                    // `kind: "intrinsic"` can't smuggle in a body it
                    // didn't (and couldn't) submit.
                    //
                    // The lookup is by implRef alone, so a manifest *can*
                    // rebind an intrinsic body to an arbitrary `stepType`
                    // name. That's harmless, not a leak: invoke / wasm /
                    // script are already first-class under their
                    // canonical step types, and the invoke grant check
                    // lives inside the intrinsic body rather than at the
                    // dispatch name, so a second alias grants no
                    // capability the manifest didn't already have.
                    let body = self.intrinsic_step_impls.get(impl_ref).ok_or_else(|| {
                        KernelError::Validation(format!(
                            "Plugin '{plugin_name}': step_type_impls entry for \
                             '{step_type}' references intrinsic implRef '{impl_ref}' which \
                             the engine did not submit via inventory::submit!. \
                             Intrinsic bodies are kernel-internal — only \
                             gwead.intrinsics.* names exist"
                        ))
                    })?;
                    PreparedStepImpl::Intrinsic {
                        step_type: step_type.to_string(),
                        body,
                    }
                }
            });
        }

        Ok(PreparedStepTypes { defs, impls })
    }

    /// Shared field-shape check for the two `implRef`-bearing impl
    /// kinds. Both require `implRef`, forbid `wasmModule`, and forbid
    /// `matches` — dispatch for them goes through the wasmtime linker
    /// by step type name, which has no per-selector routing.
    fn require_impl_ref<'a>(
        plugin_name: &str,
        impl_decl: &'a types::StepTypeImpl,
        kind: &str,
    ) -> Result<&'a str, KernelError> {
        let step_type = &impl_decl.step_type;
        let Some(impl_ref) = impl_decl.impl_ref.as_deref() else {
            return Err(KernelError::Validation(format!(
                "Plugin '{plugin_name}': step_type_impls entry for '{step_type}' \
                 has kind: \"{kind}\" but no `implRef` field"
            )));
        };
        if impl_decl.wasm_module.is_some() {
            return Err(KernelError::Validation(format!(
                "Plugin '{plugin_name}': step_type_impls entry for '{step_type}' \
                 has kind: \"{kind}\" but also sets `wasmModule` — fields are \
                 mutually exclusive"
            )));
        }
        if impl_decl.matches.is_some() {
            return Err(KernelError::Validation(format!(
                "Plugin '{plugin_name}': step_type_impls entry for '{step_type}' \
                 has kind: \"{kind}\" with `matches` set; {kind} impls are \
                 selector-less (dispatch goes through the wasmtime linker by step \
                 type name, which has no per-selector routing)"
            )));
        }
        Ok(impl_ref)
    }

    /// Which step types may `plugin` run, resolved once at invocation
    /// setup and carried on the invocation.
    ///
    /// This is the gate on **direct** step dispatch, the companion to
    /// the one on the alias path. `runtime::run_step` consults the
    /// result; [`Self::explain_step_type_refusal`] supplies the
    /// operator-facing reason on refusal.
    ///
    /// # Why this is one function
    ///
    /// Direct dispatch and alias dispatch both reach another plugin's
    /// body, and a default-deny gate placed only on the call sites its
    /// author enumerated is a gate with a path around it: a plugin
    /// declaring nothing (no `stepTypeDefs`, no `permissions`) could
    /// run another plugin's privileged body by naming it, and a plugin
    /// in a namespace could run a **root** plugin's body, crossing the
    /// boundary namespaces exist to draw. The decision therefore lives
    /// on `Kernel` beside the other two-key checks — one function,
    /// findable by anyone adding another dispatch path.
    ///
    /// # The rule
    ///
    /// In order:
    ///
    /// 1. **Reserved intrinsics are always allowed.** `let`, `ifs`,
    ///    `script` and the rest are kernel primitives, not a plugin's
    ///    property, even though `gwead_intrinsics` is nominally their
    ///    owner. Deciding they are universally available *is* the rule
    ///    here, not an exemption from it.
    /// 2. **Your own step types are always allowed.**
    /// 3. **A def marked [`freelyUsable`](types::StepTypeDef::freely_usable)
    ///    is allowed.** The provider decides whether using their
    ///    capability is privileged.
    /// 4. **Otherwise `step_type:<name>` is required.**
    ///
    /// An *unknown* step type is allowed through: it fails immediately
    /// afterwards at the linker with "Host function not registered",
    /// which is the clearer diagnostic. Refusing here would also turn
    /// every typo into a security-shaped message.
    pub(crate) fn step_type_access_for(&self, plugin: &str) -> host_api::StepTypeAccess {
        let grants = self.registry.permissions_for(plugin);
        let mut allowed: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut body_owners = std::collections::HashMap::new();

        // Resolution is a chain walk, nearest namespace first: the first
        // registration of a written name on the chain wins, so a
        // tenant's `vault.sign` shadows root's for that tenant's steps.
        // Kernel (bare) names live in root and are reached by everyone.
        // Walking nearest-first and inserting only if absent is what
        // implements "first hit wins".
        let plugin_ns = self::identity::namespace_of(plugin);
        for ns in self::identity::ancestor_namespaces(plugin_ns) {
            for (key, owner, def) in self.registry.step_type_defs_iter() {
                if self::identity::namespace_of(owner) != ns {
                    continue;
                }
                let written = def.name.as_str();
                if allowed.contains_key(written) {
                    continue;
                }
                if owner == plugin
                    || def.freely_usable
                    || permissions::check_step_type(grants, written).is_granted()
                {
                    allowed.insert(written.to_string(), key.to_string());
                    // A body shipped by another plugin runs with *its
                    // owner's* view of secrets, not this execution's.
                    // Carry the owner and what it declared so the step
                    // dispatcher can pull that view without a kernel
                    // back-reference.
                    if owner != plugin
                        && let Some(m) = self.registry.get_manifest(owner)
                    {
                        body_owners.insert(
                            written.to_string(),
                            host_api::BodyOwner {
                                identity: owner.to_string(),
                                declared_keys: m.declared_secret_keys(),
                                overridable_keys: m.overridable_secret_keys(),
                            },
                        );
                    }
                }
            }
            // Aliases share the step-type name space but live in their
            // own table, so they need the same pass or every alias step
            // would be refused. There is no `freelyUsable` equivalent:
            // an alias dispatches into its owner's *action*, which is
            // cross-plugin invocation wearing a step type's clothes, and
            // that is never free.
            for (key, owner) in self.registry.step_type_aliases_iter() {
                if self::identity::namespace_of(owner) != ns {
                    continue;
                }
                let written = self::identity::local_name_of(key);
                if allowed.contains_key(written) {
                    continue;
                }
                if owner == plugin || permissions::check_step_type(grants, written).is_granted() {
                    allowed.insert(written.to_string(), key.to_string());
                }
            }
        }
        host_api::StepTypeAccess::new(allowed, body_owners)
    }

    /// The operator-facing reason a step type was refused, looked up
    /// after [`host_api::StepTypeAccess::resolve`] has already said no.
    ///
    /// Separate from the decision on purpose: the decision has to work
    /// without a kernel reference, but the *message* is only ever needed
    /// on the failure path, where taking a registry lookup is free and
    /// naming the owner is worth a great deal to whoever has to fix it.
    pub(crate) fn explain_step_type_refusal(&self, caller_plugin: &str, step_type: &str) -> String {
        // Explain against the nearest registration on the caller's
        // chain — the one the caller would have reached.
        let nearest_def =
            self::identity::ancestor_namespaces(self::identity::namespace_of(caller_plugin))
                .find_map(|ns| {
                    let key = if step_type.contains(self::identity::STEP_TYPE_SEPARATOR) {
                        self::identity::qualify(ns, step_type)
                    } else {
                        step_type.to_string()
                    };
                    self.registry
                        .get_step_type_def(&key)
                        .map(|(owner, _)| owner.to_string())
                });
        if let Some(owner) = nearest_def {
            return format!(
                "plugin '{caller_plugin}' may not use step type '{step_type}', which is \
                 defined by plugin '{owner}'. Add \"step_type:{step_type}\" to this \
                 manifest's `permissions`, or — if the step type is safe for anyone to \
                 call — have '{owner}' mark its `stepTypeDefs` entry \"freelyUsable\": true"
            );
        }
        // Aliases carry no def, so they land here rather than above.
        // There is no `freelyUsable` route to offer: an alias dispatches
        // into its owner's action, so the grant is the only answer.
        if let Some(owner) = self
            .registry
            .step_type_aliases_iter()
            .find(|(key, _)| self::identity::local_name_of(key) == step_type)
            .map(|(_, owner)| owner.to_string())
        {
            return format!(
                "plugin '{caller_plugin}' lacks step_type:{step_type} permission (add it \
                 to the manifest's `permissions` list). Step type '{step_type}' is an \
                 alias registered by plugin '{owner}', so using it dispatches into that \
                 plugin's action"
            );
        }
        format!(
            "plugin '{caller_plugin}' lacks step_type:{step_type} permission, and no \
             registered `stepTypeDefs` entry or alias defines '{step_type}'"
        )
    }

    /// May `plugin_name` bind the native body `impl_ref`?
    ///
    /// Two axes govern a `stepTypeImpls` entry, and a check on only one
    /// of them leaves a hole:
    ///
    /// | Question | Gate |
    /// |---|---|
    /// | Which slot am I filling? | `provide:step_type:` + [`Self::check_step_type_impl_claim`] |
    /// | Whose body am I binding? | this |
    ///
    /// A plugin could declare a step type of its own — satisfying the
    /// first gate honestly — and point `implRef` at another plugin's
    /// privileged body, if resolution were one flat lookup on a global
    /// table.
    ///
    /// The rule:
    ///
    /// - **Free path.** Binding a body you own needs no declaration and
    ///   no authorisation. Ownership is the implRef's middle segment
    ///   (`<owner>.<plugin>.<step>`) matching your own local name —
    ///   **and only in the root namespace.**
    /// - **Escape hatch.** Anything else needs
    ///   `bind:native_impl:<implRef>` in the manifest **and** the exact
    ///   `(identity, implRef)` pair in
    ///   [`KernelConfig::native_impl_bindings`].
    ///
    /// ## Why the free path is root-only
    ///
    /// It rests on an assumption that holds in root and nowhere else:
    /// that the plugin binding a body and the crate that shipped it are
    /// the same party. Native bodies are compiled into the host binary,
    /// so in root — where an embedder loads manifests it wrote itself —
    /// a plugin named `vault` binding `myapp.vault.sign` is the vault
    /// author binding their own code.
    ///
    /// A namespace exists precisely because those manifests are *not*
    /// embedder-authored. If the free path applied there, a tenant who
    /// named their plugin `vault` would freely bind `myapp.vault.sign`
    /// — the same hole, wearing a namespace — and the escape hatch
    /// would never engage in the one case it exists for. So a
    /// namespaced plugin binds nothing implicitly: it may name any
    /// implRef it likes and gets nowhere without the operator.
    ///
    /// Name-derived ownership is sound only because identity is
    /// authenticated by the embedder at registration, not declared by
    /// the manifest. Were it self-declared, a plugin could call itself
    /// `vault` and own `myapp.vault.*` by assertion — the free path
    /// would *be* the vulnerability.
    ///
    /// The rejections say different things on purpose: "did not ask" is
    /// a manifest bug the plugin author fixes, "asked and is not
    /// authorised" is a deployment decision the operator makes, and the
    /// namespaced case is neither — it is about who may assume
    /// ownership at all.
    fn check_native_impl_binding(
        &self,
        plugin_name: &str,
        step_type: &str,
        impl_ref: &str,
        parsed_permissions: &[permissions::Permission],
    ) -> Result<(), KernelError> {
        let namespace = self::identity::namespace_of(plugin_name);
        let local_name = self::identity::local_name_of(plugin_name);
        let owner = self::identity::impl_ref_owner(impl_ref);
        let owns_by_name = owner == Some(local_name);

        if owns_by_name && namespace.is_empty() {
            return Ok(());
        }

        let owner_desc = if owns_by_name {
            // Name matched but the plugin is namespaced. Say so, or the
            // message reads as a contradiction: the plugin *is* called
            // `vault` and is being told the body belongs to `vault`.
            format!(
                "plugin '{local_name}' as shipped by the embedder. This plugin is \
                 also named '{local_name}', but it is registered in namespace \
                 '{namespace}' rather than the root namespace, so it is not the \
                 party that shipped the body and does not inherit ownership of it"
            )
        } else {
            match owner {
                Some(owner) => format!("plugin '{owner}'"),
                None => "another plugin (the implRef is not in \
                         <owner>.<plugin>.<step> form, so no owner can be \
                         derived from it)"
                    .to_string(),
            }
        };

        let declared = parsed_permissions
            .iter()
            .any(|p| matches!(p, permissions::Permission::BindNativeImpl(r) if r == impl_ref));
        if !declared {
            return Err(KernelError::Validation(format!(
                "Plugin '{plugin_name}': step_type_impls entry for '{step_type}' \
                 binds native implRef '{impl_ref}', which belongs to {owner_desc}, \
                 but the manifest does not declare the matching permission. Add \
                 \"bind:native_impl:{impl_ref}\" to `permissions`. Binding another \
                 plugin's native body means running privileged code you did not \
                 ship, so the claim has to be stated in the manifest an operator \
                 reviews"
            )));
        }

        if !self
            .native_impl_bindings
            .iter()
            .any(|b| b.binder == plugin_name && b.impl_ref == impl_ref)
        {
            return Err(KernelError::Validation(format!(
                "Plugin '{plugin_name}': step_type_impls entry for '{step_type}' \
                 declares \"bind:native_impl:{impl_ref}\" but the embedder has not \
                 authorised that binding. The body belongs to {owner_desc}; add \
                 the pair via \
                 KernelConfig::allowing_native_impl_binding(\"{plugin_name}\", \
                 \"{impl_ref}\") to permit it"
            )));
        }

        Ok(())
    }

    /// May `plugin` supply the implementation behind this step type
    /// slot?
    ///
    /// Claiming a `(step_type, matches)` slot is not like using a step
    /// type — it is *becoming* the code every other plugin's steps of
    /// that type run inside. Supplying `(script, "lua")` means
    /// supplying the interpreter that executes every plugin's Lua
    /// script step, which receives that plugin's resolution context
    /// and a parent context naming it. Without this check the slot
    /// would be first-come, first-served: a manifest declaring no
    /// permissions and no actions could take it, and a legitimate
    /// runtime loading afterwards would fail with an error blaming
    /// *itself*.
    ///
    /// The rule, in order:
    ///
    /// 1. A plugin may always implement a step type **it defines in
    ///    the same manifest**. Your own extension point is yours; this
    ///    is also what lets the kernel's own `intrinsics.json` claim
    ///    its slots without special-casing.
    /// 2. Otherwise the manifest must declare
    ///    `provide:step_type:<type>[:<selector>]`. Manifests are
    ///    self-describing, so this proves only that the plugin asked —
    ///    but it puts the claim in the document an operator reviews,
    ///    and makes every such claim greppable.
    /// 3. And the plugin must be listed in
    ///    [`KernelConfig::trusted_step_type_providers`]. This is the
    ///    half that actually authorises, and it defaults to empty.
    ///
    /// Steps 2 and 3 produce distinct errors on purpose: "did not ask"
    /// is a manifest bug, "asked and is not trusted" is a deployment
    /// decision, and an operator debugging a plugin that won't load
    /// needs to know which.
    fn check_step_type_impl_claim(
        &self,
        plugin_name: &str,
        step_type: &str,
        matches: Option<&str>,
        defines_locally: bool,
        parsed_permissions: &[permissions::Permission],
    ) -> Result<(), KernelError> {
        if defines_locally {
            return Ok(());
        }

        let slot = match matches {
            Some(m) => format!("{step_type}:{m}"),
            None => step_type.to_string(),
        };
        let owner = self
            .registry
            .get_step_type_def(&self::registry::PluginRegistry::step_type_key(
                plugin_name,
                step_type,
            ))
            .map(|(p, _)| p.to_string())
            .unwrap_or_else(|| "another plugin".to_string());

        let declared = parsed_permissions.iter().any(|p| {
            matches!(
                p,
                permissions::Permission::ProvideStepType { step_type: t, selector }
                    if t == step_type && selector.as_deref() == matches
            )
        });
        if !declared {
            return Err(KernelError::Validation(format!(
                "Plugin '{plugin_name}': step_type_impls entry for '{slot}' claims a \
                 step type defined by '{owner}', but the manifest does not declare \
                 the matching permission. Add \"provide:step_type:{slot}\" to \
                 `permissions`. Supplying an implementation means every plugin's \
                 steps of this type execute inside your code, so the claim has to \
                 be stated in the manifest an operator reviews"
            )));
        }

        // `plugin_name` is the qualified identity, so this compares the
        // embedder's allowlist against a name the manifest could not
        // choose for itself: the namespace half came from the
        // registration call site. In the root namespace both sides are
        // bare manifest names.
        if !self
            .trusted_step_type_providers
            .iter()
            .any(|p| p.identity == plugin_name)
        {
            return Err(KernelError::Validation(format!(
                "Plugin '{plugin_name}': step_type_impls entry for '{slot}' declares \
                 \"provide:step_type:{slot}\" but '{plugin_name}' is not in the \
                 embedder's `trusted_step_type_providers`. Supplying the \
                 implementation behind a step type defined by '{owner}' means \
                 every plugin's steps of this type run inside this plugin's code; \
                 add it to KernelConfig::trusted_step_type_providers to authorise \
                 that"
            )));
        }

        Ok(())
    }

    /// Decision tree for the wallclock cap applied at every
    /// `execute_action*` entry point. Returns `Some(d)` to
    /// wrap the action future in `tokio::time::timeout`, or `None`
    /// to let it run uncapped (cooperative cancellation only).
    ///
    /// Precedence:
    ///
    /// 0. [`RuntimeLimits::max_wallclock_timeout`], when the operator
    ///    set one, clamps whatever the rest of this list produces —
    ///    including the dataflow uncap. Everything below is the
    ///    *manifest's* choice, and a manifest cannot raise itself past
    ///    the operator's ceiling. Default is `None`, no ceiling.
    /// 1. The action declares its own `wallclock_timeout_ms` →
    ///    use it. Wins over both defaults below; even a dataflow action
    ///    that sets "max 2 hours" gets a hard kill at 2 hours.
    /// 2. The action is `dataflow: true` and declared nothing →
    ///    `None`. Streaming pipelines (transcoding, speech-to-text,
    ///    long-poll listeners, queue consumers) can legitimately
    ///    run minutes-to-days; cooperative cancel via the action's
    ///    `CancellationToken` is the only tear-down primitive.
    /// 3. Else → deployment default (`self.limits.default_wallclock_timeout`,
    ///    populated at `boot` from the `defaultWallclockTimeoutMs`
    ///    settings key with a 60 s hardcoded fallback).
    ///
    /// **The deployment default is a default, not a bound.** Cases 1 and 2
    /// are the manifest overriding it, in either direction. That is
    /// deliberate — an author knows their action better than a global
    /// number does — but it means an operator who needs a real limit
    /// wants case 0, not case 3.
    ///
    /// **Why `continuous: true` actions are NOT auto-uncapped:** the
    /// re-execute loop runs the action's DAG once per
    /// iteration with a per-iteration tear-down. Each iteration is
    /// expected to complete in a bounded time (long-poll +
    /// response, MQ-message + dispatch, etc.); the loop driver in
    /// `execute_action_continuous` handles the open-ended part. So
    /// a per-iteration wallclock cap is still appropriate, and
    /// `continuous` falls into case (3). Authors who need a
    /// per-iteration cap longer than the deployment default declare
    /// `wallclock_timeout_ms` explicitly. Dataflow is the form
    /// where one DAG run holds open many seconds-to-days of
    /// streaming work, which is why it gets the auto-uncap.
    fn effective_wallclock_timeout(&self, action: &Action) -> Option<std::time::Duration> {
        let requested = if let Some(ms) = action.wallclock_timeout_ms {
            Some(std::time::Duration::from_millis(ms))
        } else if action.dataflow {
            None
        } else {
            Some(self.limits.default_wallclock_timeout)
        };

        // Steps 1 and 2 are both the *manifest* choosing its own
        // deadline, and without a ceiling nothing bounds that choice
        // upward: `wallclockTimeoutMs: 86400000` beats a 60-second
        // operator default, and `dataflow: true` beats everything.
        // Asking for *less* time is never an escalation, so the ceiling
        // only ever clamps down — and `None` (the default) clamps
        // nothing.
        match (requested, self.limits.max_wallclock_timeout) {
            (_, None) => requested,
            (None, Some(ceiling)) => Some(ceiling),
            (Some(asked), Some(ceiling)) => Some(asked.min(ceiling)),
        }
    }

    /// Build a single plugin-action invocation.
    ///
    /// Returns an [`ExecuteActionRequest`](execute_request::ExecuteActionRequest) fluent builder. Set the
    /// optional knobs (`config`, `cancel`, `exec_ctx`, `streams`)
    /// with the `with_*` methods, then call one of the
    /// terminal verbs to choose the execution shape:
    ///
    /// - [`ExecuteActionRequest::run`](execute_request::ExecuteActionRequest::run) — single-shot, returns the
    ///   resolved [`ActionResult`].
    /// - [`ExecuteActionRequest::into_dataflow_handle`](execute_request::ExecuteActionRequest::into_dataflow_handle) — spawn a
    ///   streaming-dataflow pipeline (action must declare
    ///   `dataflow: true`).
    /// - [`ExecuteActionRequest::into_dataflow_streaming_handle`](execute_request::ExecuteActionRequest::into_dataflow_streaming_handle) —
    ///   same shape plus a live byte-stream from the action's single
    ///   long-running step.
    /// - [`ExecuteActionRequest::into_continuous_handle`](execute_request::ExecuteActionRequest::into_continuous_handle) — drive a
    ///   `continuous: true` action on a loop.
    ///
    /// ```ignore
    /// kernel.execute(plugin, action, input)
    ///     .with_config(&config)
    ///     .with_cancel(cancel)
    ///     .run()
    ///     .await?;
    /// ```
    pub fn execute<'a>(
        &'a self,
        plugin_name: &'a str,
        action_name: &'a str,
        input: Value,
    ) -> self::execute_request::ExecuteActionRequest<'a> {
        self::execute_request::ExecuteActionRequest::new(self, plugin_name, action_name, input)
    }

    /// Streaming variant of [`Self::execute_action_invoked`]: spawn the
    /// callee on a background tokio task and return a stream handle the
    /// caller can read from while the callee runs. This is the live
    /// cross-action streaming path — what makes `io.invoke_streaming`
    /// useful inside a plugin that relays a callee's stream to its own
    /// caller.
    ///
    /// The callee MUST be `dataflow: true` and have exactly one
    /// `long_running` step, which itself MUST have zero in-action
    /// consumers (its output flows out to the parent, not to a sibling
    /// step). Both constraints are enforced here before the spawn so a
    /// misconfigured manifest errors loudly rather than silently
    /// behaving like the synchronous variant.
    ///
    /// The returned `StreamId` is registered in the parent's stream
    /// registry (passed as `parent_streams`). The caller reads from it
    /// like any other readable; when the callee finishes, the writable
    /// side drops and the stream surfaces EOF. Callee-side errors are
    /// logged at `warn` and end the stream early with EOF.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn execute_action_invoked_streaming(
        self: &Arc<Self>,
        plugin_name: &str,
        action_name: &str,
        input: Value,
        config: &Value,
        secret_resolver: Option<Arc<dyn SecretResolver>>,
        exec_ctx: &ExecutionContext,
        parent_streams: std::sync::Arc<std::sync::Mutex<self::streams::StreamRegistry>>,
        parent_depth: u32,
        parent_cancel: Option<tokio_util::sync::CancellationToken>,
    ) -> Result<self::streams::StreamId, KernelError> {
        let registration = self
            .registry
            .get_action(plugin_name, action_name)
            .ok_or_else(|| {
                KernelError::NotFound(format!(
                    "No action '{action_name}' on plugin '{plugin_name}'"
                ))
            })?;

        if !registration.action.dataflow {
            return Err(KernelError::Validation(format!(
                "io.invoke_streaming: action {plugin_name}.{action_name} is not \
                 declared `dataflow: true`; use io.invoke for non-streaming calls"
            )));
        }

        // Identify the single long-running step. Multi-producer
        // dataflow actions are valid in general but ambiguous here —
        // which step's output flows to the parent? Reject and let the
        // plugin author split or rethink.
        let mut long_running_steps: Vec<&str> = Vec::new();
        for (idx, step) in registration.action.steps.iter().enumerate() {
            if step.long_running {
                if !registration.plan.consumers[idx].is_empty() {
                    return Err(KernelError::Validation(format!(
                        "io.invoke_streaming: action {plugin_name}.{action_name} \
                         long-running step '{}' has in-action consumer(s); the \
                         output must flow to the parent, not a sibling step",
                        step.id
                    )));
                }
                long_running_steps.push(step.id.as_str());
            }
        }
        let producer_step_id = match long_running_steps.as_slice() {
            [one] => (*one).to_string(),
            [] => {
                return Err(KernelError::Validation(format!(
                    "io.invoke_streaming: action {plugin_name}.{action_name} declares \
                 `dataflow: true` but has no `long_running` step — nothing to \
                 stream from"
                )));
            }
            many => {
                return Err(KernelError::Validation(format!(
                    "io.invoke_streaming: action {plugin_name}.{action_name} has {} \
                 long-running steps ({}); exactly one is required so the \
                 parent stream destination is unambiguous",
                    many.len(),
                    many.join(", ")
                )));
            }
        };

        // Allocate the pipe with an end in each execution's own table.
        //
        // The two ends are separate streams over one mpsc channel, not
        // one stream seen twice, so this is a clean split rather than a
        // shared handle: the callee's table holds only the writable it
        // is meant to produce into, and the parent's holds only the
        // readable it consumes. Neither can name anything else of the
        // other's — which is the whole point of per-execution tables,
        // and this is the one path that legitimately crosses them.
        let callee_streams: self::streams::SharedStreamRegistry = Default::default();
        let (writable_id, receiver) = {
            let mut reg = self::streams::lock_shared(&callee_streams);
            reg.register_writable(
                "application/octet-stream",
                self::streams::STREAM_FANOUT_CAPACITY,
            )
        };
        let recv_source: self::streams::ReadableSource =
            Box::pin(futures::stream::unfold(receiver, |mut rx| async move {
                rx.recv().await.map(|item| (item, rx))
            }));
        let readable_id = {
            let mut reg = self::streams::lock_shared(&parent_streams);
            reg.register_readable("application/octet-stream", recv_source)
        };

        // Spawn the callee on a background task. Errors in the spawned
        // callee surface as a `warn` and an early EOF on the stream; no
        // JoinHandle is exposed.
        let mut pre_allocated = std::collections::HashMap::new();
        pre_allocated.insert(producer_step_id.clone(), writable_id);

        let kernel = Arc::clone(self);
        let plugin_owned = plugin_name.to_string();
        let action_owned = action_name.to_string();
        let input_owned = input;
        let config_owned = config.clone();
        let exec_ctx_owned = exec_ctx.clone();
        // Pull the callee's secrets before the spawn, so a resolver
        // failure surfaces to the caller as an error rather than as a
        // stream that silently hits EOF.
        let secrets_owned = self
            .pull_secrets(plugin_name, secret_resolver.as_ref(), exec_ctx)
            .await?;

        tokio::spawn(async move {
            let Some(registration) = kernel.registry.get_action(&plugin_owned, &action_owned)
            else {
                tracing::warn!(
                    plugin = %plugin_owned,
                    action = %action_owned,
                    "io.invoke_streaming: action unregistered between spawn and run"
                );
                return;
            };
            let ctx = self::runtime::InvocationContext {
                // Resolved for the CALLEE, not the caller: step types
                // resolve by the executing plugin's identity.
                step_type_access: kernel.step_type_access_for(&plugin_owned),
                // The callee's own table, holding the writable end and
                // nothing else. `pre_allocated_outputs` names a handle
                // in *this* table, not in the parent's.
                streams: Some(callee_streams),
                invoke_depth: parent_depth + 1,
                dispatch_depth: 0,
                kernel: kernel.self_weak.get().cloned(),
                trigger: None,
                drain_streams: false,
                cancel: parent_cancel,
                dataflow_events: None,
                pre_allocated_outputs: Some(pre_allocated),
                secret_resolver,
            };
            let result = kernel
                .runtime
                .execute_dag(
                    &plugin_owned,
                    &registration.action,
                    &registration.plan,
                    input_owned,
                    &config_owned,
                    &secrets_owned,
                    kernel.script_runtimes(),
                    exec_ctx_owned,
                    ctx,
                    kernel.limits.clone(),
                )
                .await;
            if let Err(e) = result {
                tracing::warn!(
                    plugin = %plugin_owned,
                    action = %action_owned,
                    error = %e,
                    "io.invoke_streaming: background action failed; \
                     stream EOF reached early"
                );
            }
        });

        Ok(readable_id)
    }

    /// Execute a child action initiated by an `invoke` step in a parent
    /// invocation, incrementing the recursion depth so the runtime can
    /// enforce the cap.
    ///
    /// # The callee gets its own stream handle table
    ///
    /// It does not inherit the caller's registry, tempting as that is
    /// for letting handles "pass through without buffering". What would
    /// actually pass through is the caller's whole handle space:
    /// handles are small integers from a counter starting at 1, so a
    /// callee could read handle `1` and receive bytes from a stream
    /// nobody had granted it. Sharing a namespace is not the same as
    /// sharing a stream.
    ///
    /// Nothing is buffered by the separation — a stream is an `Arc`
    /// behind its handle, so moving one across the boundary is still a
    /// pointer hand-off. It simply has to be done on purpose, via
    /// [`StreamRegistry::take`](self::streams::StreamRegistry::take) and
    /// [`adopt`](self::streams::StreamRegistry::adopt).
    ///
    /// `parent_cancel` propagates the parent action's cancellation
    /// signal into the child's `InvocationContext`, so a parent-side
    /// cancel fired mid-invoke tears the child down too. `None` means
    /// "parent has no cancel surface" — the runtime allocates a
    /// fresh never-cancelled token internally.
    ///
    /// Kernel-internal: external plugin crates dispatch through
    /// [`Self::dispatch_role`] instead, which derives `parent_depth`
    /// and `parent_cancel` from the calling step's
    /// [`PluginExecution`] handle rather than asking the caller to snapshot
    /// them. The `invoke` step type and the script-runtime host call
    /// in directly because they already own the kernel-internal
    /// plumbing.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn execute_action_invoked(
        &self,
        plugin_name: &str,
        action_name: &str,
        input: Value,
        config: &Value,
        secret_resolver: Option<Arc<dyn SecretResolver>>,
        exec_ctx: &ExecutionContext,
        parent_depth: u32,
        parent_cancel: Option<tokio_util::sync::CancellationToken>,
    ) -> Result<ActionResult, KernelError> {
        let registration = self
            .registry
            .get_action(plugin_name, action_name)
            .ok_or_else(|| {
                KernelError::NotFound(format!(
                    "No action '{action_name}' on plugin '{plugin_name}'"
                ))
            })?;

        // The callee's own handle table. `None` makes the runtime
        // allocate a fresh one; see this method's docs for why it is not
        // the parent's.
        let ctx = self::runtime::InvocationContext {
            // The callee's set, not the caller's.
            step_type_access: self.step_type_access_for(plugin_name),
            streams: None,
            invoke_depth: parent_depth + 1,
            dispatch_depth: 0,
            kernel: self.self_weak.get().cloned(),
            trigger: None,
            // The callee's table is dropped with its execution, and
            // the runtime's `invoke_depth == 0` guard would suppress a
            // drain here anyway; `false` states the intent explicitly.
            drain_streams: false,
            cancel: parent_cancel,
            dataflow_events: None,
            pre_allocated_outputs: None,
            secret_resolver: secret_resolver.clone(),
        };
        // The callee's OWN secrets, pulled for the callee's identity —
        // never the caller's bag. This is the line that makes an
        // `invoke:` grant a grant to call, not a grant to the caller's
        // credentials.
        let secrets = self
            .pull_secrets(plugin_name, secret_resolver.as_ref(), exec_ctx)
            .await?;

        self.runtime
            .execute_dag(
                plugin_name,
                &registration.action,
                &registration.plan,
                input,
                config,
                &secrets,
                self.script_runtimes(),
                exec_ctx.clone(),
                ctx,
                self.limits.clone(),
            )
            .await
    }

    /// Dispatch to whichever plugin is bound to `role`, calling `action`
    /// with `input`, from inside a step body. The child gets its own
    /// stream registry (a callee cannot reach its caller's handles),
    /// inherits the caller's `invoke_depth` (so the
    /// recursion cap applies), and its cancellation token (so a parent-side cancel
    /// tears the child down).
    ///
    /// This is the constrained seam external plugin crates use when a
    /// step body needs to call another plugin through the SPI surface:
    /// a storage plugin that needs a signature reaches a signing role
    /// this way. Callers say
    /// "dispatch to this role" and the kernel handles the inherited
    /// plumbing — `parent_depth` and `parent_cancel` stay
    /// kernel-internal concepts rather than appearing in every
    /// plugin's vocabulary.
    ///
    /// Callee config is resolved through the dispatch orchestrator
    /// with the caller's namespace as the default, and callee secrets
    /// are pulled for the callee's own identity through the
    /// invocation's resolver. Mirrors the manifest-level `invoke` step
    /// type so a plugin sees the same namespaces regardless of who
    /// dispatched to it — closes the failure mode where a role impl with
    /// its own credentials (HSM signer, etc.) would silently inherit
    /// the *caller's* under role dispatch but its own under `invoke`.
    pub fn dispatch_role<'a>(
        &'a self,
        ex: &dyn PluginExecution,
        role: &str,
        action: &str,
        input: Value,
        hints: Value,
    ) -> impl std::future::Future<Output = Result<ActionResult, KernelError>> + Send + 'a {
        // Snapshot the parent's invocation context up-front so the
        // returned future doesn't borrow `&dyn PluginExecution` across its
        // await — the trait object is `!Sync` (single-threaded step
        // body), so a future that captures `ex` past the await wouldn't
        // be `Send`.
        let snapshot = host_api::DispatchSnapshot::capture(ex);
        self.dispatch_role_inner(role.to_string(), action.to_string(), input, hints, snapshot)
    }

    /// Shared inner body of [`Self::dispatch_role`] and the trait-level
    /// [`PluginExecution::dispatch_role`] default impl. Takes pre-snapshotted
    /// invocation context so both entry points funnel through one
    /// implementation — the role-resolve / callee-config-resolve /
    /// `execute_action_invoked` sequence lives in exactly one place.
    pub(crate) async fn dispatch_role_inner(
        &self,
        role: String,
        action: String,
        input: Value,
        hints: Value,
        snapshot: host_api::DispatchSnapshot,
    ) -> Result<ActionResult, KernelError> {
        let request = DispatchRequest::ByRole {
            role: &role,
            action: &action,
            input: &input,
            hints: &hints,
        };
        // This surface is gated like every other plugin-initiated one:
        // without this check, a native step body would be a laundering
        // path around every `invoke:` grant in the system.
        self.check_invoke_grant(&snapshot.caller_plugin, &request)
            .map_err(KernelError::Validation)?;
        // Recursion cap, same as the `invoke` step's. Without it a
        // native body dispatching by role in a cycle would run until
        // the wallclock watchdog caught it.
        if snapshot.invoke_depth >= host_api::INVOKE_MAX_DEPTH {
            return Err(KernelError::Validation(format!(
                "invoke recursion cap ({}) exceeded: '{}' dispatching role '{role}'",
                host_api::INVOKE_MAX_DEPTH,
                snapshot.caller_plugin
            )));
        }
        let plan = self
            .prepare_dispatch_via_orchestrator(
                DispatchRequest::ByRole {
                    role: &role,
                    action: &action,
                    input: &input,
                    hints: &hints,
                },
                &snapshot.exec_ctx,
                Some(&snapshot.caller_plugin),
                &snapshot.caller_config,
            )
            .await?;
        self.authorize_resolved_dispatch(&snapshot.caller_plugin, &request, &plan, None)
            .map_err(KernelError::Validation)?;
        self.execute_action_invoked(
            &plan.plugin,
            &plan.action,
            input,
            &plan.config,
            snapshot.secret_resolver,
            &snapshot.exec_ctx,
            snapshot.invoke_depth,
            Some(snapshot.cancel),
        )
        .await
    }

    /// Fire `event_type` with `payload` to every subscribed action.
    ///
    /// Subscribers are looked up in the registry's subscription index
    /// (populated at registration time from each action's
    /// `subscribes_to`). Each subscribed action runs with `payload`
    /// bound to the `$trigger` / `{{$trigger.*}}` reference and shares
    /// no state with sibling subscribers — failures are isolated.
    ///
    /// `payload` is wrapped in `Arc<Value>` so fan-out to N subscribers
    /// is N refcount bumps rather than N deep clones of an immutable
    /// payload. The eventual `Value::clone` when building a subscriber's
    /// `resolution_context` is unavoidable but only happens once per
    /// subscriber.
    ///
    /// `parent_dispatch_depth` is the dispatch depth of the caller
    /// publishing this event (0 for externally-originating events).
    /// If `parent_dispatch_depth >= DISPATCH_MAX_DEPTH` the call logs
    /// a warning and returns an empty Vec — invocations exceeding the
    /// cap complete their current action but their downstream events
    /// don't propagate, breaking event-driven cycles.
    ///
    /// `exec_ctx` is handed to every subscriber unchanged; the
    /// subscriber list itself is global — every plugin subscribed to
    /// `event_type` fires.
    ///
    /// # Events cross namespaces
    ///
    /// The subscriber list is global **across namespaces too**, and
    /// this is the one dispatch path the namespace containment rule
    /// does not cover. Every other cross-plugin path has a calling
    /// plugin whose namespace bounds the callee; an event has no caller
    /// plugin at all, so there is no namespace to bound it by.
    ///
    /// The consequence is the embedder's to manage: firing an event
    /// carrying one tenant's data delivers that payload to **every**
    /// namespace's subscribers. Events are for embedder-originated,
    /// namespace-agnostic signals. Anything tenant-shaped should be
    /// dispatched explicitly to a known plugin instead.
    ///
    /// The orchestrator sees
    /// [`DispatchContext::caller_plugin`](dispatch::DispatchContext)
    /// `== None` on this path — the one place it is `None` — so
    /// it can tell an event from a root-namespace caller without
    /// guessing from which path it is on.
    ///
    /// Returns one [`DispatchedActionResult`] per subscriber in
    /// registration order, each carrying the `(plugin, action)`
    /// identity alongside the result so callers can log per-subscriber
    /// failures with names rather than indices.
    pub async fn dispatch_event(
        &self,
        event_type: &str,
        payload: Arc<Value>,
        config: &Value,
        exec_ctx: &ExecutionContext,
        parent_dispatch_depth: u32,
    ) -> Vec<DispatchedActionResult> {
        if parent_dispatch_depth >= DISPATCH_MAX_DEPTH {
            tracing::warn!(
                event_type = %event_type,
                depth = parent_dispatch_depth,
                cap = DISPATCH_MAX_DEPTH,
                "dispatch_event cascade cap reached; refusing to fan out further"
            );
            return Vec::new();
        }

        // The subscriber list is global; see the method docs.
        let subscribers = self.registry.subscribers_for(event_type).to_vec();
        if subscribers.is_empty() {
            return Vec::new();
        }

        let mut results = Vec::with_capacity(subscribers.len());
        for (plugin_name, action_name) in subscribers {
            // Run the subscriber through the orchestrator as a ByPlugin
            // dispatch — selection is fixed (event handlers are
            // pre-registered subscribers), but the orchestrator still
            // owns the per-callee config decision.
            let plan = match self
                .prepare_dispatch_via_orchestrator(
                    DispatchRequest::ByPlugin {
                        plugin: &plugin_name,
                        action: &action_name,
                        input: payload.as_ref(),
                        // Event dispatch has no per-callee hint
                        // surface; subscribers are already
                        // pre-selected (`subscribes_to` index).
                        hints: &Value::Null,
                    },
                    exec_ctx,
                    // Event dispatch has no calling plugin (events are
                    // global), and the contract says so explicitly.
                    None,
                    config,
                )
                .await
            {
                Ok(p) => p,
                Err(e) => {
                    results.push(DispatchedActionResult {
                        plugin: plugin_name.clone(),
                        action: action_name.clone(),
                        result: Err(e),
                    });
                    continue;
                }
            };
            let result = self
                .execute_action_event_dispatched(
                    &plan.plugin,
                    &plan.action,
                    Arc::clone(&payload),
                    &plan.config,
                    exec_ctx,
                    parent_dispatch_depth,
                )
                .await;
            results.push(DispatchedActionResult {
                plugin: plugin_name,
                action: action_name,
                result,
            });
        }
        results
    }

    /// Release every step-type linker import `manifest` registered —
    /// native impls, intrinsic impls, and alias dispatchers — so the
    /// names become claimable again after unload/reload. Only entries
    /// this plugin actually owns are touched.
    fn release_step_imports(&mut self, plugin_name: &str, manifest: &PluginManifest) {
        let impl_names = manifest
            .step_type_impls
            .iter()
            .filter(|decl| !matches!(decl.kind, types::StepTypeImplKind::Wasm))
            .map(|decl| decl.step_type.as_str());
        for name in impl_names.chain(manifest.step_types.keys().map(String::as_str)) {
            let key = self::registry::PluginRegistry::step_type_key(plugin_name, name);
            if self
                .step_import_owners
                .get(&key)
                .is_some_and(|owner| owner == plugin_name)
            {
                self.step_import_owners.remove(&key);
                self.runtime.remove_step_type(&key);
            }
        }
    }

    /// Resolve a bare plugin reference made *by* `caller_plugin` into
    /// the qualified identity it denotes.
    ///
    /// Walks the caller's ancestor chain — its own namespace, then each
    /// enclosing one, then root — and returns the first candidate that
    /// is registered. A tenant writing `pdf_service` reaches its own
    /// `tenant/pdf_service` if it has one, else the global
    /// `pdf_service`. When nothing on the chain is registered the
    /// nearest candidate is returned, so a not-found error names the
    /// plugin the author most plausibly meant.
    ///
    /// Shadowing follows: a tenant that later registers its own
    /// `pdf_service` silently redirects its existing references (and
    /// grants, which resolve through this same walk) from the global
    /// one to the local one. That only ever affects that tenant, and
    /// it is the same rule step types already follow — but "adding a
    /// plugin changed what my old grants point at" surprises people
    /// the first time.
    ///
    /// A qualified reference (one carrying the separator) is rejected:
    /// a plugin cannot name a namespace, only walk its own chain.
    pub fn resolve_plugin_reference(
        &self,
        caller_plugin: &str,
        reference: &str,
    ) -> Result<String, self::identity::NameError> {
        let mut candidates =
            self::identity::plugin_reference_candidates(caller_plugin, reference)?.peekable();
        let nearest = candidates
            .peek()
            .cloned()
            .expect("the chain always has at least the caller's own namespace");
        Ok(candidates
            .find(|candidate| self.registry.has_plugin(candidate))
            .unwrap_or(nearest))
    }

    /// Does `caller_plugin`'s grant set authorise dispatch to the
    /// qualified identity `target`?
    ///
    /// `invoke:plugin:<name>` grants are stored as written and resolved
    /// here through [`Self::resolve_plugin_reference`], so a grant and
    /// the reference it authorises always denote the same plugin.
    /// `invoke:plugin:*` means "any plugin in my own namespace" and
    /// never crosses a level — reaching a plugin above you is always by
    /// name, so the capabilities a tenant reaches are the ones its
    /// manifest lists.
    fn check_invoke_plugin(
        &self,
        caller_plugin: &str,
        target: &str,
    ) -> permissions::PermissionCheck {
        for grant in self.registry.permissions_for(caller_plugin) {
            let granted = match grant {
                permissions::Permission::InvokePlugin(permissions::NamePattern::Any) => {
                    self::identity::same_namespace(caller_plugin, target)
                }
                permissions::Permission::InvokePlugin(permissions::NamePattern::Exact(name)) => {
                    self.resolve_plugin_reference(caller_plugin, name)
                        .is_ok_and(|resolved| resolved == target)
                }
                _ => false,
            };
            if granted {
                return permissions::PermissionCheck::Granted;
            }
        }
        permissions::PermissionCheck::Denied {
            requested: format!("invoke:plugin:{}", self::identity::local_name_of(target)),
        }
    }

    /// Enforce the caller's `invoke:*` grants against the dispatch a
    /// plugin **requested**, before the orchestrator runs.
    ///
    /// This is the cheap early-out, not the authority. It denies an
    /// obviously-unauthorised call before the orchestrator does any
    /// work (which may include fetching the callee's secrets), but it
    /// judges intent rather than outcome: a plugin may always request
    /// its own actions, and a custom orchestrator can rewrite the
    /// target afterwards. `Self::authorize_resolved_dispatch` is what
    /// actually authorises, and it runs on the plan the orchestrator
    /// returned. Both must pass.
    ///
    /// Gated surfaces — all six that reach the orchestrator:
    ///
    /// | Surface | Gate |
    /// |---|---|
    /// | `invoke` step | `invoke:` both sides |
    /// | `io.invoke` | `invoke:` both sides |
    /// | `io.invoke_streaming` | `invoke:` both sides |
    /// | [`Kernel::dispatch_role`] / [`PluginExecution::dispatch_role`] | `invoke:` both sides |
    /// | alias step | `step_type:<alias>`, plus `invoke:` on any redirect |
    /// | event dispatch | **ungated, by design** — see below |
    ///
    /// Event dispatch is the one exception, and it is not a hole: it
    /// has no caller plugin (`caller_plugin` is `None`), and its
    /// subscriber list comes from `subscribes_to` declarations made by
    /// the subscribers themselves, not from any target a caller
    /// chooses. There is nothing for a `invoke:` grant to constrain.
    pub(crate) fn check_invoke_grant(
        &self,
        caller_plugin: &str,
        request: &DispatchRequest<'_>,
    ) -> Result<(), String> {
        use permissions::PermissionCheck;
        let denied = match request {
            DispatchRequest::ByPlugin { plugin, .. } => {
                if *plugin == caller_plugin {
                    return Ok(());
                }
                self.check_invoke_plugin(caller_plugin, plugin)
            }
            DispatchRequest::ByRole { role, .. } => {
                permissions::check_invoke_role(self.registry.permissions_for(caller_plugin), role)
            }
        };
        match denied {
            PermissionCheck::Granted => Ok(()),
            PermissionCheck::Denied { requested } => Err(format!(
                "plugin '{caller_plugin}' lacks {requested} permission \
                 (add it to the manifest's `permissions` list)"
            )),
        }
    }

    /// Authorise the dispatch the orchestrator actually **resolved**.
    ///
    /// Runs after [`Self::prepare_dispatch_via_orchestrator`] on every
    /// plugin-initiated surface. It is needed because
    /// [`Self::check_invoke_grant`] judges the request and the
    /// orchestrator can return a different answer:
    ///
    /// - A plugin may always *request* its own actions, so
    ///   `ByPlugin { plugin: self }` passed the pre-check with no
    ///   permission lookup at all. A custom orchestrator — the kernel's
    ///   documented extension seam — could then resolve that
    ///   self-invoke to a different plugin and run the victim's action
    ///   under the attacker's zero-permission manifest.
    /// - A `ByPlugin` request for a plugin the caller *is* granted can
    ///   likewise be redirected to one it is not.
    ///
    /// The rule on the resolved plan:
    ///
    /// 1. Resolving to the caller itself is always allowed — that is a
    ///    genuine self-invoke, not a laundered one.
    /// 2. `invoke:plugin:<resolved plugin>` authorises it.
    /// 3. For a `ByRole` request, `invoke:role:<role>` authorises it
    ///    whichever plugin the orchestrator picks. That is the point of
    ///    a role grant: the caller is delegating selection, and the
    ///    orchestrator is embedder-supplied.
    /// 4. `also_allowed` names one extra target the caller was
    ///    authorised for by a different grant — the alias step passes
    ///    the alias owner here, since `step_type:<alias>` already
    ///    authorised dispatch to it.
    pub(crate) fn authorize_resolved_dispatch(
        &self,
        caller_plugin: &str,
        request: &DispatchRequest<'_>,
        plan: &DispatchPlan,
        also_allowed: Option<&str>,
    ) -> Result<(), String> {
        // Containment, checked before every other rule including the
        // self-dispatch and alias-owner shortcuts: the target must be on
        // the caller's ancestor chain — its own namespace or one
        // enclosing it. Upward only; never down, never sideways. See
        // `identity::is_on_chain` for why each leg is what it is.
        //
        // This is structural, not a grant: no permission string can
        // authorise it, because none can express it. A reference
        // resolves along the caller's own chain and the qualified
        // syntax that would name anything else is reserved and rejected
        // at parse time — so a caller cannot *ask* to go down or
        // sideways. A resolved target off the chain therefore came from
        // an orchestrator redirect, which is embedder code choosing a
        // callee the caller could not have named.
        //
        // Position matters. Placed after the shortcuts, an alias owned
        // by another namespace (`also_allowed`) would wave an off-chain
        // target through.
        if !self::identity::is_on_chain(&plan.plugin, caller_plugin) {
            return Err(format!(
                "plugin '{caller_plugin}' may not dispatch to '{}': a plugin may only \
                 dispatch within its own namespace or into one enclosing it, never \
                 into a sibling or a descendant, and no permission grants passage \
                 otherwise",
                plan.plugin
            ));
        }
        if plan.plugin == caller_plugin || also_allowed == Some(plan.plugin.as_str()) {
            return Ok(());
        }
        if self
            .check_invoke_plugin(caller_plugin, &plan.plugin)
            .is_granted()
        {
            return Ok(());
        }
        if let DispatchRequest::ByRole { role, .. } = request
            && permissions::check_invoke_role(self.registry.permissions_for(caller_plugin), role)
                .is_granted()
        {
            return Ok(());
        }

        // Name the redirect explicitly when there was one. "You lack
        // invoke:plugin:X" is baffling if the manifest never mentions
        // X — the orchestrator chose it.
        let requested = match request {
            DispatchRequest::ByPlugin { plugin, .. } if *plugin != plan.plugin => {
                format!(
                    " (the dispatch orchestrator resolved the request for \
                     '{plugin}' to '{}')",
                    plan.plugin
                )
            }
            DispatchRequest::ByRole { role, .. } => {
                format!(" (role '{role}' resolved to '{}')", plan.plugin)
            }
            _ => String::new(),
        };
        Err(format!(
            "plugin '{caller_plugin}' lacks invoke:plugin:{} permission{requested} \
             (add it to the manifest's `permissions` list)",
            plan.plugin
        ))
    }

    /// The plugins `caller_plugin` may be dispatched to for a bare
    /// `role` name, nearest first.
    ///
    /// Role fulfilment resolves by the **calling** plugin's chain, the
    /// same way step types and plugin references do. The walk tries the
    /// caller's own namespace first, then each enclosing one, then
    /// root; at each level it takes the fulfillers bound to that
    /// level's contract, **keeps only those on the caller's chain**,
    /// and orders them own-namespace first. The first level with any
    /// survivors wins.
    ///
    /// The filter is the security property. A global contract may be
    /// fulfilled from inside a tenant (a tenant's own LLM plugin
    /// declaring `roles: ["LLM_CHAT"]`), and that fulfiller must be
    /// visible to that tenant's callers and to nobody else — above all
    /// not to a global plugin dispatching by role, which would otherwise
    /// be capturable by any tenant that registered a fulfiller. Same
    /// confused-deputy shape as step-type resolution, one axis over.
    ///
    /// `None` — an embedder-initiated call with no plugin behind it —
    /// is root-scoped: only root fulfillers.
    pub fn role_candidates(&self, caller_plugin: Option<&str>, role: &str) -> Vec<String> {
        // The embedder has root's view; its "identity" for the chain
        // test below is the root namespace itself.
        let caller_plugin = caller_plugin.unwrap_or("");
        let caller_ns = self::identity::namespace_of(caller_plugin);
        for ns in self::identity::ancestor_namespaces(caller_ns) {
            let key = self::identity::qualify(ns, role);
            let mut candidates: Vec<String> = self
                .registry
                .plugins_for_role(&key)
                .into_iter()
                .filter(|candidate| self::identity::is_on_chain(candidate, caller_plugin))
                .collect();
            if candidates.is_empty() {
                continue;
            }
            // Nearest first: a deeper namespace is closer to the caller.
            // Stable, so registration order breaks ties within a level.
            candidates.sort_by_key(|c| {
                std::cmp::Reverse(
                    self::identity::ancestor_namespaces(self::identity::namespace_of(c)).count(),
                )
            });
            return candidates;
        }
        Vec::new()
    }

    /// Run the configured dispatch orchestrator.
    /// Builds a [`DispatchContext`] from caller-side values and the
    /// kernel's registry, awaits the orchestrator, and maps
    /// [`dispatch::DispatchError`] to the kernel's error type.
    ///
    /// Used by every dispatch site (`dispatch_role_inner`,
    /// `dispatch_event`, the `invoke` step type, alias step types,
    /// the script-runtime `io.invoke` import) so the orchestrator
    /// is consulted in exactly one shape.
    pub(crate) async fn prepare_dispatch_via_orchestrator<'a>(
        &'a self,
        request: DispatchRequest<'a>,
        exec_ctx: &'a ExecutionContext,
        caller_plugin: Option<&'a str>,
        caller_config: &'a Value,
    ) -> Result<DispatchPlan, KernelError> {
        let role_candidates = match &request {
            DispatchRequest::ByRole { role, .. } => self.role_candidates(caller_plugin, role),
            _ => Vec::new(),
        };
        let ctx = DispatchContext {
            registry: &self.registry,
            exec_ctx,
            caller_plugin,
            caller_config,
            role_candidates,
        };
        self.dispatch_orchestrator
            .prepare_dispatch(request, ctx)
            .await
            .map_err(|e| match e {
                dispatch::DispatchError::RoleUnbound(m) => KernelError::NotFound(m),
                dispatch::DispatchError::SelectionFailed(m)
                | dispatch::DispatchError::ConfigResolutionFailed(m) => KernelError::Execution(m),
            })
    }

    /// Internal: dispatch a single event-subscribed action with the
    /// trigger payload bound and `dispatch_depth` incremented. Fresh
    /// stream registry (event-dispatched actions don't inherit a
    /// parent's streams — they're top-level as far as streams are concerned).
    #[allow(clippy::too_many_arguments)]
    async fn execute_action_event_dispatched(
        &self,
        plugin_name: &str,
        action_name: &str,
        trigger: Arc<Value>,
        config: &Value,
        exec_ctx: &ExecutionContext,
        parent_dispatch_depth: u32,
    ) -> Result<ActionResult, KernelError> {
        let registration = self
            .registry
            .get_action(plugin_name, action_name)
            .ok_or_else(|| {
                KernelError::NotFound(format!(
                    "No action '{action_name}' on plugin '{plugin_name}'"
                ))
            })?;

        let event_cancel = tokio_util::sync::CancellationToken::new();
        let ctx = self::runtime::InvocationContext {
            step_type_access: self.step_type_access_for(plugin_name),
            streams: None,
            invoke_depth: 0,
            dispatch_depth: parent_dispatch_depth + 1,
            kernel: self.self_weak.get().cloned(),
            trigger: Some(trigger),
            // Event dispatch is kernel-allocated and top-level — drain
            // on exit to release any leaked streams from the handler
            // action.
            drain_streams: true,
            // Event handlers get their own token so the wallclock
            // watchdog has something to fire. Nothing outside this call
            // holds it — an event dispatch has no caller to cancel it.
            cancel: Some(event_cancel.clone()),
            dataflow_events: None,
            pre_allocated_outputs: None,
            // Same source as every other execution: the kernel's
            // resolver, or nothing.
            secret_resolver: self.secret_resolver.clone(),
        };
        let secrets = self
            .pull_secrets(plugin_name, self.secret_resolver.as_ref(), exec_ctx)
            .await?;

        let fut = self.runtime.execute_dag(
            plugin_name,
            &registration.action,
            &registration.plan,
            Value::Null,
            config,
            &secrets,
            self.script_runtimes(),
            exec_ctx.clone(),
            ctx,
            self.limits.clone(),
        );
        with_wallclock_timeout(
            fut,
            self.effective_wallclock_timeout(&registration.action),
            event_cancel,
        )
        .await
    }

    /// Execute an action by SPI role — picks the first registered plugin
    /// that fulfils the role.
    pub async fn execute_by_role(
        &self,
        role: &str,
        action_name: &str,
        input: Value,
        config: &Value,
    ) -> Result<ActionResult, KernelError> {
        // Embedder-initiated, so root-scoped: the embedder's own
        // fulfillers. Reaching a tenant's plugin from outside the graph
        // is done by naming it — `execute("tenant/plugin", …)`.
        let plugin_name = self
            .role_candidates(None, role)
            .into_iter()
            .next()
            .ok_or_else(|| {
                KernelError::NotFound(format!("No plugin registered for role '{role}'"))
            })?;

        self.execute(&plugin_name, action_name, input)
            .with_config(config)
            .run()
            .await
    }

    /// Parse a plugin manifest JSON string and register it.
    ///
    /// Convenience wrapper over `serde_json::from_str::<PluginManifest>()`
    /// plus `register_plugin()`. Useful for hosts embedding manifest
    /// files via `include_str!` or loading them from disk.
    pub fn register_plugin_from_json(&mut self, json: &str) -> Result<(), KernelError> {
        let value: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| KernelError::Validation(format!("manifest is not valid JSON: {e}")))?;
        manifest_schema::validate_plugin_manifest(&value).map_err(KernelError::Validation)?;
        let manifest: PluginManifest = serde_json::from_value(value).map_err(|e| {
            KernelError::Validation(format!("Plugin manifest JSON parse failed: {e}"))
        })?;
        self.register_plugin(manifest)
    }

    /// Get a reference to the plugin registry.
    pub fn registry(&self) -> &PluginRegistry {
        &self.registry
    }

    /// Get a reference to the dispatch orchestrator.
    /// Always populated — boot promotes a `None` config slot to the
    /// kernel-shipped [`dispatch::DefaultOrchestrator`].
    pub fn dispatch_orchestrator(&self) -> &Arc<dyn DispatchOrchestrator> {
        &self.dispatch_orchestrator
    }

    /// The embedder-registered secret resolver, if any. See
    /// [`KernelConfig::secret_resolver`].
    pub fn secret_resolver(&self) -> Option<&Arc<dyn SecretResolver>> {
        self.secret_resolver.as_ref()
    }

    /// Pull `plugin_name`'s own secrets for an execution about to start.
    ///
    /// The place an execution's *own* credentials enter it. Every
    /// `execute_dag` call site goes through it, so there is no path by
    /// which a bag reaches a plugin without the three checks below. (A
    /// foreign step body's view is pulled separately, per step, by the
    /// dispatcher — see [`host_api::StepTypeAccess::body_owner`].)
    ///
    /// 1. `subject` is on the executing plugin's chain
    ///    ([`secrets::subject_is_on_chain`]) — trivially true here, where
    ///    subject and executing plugin are the same identity. The
    ///    foreign-body pull in the step dispatcher shares the same
    ///    `secrets::pull` and is where it bites.
    /// 2. The resolver answered, or the action fails. A resolver error is
    ///    never downgraded to "no secrets" — see
    ///    [`secrets::SecretError::Unavailable`].
    /// 3. The answer is intersected with the manifest's `usesSecrets`
    ///    ([`secrets::intersect_declared`]), so a plugin cannot see a key
    ///    it did not declare however much the resolver hands over.
    ///
    /// `resolver` is the one this invocation tree pulls through — the
    /// kernel's configured resolver, carried on the invocation context
    /// so the foreign-body call site can later ask through the same
    /// handle. `None` means no credentials exist for this kernel, and
    /// the plugin sees `Null`.
    pub(crate) async fn pull_secrets(
        &self,
        plugin_name: &str,
        resolver: Option<&Arc<dyn SecretResolver>>,
        exec_ctx: &ExecutionContext,
    ) -> Result<Value, KernelError> {
        let Some(resolver) = resolver else {
            return Ok(Value::Null);
        };
        let (declared, overridable) = self
            .registry
            .get_manifest(plugin_name)
            .map(|m| (m.declared_secret_keys(), m.overridable_secret_keys()))
            .unwrap_or_default();
        secrets::pull(
            resolver.as_ref(),
            plugin_name,
            plugin_name,
            &declared,
            &overridable,
            exec_ctx,
        )
        .await
    }

    /// Snapshot the registered `script` step type implementations as a
    /// language → `Arc<Module>` map. Called by every `execute_*`
    /// entry point at invocation start, so the per-invocation
    /// ExecutionState carries a frozen view of the registered runtimes
    /// — later registry changes don't affect in-flight invocations.
    pub(crate) fn script_runtimes(
        &self,
    ) -> std::sync::Arc<std::collections::HashMap<String, std::sync::Arc<wasmtime::Module>>> {
        let mut out = std::collections::HashMap::new();
        for lang in self.registry.step_type_impl_matches("script") {
            if let Some(entry) = self
                .registry
                .step_type_impl_candidates("script", Some(lang))
                .into_iter()
                .next()
                && let Some(module) = self
                    .registry
                    .get_plugin_wasm_module(&entry.plugin, &entry.wasm_module)
            {
                out.insert(lang.to_string(), module);
            }
        }
        std::sync::Arc::new(out)
    }

    /// Get a reference to the SPI registry.
    pub fn spi_registry(&self) -> &SpiRegistry {
        &self.spi_registry
    }
}

/// Race an action future against the wallclock timeout from
/// [`RuntimeLimits`]. The deadline applies to the entire
/// invocation including any nested `invoke` calls — those inherit the
/// outer budget naturally because they run inside the same `.await`
/// scope.
///
/// # Two mechanisms, because one of them cannot work alone
///
/// [`tokio::time::timeout`] can only fire when the future it wraps
/// returns `Pending`. A `repeat` body of pure `let` steps never does —
/// it runs to completion inside a single `poll`, pinning a worker
/// thread — so on its own the timeout would be unenforceable against
/// exactly the shape that most needs it: a loop of millions of such
/// iterations would run to completion, however long that takes, and
/// return `Ok`.
///
/// So the deadline also arms a **watchdog task** that fires the
/// invocation's [`CancellationToken`](tokio_util::sync::CancellationToken)
/// on its own worker. The nested executors (`run_iteration`, `run_try`,
/// `run_parallel`, `run_ifs`) poll that token between steps, so the same
/// loop exits within milliseconds of the deadline.
///
/// The `tokio::time::timeout` stays as the second half, armed
/// [`WALLCLOCK_DROP_GRACE`] later than the watchdog so the cooperative
/// exit gets first crack. It catches the mirror-image case: a future
/// that *does* yield but ignores the token (a step awaiting something
/// that never resolves). It drops the future, whose own cleanup then
/// never runs, and fires the token itself so detached work that holds
/// only the token — a streaming `invoke` callee, a forwarder task —
/// still winds down. Either way the caller sees
/// [`KernelError::ExecutionTimeout`].
///
/// Once the watchdog has fired, a cancellation-shaped outcome is
/// reported as the deadline: "your deadline expired" and "somebody
/// cancelled you" are different facts the caller acts on. The shapes
/// are typed all the way down — the wave scheduler's cooperative exit
/// and a host step's [`StepError::Cancelled`](host_api::StepError)
/// are `Cancelled`; a callee that was cancelled through the propagated
/// token is the caller's own `Cancelled`; a callee that hit a deadline
/// derived from the caller's is `CalleeFailed` over `ExecutionTimeout`
/// ([`stopped_by_cancellation`]). An `Ok` resolved after the watchdog
/// fired is the deadline too: the scheduler winding down with partial
/// results, or a step handing back what it had, is not a success, and
/// an `Ok` cannot carry the fact that the deadline passed. Any *other*
/// error passes through as the failure it is — a step that ignored the
/// token and then failed for its own reasons is reported for those
/// reasons, with the deadline noted in the log. A step that answers
/// the token with a `Failed` or `Thrown` of its own therefore
/// misreports itself; the typed variant exists so it need not. The
/// watchdog claims the stop only if nobody had fired the token before
/// it: a caller's own cancel just ahead of the deadline is reported as
/// theirs, whatever the timer did.
///
/// Still best-effort against a `block_in_place` region inside a single
/// host step, which neither mechanism can preempt. In practice those
/// are bounded by some external limit — an embedder HTTP step's client
/// timeout, or a stream EOF. Truly CPU-bound *wasm* loops are caught by
/// the per-script fuel budget.
///
/// A **dataflow** action is no exception: its deadline also surfaces as
/// [`KernelError::ExecutionTimeout`]. The watchdog's cancel makes the
/// scheduler wind down and emit `PipelineCompleted { ok: false }` on
/// the events channel, and its `Ok`-with-partial-results is remapped
/// here — that shape is for a cancel the *caller* requested, not for
/// the deadline. (`resource_limits_tests` pins this.) The dataflow
/// entry points use [`run_with_wallclock_timeout`] directly so they
/// can tell a future the backstop *dropped* (its terminal emit never
/// ran, so they send a substitute) from one that wound down itself.
///
/// `None` means no automatic cap: dataflow actions with no per-action
/// declaration and no operator ceiling end up here and rely entirely on
/// cooperative cancellation.
async fn with_wallclock_timeout<F>(
    fut: F,
    timeout: Option<std::time::Duration>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<ActionResult, KernelError>
where
    F: std::future::Future<Output = Result<ActionResult, KernelError>>,
{
    run_with_wallclock_timeout(fut, timeout, cancel)
        .await
        .result
}

/// How long the hard backstop waits past the deadline before dropping
/// the action future.
///
/// The watchdog fires the token exactly at the deadline. A future that
/// observes it — the wave scheduler between steps, a host step racing
/// its IO against the token, a dataflow scheduler winding down — exits
/// on its own within this window and its own cleanup runs. Only a
/// future that ignores the token for the whole window is dropped.
/// Armed at the same instant, the two mechanisms would race and the
/// drop would win often enough that cooperative cleanup was the
/// exception rather than the rule.
const WALLCLOCK_DROP_GRACE: std::time::Duration = std::time::Duration::from_millis(100);

/// What [`run_with_wallclock_timeout`] observed alongside the result.
///
/// The dataflow entry points need one extra bit the `Result` alone
/// cannot carry: whether the action future ran to completion or was
/// dropped mid-flight by the backstop. Only the dropped future skipped
/// the scheduler's own `PipelineCompleted` emit, so only that case
/// needs a substitute terminator. Keying the substitute on the *error
/// variant* instead would double-emit whenever a completed future's
/// outcome was remapped to the deadline.
struct WallclockOutcome {
    result: Result<ActionResult, KernelError>,
    /// `true` when the backstop dropped the future before it resolved,
    /// so none of its own cleanup ran. `false` whenever the future
    /// itself resolved, including when its outcome was remapped to
    /// [`KernelError::ExecutionTimeout`] because the watchdog stopped it.
    abandoned: bool,
}

/// [`with_wallclock_timeout`] plus the abandoned-vs-completed bit; see
/// the former for the mechanism.
async fn run_with_wallclock_timeout<F>(
    fut: F,
    timeout: Option<std::time::Duration>,
    cancel: tokio_util::sync::CancellationToken,
) -> WallclockOutcome
where
    F: std::future::Future<Output = Result<ActionResult, KernelError>>,
{
    let Some(timeout) = timeout else {
        return WallclockOutcome {
            result: fut.await,
            abandoned: false,
        };
    };
    let timeout_ms = timeout.as_millis() as u64;

    // Armed on a separate task so a step body that never yields still
    // observes the deadline — the whole point.
    let expired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watchdog = {
        let expired = Arc::clone(&expired);
        let cancel = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            // A token the caller (or a parent) fired first is their
            // cancel, not ours: leave `expired` clear so whatever the
            // future resolves to is reported as theirs.
            if !cancel.is_cancelled() {
                expired.store(true, std::sync::atomic::Ordering::SeqCst);
                cancel.cancel();
            }
        })
    };

    let outcome = tokio::time::timeout(timeout + WALLCLOCK_DROP_GRACE, fut).await;
    watchdog.abort();
    let expired = expired.load(std::sync::atomic::Ordering::SeqCst);

    match outcome {
        Err(_elapsed) => {
            // Dropping the future does not reach work that holds only
            // the token. Fire it here: the aborted watchdog may never
            // have got to, and firing an already-fired token is a no-op.
            cancel.cancel();
            WallclockOutcome {
                result: Err(KernelError::ExecutionTimeout { timeout_ms }),
                abandoned: true,
            }
        }
        // The watchdog's cancel is what stopped the action, so report
        // the deadline rather than whatever shape the stop took on the
        // way out — a cancellation the caller never asked for, a
        // step's own "I was cancelled" error, or an `Ok` of partial
        // results. A failure that merely coincided with the deadline
        // reads the same way; it is logged in full so it is not lost.
        Ok(Ok(_)) if expired => {
            tracing::debug!(
                timeout_ms,
                "action resolved Ok after the wallclock watchdog fired; reporting ExecutionTimeout"
            );
            WallclockOutcome {
                result: Err(KernelError::ExecutionTimeout { timeout_ms }),
                abandoned: false,
            }
        }
        Ok(Err(err)) if expired && stopped_by_cancellation(&err) => {
            tracing::debug!(
                timeout_ms,
                error = %err,
                "action stopped by the wallclock watchdog; reporting ExecutionTimeout"
            );
            WallclockOutcome {
                result: Err(KernelError::ExecutionTimeout { timeout_ms }),
                abandoned: false,
            }
        }
        Ok(Err(err)) if expired => {
            tracing::debug!(
                timeout_ms,
                error = %err,
                "action failed after the wallclock watchdog fired; reporting the failure itself"
            );
            WallclockOutcome {
                result: Err(err),
                abandoned: false,
            }
        }
        Ok(result) => WallclockOutcome {
            result,
            abandoned: false,
        },
    }
}

/// Whether an error is the shape a cancellation takes on its way out
/// of an action: the invocation's own `Cancelled`, or a failed callee
/// whose root cause is a cancellation or a deadline. A callee's
/// `ExecutionTimeout` counts because a callee's cap is never longer
/// than what its caller has left, so when the caller's watchdog has
/// fired, the callee's expiry is the same event seen one level down.
fn stopped_by_cancellation(err: &KernelError) -> bool {
    match err {
        KernelError::Cancelled { .. } | KernelError::ExecutionTimeout { .. } => true,
        KernelError::CalleeFailed { source, .. } => stopped_by_cancellation(source),
        _ => false,
    }
}

/// Validate every kernel-global identifier a manifest declares against
/// the [`identity`] name grammar.
///
/// The set is exactly the identifiers that become a lookup key, a wasm
/// linker import name, or a substring of a permission string:
///
/// | Field | Why it is global |
/// |---|---|
/// | `name` | the plugin registry key; appears in `invoke:plugin:<name>` |
/// | `roles[]` | the SPI dispatch key; appears in `invoke:role:<name>` |
/// | `stepTypeDefs[].name` | a step `type` keyword; appears in `step_type:<name>` |
/// | `stepTypeImpls[].stepType` | claims a linker import slot; appears in `provide:step_type:<type>` |
/// | `stepTypeImpls[].matches` | the selector half of `provide:step_type:<type>:<selector>` |
///
/// `stepTypes` alias keys are deliberately absent: they are validated
/// by [`validate_step_type_alias`], which also checks ownership and
/// the reserved names, so the message an author needs comes from one
/// place.
///
/// Action names are also absent. They are scoped to their declaring
/// plugin rather than kernel-global, and there is no `invoke:action:`
/// grant.
fn validate_manifest_names(manifest: &PluginManifest, kernel_owned: bool) -> Result<(), String> {
    use self::identity::{NameKind, validate_name};

    validate_name(NameKind::Plugin, &manifest.name).map_err(|e| e.to_string())?;

    // From here the plugin name is known good, so it can safely prefix
    // the remaining messages — an author with several manifests open
    // needs to know which one is being rejected.
    let named = |e: self::identity::NameError| format!("Plugin '{}': {e}", manifest.name);

    for role in &manifest.roles {
        validate_name(NameKind::Role, role).map_err(named)?;
    }
    // A def is owned by its declarer, so the name must carry the
    // declarer's prefix (or be bare, for the kernel). An impl may
    // target a kernel slot (`script`, bare) or a plugin-defined type —
    // its own, normally, or another's under the two-key binding rule —
    // so here only the shape is checked; ownership of the *claim* is
    // `check_step_type_impl_claim`'s.
    for def in &manifest.step_type_defs {
        self::identity::validate_step_type_name(&def.name, &manifest.name, kernel_owned)
            .map_err(named)?;
    }
    for decl in &manifest.step_type_impls {
        self::identity::validate_step_type_reference(&decl.step_type).map_err(named)?;
        if let Some(selector) = &decl.matches {
            validate_name(NameKind::StepTypeSelector, selector).map_err(named)?;
        }
    }
    Ok(())
}

/// Validate a step-type alias name. An alias is a step type the
/// declaring plugin defines, so it follows the def naming rule —
/// `<plugin>.<alias>`, bare only for the kernel — and must not be a
/// kernel-reserved name listed in [`host_api::RESERVED_STEP_TYPE_NAMES`]
/// (which covers all 11 intrinsics — control-flow + trait-shape alike).
fn validate_step_type_alias(
    alias: &str,
    declaring_plugin: &str,
    kernel_owned: bool,
) -> Result<(), String> {
    // An alias is a step type the declaring plugin defines (it
    // dispatches into that plugin's own action), so it follows the
    // def naming rule: `<plugin>.<alias>`, bare only for the kernel.
    self::identity::validate_step_type_name(alias, declaring_plugin, kernel_owned)
        .map_err(|e| e.to_string())?;
    if host_api::RESERVED_STEP_TYPE_NAMES.contains(&alias) {
        return Err(format!(
            "step_types alias '{alias}' is reserved by the kernel"
        ));
    }
    Ok(())
}

/// Register-time validation gate for the step shape.
///
/// Walks every step in `steps` (recursing into `for_each.steps`,
/// `repeat.steps`, `ifs.ifs[].then`, `try.try`/`catch`/`finally`,
/// and `parallel.branches[*]`) and enforces three contracts:
///
/// 1. **`script` language is supported**. Rejects any
///    `{type: "script", language: X}` instance unless a plugin has
///    registered `(script, X)` via [`PluginManifest::step_type_impls`].
///    The lookup spans BOTH already-registered impls AND the impls
///    this manifest is contributing in the same registration — so a
///    self-contained manifest that declares its own runtime alongside
///    its scripted actions validates cleanly.
///
/// 2. **Nested bodies are well-formed**. Every entry of a sub-block
///    step array must parse as a step, a sub-block key that is present
///    must be an array, and an `ifs` branch with no `test` must be
///    last. A malformed nested step is rejected with its path rather
///    than silently skipped.
///
/// 3. **Step ids are DSL identifiers**
///    ([`identity::validate_name`] with [`identity::NameKind::StepId`]:
///    the name grammar minus a leading digit, i.e. the DSL's `ident`).
///    An id is a reference target — `$steps.<id>` — and one the DSL
///    cannot parse would load and then be unreachable from every
///    expression, template, and dependency edge, silently. The
///    meta-schema applies the same rule to JSON input; this is what
///    covers a manifest handed in as a struct.
fn validate_step_shapes(
    action_name: &str,
    steps: &[StepDef],
    registry: &PluginRegistry,
    local_impls: &[types::StepTypeImpl],
) -> Result<(), String> {
    let language_has_impl = |lang: &str| -> bool {
        !registry
            .step_type_impl_candidates("script", Some(lang))
            .is_empty()
            || local_impls
                .iter()
                .any(|i| i.step_type == "script" && i.matches.as_deref() == Some(lang))
    };

    fn walk(
        action_name: &str,
        steps: &[StepDef],
        language_has_impl: &dyn Fn(&str) -> bool,
        registry: &PluginRegistry,
        local_impls: &[types::StepTypeImpl],
    ) -> Result<(), String> {
        for step in steps {
            if let Err(e) =
                self::identity::validate_name(self::identity::NameKind::StepId, &step.id)
            {
                return Err(format!("action '{action_name}': {e}"));
            }

            // An `invoke` step naming a target with the reserved
            // namespace separator is rejected at load, not left to fail
            // when the step eventually runs.
            //
            // Runtime resolution refuses it too, so this is not what
            // makes it safe — it is what stops a manifest *deploying*
            // with a reference that cannot work and would start
            // working, pointed at another namespace, on the day the
            // qualified syntax is honoured. Same reasoning as the glob
            // and dot-free-category reservations: reject the syntax
            // while it means nothing, so giving it meaning later cannot
            // change what an already-installed manifest does.
            //
            // Only literal targets are checked. `plugin` flows through
            // the template engine, so a `{{...}}` target is unknowable
            // here and is caught at resolution instead.
            if step.step_type == "invoke"
                && let Some(target) = step.params.get("plugin").and_then(|v| v.as_str())
                && !target.contains("{{")
                && !target.starts_with('$')
                && let Err(e) =
                    self::identity::validate_reference(self::identity::NameKind::Plugin, target)
            {
                return Err(format!("action '{action_name}' step '{}': {e}", step.id));
            }

            if step.step_type == "script" {
                // The kernel ships no script runtime and is
                // language-agnostic, so there is no default: a
                // `script` step must say which `(script, <language>)`
                // slot it wants.
                let Some(language) = step.params.get("language").and_then(|v| v.as_str()) else {
                    return Err(format!(
                        "action '{action_name}' step '{}': `script` step requires a \
                         `language` param naming a registered script runtime",
                        step.id
                    ));
                };
                if !language_has_impl(language) {
                    let mut supported: Vec<&str> = registry.step_type_impl_matches("script");
                    for impl_decl in local_impls {
                        if impl_decl.step_type == "script"
                            && let Some(m) = impl_decl.matches.as_deref()
                        {
                            supported.push(m);
                        }
                    }
                    supported.sort();
                    supported.dedup();
                    return Err(format!(
                        "action '{action_name}' step '{}' uses script language '{language}' \
                         but no plugin has registered an implementation; \
                         supported languages: {supported:?}",
                        step.id
                    ));
                }
            }

            // Recurse into known sub-block-carrying step types. The
            // shapes mirror the runtime's splice points in
            // `run_foreach` / `run_repeat` / `run_ifs` / `run_try` /
            // `run_parallel`.
            //
            // Helper: STRICT parse of a JSON array into Vec<StepDef>.
            // Every entry must parse — a typo'd step in a
            // nested block would otherwise be silently dropped by the
            // runtime's filter_map, so the step would just never run
            // with no signal to the author. Instead, registration
            // fails with the action / parent step / key path and the
            // serde error.
            let step_id = &step.id;
            let parse_inner =
                |key_path: &str, arr: &Vec<serde_json::Value>| -> Result<Vec<StepDef>, String> {
                    arr.iter()
                        .enumerate()
                        .map(|(i, v)| {
                            StepDef::from_inner_value(v).map_err(|e| {
                                format!(
                                    "action '{action_name}' step '{step_id}' {key_path}[{i}]: \
                                 malformed step: {e}"
                                )
                            })
                        })
                        .collect()
                };

            // A sub-block key that's present but NOT an array — e.g.
            // `"try": { ...one step... }`, forgotten brackets — would
            // be silently treated as an empty block by the runtime's
            // `.and_then(|v| v.as_array())` guards: the same silent
            // no-op this pass exists to kill, one level up.
            // Absent keys stay legal (an omitted `finally` is
            // normal authoring); only wrong types are rejected.
            let require_array = |key_path: &str,
                                 v: Option<&serde_json::Value>|
             -> Result<Option<Vec<serde_json::Value>>, String> {
                match v {
                    None => Ok(None),
                    Some(serde_json::Value::Array(arr)) => Ok(Some(arr.clone())),
                    Some(other) => Err(format!(
                        "action '{action_name}' step '{step_id}' {key_path}: must be an \
                         array of steps, got {}",
                        json_kind(other)
                    )),
                }
            };

            if step.step_type == "for_each" || step.step_type == "repeat" {
                if let Some(inner_arr) = require_array("steps", step.params.get("steps"))? {
                    walk(
                        action_name,
                        &parse_inner("steps", &inner_arr)?,
                        language_has_impl,
                        registry,
                        local_impls,
                    )?;
                }
            } else if step.step_type == "ifs" {
                let Some(ifs) = step.params.get("ifs") else {
                    return Err(format!(
                        "action '{action_name}' step '{step_id}': `ifs` step requires an \
                         `ifs` array of branch objects"
                    ));
                };
                let Some(ifs_arr) = ifs.as_array() else {
                    return Err(format!(
                        "action '{action_name}' step '{step_id}' ifs: must be an \
                         array of branch objects, got {}",
                        json_kind(ifs)
                    ));
                };
                let last_idx = ifs_arr.len().saturating_sub(1);
                for (branch_idx, branch) in ifs_arr.iter().enumerate() {
                    if !branch.is_object() {
                        return Err(format!(
                            "action '{action_name}' step '{step_id}' ifs[{branch_idx}]: \
                             must be a branch object with `test` and `then`, got {}",
                            json_kind(branch)
                        ));
                    }
                    // `test` is a DSL string, or absent/null for the
                    // always-matching "else" branch. An untested branch
                    // must be last: every branch after it is dead, and
                    // a silently unreachable branch is a manifest bug.
                    match branch.get("test") {
                        None | Some(serde_json::Value::Null) => {
                            if branch_idx != last_idx {
                                return Err(format!(
                                    "action '{action_name}' step '{step_id}' \
                                     ifs[{branch_idx}]: a branch with no `test` always \
                                     matches, so it must be the last branch (found {} \
                                     after it)",
                                    last_idx - branch_idx
                                ));
                            }
                        }
                        Some(serde_json::Value::String(_)) => {}
                        Some(other) => {
                            return Err(format!(
                                "action '{action_name}' step '{step_id}' \
                                 ifs[{branch_idx}].test: must be a DSL condition string \
                                 (or null / omitted for the final else branch), got {}",
                                json_kind(other)
                            ));
                        }
                    }
                    if let Some(then_arr) =
                        require_array(&format!("ifs[{branch_idx}].then"), branch.get("then"))?
                    {
                        walk(
                            action_name,
                            &parse_inner(&format!("ifs[{branch_idx}].then"), &then_arr)?,
                            language_has_impl,
                            registry,
                            local_impls,
                        )?;
                    }
                }
            } else if step.step_type == "try" {
                // try / catch / finally bodies.
                for key in ["try", "catch", "finally"] {
                    if let Some(arr) = require_array(key, step.params.get(key))? {
                        walk(
                            action_name,
                            &parse_inner(key, &arr)?,
                            language_has_impl,
                            registry,
                            local_impls,
                        )?;
                    }
                }
            } else if step.step_type == "parallel" {
                // `branches` is an array of branches, each itself an
                // array of steps. Present-but-not-an-array is rejected
                // like every other sub-block key.
                if let Some(branches_val) = step.params.get("branches")
                    && !branches_val.is_array()
                {
                    return Err(format!(
                        "action '{action_name}' step '{step_id}' branches: must be an \
                         array of step arrays, got {}",
                        json_kind(branches_val)
                    ));
                }
                if let Some(branches) = step.params.get("branches").and_then(|v| v.as_array()) {
                    // Cross-branch step-id collision check.
                    // Branches run concurrently on forked states whose
                    // writes merge into one result keyspace, so the
                    // same id in two branches would be a join-order
                    // race. Ids are
                    // collected recursively — a nested `ifs`/`try`
                    // body's steps write `step_results` slots too.
                    // Duplicates *within* one branch are out of scope
                    // here (no concurrency between them).
                    let mut seen: std::collections::HashMap<String, usize> =
                        std::collections::HashMap::new();
                    for (branch_idx, branch) in branches.iter().enumerate() {
                        let mut ids = Vec::new();
                        for branch_step in branch.as_array().into_iter().flatten() {
                            collect_step_field_recursive(branch_step, "id", &mut ids);
                        }
                        for id in ids {
                            match seen.get(&id) {
                                Some(&prev) if prev != branch_idx => {
                                    return Err(format!(
                                        "action '{action_name}' parallel step '{}': step id \
                                         '{id}' appears in both branch {prev} and branch \
                                         {branch_idx}; branches execute concurrently and \
                                         merge into one result keyspace, so step ids must \
                                         be unique across branches",
                                        step.id
                                    ));
                                }
                                _ => {
                                    seen.entry(id).or_insert(branch_idx);
                                }
                            }
                        }
                    }
                    // Cross-branch storeToVariable collision check.
                    // The branch merge keeps only NEW variables
                    // (pre-existing-variable writes are documented as
                    // discarded), so two branches introducing the same
                    // new variable would resolve last-merged-wins,
                    // silently — a join-order race, same shape as the
                    // step-id collision above. storeToVariable is a
                    // static manifest field, so reject it here.
                    // Duplicates *within* one branch stay legal
                    // (sequential overwrite, no concurrency).
                    let mut seen_vars: std::collections::HashMap<String, usize> =
                        std::collections::HashMap::new();
                    for (branch_idx, branch) in branches.iter().enumerate() {
                        let mut vars = Vec::new();
                        for branch_step in branch.as_array().into_iter().flatten() {
                            collect_step_field_recursive(branch_step, "storeToVariable", &mut vars);
                        }
                        for var in vars {
                            match seen_vars.get(&var) {
                                Some(&prev) if prev != branch_idx => {
                                    return Err(format!(
                                        "action '{action_name}' parallel step '{}': \
                                         storeToVariable '{var}' appears in both branch \
                                         {prev} and branch {branch_idx}; branches execute \
                                         concurrently and merge new variables into one \
                                         keyspace, so a variable may be introduced by at \
                                         most one branch (and writes to a variable that \
                                         already existed before the parallel are discarded \
                                         at merge, so this write cannot take effect either \
                                         way)",
                                        step.id
                                    ));
                                }
                                _ => {
                                    seen_vars.entry(var).or_insert(branch_idx);
                                }
                            }
                        }
                    }
                    for (branch_idx, branch) in branches.iter().enumerate() {
                        // A branch that isn't an array is the same
                        // authoring mistake one level up — the runtime
                        // would treat it as an empty branch.
                        let Some(branch_steps) = branch.as_array() else {
                            return Err(format!(
                                "action '{action_name}' step '{step_id}' branches[{branch_idx}]: \
                                 must be an array of steps"
                            ));
                        };
                        walk(
                            action_name,
                            &parse_inner(&format!("branches[{branch_idx}]"), branch_steps)?,
                            language_has_impl,
                            registry,
                            local_impls,
                        )?;
                    }
                }
            }

            // Failure-handler bodies live inside `{type: "try",
            // catch: [...]}`, which the `try` branch above already
            // walks.
        }
        Ok(())
    }

    walk(
        action_name,
        steps,
        &language_has_impl,
        registry,
        local_impls,
    )
}

/// Describe a JSON value's kind for sub-block validation errors.
fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Object(_) => "an object",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Null => "null",
    }
}

/// Collect a string field (`"id"`, `"storeToVariable"`) from a step
/// plus every step nested inside its control-flow sub-blocks.
/// Used by the parallel cross-branch collision
/// checks in [`validate_step_shapes`].
///
/// The walk is **exact against the StepDef grammar**, not heuristic:
/// it recurses only through the keys that carry step lists for the
/// step's own type — `steps` (for_each/repeat), `ifs[*].then` (ifs),
/// `try`/`catch`/`finally` (try), `branches` (parallel).
/// Anything else — including step-*shaped* data literals like a `let`
/// value of `{id, type}` entity shape — is payload, not a step, and
/// must not contribute phantom values.
fn collect_step_field_recursive(step: &serde_json::Value, field: &str, out: &mut Vec<String>) {
    let Some(map) = step.as_object() else {
        return;
    };
    let Some(step_type) = map.get("type").and_then(|v| v.as_str()) else {
        return;
    };
    if let Some(value) = map.get(field).and_then(|v| v.as_str()) {
        out.push(value.to_string());
    }
    // Inner bodies live under `params`, like every other step-type
    // input. A step with no `params` has no bodies.
    let Some(map) = map.get("params").and_then(|v| v.as_object()) else {
        return;
    };

    let collect_list = |v: Option<&serde_json::Value>, out: &mut Vec<String>| {
        if let Some(arr) = v.and_then(|v| v.as_array()) {
            for s in arr {
                collect_step_field_recursive(s, field, out);
            }
        }
    };

    match step_type {
        "for_each" | "repeat" => collect_list(map.get("steps"), out),
        "ifs" => {
            if let Some(ifs) = map.get("ifs").and_then(|v| v.as_array()) {
                for branch in ifs {
                    collect_list(branch.get("then"), out);
                }
            }
        }
        "try" => {
            for key in ["try", "catch", "finally"] {
                collect_list(map.get(key), out);
            }
        }
        "parallel" => {
            if let Some(branches) = map.get("branches").and_then(|v| v.as_array()) {
                for branch in branches {
                    collect_list(Some(branch), out);
                }
            }
        }
        _ => {}
    }
}

/// Errors from kernel operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KernelError {
    #[error("Kernel boot failed: {0}")]
    Boot(String),

    #[error("Plugin/action not found: {0}")]
    NotFound(String),

    /// A manifest was rejected at load. Covers every load-time gate —
    /// meta-schema, name grammar, permission parse, DAG shape, step
    /// shape, step-type claims, SPI contract — so the message names no
    /// single gate. An operator told "SPI validation failed" for a
    /// malformed plugin name would go and read SPI definitions, which
    /// is the wrong place; the inner string already says which gate
    /// actually rejected it.
    #[error("Manifest validation failed: {0}")]
    Validation(String),

    #[error("Wasm runtime error: {0}")]
    Runtime(String),

    #[error("Execution error: {0}")]
    Execution(String),

    /// Wasm consumed its fuel budget. A guest module (a `script`
    /// interpreter or a `wasm` step) ran longer than
    /// `RuntimeLimits::fuel_budget` instructions allowed. The action is
    /// aborted; subsequent steps don't run.
    #[error("Wasm fuel exhausted ({budget} unit budget): {detail}")]
    FuelExhausted { budget: u64, detail: String },

    /// Wasm tried to grow its linear memory past
    /// `RuntimeLimits::max_memory_bytes`. A guest module allocated more
    /// than the per-invocation ceiling allowed.
    #[error("Wasm memory limit exceeded ({limit_bytes} bytes)")]
    MemoryLimitExceeded { limit_bytes: usize },

    /// One invocation's step results outgrew
    /// `RuntimeLimits::max_step_results_bytes`. Host-side memory, not
    /// wasm memory — a manifest can compose step results into a
    /// doubling chain without any guest code running at all.
    #[error(
        "Step results exceeded the {limit_bytes}-byte budget (needed {attempted_bytes}). \
         Step results accumulate across an action and one step may reference another's \
         result more than once, so a chain of them grows geometrically; raise \
         RuntimeLimits::max_step_results_bytes if this action legitimately holds \
         this much."
    )]
    StepResultsLimitExceeded {
        limit_bytes: usize,
        attempted_bytes: usize,
    },

    /// Action exceeded its effective wallclock deadline — the action's
    /// own `wallclockTimeoutMs`, else
    /// `RuntimeLimits::default_wallclock_timeout`, either clamped by
    /// `max_wallclock_timeout`; see `Kernel::effective_wallclock_timeout`.
    /// Wraps the entire `execute_dag` future; fires on either a
    /// genuinely long-running step or a hung blocking call.
    #[error("Action wallclock timeout exceeded ({timeout_ms} ms)")]
    ExecutionTimeout { timeout_ms: u64 },

    /// The invocation's cancellation token fired and the wave
    /// scheduler stopped before the next step. Distinct from
    /// [`Self::Execution`] so callers can tell "we cancelled it" from
    /// "it broke". (Dataflow actions surface cancellation differently
    /// — via `PipelineCompleted { ok: false }` with an `Ok` result —
    /// see `DataflowHandle::cancel`.)
    #[error("Action cancelled at step '{at_step}'")]
    Cancelled { at_step: String },

    /// A nested invocation failed — an `invoke` or alias step's callee,
    /// or an action a native step dispatched by role — and this is the
    /// callee's own error, intact. Callers branch on `source` (a
    /// callee's `PluginError` code, its `ExecutionTimeout`) instead of
    /// parsing the message, which keeps the flattened shape so a
    /// `try.catch` handler's `{{$.error}}` reads as before. Shared
    /// rather than boxed because it travels through the `Clone` step
    /// error. (A *cancelled* callee is not this: its token is a child
    /// of the caller's, so it surfaces as the caller's own
    /// [`Self::Cancelled`].)
    #[error("step '{step_id}' → {plugin}.{action} failed: {source}")]
    CalleeFailed {
        step_id: String,
        plugin: String,
        action: String,
        #[source]
        source: Arc<KernelError>,
    },

    /// A plugin explicitly threw a structured error via the
    /// `throw_error` step type. Carries the plugin-supplied
    /// `code`, optional `message`, and optional `params` object so
    /// callers can branch on the code rather than
    /// parse strings.
    #[error("Plugin error {code}: {message}")]
    PluginError {
        code: String,
        message: String,
        params: serde_json::Value,
    },
}

#[cfg(test)]
mod wallclock_timeout_tests {
    use super::*;

    fn ok_result() -> ActionResult {
        ActionResult {
            output: Value::Null,
            variables: Default::default(),
            step_results: Default::default(),
        }
    }

    fn host_cancelled() -> KernelError {
        KernelError::PluginError {
            code: "host_cancelled".into(),
            message: String::new(),
            params: Value::Null,
        }
    }

    /// A future that ignores the token and never resolves is dropped
    /// by the backstop: `ExecutionTimeout`, `abandoned` so the dataflow
    /// path knows the future's own cleanup never ran, and the token
    /// fired anyway so detached work holding only the token winds down.
    #[tokio::test]
    async fn future_that_ignores_the_token_is_abandoned_and_token_fired() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let outcome = run_with_wallclock_timeout(
            std::future::pending(),
            Some(std::time::Duration::from_millis(20)),
            cancel.clone(),
        )
        .await;
        assert!(outcome.abandoned);
        assert!(matches!(
            outcome.result,
            Err(KernelError::ExecutionTimeout { timeout_ms: 20 })
        ));
        assert!(
            cancel.is_cancelled(),
            "the abandoned path must still fire the token"
        );
    }

    fn cancelled() -> KernelError {
        KernelError::Cancelled {
            at_step: "s".into(),
        }
    }

    /// A future that answers the watchdog's cancel with `Cancelled`
    /// resolved on its own: not abandoned, and reported as the
    /// deadline. The grace window makes this deterministic — the
    /// watchdog fires first, the backstop only 100 ms later.
    #[tokio::test]
    async fn cancellation_after_the_watchdog_fired_is_the_deadline_not_abandoned() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let observed = cancel.clone();
        let outcome = run_with_wallclock_timeout(
            async move {
                observed.cancelled().await;
                Err(cancelled())
            },
            Some(std::time::Duration::from_millis(20)),
            cancel,
        )
        .await;
        assert!(!outcome.abandoned);
        assert!(matches!(
            outcome.result,
            Err(KernelError::ExecutionTimeout { timeout_ms: 20 })
        ));
    }

    /// A callee cancelled or timed out one level down is the same
    /// event: reported as the deadline when the watchdog has fired.
    #[tokio::test]
    async fn callee_deadline_after_the_watchdog_fired_is_the_deadline() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let observed = cancel.clone();
        let outcome = run_with_wallclock_timeout(
            async move {
                observed.cancelled().await;
                Err(KernelError::CalleeFailed {
                    step_id: "call".into(),
                    plugin: "callee".into(),
                    action: "go".into(),
                    source: Arc::new(KernelError::ExecutionTimeout { timeout_ms: 20 }),
                })
            },
            Some(std::time::Duration::from_millis(20)),
            cancel,
        )
        .await;
        assert!(matches!(
            outcome.result,
            Err(KernelError::ExecutionTimeout { timeout_ms: 20 })
        ));
    }

    /// A failure that is not cancellation-shaped passes through even
    /// after the watchdog fired: the step failed for its own reasons
    /// and those reasons are what the caller needs.
    #[tokio::test]
    async fn own_failure_after_the_watchdog_fired_passes_through() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let observed = cancel.clone();
        let outcome = run_with_wallclock_timeout(
            async move {
                observed.cancelled().await;
                Err(host_cancelled())
            },
            Some(std::time::Duration::from_millis(20)),
            cancel,
        )
        .await;
        assert!(!outcome.abandoned);
        assert!(matches!(
            outcome.result,
            Err(KernelError::PluginError { code, .. }) if code == "host_cancelled"
        ));
    }

    /// Same for a future that answers the cancel with an `Ok`: a result
    /// produced because the deadline fired is not a success.
    #[tokio::test]
    async fn ok_after_the_watchdog_fired_is_the_deadline() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let observed = cancel.clone();
        let outcome = run_with_wallclock_timeout(
            async move {
                observed.cancelled().await;
                Ok(ok_result())
            },
            Some(std::time::Duration::from_millis(20)),
            cancel,
        )
        .await;
        assert!(!outcome.abandoned);
        assert!(matches!(
            outcome.result,
            Err(KernelError::ExecutionTimeout { timeout_ms: 20 })
        ));
    }

    /// The caller fires the token just before the deadline and the
    /// future takes a while to wind down, so the deadline timer fires
    /// while it is still running. That is the caller's cancel, not the
    /// watchdog's: the future's own error passes through.
    #[tokio::test]
    async fn caller_cancel_before_the_deadline_is_not_claimed_by_the_watchdog() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let observed = cancel.clone();
        let trigger = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            trigger.cancel();
        });
        let outcome = run_with_wallclock_timeout(
            async move {
                observed.cancelled().await;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                Err(host_cancelled())
            },
            Some(std::time::Duration::from_millis(20)),
            cancel,
        )
        .await;
        assert!(!outcome.abandoned);
        assert!(matches!(
            outcome.result,
            Err(KernelError::PluginError { code, .. }) if code == "host_cancelled"
        ));
    }

    /// An error inside the deadline is the future's own business: it
    /// passes through, and the future was not abandoned.
    #[tokio::test]
    async fn error_inside_the_deadline_passes_through() {
        let outcome = run_with_wallclock_timeout(
            async { Err(host_cancelled()) },
            Some(std::time::Duration::from_secs(10)),
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
        assert!(!outcome.abandoned);
        assert!(matches!(
            outcome.result,
            Err(KernelError::PluginError { code, .. }) if code == "host_cancelled"
        ));
    }

    /// `None` is no cap at all: no watchdog, no outer timeout.
    #[tokio::test]
    async fn no_cap_runs_bare() {
        let outcome = run_with_wallclock_timeout(
            async { Ok(ok_result()) },
            None,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
        assert!(!outcome.abandoned);
        assert!(outcome.result.is_ok());
    }
}

#[cfg(test)]
mod load_manifest_tests {
    use super::*;

    fn boot() -> Kernel {
        Kernel::boot(KernelConfig::default()).expect("kernel boots")
    }

    #[test]
    fn classifies_and_loads_spi_def() {
        let mut k = boot();
        let spi = r#"{
            "name": "TEST_SPI",
            "version": "1.0",
            "actions": {
                "ping": {"input": {"type": "object"}, "output": {"type": "object"}}
            }
        }"#;
        let handle = k.load_manifest(spi).register().expect("loads as SPI def");
        // Handles are u64 — distinct ids on successive loads.
        let spi2 = r#"{
            "name": "TEST_SPI_2",
            "version": "1.0",
            "actions": {"x": {"input": {}, "output": {}}}
        }"#;
        let handle2 = k
            .load_manifest(spi2)
            .register()
            .expect("loads a second SPI");
        assert_ne!(handle, handle2);
    }

    #[test]
    fn classifies_and_loads_plugin() {
        let mut k = boot();
        // Plugin that claims no roles → trivially satisfies SPI
        // validation. `log` is not a registered step type here;
        // registration does not resolve bodies, so the manifest loads.
        let plugin = r#"{
            "name": "tiny_test_plugin",
            "version": "1.0",
            "actions": {
                "noop": {
                    "steps": [
                        {"id": "s", "type": "log", "params": {"message": "ok"}}
                    ]
                }
            }
        }"#;
        let _handle = k.load_manifest(plugin).register().expect("loads as plugin");
        assert!(
            k.registry()
                .get_action("tiny_test_plugin", "noop")
                .is_some()
        );
    }

    #[test]
    fn rejects_malformed_shape() {
        let mut k = boot();
        let bad = r#"{ "name": "nothing", "version": "1.0" }"#;
        let err = k
            .load_manifest(bad)
            .register()
            .expect_err("no actions, no metadata");
        let msg = err.to_string();
        assert!(
            msg.contains("not a recognized shape") || msg.contains("recognized"),
            "expected classification error, got: {msg}"
        );
    }

    #[test]
    fn manifest_kind_classifies_without_registering() {
        let spi = r#"{
            "name": "SOMETHING",
            "actions": { "ping": {"input": {}, "output": {}} }
        }"#;
        assert_eq!(Kernel::manifest_kind(spi).unwrap(), ManifestKind::SpiDef);

        let plugin = r#"{
            "name": "plug",
            "actions": {
                "noop": {"steps": [{"id":"s","type":"log","params":{"message":"x"}}]}
            }
        }"#;
        assert_eq!(Kernel::manifest_kind(plugin).unwrap(), ManifestKind::Plugin);

        let bad = r#"{ "name": "no shape" }"#;
        assert!(matches!(
            Kernel::manifest_kind(bad).unwrap_err(),
            KernelError::Validation(_)
        ));
    }

    #[test]
    fn unload_unknown_handle_is_not_found() {
        let mut k = boot();
        let h = ManifestHandle(9_999);
        let unload_err = k.unload_manifest(h).expect_err("unknown handle");
        assert!(matches!(unload_err, KernelError::NotFound(_)));
        let reload_err = k
            .reload_manifest(h, r#"{"name":"x","actions":{}}"#)
            .expect_err("unknown handle");
        assert!(matches!(reload_err, KernelError::NotFound(_)));
    }

    /// The intrinsics manifest loaded at `Kernel::boot` is marked
    /// `immutable: true`. The handle is never exposed by `boot()`, so
    /// no external caller can reach it; the immutable flag is the
    /// belt-and-braces guarantee. Lives as a lib test because
    /// constructing the
    /// `ManifestHandle(1)` reference uses the crate-private tuple
    /// struct.
    #[test]
    fn intrinsics_manifest_rejects_unload_and_reload() {
        let mut k = boot();
        // Boot assigns id 1 to the intrinsics manifest before any
        // embedder call (first thing `boot` loads). If that
        // invariant ever changes (e.g. another load-on-boot lands),
        // this test fires as an early warning.
        let intrinsics = ManifestHandle(1);

        let unload_err = k
            .unload_manifest(intrinsics)
            .expect_err("intrinsics manifest must not unload");
        match unload_err {
            KernelError::Validation(ref m) => assert!(
                m.contains("immutable"),
                "expected immutable-rejection message, got: {m}"
            ),
            other => panic!("expected Validation(immutable), got {other:?}"),
        }

        let reload_err = k
            .reload_manifest(intrinsics, r#"{"name":"x","stepTypeDefs":[]}"#)
            .expect_err("intrinsics manifest must not reload");
        match reload_err {
            KernelError::Validation(ref m) => assert!(
                m.contains("immutable"),
                "expected immutable-rejection message, got: {m}"
            ),
            other => panic!("expected Validation(immutable), got {other:?}"),
        }
    }
}
