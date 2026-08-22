//! Gwead — a wasm plugin microkernel any application can embed for
//! data-driven plugin execution.
//!
//! ## Architecture: Gwead wasm microkernel
//!
//! The engine is a small Rust kernel that loads declarative JSON plugin
//! manifests, plans each action's steps into a DAG, and executes that
//! plan with a **host-side scheduler**: steps run in topological waves,
//! with parallel branches and fan-out orchestrated on the host. wasm
//! (via wasmtime) enters at the *step* level — the `wasm` step type
//! runs plugin-supplied modules in a sandboxed store, and the `script`
//! step type executes through interpreter wasm modules contributed by
//! script-runtime plugins.
//!
//! - **`kernel`**: The Gwead microkernel — types, runtime, registry,
//!   host API, streams.
//! - **`spi`**: the SPI (Service Provider Interface) machinery — types and
//!   validator for the role contracts embedders register and plugin
//!   manifests are validated against. The kernel ships no role
//!   definitions of its own.
//! - **`dsl`**: Reference DSL — path/expression language used inside plugin
//!   manifests. See `dsl/README.md`.
//! - **`domain`**: the `{{var}}` template resolver (`domain::resolve`)
//!   every step type uses for param interpolation; it delegates to the
//!   DSL.
//!
//! ## Uniform-registration invariant
//!
//! **Step types and SPIs register through one path.** Boot itself
//! loads `gwead_intrinsics` (11 step type defs, 5 impls) through that
//! same path before any embedder code runs; the kernel's own content
//! gets no privileged shortcut.
//!
//! - Step types: every step type — kernel intrinsic or external
//!   plugin — registers through `Kernel::load_manifest` (or its
//!   `register_plugin*` convenience wrappers) and resolves
//!   `stepTypeImpls` entries against either the manifest's own
//!   `wasmModules` block (for `kind: "wasm"`), a
//!   [`kernel::native_impls::NativeStepImplTable`] built from
//!   `inventory::submit!` submissions (for `kind: "native"`), or a
//!   kernel-private intrinsic table (for `kind: "intrinsic"`). The 11
//!   intrinsics ship as `resources/manifests/intrinsics.json`,
//!   submit their five impls via `inventory::submit!` from inside
//!   this crate — two as `NativeStepImplEntry`, three as
//!   `IntrinsicStepImplEntry` — and load through the same path any
//!   external plugin uses. The five split by
//!   capability: `throw_error` and `let` are implementable through
//!   the public `PluginExecution` surface alone, so they use
//!   `kind: "native"` — the same path any external plugin's native
//!   step bodies take — while `invoke`, `wasm`, and `script` need
//!   engine internals, so they use `kind: "intrinsic"` and receive a
//!   concrete execution state that external crates cannot supply.
//!   The six control-flow
//!   intrinsics (`ifs`, `for_each`, `repeat`, `parallel`, `return`,
//!   `try`) are dispatched directly inside `runtime.rs` because they
//!   manipulate control flow rather than executing as step bodies.
//!   `let` is the value-origination primitive: it resolves its `value`
//!   param and returns it as the step result, and because it is
//!   body-shaped it picks up `store_to_variable` mirroring like any
//!   other step body, unlike the control-flow intrinsics. The `script`
//!   definition carries `selector: "language"` while its intrinsic
//!   impl is selector-less by design: `step_script` is the single
//!   dispatcher for every `script` step regardless of language, and
//!   the language-keyed `(script, lang)` registry entries that hold
//!   the actual interpreter wasm modules are contributed by
//!   language-runtime plugins — the engine ships none of its own.
//! - SPIs: the kernel ships zero SPI definitions. Embedders register
//!   them at startup via the uniform `load_manifest` entry point (or
//!   [`kernel::Kernel::register_spi_from_json`] directly).
//! - Kernel services (`step_success`, `begin_foreach`, `next_foreach`,
//!   `end_foreach`, `begin_repeat`) are not step types and do not register at all —
//!   they're host functions on the kernel/wasm Linker ABI, not a
//!   plugin surface.
//!
//! ## Step type aliases
//!
//! Plugins can publish *step type aliases* — names that resolve to one
//! of the plugin's own actions. A manifest authoring
//! `{"type": "sigv4.sign", "params": {"key": "..."}}` invokes the
//! producer plugin's `sign` action with the step params resolved as
//! the action input. Equivalent to
//! `{"type":"invoke","params":{"plugin":"sigv4","action":"sign","input":{...}}}`,
//! but readable. Declaration:
//!
//! ```jsonc
//! { "name": "sigv4",
//!   "stepTypes": { "sigv4.sign": "sign", "sigv4.verify": "verify" },
//!   "actions":   { "sign": { ... }, "verify": { ... } } }
//! ```
//!
//! An alias is a step type the declaring plugin defines, so it is
//! named `<plugin>.<alias>`; dot-free names are reserved for the
//! kernel, which is also why kernel step types cannot be aliased. An
//! alias is keyed by the declaring plugin's namespace: a second
//! manifest claiming the same key in the same namespace is rejected
//! at load, and at execution a written name resolves along the
//! executing plugin's ancestor chain, nearest namespace first. Alias
//! dispatch is registered as an intrinsic step type per alias at load
//! and routed to the target action through the registry's alias index
//! (see `PluginRegistry::step_type_aliases_iter`).
//!
//! ## Streams
//!
//! Byte streams are the kernel's pipe abstraction for data flow
//! between steps. A stream is an opaque `StreamId` owned by a
//! per-invocation [`kernel::streams::StreamRegistry`]; plugins
//! exchange the integer handle. Guest runtimes (the interpreter
//! modules behind `script` steps) call the `stream_read`,
//! `stream_write`, `stream_close` host imports to pull bytes in, push
//! bytes out, or signal EOF; host-native step types use
//! `StreamRegistry` directly.
//!
//! **Zero-copy by construction.** Chunks are [`bytes::Bytes`] —
//! ref-counted slices where `clone` is a refcount bump and `slice`
//! is a refcount bump plus a window. Host-native step types (Rust
//! code that routes, slices, tees, or forwards bytes) operate on
//! `Bytes` with no copies anywhere. The wasm-boundary copy is
//! inherent to sandboxing, not to streaming.
//!
//! **Streaming HTTP.** An embedder-provided HTTP step type can use
//! the stream registry to hand a response body back as a stream
//! handle instead of buffering it into a JSON `Value`, and to accept
//! a prior stream handle as a request body — the proxy pattern that
//! pipes one request's response into another request's body without
//! any host-side buffering.
//!
//! The full return-code contract, lifetime model, ABI versioning, and
//! guest runtime binding reference live in `src/kernel/STREAMS_ABI.md`
//! in the repository; the module-level docs on [`kernel::streams`]
//! cover the design anchor and the shipped fan-out.
//!
//! ## wasm ABI version
//!
//! Guest modules import host functions from the module name
//! [`kernel::abi::ABI_MODULE`] (`"gwead1"`) — the version is in-band,
//! and a module built against a different one fails at instantiation
//! rather than misbehaving at runtime.
//!
pub mod domain;
pub mod dsl;
pub mod kernel;
pub mod spi;

// ---------------------------------------------------------------------------
// Dependency re-exports
//
// These crates appear in Gwead's public API signatures — `wasmtime::Engine`
// and `Arc<wasmtime::Module>` around module registration, `indexmap::IndexMap`
// throughout the manifest types, tokio-util's `CancellationToken` on the
// cancellation surface, `bytes::Bytes` and `serde_json::Value` everywhere,
// `futures::stream::BoxStream` behind `ReadableSource`, and tokio's
// `mpsc` / `oneshot` receivers as the pub fields of the dataflow handles.
// Re-exporting them lets embedders and plugin crates name exactly the
// versions the kernel was built against (`gwead::wasmtime::…`) instead of
// pinning their own copies and hitting an incompatible-types error on every
// major bump. The rule: anything that appears in a public signature is
// re-exported here, so the kernel and its embedders bump together.
// ---------------------------------------------------------------------------
pub use bytes;
pub use futures;
pub use indexmap;
pub use serde_json;
pub use tokio;
pub use tokio_util;
pub use wasmtime;

/// Implementation details reachable from Gwead's exported macros.
///
/// Not a public API: contents may change in any release. Naming
/// anything under here directly will break. It exists so
/// [`native_step_impl!`](crate::native_step_impl) expands without
/// requiring the calling crate to depend on `inventory` itself, or to
/// have it in scope under that name.
#[doc(hidden)]
pub mod __private {
    pub use inventory;
}
