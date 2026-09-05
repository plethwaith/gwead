//! Sub-store state for the script runtime instance.
//!
//! Every script-runtime wasm instance runs against a `Store<ScriptRuntimeStoreData>`.
//! The struct carries:
//! - WASI context (sandboxed: no filesystem, no env, no args)
//! - Result / error slots the wasm side writes via `host_set_result` /
//!   `host_set_error`
//! - A shared stream registry handle (for `stream_read` / `stream_write` /
//!   `stream_close`)
//! - The dataflow output id (for `io.stream.output` if the step is
//!   `long_running` in a dataflow action — `None` otherwise)
//! - A cancellation token (for `is_cancelled`)
//! - Snapshotted parent-action context (`kernel`, `parent_*`) so the
//!   `host_invoke` import (the `io.invoke` a guest runtime wraps it in)
//!   recurses into the same kernel with the same scope / depth a
//!   DAG-level step would
//! - A single-slot stash (`call_result` / `call_error`) the
//!   three-import call protocol writes to and the wasm side drains via
//!   `host_call_result_size` / `host_call_result_read`

use serde_json::Value;

/// Store data for a script-runtime wasm sub-instance.
///
/// `streams` is the parent invocation's shared stream registry. The
/// sub-instance's `stream_read`/`stream_write` host imports are
/// registered with `func_wrap_async` and route through
/// [`crate::kernel::streams::read_async_shared`] /
/// [`crate::kernel::streams::write_async_shared`] — direct `.await` with
/// no `block_in_place`, no `block_on`, and no registry-wide mutex held
/// across the await. That's the property that lets streaming-dataflow
/// consumers scale past tokio's blocking-thread cap. `stream_close`
/// is metadata-only and stays sync.
pub(super) struct ScriptRuntimeStoreData {
    pub(super) wasi: wasmtime_wasi::p1::WasiP1Ctx,
    pub(super) result: Option<String>,
    pub(super) error: Option<String>,
    pub(super) streams: crate::kernel::streams::SharedStreamRegistry,
    /// Store-wide memory / table / object-count budget backing the
    /// [`wasmtime::ResourceLimiter`] impl. Built from
    /// [`crate::kernel::RuntimeLimits`]; see
    /// [`crate::kernel::resource_budget`] for why the accounting is
    /// store-wide rather than per-object.
    pub(super) budget: crate::kernel::resource_budget::ResourceBudget,
    /// Pre-resolved writable handle for `io.stream.output()`.
    /// `Some` only when the script step is marked `long_running` in a
    /// dataflow action — the parent
    /// [`ExecutionState::dataflow_outputs`] lookup happens once at sub-
    /// instance construction. `None` makes the wasm-side helper return
    /// `STREAM_INVALID_HANDLE`.
    pub(super) dataflow_output: Option<crate::kernel::streams::StreamId>,
    /// Cancellation token observable via `io.cancelled()`.
    /// Cloned from [`ExecutionState::cancel`]; always present, defaults to
    /// a never-cancelled token for invocations without a real
    /// cancellation surface.
    pub(super) cancel: tokio_util::sync::CancellationToken,
    /// Whether a host import has told the guest its step was
    /// cancelled. Exactly three imports set it: `is_cancelled`
    /// answering 1, a `stream_write` returning `STREAM_CANCELLED`, and
    /// `host_invoke` failing because the callee stopped on this step's
    /// fired token. A callee's own deadline under a quiet token is the
    /// callee's failure and sets nothing; under a fired token it is
    /// counted as a telling, the deadline being the same event seen
    /// one level down. A streaming callee stopped by the token reaches
    /// the guest through `stream_read`, as EOF or as an error item at
    /// the end of an inherited budget; neither is a telling, so
    /// `host_invoke_streaming` and `stream_read` never set it. A guest
    /// has no typed cancellation
    /// of its own, so `step_script` reads a script error from a guest
    /// that was told as the cancellation surfacing through the guest's
    /// error idiom — and only then; a guest that was never told keeps
    /// its own failure.
    pub(super) told_of_cancel: bool,
    // ── Recurse-into-kernel support ─────────────────────────────
    //
    // Snapshotted from the parent action's `ExecutionState` at sub-instance
    // construction. The `host_invoke` import (the `io.invoke` a guest
    // runtime wraps it in) calls back into the kernel using these, so the callee sees the same depth
    // tracking, scope, and resolver path a DAG-level `invoke` step
    // would. `None` for tests that boot a kernel without a self-Arc;
    // the imports then return an error rather than silently no-op.
    pub(super) kernel: Option<std::sync::Weak<crate::kernel::Kernel>>,
    /// Plugin that owns the script step. Passed to the dispatch
    /// orchestrator from `io.invoke` so app-shaped orchestrators can
    /// scope selection by caller identity.
    pub(super) parent_plugin: String,
    pub(super) parent_config: Value,
    /// Resolver the parent invocation tree pulls credentials through,
    /// handed on to whatever `io.invoke` dispatches.
    pub(super) parent_secret_resolver:
        Option<std::sync::Arc<dyn crate::kernel::secrets::SecretResolver>>,
    pub(super) parent_exec_ctx: crate::kernel::exec_context::ExecutionContext,
    pub(super) parent_invoke_depth: u32,
    /// The parent invocation's wallclock deadline (`None` when
    /// uncapped); bounds whatever `io.invoke` dispatches.
    pub(super) parent_deadline: Option<tokio::time::Instant>,
    /// Scratch slot for `io.invoke` result JSON. The
    /// wasm-side wrapper calls the host import (which writes here), then
    /// a follow-up `host_call_result_size` / `host_call_result_read` pair
    /// pulls the bytes into wasm-owned memory. Single slot → only one
    /// pending call at a time per script step; that matches the
    /// blocking semantics scripts execute under (a script step's body
    /// executes sequentially even across `.await` points on host imports).
    ///
    /// `Vec<u8>` over `String` because the contents are JSON-encoded
    /// bytes the wasm wrapper feeds into a UTF-8-tolerant deserialise —
    /// there's no in-host text indexing that would benefit from
    /// `String`'s invariant.
    pub(super) call_result: Option<Vec<u8>>,
    pub(super) call_error: Option<Vec<u8>>,
}

crate::kernel::resource_budget::impl_budget_limiter!(ScriptRuntimeStoreData, budget);

/// Stash an error message onto [`ScriptRuntimeStoreData::call_error`] and
/// return the failure status code in one expression, so a host import
/// can `return bail_host_call(…)` inline instead of repeating the
/// assign-and-return ladder. The fn takes
/// `&mut Caller` so the caller can `return bail(...)` inline without
/// the borrow-checker complaining about a re-borrow further down.
pub(super) fn bail_host_call(
    caller: &mut wasmtime::Caller<'_, ScriptRuntimeStoreData>,
    msg: impl Into<String>,
) -> i32 {
    let bytes: String = msg.into();
    caller.data_mut().call_error = Some(bytes.into_bytes());
    0
}

/// Render a JSON value as a short preview for `tracing` events. Used by
/// the io.* host-call debug logs to keep MB-scale results
/// out of the log file when an operator enables
/// `gwead::script_runtime=debug`. Truncates the JSON representation to
/// ~200 chars with an ellipsis suffix.
pub(super) fn truncate_for_log(value: &Value) -> String {
    const MAX: usize = 200;
    let s = value.to_string();
    if s.len() <= MAX {
        s
    } else {
        let cut = s
            .char_indices()
            .take_while(|(i, _)| *i < MAX)
            .last()
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);
        format!("{}… ({} bytes total)", &s[..cut], s.len())
    }
}
