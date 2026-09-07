//! Script-runtime host subsystem.
//!
//! The kernel exposes the **script runtime host ABI** — a stable set of
//! wasmtime host imports (`host_set_result`, `host_log`, `host_invoke`,
//! `stream_read/write`, …) that any
//! script-runtime wasm module can target. The wasm module is the
//! *language interpreter* (a Lua interpreter, a JavaScript engine, …).
//! The host imports are intentionally language-agnostic so
//! the kernel never needs to know which language is hosted.
//!
//! Module layout:
//!
//! - `step_script` — the `script` step type dispatch entry
//! - `run_script_runtime` — instantiates a script-runtime wasm module
//!   and runs a script through its `execute` entry point
//! - `store_data` — `ScriptRuntimeStoreData` + [`wasmtime::ResourceLimiter`]
//!   impl + per-call helpers (`bail_host_call`, `truncate_for_log`)
//! - `parent_context` — `ScriptRuntimeParentContext` snapshot the
//!   sub-instance reads via the `io.*` imports
//! - `traps` — `ScriptRunError` (a typed resource-cap trip or a
//!   plain failure) + `classify_error`, applied to every wasmtime
//!   call of a run with the `Phase` it was in and what the store's
//!   limiter and fuel meter say
//! - `imports` — host import registration, organised by area (result,
//!   streams, invoke, call_result).
//!
//! What it does NOT know:
//! - Lua appears in examples because a Lua interpreter is the reference
//!   guest for this ABI. No script runtime ships in this crate —
//!   interpreter modules are registered by embedder plugins — and
//!   swapping the interpreter changes no code here: the imports stay
//!   the same; only the wasm bytes targeting them change.

mod imports;
mod parent_context;
mod store_data;
mod traps;

use std::future::Future;
use std::pin::Pin;

use serde_json::Value;
use wasmtime::{Engine, Module};

use crate::kernel::host_api::{
    ExecutionState, PluginExecution, ResourceViolation, StepError, StepOutput,
};
use crate::kernel::native_impls::IntrinsicStepImplEntry;

pub(crate) use parent_context::ScriptRuntimeParentContext;
use store_data::ScriptRuntimeStoreData;
pub(crate) use traps::is_out_of_fuel;
use traps::{Phase, ResourceCap, ScriptRunError, classify_error};

/// How much fuel a wasm guest burns between forced yields back to the
/// tokio scheduler (`Store::fuel_async_yield_interval`). Applied to
/// both the script-runtime sub-store and the `wasm` step type's store.
/// Without an interval, a CPU-bound guest with no host-import await
/// points holds its worker thread for the entire fuel budget — seconds
/// at the default 1e9 units — during which the cancellation token and
/// wallclock timer on that worker can't even be polled. 100k units is
/// coarse enough to be free (≤0.01% overhead) and fine enough to keep
/// cancellation latency in the tens of microseconds.
pub(crate) const FUEL_ASYNC_YIELD_INTERVAL: u64 = 100_000;

// Submit the `script` intrinsic's impl into the global inventory slice.
// `script` needs engine internals (`script_runtimes` + `engine`), so it's
// a kernel-internal [`IntrinsicStepImplEntry`]: the intrinsics
// manifest references it via `implRef: "gwead.intrinsics.script"` with
// `kind: "intrinsic"`, the kernel resolves it at boot through
// `IntrinsicStepImplTable::discover()`, and the body receives a concrete
// `&mut ExecutionState`.
inventory::submit! {
    IntrinsicStepImplEntry {
        name: "gwead.intrinsics.script",
        impl_: step_script,
    }
}

/// Execute a `script` step — runs the source via a script-runtime
/// wasm module looked up by the step's `language` selector.
///
/// **Dispatch coexistence note.** The `script` step type def carries
/// `selector: "language"`, but its intrinsic impl registered through
/// `intrinsics.json` is selector-less (`matches: None`, which the
/// `kind: "intrinsic"` registration path requires). So the
/// registry holds **two distinct entries** for `script`:
///
/// 1. `(script, None)` → this fn (`step_script`). The intrinsic step
///    body the wasmtime linker invokes for *every* `script` step
///    regardless of language.
/// 2. `(script, Some("lua"))`, `(script, Some("js"))`, … → wasm
///    modules registered by language-runtime plugins. These provide the
///    *interpreter* this fn loads at runtime from the `script_runtimes`
///    map on `ExecutionState`.
///
/// The two paths serve different purposes. The trait-step-type entry
/// is "what runs when you call a `script` step." The language-keyed
/// entries are "what wasm interpreter is available for language X."
/// Any reshaping of dispatch that makes the primary path honor
/// `selector` must keep this coexistence explicit, or the two would
/// silently mismatch.
pub(crate) fn step_script<'a>(
    ex: &'a mut ExecutionState,
    params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move {
        let source = match params.get("source").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => {
                return Err(StepError::Failed(
                    "Script step missing 'source' field".into(),
                ));
            }
        };

        // Selector value for the `script` step type's `language`
        // selector. Registration requires it, so its absence here is a
        // kernel bug, not a manifest one — but the kernel is
        // language-agnostic and has no default to fall back to.
        let Some(language) = params.get("language").and_then(|v| v.as_str()) else {
            return Err(StepError::Failed(
                "Script step missing 'language' field; registration should have refused the manifest"
                    .into(),
            ));
        };
        let language = language.to_string();

        // Look up the pre-resolved runtime. The map was built from the
        // registry at ExecutionState construction time — `step_script`
        // never touches the registry itself, so this works even when the
        // kernel was constructed without `into_arc` (no kernel weak ref
        // available). Tests construct ExecutionState directly with an
        // empty map; those paths skip script dispatch entirely.
        // Kernel-internal fields (`script_runtimes`, `engine`, `kernel`,
        // `resource_violation`) aren't on the public PluginExecution
        // surface — `step_script` is an `IntrinsicStepFn`, so it
        // holds the concrete `&mut ExecutionState` and reaches them
        // directly.
        let runtime_module = ex.script_runtimes.get(&language).cloned().ok_or_else(|| {
            StepError::Failed(format!(
                "no script runtime registered for language '{language}'"
            ))
        })?;

        // `passSecrets` — the step's declared secret allowlist.
        //
        // The args buffer handed to the interpreter is the plugin's
        // full resolution context, and `resolution_context()` puts
        // every secret in it. The interpreter is a wasm module some
        // *other* plugin supplied, so shipping the whole `secrets`
        // namespace by default hands one plugin's credentials to
        // another plugin's code on every script step. The default is
        // an empty allowlist: a script sees `secrets` as `{}` unless
        // the step names the keys it needs.
        //
        // Absent (the common case) and `[]` mean the same thing — no
        // secrets — so the default is the safe one and the reach is
        // visible in the manifest an operator reviews.
        let pass_secrets: Vec<String> = params
            .get("passSecrets")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let engine = ex.engine.clone();
        let mut ctx = ex.resolution_context();
        filter_secrets(&mut ctx, &pass_secrets);
        let args_json = serde_json::to_vec(&ctx).unwrap_or_else(|_| b"{}".to_vec());
        let owner_plugin = ex.plugin_name().to_string();
        let streams_arc = ex.streams().clone();
        let limits = ex.limits();
        let step_id = ex.current_step_id().to_string();
        // If this script step is marked `long_running` in a
        // dataflow action, the scheduler pre-provisioned a writable
        // output for it. Pre-resolve the StreamId once here so the
        // wasm-side `io.stream.output()` is a constant-time lookup. For
        // every other script invocation this stays `None`.
        let dataflow_output = ex.dataflow_outputs().get(&step_id).copied();
        let cancel = ex.cancel_token();
        // Snapshot parent context for the sub-instance's `host_invoke`
        // import (the `io.invoke` a guest runtime wraps it in). Kernel weak ref lets the import dispatch back into
        // the same kernel; the parent's config is the default the
        // orchestrator falls back to when no per-callee override
        // applies, and the parent's secret resolver is what the callee
        // pulls its own credentials through — matching `step_invoke`.
        let parent_ctx = ScriptRuntimeParentContext {
            kernel: ex.kernel.clone(),
            plugin: ex.plugin_name().to_string(),
            config: ex.config().clone(),
            secret_resolver: ex.secret_resolver().cloned(),
            exec_ctx: ex.exec_ctx().clone(),
            invoke_depth: ex.invoke_depth(),
            deadline: ex.wallclock_deadline(),
        };

        tracing::debug!(
            plugin = %owner_plugin,
            step_id = %step_id,
            source_len = source.len(),
            dataflow_output = ?dataflow_output,
            "script step starting"
        );
        let outcome = run_script_runtime(
            &engine,
            &runtime_module,
            &source,
            &args_json,
            &streams_arc,
            &limits,
            dataflow_output,
            cancel,
            parent_ctx,
        )
        .await;

        match outcome.result {
            Ok(result_json) => {
                let val: Value = serde_json::from_str(&result_json).unwrap_or(Value::Null);
                Ok(StepOutput::from(val))
            }
            // A resource cap is typed by the host from the wasmtime
            // error, never from guest text: record it on the
            // ExecutionState marker so the runtime surfaces
            // `KernelError::FuelExhausted` / `MemoryLimitExceeded`
            // rather than a generic `PluginExecution(string)`.
            Err(ScriptRunError::Cap { cap, error }) => {
                ex.resource_violation = Some(match &cap {
                    ResourceCap::Fuel { budget, .. } => ResourceViolation::FuelExhausted {
                        budget: *budget,
                        detail: format!("step '{step_id}': {cap}"),
                    },
                    // wasmtime's text says how much the module
                    // declared, which is what its author needs; the
                    // cap itself is in the error this becomes.
                    ResourceCap::Memory { bytes } => ResourceViolation::MemoryLimit {
                        bytes: *bytes,
                        detail: format!("step '{step_id}': {error}"),
                    },
                });
                tracing::warn!(
                    plugin = %owner_plugin,
                    step_id = %step_id,
                    cap = %cap,
                    error = %error,
                    "Script step hit a resource cap"
                );
                Err(StepError::Failed(format!("{}: {cap}", cap.kind())))
            }
            Err(ScriptRunError::Failed(e)) => {
                // A guest has no typed cancellation of its own. Its
                // binding may raise a language-level error when a host
                // import tells it the step was cancelled —
                // `STREAM_CANCELLED` from a parked `stream_write` or
                // `stream_read`, `is_cancelled` answering 1, or a plain
                // `io.invoke` whose callee stopped on this step's
                // token. An error from a guest
                // that was told is the cancellation surfacing through
                // the guest's error idiom, and is reported as such, so
                // the dataflow scheduler sees a step winding down and
                // the wallclock wrapper sees its deadline rather than a
                // failure carrying the guest's text. The gate is the
                // telling, not the token: a guest that never heard of
                // the cancel and failed for its own reasons keeps its
                // failure, as the wallclock wrapper promises. The text
                // has no other home once the step is recorded as
                // cancelled, so it is logged at info. A resource cap
                // is the arm above, before this: a guest that ignores
                // its cancel until its fuel runs out has still hit the
                // kernel's limit.
                if outcome.told_of_cancel {
                    tracing::info!(
                        plugin = %owner_plugin,
                        step_id = %step_id,
                        error = %e,
                        "Script step failed after being told of its cancellation; reporting cancellation"
                    );
                    return Err(StepError::Cancelled);
                }
                tracing::warn!(
                    plugin = %owner_plugin,
                    step_id = %step_id,
                    error = %e,
                    "Script step failed"
                );
                Err(StepError::Failed(e))
            }
        }
    })
}

/// What a script-runtime run came to, with the one fact about the
/// guest's view that outlives its store: whether a host import told
/// it the step was cancelled (see
/// [`ScriptRuntimeStoreData::told_of_cancel`]).
pub(crate) struct ScriptOutcome {
    /// The result JSON on success; otherwise a resource cap the host
    /// typed, or the failure's text (the guest's own, for an error it
    /// raised).
    pub(crate) result: Result<String, ScriptRunError>,
    pub(crate) told_of_cancel: bool,
}

/// Instantiate a script-runtime wasm module and execute a script.
///
/// `streams` is the parent invocation's shared stream registry. Each
/// `stream_read`/`stream_write`/`stream_close` host import locks
/// per-call rather than holding the registry lock for the whole script
/// execution — that's the property that lets the parent step's caller
/// run another stream op concurrently (e.g. through a host callback
/// triggered from inside the script) without self-deadlocking.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_script_runtime(
    engine: &Engine,
    runtime_module: &Module,
    source: &str,
    args_json: &[u8],
    streams: &crate::kernel::streams::SharedStreamRegistry,
    limits: &crate::kernel::RuntimeLimits,
    dataflow_output: Option<crate::kernel::streams::StreamId>,
    cancel: tokio_util::sync::CancellationToken,
    parent: ScriptRuntimeParentContext,
) -> ScriptOutcome {
    // No store yet, so nothing could have told the guest anything.
    let setup_failed = |err: String| ScriptOutcome {
        result: Err(ScriptRunError::Failed(err)),
        told_of_cancel: false,
    };
    let mut linker = wasmtime::Linker::<ScriptRuntimeStoreData>::new(engine);

    // Async-required WASI linker. Pairs with `call_async`
    // in `execute_in_store` so the sub-store can host `.await`-ing
    // imports (`stream_read` / `stream_write`).
    if let Err(e) = wasmtime_wasi::p1::add_to_linker_async(&mut linker, |data| &mut data.wasi) {
        return setup_failed(format!("WASI linker setup failed: {e}"));
    }
    if let Err(e) = imports::register_all(&mut linker) {
        return setup_failed(e);
    }

    // Create WASI context (sandboxed: no filesystem, no env, no args)
    let wasi_p1 = wasmtime_wasi::WasiCtxBuilder::new().build_p1();
    let store_data = ScriptRuntimeStoreData {
        wasi: wasi_p1,
        result: None,
        error: None,
        streams: streams.clone(),
        budget: crate::kernel::resource_budget::ResourceBudget::new(limits),
        dataflow_output,
        cancel,
        kernel: parent.kernel,
        parent_plugin: parent.plugin,
        parent_config: parent.config,
        parent_secret_resolver: parent.secret_resolver,
        parent_exec_ctx: parent.exec_ctx,
        parent_invoke_depth: parent.invoke_depth,
        parent_deadline: parent.deadline,
        call_result: None,
        call_error: None,
        told_of_cancel: false,
    };
    let mut store = wasmtime::Store::new(engine, store_data);

    let result = execute_in_store(
        &mut store,
        &linker,
        runtime_module,
        source,
        args_json,
        limits,
    )
    .await;
    ScriptOutcome {
        result,
        told_of_cancel: store.data().told_of_cancel,
    }
}

/// Run the guest in `store`: apply the invocation's caps, instantiate
/// `runtime_module`, hand it `source` and `args_json`, call `execute`,
/// and read back what it set. The store outlives the run so the
/// caller can read what the guest was told.
async fn execute_in_store(
    store: &mut wasmtime::Store<ScriptRuntimeStoreData>,
    linker: &wasmtime::Linker<ScriptRuntimeStoreData>,
    runtime_module: &Module,
    source: &str,
    args_json: &[u8],
    limits: &crate::kernel::RuntimeLimits,
) -> Result<String, ScriptRunError> {
    // Apply per-invocation resource caps. The engine itself was
    // constructed with `consume_fuel(true)`, so this just sets the
    // budget for THIS invocation. `limiter` installs the
    // `ResourceLimiter` impl on `ScriptRuntimeStoreData` so `memory.grow`
    // calls are gated by `max_memory`.
    store
        .set_fuel(limits.fuel_budget)
        .map_err(|e| format!("Failed to set fuel budget: {e}"))?;
    // Yield back to tokio every ~100k fuel units. Without this, a
    // CPU-bound guest with no host-import await points pins its tokio
    // worker for the entire fuel budget (seconds at 1e9 units) — and
    // the wallclock/cancellation timers that are supposed to catch it
    // can't get polled on that worker in the meantime.
    store
        .fuel_async_yield_interval(Some(FUEL_ASYNC_YIELD_INTERVAL))
        .map_err(|e| format!("Failed to set fuel yield interval: {e}"))?;
    store.limiter(|data| data as &mut dyn wasmtime::ResourceLimiter);

    // Instantiate. Both resource caps can trip here: a memory limiter
    // denial when the module's declared minimum memory exceeds the
    // configured cap, and fuel exhaustion when the module's `start`
    // function consumes the budget before `execute` is reached. Every
    // wasmtime call from here on is classified the same way, with its
    // phase and what the limiter and the fuel meter say, so a cap is
    // typed wherever it trips.
    let instance = match linker.instantiate_async(&mut *store, runtime_module).await {
        Ok(instance) => instance,
        Err(e) => return Err(classify_from_store(&*store, &e, Phase::Instantiate, limits)),
    };

    // Get the alloc and execute exports
    let alloc_fn = instance
        .get_typed_func::<i32, i32>(&mut *store, "alloc")
        .map_err(|e| format!("No 'alloc' export: {e}"))?;

    let execute_fn = instance
        .get_typed_func::<(i32, i32, i32, i32), i32>(&mut *store, "execute")
        .map_err(|e| format!("No 'execute' export: {e}"))?;

    let memory = instance
        .get_memory(&mut *store, "memory")
        .ok_or_else(|| ScriptRunError::Failed("No 'memory' export".into()))?;

    // Allocate and write source, then args.
    //
    // The guest chooses the offset here — this is the host→guest
    // direction, where the host trusts a value the *guest* returned.
    // Every guest→host import bounds-checks its pointers
    // (`imports::result::read_guest_slice` and friends); this
    // direction needs the same check: a guest whose `alloc` returns
    // -1, a huge offset, or an offset that overflows past the end of
    // linear memory would otherwise panic the host process on the
    // slice index below. There is no `catch_unwind` anywhere in the
    // crate, so that panic would be a host kill, not a failed step.
    // `write_guest_slice` makes it an ordinary step error.
    let source_bytes = source.as_bytes();
    let source_ptr = alloc_fn
        .call_async(&mut *store, source_bytes.len() as i32)
        .await
        .map_err(|e| classify_from_store(&*store, &e, Phase::Alloc("source"), limits))?;
    write_guest_slice(&memory, store, source_ptr, source_bytes, "source")?;

    let args_ptr = alloc_fn
        .call_async(&mut *store, args_json.len() as i32)
        .await
        .map_err(|e| classify_from_store(&*store, &e, Phase::Alloc("args"), limits))?;
    write_guest_slice(&memory, store, args_ptr, args_json, "args")?;

    // Call execute.
    let success = execute_fn
        .call_async(
            &mut *store,
            (
                source_ptr,
                source_bytes.len() as i32,
                args_ptr,
                args_json.len() as i32,
            ),
        )
        .await
        .map_err(|e| classify_from_store(&*store, &e, Phase::Execute, limits))?;

    if success == 1 {
        let result = store.data().result.clone().unwrap_or_else(|| "null".into());
        Ok(result)
    } else {
        let err = store
            .data()
            .error
            .clone()
            .unwrap_or_else(|| "script runtime reported an error with no message".into());
        Err(ScriptRunError::Failed(err))
    }
}

/// [`classify_error`] for a wasmtime error from `store`'s run, with
/// whether its limiter refused a memory allocation before any guest
/// code ran. The fuel meter still reading the whole budget is that
/// "before", by a wasmtime mechanism worth naming, since a wasmtime
/// that dropped it would reopen the gate: instantiation runs a
/// module-startup function wasmtime synthesises (no wasm body of its
/// own), which applies data and element segments and then calls the
/// module's `start`. Memories are created, and a declared minimum
/// past the cap refused, before that function runs, so a refusal
/// there leaves the meter untouched. The call into `start` is
/// hand-written in the Cranelift backend as `module_start`, which
/// charges one unit and saves the counter to the store immediately
/// before the call, so the meter reads below the budget for anything
/// `start` then does, however it fails. That save is load-bearing,
/// because Cranelift does not save the counter at every instruction
/// — only at calls, returns, `unreachable`, and function exit — so a
/// trap from division or a dynamically out-of-bounds load in `start`
/// flushes nothing of `start`'s own spending, and it is
/// `module_start`'s saved unit that the gate sees in that case.
/// Verified against wasmtime 47: `require_startup_func` in
/// `wasmtime-environ`, and `module_start` and `fuel_before_op` in
/// `wasmtime-internal-cranelift`'s `func_environ.rs`.
fn classify_from_store(
    store: &wasmtime::Store<ScriptRuntimeStoreData>,
    err: &wasmtime::Error,
    phase: Phase,
    limits: &crate::kernel::RuntimeLimits,
) -> ScriptRunError {
    let refused_before_the_guest_ran = store.data().budget.memory_denied()
        && store
            .get_fuel()
            .is_ok_and(|left| left == limits.fuel_budget);
    classify_error(err, phase, limits, refused_before_the_guest_ran)
}

/// Run `guest` as the script runtime for plugin `p` under `cancel`,
/// with `kernel` (if any) as the parent the invoke imports recurse
/// into — the caller keeps the `Arc` alive for the run. Shared by the
/// test modules below that drive `run_script_runtime` from a WAT guest.
#[cfg(test)]
async fn run_guest(
    kernel: Option<&std::sync::Arc<crate::kernel::Kernel>>,
    guest: Vec<u8>,
    cancel: tokio_util::sync::CancellationToken,
) -> ScriptOutcome {
    let mut config = wasmtime::Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config).expect("engine");
    let module = Module::new(&engine, &guest).expect("module compiles");
    let parent = ScriptRuntimeParentContext {
        kernel: kernel.map(std::sync::Arc::downgrade),
        plugin: "p".into(),
        config: Value::Null,
        secret_resolver: None,
        exec_ctx: Default::default(),
        invoke_depth: 0,
        deadline: None,
    };
    run_script_runtime(
        &engine,
        &module,
        "",
        b"{}",
        &Default::default(),
        &crate::kernel::RuntimeLimits::default(),
        None,
        cancel,
        parent,
    )
    .await
}

#[cfg(test)]
mod stream_last_error_tests {
    //! What a guest learns of a streaming callee's failure through
    //! `stream_last_error`: the text behind the `STREAM_IO_ERROR` its
    //! `stream_read` returned, or nothing after a clean EOF.
    use super::*;

    type StepFuture<'a> = Pin<
        Box<
            dyn Future<
                    Output = Result<
                        crate::kernel::host_api::StepOutput,
                        crate::kernel::host_api::StepError,
                    >,
                > + Send
                + 'a,
        >,
    >;

    /// Write one chunk to the step's dataflow output, then end as
    /// `params.then` says: `"ok"`, `"fail"` or `"panic"`.
    fn write_then<'a>(
        ex: &'a mut (dyn crate::kernel::host_api::PluginExecution + Send),
        params: &'a Value,
    ) -> StepFuture<'a> {
        Box::pin(async move {
            let writable = ex
                .dataflow_outputs()
                .get(ex.current_step_id())
                .copied()
                .expect("a pre-provisioned writable");
            let n = crate::kernel::streams::write_async_shared(
                ex.streams(),
                writable,
                b"partial",
                &ex.cancel_token(),
            )
            .await;
            assert!(n > 0, "the chunk before the end is accepted");
            match params["then"].as_str() {
                Some("fail") => Err(crate::kernel::host_api::StepError::Failed(
                    "upstream fell over".into(),
                )),
                Some("panic") => panic!("relay body fell over"),
                _ => Ok(crate::kernel::host_api::StepOutput::from(Value::Null)),
            }
        })
    }

    /// A kernel with plugin `p` as the relaying guest's parent, and
    /// three dataflow actions whose one long-running step writes a
    /// chunk and then ends cleanly (`ok`), fails (`fail`), or panics
    /// (`boom`).
    fn kernel_with_p() -> std::sync::Arc<crate::kernel::Kernel> {
        let mut config = crate::kernel::KernelConfig::default();
        config
            .native_step_impls
            .insert("test.p.write_then", write_then)
            .expect("fresh table");
        let mut kernel = crate::kernel::Kernel::boot(config).expect("boot");
        let action = |then: &str| {
            format!(
                r#""dataflow": true,
                   "steps": [{{"id": "produce", "type": "p.write_then",
                              "params": {{"then": "{then}"}}, "longRunning": true}}]"#
            )
        };
        kernel
            .register_plugin_from_json(&format!(
                r#"{{
                    "name": "p",
                    "version": "0.0.0",
                    "stepTypeDefs": [{{"name": "p.write_then", "freelyUsable": true}}],
                    "stepTypeImpls": [{{"stepType": "p.write_then", "kind": "native",
                                       "implRef": "test.p.write_then"}}],
                    "actions": {{
                        "ok": {{{}}},
                        "fail": {{{}}},
                        "boom": {{{}}}
                    }}
                }}"#,
                action("ok"),
                action("fail"),
                action("panic"),
            ))
            .expect("registers");
        kernel.into_arc()
    }

    /// A guest that streams `p.<action>` through `host_invoke_streaming`
    /// and reads it to the end. On `STREAM_IO_ERROR` it sizes the
    /// text with a zero-length `stream_last_error`, fetches it with a
    /// second call, and raises with it — the binding shape the ABI doc
    /// describes. On `STREAM_EOF` it reports `"clean"` if the handle
    /// has no text and `"stale"` if it has; any other code is
    /// `"other"`. A failed invoke raises with the host's call-error
    /// text so the test sees why.
    fn relaying_guest(action: &str) -> Vec<u8> {
        let m = crate::kernel::abi::ABI_MODULE;
        let action_len = action.len();
        let io_error = crate::kernel::streams::STREAM_IO_ERROR;
        let eof = crate::kernel::streams::STREAM_EOF;
        let wat = format!(
            r#"
            (module
              (import "{m}" "host_set_result" (func $host_set_result (param i32 i32)))
              (import "{m}" "host_set_error" (func $host_set_error (param i32 i32)))
              (import "{m}" "host_call_result_size" (func $call_result_size (result i32)))
              (import "{m}" "host_call_result_read"
                (func $call_result_read (param i32 i32) (result i32)))
              (import "{m}" "host_invoke_streaming"
                (func $invoke_streaming (param i32 i32 i32 i32 i32 i32) (result i32)))
              (import "{m}" "stream_read" (func $stream_read (param i32 i32 i32) (result i32)))
              (import "{m}" "stream_last_error"
                (func $stream_last_error (param i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (data (i32.const 8) "\"clean\"")
              (data (i32.const 16) "\"stale\"")
              (data (i32.const 24) "\"other\"")
              (data (i32.const 32) "{{\"plugin\": \"p\"}}")
              (data (i32.const 48) "{action}")
              (data (i32.const 64) "{{}}")
              (global $next (mut i32) (i32.const 128))
              (func (export "alloc") (param $len i32) (result i32)
                (local $ptr i32)
                global.get $next
                local.set $ptr
                global.get $next
                local.get $len
                i32.add
                global.set $next
                local.get $ptr)
              (func (export "execute") (param i32 i32 i32 i32) (result i32)
                (local $h i32)
                (local $rc i32)
                (local $len i32)
                (local.set $h (call $invoke_streaming
                  (i32.const 32) (i32.const 15)
                  (i32.const 48) (i32.const {action_len})
                  (i32.const 64) (i32.const 2)))
                (if (i32.le_s (local.get $h) (i32.const 0))
                  (then
                    (local.set $len (call $call_result_size))
                    (drop (call $call_result_read (i32.const 8192) (local.get $len)))
                    (call $host_set_error (i32.const 8192) (local.get $len))
                    (return (i32.const 0))))
                (block $done
                  (loop $again
                    (local.set $rc
                      (call $stream_read (local.get $h) (i32.const 4096) (i32.const 64)))
                    (br_if $done (i32.lt_s (local.get $rc) (i32.const 0)))
                    (br $again)))
                (if (i32.eq (local.get $rc) (i32.const {io_error}))
                  (then
                    (local.set $len
                      (call $stream_last_error (local.get $h) (i32.const 0) (i32.const 0)))
                    (drop (call $stream_last_error
                      (local.get $h) (i32.const 8192) (local.get $len)))
                    (call $host_set_error (i32.const 8192) (local.get $len))
                    (return (i32.const 0))))
                (if (i32.eq (local.get $rc) (i32.const {eof}))
                  (then
                    (if (i32.eqz
                          (call $stream_last_error (local.get $h) (i32.const 0) (i32.const 0)))
                      (then (call $host_set_result (i32.const 8) (i32.const 7)))
                      (else (call $host_set_result (i32.const 16) (i32.const 7))))
                    (return (i32.const 1))))
                (call $host_set_result (i32.const 24) (i32.const 7))
                (i32.const 1))
            )
            "#
        );
        wat::parse_str(&wat).expect("wat parses")
    }

    /// The relaying guest's result, or its failure's text.
    async fn run_relaying(action: &str) -> Result<String, String> {
        let kernel = kernel_with_p();
        run_guest(
            Some(&kernel),
            relaying_guest(action),
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .result
        .map_err(|e| e.to_string())
    }

    /// A callee that ends cleanly leaves nothing on the handle: the
    /// guest reads to EOF and the probe answers 0.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_guest_finds_no_text_after_a_clean_stream() {
        assert_eq!(run_relaying("ok").await, Ok("\"clean\"".into()));
    }

    /// A callee that fails reaches the guest as `STREAM_IO_ERROR`, and
    /// `stream_last_error` explains it: the guest's own error carries
    /// the callee's name and what went wrong, sized by the probe and
    /// fetched whole.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_guest_finds_a_failed_callees_text() {
        let text = run_relaying("fail")
            .await
            .expect_err("the guest raises with the failure text");
        assert!(
            text.contains("p.fail failed") && text.contains("upstream fell over"),
            "the guest's error carries the callee's failure: {text}"
        );
    }

    /// A guest that streams `p.<action>` until a negative read and
    /// then evaluates `condition` — a WAT `i32` expression with `$h`
    /// bound to the handle, typically around a `stream_last_error`
    /// call — reporting `"as expected"` if it is 1, else raising.
    fn probing_guest(action: &str, condition: &str) -> Vec<u8> {
        let m = crate::kernel::abi::ABI_MODULE;
        let action_len = action.len();
        let wat = format!(
            r#"
            (module
              (import "{m}" "host_set_result" (func $host_set_result (param i32 i32)))
              (import "{m}" "host_set_error" (func $host_set_error (param i32 i32)))
              (import "{m}" "host_invoke_streaming"
                (func $invoke_streaming (param i32 i32 i32 i32 i32 i32) (result i32)))
              (import "{m}" "stream_read" (func $stream_read (param i32 i32 i32) (result i32)))
              (import "{m}" "stream_last_error"
                (func $stream_last_error (param i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (data (i32.const 0) "\"as expected\"")
              (data (i32.const 16) "unexpected code")
              (data (i32.const 32) "{{\"plugin\": \"p\"}}")
              (data (i32.const 48) "{action}")
              (data (i32.const 64) "{{}}")
              (global $next (mut i32) (i32.const 128))
              (func (export "alloc") (param $len i32) (result i32)
                (local $ptr i32)
                global.get $next
                local.set $ptr
                global.get $next
                local.get $len
                i32.add
                global.set $next
                local.get $ptr)
              (func (export "execute") (param i32 i32 i32 i32) (result i32)
                (local $h i32)
                (local.set $h (call $invoke_streaming
                  (i32.const 32) (i32.const 15)
                  (i32.const 48) (i32.const {action_len})
                  (i32.const 64) (i32.const 2)))
                (block $done
                  (loop $again
                    (br_if $done (i32.lt_s
                      (call $stream_read (local.get $h) (i32.const 4096) (i32.const 64))
                      (i32.const 0)))
                    (br $again)))
                (if (result i32) (i32.eq {condition} (i32.const 1))
                  (then (call $host_set_result (i32.const 0) (i32.const 13)) (i32.const 1))
                  (else (call $host_set_error (i32.const 16) (i32.const 15)) (i32.const 0))))
            )
            "#
        );
        wat::parse_str(&wat).expect("wat parses")
    }

    /// The guest's whole buffer range is checked before the handle is
    /// looked up and before any byte is copied, as `stream_read` and
    /// `stream_write` check theirs: a negative
    /// length or a pointer past linear memory is `STREAM_OOB` even on
    /// a handle with nothing recorded, and a bad handle is
    /// `STREAM_INVALID_HANDLE` — never a 0 that reads as "no text".
    #[tokio::test(flavor = "multi_thread")]
    async fn a_probe_with_a_bad_buffer_or_handle_is_refused() {
        use crate::kernel::streams::{STREAM_INVALID_HANDLE, STREAM_OOB};
        let cases = [
            (
                "negative length",
                "(local.get $h) (i32.const 0) (i32.const -1)",
                STREAM_OOB,
            ),
            (
                "pointer past memory",
                "(local.get $h) (i32.const 70000) (i32.const 16)",
                STREAM_OOB,
            ),
            (
                "length past memory",
                "(local.get $h) (i32.const 65530) (i32.const 16)",
                STREAM_OOB,
            ),
            (
                "zero handle",
                "(i32.const 0) (i32.const 0) (i32.const 0)",
                STREAM_INVALID_HANDLE,
            ),
            (
                "unknown handle",
                "(i32.const 99) (i32.const 0) (i32.const 0)",
                STREAM_INVALID_HANDLE,
            ),
            (
                "in-range probe on a clean handle",
                "(local.get $h) (i32.const 0) (i32.const 0)",
                0,
            ),
        ];
        for (name, args, expected) in cases {
            let kernel = kernel_with_p();
            let condition =
                format!("(i32.eq (call $stream_last_error {args}) (i32.const {expected}))");
            let outcome = run_guest(
                Some(&kernel),
                probing_guest("ok", &condition),
                tokio_util::sync::CancellationToken::new(),
            )
            .await;
            assert_eq!(
                outcome.result,
                Ok("\"as expected\"".into()),
                "{name}: expected {expected}"
            );
        }
    }

    /// The convention the ABI doc contrasts with `host_call_result_read`:
    /// a buffer smaller than the text gets only what fits, and the
    /// call still answers the text's full length — so the guest can
    /// come back with a bigger buffer — and writes nothing past the
    /// buffer it was given.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_copy_into_a_small_buffer_answers_the_full_length_and_stays_inside_it() {
        let full = run_relaying("fail")
            .await
            .expect_err("the failing callee's text, fetched whole");
        assert!(full.len() > 4, "{full:?}");
        // Four bytes of the text at 8192; a sentinel planted in the
        // byte after must survive, and the answer must be the whole
        // length, not 4.
        let condition = format!(
            "(block (result i32) \
               (i32.store8 (i32.const 8196) (i32.const 170)) \
               (i32.and \
                 (i32.eq (call $stream_last_error (local.get $h) (i32.const 8192) (i32.const 4)) \
                         (i32.const {})) \
                 (i32.eq (i32.load8_u (i32.const 8196)) (i32.const 170))))",
            full.len()
        );
        let kernel = kernel_with_p();
        let outcome = run_guest(
            Some(&kernel),
            probing_guest("fail", &condition),
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
        assert_eq!(outcome.result, Ok("\"as expected\"".into()));
    }

    /// A callee whose body panics reaches the guest the same way,
    /// with the panic in the text rather than a clean EOF.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_guest_finds_a_panicking_callees_text() {
        let text = run_relaying("boom")
            .await
            .expect_err("the guest raises with the panic text");
        assert!(
            text.contains("p.boom failed")
                && text.contains("panicked")
                && text.contains("relay body fell over"),
            "the guest's error carries the callee's panic: {text}"
        );
    }
}

#[cfg(test)]
mod told_of_cancel_tests {
    //! The gate on reading a guest's error as its cancellation is
    //! whether a host import told the guest about the cancel, not
    //! whether the token has fired.
    use super::*;

    /// A guest that asks `is_cancelled` and raises if the answer is 1,
    /// or raises unasked when `ask` is false.
    fn raising_guest(ask: bool) -> Vec<u8> {
        let m = crate::kernel::abi::ABI_MODULE;
        let decide = if ask {
            "(call $is_cancelled)"
        } else {
            "(i32.const 1)"
        };
        let wat = format!(
            r#"
            (module
              (import "{m}" "host_set_result" (func $host_set_result (param i32 i32)))
              (import "{m}" "host_set_error" (func $host_set_error (param i32 i32)))
              (import "{m}" "is_cancelled" (func $is_cancelled (result i32)))
              (memory (export "memory") 1)
              (data (i32.const 0) "null")
              (data (i32.const 8) "guest raised")
              (global $next (mut i32) (i32.const 32))
              (func (export "alloc") (param $len i32) (result i32)
                (local $ptr i32)
                global.get $next
                local.set $ptr
                global.get $next
                local.get $len
                i32.add
                global.set $next
                local.get $ptr)
              (func (export "execute") (param i32 i32 i32 i32) (result i32)
                (if (result i32) {decide}
                  (then (call $host_set_error (i32.const 8) (i32.const 12)) (i32.const 0))
                  (else (call $host_set_result (i32.const 0) (i32.const 4)) (i32.const 1))))
            )
            "#
        );
        wat::parse_str(&wat).expect("wat parses")
    }

    async fn run(guest: Vec<u8>, cancel: tokio_util::sync::CancellationToken) -> ScriptOutcome {
        run_guest(None, guest, cancel).await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_guest_told_by_is_cancelled_that_raises_was_told() {
        let cancel = tokio_util::sync::CancellationToken::new();
        cancel.cancel();
        let outcome = run(raising_guest(true), cancel).await;
        assert_eq!(
            outcome.result,
            Err(ScriptRunError::Failed("guest raised".into()))
        );
        assert!(outcome.told_of_cancel);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_guest_that_asked_under_a_quiet_token_was_not_told() {
        let outcome = run(
            raising_guest(true),
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
        assert_eq!(outcome.result, Ok("null".into()));
        assert!(!outcome.told_of_cancel);
    }

    /// The token has fired, but nothing told the guest: its error is
    /// its own, and `step_script` must keep it a failure.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_guest_that_raises_unasked_under_a_fired_token_was_not_told() {
        let cancel = tokio_util::sync::CancellationToken::new();
        cancel.cancel();
        let outcome = run(raising_guest(false), cancel).await;
        assert_eq!(
            outcome.result,
            Err(ScriptRunError::Failed("guest raised".into()))
        );
        assert!(!outcome.told_of_cancel);
    }

    /// A guest that invokes `p.<action>` on its own plugin through
    /// `host_invoke` and, if the invoke fails, raises with the host's
    /// call-error text — read back through the call-result protocol
    /// — so a test sees why.
    fn invoking_guest(action: &str) -> Vec<u8> {
        let m = crate::kernel::abi::ABI_MODULE;
        let action_len = action.len();
        let wat = format!(
            r#"
            (module
              (import "{m}" "host_set_result" (func $host_set_result (param i32 i32)))
              (import "{m}" "host_set_error" (func $host_set_error (param i32 i32)))
              (import "{m}" "host_call_result_size" (func $call_result_size (result i32)))
              (import "{m}" "host_call_result_read"
                (func $call_result_read (param i32 i32) (result i32)))
              (import "{m}" "host_invoke"
                (func $host_invoke (param i32 i32 i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (data (i32.const 0) "null")
              (data (i32.const 24) "{{\"plugin\": \"p\"}}")
              (data (i32.const 40) "{action}")
              (data (i32.const 60) "{{}}")
              (global $next (mut i32) (i32.const 64))
              (func (export "alloc") (param $len i32) (result i32)
                (local $ptr i32)
                global.get $next
                local.set $ptr
                global.get $next
                local.get $len
                i32.add
                global.set $next
                local.get $ptr)
              (func (export "execute") (param i32 i32 i32 i32) (result i32)
                (local $len i32)
                (if (result i32)
                  (i32.eqz (call $host_invoke
                    (i32.const 24) (i32.const 15)
                    (i32.const 40) (i32.const {action_len})
                    (i32.const 60) (i32.const 2)))
                  (then
                    (local.set $len (call $call_result_size))
                    (drop (call $call_result_read (i32.const 4096) (local.get $len)))
                    (call $host_set_error (i32.const 4096) (local.get $len))
                    (i32.const 0))
                  (else (call $host_set_result (i32.const 0) (i32.const 4)) (i32.const 1))))
            )
            "#
        );
        wat::parse_str(&wat).expect("wat parses")
    }

    /// A step body that sleeps `params.ms` (default two seconds)
    /// without racing the token.
    fn sleep_ignoring_token<'a>(
        _ex: &'a mut (dyn crate::kernel::host_api::PluginExecution + Send),
        params: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
        let ms = params["ms"].as_u64().unwrap_or(2000);
        Box::pin(async move {
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
            Ok(StepOutput::from(Value::Null))
        })
    }

    /// A kernel with plugin `p` as the invoking guest's parent: its
    /// one-step action `a`; `slow`, whose own 50 ms wallclock cap ends
    /// a two-second sleep; and `stall`, a dataflow action whose one
    /// long-running step holds its writable open, writes nothing,
    /// ignores the token, and ends after 300 ms — the scheduler does
    /// not abort step tasks on cancel, so the stream stays open and
    /// quiet for the whole 300 ms whatever the token does.
    fn kernel_with_p() -> std::sync::Arc<crate::kernel::Kernel> {
        let mut config = crate::kernel::KernelConfig::default();
        config
            .native_step_impls
            .insert("test.p.sleep", sleep_ignoring_token)
            .expect("fresh table");
        let mut kernel = crate::kernel::Kernel::boot(config).expect("boot");
        kernel
            .register_plugin_from_json(
                r#"{
                    "name": "p",
                    "version": "0.0.0",
                    "stepTypeDefs": [{"name": "p.sleep", "freelyUsable": true}],
                    "stepTypeImpls": [{"stepType": "p.sleep", "kind": "native",
                                       "implRef": "test.p.sleep"}],
                    "actions": {
                        "a": {"steps": [{"id": "v", "type": "let", "params": {"value": 1}}]},
                        "slow": {
                            "wallclockTimeoutMs": 50,
                            "steps": [{"id": "s", "type": "p.sleep", "params": {}}]
                        },
                        "stall": {
                            "dataflow": true,
                            "steps": [{"id": "hold", "type": "p.sleep",
                                       "params": {"ms": 300}, "longRunning": true}]
                        }
                    }
                }"#,
            )
            .expect("registers");
        kernel.into_arc()
    }

    async fn run_invoking(
        action: &str,
        cancel: tokio_util::sync::CancellationToken,
    ) -> ScriptOutcome {
        let kernel = kernel_with_p();
        run_guest(Some(&kernel), invoking_guest(action), cancel).await
    }

    /// The callee runs under a child of the step's token, so a fired
    /// token stops it as a cancellation, and the failed invoke is the
    /// guest being told of its own cancel.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_guest_whose_invoke_was_cancelled_under_its_token_was_told() {
        let cancel = tokio_util::sync::CancellationToken::new();
        cancel.cancel();
        let outcome = run_invoking("a", cancel).await;
        let text = outcome
            .result
            .expect_err("the cancelled invoke fails the guest")
            .to_string();
        assert!(text.starts_with("io.invoke → p.a failed"), "{text}");
        assert!(outcome.told_of_cancel, "{text}");
    }

    /// An invoke that fails for its own reasons tells the guest
    /// nothing about a cancel, fired token or not.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_guest_whose_invoke_failed_for_its_own_reasons_was_not_told() {
        for fired in [false, true] {
            let cancel = tokio_util::sync::CancellationToken::new();
            if fired {
                cancel.cancel();
            }
            let outcome = run_invoking("missing", cancel).await;
            let text = outcome
                .result
                .expect_err("the invoke of a missing action fails")
                .to_string();
            assert!(
                text.starts_with("io.invoke → p.missing failed"),
                "the error arm was reached; fired = {fired}: {text}"
            );
            assert!(!outcome.told_of_cancel, "fired = {fired}: {text}");
        }
    }

    /// A callee that hit its own, shorter cap under a quiet parent
    /// token has failed for its own reasons, however cancellation-
    /// shaped the error: the guard on the token is what keeps it from
    /// counting as a telling.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_guest_whose_callee_hit_its_own_deadline_under_a_quiet_token_was_not_told() {
        let outcome = run_invoking("slow", tokio_util::sync::CancellationToken::new()).await;
        let text = outcome
            .result
            .expect_err("the callee's deadline fails the invoke")
            .to_string();
        assert!(
            text.starts_with("io.invoke → p.slow failed") && text.contains("wallclock"),
            "{text}"
        );
        assert!(!outcome.told_of_cancel, "{text}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_guest_whose_invoke_succeeded_was_not_told() {
        let outcome = run_invoking("a", tokio_util::sync::CancellationToken::new()).await;
        assert_eq!(outcome.result, Ok("null".into()));
        assert!(!outcome.told_of_cancel);
    }

    /// A guest that streams `p.<action>` through `host_invoke_streaming`
    /// and reads it to a negative code: `STREAM_EOF` reports the
    /// result `"eof"`; any other negative code — the binding shape
    /// #17 describes — raises with `"stream read failed"`. A failed
    /// invoke raises with the host's call-error text, as
    /// `relaying_guest` in `stream_last_error_tests` does.
    fn streaming_guest(action: &str) -> Vec<u8> {
        let m = crate::kernel::abi::ABI_MODULE;
        let action_len = action.len();
        let eof = crate::kernel::streams::STREAM_EOF;
        let wat = format!(
            r#"
            (module
              (import "{m}" "host_set_result" (func $host_set_result (param i32 i32)))
              (import "{m}" "host_set_error" (func $host_set_error (param i32 i32)))
              (import "{m}" "host_call_result_size" (func $call_result_size (result i32)))
              (import "{m}" "host_call_result_read"
                (func $call_result_read (param i32 i32) (result i32)))
              (import "{m}" "host_invoke_streaming"
                (func $invoke_streaming (param i32 i32 i32 i32 i32 i32) (result i32)))
              (import "{m}" "stream_read" (func $stream_read (param i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (data (i32.const 8) "\"eof\"")
              (data (i32.const 32) "stream read failed")
              (data (i32.const 64) "{{\"plugin\": \"p\"}}")
              (data (i32.const 96) "{action}")
              (data (i32.const 112) "{{}}")
              (global $next (mut i32) (i32.const 128))
              (func (export "alloc") (param $len i32) (result i32)
                (local $ptr i32)
                global.get $next
                local.set $ptr
                global.get $next
                local.get $len
                i32.add
                global.set $next
                local.get $ptr)
              (func (export "execute") (param i32 i32 i32 i32) (result i32)
                (local $h i32)
                (local $rc i32)
                (local $len i32)
                (local.set $h (call $invoke_streaming
                  (i32.const 64) (i32.const 15)
                  (i32.const 96) (i32.const {action_len})
                  (i32.const 112) (i32.const 2)))
                (if (i32.le_s (local.get $h) (i32.const 0))
                  (then
                    (local.set $len (call $call_result_size))
                    (drop (call $call_result_read (i32.const 8192) (local.get $len)))
                    (call $host_set_error (i32.const 8192) (local.get $len))
                    (return (i32.const 0))))
                (block $done
                  (loop $again
                    (local.set $rc
                      (call $stream_read (local.get $h) (i32.const 4096) (i32.const 64)))
                    (br_if $done (i32.lt_s (local.get $rc) (i32.const 0)))
                    (br $again)))
                (if (i32.eq (local.get $rc) (i32.const {eof}))
                  (then
                    (call $host_set_result (i32.const 8) (i32.const 5))
                    (return (i32.const 1))))
                (call $host_set_error (i32.const 32) (i32.const 18))
                (i32.const 0))
            )
            "#
        );
        wat::parse_str(&wat).expect("wat parses")
    }

    async fn run_streaming(
        action: &str,
        cancel: tokio_util::sync::CancellationToken,
    ) -> ScriptOutcome {
        let kernel = kernel_with_p();
        run_guest(Some(&kernel), streaming_guest(action), cancel).await
    }

    /// A streaming callee stopped by the step's own token, parked
    /// mid-read: the token fires while the guest is inside
    /// `stream_read`, the read is released as `STREAM_CANCELLED`, and
    /// that release is a telling. The guest raises, and the host
    /// reports the cancellation rather than the guest's text — well
    /// under the callee's 300 ms hold, since it is the token that
    /// released the read, not the callee's own end.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_guest_whose_streaming_callees_read_was_released_mid_read_was_told() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let firing = {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                cancel.cancel();
            })
        };
        let started = std::time::Instant::now();
        let outcome = run_streaming("stall", cancel).await;
        firing.await.unwrap();
        assert_eq!(
            outcome.result,
            Err(ScriptRunError::Failed("stream read failed".into()))
        );
        assert!(outcome.told_of_cancel);
        assert!(
            started.elapsed() < std::time::Duration::from_millis(300),
            "the token released the read; the callee's own end did not: {:?}",
            started.elapsed()
        );
    }

    /// Same as above, but the token has already fired before the
    /// guest's first read: deterministic because `stall` ignores the
    /// token, so the source is open and quiet when the guest's first
    /// read parks.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_guest_whose_streaming_callees_read_was_released_before_its_first_read_was_told() {
        let cancel = tokio_util::sync::CancellationToken::new();
        cancel.cancel();
        let outcome = run_streaming("stall", cancel).await;
        assert_eq!(
            outcome.result,
            Err(ScriptRunError::Failed("stream read failed".into()))
        );
        assert!(outcome.told_of_cancel);
    }

    /// A streaming callee that ends under a token that never fires
    /// reaches the guest as a plain `STREAM_EOF`: nothing told it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_guest_whose_streaming_callee_ended_under_a_quiet_token_was_not_told() {
        let outcome = run_streaming("stall", tokio_util::sync::CancellationToken::new()).await;
        assert_eq!(outcome.result, Ok("\"eof\"".into()));
        assert!(!outcome.told_of_cancel);
    }
}

#[cfg(test)]
mod step_script_tests {
    //! How `step_script` reads a guest that did not succeed: the
    //! cancellation when a host import told the guest of the cancel,
    //! the guest's own failure when nothing did, and a resource cap
    //! before either.
    use super::*;
    use crate::kernel::host_api::{ExecutionStateParams, ResourceViolation};

    /// A guest whose `execute` is `body`, with `is_cancelled`,
    /// `host_set_result`, and `host_set_error` in reach.
    fn guest(body: &str) -> Vec<u8> {
        guest_starting("", body)
    }

    /// [`guest`], with `fields` — any module fields, placed after
    /// `execute`: a function and a `(start …)` naming it, a `data`
    /// segment, a `table`, or nothing.
    fn guest_starting(fields: &str, body: &str) -> Vec<u8> {
        let m = crate::kernel::abi::ABI_MODULE;
        let wat = format!(
            r#"
            (module
              (import "{m}" "host_set_result" (func $host_set_result (param i32 i32)))
              (import "{m}" "host_set_error" (func $host_set_error (param i32 i32)))
              (import "{m}" "is_cancelled" (func $is_cancelled (result i32)))
              (memory (export "memory") 1)
              (data (i32.const 0) "null")
              (data (i32.const 8) "guest raised")
              (global $next (mut i32) (i32.const 32))
              (func (export "alloc") (param $len i32) (result i32)
                (local $ptr i32)
                global.get $next
                local.set $ptr
                global.get $next
                local.get $len
                i32.add
                global.set $next
                local.get $ptr)
              (func (export "execute") (param i32 i32 i32 i32) (result i32)
                {body})
              {fields}
            )
            "#
        );
        wat::parse_str(&wat).expect("wat parses")
    }

    const RAISE: &str = "(call $host_set_error (i32.const 8) (i32.const 12)) (i32.const 0)";

    /// An execution state whose `(script, "lua")` runtime is `guest`,
    /// under `cancel` and `limits`.
    fn state(
        guest: Vec<u8>,
        cancel: tokio_util::sync::CancellationToken,
        limits: crate::kernel::RuntimeLimits,
    ) -> ExecutionState {
        let engine = Engine::new(wasmtime::Config::new().consume_fuel(true)).expect("engine");
        let module = Module::new(&engine, guest).expect("module compiles");
        let mut runtimes = std::collections::HashMap::new();
        runtimes.insert("lua".to_string(), std::sync::Arc::new(module));
        ExecutionState::new(ExecutionStateParams {
            plugin_name: "p".to_string(),
            step_type_access: Default::default(),
            action: serde_json::from_value(serde_json::json!({ "steps": [] })).unwrap(),
            input: Value::Null,
            config: Value::Null,
            secrets: Value::Null,
            secret_resolver: None,
            script_runtimes: std::sync::Arc::new(runtimes),
            engine,
            exec_ctx: Default::default(),
            streams: None,
            invoke_depth: 0,
            dispatch_depth: 0,
            kernel: None,
            trigger: None,
            limits,
            deadline: None,
            cancel: Some(cancel),
            dataflow_events: None,
        })
    }

    fn fired() -> tokio_util::sync::CancellationToken {
        let cancel = tokio_util::sync::CancellationToken::new();
        cancel.cancel();
        cancel
    }

    async fn run(state: &mut ExecutionState) -> Result<StepOutput, StepError> {
        let params = serde_json::json!({ "language": "lua", "source": "" });
        step_script(state, &params).await
    }

    /// The token has fired, but no host import told the guest: the
    /// error it raised is its own, and stays a failure carrying its
    /// text. The gate is the telling, not the token.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_untold_guest_that_raises_under_a_fired_token_keeps_its_failure() {
        let mut state = state(guest(RAISE), fired(), Default::default());
        let result = run(&mut state).await;
        assert!(
            matches!(&result, Err(StepError::Failed(text)) if text == "guest raised"),
            "{result:?}"
        );
        assert!(state.resource_violation.is_none());
    }

    /// The same raise from a guest `is_cancelled` had told: the
    /// cancellation.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_told_guest_that_raises_is_cancelled() {
        let body = format!("(drop (call $is_cancelled)) {RAISE}");
        let mut state = state(guest(&body), fired(), Default::default());
        let result = run(&mut state).await;
        assert!(matches!(result, Err(StepError::Cancelled)), "{result:?}");
    }

    /// A guest that was told and then spins until its fuel runs out
    /// has hit the kernel's limit; the resource cap is mapped before
    /// the telling is consulted.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_told_guest_that_exhausts_its_fuel_reports_the_fuel_cap() {
        let body = "(drop (call $is_cancelled)) (loop $spin (br $spin)) (unreachable)";
        let limits = crate::kernel::RuntimeLimits {
            fuel_budget: 1_000_000,
            ..Default::default()
        };
        let mut state = state(guest(body), fired(), limits);
        let result = run(&mut state).await;
        assert!(
            matches!(&result, Err(StepError::Failed(text)) if text.starts_with("FuelExhausted")),
            "{result:?}"
        );
        assert!(matches!(
            state.resource_violation,
            Some(ResourceViolation::FuelExhausted {
                budget: 1_000_000,
                ..
            })
        ));
    }

    /// Run `guest` under a 1M budget and require the fuel cap, typed
    /// in the failure text and recorded on the state, with `phase`
    /// saying where it was hit.
    async fn assert_fuel_cap(guest: Vec<u8>, phase: &str) {
        let limits = crate::kernel::RuntimeLimits {
            fuel_budget: 1_000_000,
            ..Default::default()
        };
        let mut state = state(guest, tokio_util::sync::CancellationToken::new(), limits);
        let result = run(&mut state).await;
        let expected = format!("FuelExhausted: wasm consumed its 1000000 unit budget ({phase})");
        assert!(
            matches!(&result, Err(StepError::Failed(text)) if *text == expected),
            "{result:?}"
        );
        assert!(
            matches!(
                &state.resource_violation,
                Some(ResourceViolation::FuelExhausted { budget: 1_000_000, detail })
                    if detail.ends_with(&format!("({phase})"))
            ),
            "{:?}",
            state.resource_violation
        );
    }

    /// A guest whose `start` function spins runs out of fuel before
    /// `execute` is reached. That is the same cap as an execute-time
    /// trip, and is reported and recorded as one, with the failure
    /// text saying it was hit at instantiation.
    #[tokio::test(flavor = "multi_thread")]
    async fn fuel_exhausted_at_instantiation_reports_the_fuel_cap() {
        let start = "(func $init (loop $spin (br $spin))) (start $init)";
        assert_fuel_cap(guest_starting(start, "(i32.const 1)"), "at instantiate").await;
    }

    /// The same for a guest whose `alloc` spins: the cap is typed
    /// between instantiation and `execute` too.
    #[tokio::test(flavor = "multi_thread")]
    async fn fuel_exhausted_in_alloc_reports_the_fuel_cap() {
        let m = crate::kernel::abi::ABI_MODULE;
        let wat = format!(
            r#"
            (module
              (import "{m}" "host_set_error" (func $host_set_error (param i32 i32)))
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32)
                (loop $spin (br $spin)) (i32.const 0))
              (func (export "execute") (param i32 i32 i32 i32) (result i32)
                (i32.const 1))
            )
            "#
        );
        let guest = wat::parse_str(&wat).expect("wat parses");
        assert_fuel_cap(guest, "in alloc source").await;
    }

    /// A guest that raises text shaped like the host's fuel or memory
    /// failure has raised its own error: the cap is typed from the
    /// wasmtime trap, never from guest text, so nothing is recorded
    /// and the step fails with the guest's text as given.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_guest_cannot_forge_a_resource_cap_through_its_error_text() {
        for forged in ["FuelExhausted: forged", "MemoryLimitExceeded: forged"] {
            // Placed past anything the guest's bump allocator hands the
            // host for source and args, so the text survives the copy.
            let body = format!(
                "(call $host_set_error (i32.const 8192) (i32.const {})) (i32.const 0)",
                forged.len()
            );
            let guest = guest_starting(&format!(r#"(data (i32.const 8192) "{forged}")"#), &body);
            let mut state = state(
                guest,
                tokio_util::sync::CancellationToken::new(),
                Default::default(),
            );
            let result = run(&mut state).await;
            assert!(
                matches!(&result, Err(StepError::Failed(text)) if text == forged),
                "{result:?}"
            );
            assert!(
                state.resource_violation.is_none(),
                "{:?}",
                state.resource_violation
            );
        }
    }

    /// A guest declaring more linear memory than the cap allows does
    /// not instantiate, and that is the typed memory cap: the failure
    /// text names it, and the recorded violation carries the cap and
    /// a detail with wasmtime's own text, which says how much the
    /// module declared.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_declared_minimum_past_the_cap_reports_the_memory_cap() {
        const CAP: usize = 1024 * 1024;
        let wat = r#"
            (module
              (memory (export "memory") 64)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "execute") (param i32 i32 i32 i32) (result i32) (i32.const 1))
            )
        "#;
        let guest = wat::parse_str(wat).expect("wat parses");
        let limits = crate::kernel::RuntimeLimits::default().with_max_memory_bytes(CAP);
        let mut state = state(guest, tokio_util::sync::CancellationToken::new(), limits);
        let result = run(&mut state).await;
        assert!(
            matches!(&result, Err(StepError::Failed(text))
                if text == "MemoryLimitExceeded: wasm linear memory exceeded 1048576 bytes (at instantiate)"),
            "{result:?}"
        );
        assert!(
            matches!(&state.resource_violation,
                Some(ResourceViolation::MemoryLimit { bytes: CAP, detail })
                    if detail == "step '': memory minimum size of 64 pages exceeds memory limits"),
            "{:?}",
            state.resource_violation
        );
    }

    /// A refused `memory.grow` sets the limiter's flag without a
    /// declared-minimum refusal. A `start` function that has its own
    /// grow refused and then fails — through a host import returning
    /// an error, or a trap — has run instructions to do so, and is
    /// reported as its own failure; so is `execute` doing the same.
    /// The memory cap needs the refusal to come before any guest
    /// instruction ran, which only a declared minimum does.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_guest_cannot_forge_the_memory_cap_with_a_refused_grow() {
        // 2048 pages past a one-page memory is 128 MiB, over the
        // default 64 MiB cap but under wasm32's own ceiling, so the
        // limiter is asked and refuses.
        const GROW: &str = "(drop (memory.grow (i32.const 2048)))";
        // A negative pointer, which the host import rejects.
        const HOST_ERROR: &str = "(call $host_set_error (i32.const -1) (i32.const 1))";
        let cases = [
            (
                "start, host error",
                guest_starting(
                    &format!("(func $init {GROW} {HOST_ERROR}) (start $init)"),
                    "(i32.const 1)",
                ),
                "script runtime instantiation failed:",
            ),
            (
                "start, trap",
                guest_starting(
                    &format!("(func $init {GROW} unreachable) (start $init)"),
                    "(i32.const 1)",
                ),
                "script runtime instantiation failed:",
            ),
            // Division by zero traps without Cranelift saving the fuel
            // counter first, unlike `unreachable` and a call. The gate
            // still sees the startup function's own spending.
            (
                "start, non-flushing trap",
                guest_starting(
                    &format!(
                        "(func $init {GROW} (drop (i32.div_s (i32.const 1) (i32.const 0)))) \
                         (start $init)"
                    ),
                    "(i32.const 1)",
                ),
                "script runtime instantiation failed:",
            ),
            (
                "execute, host error",
                guest(&format!("{GROW} {HOST_ERROR} (i32.const 1)")),
                "script runtime trapped:",
            ),
            // The same non-flushing trap in a module with no data
            // segments, so nothing but `module_start`'s one saved unit
            // separates the meter from the budget.
            (
                "start, non-flushing trap, no data segments",
                wat::parse_str(format!(
                    r#"
                    (module
                      (memory (export "memory") 1)
                      (func (export "alloc") (param i32) (result i32) (i32.const 0))
                      (func (export "execute") (param i32 i32 i32 i32) (result i32)
                        (i32.const 1))
                      (func $init {GROW} (drop (i32.div_s (i32.const 1) (i32.const 0))))
                      (start $init)
                    )
                    "#
                ))
                .expect("wat parses"),
                "script runtime instantiation failed:",
            ),
        ];
        for (name, guest, prefix) in cases {
            let mut state = state(
                guest,
                tokio_util::sync::CancellationToken::new(),
                Default::default(),
            );
            let result = run(&mut state).await;
            assert!(
                matches!(&result, Err(StepError::Failed(text)) if text.starts_with(prefix)),
                "{name}: {result:?}"
            );
            assert!(
                state.resource_violation.is_none(),
                "{name}: {:?}",
                state.resource_violation
            );
        }
    }

    /// An instantiation that fails before any guest code runs, but
    /// with no memory refused — an import the host does not provide,
    /// or a table declared past the table cap — leaves the fuel meter
    /// full and is a plain failure: both halves of the memory-cap
    /// gate are needed.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_instantiation_failure_without_a_refusal_is_a_plain_failure() {
        let m = crate::kernel::abi::ABI_MODULE;
        let missing_import = format!(
            r#"
            (module
              (import "{m}" "no_such_import" (func $missing))
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "execute") (param i32 i32 i32 i32) (result i32)
                (call $missing) (i32.const 1))
            )
            "#
        );
        let cases = [
            (
                "missing import",
                wat::parse_str(&missing_import).expect("wat parses"),
                "unknown import",
            ),
            (
                "table past the cap",
                guest_starting("(table 64 funcref)", "(i32.const 1)"),
                "table",
            ),
        ];
        for (name, guest, mentions) in cases {
            let limits = crate::kernel::RuntimeLimits::default().with_max_table_elements(16);
            let mut state = state(guest, tokio_util::sync::CancellationToken::new(), limits);
            let result = run(&mut state).await;
            assert!(
                matches!(&result, Err(StepError::Failed(text))
                    if text.starts_with("script runtime instantiation failed:")
                        && text.contains(mentions)),
                "{name}: {result:?}"
            );
            assert!(
                state.resource_violation.is_none(),
                "{name}: {:?}",
                state.resource_violation
            );
        }
    }

    /// A trap's backtrace prints the function names the guest's name
    /// section chose. A guest that names the function it traps in
    /// after the limiter's own error text, and traps there from
    /// `execute` or from `start`, has still just trapped: the memory
    /// cap is typed from the limiter's refusal, never from text.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_guest_cannot_forge_a_resource_cap_through_its_name_section() {
        for name in ["memory limit", "memory minimum size"] {
            let func = format!(r#"(func $"{name}" unreachable)"#);
            let from_execute = guest_starting(&func, &format!(r#"(call $"{name}") (i32.const 1)"#));
            let from_start =
                guest_starting(&format!(r#"{func} (start $"{name}")"#), "(i32.const 1)");
            for (guest, prefix) in [
                (from_execute, "script runtime trapped:"),
                (from_start, "script runtime instantiation failed:"),
            ] {
                let mut state = state(
                    guest,
                    tokio_util::sync::CancellationToken::new(),
                    Default::default(),
                );
                let result = run(&mut state).await;
                assert!(
                    matches!(&result, Err(StepError::Failed(text))
                        if text.starts_with(prefix) && text.contains(name)),
                    "{name}: {result:?}"
                );
                assert!(
                    state.resource_violation.is_none(),
                    "{name}: {:?}",
                    state.resource_violation
                );
            }
        }
    }
}

/// Narrow a resolution context's `secrets` object down to `allowed`.
///
/// Keys not named are removed; an empty allowlist leaves an empty
/// object rather than removing the namespace, so a script's
/// `args.secrets.foo` reads as absent instead of erroring on a missing
/// parent. Names in `allowed` that the plugin has no secret for are
/// simply not present — the allowlist grants reach, it does not
/// conjure values.
fn filter_secrets(ctx: &mut Value, allowed: &[String]) {
    let Some(obj) = ctx.as_object_mut() else {
        return;
    };
    let Some(secrets) = obj.get_mut("secrets") else {
        return;
    };
    let kept = match secrets.as_object() {
        Some(map) => allowed
            .iter()
            .filter_map(|k| map.get(k).map(|v| (k.clone(), v.clone())))
            .collect(),
        None => serde_json::Map::new(),
    };
    *secrets = Value::Object(kept);
}

/// Copy `payload` into the guest's linear memory at the offset the
/// guest's own `alloc` returned, after checking that the whole
/// destination range is actually inside that memory.
///
/// A guest is free to return anything from `alloc`, including a
/// negative value or an offset near `i32::MAX`. Indexing
/// `memory.data_mut()` with an unchecked range is a host panic, and
/// nothing in this crate catches unwinds — so this returns a `String`
/// error, which surfaces as a failed step, instead.
///
/// Also the host→guest copy behind an import that hands the guest
/// bytes at a pointer the guest passed (`stream_last_error`); `store`
/// is then the import's `Caller`.
pub(super) fn write_guest_slice<C: wasmtime::AsContextMut>(
    memory: &wasmtime::Memory,
    store: &mut C,
    ptr: i32,
    payload: &[u8],
    what: &str,
) -> Result<(), String> {
    let data = memory.data_mut(&mut *store);
    let start = usize::try_from(ptr)
        .map_err(|_| format!("guest alloc returned a negative {what} pointer ({ptr})"))?;
    let end = start
        .checked_add(payload.len())
        .ok_or_else(|| format!("guest {what} pointer {ptr} + length overflows"))?;
    if end > data.len() {
        return Err(format!(
            "guest alloc returned an out-of-bounds {what} pointer: \
             {start}..{end} exceeds linear memory of {} bytes",
            data.len()
        ));
    }
    data[start..end].copy_from_slice(payload);
    Ok(())
}

#[cfg(test)]
mod abi_alignment_tests {
    //! ABI-alignment guard for the script runtime host imports.
    //!
    //! The mock at `tests/common/script_runtime_mock.rs` and every real
    //! script-runtime wasm module import the host symbols that
    //! [`imports::register_all`] registers. If a function name or
    //! signature drifts on either side, the wasm load fails at
    //! instantiation with a misleading "linker import not found"
    //! error.
    //!
    //! These tests pin the import names that any script runtime is
    //! entitled to call. They live next to `imports::register_all` so
    //! a rename refactor touches the test in the same diff.
    //!
    //! Adding a new import: add the name to `EXPECTED_HOST_IMPORTS`
    //! and to `imports/mod.rs::register_all`. CI catches the drift if
    //! one of the two is forgotten.
    //!
    //! Removing an import is an ABI break: every runtime wasm built
    //! against it must be rebuilt, and this test failing is the signal.
    use super::*;
    use wasmtime::{Engine, Linker};

    /// Every host symbol the kernel's script runtime ABI exposes.
    /// Sorted alphabetically so a stale entry shows up as a clear diff
    /// rather than as a hard-to-spot insertion in the middle of the
    /// list.
    const EXPECTED_HOST_IMPORTS: &[&str] = &[
        "host_call_result_read",
        "host_call_result_size",
        "host_invoke",
        "host_invoke_streaming",
        "host_log",
        "host_set_error",
        "host_set_result",
        "is_cancelled",
        "stream_close",
        "stream_last_error",
        "stream_output",
        "stream_read",
        "stream_write",
    ];

    /// Build a linker, call `register_all`, and hold the result against
    /// [`EXPECTED_HOST_IMPORTS`] two ways: (1) enumerate the linker's
    /// ACTUAL registered set via `Linker::iter` and require exact
    /// equality — an import added to `register_all` without updating
    /// the list (or vice versa) fails here; (2) instantiate a module
    /// that imports every name with its ABI-documented signature —
    /// a signature change in any `imports/*.rs` registration fails
    /// instantiation. Both checks consult the real linker; neither can
    /// pass by comparing the test's own constants to themselves.
    #[tokio::test(flavor = "multi_thread")]
    async fn register_all_binds_expected_host_imports() {
        // wasmtime supports async unconditionally (`Config::async_support`
        // is a deprecated no-op), so the engine accepts async imports
        // without an explicit Config flag.
        let engine = Engine::default();
        let mut linker = Linker::<store_data::ScriptRuntimeStoreData>::new(&engine);
        // Run the same registration path `run_script_runtime` runs.
        imports::register_all(&mut linker).expect("register_all binds imports cleanly");

        let store_data = store_data::ScriptRuntimeStoreData {
            wasi: wasmtime_wasi::WasiCtxBuilder::new().build_p1(),
            result: None,
            error: None,
            streams: std::sync::Arc::new(std::sync::Mutex::new(
                crate::kernel::streams::StreamRegistry::new(),
            )),
            budget: crate::kernel::resource_budget::ResourceBudget::new(
                &crate::kernel::RuntimeLimits::default(),
            ),
            dataflow_output: None,
            cancel: tokio_util::sync::CancellationToken::new(),
            kernel: None,
            parent_plugin: "abi_test".to_string(),
            parent_config: serde_json::Value::Null,
            parent_secret_resolver: None,
            parent_exec_ctx: crate::kernel::exec_context::ExecutionContext::default(),
            parent_invoke_depth: 0,
            parent_deadline: None,
            call_result: None,
            call_error: None,
            told_of_cancel: false,
        };
        let mut store = wasmtime::Store::new(&engine, store_data);

        // Check 1: the linker's actual registered name set.
        let mut registered: Vec<String> = linker
            .iter(&mut store)
            .filter(|(module, _, _)| *module == crate::kernel::abi::ABI_MODULE)
            .map(|(_, name, _)| name.to_string())
            .collect();
        registered.sort();
        registered.dedup();
        assert_eq!(
            registered,
            EXPECTED_HOST_IMPORTS
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
            "if this diff is non-empty, `register_all` and the expected \
             ABI list disagree — update both the list AND every runtime \
             wasm that targets this ABI"
        );

        // Build a minimal wat that imports every name + an exported
        // `_start` so wasmtime treats it as valid. Each import's
        // signature here matches the registration in
        // `imports/{result,streams,invoke,call_result}.rs` —
        // mismatched signatures fail at linker.instantiate.
        //
        // The module name comes from `ABI_MODULE` rather than being
        // spelled out, so an ABI-version bump that misses a
        // registration site fails check 1 above instead of leaving this
        // WAT pinned to a name nothing registers under any more.
        let m = crate::kernel::abi::ABI_MODULE;
        let wat = format!(
            r#"
            (module
              (import "{m}" "host_set_result" (func (param i32 i32)))
              (import "{m}" "host_set_error"  (func (param i32 i32)))
              (import "{m}" "host_log"        (func (param i32 i32 i32)))
              (import "{m}" "stream_read"     (func (param i32 i32 i32) (result i32)))
              (import "{m}" "stream_write"    (func (param i32 i32 i32) (result i32)))
              (import "{m}" "stream_close"    (func (param i32) (result i32)))
              (import "{m}" "stream_last_error" (func (param i32 i32 i32) (result i32)))
              (import "{m}" "stream_output"   (func (result i32)))
              (import "{m}" "is_cancelled"    (func (result i32)))
              (import "{m}" "host_invoke"
                (func (param i32 i32 i32 i32 i32 i32) (result i32)))
              (import "{m}" "host_invoke_streaming"
                (func (param i32 i32 i32 i32 i32 i32) (result i32)))
              (import "{m}" "host_call_result_size"
                (func (result i32)))
              (import "{m}" "host_call_result_read"
                (func (param i32 i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "_start")))
        "#
        );
        let wasm = wat::parse_str(&wat).expect("wat parses");
        let module = wasmtime::Module::new(&engine, &wasm).expect("module compiles");
        // Check 2: instantiation resolves every import against the
        // real registrations, so a signature drift in any
        // `imports/*.rs` file fails here even though the names match.
        linker.instantiate_async(&mut store, &module).await.expect(
            "instantiation binds every ABI import with its documented \
                 signature — a failure here means a host import's \
                 registration signature drifted from the WAT above",
        );
    }

    /// STREAMS_ABI.md is the contract third-party guest authors build
    /// against, so it has to name the same module and the same imports
    /// the linker actually registers. Without this the ABI-alignment
    /// test above can be updated in isolation and the published
    /// contract would drift from the code.
    #[test]
    fn streams_abi_doc_matches_registered_imports() {
        let doc = include_str!("../STREAMS_ABI.md");

        assert!(
            doc.contains(crate::kernel::abi::ABI_MODULE),
            "STREAMS_ABI.md never names the import module `{}` guests \
             must link against",
            crate::kernel::abi::ABI_MODULE
        );

        // The import inventory lives in one fenced `text` block under
        // the host-functions heading; each line is `name(args) -> ret`.
        let block = doc
            .split("## Host functions")
            .nth(1)
            .and_then(|s| s.split("```text").nth(1))
            .and_then(|s| s.split("```").next())
            .expect("STREAMS_ABI.md has a ```text import block under `## Host functions`");

        let mut documented: Vec<&str> = block
            .lines()
            .filter_map(|l| l.trim().split('(').next())
            .filter(|n| !n.is_empty())
            .collect();
        documented.sort_unstable();
        documented.dedup();

        assert_eq!(
            documented, EXPECTED_HOST_IMPORTS,
            "STREAMS_ABI.md's import list and the registered ABI \
             disagree — a host import was added or removed on one side \
             only"
        );
    }
}
