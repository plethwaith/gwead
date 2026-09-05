//! Wasmtime trap classification for the script runtime.
//!
//! Resource-cap trips get sentinel prefixes so the dispatch entry
//! (`step_script`) can map them onto structured `ResourceViolation`
//! variants: fuel exhaustion here, from the execution trap; the memory
//! limit in `run_script_runtime`, from the instantiation error, which
//! is the only place a memory denial is an error. Generic traps
//! (script error, host panic) keep a plain `"script runtime trapped:
//! …"` shape.

/// Sentinel prefixes the caller can match on to distinguish a generic
/// runtime error from a resource-cap trip. These prefixes are the
/// contract `step_script` uses to populate
/// [`super::super::host_api::ResourceViolation`] for the runtime's
/// structured error mapping.
pub(super) const SCRIPT_ERR_FUEL: &str = "FUEL_EXHAUSTED:";
pub(super) const SCRIPT_ERR_MEMORY: &str = "MEMORY_LIMIT:";

/// Inspect a wasmtime trap from `execute_fn.call` and format it with
/// a sentinel prefix when it matches a known resource cap.
pub(super) fn classify_runtime_trap(
    err: &wasmtime::Error,
    limits: &crate::kernel::RuntimeLimits,
) -> String {
    if let Some(trap) = err.downcast_ref::<wasmtime::Trap>()
        && matches!(trap, wasmtime::Trap::OutOfFuel)
    {
        return format!(
            "{SCRIPT_ERR_FUEL} wasm consumed its {} unit budget",
            limits.fuel_budget,
        );
    }
    // No memory-cap arm: the limiter answers a `memory.grow` past the
    // cap with `-1` and no trap, so a denial never reaches an
    // execution error. The one memory denial that is an error — a
    // declared minimum past the cap — happens at instantiation, and
    // `run_script_runtime` classifies that itself.
    let chain: String = err
        .chain()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(" | ");
    // Report the whole chain, not just the top-level Display — for a
    // host-import trap the root cause (e.g. a bounds-check rejection)
    // lives at the bottom of the chain, and "error while executing at
    // wasm backtrace" alone is undiagnosable.
    format!("script runtime trapped: {chain}")
}
