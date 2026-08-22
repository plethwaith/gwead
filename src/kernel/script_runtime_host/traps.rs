//! Wasmtime trap classification for the script runtime.
//!
//! Resource-cap trips (fuel exhaustion, memory limit) get sentinel
//! prefixes so the dispatch entry (`step_script`) can map them onto
//! structured `ResourceViolation` variants. Generic traps (script
//! error, host panic) keep a plain `"script runtime trapped: …"` shape.

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
    // wasmtime surfaces a memory-limiter denial as an error chain whose
    // message contains "memory minimum size of N pages exceeds memory
    // maximum size" or similar. Detect both that and the explicit
    // "exceeds maximum" wording the ResourceLimiter path produces.
    let msg = err.to_string();
    let chain: String = err
        .chain()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(" | ");
    if msg.contains("memory minimum size")
        || chain.contains("memory minimum size")
        || msg.contains("exceeds memory maximum")
        || chain.contains("exceeds memory maximum")
        || msg.contains("memory grow denied")
        || chain.contains("memory grow denied")
    {
        return format!(
            "{SCRIPT_ERR_MEMORY} wasm linear memory exceeded {} bytes",
            limits.max_memory_bytes,
        );
    }
    // Report the whole chain, not just the top-level Display — for a
    // host-import trap the root cause (e.g. a bounds-check rejection)
    // lives at the bottom of the chain, and "error while executing at
    // wasm backtrace" alone is undiagnosable.
    format!("script runtime trapped: {chain}")
}
