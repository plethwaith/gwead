//! Wasmtime trap classification for the script runtime.
//!
//! Resource-cap trips get sentinel prefixes so the dispatch entry
//! (`step_script`) can map them onto structured `ResourceViolation`
//! variants. Fuel can run out on either side of instantiation: in
//! `execute`, or in the module's `start` function before `execute` is
//! ever reached, so both the execution trap and the instantiation
//! error are inspected for it. The memory limit is classified from
//! the instantiation error only, which is the one place a memory
//! denial is an error. Generic traps (script error, host panic) keep
//! a plain `"script runtime trapped: …"` shape, and other
//! instantiation errors a plain `"script runtime instantiation
//! failed: …"`.

/// Sentinel prefixes the caller can match on to distinguish a generic
/// runtime error from a resource-cap trip. These prefixes are the
/// contract `step_script` uses to populate
/// [`super::super::host_api::ResourceViolation`] for the runtime's
/// structured error mapping.
pub(super) const SCRIPT_ERR_FUEL: &str = "FUEL_EXHAUSTED:";
pub(super) const SCRIPT_ERR_MEMORY: &str = "MEMORY_LIMIT:";

/// Whether `err` is wasmtime's out-of-fuel trap. Matched on the typed
/// trap rather than its text, so a guest's own error text cannot pass
/// for the cap.
fn is_out_of_fuel(err: &wasmtime::Error) -> bool {
    matches!(
        err.downcast_ref::<wasmtime::Trap>(),
        Some(wasmtime::Trap::OutOfFuel)
    )
}

/// Inspect a wasmtime trap from `execute_fn.call` and format it with
/// a sentinel prefix when it matches a known resource cap.
pub(super) fn classify_runtime_trap(
    err: &wasmtime::Error,
    limits: &crate::kernel::RuntimeLimits,
) -> String {
    if is_out_of_fuel(err) {
        return format!(
            "{SCRIPT_ERR_FUEL} wasm consumed its {} unit budget",
            limits.fuel_budget,
        );
    }
    // No memory-cap arm: the limiter answers a `memory.grow` past the
    // cap with `-1` and no trap, so a denial never reaches an
    // execution error. The one memory denial that is an error — a
    // declared minimum past the cap — happens at instantiation, and
    // `classify_instantiate_error` classifies that.
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

/// Inspect the error from `instantiate_async` and format it with a
/// sentinel prefix when it is a resource cap: the fuel budget consumed
/// by the module's `start` function before `execute` was reached, or
/// a declared minimum memory past the configured cap. Both carry an
/// "(at instantiate)" note so the failure text says which side of
/// instantiation the cap was hit on.
pub(super) fn classify_instantiate_error(
    err: &wasmtime::Error,
    limits: &crate::kernel::RuntimeLimits,
) -> String {
    if is_out_of_fuel(err) {
        return format!(
            "{SCRIPT_ERR_FUEL} wasm consumed its {} unit budget (at instantiate)",
            limits.fuel_budget,
        );
    }
    // The limiter's denial of a declared minimum surfaces as a plain
    // error message, not a typed trap, so this arm matches on text.
    let chain: String = err
        .chain()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(" | ");
    if chain.contains("memory minimum size") || chain.contains("memory limit") {
        return format!(
            "{SCRIPT_ERR_MEMORY} wasm linear memory exceeded {} bytes (at instantiate)",
            limits.max_memory_bytes,
        );
    }
    format!("script runtime instantiation failed: {err}")
}
