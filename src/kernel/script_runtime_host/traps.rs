//! Wasmtime error classification for the script runtime.
//!
//! Every wasmtime call a script-runtime run makes — instantiation,
//! the two `alloc` calls, and `execute` — can trap on a resource cap,
//! and each one goes through [`classify_trap`] with the [`Phase`] it
//! was in. A cap trip comes back as [`ScriptRunError::Cap`], a typed
//! value only the host constructs, so the dispatch entry
//! (`step_script`) records a `ResourceViolation` from it without
//! parsing text, and nothing a guest hands back through
//! `host_set_error` can pass for the cap. Anything else — a generic
//! trap, a setup failure, or the guest's own error text — is
//! [`ScriptRunError::Failed`] carrying its text.
//!
//! Fuel is recognised by the typed trap at any phase: in `execute`,
//! in `alloc`, or in the module's `start` function at instantiation.
//! The memory limit is recognised from the error text, which is the
//! shape the limiter's denial of a declared minimum takes; that
//! denial happens at instantiation, the one place a memory denial is
//! an error at all (a `memory.grow` past the cap answers `-1` to the
//! guest and never traps).

use std::fmt;

/// Which wasmtime call of a script-runtime run an error came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    /// `instantiate_async`, which runs the module's `start` function.
    Instantiate,
    /// The guest's `alloc` export, for the named payload.
    Alloc(&'static str),
    /// The guest's `execute` export.
    Execute,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Instantiate => f.write_str("at instantiate"),
            Self::Alloc(what) => write!(f, "in alloc {what}"),
            Self::Execute => f.write_str("in execute"),
        }
    }
}

/// A resource cap a script-runtime run tripped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ResourceCap {
    /// The fuel budget ran out, in `phase`.
    Fuel { phase: Phase },
    /// The module declared more linear memory than the cap allows.
    Memory,
}

/// Why a script-runtime run produced no result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ScriptRunError {
    /// A resource cap tripped. Constructed only by [`classify_trap`]
    /// from a wasmtime error, never from guest text, so a step that
    /// sees it has hit the kernel's limit.
    Cap { cap: ResourceCap, detail: String },
    /// Anything else: a setup failure, a generic trap, or the guest's
    /// own error text, verbatim.
    Failed(String),
}

impl fmt::Display for ScriptRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cap {
                cap: ResourceCap::Fuel { .. },
                detail,
            } => write!(f, "FuelExhausted: {detail}"),
            Self::Cap {
                cap: ResourceCap::Memory,
                detail,
            } => write!(f, "MemoryLimitExceeded: {detail}"),
            Self::Failed(text) => f.write_str(text),
        }
    }
}

impl From<String> for ScriptRunError {
    fn from(text: String) -> Self {
        Self::Failed(text)
    }
}

/// Whether `err` is wasmtime's out-of-fuel trap, matched on the typed
/// trap rather than its text. Shared with the `wasm` step, whose
/// store runs under the same budget.
pub(crate) fn is_out_of_fuel(err: &wasmtime::Error) -> bool {
    matches!(
        err.downcast_ref::<wasmtime::Trap>(),
        Some(wasmtime::Trap::OutOfFuel)
    )
}

/// Classify the error a wasmtime call returned in `phase`: the fuel
/// cap, the memory cap, or a generic failure named for the phase.
pub(crate) fn classify_trap(
    err: &wasmtime::Error,
    phase: Phase,
    limits: &crate::kernel::RuntimeLimits,
) -> ScriptRunError {
    if is_out_of_fuel(err) {
        return ScriptRunError::Cap {
            cap: ResourceCap::Fuel { phase },
            detail: format!(
                "wasm consumed its {} unit budget ({phase})",
                limits.fuel_budget
            ),
        };
    }
    // Report the whole chain, not just the top-level Display — for a
    // host-import trap the root cause (e.g. a bounds-check rejection)
    // lives at the bottom of the chain, and "error while executing at
    // wasm backtrace" alone is undiagnosable.
    let chain: String = err
        .chain()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(" | ");
    if chain.contains("memory minimum size") || chain.contains("memory limit") {
        return ScriptRunError::Cap {
            cap: ResourceCap::Memory,
            detail: format!(
                "wasm linear memory exceeded {} bytes ({phase})",
                limits.max_memory_bytes
            ),
        };
    }
    ScriptRunError::Failed(match phase {
        Phase::Instantiate => format!("script runtime instantiation failed: {chain}"),
        Phase::Alloc(what) => format!("alloc {what}: {chain}"),
        Phase::Execute => format!("script runtime trapped: {chain}"),
    })
}
