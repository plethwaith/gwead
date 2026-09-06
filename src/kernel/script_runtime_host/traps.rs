//! Wasmtime error classification for the script runtime.
//!
//! Every wasmtime call a script-runtime run makes — instantiation,
//! the two `alloc` calls, and `execute` — can fail on a resource cap,
//! and each one goes through [`classify_trap`] with the [`Phase`] it
//! was in. A cap trip comes back as [`ScriptRunError::Cap`], a typed
//! value only the host constructs from what wasmtime and the store's
//! own limiter report, so the dispatch entry (`step_script`) records
//! a `ResourceViolation` from it without reading text, and nothing a
//! guest controls — the text it hands `host_set_error`, or the
//! function and module names its name section puts in a trap's
//! backtrace — can pass for the cap. Anything else — a generic trap,
//! a setup failure, or the guest's own error text — is
//! [`ScriptRunError::Failed`] carrying its text.
//!
//! Fuel is recognised by the typed `OutOfFuel` trap at any phase: in
//! `execute`, in `alloc`, or in the module's `start` function at
//! instantiation. The memory limit is recognised at instantiation
//! only, from the limiter having refused an allocation
//! ([`ResourceBudget::memory_denied`]) together with the error not
//! being a trap: a declared minimum past the cap is refused by the
//! limiter and fails instantiation with a plain error, the one place
//! a memory denial is an error at all. A `memory.grow` past the cap
//! answers `-1` to the guest and never traps, so a denial the
//! limiter recorded during a `start` function that then trapped for
//! its own reasons is a trap, not the cap.
//!
//! [`ResourceBudget::memory_denied`]: crate::kernel::resource_budget::ResourceBudget::memory_denied

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

/// A resource cap a script-runtime run tripped, with the cap's value.
/// Displays as the description a step's failure text and its recorded
/// violation both carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ResourceCap {
    /// The fuel `budget` ran out, in `phase`.
    Fuel { budget: u64, phase: Phase },
    /// The module declared more linear memory than the `bytes` cap
    /// allows, so it did not instantiate.
    Memory { bytes: usize },
}

impl fmt::Display for ResourceCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fuel { budget, phase } => {
                write!(f, "wasm consumed its {budget} unit budget ({phase})")
            }
            Self::Memory { bytes } => {
                write!(
                    f,
                    "wasm linear memory exceeded {bytes} bytes (at instantiate)"
                )
            }
        }
    }
}

/// Why a script-runtime run produced no result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ScriptRunError {
    /// A resource cap tripped. Constructed only by [`classify_trap`],
    /// never from guest text, so a step that sees it has hit the
    /// kernel's limit.
    Cap(ResourceCap),
    /// Anything else: a setup failure, a generic trap, or the guest's
    /// own error text, verbatim.
    Failed(String),
}

impl fmt::Display for ScriptRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cap(cap @ ResourceCap::Fuel { .. }) => write!(f, "FuelExhausted: {cap}"),
            Self::Cap(cap @ ResourceCap::Memory { .. }) => {
                write!(f, "MemoryLimitExceeded: {cap}")
            }
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
/// `memory_denied` is whether the store's limiter has refused an
/// allocation (see the module docs for why that, and not the error's
/// text, is what types the memory cap).
pub(crate) fn classify_trap(
    err: &wasmtime::Error,
    phase: Phase,
    limits: &crate::kernel::RuntimeLimits,
    memory_denied: bool,
) -> ScriptRunError {
    if is_out_of_fuel(err) {
        return ScriptRunError::Cap(ResourceCap::Fuel {
            budget: limits.fuel_budget,
            phase,
        });
    }
    let is_trap = err.downcast_ref::<wasmtime::Trap>().is_some();
    if phase == Phase::Instantiate && memory_denied && !is_trap {
        return ScriptRunError::Cap(ResourceCap::Memory {
            bytes: limits.max_memory_bytes,
        });
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
    ScriptRunError::Failed(match phase {
        Phase::Instantiate => format!("script runtime instantiation failed: {chain}"),
        Phase::Alloc(what) => format!("alloc {what}: {chain}"),
        Phase::Execute => format!("script runtime trapped: {chain}"),
    })
}

#[cfg(test)]
mod tests {
    //! What `classify_trap` makes of each kind of error at each
    //! phase, on hand-built errors rather than a running guest.
    use super::*;
    use crate::kernel::RuntimeLimits;

    const PHASES: [Phase; 4] = [
        Phase::Instantiate,
        Phase::Alloc("source"),
        Phase::Alloc("args"),
        Phase::Execute,
    ];

    fn limits() -> RuntimeLimits {
        RuntimeLimits::default()
            .with_fuel_budget(1_000)
            .with_max_memory_bytes(4_096)
    }

    fn out_of_fuel() -> wasmtime::Error {
        wasmtime::Error::from(wasmtime::Trap::OutOfFuel)
    }

    fn unreachable_trap() -> wasmtime::Error {
        wasmtime::Error::from(wasmtime::Trap::UnreachableCodeReached)
    }

    /// The fuel trap is the fuel cap at every phase, naming the phase
    /// and the budget, whatever the limiter has recorded.
    #[test]
    fn out_of_fuel_is_the_fuel_cap_at_every_phase() {
        for phase in PHASES {
            for denied in [false, true] {
                let got = classify_trap(&out_of_fuel(), phase, &limits(), denied);
                assert_eq!(
                    got,
                    ScriptRunError::Cap(ResourceCap::Fuel {
                        budget: 1_000,
                        phase
                    }),
                    "{phase}, denied = {denied}"
                );
                assert_eq!(
                    got.to_string(),
                    format!("FuelExhausted: wasm consumed its 1000 unit budget ({phase})")
                );
            }
        }
    }

    /// A plain error at instantiation after the limiter refused an
    /// allocation is the memory cap: that is the shape of a declared
    /// minimum past the cap.
    #[test]
    fn a_refused_allocation_that_failed_instantiation_is_the_memory_cap() {
        let err = wasmtime::Error::msg("memory minimum size of 64 pages exceeds memory limits");
        let got = classify_trap(&err, Phase::Instantiate, &limits(), true);
        assert_eq!(
            got,
            ScriptRunError::Cap(ResourceCap::Memory { bytes: 4_096 })
        );
        assert_eq!(
            got.to_string(),
            "MemoryLimitExceeded: wasm linear memory exceeded 4096 bytes (at instantiate)"
        );
    }

    /// The memory cap is typed from the limiter, not from text: an
    /// error whose text says "memory limit" — a trap backtrace prints
    /// whatever names the guest's name section gives its functions —
    /// is a plain failure when the limiter refused nothing, and a
    /// trap is a plain failure even when it did (a `start` function
    /// whose `memory.grow` was answered `-1` and then trapped for its
    /// own reasons).
    #[test]
    fn memory_text_and_traps_are_not_the_memory_cap() {
        let named = wasmtime::Error::msg("wasm trap: unreachable\n  0: memory limit exceeded");
        let got = classify_trap(&named, Phase::Instantiate, &limits(), false);
        assert_eq!(
            got,
            ScriptRunError::Failed(
                "script runtime instantiation failed: wasm trap: unreachable\n  0: memory limit exceeded"
                    .into()
            )
        );

        let got = classify_trap(&unreachable_trap(), Phase::Instantiate, &limits(), true);
        assert!(
            matches!(&got, ScriptRunError::Failed(text)
                if text.starts_with("script runtime instantiation failed: wasm trap: wasm `unreachable`")),
            "{got:?}"
        );
    }

    /// A refused allocation outside instantiation answers `-1` to the
    /// guest and is not an error; a later failure in that run is its
    /// own, whatever the limiter recorded.
    #[test]
    fn a_refused_allocation_types_nothing_after_instantiation() {
        for phase in [Phase::Alloc("source"), Phase::Alloc("args"), Phase::Execute] {
            let err = wasmtime::Error::msg("memory limit");
            let got = classify_trap(&err, phase, &limits(), true);
            assert!(matches!(got, ScriptRunError::Failed(_)), "{phase}: {got:?}");
        }
    }

    /// A generic error is a plain failure named for its phase and
    /// carrying the whole chain, root cause included.
    #[test]
    fn a_generic_error_is_a_failure_named_for_its_phase_with_its_chain() {
        let err = wasmtime::Error::msg("root cause").context("outer");
        let expect = |phase: Phase| match phase {
            Phase::Instantiate => "script runtime instantiation failed: outer | root cause",
            Phase::Alloc("source") => "alloc source: outer | root cause",
            Phase::Alloc(_) => "alloc args: outer | root cause",
            Phase::Execute => "script runtime trapped: outer | root cause",
        };
        for phase in PHASES {
            assert_eq!(
                classify_trap(&err, phase, &limits(), false),
                ScriptRunError::Failed(expect(phase).into()),
                "{phase}"
            );
        }
    }
}
