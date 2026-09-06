//! Wasmtime error classification for the script runtime.
//!
//! Every wasmtime call a script-runtime run makes — instantiation,
//! the two `alloc` calls, and `execute` — can fail on a resource cap,
//! and each one goes through [`classify_error`] with the [`Phase`] it
//! was in. A cap trip comes back as [`ScriptRunError::Cap`], a typed
//! value only the host constructs from what wasmtime and the store's
//! own limiter and fuel meter report, so the dispatch entry
//! (`step_script`) records a `ResourceViolation` from it without
//! reading text, and nothing a guest controls — the text it hands
//! `host_set_error`, the function and module names its name section
//! puts in a trap's backtrace, or the errors it can make host imports
//! return — can pass for the cap. Anything else — a generic trap, a
//! setup failure, or the guest's own error text — is
//! [`ScriptRunError::Failed`] carrying its text.
//!
//! Fuel is recognised by the typed `OutOfFuel` trap at any phase: in
//! `execute`, in `alloc`, or in the module's `start` function at
//! instantiation. The memory limit is recognised at instantiation
//! only, from the limiter having refused an allocation before any
//! guest code ran: a declared minimum past the cap is refused by the
//! limiter while the memory is being created, before the `start`
//! function, and fails instantiation with a plain error. The caller
//! establishes "before any guest code ran" from the fuel meter, which
//! still reads the full budget then and never does once `start` has
//! been entered (see `classify_from_store` in the parent module for
//! the wasmtime mechanism that guarantees it). A `start` function can
//! have its own `memory.grow` refused too — answered `-1`, no trap —
//! and then fail in any way it likes, a trap or an error from a host
//! import; the fuel meter says it ran, so that is its own failure and
//! not the cap.

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

impl ResourceCap {
    /// The failure text a step reports for this cap: the description
    /// under the name of the `KernelError` it becomes.
    pub(crate) fn failure_text(&self) -> String {
        match self {
            Self::Fuel { .. } => format!("FuelExhausted: {self}"),
            Self::Memory { .. } => format!("MemoryLimitExceeded: {self}"),
        }
    }
}

impl fmt::Display for ResourceCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fuel { budget, phase } => {
                write!(f, "wasm consumed its {budget} unit budget ({phase})")
            }
            Self::Memory { bytes } => write!(
                f,
                "wasm linear memory exceeded {bytes} bytes ({})",
                Phase::Instantiate
            ),
        }
    }
}

/// Why a script-runtime run produced no result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ScriptRunError {
    /// A resource cap tripped. Constructed only by [`classify_error`],
    /// never from guest text, so a step that sees it has hit the
    /// kernel's limit. `error` is the wasmtime error's chain, kept for
    /// the log: the cap is what the step reports.
    Cap { cap: ResourceCap, error: String },
    /// Anything else: a setup failure, a generic trap, or the guest's
    /// own error text, verbatim.
    Failed(String),
}

impl fmt::Display for ScriptRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cap { cap, .. } => f.write_str(&cap.failure_text()),
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
/// `refused_before_the_guest_ran` is whether the store's limiter
/// refused a memory allocation while no guest instruction had yet
/// run, which is the shape of a declared minimum past the cap and of
/// nothing a guest can do (see the module docs).
pub(crate) fn classify_error(
    err: &wasmtime::Error,
    phase: Phase,
    limits: &crate::kernel::RuntimeLimits,
    refused_before_the_guest_ran: bool,
) -> ScriptRunError {
    // Report the whole chain, not just the top-level Display — for a
    // host-import trap the root cause (e.g. a bounds-check rejection)
    // lives at the bottom of the chain, and "error while executing at
    // wasm backtrace" alone is undiagnosable.
    let chain: String = err
        .chain()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(" | ");
    if is_out_of_fuel(err) {
        return ScriptRunError::Cap {
            cap: ResourceCap::Fuel {
                budget: limits.fuel_budget,
                phase,
            },
            error: chain,
        };
    }
    if phase == Phase::Instantiate && refused_before_the_guest_ran {
        return ScriptRunError::Cap {
            cap: ResourceCap::Memory {
                bytes: limits.max_memory_bytes,
            },
            error: chain,
        };
    }
    ScriptRunError::Failed(match phase {
        Phase::Instantiate => format!("script runtime instantiation failed: {chain}"),
        Phase::Alloc(what) => format!("alloc {what}: {chain}"),
        Phase::Execute => format!("script runtime trapped: {chain}"),
    })
}

#[cfg(test)]
mod tests {
    //! What `classify_error` makes of each kind of error at each
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

    /// The fuel trap is the fuel cap at every phase, naming the phase
    /// and the budget, whatever the limiter has recorded.
    #[test]
    fn out_of_fuel_is_the_fuel_cap_at_every_phase() {
        for phase in PHASES {
            for refused in [false, true] {
                let got = classify_error(&out_of_fuel(), phase, &limits(), refused);
                assert!(
                    matches!(
                        &got,
                        ScriptRunError::Cap {
                            cap: ResourceCap::Fuel { budget: 1_000, phase: p },
                            error,
                        } if *p == phase && error.contains("fuel")
                    ),
                    "{phase}, refused = {refused}: {got:?}"
                );
                assert_eq!(
                    got.to_string(),
                    format!("FuelExhausted: wasm consumed its 1000 unit budget ({phase})")
                );
            }
        }
    }

    /// A plain error at instantiation after the limiter refused an
    /// allocation before the guest ran is the memory cap: that is the
    /// shape of a declared minimum past the cap. The wasmtime error
    /// rides along for the log.
    #[test]
    fn a_refusal_before_the_guest_ran_that_failed_instantiation_is_the_memory_cap() {
        let err = wasmtime::Error::msg("memory minimum size of 64 pages exceeds memory limits");
        let got = classify_error(&err, Phase::Instantiate, &limits(), true);
        assert_eq!(
            got,
            ScriptRunError::Cap {
                cap: ResourceCap::Memory { bytes: 4_096 },
                error: "memory minimum size of 64 pages exceeds memory limits".into(),
            }
        );
        assert_eq!(
            got.to_string(),
            "MemoryLimitExceeded: wasm linear memory exceeded 4096 bytes (at instantiate)"
        );
    }

    /// The memory cap is typed from the limiter and the fuel meter,
    /// not from text: an error whose text says "memory limit" — a
    /// trap backtrace prints whatever names the guest's name section
    /// gives its functions — is a plain failure when nothing was
    /// refused before the guest ran, whatever kind of error it is.
    #[test]
    fn memory_text_without_a_refusal_before_the_guest_ran_is_not_the_memory_cap() {
        for err in [
            wasmtime::Error::msg("wasm trap: unreachable\n  0: memory limit exceeded"),
            wasmtime::Error::from(wasmtime::Trap::UnreachableCodeReached),
            wasmtime::Error::msg("memory minimum size of 64 pages exceeds memory limits"),
        ] {
            let got = classify_error(&err, Phase::Instantiate, &limits(), false);
            assert!(
                matches!(&got, ScriptRunError::Failed(text)
                    if text.starts_with("script runtime instantiation failed: ")),
                "{got:?}"
            );
        }
    }

    /// A refusal outside instantiation answers `-1` to the guest and
    /// is not an error; a later failure in that run is its own,
    /// whatever the caller reports about the limiter.
    #[test]
    fn a_refusal_types_nothing_after_instantiation() {
        for phase in [Phase::Alloc("source"), Phase::Alloc("args"), Phase::Execute] {
            let err = wasmtime::Error::msg("memory limit");
            let got = classify_error(&err, phase, &limits(), true);
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
                classify_error(&err, phase, &limits(), false),
                ScriptRunError::Failed(expect(phase).into()),
                "{phase}"
            );
        }
    }
}
