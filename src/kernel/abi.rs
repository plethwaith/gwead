//! The wasm ABI version — in-band, machine-checkable.
//!
//! Guest modules reach the host through wasm imports. The module name
//! those imports carry **is** the ABI version handshake: a module
//! compiled against ABI 1 imports from [`ABI_MODULE`] (`"gwead1"`), and
//! a kernel that speaks a different ABI registers a different module
//! name, so the mismatch surfaces as a deterministic
//! `unknown import` failure at instantiation rather than as a trap or a
//! silent misbehaviour partway through execution.
//!
//! This is the only version signal the wasm layer has.
//! `formatVersion` on the plugin manifest does not cover it: the
//! manifest carries wasm modules as opaque base64, so a format-1
//! manifest can carry a module compiled against any ABI.
//!
//! ## Scope
//!
//! One namespace covers both guest→host ABIs, and they version
//! together:
//!
//! - the **script-runtime ABI** — `host_set_result`, `host_log`,
//!   `stream_read`, `host_invoke`, … — documented in full in
//!   `src/kernel/STREAMS_ABI.md`;
//! - the **wasm step-type ABI** — `step_success`, `begin_foreach`,
//!   `next_foreach`, `end_foreach`, `begin_repeat`, plus one import
//!   per registered step type.
//!
//! They run on separate stores with separate linkers and never mix, but
//! a guest author sees one "which Gwead ABI am I building against"
//! question, and one answer is easier to get right than two. A future
//! ABI 2 bumps both.
//!
//! ## Evolution
//!
//! Until Gwead 1.0 the import set and return-code contract may change
//! in breaking ways between pre-1.0 releases without a version bump;
//! runtime wasm modules must be rebuilt against the kernel version that
//! hosts them (see `STREAMS_ABI.md`). The rule below is the one that
//! applies from 1.0 on.
//!
//! Adding an import to an existing ABI version is backward compatible —
//! old modules simply don't import it. **Removing** an import, changing
//! a signature, or changing the meaning of a return code requires a new
//! [`ABI_VERSION`] and a new [`ABI_MODULE`]. Because the module name is
//! part of the guest's compiled bytes, a kernel can register `gwead1`
//! and `gwead2` shims side by side and run a mixed fleet through one
//! migration, which is the property the bare `"gwead"` name could never
//! provide.
//!
//! ## Wasm features
//!
//! Every engine the kernel builds enables exactly the WebAssembly
//! features below, and no others. A module that uses any other feature
//! fails to compile when its plugin is registered. The list is part of
//! the guest ABI: it changes only on purpose, in a minor release, and
//! the release notes say so. It began as the core-wasm features wasmtime
//! 48 enables by default. The component model is not enabled: Gwead
//! loads core modules only.
//!
//! Names are wasmparser's feature names; a few (`floats`, `gc_types`,
//! `call_indirect_overlong`, `bulk_memory_opt`) are parts of a proposal
//! rather than proposals.
//!
//! - `mutable_global`: mutable globals, imported and exported
//! - `saturating_float_to_int`: the saturating `trunc_sat` conversions
//! - `sign_extension`: `i32.extend8_s` and the other sign-extension operators
//! - `reference_types`: several tables, and `table.get`, `table.set`, `table.grow` and `table.fill`
//! - `call_indirect_overlong`: over-long encodings of `call_indirect`'s table index
//! - `multi_value`: functions and blocks with several results
//! - `bulk_memory`: `memory.init`, `data.drop`, `table.init`, `table.copy`, `elem.drop`, and passive segments
//! - `bulk_memory_opt`: `memory.copy` and `memory.fill`
//! - `simd`: 128-bit `v128` vector operations
//! - `relaxed_simd`: the relaxed SIMD operations
//! - `threads`: shared memories and atomic operations
//! - `tail_call`: `return_call`, `return_call_indirect`, `return_call_ref`
//! - `floats`: floating-point types and operations
//! - `multi_memory`: more than one memory in a module
//! - `exceptions`: tags, `throw`, `throw_ref`, and `try_table` with `catch` clauses
//! - `memory64`: 64-bit memories and tables, indexed by `i64`
//! - `extended_const`: `i32.add`, `i32.sub`, `i32.mul` and their `i64` forms in constant expressions
//! - `function_references`: typed function references, `call_ref`, `ref.as_non_null`, `br_on_null`
//! - `gc`: struct and array types and their operations, `i31`, and `ref.cast`
//! - `gc_types`: the garbage-collected reference types, such as `externref` and `anyref`
//!
//! ## Fuel
//!
//! Each guest run (a `script` interpreter run or a `wasm` step) gets
//! [`RuntimeLimits::fuel_budget`](crate::kernel::RuntimeLimits::fuel_budget)
//! units of fuel, and running out fails the step. What an operation
//! costs is defined by wasmtime, not by Gwead, and is approximate: most
//! instructions cost one unit and a few cost none. Costs may shift
//! between Gwead minor releases, and a wasmtime security fix in a patch
//! release can correct an undercount, as 48.0.3 did for `call_ref` and
//! caught exceptions. Size a budget with headroom; do not rely on exact
//! counts.
//!
//! Bulk operations (`memory.copy`, `memory.fill`, `memory.init`,
//! `table.copy`, `table.fill`, `table.init`, `table.grow`, and the GC
//! proposal's array operations) are charged one unit per byte or element
//! they ask for, before they run. One that asks for more than the fuel
//! left ends in fuel exhaustion, even where it would otherwise have
//! trapped out of bounds or, for `table.grow`, returned `-1`.
//! `memory.grow` is not charged by the number of pages it asks for; a
//! grow past the memory cap returns `-1`.
//!
//! Instantiation can consume fuel too: the module's `start` function,
//! and wasmtime's initialisation of its globals, tables and data
//! segments.

/// The current wasm ABI version.
///
/// Paired with [`ABI_MODULE`], which is `"gwead"` with this number
/// appended. Bump both together — see the module docs for what
/// requires a bump.
pub const ABI_VERSION: u32 = 1;

/// The wasm import module name every Gwead host function is registered
/// under, for the ABI version this kernel speaks.
///
/// Guest modules must import from this exact name:
///
/// ```wat
/// (import "gwead1" "host_set_result" (func (param i32 i32)))
/// ```
///
/// A module importing any other module name fails at instantiation
/// with an unknown-import error naming the module it asked for, which
/// is the intended diagnostic for an ABI mismatch.
pub const ABI_MODULE: &str = "gwead1";

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{ABI_MODULE, ABI_VERSION};
    use crate::kernel::runtime::WasmRuntime;

    /// The module name and the version number are two encodings of one
    /// fact; a bump that touches only one of them ships a kernel whose
    /// self-description disagrees with what guests actually link
    /// against.
    #[test]
    fn abi_module_name_encodes_the_abi_version() {
        assert_eq!(ABI_MODULE, format!("gwead{ABI_VERSION}"));
    }

    /// The whole point of the versioned namespace is that the
    /// unversioned name is not what guests link against. Were the name
    /// ever unversioned, every ABI change would be a flag-day rebuild.
    #[test]
    fn abi_module_name_is_versioned() {
        assert_ne!(ABI_MODULE, "gwead");
    }

    /// The "Wasm features" section of the module docs is the guest ABI's
    /// feature list. Its bullets are compared with the features the
    /// production engine reports as enabled (`WasmRuntime::new`'s engine,
    /// through `Config`'s `Debug` output, one `wasm_<name>: <bool>` pair
    /// per wasmparser flag), so neither the documentation nor
    /// `WASM_FEATURES` nor the mask in `engine_config` can change without
    /// the other. An unparsable `Debug` format yields an empty set, which
    /// cannot equal the documented list.
    #[test]
    fn the_engine_enables_exactly_the_documented_wasm_features() {
        let runtime = WasmRuntime::new().expect("runtime constructs");
        let debug = format!("{:?}", runtime.engine().config());
        let enabled: BTreeSet<String> = debug
            .trim_start_matches("Config { ")
            .split(", ")
            .filter_map(|pair| pair.split_once(": "))
            .filter(|(key, value)| key.starts_with("wasm_") && *value == "true")
            .map(|(key, _)| key.trim_start_matches("wasm_").to_string())
            .collect();

        let source = include_str!("abi.rs");
        let start = source
            .find("\n//! ## Wasm features\n")
            .expect("the Wasm features section exists");
        let section = &source[start + 1..];
        let end = section.find("\n//! ## ").unwrap_or(section.len());
        let documented: BTreeSet<String> = section[..end]
            .lines()
            .filter_map(|line| line.strip_prefix("//! - `"))
            .filter_map(|rest| rest.split_once("`:"))
            .map(|(name, _)| name.to_string())
            .collect();

        let only_in_engine: Vec<_> = enabled.difference(&documented).collect();
        let only_in_docs: Vec<_> = documented.difference(&enabled).collect();
        assert!(
            !documented.is_empty() && only_in_engine.is_empty() && only_in_docs.is_empty(),
            "the engine and the abi docs disagree: enabled but undocumented \
             {only_in_engine:?}; documented but not enabled {only_in_docs:?}"
        );
    }
}
