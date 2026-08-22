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
    use super::{ABI_MODULE, ABI_VERSION};

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
}
