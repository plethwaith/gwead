//! Minimal in-test `script` step type implementation.
//!
//! `script` dispatch is fully data-driven through the
//! registry: a step instance of shape `{type: "script", language: X}`
//! routes to whichever plugin registered `(script, X)` in its manifest.
//! The kernel bundles no script runtime, so a gwead test that needs `script`
//! dispatch to succeed must register *something* under `(script, X)`.
//!
//! Gwead's tests can't depend on a real runtime plugin crate — such a
//! crate depends on `gwead` itself, which would form a cycle, and the
//! kernel has no dependency on any specific runtime. So the mock lives
//! here as a test-only artifact compiled inline via [`wat::parse_str`].
//!
//! What the mock provides:
//! - Three exports: `memory`, `alloc(len) -> ptr`, `execute(src_ptr,
//!   src_len, args_ptr, args_len) -> i32`
//! - One import: `gwead1.host_set_result(ptr, len)` — called from
//!   `execute` to write a fixed-payload "mock-script-result" UTF-8
//!   string back to the host
//! - Always returns `1` from `execute` (success). Resource caps, fuel,
//!   and host-import behaviour are NOT exercised — tests that care
//!   about those have to use a real runtime plugin.
//!
//! Registration:
//! - Compile the wat to wasm once per test via [`build_wasm_bytes`]
//! - Boot the kernel from a config that trusts the mock — see
//!   [`trusting`]. Claiming a `(script, <language>)` slot means
//!   supplying the interpreter every plugin's script steps of that
//!   language run inside, so the kernel requires both a
//!   `provide:step_type:script:<language>` declaration in the manifest
//!   and the plugin's name in
//!   `KernelConfig::trusted_step_type_providers`. The mock declares
//!   the permission itself; [`trusting`] supplies the other half.
//! - Use [`register`] to plug it into that kernel under
//!   `(script, "lua")` (default) or [`register_for_language`] for a
//!   different selector value
//!
//! This is the only piece of the test stack that knows the wasm ABI
//! shape; a real runtime lives in its own crate.

use std::sync::Arc;

use gwead::kernel::{Kernel, KernelConfig, KernelError};

/// WAT source for the mock. Imports `host_set_result` so dispatch
/// returns a real (host-visible) result rather than a null. The literal
/// payload `"mock-script-result"` is intentionally distinctive so a
/// confused test that ends up running THIS instead of a real runtime
/// shows up loudly in its assertion failure.
///
/// The bump allocator matters: a naive `alloc` that handed out offset 0
/// on every call would let the host's writes of the script source and
/// args OVERWRITE the result data segment — `host_set_result(0, 20)`
/// would then ship the first 20 bytes of the args JSON, which fails the
/// host-side parse and silently becomes a `Null` step result. The bump
/// allocator below keeps host writes clear of the payload so the mock
/// honestly returns `"mock-script-result"`.
const MOCK_WAT: &str = r#"
(module
  (import "gwead1" "host_set_result" (func $host_set_result (param i32 i32)))
  (memory (export "memory") 1)
  ;; "\"mock-script-result\"" — 20 bytes, valid JSON string
  (data (i32.const 0) "\"mock-script-result\"")
  ;; Real bump allocator: starts past the data segment (offset 32) so
  ;; the host's source/args writes never alias the result payload.
  ;; Returns the current watermark and bumps it by len. No bounds
  ;; check against the 64 KiB memory — fine for a mock fed tiny test
  ;; sources; an overrun traps loudly rather than corrupting state.
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
  (func (export "execute") (param $src_ptr i32) (param $src_len i32)
                           (param $args_ptr i32) (param $args_len i32)
                           (result i32)
    i32.const 0       ;; ptr to the JSON string literal
    i32.const 20      ;; length
    call $host_set_result
    i32.const 1)      ;; success
)
"#;

/// A twin of [`MOCK_WAT`] whose `execute` never returns: it spins
/// until the fuel meter traps. The one way a test can trip
/// `RuntimeLimits::fuel_budget` without a real runtime.
const SPINNING_WAT: &str = r#"
(module
  (memory (export "memory") 1)
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
  (func (export "execute") (param $src_ptr i32) (param $src_len i32)
                           (param $args_ptr i32) (param $args_len i32)
                           (result i32)
    (loop $spin br $spin)
    i32.const 1)
)
"#;

/// Compile the mock wat → wasm bytes. Caching is unnecessary —
/// compilation is fast and each test typically calls this once.
pub fn build_wasm_bytes() -> Vec<u8> {
    wat::parse_str(MOCK_WAT).expect("mock script-runtime wat parses")
}

/// Compile the spinning twin — see [`SPINNING_WAT`].
pub fn build_spinning_wasm_bytes() -> Vec<u8> {
    wat::parse_str(SPINNING_WAT).expect("spinning script-runtime wat parses")
}

/// The plugin name the mock registers under for `language`. Tests
/// need it to put the mock in the kernel's trusted-provider list — see
/// [`trusting`].
pub fn plugin_name(language: &str) -> String {
    format!("__test_script_mock_{language}__")
}

/// Authorise the mock to supply `(script, <language>)` for each of
/// `languages`, on top of whatever `config` already carries.
///
/// Every test kernel that registers the mock must boot from a config
/// that went through here; `register` fails otherwise, by design.
pub fn trusting(config: KernelConfig, languages: &[&str]) -> KernelConfig {
    languages.iter().fold(config, |c, lang| {
        c.trusting_step_type_provider(plugin_name(lang))
    })
}

/// Register the mock as the `(script, "lua")` impl on a fresh kernel.
/// Calls [`register_for_language`] under the hood.
pub fn register(kernel: &mut Kernel) -> Result<(), KernelError> {
    register_for_language(kernel, "lua")
}

/// Register the mock as the `(script, language)` impl. Lets tests that
/// validate selector dispatch route a non-`"lua"` value too.
pub fn register_for_language(kernel: &mut Kernel, language: &str) -> Result<(), KernelError> {
    register_module_for_language(kernel, language, build_wasm_bytes())
}

/// Register the spinning twin as the `(script, language)` impl. A
/// `script` step of that language runs until it exhausts its fuel.
pub fn register_spinning_for_language(
    kernel: &mut Kernel,
    language: &str,
) -> Result<(), KernelError> {
    register_module_for_language(kernel, language, build_spinning_wasm_bytes())
}

fn register_module_for_language(
    kernel: &mut Kernel,
    language: &str,
    wasm_bytes: Vec<u8>,
) -> Result<(), KernelError> {
    use base64::Engine as _;
    let base64_bytes = base64::engine::general_purpose::STANDARD.encode(&wasm_bytes);
    let manifest = serde_json::json!({
        "name": plugin_name(language),
        "version": "0.0.0-test",
        "description": "Test-only mock script runtime",
        // Declares the claim. The kernel additionally requires this
        // plugin name in `trusted_step_type_providers` — see
        // `trusting`.
        "permissions": [format!("provide:step_type:script:{language}")],
        "wasmModules": {
            "runtime": {"base64": base64_bytes},
        },
        "stepTypeImpls": [
            {"stepType": "script", "matches": language, "wasmModule": "runtime"},
        ],
    });
    let json_str = serde_json::to_string(&manifest).expect("static manifest serialises");
    kernel.register_plugin_from_json(&json_str)
}

/// Convenience: register the mock and return the kernel wrapped in
/// `Arc::new`. Some tests Arc the kernel right after boot for the
/// invoke-recursion path; this short-cuts the pattern.
pub fn register_into_arc(mut kernel: Kernel) -> Result<Arc<Kernel>, KernelError> {
    register(&mut kernel)?;
    Ok(kernel.into_arc())
}
