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

/// Compile the mock wat → wasm bytes. Caching is unnecessary —
/// compilation is fast and each test typically calls this once.
pub fn build_wasm_bytes() -> Vec<u8> {
    wat::parse_str(MOCK_WAT).expect("mock script-runtime wat parses")
}

/// What the write-until-refused guest does when its parked write comes
/// back `STREAM_CANCELLED` — the two ways a real binding might surface
/// the code to its script.
#[derive(Clone, Copy, Debug)]
pub enum OnCancelled {
    /// Report `"cancelled"` as the step result and succeed: the binding
    /// let the script notice and return normally.
    ReturnResult,
    /// Raise: the binding turned the code into a language-level error,
    /// so `execute` fails with the text `"stream write cancelled"`.
    RaiseError,
}

/// WAT source for a mock whose `execute` writes to its dataflow
/// output until the host refuses a write, then reports how the loop
/// ended. Imports `stream_output` and `stream_write` on top of
/// `host_set_result` / `host_set_error`, so a test can park a real wasm
/// guest inside the `stream_write` import — the shape a relay guest has
/// when its consumer stalls — and observe what releases it.
///
/// `{cancelled}` and `{closed}` are the `STREAM_CANCELLED` /
/// `STREAM_CLOSED` codes, spliced in by name from the kernel's
/// constants; `{on_cancelled}` is the body for the cancelled branch
/// (see [`OnCancelled`]). The result is `"closed"` on `STREAM_CLOSED`
/// and `"other"` for any other negative code.
const WRITE_UNTIL_REFUSED_WAT: &str = r#"
(module
  (import "gwead1" "host_set_result" (func $host_set_result (param i32 i32)))
  (import "gwead1" "host_set_error" (func $host_set_error (param i32 i32)))
  (import "gwead1" "stream_output" (func $stream_output (result i32)))
  (import "gwead1" "stream_write" (func $stream_write (param i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  ;; The chunk, then the JSON string results and the error text.
  (data (i32.const 0) "chunk")
  (data (i32.const 8) "\"cancelled\"")
  (data (i32.const 20) "\"closed\"   ")
  (data (i32.const 32) "\"other\"    ")
  (data (i32.const 48) "stream write cancelled")
  (global $next (mut i32) (i32.const 96))
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
    (local $handle i32)
    (local $rc i32)
    (local.set $handle (call $stream_output))
    (block $refused
      (loop $again
        (local.set $rc
          (call $stream_write (local.get $handle) (i32.const 0) (i32.const 5)))
        (br_if $refused (i32.lt_s (local.get $rc) (i32.const 0)))
        (br $again)))
    (if (result i32) (i32.eq (local.get $rc) (i32.const {cancelled}))
      (then {on_cancelled})
      (else
        (if (result i32) (i32.eq (local.get $rc) (i32.const {closed}))
          (then (call $host_set_result (i32.const 20) (i32.const 8)) (i32.const 1))
          (else (call $host_set_result (i32.const 32) (i32.const 7)) (i32.const 1))))))
)
"#;

/// Compile the write-until-refused mock — see
/// [`WRITE_UNTIL_REFUSED_WAT`] — with `on_cancelled` as its response
/// to `STREAM_CANCELLED`.
pub fn build_write_until_refused_wasm_bytes(on_cancelled: OnCancelled) -> Vec<u8> {
    use gwead::kernel::streams::{STREAM_CANCELLED, STREAM_CLOSED};
    let on_cancelled = match on_cancelled {
        OnCancelled::ReturnResult => {
            "(call $host_set_result (i32.const 8) (i32.const 11)) (i32.const 1)"
        }
        OnCancelled::RaiseError => {
            "(call $host_set_error (i32.const 48) (i32.const 22)) (i32.const 0)"
        }
    };
    let wat = WRITE_UNTIL_REFUSED_WAT
        .replace("{cancelled}", &STREAM_CANCELLED.to_string())
        .replace("{closed}", &STREAM_CLOSED.to_string())
        .replace("{on_cancelled}", on_cancelled);
    wat::parse_str(&wat).expect("write-until-refused wat parses")
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

/// Register `wasm_bytes` as the `(script, language)` impl under the
/// mock's plugin name. [`register_for_language`] with the standard
/// mock; tests that need a guest with a specific body (see
/// [`build_write_until_refused_wasm_bytes`]) pass their own.
pub fn register_module_for_language(
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
