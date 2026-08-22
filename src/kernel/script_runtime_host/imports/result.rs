//! Result + logging host imports.
//!
//! Three imports the script runtime always provides:
//! - `host_set_result(ptr, len)` — wasm writes a UTF-8 result string the
//!   kernel reads after `execute` returns success.
//! - `host_set_error(ptr, len)` — wasm writes a UTF-8 error string the
//!   kernel reads after `execute` returns failure.
//! - `host_log(level, ptr, len)` — wasm emits a tracing event into the
//!   `gwead::script_runtime` target. Level 0 = debug, 1 = info,
//!   2 = warn, 3 = error.
//!
//! Guest-supplied `(ptr, len)` pairs are untrusted: each import bounds-
//! checks the range against linear memory and raises a wasm trap on
//! violation instead of panicking the host.

use super::super::store_data::ScriptRuntimeStoreData;

/// Copy a guest-declared `(ptr, len)` slice out of the caller's linear
/// memory. Returns a trap-producing error (never panics) when the module
/// exports no memory, when either value is negative, or when the range
/// falls outside the memory's current size.
fn read_guest_slice(
    caller: &mut wasmtime::Caller<'_, ScriptRuntimeStoreData>,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, wasmtime::Error> {
    let mem = caller
        .get_export("memory")
        .and_then(|e| e.into_memory())
        .ok_or_else(|| wasmtime::Error::msg("script runtime module exports no memory"))?;
    if ptr < 0 || len < 0 {
        return Err(wasmtime::Error::msg(format!(
            "guest passed negative pointer or length: ptr={ptr} len={len}"
        )));
    }
    let start = ptr as usize;
    let data = mem.data(&caller);
    let end = match start.checked_add(len as usize) {
        Some(e) if e <= data.len() => e,
        _ => {
            return Err(wasmtime::Error::msg(format!(
                "guest pointer range out of bounds: ptr={ptr} len={len} memory={}",
                data.len()
            )));
        }
    };
    Ok(data[start..end].to_vec())
}

/// Register `host_set_result`, `host_set_error`, and `host_log` on the
/// linker. Each closure reads a wasm linear-memory slice and writes into
/// the [`ScriptRuntimeStoreData`] slots / the `tracing` subscriber.
pub(super) fn register(
    linker: &mut wasmtime::Linker<ScriptRuntimeStoreData>,
) -> Result<(), String> {
    linker
        .func_wrap(
            crate::kernel::abi::ABI_MODULE,
            "host_set_result",
            |mut caller: wasmtime::Caller<'_, ScriptRuntimeStoreData>,
             ptr: i32,
             len: i32|
             -> Result<(), wasmtime::Error> {
                let bytes = read_guest_slice(&mut caller, ptr, len)?;
                caller.data_mut().result = Some(String::from_utf8_lossy(&bytes).to_string());
                Ok(())
            },
        )
        .map_err(|e| format!("host_set_result: {e}"))?;

    linker
        .func_wrap(
            crate::kernel::abi::ABI_MODULE,
            "host_set_error",
            |mut caller: wasmtime::Caller<'_, ScriptRuntimeStoreData>,
             ptr: i32,
             len: i32|
             -> Result<(), wasmtime::Error> {
                let bytes = read_guest_slice(&mut caller, ptr, len)?;
                caller.data_mut().error = Some(String::from_utf8_lossy(&bytes).to_string());
                Ok(())
            },
        )
        .map_err(|e| format!("host_set_error: {e}"))?;

    linker
        .func_wrap(
            crate::kernel::abi::ABI_MODULE,
            "host_log",
            |mut caller: wasmtime::Caller<'_, ScriptRuntimeStoreData>,
             level: i32,
             ptr: i32,
             len: i32|
             -> Result<(), wasmtime::Error> {
                let bytes = read_guest_slice(&mut caller, ptr, len)?;
                let msg = String::from_utf8_lossy(&bytes);
                match level {
                    0 => tracing::debug!(target: "gwead::script_runtime", "{msg}"),
                    2 => tracing::warn!(target: "gwead::script_runtime", "{msg}"),
                    3 => tracing::error!(target: "gwead::script_runtime", "{msg}"),
                    _ => tracing::info!(target: "gwead::script_runtime", "{msg}"),
                }
                Ok(())
            },
        )
        .map_err(|e| format!("host_log: {e}"))?;

    Ok(())
}
