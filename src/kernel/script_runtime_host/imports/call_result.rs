//! The single-slot call result protocol — two imports paired with the
//! dispatching imports (`host_invoke` / `host_invoke_streaming`).
//!
//! Three-import protocol per host call:
//!   1. The dispatching import performs the call, stashes the
//!      result-or-error JSON in [`ScriptRuntimeStoreData::call_result`] /
//!      [`ScriptRuntimeStoreData::call_error`], and returns a status code
//!      (`1` = result, `0` = error, `-1` = host setup error).
//!   2. `host_call_result_size` returns the stashed byte length so the
//!      wasm wrapper can allocate the right buffer.
//!   3. `host_call_result_read` copies the stashed bytes into wasm-owned
//!      memory and clears the stash.
//!
//! Single-slot stash is fine because scripts execute their host imports
//! sequentially even across `.await` points.

use super::super::store_data::ScriptRuntimeStoreData;

pub(super) fn register(
    linker: &mut wasmtime::Linker<ScriptRuntimeStoreData>,
) -> Result<(), String> {
    linker
        .func_wrap(
            crate::kernel::abi::ABI_MODULE,
            "host_call_result_size",
            |caller: wasmtime::Caller<'_, ScriptRuntimeStoreData>| -> i32 {
                let d = caller.data();
                let bytes = d
                    .call_result
                    .as_deref()
                    .or(d.call_error.as_deref())
                    .map(|s: &[u8]| s.len())
                    .unwrap_or(0);
                bytes.min(i32::MAX as usize) as i32
            },
        )
        .map_err(|e| format!("host_call_result_size: {e}"))?;

    linker
        .func_wrap(
            crate::kernel::abi::ABI_MODULE,
            "host_call_result_read",
            |mut caller: wasmtime::Caller<'_, ScriptRuntimeStoreData>,
             buf_ptr: i32,
             max_len: i32|
             -> i32 {
                let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return -1,
                };
                // Take ownership of the stash so the slot is cleared
                // even on error paths — single-pending-call invariant.
                let bytes = {
                    let d = caller.data_mut();
                    d.call_result.take().or_else(|| d.call_error.take())
                };
                let Some(s) = bytes else { return 0 };
                let copy_len = s.len().min(max_len as usize);
                let mem_data = mem.data_mut(&mut caller);
                let start = buf_ptr as usize;
                let end = match start.checked_add(copy_len) {
                    Some(e) if e <= mem_data.len() => e,
                    _ => return -1,
                };
                mem_data[start..end].copy_from_slice(&s[..copy_len]);
                copy_len.min(i32::MAX as usize) as i32
            },
        )
        .map_err(|e| format!("host_call_result_read: {e}"))?;

    Ok(())
}
