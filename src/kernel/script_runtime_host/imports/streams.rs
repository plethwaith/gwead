//! Stream-handle host imports.
//!
//! Five imports the script runtime always provides:
//! - `stream_read(handle, buf_ptr, buf_len) -> i32` (async)
//! - `stream_write(handle, buf_ptr, buf_len) -> i32` (async)
//! - `stream_close(handle) -> i32`
//! - `stream_output() -> i32` — returns the pre-resolved dataflow
//!   output handle if the step is `long_running` in a dataflow action;
//!   `STREAM_INVALID_HANDLE` otherwise.
//! - `is_cancelled() -> i32` — 1 if the parent step's cancellation
//!   token has fired; 0 otherwise. The same token releases a
//!   `stream_write` parked on a full channel (`STREAM_CANCELLED`).
//!   An answer of 1 records on the store that the guest was told
//!   (`told_of_cancel`), which is what lets `step_script` read a
//!   later guest error as the cancellation.
//!
//! Read + write are `func_wrap_async` so `.await` happens directly on
//! the underlying channel — no `block_in_place`, no `block_on`, no
//! registry-wide mutex held across the await. That's the property
//! that lets streaming-dataflow consumers scale past tokio's blocking-
//! thread cap.

use super::super::store_data::ScriptRuntimeStoreData;

pub(super) fn register(
    linker: &mut wasmtime::Linker<ScriptRuntimeStoreData>,
) -> Result<(), String> {
    linker
        .func_wrap_async(
            crate::kernel::abi::ABI_MODULE,
            "stream_read",
            |mut caller: wasmtime::Caller<'_, ScriptRuntimeStoreData>,
             (handle, buf_ptr, buf_len): (i32, i32, i32)| {
                let id = std::num::NonZeroU32::new(handle as u32);
                let streams_arc = caller.data().streams.clone();
                // Snapshot the memory slice's offset + length, then
                // resolve it inside the future just before the put-back
                // — wasm linear memory can be re-borrowed across the
                // await because `Caller` is moved into the future.
                let mem = caller.get_export("memory").and_then(|e| e.into_memory());
                Box::new(async move {
                    let Some(id) = id else {
                        return crate::kernel::streams::STREAM_INVALID_HANDLE;
                    };
                    let Some(mem) = mem else {
                        return crate::kernel::streams::STREAM_IO_ERROR;
                    };
                    let mem_data = mem.data_mut(&mut caller);
                    let start = buf_ptr as usize;
                    let end = match start.checked_add(buf_len as usize) {
                        Some(e) if e <= mem_data.len() => e,
                        _ => return crate::kernel::streams::STREAM_OOB,
                    };
                    let buf = &mut mem_data[start..end];
                    crate::kernel::streams::read_async_shared(&streams_arc, id, buf).await
                })
            },
        )
        .map_err(|e| format!("stream_read: {e}"))?;

    linker
        .func_wrap_async(
            crate::kernel::abi::ABI_MODULE,
            "stream_write",
            |mut caller: wasmtime::Caller<'_, ScriptRuntimeStoreData>,
             (handle, buf_ptr, buf_len): (i32, i32, i32)| {
                let id = std::num::NonZeroU32::new(handle as u32);
                let mem = caller.get_export("memory").and_then(|e| e.into_memory());
                Box::new(async move {
                    let Some(id) = id else {
                        return crate::kernel::streams::STREAM_INVALID_HANDLE;
                    };
                    let Some(mem) = mem else {
                        return crate::kernel::streams::STREAM_IO_ERROR;
                    };
                    // Snapshot the wasm bytes before the await; the
                    // wasm linear memory borrow can't span the
                    // channel send.
                    let buf: Vec<u8> = {
                        let mem_data = mem.data(&caller);
                        let start = buf_ptr as usize;
                        let end = match start.checked_add(buf_len as usize) {
                            Some(e) if e <= mem_data.len() => e,
                            _ => return crate::kernel::streams::STREAM_OOB,
                        };
                        mem_data[start..end].to_vec()
                    };
                    // Registry and token are borrowed from the store
                    // rather than cloned per chunk: the snapshot above
                    // released the memory borrow, so nothing else holds
                    // `caller` across the await. The step's token
                    // releases a send parked on a full channel
                    // (`STREAM_CANCELLED`); a guest parked inside this
                    // import cannot poll `is_cancelled` itself.
                    let data = caller.data();
                    let n = crate::kernel::streams::write_async_shared(
                        &data.streams,
                        id,
                        &buf,
                        &data.cancel,
                    )
                    .await;
                    if n == crate::kernel::streams::STREAM_CANCELLED {
                        caller.data_mut().told_of_cancel = true;
                    }
                    n
                })
            },
        )
        .map_err(|e| format!("stream_write: {e}"))?;

    linker
        .func_wrap(
            crate::kernel::abi::ABI_MODULE,
            "stream_close",
            |caller: wasmtime::Caller<'_, ScriptRuntimeStoreData>, handle: i32| -> i32 {
                let id = match std::num::NonZeroU32::new(handle as u32) {
                    Some(id) => id,
                    None => return crate::kernel::streams::STREAM_INVALID_HANDLE,
                };
                let streams_arc = caller.data().streams.clone();
                crate::kernel::streams::lock_shared(&streams_arc).close_handle(id)
            },
        )
        .map_err(|e| format!("stream_close: {e}"))?;

    // Dataflow helper — sync, pure ExecutionState lookup.
    linker
        .func_wrap(
            crate::kernel::abi::ABI_MODULE,
            "stream_output",
            |caller: wasmtime::Caller<'_, ScriptRuntimeStoreData>| -> i32 {
                match caller.data().dataflow_output {
                    Some(id) => {
                        let raw = u32::from(id);
                        // The wasm-side ABI hands handles back as
                        // `i32`; values ≥ `0x80000000` wrap into the
                        // negative space and would be misread by the
                        // wasm wrapper as one of the STREAM_* error
                        // codes. `StreamRegistry::next_handle` refuses
                        // to allocate past `MAX_STREAM_HANDLE`, so this
                        // is unreachable by construction; the debug
                        // assert is a tripwire for anyone widening the
                        // id space or bypassing the allocator.
                        debug_assert!(
                            raw <= crate::kernel::streams::MAX_STREAM_HANDLE,
                            "stream id {raw} doesn't fit in positive i32 — wasm ABI break"
                        );
                        raw as i32
                    }
                    None => crate::kernel::streams::STREAM_INVALID_HANDLE,
                }
            },
        )
        .map_err(|e| format!("stream_output: {e}"))?;

    linker
        .func_wrap(
            crate::kernel::abi::ABI_MODULE,
            "is_cancelled",
            |mut caller: wasmtime::Caller<'_, ScriptRuntimeStoreData>| -> i32 {
                if caller.data().cancel.is_cancelled() {
                    caller.data_mut().told_of_cancel = true;
                    1
                } else {
                    0
                }
            },
        )
        .map_err(|e| format!("is_cancelled: {e}"))?;

    Ok(())
}
