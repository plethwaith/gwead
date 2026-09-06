//! Host imports the kernel provides to every script-runtime wasm module.
//!
//! Each sub-module registers one related area of imports on the
//! [`wasmtime::Linker`]:
//!
//! | Module | Imports | Purpose |
//! |--------|---------|---------|
//! | [`result`] | `host_set_result`, `host_set_error`, `host_log` | Script-result marshaling + logging |
//! | [`streams`] | `stream_read`, `stream_write`, `stream_close`, `stream_last_error`, `stream_output`, `is_cancelled` | Stream-handle I/O, failure text + cancellation |
//! | [`invoke`] | `host_invoke`, `host_invoke_streaming` | Recurse-into-kernel action invocation |
//! | [`call_result`] | `host_call_result_size`, `host_call_result_read` | Single-slot result-stash drain (used by `invoke`) |

mod call_result;
mod invoke;
mod result;
mod streams;

use super::store_data::ScriptRuntimeStoreData;

/// Register every script-runtime host import on the linker. Called once
/// per `run_script_runtime` invocation.
pub(super) fn register_all(
    linker: &mut wasmtime::Linker<ScriptRuntimeStoreData>,
) -> Result<(), String> {
    result::register(linker)?;
    streams::register(linker)?;
    invoke::register(linker)?;
    call_result::register(linker)?;
    Ok(())
}
