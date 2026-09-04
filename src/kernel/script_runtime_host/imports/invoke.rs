//! Recurse-into-kernel host imports: `host_invoke` + `host_invoke_streaming`
//! (the `io.invoke` / `io.invoke_streaming` a guest runtime wraps them in).
//!
//! The script can call back into the kernel to invoke another action.
//! Two variants:
//! - `host_invoke` (async) — synchronous invocation; result JSON is
//!   stashed in [`call_result`] and the wasm side drains it via the
//!   [`super::call_result`] read protocol.
//! - `host_invoke_streaming` (async) — the callee must be a
//!   `dataflow: true` action with a single long-running output step;
//!   returns a stream handle the caller drains via `stream_read`.
//!
//! CANCELLATION: `host_invoke` doesn't consult the sub-store's
//! `cancel` directly — instead it passes `Some(parent_cancel)` into
//! the child's `InvocationContext` (via `execute_action_invoked`), so
//! the child observes the same cancellation surface a top-level
//! invocation would. The shape mirrors `step_invoke` and
//! `step_alias_dispatch`; search for `parent_cancel` to find all
//! three sites if the cancellation model ever needs to change.

use serde_json::Value;

use super::super::store_data::{ScriptRuntimeStoreData, bail_host_call, truncate_for_log};
use crate::kernel::host_api::INVOKE_MAX_DEPTH;

pub(super) fn register(
    linker: &mut wasmtime::Linker<ScriptRuntimeStoreData>,
) -> Result<(), String> {
    linker
        .func_wrap_async(
            crate::kernel::abi::ABI_MODULE,
            "host_invoke",
            |mut caller: wasmtime::Caller<'_, ScriptRuntimeStoreData>,
             (target_ptr, target_len, action_ptr, action_len, input_ptr, input_len): (
                i32,
                i32,
                i32,
                i32,
                i32,
                i32,
            )| {
                let mem = caller.get_export("memory").and_then(|e| e.into_memory());
                Box::new(async move {
                    let Some(mem) = mem else {
                        return bail_host_call(&mut caller, "wasm linear memory not exported");
                    };
                    let (target_bytes, action_bytes, input_bytes) = {
                        let data = mem.data(&caller);
                        let read = |ptr: i32, len: i32| -> Option<Vec<u8>> {
                            let s = ptr as usize;
                            let e = s.checked_add(len as usize)?;
                            if e > data.len() {
                                return None;
                            }
                            Some(data[s..e].to_vec())
                        };
                        let t = read(target_ptr, target_len);
                        let a = read(action_ptr, action_len);
                        let i = read(input_ptr, input_len);
                        match (t, a, i) {
                            (Some(t), Some(a), Some(i)) => (t, a, i),
                            _ => return bail_host_call(&mut caller, "host_invoke OOB read"),
                        }
                    };

                    // Parse target spec: {"plugin":"x"} or {"role":"X"}.
                    let target_val: Value = match serde_json::from_slice(&target_bytes) {
                        Ok(v) => v,
                        Err(e) => {
                            return bail_host_call(
                                &mut caller,
                                format!("host_invoke target JSON: {e}"),
                            );
                        }
                    };
                    let action_name = match String::from_utf8(action_bytes) {
                        Ok(s) => s,
                        Err(e) => {
                            return bail_host_call(
                                &mut caller,
                                format!("host_invoke action utf-8: {e}"),
                            );
                        }
                    };
                    let input_val: Value = match serde_json::from_slice(&input_bytes) {
                        Ok(v) => v,
                        Err(e) => {
                            return bail_host_call(
                                &mut caller,
                                format!("host_invoke input JSON: {e}"),
                            );
                        }
                    };

                    let kernel = match caller.data().kernel.as_ref().and_then(|w| w.upgrade()) {
                        Some(k) => k,
                        None => {
                            return bail_host_call(
                                &mut caller,
                                "io.invoke requires a kernel constructed via Kernel::into_arc",
                            );
                        }
                    };

                    // Validate the target spec (exactly one of plugin /
                    // role; no foreign keys). Selection itself happens
                    // in the orchestrator.
                    let plugin_field = target_val.get("plugin").and_then(|v| v.as_str());
                    let role_field = target_val.get("role").and_then(|v| v.as_str());
                    let (plugin_field, role_field) = match (plugin_field, role_field) {
                        (Some(_), Some(_)) => {
                            return bail_host_call(
                                &mut caller,
                                "io.invoke target specifies both `plugin` and `role`; \
                                 use exactly one",
                            );
                        }
                        (None, None) => {
                            return bail_host_call(
                                &mut caller,
                                "io.invoke target must be {\"plugin\": \"...\"} or {\"role\": \"...\"}",
                            );
                        }
                        (Some(p), None) => (Some(p.to_string()), None),
                        (None, Some(r)) => (None, Some(r.to_string())),
                    };
                    if let Some(obj) = target_val.as_object() {
                        for key in obj.keys() {
                            if key != "plugin" && key != "role" && key != "hints" {
                                return bail_host_call(
                                    &mut caller,
                                    format!(
                                        "io.invoke target has unrecognised key '{key}' \
                                         (only 'plugin', 'role', and 'hints' are valid)"
                                    ),
                                );
                            }
                        }
                    }
                    // Optional dispatch hints surfaced from the
                    // script. Orchestrators inspect
                    // them during selection; `Value::Null` when
                    // absent.
                    let hints_val = target_val.get("hints").cloned().unwrap_or(Value::Null);

                    // Snapshot parent context for the recursive call.
                    let (
                        parent_plugin,
                        parent_config,
                        parent_secret_resolver,
                        exec_ctx,
                        parent_depth,
                        parent_cancel,
                        parent_deadline,
                    ) = {
                        let d = caller.data();
                        (
                            d.parent_plugin.clone(),
                            d.parent_config.clone(),
                            d.parent_secret_resolver.clone(),
                            d.parent_exec_ctx.clone(),
                            d.parent_invoke_depth,
                            d.cancel.clone(),
                            d.parent_deadline,
                        )
                    };

                    // Depth cap — same `INVOKE_MAX_DEPTH` as
                    // `step_invoke`. Both call sites check
                    // independently, which is the safety property
                    // (script-driven invoke can sit inside a DAG-driven
                    // invoke chain), but a future refactor to the
                    // depth model needs to touch BOTH paths. Search
                    // for `INVOKE_MAX_DEPTH` to find them.
                    if parent_depth >= INVOKE_MAX_DEPTH {
                        return bail_host_call(
                            &mut caller,
                            format!("io.invoke recursion cap ({INVOKE_MAX_DEPTH}) exceeded"),
                        );
                    }

                    // A guest-supplied `plugin` target resolves along
                    // the calling plugin's ancestor chain, exactly as
                    // the DAG-level `invoke` step's does. This is the most
                    // dynamic naming surface there is — the string comes
                    // straight out of a script — so it is also the one
                    // where an unresolved name would most easily reach
                    // another namespace's registry key.
                    let plugin_field = match plugin_field {
                        Some(raw) => match kernel.resolve_plugin_reference(&parent_plugin, &raw) {
                            Ok(resolved) => Some(resolved),
                            Err(e) => {
                                return bail_host_call(
                                    &mut caller,
                                    format!("io.invoke target: {e}"),
                                );
                            }
                        },
                        None => None,
                    };

                    let request = match (&plugin_field, &role_field) {
                        (Some(p), None) => crate::kernel::dispatch::DispatchRequest::ByPlugin {
                            plugin: p.as_str(),
                            action: &action_name,
                            input: &input_val,
                            hints: &hints_val,
                        },
                        (None, Some(r)) => crate::kernel::dispatch::DispatchRequest::ByRole {
                            role: r.as_str(),
                            action: &action_name,
                            input: &input_val,
                            hints: &hints_val,
                        },
                        _ => unreachable!("validated above"),
                    };
                    // Capability gate — script-driven invoke is the
                    // runtime-dynamic dispatch surface, so it checks the
                    // same `invoke:*` grants as the DAG-level step.
                    if let Err(reason) = kernel.check_invoke_grant(&parent_plugin, &request) {
                        return bail_host_call(&mut caller, format!("io.invoke: {reason}"));
                    }
                    let plan = match kernel
                        .prepare_dispatch_via_orchestrator(
                            request.clone(),
                            &exec_ctx,
                            Some(&parent_plugin),
                            &parent_config,
                        )
                        .await
                    {
                        Ok(p) => p,
                        Err(crate::kernel::KernelError::NotFound(_)) if role_field.is_some() => {
                            let r = role_field.as_deref().unwrap_or_default();
                            return bail_host_call(
                                &mut caller,
                                format!("io.invoke role '{r}' has no registered plugin"),
                            );
                        }
                        Err(e) => {
                            return bail_host_call(
                                &mut caller,
                                format!("io.invoke dispatch policy: {e}"),
                            );
                        }
                    };
                    // Re-authorise the plan the orchestrator returned,
                    // not just the request. A self-invoke needs no
                    // grant, so without this a custom orchestrator
                    // could redirect one into any plugin it liked.
                    if let Err(reason) =
                        kernel.authorize_resolved_dispatch(&parent_plugin, &request, &plan, None)
                    {
                        return bail_host_call(&mut caller, format!("io.invoke: {reason}"));
                    }
                    let plugin_name = plan.plugin.clone();
                    let action_name = plan.action.clone();

                    let result = kernel
                        .execute_action_invoked(
                            &plugin_name,
                            &action_name,
                            input_val,
                            &plan.config,
                            parent_secret_resolver,
                            &exec_ctx,
                            parent_depth,
                            Some(parent_cancel),
                            parent_deadline,
                        )
                        .await;

                    let state = caller.data_mut();
                    match result {
                        Ok(action_result) => {
                            let value_type = match &action_result.output {
                                Value::Null => "null",
                                Value::Bool(_) => "bool",
                                Value::Number(_) => "number",
                                Value::String(_) => "string",
                                Value::Array(_) => "array",
                                Value::Object(_) => "object",
                            };
                            tracing::debug!(
                                op = "invoke",
                                plugin = %plugin_name,
                                action = %action_name,
                                return_type = %value_type,
                                return_value = %truncate_for_log(&action_result.output),
                                "io.invoke returning to wasm"
                            );
                            let json = serde_json::to_vec(&action_result.output)
                                .unwrap_or_else(|_| b"null".to_vec());
                            state.call_result = Some(json);
                            state.call_error = None;
                            1
                        }
                        Err(e) => {
                            tracing::debug!(
                                op = "invoke",
                                plugin = %plugin_name,
                                action = %action_name,
                                error = %e,
                                "io.invoke failed"
                            );
                            state.call_error = Some(
                                format!("io.invoke → {plugin_name}.{action_name} failed: {e}")
                                    .into_bytes(),
                            );
                            state.call_result = None;
                            0
                        }
                    }
                })
            },
        )
        .map_err(|e| format!("host_invoke: {e}"))?;

    // `host_invoke_streaming` — streaming variant of `host_invoke`. The
    // callee must be `dataflow: true` with a single long-running output
    // step; the kernel spawns it on a background tokio task and returns
    // a readable stream handle the caller can drain from while the
    // callee is still running. Validation errors stash via the same
    // `call_error` slot as `host_invoke` and surface as a wasm-side error.
    //
    // Return value semantics:
    //   `> 0` — stream handle the caller passes to `io.stream.read`
    //   `  0` — error stashed in `call_error`; caller fetches via the
    //           usual `host_call_result_size` / `host_call_result_read`
    linker
        .func_wrap_async(
            crate::kernel::abi::ABI_MODULE,
            "host_invoke_streaming",
            |mut caller: wasmtime::Caller<'_, ScriptRuntimeStoreData>,
             (target_ptr, target_len, action_ptr, action_len, input_ptr, input_len): (
                i32,
                i32,
                i32,
                i32,
                i32,
                i32,
            )| {
                let mem = caller.get_export("memory").and_then(|e| e.into_memory());
                Box::new(async move {
                    let Some(mem) = mem else {
                        return bail_host_call(&mut caller, "wasm linear memory not exported");
                    };
                    let (target_bytes, action_bytes, input_bytes) = {
                        let data = mem.data(&caller);
                        let read = |ptr: i32, len: i32| -> Option<Vec<u8>> {
                            let s = ptr as usize;
                            let e = s.checked_add(len as usize)?;
                            if e > data.len() {
                                return None;
                            }
                            Some(data[s..e].to_vec())
                        };
                        match (
                            read(target_ptr, target_len),
                            read(action_ptr, action_len),
                            read(input_ptr, input_len),
                        ) {
                            (Some(t), Some(a), Some(i)) => (t, a, i),
                            _ => {
                                return bail_host_call(
                                    &mut caller,
                                    "host_invoke_streaming OOB read",
                                );
                            }
                        }
                    };

                    let target_val: Value = match serde_json::from_slice(&target_bytes) {
                        Ok(v) => v,
                        Err(e) => {
                            return bail_host_call(
                                &mut caller,
                                format!("host_invoke_streaming target JSON: {e}"),
                            );
                        }
                    };
                    let action_name = match String::from_utf8(action_bytes) {
                        Ok(s) => s,
                        Err(e) => {
                            return bail_host_call(
                                &mut caller,
                                format!("host_invoke_streaming action utf-8: {e}"),
                            );
                        }
                    };
                    let input_val: Value = match serde_json::from_slice(&input_bytes) {
                        Ok(v) => v,
                        Err(e) => {
                            return bail_host_call(
                                &mut caller,
                                format!("host_invoke_streaming input JSON: {e}"),
                            );
                        }
                    };

                    let kernel = match caller.data().kernel.as_ref().and_then(|w| w.upgrade()) {
                        Some(k) => k,
                        None => {
                            return bail_host_call(
                                &mut caller,
                                "io.invoke_streaming requires a kernel constructed via Kernel::into_arc",
                            );
                        }
                    };

                    // Validate the target spec. Selection itself flows
                    // through the dispatch orchestrator.
                    let plugin_field = target_val.get("plugin").and_then(|v| v.as_str());
                    let role_field = target_val.get("role").and_then(|v| v.as_str());
                    let (plugin_field, role_field) = match (plugin_field, role_field) {
                        (Some(_), Some(_)) => {
                            return bail_host_call(
                                &mut caller,
                                "io.invoke_streaming target specifies both `plugin` and `role`; \
                                 use exactly one",
                            );
                        }
                        (None, None) => {
                            return bail_host_call(
                                &mut caller,
                                "io.invoke_streaming target must be {\"plugin\": \"...\"} or {\"role\": \"...\"}",
                            );
                        }
                        (Some(p), None) => (Some(p.to_string()), None),
                        (None, Some(r)) => (None, Some(r.to_string())),
                    };
                    if let Some(obj) = target_val.as_object() {
                        for key in obj.keys() {
                            if key != "plugin" && key != "role" && key != "hints" {
                                return bail_host_call(
                                    &mut caller,
                                    format!(
                                        "io.invoke_streaming target has unrecognised key '{key}' \
                                         (only 'plugin', 'role', and 'hints' are valid)"
                                    ),
                                );
                            }
                        }
                    }
                    let hints_val =
                        target_val.get("hints").cloned().unwrap_or(Value::Null);

                    let (
                        parent_plugin,
                        parent_config,
                        parent_secret_resolver,
                        exec_ctx,
                        parent_depth,
                        streams_arc,
                        parent_cancel,
                        parent_deadline,
                    ) = {
                        let d = caller.data();
                        (
                            d.parent_plugin.clone(),
                            d.parent_config.clone(),
                            d.parent_secret_resolver.clone(),
                            d.parent_exec_ctx.clone(),
                            d.parent_invoke_depth,
                            d.streams.clone(),
                            d.cancel.clone(),
                            d.parent_deadline,
                        )
                    };

                    if parent_depth >= INVOKE_MAX_DEPTH {
                        return bail_host_call(
                            &mut caller,
                            format!(
                                "io.invoke_streaming recursion cap ({INVOKE_MAX_DEPTH}) exceeded"
                            ),
                        );
                    }

                    // Namespace-relative target resolution, identical to
                    // `io.invoke`. Both guest surfaces resolve, or the
                    // streaming one becomes the way around the other.
                    let plugin_field = match plugin_field {
                        Some(raw) => {
                            match kernel.resolve_plugin_reference(&parent_plugin, &raw) {
                                Ok(resolved) => Some(resolved),
                                Err(e) => {
                                    return bail_host_call(
                                        &mut caller,
                                        format!("io.invoke_streaming target: {e}"),
                                    );
                                }
                            }
                        }
                        None => None,
                    };

                    let request = match (&plugin_field, &role_field) {
                        (Some(p), None) => crate::kernel::dispatch::DispatchRequest::ByPlugin {
                            plugin: p.as_str(),
                            action: &action_name,
                            input: &input_val,
                            hints: &hints_val,
                        },
                        (None, Some(r)) => crate::kernel::dispatch::DispatchRequest::ByRole {
                            role: r.as_str(),
                            action: &action_name,
                            input: &input_val,
                            hints: &hints_val,
                        },
                        _ => unreachable!("validated above"),
                    };
                    // Same `invoke:*` capability gate as `host_invoke`.
                    if let Err(reason) = kernel.check_invoke_grant(&parent_plugin, &request) {
                        return bail_host_call(
                            &mut caller,
                            format!("io.invoke_streaming: {reason}"),
                        );
                    }
                    let plan = match kernel
                        .prepare_dispatch_via_orchestrator(
                            request.clone(),
                            &exec_ctx,
                            Some(&parent_plugin),
                            &parent_config,
                        )
                        .await
                    {
                        Ok(p) => p,
                        Err(crate::kernel::KernelError::NotFound(_)) if role_field.is_some() => {
                            let r = role_field.as_deref().unwrap_or_default();
                            return bail_host_call(
                                &mut caller,
                                format!(
                                    "io.invoke_streaming role '{r}' has no registered plugin"
                                ),
                            );
                        }
                        Err(e) => {
                            return bail_host_call(
                                &mut caller,
                                format!("io.invoke_streaming dispatch policy: {e}"),
                            );
                        }
                    };
                    // Re-authorise the plan the orchestrator returned,
                    // not just the request. A self-invoke needs no
                    // grant, so without this a custom orchestrator
                    // could redirect one into any plugin it liked.
                    if let Err(reason) = kernel.authorize_resolved_dispatch(
                        &parent_plugin,
                        &request,
                        &plan,
                        None,
                    ) {
                        return bail_host_call(&mut caller, format!("io.invoke_streaming: {reason}"));
                    }
                    let plugin_name = plan.plugin.clone();
                    let action_name = plan.action.clone();

                    let result = kernel
                        .execute_action_invoked_streaming(
                            &plugin_name,
                            &action_name,
                            input_val,
                            &plan.config,
                            parent_secret_resolver,
                            &exec_ctx,
                            streams_arc,
                            parent_depth,
                            Some(parent_cancel),
                            parent_deadline,
                        )
                        .await;

                    // ABI contract: `> 0` is a stream handle, `0` means
                    // "error stashed in `call_error`". A positive return
                    // from an error path would be silently misread by
                    // the wasm wrapper as a valid handle and crash the
                    // next `io.stream.read`. Both arms here honour that:
                    // the `Ok` arm asserts the handle fits in positive
                    // `i32` (NonZeroU32 → `raw > 0` by construction);
                    // the `Err` arm delegates to `bail_host_call`,
                    // which is the project-wide error-return helper
                    // and is statically defined to return `0`.
                    match result {
                        Ok(stream_id) => {
                            // The wasm-side ABI hands handles back as
                            // `i32`; values ≥ 0x80000000 wrap into the
                            // negative space and would be misread by
                            // the wasm wrapper as an error. Mirrors
                            // the safety check in `stream_output`.
                            let raw = u32::from(stream_id);
                            debug_assert!(
                                raw <= crate::kernel::streams::MAX_STREAM_HANDLE,
                                "stream id {raw} doesn't fit in positive i32 — wasm ABI break"
                            );
                            tracing::debug!(
                                op = "invoke_streaming",
                                plugin = %plugin_name,
                                action = %action_name,
                                stream_handle = raw,
                                "io.invoke_streaming returning stream handle to wasm"
                            );
                            // Clear any stale stash from earlier calls.
                            let state = caller.data_mut();
                            state.call_result = None;
                            state.call_error = None;
                            raw as i32
                        }
                        Err(e) => {
                            tracing::debug!(
                                op = "invoke_streaming",
                                plugin = %plugin_name,
                                action = %action_name,
                                error = %e,
                                "io.invoke_streaming failed"
                            );
                            bail_host_call(
                                &mut caller,
                                format!(
                                    "io.invoke_streaming → {plugin_name}.{action_name} failed: {e}"
                                ),
                            )
                        }
                    }
                })
            },
        )
        .map_err(|e| format!("host_invoke_streaming: {e}"))?;

    Ok(())
}
