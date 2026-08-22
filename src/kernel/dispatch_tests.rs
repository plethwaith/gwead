//! Unit tests for the `DispatchOrchestrator` seam.
//!
//! Coverage:
//! - `DefaultOrchestrator` shapes (ByRole first-match, ByPlugin
//!   pass-through, role unbound → `RoleUnbound`).
//! - `KernelConfig.dispatch_orchestrator` slot honoured: boot promotes
//!   `None` to the default impl; `Some` is used as-supplied.
//!
//! Tests that exercise dispatch end-to-end (custom orchestrator
//! plans driving the kernel's `dispatch_role`) live in
//! `dispatch_role_tests.rs`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::{Value, json};

use super::dispatch::{
    DefaultOrchestrator, DispatchContext, DispatchError, DispatchOrchestrator, DispatchPlan,
    DispatchRequest,
};
use super::exec_context::ExecutionContext;
use super::registry::PluginRegistry;
use super::{Kernel, KernelConfig};

fn empty_registry() -> PluginRegistry {
    PluginRegistry::new()
}

fn empty_ctx<'a>(registry: &'a PluginRegistry) -> DispatchContext<'a> {
    static CALLER_PLUGIN: &str = "test-caller";
    DispatchContext {
        registry,
        exec_ctx: leak_exec_ctx(),
        caller_plugin: Some(CALLER_PLUGIN),
        caller_config: leak_value(Value::Object(Default::default())),
        role_candidates: Vec::new(),
    }
}

// Small helpers — the `DispatchContext` borrows references so test
// helpers need a place to anchor the data. `Box::leak` is fine in
// test code; each test runs in a fresh process state.
fn leak_value(v: Value) -> &'static Value {
    Box::leak(Box::new(v))
}
fn leak_exec_ctx() -> &'static ExecutionContext {
    Box::leak(Box::new(ExecutionContext::default()))
}

#[tokio::test]
async fn default_orchestrator_by_plugin_passes_through() {
    let registry = empty_registry();
    let plan = DefaultOrchestrator
        .prepare_dispatch(
            DispatchRequest::ByPlugin {
                plugin: "p",
                action: "a",
                input: &json!(null),
                hints: &json!(null),
            },
            empty_ctx(&registry),
        )
        .await
        .expect("ByPlugin should succeed");
    assert_eq!(plan.plugin, "p");
    assert_eq!(plan.action, "a");
}

#[tokio::test]
async fn default_orchestrator_by_role_unbound_returns_role_unbound() {
    let registry = empty_registry();
    let err = DefaultOrchestrator
        .prepare_dispatch(
            DispatchRequest::ByRole {
                role: "MISSING",
                action: "a",
                input: &json!(null),
                hints: &json!(null),
            },
            empty_ctx(&registry),
        )
        .await
        .expect_err("unbound role must error");
    match err {
        DispatchError::RoleUnbound(m) => {
            assert!(m.contains("MISSING"), "message should name the role: {m}");
        }
        other => panic!("expected RoleUnbound, got {other:?}"),
    }
}

#[tokio::test]
async fn kernel_boot_promotes_none_to_default_orchestrator() {
    // Sanity: a kernel booted with the default config exposes a
    // populated orchestrator handle (the accessor never returns
    // `None` even though the config slot does).
    let kernel = Kernel::boot(KernelConfig::default()).expect("boot");
    let _orch: &Arc<dyn DispatchOrchestrator> = kernel.dispatch_orchestrator();
}

#[tokio::test]
async fn kernel_boot_uses_supplied_orchestrator() {
    // A custom orchestrator wrapped in Arc and handed to boot via
    // KernelConfig.dispatch_orchestrator is the one the kernel
    // exposes — boot doesn't silently overwrite it.
    struct Sentinel;
    impl DispatchOrchestrator for Sentinel {
        fn prepare_dispatch<'a>(
            &'a self,
            _request: DispatchRequest<'a>,
            _ctx: DispatchContext<'a>,
        ) -> Pin<Box<dyn Future<Output = Result<DispatchPlan, DispatchError>> + Send + 'a>>
        {
            Box::pin(async {
                Err(DispatchError::SelectionFailed(
                    "sentinel orchestrator was invoked".into(),
                ))
            })
        }
    }
    let sentinel: Arc<dyn DispatchOrchestrator> = Arc::new(Sentinel);
    let config = KernelConfig {
        dispatch_orchestrator: Some(sentinel.clone()),
        ..Default::default()
    };
    let kernel = Kernel::boot(config).expect("boot");
    // Pointer equality on the trait object's data pointer is the
    // cheapest way to assert "same Arc" without adding a marker
    // method to the trait.
    let from_kernel = kernel.dispatch_orchestrator();
    assert!(
        Arc::ptr_eq(from_kernel, &sentinel),
        "kernel must return the supplied orchestrator unchanged"
    );
}
