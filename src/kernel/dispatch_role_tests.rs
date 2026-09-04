//! Focused tests for [`super::Kernel::dispatch_role`], written
//! against the orchestrator seam.
//!
//! `dispatch_role` is the constrained kernel seam external plugin
//! crates use when a step body needs to call another plugin through
//! the SPI surface (e.g. a storage plugin dispatching to a
//! signing role). Its behaviour is also exercised indirectly through
//! plugin integration paths, but the orchestrator-mirroring semantics
//! are subtle enough that a direct test makes the contract explicit
//! and locks it in against future drift.
//!
//! Coverage:
//! 1. Unbound role surfaces as [`super::KernelError::NotFound`] before
//!    any callee runs.
//! 2. With the default orchestrator, the callee runs with the caller's
//!    config (the default for embedders that don't register a custom
//!    one).
//! 3. A custom orchestrator that overrides config for the
//!    target plugin makes the callee see those overrides, NOT the
//!    caller's. The central guarantee that lets a role implementation
//!    with its own configuration (an endpoint, a backend selection)
//!    see that configuration regardless of who dispatched to it.
//!    Config is configuration only: credentials come from the
//!    embedder's `SecretResolver`, never from config — see
//!    [`super::dispatch`] and `SECURITY.md`.
//! 4. A custom orchestrator returning [`super::dispatch::DispatchError::
//!    ConfigResolutionFailed`] surfaces as
//!    [`super::KernelError::Execution`] — no silent fallback. The
//!    embedder authored the orchestrator; a backend failure means the
//!    kernel doesn't know whose config to use, so refusing is correct.
//!
//! Lives as a crate-internal `#[cfg(test)] mod` rather than an
//! integration test under `tests/` because constructing a parent
//! [`super::host_api::ExecutionState`] requires
//! [`super::host_api::ExecutionStateParams::plugin_name`], which is
//! `pub(crate)` by design — external code reaches a `PluginExecution`
//! handle by *being called from inside a step body*, not by
//! constructing one. Keeping the test module here preserves that
//! invariant without widening the public surface.
//!
//! The callee in each test is a single `throw_error` step that
//! echoes `{{$config.marker}}` into its resulting
//! [`super::KernelError::PluginError`] message; that field doubles
//! as the test's observation channel for "what config did the
//! callee actually see".

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use indexmap::IndexMap;
use serde_json::{Value, json};
use uuid::Uuid;

use super::dispatch::{
    DispatchContext, DispatchError, DispatchOrchestrator, DispatchPlan, DispatchRequest,
};
use super::exec_context::ExecutionContext;
use super::host_api::{ExecutionState, ExecutionStateParams};
use super::types::*;
use super::{Kernel, KernelConfig, KernelError, RuntimeLimits};

// Test helpers for the opaque ExecutionContext. The context is an
// opaque blob, so we stash the tenant id inside it under the
// `tenantId` key a multi-tenant embedder would use.
fn ctx_with_tenant(tenant: Uuid) -> ExecutionContext {
    ExecutionContext::new(json!({"tenantId": tenant.to_string()}))
}
fn tenant_of(ctx: &ExecutionContext) -> Option<Uuid> {
    ctx.as_value()
        .get("tenantId")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
}

// ── orchestrator test doubles ──────────────────────────────────

/// Orchestrator that overrides config when the
/// dispatch request matches a recorded `(tenant_id, plugin)` pair.
/// Non-matching dispatches fall back to caller config (first-match by
/// role for selection — same shape `DefaultOrchestrator` ships).
struct OverridingOrchestrator {
    expected: Option<(Uuid, String)>,
    answer: Option<Value>,
    calls: AtomicUsize,
}

impl DispatchOrchestrator for OverridingOrchestrator {
    fn prepare_dispatch<'a>(
        &'a self,
        request: DispatchRequest<'a>,
        ctx: DispatchContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<DispatchPlan, DispatchError>> + Send + 'a>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let (plugin, action) = match request {
                DispatchRequest::ByRole { role, action, .. } => {
                    let plugin = ctx
                        .registry
                        .plugins_for_role(role)
                        .into_iter()
                        .next()
                        .ok_or_else(|| {
                            DispatchError::RoleUnbound(format!(
                                "No plugin registered for role '{role}'"
                            ))
                        })?;
                    (plugin, action.to_string())
                }
                DispatchRequest::ByPlugin { plugin, action, .. } => {
                    (plugin.to_string(), action.to_string())
                }
            };
            let ctx_tenant = tenant_of(ctx.exec_ctx);
            let matches = matches!(
                (&self.expected, ctx_tenant),
                (Some((t, p)), Some(tid)) if *t == tid && *p == plugin
            );
            if matches && let Some(cfg) = self.answer.clone() {
                return Ok(DispatchPlan {
                    plugin,
                    action,
                    config: cfg,
                });
            }
            Ok(DispatchPlan {
                plugin,
                action,
                config: ctx.caller_config.clone(),
            })
        })
    }
}

/// Orchestrator that records the hints blob it received from the
/// most recent dispatch — used to assert hints flow through the
/// `PluginExecution::dispatch_role` surface unchanged.
struct HintCapturingOrchestrator {
    last_hints: std::sync::Mutex<Value>,
}

impl DispatchOrchestrator for HintCapturingOrchestrator {
    fn prepare_dispatch<'a>(
        &'a self,
        request: DispatchRequest<'a>,
        ctx: DispatchContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<DispatchPlan, DispatchError>> + Send + 'a>> {
        let hints_clone = match &request {
            DispatchRequest::ByRole { hints, .. } => (**hints).clone(),
            DispatchRequest::ByPlugin { hints, .. } => (**hints).clone(),
        };
        *self.last_hints.lock().unwrap() = hints_clone;
        Box::pin(async move {
            let (plugin, action) = match request {
                DispatchRequest::ByRole { role, action, .. } => {
                    let plugin = ctx
                        .registry
                        .plugins_for_role(role)
                        .into_iter()
                        .next()
                        .ok_or_else(|| {
                            DispatchError::RoleUnbound(format!(
                                "No plugin registered for role '{role}'"
                            ))
                        })?;
                    (plugin, action.to_string())
                }
                DispatchRequest::ByPlugin { plugin, action, .. } => {
                    (plugin.to_string(), action.to_string())
                }
            };
            Ok(DispatchPlan {
                plugin,
                action,
                config: ctx.caller_config.clone(),
            })
        })
    }
}

/// Orchestrator that always errors with a fixed message. Used to
/// assert the dispatch site maps `ConfigResolutionFailed` onto
/// `KernelError::Execution`.
struct FailingOrchestrator {
    message: String,
}

impl DispatchOrchestrator for FailingOrchestrator {
    fn prepare_dispatch<'a>(
        &'a self,
        _request: DispatchRequest<'a>,
        _ctx: DispatchContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<DispatchPlan, DispatchError>> + Send + 'a>> {
        let msg = self.message.clone();
        Box::pin(async move { Err(DispatchError::ConfigResolutionFailed(msg)) })
    }
}

// ── manifest helpers ───────────────────────────────────────────

fn manifest(name: &str, roles: &[&str], actions: IndexMap<String, Action>) -> PluginManifest {
    PluginManifest {
        format_version: None,
        name: name.to_string(),
        display_name: None,
        version: None,
        description: None,
        roles: roles.iter().map(|s| s.to_string()).collect(),
        actions,
        step_types: IndexMap::new(),
        config_schema: None,
        auth: None,
        metadata: IndexMap::new(),
        permissions: vec![],
        uses_secrets: Vec::new(),
        tracking_tag: None,
        step_type_defs: Vec::new(),
        wasm_modules: IndexMap::new(),
        step_type_impls: Vec::new(),
    }
}

fn step(id: &str, step_type: &str, params: Value) -> StepDef {
    StepDef {
        id: id.to_string(),
        step_type: step_type.to_string(),
        params,
        store_to_variable: None,
        depends_on: Vec::new(),
        long_running: false,
    }
}

fn action(steps: Vec<StepDef>) -> Action {
    Action {
        description: None,
        steps,
        results_path: None,
        result_mapping: IndexMap::new(),
        input_schema: None,
        output_schema: None,
        subscribes_to: Vec::new(),
        continuous: false,
        interval_ms: 0,
        parallel_waves: false,
        dataflow: false,
        wallclock_timeout_ms: None,
        tool: None,
    }
}

fn one_action(name: &str, a: Action) -> IndexMap<String, Action> {
    let mut m = IndexMap::new();
    m.insert(name.to_string(), a);
    m
}

/// Callee action: one `throw_error` step that echoes
/// `{{$config.marker}}` into its resolved message. Whichever config
/// namespace the kernel hands the callee is the one the caller sees
/// in the surfaced [`KernelError::PluginError`].
fn echo_marker_action() -> Action {
    action(vec![step(
        "echo",
        "throw_error",
        json!({"code": "ECHO", "message": "{{$config.marker}}"}),
    )])
}

/// Boot a kernel with optional custom orchestrator + a set of plugin
/// manifests. Wrapped in `Arc` ready for `dispatch_role` to call.
fn boot(
    orchestrator: Option<Arc<dyn DispatchOrchestrator>>,
    manifests: Vec<PluginManifest>,
) -> Arc<Kernel> {
    let mut k = Kernel::boot(KernelConfig {
        dispatch_orchestrator: orchestrator,
        ..KernelConfig::default()
    })
    .expect("kernel boots");
    // `dispatch_role` is plugin-initiated and default-deny, so the
    // caller these tests stand up needs a real registered manifest
    // carrying an `invoke:role:` grant — `permissions_for` on an
    // unregistered name fails closed and returns an empty set. Tests
    // that exercise the *denial* build their caller themselves; see
    // `dispatch_role_without_invoke_grant_is_denied`.
    let mut caller = manifest("test_caller", &[], IndexMap::new());
    caller.permissions = vec!["invoke:role:*".to_string()];
    k.register_plugin(caller).expect("caller registers");
    for m in manifests {
        k.register_plugin(m).expect("plugin registers");
    }
    k.into_arc()
}

/// Build a minimal parent [`ExecutionState`] standing in for the
/// invoking step body. Only the methods `dispatch_role` reads on `ex`
/// matter (config / streams / invoke_depth / exec_ctx / cancel_token)
/// — everything else uses real-but-defaulted plumbing. No secret
/// resolver: these tests are about config routing, and the callee
/// resolving `Null` secrets is the correct answer for a tree with no
/// credentials.
fn parent_state(
    kernel: &Arc<Kernel>,
    caller_config: Value,
    exec_ctx: ExecutionContext,
) -> ExecutionState {
    let parent_action: Action = serde_json::from_value(json!({ "steps": [] })).unwrap();
    let engine = wasmtime::Engine::new(wasmtime::Config::new().consume_fuel(true))
        .expect("engine constructs");
    ExecutionState::new(ExecutionStateParams {
        plugin_name: "test_caller".to_string(),
        step_type_access: Default::default(),
        action: parent_action,
        input: Value::Null,
        config: caller_config,
        secrets: Value::Null,
        secret_resolver: None,
        script_runtimes: Arc::new(std::collections::HashMap::new()),
        engine,
        exec_ctx,
        streams: None,
        invoke_depth: 0,
        dispatch_depth: 0,
        kernel: Some(Arc::downgrade(kernel)),
        trigger: None,
        limits: RuntimeLimits::default(),
        deadline: None,
        cancel: None,
        dataflow_events: None,
    })
}

/// Extract the message from a [`KernelError::PluginError`] or panic
/// with the unexpected variant — the callee always throws, so any
/// other variant is a test-infrastructure regression.
fn expect_plugin_error_message(err: KernelError) -> String {
    match err {
        KernelError::PluginError { message, .. } => message,
        other => panic!("expected PluginError, got: {other:?}"),
    }
}

// ── tests ──────────────────────────────────────────────────────

/// (1) Unbound role short-circuits with [`KernelError::NotFound`]
/// before any callee runs. Catches the "typo'd role name" case
/// loudly.
#[tokio::test(flavor = "multi_thread")]
async fn unbound_role_returns_not_found() {
    let kernel = boot(None, vec![]);
    let state = parent_state(&kernel, Value::Null, ExecutionContext::default());

    let err = kernel
        .dispatch_role(
            &state,
            "NONEXISTENT_ROLE",
            "whatever",
            json!({}),
            json!(null),
        )
        .await
        .expect_err("unbound role should error");

    match err {
        KernelError::NotFound(msg) => {
            assert!(
                msg.contains("NONEXISTENT_ROLE"),
                "error message should name the role, got: {msg}"
            );
        }
        other => panic!("expected NotFound, got: {other:?}"),
    }
}

/// (2) Default orchestrator (no custom override) → callee runs with
/// caller's config — the default for embedders that don't register a
/// custom one.
#[tokio::test(flavor = "multi_thread")]
async fn default_orchestrator_passes_caller_config_through() {
    let kernel = boot(
        None,
        vec![manifest(
            "echo_plugin",
            &["ECHO_ROLE"],
            one_action("echo", echo_marker_action()),
        )],
    );
    let state = parent_state(
        &kernel,
        json!({"marker": "from-caller"}),
        ExecutionContext::default(),
    );

    let err = kernel
        .dispatch_role(&state, "ECHO_ROLE", "echo", json!({}), json!(null))
        .await
        .expect_err("callee throws by design");

    let message = expect_plugin_error_message(err);
    assert_eq!(
        message, "from-caller",
        "callee should see caller's config when default orchestrator is in use"
    );
}

/// (3) Custom orchestrator overrides config for the target
/// plugin → callee sees the orchestrator-supplied config, NOT the
/// caller's. The central guarantee: a role implementation with its
/// own per-tenant configuration gets it regardless of who dispatched
/// to it.
#[tokio::test(flavor = "multi_thread")]
async fn orchestrator_override_supersedes_caller_config() {
    let tenant = Uuid::new_v4();
    let orchestrator = Arc::new(OverridingOrchestrator {
        expected: Some((tenant, "echo_plugin".to_string())),
        answer: Some(json!({"marker": "from-orchestrator"})),
        calls: AtomicUsize::new(0),
    });
    let calls_handle = orchestrator.clone();
    let kernel = boot(
        Some(orchestrator),
        vec![manifest(
            "echo_plugin",
            &["ECHO_ROLE"],
            one_action("echo", echo_marker_action()),
        )],
    );
    let exec_ctx = ctx_with_tenant(tenant);
    let state = parent_state(&kernel, json!({"marker": "from-caller"}), exec_ctx);

    let err = kernel
        .dispatch_role(&state, "ECHO_ROLE", "echo", json!({}), json!(null))
        .await
        .expect_err("callee throws by design");

    let message = expect_plugin_error_message(err);
    assert_eq!(
        message, "from-orchestrator",
        "callee should see orchestrator-supplied config, not caller's"
    );
    assert_eq!(
        calls_handle.calls.load(Ordering::SeqCst),
        1,
        "orchestrator should be consulted exactly once"
    );
}

/// (3b) Same orchestrator shape but the expectation doesn't match
/// (different `plugin_key`) → caller fallback applies. Exercises the
/// miss path on the override predicate.
#[tokio::test(flavor = "multi_thread")]
async fn orchestrator_miss_falls_back_to_caller_config() {
    let tenant = Uuid::new_v4();
    let orchestrator = Arc::new(OverridingOrchestrator {
        expected: Some((tenant, "some_other_plugin".to_string())),
        answer: Some(json!({"marker": "would-not-be-used"})),
        calls: AtomicUsize::new(0),
    });
    let calls_handle = orchestrator.clone();
    let kernel = boot(
        Some(orchestrator),
        vec![manifest(
            "echo_plugin",
            &["ECHO_ROLE"],
            one_action("echo", echo_marker_action()),
        )],
    );
    let exec_ctx = ctx_with_tenant(tenant);
    let state = parent_state(&kernel, json!({"marker": "from-caller"}), exec_ctx);

    let err = kernel
        .dispatch_role(&state, "ECHO_ROLE", "echo", json!({}), json!(null))
        .await
        .expect_err("callee throws by design");

    let message = expect_plugin_error_message(err);
    assert_eq!(
        message, "from-caller",
        "missed override should fall back to caller config"
    );
    assert_eq!(calls_handle.calls.load(Ordering::SeqCst), 1);
}

/// (4) Orchestrator returning `ConfigResolutionFailed` → surfaces as
/// [`KernelError::Execution`], not a silent fallback. The embedder
/// authored the orchestrator; a backend failure means the kernel
/// doesn't know whose config to use, so refusing is the correct
/// answer.
#[tokio::test(flavor = "multi_thread")]
async fn orchestrator_failure_surfaces_as_execution_error() {
    let kernel = boot(
        Some(Arc::new(FailingOrchestrator {
            message: "simulated resolver outage".to_string(),
        })),
        vec![manifest(
            "echo_plugin",
            &["ECHO_ROLE"],
            one_action("echo", echo_marker_action()),
        )],
    );
    let state = parent_state(&kernel, Value::Null, ExecutionContext::default());

    let err = kernel
        .dispatch_role(&state, "ECHO_ROLE", "echo", json!({}), json!(null))
        .await
        .expect_err("orchestrator failure should propagate");

    match err {
        KernelError::Execution(msg) => {
            assert!(
                msg.contains("simulated resolver outage"),
                "execution error should carry the orchestrator's failure: {msg}"
            );
        }
        other => panic!("expected Execution, got: {other:?}"),
    }
}

/// Hints passed to `dispatch_role` flow through to the
/// orchestrator unchanged. The kernel doesn't unwrap, transform, or
/// drop them — the orchestrator is the only consumer.
#[tokio::test(flavor = "multi_thread")]
async fn dispatch_role_threads_hints_to_orchestrator() {
    let orchestrator = Arc::new(HintCapturingOrchestrator {
        last_hints: std::sync::Mutex::new(Value::Null),
    });
    let capturing = orchestrator.clone();
    let kernel = boot(
        Some(orchestrator),
        vec![manifest(
            "echo_plugin",
            &["ECHO_ROLE"],
            one_action("echo", echo_marker_action()),
        )],
    );
    let state = parent_state(&kernel, Value::Null, ExecutionContext::default());

    let supplied_hints = json!({"catalogType": "books", "preferProvider": "openLibrary"});
    let _ = kernel
        .dispatch_role(
            &state,
            "ECHO_ROLE",
            "echo",
            json!({}),
            supplied_hints.clone(),
        )
        .await
        .expect_err("callee throws by design");

    let captured = capturing.last_hints.lock().unwrap().clone();
    assert_eq!(
        captured, supplied_hints,
        "orchestrator must receive the caller-supplied hints verbatim"
    );
}

// ── trait-method surface ───────────────────────────────────────
//
// The above tests drive `Kernel::dispatch_role(&state, …)`. Plugin
// step bodies should reach the same machinery
// via `state.dispatch_role(…)` — the `PluginExecution` trait default
// method that hides the kernel handle entirely. Both call paths
// funnel through `Kernel::dispatch_role_inner`, but the trait-method
// surface is the one external plugin crates touch, so it gets its own
// coverage rather than being implicit-only.

/// Trait-method surface: `state.dispatch_role(…)` (no explicit kernel
/// handle) propagates the caller's config under the default
/// orchestrator.
#[tokio::test(flavor = "multi_thread")]
async fn trait_dispatch_role_default_orchestrator_passes_caller_config_through() {
    let kernel = boot(
        None,
        vec![manifest(
            "echo_plugin",
            &["ECHO_ROLE"],
            one_action("echo", echo_marker_action()),
        )],
    );
    let state = parent_state(
        &kernel,
        json!({"marker": "from-caller-via-trait"}),
        ExecutionContext::default(),
    );

    let err = super::host_api::PluginExecution::dispatch_role(
        &state,
        "ECHO_ROLE",
        "echo",
        json!({}),
        json!(null),
    )
    .await
    .expect_err("callee throws by design");

    let message = expect_plugin_error_message(err);
    assert_eq!(message, "from-caller-via-trait");
}

/// Trait-method surface: orchestrator override still wins through the
/// trait method. Same guarantee as the Kernel-surface test, exercised
/// through the seam external plugins actually use.
#[tokio::test(flavor = "multi_thread")]
async fn trait_dispatch_role_orchestrator_override_supersedes_caller_config() {
    let tenant = Uuid::new_v4();
    let orchestrator = Arc::new(OverridingOrchestrator {
        expected: Some((tenant, "echo_plugin".to_string())),
        answer: Some(json!({"marker": "from-orchestrator-via-trait"})),
        calls: AtomicUsize::new(0),
    });
    let calls_handle = orchestrator.clone();
    let kernel = boot(
        Some(orchestrator),
        vec![manifest(
            "echo_plugin",
            &["ECHO_ROLE"],
            one_action("echo", echo_marker_action()),
        )],
    );
    let exec_ctx = ctx_with_tenant(tenant);
    let state = parent_state(
        &kernel,
        json!({"marker": "from-caller-via-trait"}),
        exec_ctx,
    );

    let err = super::host_api::PluginExecution::dispatch_role(
        &state,
        "ECHO_ROLE",
        "echo",
        json!({}),
        json!(null),
    )
    .await
    .expect_err("callee throws by design");

    let message = expect_plugin_error_message(err);
    assert_eq!(message, "from-orchestrator-via-trait");
    assert_eq!(calls_handle.calls.load(Ordering::SeqCst), 1);
}

/// Trait-method surface: a `PluginExecution` with no kernel back-ref
/// (constructed via raw `ExecutionStateParams` without wrapping the
/// kernel in `Arc::downgrade`) returns a clear `Execution` error
/// rather than panicking or silently doing nothing. Documents the
/// runtime failure mode the doc comment on
/// [`super::host_api::PluginExecution::dispatch_role`] promises.
/// (Wiring/setup error rather than malformed-input — `Execution` is
/// the right variant for that, not `Validation`, which is reserved for
/// caller-supplied bad data.)
#[tokio::test(flavor = "multi_thread")]
async fn trait_dispatch_role_without_kernel_back_ref_errors_cleanly() {
    // Build a state with `kernel: None` — happens in low-level tests
    // that bypass `Kernel::into_arc`.
    let parent_action: super::types::Action =
        serde_json::from_value(json!({ "steps": [] })).unwrap();
    let engine = wasmtime::Engine::new(wasmtime::Config::new().consume_fuel(true))
        .expect("engine constructs");
    let state = ExecutionState::new(ExecutionStateParams {
        plugin_name: "test_caller".to_string(),
        step_type_access: Default::default(),
        action: parent_action,
        input: Value::Null,
        config: Value::Null,
        secrets: Value::Null,
        secret_resolver: None,
        script_runtimes: Arc::new(std::collections::HashMap::new()),
        engine,
        exec_ctx: ExecutionContext::default(),
        streams: None,
        invoke_depth: 0,
        dispatch_depth: 0,
        kernel: None, // ← the case under test
        trigger: None,
        limits: RuntimeLimits::default(),
        deadline: None,
        cancel: None,
        dataflow_events: None,
    });

    let err = super::host_api::PluginExecution::dispatch_role(
        &state,
        "ANY_ROLE",
        "anything",
        json!({}),
        json!(null),
    )
    .await
    .expect_err("missing kernel back-ref should error, not panic");

    match err {
        KernelError::Execution(msg) => {
            assert!(
                msg.contains("kernel back-ref") || msg.contains("Kernel::into_arc"),
                "error should explain the missing-back-ref cause: {msg}"
            );
        }
        other => panic!("expected Execution, got: {other:?}"),
    }
}

// ── invoke-grant enforcement on the dispatch_role surface ──────────
//
// `dispatch_role` is the seam the docs point external plugin crates at
// (a storage plugin reaching a signing role). If it reached
// dispatch with no invoke check, a native step body would be a
// laundering path around every `invoke:` grant in the system: a
// zero-permission plugin could exfiltrate an SPI-role plugin's payload
// through it. These tests pin the check.

/// Boot a kernel whose caller plugin holds NO invoke grants, so the
/// default-deny path is what gets exercised.
fn boot_with_ungranted_caller(manifests: Vec<PluginManifest>) -> Arc<Kernel> {
    let mut k = Kernel::boot(KernelConfig {
        dispatch_orchestrator: None,
        ..KernelConfig::default()
    })
    .expect("kernel boots");
    k.register_plugin(manifest("test_caller", &[], IndexMap::new()))
        .expect("caller registers");
    for m in manifests {
        k.register_plugin(m).expect("plugin registers");
    }
    k.into_arc()
}

#[tokio::test(flavor = "multi_thread")]
async fn dispatch_role_without_invoke_grant_is_denied() {
    let mut actions = IndexMap::new();
    actions.insert("echo".to_string(), echo_marker_action());
    let kernel = boot_with_ungranted_caller(vec![manifest("echo_plugin", &["ECHO_ROLE"], actions)]);
    let state = parent_state(&kernel, json!({"marker": "x"}), ExecutionContext::default());

    let err = kernel
        .dispatch_role(&state, "ECHO_ROLE", "echo", json!({}), Value::Null)
        .await
        .expect_err("dispatch_role must default-deny without an invoke:role grant");

    match err {
        KernelError::Validation(msg) => assert!(
            msg.contains("invoke:role:ECHO_ROLE"),
            "denial must name the missing permission: {msg}"
        ),
        other => panic!("expected Validation, got: {other:?}"),
    }
}

/// The trait-method entry point funnels into the same
/// `dispatch_role_inner`, so it must be gated identically — gating one
/// and not the other would leave a path around the gate.
#[tokio::test(flavor = "multi_thread")]
async fn trait_dispatch_role_without_invoke_grant_is_denied() {
    let mut actions = IndexMap::new();
    actions.insert("echo".to_string(), echo_marker_action());
    let kernel = boot_with_ungranted_caller(vec![manifest("echo_plugin", &["ECHO_ROLE"], actions)]);
    let state = parent_state(&kernel, json!({"marker": "x"}), ExecutionContext::default());

    let err = super::host_api::PluginExecution::dispatch_role(
        &state,
        "ECHO_ROLE",
        "echo",
        json!({}),
        Value::Null,
    )
    .await
    .expect_err("the trait surface must be gated too");

    match err {
        KernelError::Validation(msg) => assert!(
            msg.contains("invoke:role:ECHO_ROLE"),
            "denial must name the missing permission: {msg}"
        ),
        other => panic!("expected Validation, got: {other:?}"),
    }
}

/// Anti-over-denial companion: with the grant present the call reaches
/// the callee, which proves the two tests above fail on a *permission*
/// check rather than on broken fixture wiring.
#[tokio::test(flavor = "multi_thread")]
async fn dispatch_role_with_invoke_grant_reaches_the_callee() {
    let mut actions = IndexMap::new();
    actions.insert("echo".to_string(), echo_marker_action());
    let kernel = boot(None, vec![manifest("echo_plugin", &["ECHO_ROLE"], actions)]);
    let state = parent_state(
        &kernel,
        json!({"marker": "REACHED"}),
        ExecutionContext::default(),
    );

    let err = kernel
        .dispatch_role(&state, "ECHO_ROLE", "echo", json!({}), Value::Null)
        .await
        .expect_err("the callee's only step throws");

    // `PluginError` means we got all the way into the callee's body.
    match err {
        KernelError::PluginError { message, .. } => assert!(
            message.contains("REACHED"),
            "the callee ran and resolved the caller's config: {message}"
        ),
        other => panic!("expected to reach the callee, got: {other:?}"),
    }
}
