//! Integration tests for the `invoke` step type.
//!
//! Covers:
//!
//! - by-plugin resolution
//! - by-role resolution
//! - recursion cap
//! - structural cycle rejection at registration time

use std::sync::Arc;

use gwead::kernel::types::*;
use gwead::kernel::{Kernel, KernelConfig};
use indexmap::IndexMap;
use serde_json::{Value, json};

mod common;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "gwead=debug".into()),
        )
        .with_test_writer()
        .try_init();
}

/// Boot the kernel, register every supplied manifest, then wrap via
/// `into_arc`. Registration must happen before `into_arc` because the
/// self-Weak it populates blocks `Arc::get_mut`. For tests that need to
/// observe a registration *failure* (the structural cycle test), use
/// [`boot_bare`], which keeps the kernel out of the `Arc`.
fn boot_with(manifests: Vec<PluginManifest>) -> Arc<Kernel> {
    init_tracing();
    let mut k = Kernel::boot(common::script_runtime_mock::trusting(
        KernelConfig::default(),
        &["lua"],
    ))
    .expect("kernel should boot");
    common::script_runtime_mock::register(&mut k).expect("mock script runtime registers");
    for m in manifests {
        k.register_plugin(m).expect("registration");
    }
    k.into_arc()
}

/// Pre-Arc kernel for tests that need to call register_plugin and observe
/// success or failure directly.
fn boot_bare() -> Kernel {
    init_tracing();
    Kernel::boot(KernelConfig::default()).expect("kernel should boot")
}

fn manifest(name: &str, roles: &[&str], actions: IndexMap<String, Action>) -> PluginManifest {
    {
        let mut m = PluginManifest::new(name.to_string());
        m.roles = roles.iter().map(|s| s.to_string()).collect();
        m.actions = actions;
        m.permissions = vec![
            "network:egress:*".to_string(),
            "blobs:read:*".to_string(),
            "blobs:write:*".to_string(),
            "blobs:delete:*".to_string(),
            // Cross-plugin dispatch is default-deny; these fixtures
            // exercise both invoke shapes.
            "invoke:plugin:*".to_string(),
            "invoke:role:*".to_string(),
        ];
        m
    }
}

fn step(id: &str, step_type: &str, params: Value) -> StepDef {
    StepDef::new(id.to_string(), step_type.to_string(), params)
}

fn action(steps: Vec<StepDef>) -> Action {
    Action::new(steps)
}

fn one_action(name: &str, steps: Vec<StepDef>) -> IndexMap<String, Action> {
    let mut m = IndexMap::new();
    m.insert(name.to_string(), action(steps));
    m
}

// ---------------------------------------------------------------------------
// by-plugin invoke
// ---------------------------------------------------------------------------

/// Plugin A's only step is an `invoke` of plugin B's `compute` action.
/// B's `compute` action just produces a value via `let`. The invoke's
/// result is the child action's `output`, which (no result_mapping, no
/// results_path) defaults to the last step's result.
#[tokio::test(flavor = "multi_thread")]
async fn invoke_by_plugin_returns_child_output() {
    let kernel = boot_with(vec![
        manifest(
            "child",
            &[],
            one_action("compute", vec![step("c1", "let", json!({"value": 42}))]),
        ),
        manifest(
            "parent",
            &[],
            one_action(
                "go",
                vec![step(
                    "call_child",
                    "invoke",
                    json!({"plugin": "child", "action": "compute", "input": {}}),
                )],
            ),
        ),
    ]);

    let result = kernel
        .execute("parent", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution");

    // child.compute's last step (`let`) yields its `value`.
    assert_eq!(result.step_results["call_child"], json!(42));
}

/// Cross-plugin invoke without an `invoke:*` grant is default-deny —
/// the capability gate that keeps `network:egress` / `blobs` grants
/// from being laundered through a plugin that holds them.
#[tokio::test(flavor = "multi_thread")]
async fn invoke_without_grant_is_denied() {
    let mut ungranted = manifest(
        "parent",
        &[],
        one_action(
            "go",
            vec![step(
                "call_child",
                "invoke",
                json!({"plugin": "child", "action": "compute", "input": {}}),
            )],
        ),
    );
    ungranted.permissions = vec![];

    let kernel = boot_with(vec![
        manifest(
            "child",
            &[],
            one_action("compute", vec![step("c1", "let", json!({"value": 42}))]),
        ),
        ungranted,
    ]);

    let err = kernel
        .execute("parent", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect_err("cross-plugin invoke without a grant must be denied");
    let msg = err.to_string();
    assert!(
        msg.contains("invoke:plugin:child"),
        "denial should name the missing permission: {msg}"
    );
}

/// A plugin may always invoke its own actions — no grant required.
#[tokio::test(flavor = "multi_thread")]
async fn self_invoke_needs_no_grant() {
    let mut actions = one_action("compute", vec![step("c1", "let", json!({"value": 7}))]);
    actions.extend(one_action(
        "go",
        vec![step(
            "call_self",
            "invoke",
            json!({"plugin": "solo", "action": "compute", "input": {}}),
        )],
    ));
    let mut solo = manifest("solo", &[], actions);
    solo.permissions = vec![];

    let kernel = boot_with(vec![solo]);
    let result = kernel
        .execute("solo", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("self-invoke is implicitly allowed");
    assert_eq!(result.step_results["call_self"], json!(7));
}

// ---------------------------------------------------------------------------
// by-role invoke
// ---------------------------------------------------------------------------

/// Plugin A invokes role `LLM_CHAT`; the kernel resolves that to whichever
/// plugin claimed it (we register a mock). Exercises the role-resolution
/// path that role-dispatching plugins use.
#[tokio::test(flavor = "multi_thread")]
async fn invoke_by_role_resolves_via_registry() {
    let kernel = boot_with(vec![
        manifest(
            "mock-llm",
            &["LLM_CHAT"],
            one_action(
                "chat",
                vec![step(
                    "respond",
                    "let",
                    json!({"value": "hello from mock-llm"}),
                )],
            ),
        ),
        manifest(
            "consumer",
            &[],
            one_action(
                "use_llm",
                vec![step(
                    "ask",
                    "invoke",
                    json!({"role": "LLM_CHAT", "action": "chat", "input": {}}),
                )],
            ),
        ),
    ]);

    let result = kernel
        .execute("consumer", "use_llm", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution");

    assert_eq!(result.step_results["ask"], json!("hello from mock-llm"));
}

#[tokio::test(flavor = "multi_thread")]
async fn invoke_by_role_unregistered_role_errors_cleanly() {
    // Use a role name nothing in this test registers.
    let kernel = boot_with(vec![manifest(
        "consumer",
        &[],
        one_action(
            "use_missing",
            vec![step(
                "ask",
                "invoke",
                json!({"role": "MADE_UP_ROLE", "action": "do", "input": {}}),
            )],
        ),
    )]);

    let err = kernel
        .execute("consumer", "use_missing", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect_err("should error: MADE_UP_ROLE not registered");
    let msg = format!("{err}");
    assert!(
        msg.contains("MADE_UP_ROLE"),
        "error should mention the role: {msg}"
    );
}

// ---------------------------------------------------------------------------
// validation errors
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn invoke_with_both_plugin_and_role_errors() {
    let kernel = boot_with(vec![manifest(
        "bad",
        &[],
        one_action(
            "go",
            vec![step(
                "x",
                "invoke",
                json!({"plugin": "p", "role": "R", "action": "a"}),
            )],
        ),
    )]);
    let err = kernel
        .execute("bad", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("both `plugin` and `role`"));
}

#[tokio::test(flavor = "multi_thread")]
async fn invoke_without_plugin_or_role_errors() {
    let kernel = boot_with(vec![manifest(
        "bad",
        &[],
        one_action("go", vec![step("x", "invoke", json!({"action": "a"}))]),
    )]);
    let err = kernel
        .execute("bad", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("neither `plugin` nor `role`"));
}

// ---------------------------------------------------------------------------
// recursion cap
// ---------------------------------------------------------------------------

/// Trip the runtime depth cap (16). A by-plugin cycle would be rejected
/// at registration by the structural check, so this builds a by-role
/// cycle — which the static check skips — and lets the runtime cap
/// fire.
#[tokio::test(flavor = "multi_thread")]
async fn invoke_recursion_cap_trips_via_by_role_cycle() {
    let kernel = boot_with(vec![manifest(
        "loop",
        &["RECURSIVE"],
        one_action(
            "go",
            vec![step(
                "again",
                "invoke",
                json!({"role": "RECURSIVE", "action": "go", "input": {}}),
            )],
        ),
    )]);

    let err = kernel
        .execute("loop", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("recursion cap") && msg.contains("16"),
        "expected recursion cap mention in error: {msg}",
    );
}

// ---------------------------------------------------------------------------
// structural cycle detection at registration
// ---------------------------------------------------------------------------

#[test]
fn structural_cycle_rejected_at_registration() {
    let mut k = boot_bare();
    // a.x → b.y (registered first; target b doesn't exist yet but the
    // kernel doesn't validate target existence — only the cycle shape).
    k.register_plugin(manifest(
        "a",
        &[],
        one_action(
            "x",
            vec![step("i", "invoke", json!({"plugin": "b", "action": "y"}))],
        ),
    ))
    .expect("registration of `a` should succeed");

    // b.y → a.x closes the cycle. Should fail at registration.
    let err = k
        .register_plugin(manifest(
            "b",
            &[],
            one_action(
                "y",
                vec![step("i", "invoke", json!({"plugin": "a", "action": "x"}))],
            ),
        ))
        .expect_err("should reject cycle");
    let msg = format!("{err}");
    assert!(
        msg.contains("cycle") || msg.contains("Cycle"),
        "expected cycle error: {msg}",
    );
}
