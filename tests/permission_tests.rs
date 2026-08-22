//! Integration tests for the plugin capability model —
//! registration-time validation of the `permissions` field.
//!
//! Enforcement tests for the advisory categories live with the
//! embedder step types that own those gates (`network:egress` with
//! whatever performs HTTP, `blobs:*` with whatever performs blob I/O).
//! The kernel-side permission *parsing* unit tests live in
//! `src/kernel/permissions.rs`.

mod common;

use gwead::kernel::types::*;
use gwead::kernel::{Kernel, KernelConfig};
use indexmap::IndexMap;
use serde_json::{Value, json};

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "gwead=debug".into()),
        )
        .with_test_writer()
        .try_init();
}

fn boot_bare() -> Kernel {
    init_tracing();
    Kernel::boot(KernelConfig::default()).expect("kernel boot")
}

fn step(id: &str, step_type: &str, params: Value) -> StepDef {
    StepDef::new(id.to_string(), step_type.to_string(), params)
}

fn action(steps: Vec<StepDef>) -> Action {
    Action::new(steps)
}

fn manifest_with_permissions(
    name: &str,
    steps: Vec<StepDef>,
    permissions: &[&str],
) -> PluginManifest {
    let mut actions = IndexMap::new();
    actions.insert("go".to_string(), action(steps));
    {
        let mut m = PluginManifest::new(name.to_string());
        m.actions = actions;
        m.permissions = permissions.iter().map(|s| s.to_string()).collect();
        m
    }
}

// ---------------------------------------------------------------------------
// Registration validation
// ---------------------------------------------------------------------------

#[test]
fn a_declared_app_category_registers_cleanly() {
    // The kernel parses an embedder category into
    // `Permission::AppDefined` and stores it untouched — it has no
    // opinion about what `acme.nonsense` means and never consults the
    // grant. What it does require is that the embedder said the
    // category exists; see the next test for why.
    let mut k =
        Kernel::boot(KernelConfig::default().defining_app_permission_category("acme.nonsense"))
            .expect("kernel boot");
    let m = manifest_with_permissions(
        "fine",
        vec![step("noop", "set_var", json!({"name": "x", "value": 1}))],
        &["acme.nonsense:not_a_category"],
    );
    k.register_plugin(m)
        .expect("a declared AppDefined category registers cleanly");
}

#[test]
fn an_undeclared_app_category_is_rejected() {
    // If this registered, the grant would match nothing, for the life
    // of the deployment, silently — the kernel never enforces
    // AppDefined, and the embedder's layer looks up a `kind` it does
    // not have. A typo and a real category are the same thing to the
    // kernel, so it asks the one party that can tell them apart.
    let mut k = boot_bare();
    let m = manifest_with_permissions(
        "bad",
        vec![step("noop", "set_var", json!({"name": "x", "value": 1}))],
        &["acme.nonsense:not_a_category"],
    );
    let err = k
        .register_plugin(m)
        .expect_err("a category no embedder declared is a load error")
        .to_string();
    assert!(err.contains("acme.nonsense"), "names the category: {err}");
    assert!(
        err.contains("defining_app_permission_category"),
        "an embedder meeting this rule for the first time is told the fix: {err}"
    );
}

#[test]
fn empty_permission_string_rejected() {
    let mut k = boot_bare();
    let m = manifest_with_permissions(
        "bad",
        vec![step("noop", "set_var", json!({"name": "x", "value": 1}))],
        &[""],
    );
    assert!(k.register_plugin(m).is_err());
}

#[test]
fn bad_blobs_op_rejected() {
    let mut k = boot_bare();
    let m = manifest_with_permissions(
        "bad",
        vec![step("noop", "set_var", json!({"name": "x", "value": 1}))],
        &["blobs:execute:foo"],
    );
    assert!(k.register_plugin(m).is_err());
}
