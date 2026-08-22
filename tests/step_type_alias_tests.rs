//! Integration tests for step type aliases.
//!
//! Covers:
//!
//! - alias resolves to the producer plugin's named action
//! - step params flow as the action input (no `input` wrapper)
//! - alias declaration validation (name format, reserved, target exists)
//! - duplicate-alias conflict rejected at registration
//! - declaring aliases binds the plugin to no role; aliases live in
//!   their own index
//! - structural cycle detection extends through aliases

mod common;

use std::sync::Arc;

use gwead::kernel::types::*;
use gwead::kernel::{Kernel, KernelConfig};
use indexmap::IndexMap;
use serde_json::{Value, json};

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

fn boot_bare() -> Kernel {
    init_tracing();
    Kernel::boot(KernelConfig::default()).expect("kernel should boot")
}

fn boot_with(manifests: Vec<PluginManifest>) -> Arc<Kernel> {
    let mut k = boot_bare();
    for m in manifests {
        k.register_plugin(m).expect("registration");
    }
    k.into_arc()
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

fn manifest(
    name: &str,
    roles: &[&str],
    actions: IndexMap<String, Action>,
    step_types: &[(&str, &str)],
) -> PluginManifest {
    // A plugin's aliases are its own step types, so they are named
    // `<plugin>.<alias>`; a fixture passes the local half and the
    // helper prefixes it (an already-dotted name is left alone so the
    // grammar tests can misspell on purpose).
    let mut aliases = IndexMap::new();
    for (alias, target) in step_types {
        let key = if alias.contains('.') {
            (*alias).to_string()
        } else {
            format!("{name}.{alias}")
        };
        aliases.insert(key, (*target).to_string());
    }
    {
        let mut m = PluginManifest::new(name.to_string());
        m.roles = roles.iter().map(|s| s.to_string()).collect();
        m.actions = actions;
        m.step_types = aliases;
        m.permissions = vec![
            "network:egress:*".to_string(),
            "blobs:read:*".to_string(),
            "blobs:write:*".to_string(),
            "blobs:delete:*".to_string(),
            // Using another plugin's alias step type requires the
            // matching `step_type:` grant; these fixtures exercise
            // the two aliases the producer plugins declare.
            "step_type:producer.make_const".to_string(),
            "step_type:echo.echo_now".to_string(),
        ];
        m
    }
}

// ---------------------------------------------------------------------------
// Resolution + execution
// ---------------------------------------------------------------------------

/// Producer plugin declares `step_type: {"make_const": "compute"}`.
/// Consumer's manifest writes `{"type": "producer.make_const"}` and gets back the
/// producer's `compute` action output.
#[tokio::test(flavor = "multi_thread")]
async fn alias_resolves_to_producer_action() {
    let kernel = boot_with(vec![
        manifest(
            "producer",
            &[],
            one_action("compute", vec![step("c1", "let", json!({"value": 42}))]),
            &[("make_const", "compute")],
        ),
        manifest(
            "consumer",
            &[],
            one_action(
                "go",
                vec![step("call_alias", "producer.make_const", json!({}))],
            ),
            &[],
        ),
    ]);

    let result = kernel
        .execute("consumer", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution");

    // producer.compute's last step is `let`, which produces its `value`
    // as the step result.
    assert_eq!(result.step_results["call_alias"], json!(42));
}

/// Step params (other than the type) flow through as the child action's
/// input. The producer's action consumes them via the input namespace.
#[tokio::test(flavor = "multi_thread")]
async fn alias_step_params_flow_as_child_input() {
    let kernel = boot_with(vec![
        manifest(
            "echo",
            &[],
            one_action(
                "echo_back",
                // input.message → `let` → produced as the action output.
                vec![step("out", "let", json!({"value": "{{$.message}}"}))],
            ),
            &[("echo_now", "echo_back")],
        ),
        manifest(
            "caller",
            &[],
            one_action(
                "go",
                vec![step(
                    "say",
                    "echo.echo_now",
                    json!({"message": "hello-via-alias"}),
                )],
            ),
            &[],
        ),
    ]);

    let result = kernel
        .execute("caller", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution");

    assert_eq!(
        result.step_results["say"],
        json!("hello-via-alias"),
        "alias params should reach the producer action's input",
    );
}

// ---------------------------------------------------------------------------
// Validation at registration
// ---------------------------------------------------------------------------

#[test]
fn empty_alias_name_rejected() {
    let mut k = boot_bare();
    let err = k
        .register_plugin(manifest(
            "p",
            &[],
            one_action("a", vec![step("s", "log", json!({"message": "m"}))]),
            &[("", "a")],
        ))
        .expect_err("empty alias name should be rejected");
    assert!(format!("{err}").contains("empty"), "{err}");
}

#[test]
fn alias_with_too_many_segments_rejected() {
    let mut k = boot_bare();
    let err = k
        .register_plugin(manifest(
            "p",
            &[],
            one_action("a", vec![step("s", "log", json!({"message": "m"}))]),
            &[("p.1bad.extra", "a")],
        ))
        .expect_err("a third segment is not part of the step type grammar");
    assert!(format!("{err}").contains("invalid character '.'"), "{err}");
}

#[test]
fn alias_under_another_plugins_prefix_rejected() {
    let mut k = boot_bare();
    let err = k
        .register_plugin(manifest(
            "p",
            &[],
            one_action("a", vec![step("s", "log", json!({"message": "m"}))]),
            &[("other.alias", "a")],
        ))
        .expect_err("an alias under another plugin's prefix is rejected");
    let msg = format!("{err}");
    assert!(msg.contains("may not be declared by plugin 'p'"), "{msg}");
}

// Note: names like `http_call` are plugin-supplied step types, not
// kernel built-ins, so aliasing them triggers no "built-in" rejection.
// The kernel's reserved-name surface is exactly the 11 intrinsics,
// covered by `alias_shadowing_reserved_for_each_rejected` below and
// `step_types_alias_rejects_reserved_intrinsic_names` in
// `intrinsics_tests.rs`.

/// A bare name is the kernel's — `for_each` today, any word tomorrow —
/// and a plugin cannot alias one. (`p.for_each` would be fine: the
/// dot is what keeps the two spaces apart.)
#[test]
fn alias_shadowing_a_bare_kernel_name_rejected() {
    let mut k = boot_bare();
    let mut m = manifest(
        "p",
        &[],
        one_action("a", vec![step("s", "log", json!({"message": "m"}))]),
        &[],
    );
    m.step_types.insert("for_each".to_string(), "a".to_string());
    let err = k
        .register_plugin(m)
        .expect_err("a bare alias is a kernel name and is rejected");
    assert!(
        format!("{err}").contains("reserved for the kernel"),
        "{err}"
    );
}

#[test]
fn alias_target_action_must_exist() {
    let mut k = boot_bare();
    let err = k
        .register_plugin(manifest(
            "p",
            &[],
            one_action(
                "real_action",
                vec![step("s", "log", json!({"message": "m"}))],
            ),
            &[("good_alias", "does_not_exist")],
        ))
        .expect_err("target action missing");
    let msg = format!("{err}");
    assert!(
        msg.contains("does_not_exist") && msg.contains("not defined"),
        "error names the missing target: {msg}",
    );
}

#[test]
fn the_same_alias_name_in_two_plugins_is_two_step_types() {
    let mut k = boot_bare();
    k.register_plugin(manifest(
        "first",
        &[],
        one_action("a", vec![step("s", "log", json!({"message": "m"}))]),
        &[("shared", "a")],
    ))
    .expect("first plugin registers");
    // Ownership is in the name: `second.shared` cannot collide with
    // `first.shared`, so there is nothing to squat.
    k.register_plugin(manifest(
        "second",
        &[],
        one_action("b", vec![step("s", "log", json!({"message": "m"}))]),
        &[("shared", "b")],
    ))
    .expect("second plugin registers its own `second.shared`");
    assert_eq!(
        k.registry().step_type_alias_candidates("first.shared"),
        vec![("first".to_string(), "a".to_string())]
    );
    assert_eq!(
        k.registry().step_type_alias_candidates("second.shared"),
        vec![("second".to_string(), "b".to_string())]
    );
}

// ---------------------------------------------------------------------------
// Alias registration binds no role
// ---------------------------------------------------------------------------
//
// Declaring an alias binds the declaring plugin to no role — alias
// resolution flows only through
// `PluginRegistry::step_type_alias_candidates`. These tests assert the
// alias index works AND that no role gets attached.

#[test]
fn declaring_step_types_populates_alias_index() {
    let mut k = boot_bare();
    k.register_plugin(manifest(
        "alias_owner",
        &[],
        one_action("real", vec![step("s", "log", json!({"message": "m"}))]),
        &[("provided_alias", "real")],
    ))
    .expect("registration");

    // The registry keys aliases by owner-qualified name — root here, so
    // the written name.
    let candidates = k
        .registry()
        .step_type_alias_candidates("alias_owner.provided_alias");
    let resolved = candidates.into_iter().next().expect("alias indexed");
    assert_eq!(resolved, ("alias_owner".to_string(), "real".to_string()));
    assert!(
        k.registry().plugins_for_role("STEP_TYPE").is_empty(),
        "declaring an alias binds no role"
    );
}

#[test]
fn no_step_types_means_no_alias_no_marker_role() {
    let mut k = boot_bare();
    k.register_plugin(manifest(
        "plain",
        &[],
        one_action("real", vec![step("s", "log", json!({"message": "m"}))]),
        &[],
    ))
    .expect("registration");

    assert!(
        k.registry()
            .step_type_alias_candidates("anything")
            .is_empty(),
        "plain plugin contributes no aliases"
    );
    assert!(
        k.registry().plugins_for_role("STEP_TYPE").is_empty(),
        "declaring an alias binds no role"
    );
}

// ---------------------------------------------------------------------------
// Structural cycle detection through aliases
// ---------------------------------------------------------------------------

/// `producer.target` is exposed as alias `cycle_back`. A second plugin
/// `consumer.entry` uses `{"type":"producer.cycle_back"}`. The first plugin's
/// `target` action also writes `{"type":"invoke","plugin":"consumer",
/// "action":"entry"}` — closing a cycle that flows through the alias.
/// Cycle detection must extend through aliases for this to be caught at
/// registration of `consumer`.
#[test]
fn alias_chain_cycle_rejected_at_registration() {
    let mut k = boot_bare();

    // Register producer first. Its `target` action invokes consumer.entry
    // by plugin slug — no cycle yet because consumer doesn't exist.
    k.register_plugin(manifest(
        "producer",
        &[],
        one_action(
            "target",
            vec![step(
                "back_through_consumer",
                "invoke",
                json!({"plugin": "consumer", "action": "entry"}),
            )],
        ),
        &[("cycle_back", "target")],
    ))
    .expect("producer registers (no cycle yet)");

    // Now register consumer.entry whose step is the alias `cycle_back`.
    // The alias resolves to producer.target — producer.target invokes
    // consumer.entry — that closes the cycle.
    let err = k
        .register_plugin(manifest(
            "consumer",
            &[],
            one_action(
                "entry",
                vec![step("via_alias", "producer.cycle_back", json!({}))],
            ),
            &[],
        ))
        .expect_err("alias-mediated cycle should be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("cycle") || msg.contains("Cycle"),
        "expected cycle error: {msg}",
    );
}

/// Using another plugin's alias step type without the matching
/// `step_type:` grant is default-deny — an alias dispatches into the
/// producer plugin's action, so it's gated like any cross-plugin
/// dispatch.
#[tokio::test(flavor = "multi_thread")]
async fn alias_without_step_types_grant_is_denied() {
    let mut ungranted = manifest(
        "consumer",
        &[],
        one_action(
            "go",
            vec![step("call_alias", "producer.make_const", json!({}))],
        ),
        &[],
    );
    ungranted.permissions = vec![];

    let kernel = boot_with(vec![
        manifest(
            "producer",
            &[],
            one_action("compute", vec![step("c1", "let", json!({"value": 42}))]),
            &[("make_const", "compute")],
        ),
        ungranted,
    ]);

    let err = kernel
        .execute("consumer", "go", json!({}))
        .with_config(&json!({}))
        .run()
        .await
        .expect_err("alias use without a step_types grant must be denied");
    let msg = err.to_string();
    assert!(
        msg.contains("step_type:producer.make_const"),
        "denial should name the missing permission: {msg}"
    );
}

/// A self-cycle through an alias is rejected even though the alias is
/// declared by the *same* manifest being validated (local aliases are
/// consulted in `register_plugin`).
#[test]
fn alias_self_cycle_within_one_plugin_rejected() {
    let mut k = boot_bare();

    let err = k
        .register_plugin(manifest(
            "loop",
            &[],
            one_action("a", vec![step("recurse", "loop.self_alias", json!({}))]),
            &[("self_alias", "a")],
        ))
        .expect_err("self-cycle through own alias should be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("cycle") || msg.contains("Cycle"),
        "expected cycle error: {msg}",
    );
}
