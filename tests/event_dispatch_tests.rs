//! Integration tests for event subscription + dispatch.
//!
//! Covers:
//!
//! - Action with `subscribes_to` registers as event subscriber on plugin load
//! - Domain event fires → all subscribed plugins' actions execute with event
//!   payload available as `$trigger`
//! - Cascade depth cap refuses to fan out once the parent depth reaches
//!   the cap — the mechanism that terminates plugin-A → event →
//!   plugin-B → event → plugin-A chains
//! - Empty subscribers list dispatches cleanly

mod common;

use std::sync::Arc;

use gwead::kernel::ExecutionContext;
use gwead::kernel::types::*;
use gwead::kernel::{DISPATCH_MAX_DEPTH, Kernel, KernelConfig};

fn payload(v: Value) -> Arc<Value> {
    Arc::new(v)
}
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

fn boot_with(manifests: Vec<PluginManifest>) -> Arc<Kernel> {
    init_tracing();
    let mut k = Kernel::boot(KernelConfig::default()).expect("kernel should boot");
    for m in manifests {
        k.register_plugin(m).expect("registration");
    }
    k.into_arc()
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
        ];
        m
    }
}

fn step(id: &str, step_type: &str, params: Value) -> StepDef {
    StepDef::new(id.to_string(), step_type.to_string(), params)
}

fn action_subscribing(steps: Vec<StepDef>, events: &[&str]) -> Action {
    {
        let mut m = Action::new(steps);
        m.subscribes_to = events.iter().map(|s| s.to_string()).collect();
        m
    }
}

fn one_action(name: &str, action: Action) -> IndexMap<String, Action> {
    let mut m = IndexMap::new();
    m.insert(name.to_string(), action);
    m
}

// ---------------------------------------------------------------------------
// Subscription registration
// ---------------------------------------------------------------------------

/// Action declaring `subscribes_to` should appear in the registry's
/// subscriber list for that event. Subscribers are indexed by event
/// type, only via `PluginRegistry::subscribers_for` — no role is
/// synthesised for them.
#[test]
fn subscribes_to_registers_subscriber() {
    init_tracing();
    let mut k = Kernel::boot(KernelConfig::default()).unwrap();
    k.register_plugin(manifest(
        "handler",
        &[],
        one_action(
            "on_item_created",
            action_subscribing(
                vec![step("noop", "set_var", json!({"name": "x", "value": 1}))],
                &["catalog.item.created"],
            ),
        ),
    ))
    .unwrap();

    let subs = k.registry().subscribers_for("catalog.item.created");
    assert_eq!(subs.len(), 1);
    assert_eq!(
        subs[0],
        ("handler".to_string(), "on_item_created".to_string())
    );

    // Subscribing does not bind the plugin to any role.
    assert!(k.registry().plugins_for_role("EVENT_HANDLER").is_empty());
}

#[test]
fn no_subscribes_to_means_no_subscriber() {
    init_tracing();
    let mut k = Kernel::boot(KernelConfig::default()).unwrap();
    k.register_plugin(manifest(
        "plain",
        &[],
        one_action(
            "go",
            action_subscribing(
                vec![step("noop", "set_var", json!({"name": "x", "value": 1}))],
                &[],
            ),
        ),
    ))
    .unwrap();

    assert!(k.registry().subscribers_for("anything").is_empty());
    assert!(k.registry().plugins_for_role("EVENT_HANDLER").is_empty());
}

// ---------------------------------------------------------------------------
// Event dispatch happy path
// ---------------------------------------------------------------------------

/// Dispatching an event fires the subscribed action, which can read the
/// payload via `$trigger` (and the template form `{{$trigger.foo}}`).
#[tokio::test(flavor = "multi_thread")]
async fn dispatch_event_invokes_subscriber_with_trigger_payload() {
    let kernel = boot_with(vec![manifest(
        "handler",
        &[],
        one_action(
            "on_item_created",
            action_subscribing(
                vec![step(
                    "capture",
                    "let",
                    json!({"value": "{{$trigger.title}}"}),
                )],
                &["catalog.item.created"],
            ),
        ),
    )]);

    let results = kernel
        .dispatch_event(
            "catalog.item.created",
            payload(json!({"title": "Dune", "id": 42})),
            &json!({}),
            &ExecutionContext::default(),
            0,
        )
        .await;

    assert_eq!(results.len(), 1);
    let entry = results.into_iter().next().unwrap();
    assert_eq!(entry.plugin, "handler");
    assert_eq!(entry.action, "on_item_created");
    let result = entry.result.expect("dispatch ok");
    assert_eq!(result.step_results["capture"], json!("Dune"));
}

#[tokio::test(flavor = "multi_thread")]
async fn dispatch_event_with_no_subscribers_returns_empty() {
    let kernel = boot_with(vec![]);
    let results = kernel
        .dispatch_event(
            "no.such.event",
            payload(json!({})),
            &json!({}),
            &ExecutionContext::default(),
            0,
        )
        .await;
    assert!(results.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn dispatch_event_fans_out_to_every_subscriber() {
    let kernel = boot_with(vec![
        manifest(
            "h1",
            &[],
            one_action(
                "handle",
                action_subscribing(vec![step("tag", "let", json!({"value": "h1"}))], &["ping"]),
            ),
        ),
        manifest(
            "h2",
            &[],
            one_action(
                "handle",
                action_subscribing(vec![step("tag", "let", json!({"value": "h2"}))], &["ping"]),
            ),
        ),
    ]);

    let results = kernel
        .dispatch_event(
            "ping",
            payload(json!({})),
            &json!({}),
            &ExecutionContext::default(),
            0,
        )
        .await;

    assert_eq!(results.len(), 2);
    let plugins: std::collections::HashSet<String> =
        results.iter().map(|r| r.plugin.clone()).collect();
    assert_eq!(
        plugins,
        ["h1".to_string(), "h2".to_string()]
            .iter()
            .cloned()
            .collect(),
    );
    for entry in results {
        let r = entry.result.expect("dispatch ok");
        assert_eq!(r.step_results["tag"].as_str().unwrap(), entry.plugin);
    }
}

// ---------------------------------------------------------------------------
// Cascade depth cap
// ---------------------------------------------------------------------------

/// Calling dispatch_event with parent_dispatch_depth already at the cap
/// logs a warning and returns an empty Vec without firing subscribers.
/// This is the mechanism that breaks event-driven cycles: each level
/// of cascade increments the depth; when a subscriber's own publish
/// reaches the cap, that publish is refused.
#[tokio::test(flavor = "multi_thread")]
async fn dispatch_event_refuses_at_cap() {
    let kernel = boot_with(vec![manifest(
        "handler",
        &[],
        one_action(
            "on_ping",
            action_subscribing(
                vec![step("noop", "set_var", json!({"name": "x", "value": 1}))],
                &["ping"],
            ),
        ),
    )]);

    // Simulate "we're already at the cap" by calling with parent depth
    // = DISPATCH_MAX_DEPTH. Should refuse to dispatch.
    let results = kernel
        .dispatch_event(
            "ping",
            payload(json!({})),
            &json!({}),
            &ExecutionContext::default(),
            DISPATCH_MAX_DEPTH,
        )
        .await;
    assert!(results.is_empty(), "should refuse at cap");

    // Just below the cap: still allowed.
    let results = kernel
        .dispatch_event(
            "ping",
            payload(json!({})),
            &json!({}),
            &ExecutionContext::default(),
            DISPATCH_MAX_DEPTH - 1,
        )
        .await;
    assert_eq!(results.len(), 1);
}
