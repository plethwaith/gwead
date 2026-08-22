//! Empty-embedder smoke test — asserts the kernel boots and dispatches
//! with no embedder types in the dependency closure.
//!
//! Boots a kernel with `KernelConfig::default()` — no orchestrator,
//! no HTTP client, no storage, no app code at all — registers a
//! trivial plugin with one action, dispatches that action by role,
//! and asserts the result comes back. The test exists to prove that
//! gwead is genuinely usable as a standalone engine without
//! any embedding application in the dependency closure.
//!
//! If this file ever fails to compile because of a missing app-shaped
//! type or trait, that's a regression — the kernel grew an opinion
//! about something an embedder is supposed to own.

use std::sync::Arc;

use indexmap::IndexMap;
use serde_json::{Value, json};

use gwead::kernel::types::*;
use gwead::kernel::{Kernel, KernelConfig};

#[tokio::test(flavor = "multi_thread")]
async fn empty_embedder_can_boot_register_and_dispatch_a_role() {
    // 1. Boot with literally nothing supplied — no orchestrator, no
    //    HTTP client, no storage. Kernel falls back to defaults.
    let mut kernel = Kernel::boot(KernelConfig::default()).expect("boot");

    // 2. Register a trivial plugin: one role, one action with one
    //    `return` step (intrinsic — handled directly by the kernel's
    //    runtime, no embedder-provided step type plugin required).
    let mut actions: IndexMap<String, Action> = IndexMap::new();
    actions.insert("ping".to_string(), {
        let mut m = Action::new(vec![StepDef::new(
            "s".to_string(),
            "return".to_string(),
            json!({"value": {"greeting": "hello"}}),
        )]);
        m.result_mapping = {
            let mut m = IndexMap::new();
            m.insert(
                "greeting".to_string(),
                json!({"path": "$steps.s.result.greeting"}),
            );
            m
        };
        m
    });
    let manifest = {
        let mut m = PluginManifest::new("ping_plugin".to_string());
        m.roles = vec!["PING".to_string()];
        m.actions = actions;
        m
    };
    kernel.register_plugin(manifest).expect("registers");
    let _arc: Arc<Kernel> = kernel.into_arc();

    // 3. Dispatch by-role through the public kernel API. The default
    //    orchestrator (no embedder-supplied one) does first-match
    //    selection + caller-namespace config.
    let result = _arc
        .execute_by_role("PING", "ping", Value::Null, &Value::Null)
        .await
        .expect("dispatch succeeds");
    assert_eq!(result.output, json!({"greeting": "hello"}));
}
