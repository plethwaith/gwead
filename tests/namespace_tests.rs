//! Plugin identity is namespace + local name, and the namespace comes
//! from the embedder.
//!
//! If a plugin's identity were whatever its manifest said, identity
//! would be self-asserted — a manifest is a self-describing document —
//! and identity is what every authorization decision keys on, including
//! the trusted-step-type-provider gate. With first-come name
//! allocation, a manifest registering first under a trusted name would
//! inherit the trust.
//!
//! So identity is embedder-authenticated: the embedder supplies a
//! namespace at registration and the manifest supplies only the local
//! name. The composed identity is `<namespace>/<name>`, with the root
//! namespace spelled `""` so a single-namespace embedder needs no
//! namespacing at all.
//!
//! Two properties these tests exist to pin:
//!
//! 1. **Root is a true no-op.** Everything a single-namespace embedder
//!    sees — registry keys, grant strings, error text — is exactly the
//!    un-namespaced spelling.
//! 2. **A namespace actually isolates.** Not by convention, and not by
//!    a permission an embedder has to remember to withhold: a plugin
//!    cannot name its way out of its namespace, and cannot be redirected
//!    out of it either.

use gwead::kernel::{Kernel, KernelConfig};
use serde_json::{Value, json};

fn kernel() -> Kernel {
    Kernel::boot(KernelConfig::default()).expect("boot")
}

/// A plugin that returns a constant, so a successful dispatch is
/// distinguishable from a denied one by its value.
fn echo_plugin(name: &str, marker: &str, permissions: &[&str]) -> String {
    json!({
        "name": name,
        "permissions": permissions,
        "actions": {
            "go": { "steps": [{"id": "s", "type": "return", "params": {"value": marker}}] }
        },
    })
    .to_string()
}

/// A plugin whose action invokes `target` and returns what came back.
fn caller_plugin(name: &str, target: &str, permissions: &[&str]) -> String {
    json!({
        "name": name,
        "permissions": permissions,
        "actions": {
            "go": { "steps": [{"id": "call", "type": "invoke", "params": {"plugin": target, "action": "go", "input": {}}}] }
        },
    })
    .to_string()
}

async fn run(kernel: &std::sync::Arc<Kernel>, plugin: &str, action: &str) -> Result<Value, String> {
    kernel
        .execute(plugin, action, json!({}))
        .run()
        .await
        .map(|r| r.output)
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------
// Root namespace: the bare name
// ---------------------------------------------------------------------

/// The registry key in the root namespace is the bare manifest name —
/// not `"/vault"`. This is the whole reason root is spelled as the
/// empty string, and the thing that would silently break every
/// single-namespace embedder if qualification were an unconditional
/// concatenation.
#[test]
fn root_namespace_keys_on_the_bare_manifest_name() {
    let mut k = kernel();
    k.load_manifest(&echo_plugin("vault", "V", &[]))
        .register()
        .expect("loads");
    assert!(k.registry().get_manifest("vault").is_some());
    assert!(k.registry().get_manifest("/vault").is_none());
}

/// `.register()` with no namespace and the direct entry point have to
/// produce the same identity.
#[test]
fn the_builder_default_matches_the_direct_entry_point() {
    let mut a = kernel();
    a.load_manifest(&echo_plugin("vault", "V", &[]))
        .register()
        .expect("loads");

    let mut b = kernel();
    b.register_plugin_from_json(&echo_plugin("vault", "V", &[]))
        .expect("loads");

    let mut from_builder = a.registry().plugin_names();
    let mut from_direct = b.registry().plugin_names();
    from_builder.sort_unstable();
    from_direct.sort_unstable();
    assert_eq!(from_builder, from_direct);
}

/// Explicitly passing the root namespace is the same as not passing one.
#[test]
fn the_empty_namespace_is_the_root_namespace() {
    let mut k = kernel();
    k.load_manifest(&echo_plugin("vault", "V", &[]))
        .in_namespace("")
        .register()
        .expect("loads");
    assert!(k.registry().get_manifest("vault").is_some());
}

// ---------------------------------------------------------------------
// Namespaced identity
// ---------------------------------------------------------------------

#[test]
fn a_namespaced_plugin_is_keyed_by_its_qualified_identity() {
    let mut k = kernel();
    k.load_manifest(&echo_plugin("billing", "B", &[]))
        .in_namespace("tenant42")
        .register()
        .expect("loads");
    assert!(k.registry().get_manifest("tenant42/billing").is_some());
    assert!(
        k.registry().get_manifest("billing").is_none(),
        "the local name alone must not be a registry key, or namespacing buys nothing"
    );
}

/// The collision embedder-authenticated identity exists to prevent. Two
/// tenants ship the same manifest; without namespacing the second
/// registration would be rejected as a duplicate, and whoever got there
/// first would own the name.
#[test]
fn two_namespaces_may_hold_the_same_local_name() {
    let mut k = kernel();
    let manifest = echo_plugin("inventory", "X", &[]);
    k.load_manifest(&manifest)
        .in_namespace("tenant_a")
        .register()
        .expect("tenant A loads");
    k.load_manifest(&manifest)
        .in_namespace("tenant_b")
        .register()
        .expect("tenant B loads the identical manifest");

    assert!(k.registry().get_manifest("tenant_a/inventory").is_some());
    assert!(k.registry().get_manifest("tenant_b/inventory").is_some());
}

/// Within one namespace, first-come still wins — that is the tenant's
/// own business, and it is what makes the *cross*-namespace guarantee
/// meaningful rather than an accident of key formatting.
#[test]
fn duplicate_names_within_one_namespace_are_still_rejected() {
    let mut k = kernel();
    let manifest = echo_plugin("inventory", "X", &[]);
    k.load_manifest(&manifest)
        .in_namespace("tenant_a")
        .register()
        .expect("first load");
    k.load_manifest(&manifest)
        .in_namespace("tenant_a")
        .register()
        .expect_err("second load into the same namespace collides");
}

/// A namespace is not something a manifest can talk its way into: the
/// name grammar rejects the separator, so there is no spelling of
/// `name` that reaches another namespace.
#[test]
fn a_manifest_cannot_choose_its_own_namespace() {
    let mut k = kernel();
    k.load_manifest(&echo_plugin("tenant_a/inventory", "X", &[]))
        .in_namespace("tenant_b")
        .register()
        .expect_err("a manifest may not embed a namespace in its name");
}

// ---------------------------------------------------------------------
// References resolve inside the caller's namespace
// ---------------------------------------------------------------------

/// The positive case: inside a namespace, a plain reference reaches the
/// plugin of that name *in the same namespace*. Without this, a
/// namespaced plugin could not invoke anything at all.
#[tokio::test]
async fn a_reference_resolves_within_the_callers_namespace() {
    let mut k = kernel();
    k.load_manifest(&echo_plugin("billing", "TENANT_A_BILLING", &[]))
        .in_namespace("tenant_a")
        .register()
        .expect("callee loads");
    k.load_manifest(&caller_plugin(
        "shop",
        "billing",
        &["invoke:plugin:billing"],
    ))
    .in_namespace("tenant_a")
    .register()
    .expect("caller loads");
    let k = k.into_arc();

    let out = run(&k, "tenant_a/shop", "go").await.expect("dispatch");
    assert_eq!(out, json!("TENANT_A_BILLING"));
}

/// The isolation case: the identical manifest pair in a second
/// namespace reaches its *own* billing plugin, not the first one's.
/// Same manifest text, same grant, different callee.
#[tokio::test]
async fn the_same_reference_in_another_namespace_reaches_a_different_plugin() {
    let mut k = kernel();
    k.load_manifest(&echo_plugin("billing", "TENANT_A_BILLING", &[]))
        .in_namespace("tenant_a")
        .register()
        .expect("A callee");
    k.load_manifest(&echo_plugin("billing", "TENANT_B_BILLING", &[]))
        .in_namespace("tenant_b")
        .register()
        .expect("B callee");

    let shop = caller_plugin("shop", "billing", &["invoke:plugin:billing"]);
    k.load_manifest(&shop)
        .in_namespace("tenant_a")
        .register()
        .expect("A caller");
    k.load_manifest(&shop)
        .in_namespace("tenant_b")
        .register()
        .expect("B caller");
    let k = k.into_arc();

    assert_eq!(
        run(&k, "tenant_a/shop", "go").await.expect("A dispatch"),
        json!("TENANT_A_BILLING")
    );
    assert_eq!(
        run(&k, "tenant_b/shop", "go").await.expect("B dispatch"),
        json!("TENANT_B_BILLING")
    );
}

// ---------------------------------------------------------------------
// The ancestor chain: upward only
// ---------------------------------------------------------------------
//
// A reference resolves along the caller's chain — own namespace first,
// then root — and dispatch may point up that chain, never down it and
// never across. Grants resolve through the same walk, so a grant and
// the reference it authorises always name the same plugin.

/// A tenant reaches a global plugin it has no local shadow for. This is
/// most of what "system plugins are available to everyone" is for.
#[tokio::test]
async fn a_tenant_reaches_a_global_plugin_by_name() {
    let mut k = kernel();
    k.load_manifest(&echo_plugin("billing", "ROOT_BILLING", &[]))
        .register()
        .expect("root callee");
    k.load_manifest(&caller_plugin(
        "shop",
        "billing",
        &["invoke:plugin:billing"],
    ))
    .in_namespace("tenant_a")
    .register()
    .expect("namespaced caller");
    let k = k.into_arc();

    assert_eq!(
        run(&k, "tenant_a/shop", "go")
            .await
            .expect("upward dispatch"),
        json!("ROOT_BILLING")
    );
}

/// Upward is not ambient: the `invoke:` grant still applies.
#[tokio::test]
async fn reaching_a_global_plugin_still_needs_the_grant() {
    let mut k = kernel();
    k.load_manifest(&echo_plugin("billing", "ROOT_BILLING", &[]))
        .register()
        .expect("root callee");
    k.load_manifest(&caller_plugin("shop", "billing", &[]))
        .in_namespace("tenant_a")
        .register()
        .expect("namespaced caller");
    let k = k.into_arc();

    let err = run(&k, "tenant_a/shop", "go").await.expect_err("no grant");
    assert!(
        err.contains("lacks invoke:plugin:billing") && !err.contains("ROOT_BILLING"),
        "{err}"
    );
}

/// The nearest candidate wins: a tenant's own `billing` shadows the
/// global one for that tenant only, and the grant follows the
/// reference to the same plugin.
#[tokio::test]
async fn a_local_plugin_shadows_the_global_one_for_its_own_tenant() {
    let mut k = kernel();
    k.load_manifest(&echo_plugin("billing", "ROOT_BILLING", &[]))
        .register()
        .expect("root callee");
    k.load_manifest(&echo_plugin("billing", "TENANT_A_BILLING", &[]))
        .in_namespace("tenant_a")
        .register()
        .expect("A's own callee");
    let shop = caller_plugin("shop", "billing", &["invoke:plugin:billing"]);
    k.load_manifest(&shop)
        .in_namespace("tenant_a")
        .register()
        .expect("A caller");
    k.load_manifest(&shop)
        .in_namespace("tenant_b")
        .register()
        .expect("B caller");
    let k = k.into_arc();

    assert_eq!(
        run(&k, "tenant_a/shop", "go").await.expect("A dispatch"),
        json!("TENANT_A_BILLING"),
        "tenant_a has its own billing, so its reference stops there"
    );
    assert_eq!(
        run(&k, "tenant_b/shop", "go").await.expect("B dispatch"),
        json!("ROOT_BILLING"),
        "tenant_b has no shadow, so its reference walks up to root"
    );
}

/// Two sibling tenants cannot reach each other, even with identical
/// names and a grant that would match the name. The reference walks
/// *up*, and tenant_b is not on tenant_a's chain.
#[tokio::test]
async fn a_tenant_cannot_reach_a_sibling_tenant() {
    let mut k = kernel();
    k.load_manifest(&echo_plugin("billing", "TENANT_B_BILLING", &[]))
        .in_namespace("tenant_b")
        .register()
        .expect("B callee");
    k.load_manifest(&caller_plugin(
        "shop",
        "billing",
        &["invoke:plugin:billing"],
    ))
    .in_namespace("tenant_a")
    .register()
    .expect("A caller");
    let k = k.into_arc();

    let err = run(&k, "tenant_a/shop", "go").await.expect_err("sideways");
    assert!(!err.contains("TENANT_B_BILLING"), "{err}");
}

/// Downward is refused even when an orchestrator redirect names the
/// target outright: a global plugin reachable by every tenant must not
/// be usable as a deputy into one of them.
#[tokio::test]
async fn a_global_plugin_cannot_be_redirected_into_a_tenant() {
    use gwead::kernel::dispatch::{
        DispatchContext, DispatchError, DispatchOrchestrator, DispatchPlan, DispatchRequest,
    };
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    /// Resolves every dispatch to `tenant_a/private`, whoever asked.
    struct RedirectDown;
    impl DispatchOrchestrator for RedirectDown {
        fn prepare_dispatch<'a>(
            &'a self,
            request: DispatchRequest<'a>,
            ctx: DispatchContext<'a>,
        ) -> Pin<Box<dyn Future<Output = Result<DispatchPlan, DispatchError>> + Send + 'a>>
        {
            let action = match request {
                DispatchRequest::ByPlugin { action, .. }
                | DispatchRequest::ByRole { action, .. } => action.to_string(),
                _ => unreachable!("no other request shapes exist"),
            };
            let plan = DispatchPlan::new("tenant_a/private", action)
                .with_config(ctx.caller_config.clone());
            Box::pin(async move { Ok(plan) })
        }
    }

    let mut k =
        Kernel::boot(KernelConfig::default().with_dispatch_orchestrator(Arc::new(RedirectDown)))
            .expect("boot");
    k.load_manifest(&echo_plugin("private", "TENANT_A_PRIVATE", &[]))
        .in_namespace("tenant_a")
        .register()
        .expect("tenant callee");
    // A global plugin with the broadest grant there is.
    k.load_manifest(&caller_plugin("system", "private", &["invoke:plugin:*"]))
        .register()
        .expect("global caller");
    let k = k.into_arc();

    let err = run(&k, "system", "go").await.expect_err("downward");
    assert!(
        err.contains("never into a sibling or a descendant") && !err.contains("TENANT_A_PRIVATE"),
        "{err}"
    );
}

/// `invoke:plugin:*` means "any plugin in my own namespace". It never
/// reaches up a level: a global capability is reached by name, so the
/// manifest an operator reviews lists exactly which ones this tenant
/// touches.
#[tokio::test]
async fn the_invoke_wildcard_does_not_reach_global_plugins() {
    let mut k = kernel();
    k.load_manifest(&echo_plugin("billing", "ROOT_BILLING", &[]))
        .register()
        .expect("root callee");
    k.load_manifest(&caller_plugin("shop", "billing", &["invoke:plugin:*"]))
        .in_namespace("tenant_a")
        .register()
        .expect("namespaced caller");
    let k = k.into_arc();

    let err = run(&k, "tenant_a/shop", "go")
        .await
        .expect_err("wildcard stops at the level");
    assert!(
        err.contains("lacks invoke:plugin:billing") && !err.contains("ROOT_BILLING"),
        "{err}"
    );
}

/// The wildcard is the sharpest case. `invoke:plugin:*` is
/// `NamePattern::Any`, which matches every name there is — so if
/// containment were enforced by grants rather than structurally, this
/// grant would be a passport into every namespace.
#[tokio::test]
async fn the_invoke_wildcard_does_not_cross_namespaces() {
    let mut k = kernel();
    k.load_manifest(&echo_plugin("secrets", "TENANT_B_SECRETS", &[]))
        .in_namespace("tenant_b")
        .register()
        .expect("victim loads");

    // Name the victim by its fully qualified identity — the most direct
    // attempt available, and one the grammar refuses outright.
    k.load_manifest(&caller_plugin(
        "greedy",
        "tenant_b/secrets",
        &["invoke:plugin:*"],
    ))
    .in_namespace("tenant_a")
    .register()
    .expect_err("a qualified reference is reserved syntax and is rejected at load");

    // And via a bare name, which resolves inside tenant_a and so cannot
    // name tenant_b's plugin at all.
    k.load_manifest(&caller_plugin("greedy", "secrets", &["invoke:plugin:*"]))
        .in_namespace("tenant_a")
        .register()
        .expect("loads; the reference resolves to tenant_a/secrets");
    let k = k.into_arc();

    let err = run(&k, "tenant_a/greedy", "go")
        .await
        .expect_err("tenant_a/secrets does not exist");
    assert!(
        !err.contains("TENANT_B_SECRETS"),
        "the wildcard must not have reached another namespace: {err}"
    );
}

// ---------------------------------------------------------------------
// Trust
// ---------------------------------------------------------------------

/// The hazard embedder-authenticated identity exists to close: trust
/// keyed on a name a manifest asserts about itself. A plugin in a
/// namespace must not be able to satisfy a root-namespace trust entry
/// by naming itself after the trusted plugin.
#[test]
fn a_namespaced_plugin_cannot_inherit_root_trust_by_naming_itself() {
    let runtime = json!({
        "name": "lua_rt",
        "permissions": ["provide:step_type:script:lua"],
        "wasmModules": { "rt": { "base64": runtime_module_b64() } },
        "stepTypeImpls": [{"stepType": "script", "matches": "lua", "wasmModule": "rt"}],
    })
    .to_string();

    // The embedder trusts the plugin it ships, in root.
    let mut k =
        Kernel::boot(KernelConfig::default().trusting_step_type_provider("lua_rt")).expect("boot");

    // A tenant ships a manifest calling itself `lua_rt` too. Its
    // identity is `tenant_evil/lua_rt`, which is not the trusted entry.
    let err = k
        .load_manifest(&runtime)
        .in_namespace("tenant_evil")
        .register()
        .expect_err("a namespaced plugin must not inherit root-namespace trust");
    assert!(
        err.to_string().contains("trusted_step_type_providers"),
        "the rejection should be the trust gate: {err}"
    );

    // The genuinely trusted one still loads, so the gate rejected the
    // namespace and not the manifest.
    k.load_manifest(&runtime)
        .register()
        .expect("the root-namespace runtime is trusted and loads");
}

/// Trust can be granted to a namespaced plugin explicitly, and the pair
/// composes to the same identity the registry uses.
#[test]
fn trust_can_be_granted_to_a_namespaced_plugin() {
    let runtime = json!({
        "name": "lua_rt",
        "permissions": ["provide:step_type:script:lua"],
        "wasmModules": { "rt": { "base64": runtime_module_b64() } },
        "stepTypeImpls": [{"stepType": "script", "matches": "lua", "wasmModule": "rt"}],
    })
    .to_string();

    let mut k =
        Kernel::boot(KernelConfig::default().trusting_step_type_provider_in("tenant_a", "lua_rt"))
            .expect("boot");
    k.load_manifest(&runtime)
        .in_namespace("tenant_a")
        .register()
        .expect("the explicitly trusted namespaced plugin loads");
}

// ---------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------

/// A reload is a swap of contents, never a relocation. If the namespace
/// were not retained, reloading would silently move a plugin to root —
/// changing its identity behind every grant naming it, and in a
/// multi-tenant embedder promoting a tenant's plugin into the
/// embedder's own space.
#[test]
fn reload_keeps_the_plugin_in_its_namespace() {
    let mut k = kernel();
    let handle = k
        .load_manifest(&echo_plugin("billing", "V1", &[]))
        .in_namespace("tenant42")
        .register()
        .expect("loads");

    k.reload_manifest(handle, &echo_plugin("billing", "V2", &[]))
        .expect("reloads");

    assert!(k.registry().get_manifest("tenant42/billing").is_some());
    assert!(
        k.registry().get_manifest("billing").is_none(),
        "reload must not relocate the plugin to the root namespace"
    );
}

/// Unload has to resolve the same qualified key registration used, or a
/// namespaced plugin would be unremovable.
#[test]
fn unload_removes_a_namespaced_plugin() {
    let mut k = kernel();
    let handle = k
        .load_manifest(&echo_plugin("billing", "V", &[]))
        .in_namespace("tenant42")
        .register()
        .expect("loads");
    k.unload_manifest(handle).expect("unloads");
    assert!(k.registry().get_manifest("tenant42/billing").is_none());
}

// ---------------------------------------------------------------------
// Roles resolve by chain too
// ---------------------------------------------------------------------
//
// A role is an identity like a plugin: a definition loads into a
// namespace as `ns/ROLE`, a fulfiller's bare `roles: [..]` entry binds
// to the nearest defined contract up its chain, and a caller's role
// dispatch walks *its own* chain for fulfillers, seeing only plugins
// on that chain, nearest first.

fn spi_def(role: &str) -> String {
    json!({
        "name": role,
        "version": "1.0",
        "actions": { "go": { "input": {}, "output": {} } },
    })
    .to_string()
}

/// A plugin that fulfils `role` and returns a constant.
fn fulfiller(name: &str, role: &str, marker: &str) -> String {
    json!({
        "name": name,
        "roles": [role],
        "actions": {
            "go": { "steps": [{"id": "s", "type": "return", "params": {"value": marker}}] }
        },
    })
    .to_string()
}

/// A plugin whose action dispatches by `role` and returns what came back.
fn role_caller(name: &str, role: &str) -> String {
    json!({
        "name": name,
        "permissions": [format!("invoke:role:{role}")],
        "actions": {
            "go": { "steps": [{"id": "call", "type": "invoke", "params": {"role": role, "action": "go", "input": {}}}] }
        },
    })
    .to_string()
}

/// A tenant may define its own contract. It lives at `tenant/ROLE`,
/// is fulfilled and dispatched within the tenant, and does not touch
/// — or require — a global definition of the same name.
#[tokio::test]
async fn a_tenant_may_define_its_own_role() {
    let mut k = kernel();
    k.load_manifest(&spi_def("SOME_CONTRACT"))
        .in_namespace("tenant42")
        .register()
        .expect("a tenant-defined contract loads");
    k.load_manifest(&fulfiller("impl", "SOME_CONTRACT", "TENANT42_IMPL"))
        .in_namespace("tenant42")
        .register()
        .expect("fulfiller validates against the tenant's contract");
    k.load_manifest(&role_caller("app", "SOME_CONTRACT"))
        .in_namespace("tenant42")
        .register()
        .expect("caller loads");
    let k = k.into_arc();

    assert_eq!(
        run(&k, "tenant42/app", "go")
            .await
            .expect("tenant-scoped role dispatch"),
        json!("TENANT42_IMPL")
    );
    // The embedder's root-scoped lookup does not see it.
    let err = k
        .execute_by_role("SOME_CONTRACT", "go", Value::Null, &Value::Null)
        .await
        .expect_err("no root fulfiller");
    assert!(err.to_string().contains("No plugin registered"), "{err}");
}

/// A tenant fulfiller of a GLOBAL contract is visible to that tenant's
/// callers and to nobody else — above all not to a global caller,
/// which would otherwise be capturable by whichever tenant registered
/// a fulfiller. Fulfilment resolves by the calling plugin's chain.
#[tokio::test]
async fn a_tenant_fulfiller_of_a_global_role_is_invisible_above_and_beside_it() {
    let mut k = kernel();
    k.register_spi_from_json("LLM_CHAT", &spi_def("LLM_CHAT"))
        .expect("global contract");
    // Only a tenant fulfils it.
    k.load_manifest(&fulfiller("llm", "LLM_CHAT", "TENANT_A_LLM"))
        .in_namespace("tenant_a")
        .register()
        .expect("tenant fulfiller");
    k.load_manifest(&role_caller("system", "LLM_CHAT"))
        .register()
        .expect("global caller");
    k.load_manifest(&role_caller("app", "LLM_CHAT"))
        .in_namespace("tenant_a")
        .register()
        .expect("tenant_a caller");
    k.load_manifest(&role_caller("app", "LLM_CHAT"))
        .in_namespace("tenant_b")
        .register()
        .expect("tenant_b caller");
    let k = k.into_arc();

    assert_eq!(
        run(&k, "tenant_a/app", "go").await.expect("own tenant"),
        json!("TENANT_A_LLM")
    );
    let err = run(&k, "system", "go")
        .await
        .expect_err("global caller sees no fulfiller");
    assert!(
        err.contains("role 'LLM_CHAT' has no registered plugin") && !err.contains("TENANT_A_LLM"),
        "{err}"
    );
    let err = run(&k, "tenant_b/app", "go")
        .await
        .expect_err("sibling sees no fulfiller");
    assert!(!err.contains("TENANT_A_LLM"), "{err}");
}

/// Nearest first: with both a global and a tenant fulfiller of a global
/// contract, the tenant's callers get the tenant's, global callers and
/// other tenants get the global one.
#[tokio::test]
async fn the_nearest_fulfiller_wins() {
    let mut k = kernel();
    k.register_spi_from_json("LLM_CHAT", &spi_def("LLM_CHAT"))
        .expect("global contract");
    k.load_manifest(&fulfiller("llm", "LLM_CHAT", "GLOBAL_LLM"))
        .register()
        .expect("global fulfiller");
    k.load_manifest(&fulfiller("llm", "LLM_CHAT", "TENANT_A_LLM"))
        .in_namespace("tenant_a")
        .register()
        .expect("tenant fulfiller");
    k.load_manifest(&role_caller("system", "LLM_CHAT"))
        .register()
        .expect("global caller");
    k.load_manifest(&role_caller("app", "LLM_CHAT"))
        .in_namespace("tenant_a")
        .register()
        .expect("tenant_a caller");
    k.load_manifest(&role_caller("app", "LLM_CHAT"))
        .in_namespace("tenant_b")
        .register()
        .expect("tenant_b caller");
    let k = k.into_arc();

    assert_eq!(
        run(&k, "tenant_a/app", "go").await.unwrap(),
        json!("TENANT_A_LLM")
    );
    assert_eq!(
        run(&k, "tenant_b/app", "go").await.unwrap(),
        json!("GLOBAL_LLM")
    );
    assert_eq!(run(&k, "system", "go").await.unwrap(), json!("GLOBAL_LLM"));
    assert_eq!(
        k.execute_by_role("LLM_CHAT", "go", Value::Null, &Value::Null)
            .await
            .expect("embedder lookup is root-scoped")
            .output,
        json!("GLOBAL_LLM")
    );
}

/// A tenant-defined contract shadows a global one of the same name for
/// that tenant's plugins: a tenant fulfiller binds to the tenant's
/// contract (and is validated against it), not the global one.
#[tokio::test]
async fn a_tenant_contract_shadows_the_global_one_for_its_own_plugins() {
    let mut k = kernel();
    k.register_spi_from_json("LLM_CHAT", &spi_def("LLM_CHAT"))
        .expect("global contract");
    // The tenant's version of the contract demands an action the
    // global one does not.
    k.load_manifest(
        &json!({
            "name": "LLM_CHAT",
            "version": "1.0",
            "actions": { "go": { "input": {}, "output": {} },
                         "stream": { "input": {}, "output": {} } },
        })
        .to_string(),
    )
    .in_namespace("tenant_a")
    .register()
    .expect("tenant contract");

    let err = k
        .load_manifest(&fulfiller("llm", "LLM_CHAT", "X"))
        .in_namespace("tenant_a")
        .register()
        .expect_err("validated against the tenant's contract, which it does not satisfy");
    assert!(err.to_string().contains("stream"), "{err}");

    k.load_manifest(&fulfiller("llm", "LLM_CHAT", "X"))
        .in_namespace("tenant_b")
        .register()
        .expect("tenant_b has no contract of its own, so the global one applies");
}

/// Unloading a tenant's contract is refused while a tenant plugin
/// still binds to it, exactly as for a global contract.
#[test]
fn a_tenant_contract_cannot_be_unloaded_while_fulfilled() {
    let mut k = kernel();
    let def = k
        .load_manifest(&spi_def("SOME_CONTRACT"))
        .in_namespace("tenant42")
        .register()
        .expect("contract");
    k.load_manifest(&fulfiller("impl", "SOME_CONTRACT", "X"))
        .in_namespace("tenant42")
        .register()
        .expect("fulfiller");
    let err = k.unload_manifest(def).expect_err("still claimed");
    assert!(err.to_string().contains("still claimed"), "{err}");
}

/// The builder must not be usable by accident: a chain that never calls
/// `.register()` registers nothing, and `#[must_use]` is what turns
/// that from a silent no-op into a compile warning.
#[test]
fn an_unregistered_builder_registers_nothing() {
    let mut k = kernel();
    let _ = k.load_manifest(&echo_plugin("vault", "V", &[]));
    assert!(
        k.registry().get_manifest("vault").is_none(),
        "building a load without calling register() must not register"
    );
}

fn runtime_module_b64() -> String {
    use base64::Engine as _;
    let wasm = wat::parse_str(
        r#"(module
             (memory (export "memory") 1)
             (func (export "alloc") (param i32) (result i32) i32.const 0)
             (func (export "execute") (param i32 i32 i32 i32) (result i32) i32.const 1))"#,
    )
    .expect("wat parses");
    base64::engine::general_purpose::STANDARD.encode(&wasm)
}
