//! Using a step type you did not define requires a grant — on the
//! direct path, not just the alias path.
//!
//! If [`check_step_type`] were consulted only on alias dispatch, a
//! step whose `type` named another plugin's *native* step type would go
//! straight to `run_step` → `call_host_fn("step_<name>")` with no
//! permission check and no namespace check. A plugin declaring nothing
//! — no `stepTypeDefs`, no `permissions` — could execute another
//! plugin's privileged body by naming it, and a plugin in a namespace
//! could do the same to a **root** plugin's body, crossing the boundary
//! namespaces exist to draw.
//!
//! This is the general hazard of a default-deny gate placed on the call
//! sites its author enumerated while a further path reaches the same
//! capability; the same hazard applies to `dispatch_role`, the
//! orchestrator-resolved invoke target, `io.invoke_streaming`, and the
//! implRef binding. It is why the decision lives in one function on
//! `Kernel` rather than inline at a dispatch site.
//!
//! The rule, in order: reserved intrinsics are always allowed; your own
//! step types are always allowed; a def marked `freelyUsable` is
//! allowed; otherwise `step_type:<name>` is required.

use std::future::Future;
use std::pin::Pin;

use gwead::kernel::native_impls::NativeStepImplTable;
use gwead::kernel::{Kernel, KernelConfig, PluginExecution, StepError, StepOutput};
use serde_json::{Value, json};

/// Stands in for the thing that makes this matter: an embedder body that
/// reaches a privileged host resource — a signer, a DB pool, a cloud
/// client — on behalf of whoever calls it.
fn privileged_body<'a>(
    _ex: &'a mut (dyn PluginExecution + Send),
    _p: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move { Ok(StepOutput::from(json!("SIGNED-BY-VAULT"))) })
}

/// A kernel with `vault` owning a `sign` step type. `freely_usable`
/// controls whether vault declares it safe for anyone to call.
fn boot_with_vault(freely_usable: bool) -> Kernel {
    let mut impls = NativeStepImplTable::empty();
    impls
        .insert("myapp.vault.sign", privileged_body)
        .expect("fresh table");
    let mut k = Kernel::boot(KernelConfig::default().with_native_step_impls(impls)).expect("boot");
    let mut def = json!({"name": "vault.sign"});
    if freely_usable {
        def["freelyUsable"] = json!(true);
    }
    k.register_plugin_from_json(
        &json!({
            "name": "vault",
            "stepTypeDefs": [def],
            "stepTypeImpls": [{"stepType": "vault.sign", "kind": "native",
                               "implRef": "myapp.vault.sign"}],
            "actions": {"noop": {"steps": []}}
        })
        .to_string(),
    )
    .expect("vault registers");
    k
}

/// A plugin whose action names `sign`. `permissions` is the only thing
/// that varies across these tests.
fn borrower(name: &str, permissions: &[&str]) -> String {
    json!({
        "name": name,
        "permissions": permissions,
        "actions": {"go": {
            "steps": [{"id": "s", "type": "vault.sign"}],
            "resultMapping": {"out": {"path": "$", "source": "s"}}
        }}
    })
    .to_string()
}

async fn run(kernel: &std::sync::Arc<Kernel>, plugin: &str) -> Result<Value, String> {
    kernel
        .execute(plugin, "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .map(|r| r.output["out"].clone())
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// The hole
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_declaring_nothing_cannot_run_another_plugins_body() {
    let mut k = boot_with_vault(false);
    k.register_plugin_from_json(&borrower("evil", &[]))
        .expect("the manifest is well-formed; the refusal is at dispatch");
    let err = run(&k.into_arc(), "evil")
        .await
        .expect_err("undeclared plugin must not reach vault's body");
    assert!(err.contains("may not use step type 'vault.sign'"), "{err}");
    assert!(
        err.contains("defined by plugin 'vault'"),
        "the refusal names the owner, so whoever has to fix it knows who to ask: {err}"
    );
}

/// The variant that matters most: the borrower is in its own namespace
/// and the body belongs to a **root** plugin. Namespace containment
/// guards `invoke` and role dispatch; a gate that skipped step-type
/// dispatch would cross a boundary the namespace tests claim is sealed.
#[tokio::test(flavor = "multi_thread")]
async fn a_namespaced_plugin_cannot_run_a_root_plugins_body() {
    let mut k = boot_with_vault(false);
    k.load_manifest(&borrower("evil", &[]))
        .in_namespace("tenant_evil")
        .register()
        .expect("registers");
    let err = run(&k.into_arc(), "tenant_evil/evil")
        .await
        .expect_err("a tenant must not reach a root plugin's body by naming its step type");
    assert!(err.contains("may not use step type 'vault.sign'"), "{err}");
}

// ---------------------------------------------------------------------------
// The three ways through
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn the_grant_permits_it() {
    let mut k = boot_with_vault(false);
    k.register_plugin_from_json(&borrower("friend", &["step_type:vault.sign"]))
        .expect("registers");
    assert_eq!(
        run(&k.into_arc(), "friend").await.expect("granted"),
        json!("SIGNED-BY-VAULT")
    );
}

/// The provider decides whether use is privileged. A shared utility is
/// marked open once by its author, and consumers pay nothing — which is
/// what keeps "define a step type once, reuse it everywhere" cheap.
#[tokio::test(flavor = "multi_thread")]
async fn a_freely_usable_def_needs_no_grant() {
    let mut k = boot_with_vault(true);
    k.register_plugin_from_json(&borrower("anyone", &[]))
        .expect("registers");
    assert_eq!(
        run(&k.into_arc(), "anyone").await.expect("freelyUsable"),
        json!("SIGNED-BY-VAULT")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn your_own_step_types_need_no_grant() {
    let mut impls = NativeStepImplTable::empty();
    impls.insert("myapp.solo.work", privileged_body).expect("t");
    let mut k = Kernel::boot(KernelConfig::default().with_native_step_impls(impls)).expect("boot");
    k.register_plugin_from_json(
        &json!({
            "name": "solo",
            "stepTypeDefs": [{"name": "solo.work"}],
            "stepTypeImpls": [{"stepType": "solo.work", "kind": "native",
                               "implRef": "myapp.solo.work"}],
            "actions": {"go": {
                "steps": [{"id": "s", "type": "solo.work"}],
                "resultMapping": {"out": {"path": "$", "source": "s"}}
            }}
        })
        .to_string(),
    )
    .expect("registers");
    assert_eq!(
        run(&k.into_arc(), "solo").await.expect("own type"),
        json!("SIGNED-BY-VAULT")
    );
}

// ---------------------------------------------------------------------------
// Properties that must not regress
// ---------------------------------------------------------------------------

/// The decision is resolved by the kernel at invocation setup rather
/// than looked up per step, specifically so this keeps working:
/// `execute(..).run()` is documented to need no `Arc` for actions that
/// do not invoke other plugins. A gate that demanded a back-reference
/// would have broken that for every action containing a `let`.
#[tokio::test(flavor = "multi_thread")]
async fn intrinsics_still_run_on_a_kernel_that_was_never_wrapped() {
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    k.register_plugin_from_json(
        &json!({
            "name": "own",
            "actions": {"go": {
                "steps": [{"id": "s", "type": "let", "params": {"value": 7}}],
                "resultMapping": {"out": {"path": "$", "source": "s"}}
            }}
        })
        .to_string(),
    )
    .expect("registers");
    let out = k
        .execute("own", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect("no Arc needed for kernel primitives");
    assert_eq!(out.output["out"], json!(7));
}

/// Reserved intrinsics are not any plugin's property, even though
/// `gwead_intrinsics` is nominally their owner. If they went through the
/// ownership check, every manifest in existence would need
/// `step_type:let`.
#[tokio::test(flavor = "multi_thread")]
async fn intrinsics_are_not_gated_by_ownership() {
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    k.register_plugin_from_json(
        &json!({
            "name": "p",
            "actions": {"go": {
                "steps": [
                    {"id": "a", "type": "let", "params": {"value": 1}},
                    {"id": "b", "type": "try", "params": {"try": [{"id": "c", "type": "let", "params": {"value": 2}}]}}
                ],
                "resultMapping": {"out": {"path": "$", "source": "a"}}
            }}
        })
        .to_string(),
    )
    .expect("registers");
    assert!(
        run(&k.into_arc(), "p").await.is_ok(),
        "a plugin with no permissions uses kernel primitives freely"
    );
}
