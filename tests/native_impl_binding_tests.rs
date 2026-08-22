//! Whose native step body is a manifest allowed to bind?
//!
//! Two questions govern a `stepTypeImpls` entry, and a check that asks
//! only the first leaves a hole:
//!
//! | Question | Gate |
//! |---|---|
//! | Which slot am I filling? | `provide:step_type:` |
//! | Whose body am I binding? | *(this)* |
//!
//! If `implRef` resolution were a single flat lookup against a global
//! table keyed by the raw string, a plugin could declare a step type of
//! its own — satisfying the first gate perfectly honestly — and point
//! `implRef` at a privileged body somebody else shipped: a plugin named
//! `evil`, declaring **no** permissions, would run `myapp.vault.sign`.
//!
//! The rule pinned here: you may bind a body you own, where ownership
//! is the implRef's middle segment matching your own name *and* you are
//! in the root namespace. Anything else needs
//! `bind:native_impl:<implRef>` in the manifest **and** the exact
//! `(identity, implRef)` pair authorised by the embedder.
//!
//! The permission is spelled `bind:`, not `provide:`, because the two
//! point opposite ways. `provide:` is supply-shaped — danger flows
//! outward, since everyone's steps of that type then run in your code.
//! Binding is consumption-shaped — danger flows at the body's owner,
//! since you are running privileged code you did not ship.

use std::future::Future;
use std::pin::Pin;

use gwead::kernel::host_api::{PluginExecution, StepError, StepOutput};
use gwead::kernel::native_impls::NativeStepImplTable;
use gwead::kernel::{Kernel, KernelConfig};
use serde_json::{Value, json};

const MARKER: &str = "PRIVILEGED-VAULT-OPERATION-PERFORMED";

/// Stands in for a privileged body the embedder compiled in for its own
/// vault plugin — in production the sort of thing holding a signing
/// key, an S3 client, or a database handle.
fn vault_privileged_body<'a>(
    _ex: &'a mut (dyn PluginExecution + Send),
    _params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move { Ok(StepOutput::from(json!(MARKER))) })
}

fn table() -> NativeStepImplTable {
    let mut t = NativeStepImplTable::empty();
    t.insert("myapp.vault.sign", vault_privileged_body)
        .expect("fresh table");
    t
}

fn kernel() -> Kernel {
    Kernel::boot(KernelConfig::default().with_native_step_impls(table())).expect("boot")
}

/// A manifest binding `myapp.vault.sign` under a step type it defines
/// itself — the hole's exact shape.
fn binder(name: &str, permissions: &[&str]) -> String {
    json!({
        "name": name,
        "version": "0.0.0",
        "permissions": permissions,
        "stepTypeDefs": [{"name": format!("{name}.looks_innocent")}],
        "stepTypeImpls": [
            {"stepType": format!("{name}.looks_innocent"), "kind": "native", "implRef": "myapp.vault.sign"}
        ],
        "actions": { "go": { "steps": [{"id": "s", "type": format!("{name}.looks_innocent")}] } },
    })
    .to_string()
}

// ---------------------------------------------------------------------
// The hole
// ---------------------------------------------------------------------

/// The hole, reduced. `evil` owns nothing and declares
/// nothing; the binding must be refused **at registration**, before the
/// body is even resolved.
#[test]
fn a_plugin_cannot_bind_a_body_it_does_not_own() {
    let err = kernel()
        .register_plugin_from_json(&binder("evil", &[]))
        .expect_err("binding another plugin's native body must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("myapp.vault.sign") && msg.contains("vault"),
        "the error should name the body and its owner: {msg}"
    );
    assert!(
        msg.contains("bind:native_impl:myapp.vault.sign"),
        "and should name the permission that would declare it: {msg}"
    );
}

/// The counterweight: the owner binds its own body with no permission
/// at all. Without this, the test above could pass merely because
/// native impls stopped working.
#[tokio::test]
async fn the_owner_binds_its_own_body_freely() {
    let mut k = kernel();
    k.register_plugin_from_json(&binder("vault", &[]))
        .expect("the owner needs no declaration");
    let k = k.into_arc();

    let out = k
        .execute("vault", "go", json!({}))
        .run()
        .await
        .expect("runs")
        .output;
    assert_eq!(out, json!(MARKER), "the owner's binding must actually work");
}

// ---------------------------------------------------------------------
// The two-key escape hatch
// ---------------------------------------------------------------------

/// Declaring the permission is not authorisation. A manifest is
/// self-describing, so the declaration alone proves only that the
/// plugin asked — which is what makes the claim auditable, not what
/// makes it permitted.
#[test]
fn declaring_the_permission_alone_is_not_enough() {
    let err = kernel()
        .register_plugin_from_json(&binder("evil", &["bind:native_impl:myapp.vault.sign"]))
        .expect_err("a declaration without embedder authorisation must be refused");
    assert!(
        err.to_string().contains("allowing_native_impl_binding"),
        "the error should point at the embedder-side call that would permit it: {err}"
    );
}

/// Embedder authorisation without the manifest declaration is likewise
/// not enough — both halves, or nothing.
#[test]
fn embedder_authorisation_alone_is_not_enough() {
    let mut k = Kernel::boot(
        KernelConfig::default()
            .with_native_step_impls(table())
            .allowing_native_impl_binding("evil", "myapp.vault.sign"),
    )
    .expect("boot");
    let err = k
        .register_plugin_from_json(&binder("evil", &[]))
        .expect_err("an undeclared binding must be refused even when authorised");
    assert!(
        err.to_string().contains("does not declare"),
        "the error should be the missing-declaration one: {err}"
    );
}

/// Both halves present: the binding works.
#[tokio::test]
async fn both_keys_together_permit_the_binding() {
    let mut k = Kernel::boot(
        KernelConfig::default()
            .with_native_step_impls(table())
            .allowing_native_impl_binding("borrower", "myapp.vault.sign"),
    )
    .expect("boot");
    k.register_plugin_from_json(&binder("borrower", &["bind:native_impl:myapp.vault.sign"]))
        .expect("declared and authorised");
    let k = k.into_arc();

    let out = k
        .execute("borrower", "go", json!({}))
        .run()
        .await
        .expect("runs")
        .output;
    assert_eq!(out, json!(MARKER));
}

/// The two rejections have to be distinguishable: "did not ask" is a
/// manifest bug the plugin author fixes, "asked and is not authorised"
/// is a deployment decision the operator makes. An operator debugging a
/// plugin that will not load needs to know which one they have.
#[test]
fn the_two_rejections_say_different_things() {
    let undeclared = kernel()
        .register_plugin_from_json(&binder("evil", &[]))
        .expect_err("rejected")
        .to_string();
    let unauthorised = kernel()
        .register_plugin_from_json(&binder("evil", &["bind:native_impl:myapp.vault.sign"]))
        .expect_err("rejected")
        .to_string();
    assert_ne!(undeclared, unauthorised);
    assert!(undeclared.contains("does not declare"));
    assert!(unauthorised.contains("has not authorised"));
}

/// An authorisation is for one exact pair. Authorising a *different*
/// binder must not help this one — otherwise the operator half would
/// widen beyond the binding it was written for.
#[test]
fn authorisation_does_not_transfer_between_binders() {
    let mut k = Kernel::boot(
        KernelConfig::default()
            .with_native_step_impls(table())
            .allowing_native_impl_binding("someone_else", "myapp.vault.sign"),
    )
    .expect("boot");
    k.register_plugin_from_json(&binder("evil", &["bind:native_impl:myapp.vault.sign"]))
        .expect_err("an authorisation naming another binder must not apply");
}

// ---------------------------------------------------------------------
// Ownership derivation
// ---------------------------------------------------------------------

/// An implRef that is not `<owner>.<plugin>.<step>` has no derivable
/// owner, so nobody gets the free path to it. Fail-closed: an
/// undeterminable owner is not the same as no owner.
#[test]
fn an_implref_with_no_derivable_owner_is_never_free() {
    let mut t = NativeStepImplTable::empty();
    t.insert("flat_name", vault_privileged_body).expect("seed");
    let manifest = json!({
        "name": "flat_name",
        "stepTypeDefs": [{"name": "flat_name.s"}],
        "stepTypeImpls": [{"stepType": "flat_name.s", "kind": "native", "implRef": "flat_name"}],
        "actions": { "go": { "steps": [{"id": "x", "type": "flat_name.s"}] } },
    })
    .to_string();

    let err = Kernel::boot(KernelConfig::default().with_native_step_impls(t))
        .expect("boot")
        .register_plugin_from_json(&manifest)
        .expect_err("a single-segment implRef yields no owner, so binding needs authorisation");
    assert!(
        err.to_string().contains("no owner can be derived"),
        "the error should explain why the free path did not apply: {err}"
    );
}

/// The check runs before resolution, so an unauthorised binding is
/// refused whether or not the body exists. Otherwise the error would
/// leak which implRefs are present in the host binary.
#[test]
fn the_ownership_check_precedes_resolution() {
    let manifest = json!({
        "name": "evil",
        "stepTypeDefs": [{"name": "evil.s"}],
        "stepTypeImpls": [
            {"stepType": "evil.s", "kind": "native", "implRef": "myapp.vault.does_not_exist"}
        ],
        "actions": { "go": { "steps": [{"id": "x", "type": "evil.s"}] } },
    })
    .to_string();
    let err = kernel()
        .register_plugin_from_json(&manifest)
        .expect_err("rejected");
    assert!(
        err.to_string().contains("does not declare"),
        "ownership must be judged before existence, or the error leaks the table: {err}"
    );
}

// ---------------------------------------------------------------------
// Namespaces
// ---------------------------------------------------------------------

/// The free path is root-only, and this is why.
///
/// A namespace exists because the manifest is *not* embedder-authored.
/// Native bodies are compiled into the host binary, so a tenant can
/// never ship one — but if the free path applied inside a namespace, a
/// tenant who simply named their plugin `vault` would bind
/// `myapp.vault.sign` for free. That is the same hole wearing a
/// namespace, and it would mean the escape hatch never engaged in the
/// one case it exists for.
#[test]
fn a_namespaced_plugin_does_not_inherit_ownership_by_name() {
    let err = kernel()
        .load_manifest(&binder("vault", &[]))
        .in_namespace("tenant_evil")
        .register()
        .expect_err("a namespaced plugin must not assume ownership by naming itself");
    let msg = err.to_string();
    assert!(
        msg.contains("tenant_evil"),
        "the error should name the namespace that made the difference: {msg}"
    );
    assert!(
        msg.contains("root namespace"),
        "and should explain that the free path is root-only: {msg}"
    );
}

/// A namespaced plugin can still be authorised explicitly — the
/// restriction is on assuming ownership, not on binding at all.
#[tokio::test]
async fn a_namespaced_plugin_can_be_authorised_explicitly() {
    let mut k = Kernel::boot(
        KernelConfig::default()
            .with_native_step_impls(table())
            .allowing_native_impl_binding("tenant_a/vault", "myapp.vault.sign"),
    )
    .expect("boot");
    k.load_manifest(&binder("vault", &["bind:native_impl:myapp.vault.sign"]))
        .in_namespace("tenant_a")
        .register()
        .expect("declared and explicitly authorised");
    let k = k.into_arc();

    let out = k
        .execute("tenant_a/vault", "go", json!({}))
        .run()
        .await
        .expect("runs")
        .output;
    assert_eq!(out, json!(MARKER));
}

/// The binder is named by identity, so an authorisation written for the
/// root-namespace plugin must not be satisfiable by a namespaced one of
/// the same local name.
#[test]
fn authorisation_does_not_transfer_across_namespaces() {
    let mut k = Kernel::boot(
        KernelConfig::default()
            .with_native_step_impls(table())
            .allowing_native_impl_binding("vault", "myapp.vault.sign"),
    )
    .expect("boot");
    k.load_manifest(&binder("vault", &["bind:native_impl:myapp.vault.sign"]))
        .in_namespace("tenant_evil")
        .register()
        .expect_err("a root-namespace authorisation must not cover a namespaced binder");
}

// ---------------------------------------------------------------------
// The kernel holds itself to the rule
// ---------------------------------------------------------------------

/// The intrinsics manifest binds `gwead.intrinsics.*` under the plugin
/// name `gwead_intrinsics`, so its middle segment does not match and it
/// does not qualify for the free path either. It is authorised
/// explicitly at boot rather than waved through — a boot path that
/// skipped the check would be one more door with no guard.
///
/// That every kernel boots at all is the real assertion here; this
/// makes the reason explicit so a future change that "simplifies" the
/// seeded bindings fails loudly.
#[tokio::test]
async fn the_intrinsics_manifest_satisfies_the_same_rule() {
    let k = Kernel::boot(KernelConfig::default())
        .expect("boot must succeed with the seeded kernel bindings")
        .into_arc();

    let manifest = json!({
        "name": "uses_let",
        "actions": { "go": {
            "steps": [{"id": "v", "type": "let", "params": {"value": "from-a-native-intrinsic"}}],
            "resultMapping": { "out": { "path": "$", "source": "v" } }
        } },
    })
    .to_string();

    let mut kernel = Kernel::boot(KernelConfig::default()).expect("boot");
    kernel
        .register_plugin_from_json(&manifest)
        .expect("registers");
    let kernel = kernel.into_arc();

    let out = kernel
        .execute("uses_let", "go", json!({}))
        .run()
        .await
        .expect("runs")
        .output;
    assert_eq!(
        out,
        json!({"out": "from-a-native-intrinsic"}),
        "`let` is a native-kind intrinsic bound by the intrinsics manifest; \
         dropping the seeded binding would fail the boot above, and breaking \
         the body would fail here"
    );
    drop(k);
}
