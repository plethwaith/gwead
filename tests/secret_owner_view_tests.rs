//! A foreign step body sees its *owner's* secrets, not the execution's.
//!
//! The hole this guards against: a body shipped by `vault`, used through
//! the direct step path, would read the calling plugin's whole
//! credential bundle from `ex.secrets()` and return it as its step
//! result — an exfiltration channel behind a single `step_type:` grant.
//!
//! The rule: `ex.secrets()` is the bag of the plugin that *ships the
//! body*. A body's own credentials travel with it wherever it is used;
//! the caller's never reach it except by deliberate delegation through
//! a param. Both halves are pinned here, along with the piece that makes
//! a shared credentialed step type useful across tenants: the owner may
//! mark keys `overridable` in `usesSecrets`, and the resolver is told which.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use gwead::kernel::native_impls::NativeStepImplTable;
use gwead::kernel::secrets::{SecretError, SecretRequest, SecretResolver};
use gwead::kernel::{Kernel, KernelConfig, PluginExecution, StepError, StepOutput};
use serde_json::{Value, json};

/// Returns what it can see: its ambient `ex.secrets()` and the
/// caller-resolved `key` param, side by side.
fn peeking_body<'a>(
    ex: &'a mut (dyn PluginExecution + Send),
    params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move {
        let ctx = ex.resolution_context();
        let resolved = ex.resolve_value_with(params, &ctx);
        Ok(StepOutput::from(json!({
            "ambient": ex.secrets().clone(),
            "param": resolved.get("key").cloned().unwrap_or(Value::Null),
        })))
    })
}

/// One recorded request: (subject, executing_plugin, declared, overridable).
type Request = (String, String, Vec<String>, Vec<String>);
struct Seen(Mutex<Vec<Request>>);

/// Answers per subject from a table and records every request.
struct TableResolver {
    table: Vec<(&'static str, Value)>,
    seen: Arc<Seen>,
}

impl SecretResolver for TableResolver {
    fn resolve<'a>(
        &'a self,
        request: SecretRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<Value, SecretError>> + Send + 'a>> {
        self.seen.0.lock().expect("lock").push((
            request.subject.to_string(),
            request.executing_plugin.to_string(),
            request.declared_keys.to_vec(),
            request.overridable_keys.to_vec(),
        ));
        let answer = self
            .table
            .iter()
            .find(|(p, _)| *p == request.subject)
            .map(|(_, v)| v.clone())
            .unwrap_or(Value::Null);
        Box::pin(async move { Ok(answer) })
    }
}

fn vault_manifest(overridable: &[&str]) -> String {
    let uses: Vec<Value> = ["signingKey", "apiToken"]
        .iter()
        .map(|k| {
            if overridable.contains(k) {
                json!({"key": k, "overridable": true})
            } else {
                json!(k)
            }
        })
        .collect();
    json!({
        "name": "vault",
        "usesSecrets": uses,
        "stepTypeDefs": [{"name": "vault.sign", "freelyUsable": true}],
        "stepTypeImpls": [{"stepType": "vault.sign", "kind": "native",
                           "implRef": "myapp.vault.sign"}],
        "actions": {"noop": {"steps": []}}
    })
    .to_string()
}

/// A plugin using `sign`, delegating its own `privateKey` through a
/// param, and also echoing its own ambient secrets from a `let`.
const CALLER: &str = r#"{
    "name": "app",
    "usesSecrets": ["privateKey", "dbPassword"],
    "actions": {"go": {
        "steps": [
            {"id": "s", "type": "vault.sign", "params": {"key": "{{$secrets.privateKey}}"}},
            {"id": "mine", "type": "let", "params": {"value": "{{$secrets.dbPassword}}"}}
        ],
        "resultMapping": {
            "body": {"path": "$", "source": "s"},
            "mine": {"path": "$", "source": "mine"}
        }
    }}
}"#;

fn boot(table: Vec<(&'static str, Value)>, overridable: &[&str]) -> (Kernel, Arc<Seen>) {
    let seen = Arc::new(Seen(Mutex::new(Vec::new())));
    let mut impls = NativeStepImplTable::empty();
    impls
        .insert("myapp.vault.sign", peeking_body)
        .expect("fresh");
    let mut k = Kernel::boot(
        KernelConfig::default()
            .with_native_step_impls(impls)
            .with_secret_resolver(Arc::new(TableResolver {
                table,
                seen: seen.clone(),
            })),
    )
    .expect("boot");
    k.register_plugin_from_json(&vault_manifest(overridable))
        .expect("vault");
    (k, seen)
}

fn bags() -> Vec<(&'static str, Value)> {
    vec![
        (
            "vault",
            json!({"signingKey": "VAULT-KEY", "apiToken": "FREE-TIER"}),
        ),
        (
            "app",
            json!({"privateKey": "APP-PRIVATE", "dbPassword": "hunter2"}),
        ),
        (
            "tenant_a/app",
            json!({"privateKey": "TA-PRIVATE", "dbPassword": "ta-pw"}),
        ),
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn a_foreign_body_sees_its_owners_secrets_not_the_callers() {
    let (mut k, seen) = boot(bags(), &[]);
    k.register_plugin_from_json(CALLER).expect("app");
    let out = k
        .into_arc()
        .execute("app", "go", json!({}))
        .run()
        .await
        .expect("runs")
        .output;

    assert_eq!(
        out["body"]["ambient"],
        json!({"signingKey": "VAULT-KEY", "apiToken": "FREE-TIER"}),
        "ambient view is the OWNER's bag: {out}"
    );
    let rendered = out["body"]["ambient"].to_string();
    assert!(
        !rendered.contains("hunter2") && !rendered.contains("APP-PRIVATE"),
        "the caller's credentials must not be ambient in the body: {rendered}"
    );
    // Delegation through a param still works — that is the caller's
    // deliberate choice, resolved against the caller's own bag.
    assert_eq!(out["body"]["param"], json!("APP-PRIVATE"));
    // And the caller's own steps still see the caller's own bag.
    assert_eq!(out["mine"], json!("hunter2"));

    let seen = seen.0.lock().expect("lock").clone();
    assert_eq!(
        seen.len(),
        2,
        "one pull for the execution, one for the body: {seen:?}"
    );
    assert_eq!(seen[0].0, "app");
    assert_eq!(
        (seen[1].0.as_str(), seen[1].1.as_str()),
        ("vault", "app"),
        "the body pull names the owner as subject and the caller as executing plugin"
    );
}

/// The owner-view pull is narrowed by the OWNER's `usesSecrets`: a
/// resolver handing over more than `vault` declared is cut back.
#[tokio::test(flavor = "multi_thread")]
async fn the_owners_view_is_narrowed_to_the_owners_declaration() {
    let mut table = bags();
    table[0].1 = json!({"signingKey": "VAULT-KEY", "apiToken": "FREE-TIER", "extra": "WIDENED"});
    let (mut k, _) = boot(table, &[]);
    k.register_plugin_from_json(CALLER).expect("app");
    let out = k
        .into_arc()
        .execute("app", "go", json!({}))
        .run()
        .await
        .expect("runs")
        .output;
    assert_eq!(out["body"]["ambient"].get("extra"), None, "{out}");
}

/// A failed owner pull fails the step — the body must not run with an
/// empty bag in place of the credential it declared.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_owner_pull_fails_the_step() {
    struct Broken;
    impl SecretResolver for Broken {
        fn resolve<'a>(
            &'a self,
            request: SecretRequest<'a>,
        ) -> Pin<Box<dyn Future<Output = Result<Value, SecretError>> + Send + 'a>> {
            // The execution's own pull succeeds; only the body's fails.
            let fail = request.subject == "vault";
            let subject = request.subject.to_string();
            Box::pin(async move {
                if fail {
                    Err(SecretError::Unavailable {
                        subject,
                        reason: "vault sealed".into(),
                    })
                } else {
                    Ok(json!({"privateKey": "x", "dbPassword": "y"}))
                }
            })
        }
    }
    let mut impls = NativeStepImplTable::empty();
    impls
        .insert("myapp.vault.sign", peeking_body)
        .expect("fresh");
    let mut k = Kernel::boot(
        KernelConfig::default()
            .with_native_step_impls(impls)
            .with_secret_resolver(Arc::new(Broken)),
    )
    .expect("boot");
    k.register_plugin_from_json(&vault_manifest(&[]))
        .expect("vault");
    k.register_plugin_from_json(CALLER).expect("app");
    let err = k
        .into_arc()
        .execute("app", "go", json!({}))
        .run()
        .await
        .expect_err("must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("body owner's secrets") && msg.contains("vault sealed"),
        "{msg}"
    );
}

// ── usesSecrets[].overridable ───────────────────────────────────────

/// The resolver is told which of the owner's keys are overridable, and
/// who is executing — everything an embedder needs to substitute a
/// tenant's `apiToken` for the global default. Here a tenant plugin
/// uses the global `sign`; the resolver sees subject `vault`, executing
/// `tenant_a/app`, overridable `["apiToken"]`.
#[tokio::test(flavor = "multi_thread")]
async fn the_resolver_is_told_which_owner_keys_a_tenant_may_override() {
    let (mut k, seen) = boot(bags(), &["apiToken"]);
    k.load_manifest(CALLER)
        .in_namespace("tenant_a")
        .register()
        .expect("tenant app");
    let out = k
        .into_arc()
        .execute("tenant_a/app", "go", json!({}))
        .run()
        .await
        .expect("runs")
        .output;
    // Upward use of a global body works, and the tenant's own bag is
    // what its own steps and params see.
    assert_eq!(out["body"]["param"], json!("TA-PRIVATE"));
    assert_eq!(out["mine"], json!("ta-pw"));

    let seen = seen.0.lock().expect("lock").clone();
    let body_pull = seen
        .iter()
        .find(|(subject, _, _, _)| subject == "vault")
        .expect("the body's pull happened");
    assert_eq!(body_pull.1, "tenant_a/app");
    assert_eq!(
        body_pull.2,
        vec!["signingKey".to_string(), "apiToken".to_string()]
    );
    assert_eq!(body_pull.3, vec!["apiToken".to_string()]);
}

/// Only the level that owns a key may mark it: a namespaced manifest
/// marking anything overridable is refused at load.
#[test]
fn a_tenant_may_not_mark_keys_overridable() {
    let (mut k, _) = boot(bags(), &[]);
    let err = k
        .load_manifest(
            &json!({
                "name": "t",
                "usesSecrets": [{"key": "k", "overridable": true}],
                "actions": {"noop": {"steps": []}}
            })
            .to_string(),
        )
        .in_namespace("tenant_a")
        .register()
        .expect_err("refused");
    assert!(err.to_string().contains("root-namespace"), "{err}");
}

/// The flag lives on the declaration, so "overridable but undeclared"
/// cannot be written. What *can* be written is the same key twice with
/// the entries disagreeing; that is refused rather than resolved.
#[test]
fn a_secret_key_declared_twice_is_refused() {
    let (mut k, _) = boot(bags(), &[]);
    let err = k
        .register_plugin_from_json(
            &json!({
                "name": "t",
                "usesSecrets": ["k", {"key": "k", "overridable": true}],
                "actions": {"noop": {"steps": []}}
            })
            .to_string(),
        )
        .expect_err("refused");
    assert!(err.to_string().contains("more than once"), "{err}");
}

/// Both spellings parse, and `overridable` defaults to false.
#[test]
fn uses_secrets_accepts_bare_and_object_entries() {
    use gwead::kernel::types::{PluginManifest, SecretDecl};
    let m: PluginManifest = serde_json::from_value(json!({
        "name": "t",
        "usesSecrets": ["a", {"key": "b"}, {"key": "c", "overridable": true}],
        "actions": {}
    }))
    .expect("parses");
    assert_eq!(
        m.uses_secrets,
        vec![
            SecretDecl::new("a"),
            SecretDecl::new("b"),
            SecretDecl::overridable("c")
        ]
    );
    assert_eq!(m.declared_secret_keys(), ["a", "b", "c"]);
    assert_eq!(m.overridable_secret_keys(), ["c"]);
    // Round-trips to the shortest spelling.
    let back = serde_json::to_value(&m).expect("serialises");
    assert_eq!(
        back["usesSecrets"],
        json!(["a", "b", {"key": "c", "overridable": true}])
    );
}
