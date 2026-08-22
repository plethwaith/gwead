//! Secrets are pulled, per plugin, through a resolver — never pushed
//! across a plugin boundary.
//!
//! The hole this guards against: an orchestrator that hands every
//! cross-plugin dispatch target the caller's config **and secrets**
//! verbatim, so `$secrets.apiKey` in the callee is the caller's API key
//! and one granted `invoke:` is enough. It is the kind of bug most
//! likely to bite in production and never show in testing — everything
//! else in this kernel fails loudly, and this would fail silently, in
//! exactly the composition pattern plugins exist for.
//!
//! The guarantee is structural rather than a nulled field: the dispatch plan
//! has no secrets slot at all. Every execution asks the invocation's
//! [`SecretResolver`] for its *own* credentials, and the kernel narrows
//! the answer to the manifest's `usesSecrets`. These tests pin each
//! half of that contract from the outside.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use gwead::kernel::secrets::{SecretError, SecretRequest, SecretResolver, StaticSecretResolver};
use gwead::kernel::{Kernel, KernelConfig, KernelError};
use serde_json::{Value, json};

const CALLEE: &str = r#"{
    "name": "callee",
    "usesSecrets": ["apiKey"],
    "actions": {"peek": {
        "steps": [{"id": "s", "type": "let", "params": {"value": "{{$secrets.apiKey}}"}}],
        "resultMapping": {"saw": {"path": "$", "source": "s"}}
    }}
}"#;

/// `caller` declares `apiKey`; its `go` action invokes `callee`, and
/// `self_go` just reads its own secret.
const CALLER: &str = r#"{
    "name": "caller",
    "usesSecrets": ["apiKey"],
    "permissions": ["invoke:plugin:callee"],
    "actions": {
        "go": {
            "steps": [{"id": "call", "type": "invoke", "params": {"plugin": "callee", "action": "peek", "input": {}}}],
            "resultMapping": {"out": {"path": "$", "source": "call"}}
        },
        "self_go": {
            "steps": [{"id": "mine", "type": "let", "params": {"value": "{{$secrets.apiKey}}"}}],
            "resultMapping": {"out": {"path": "$", "source": "mine"}}
        },
        "peek_both": {
            "steps": [
                {"id": "a", "type": "let", "params": {"value": "{{$secrets.apiKey}}"}},
                {"id": "b", "type": "let", "params": {"value": "{{$secrets.undeclared}}"}}
            ],
            "resultMapping": {
                "declared": {"path": "$", "source": "a"},
                "undeclared": {"path": "$", "source": "b"}
            }
        }
    }
}"#;

fn boot_with(config: KernelConfig) -> Arc<Kernel> {
    let mut k = Kernel::boot(config).expect("boot");
    k.register_plugin_from_json(CALLEE)
        .expect("callee registers");
    k.register_plugin_from_json(CALLER)
        .expect("caller registers");
    k.into_arc()
}

fn callers_bag() -> Value {
    json!({"apiKey": "CALLERS-PRIVATE-KEY", "undeclared": "SHOULD-NOT-LEAK"})
}

/// A kernel whose only credentials are one static bag for `caller`.
fn boot_static() -> Arc<Kernel> {
    boot_with(
        KernelConfig::default()
            .with_secret_resolver(Arc::new(StaticSecretResolver::new("caller", callers_bag()))),
    )
}

async fn run(k: &Arc<Kernel>, action: &str) -> Result<Value, KernelError> {
    k.execute("caller", action, json!({}))
        .run()
        .await
        .map(|r| r.output)
}

fn rendered(v: &Value) -> String {
    serde_json::to_string(v).expect("json")
}

// ── StaticSecretResolver: one bag, one plugin ──────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_static_bag_reaches_only_its_own_plugin() {
    let k = boot_static();
    let out = run(&k, "go").await.expect("runs");
    assert!(
        !rendered(&out).contains("CALLERS-PRIVATE-KEY"),
        "the callee read the caller's credential bundle: {}",
        rendered(&out)
    );
    let mine = run(&k, "self_go").await.expect("runs");
    assert_eq!(mine["out"], json!("CALLERS-PRIVATE-KEY"));
}

/// `usesSecrets` is a ceiling for the static resolver too: the bag the
/// embedder handed over is still narrowed to what the manifest declared.
#[tokio::test(flavor = "multi_thread")]
async fn a_static_bag_is_narrowed_to_the_declared_keys() {
    let k = boot_static();
    let out = run(&k, "peek_both").await.expect("runs");
    assert_eq!(out["declared"], json!("CALLERS-PRIVATE-KEY"));
    // An absent `{{…}}` reference renders as the empty string.
    assert_eq!(
        out["undeclared"],
        json!(""),
        "an undeclared key must not resolve: {}",
        rendered(&out)
    );
}

/// Declaring nothing means seeing nothing — a plugin that reads
/// `$secrets.x` without listing `x` was relying on ambient authority.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_declaring_no_secrets_sees_none() {
    let mut k = Kernel::boot(KernelConfig::default().with_secret_resolver(Arc::new(
        StaticSecretResolver::new("silent", json!({"apiKey": "AMBIENT"})),
    )))
    .expect("boot");
    k.register_plugin_from_json(
        r#"{
            "name": "silent",
            "actions": {"peek": {
                "steps": [{"id": "s", "type": "let", "params": {"value": "{{$secrets.apiKey}}"}}],
                "resultMapping": {"saw": {"path": "$", "source": "s"}}
            }}
        }"#,
    )
    .expect("registers");
    let k = k.into_arc();
    let out = k
        .execute("silent", "peek", json!({}))
        .run()
        .await
        .expect("runs")
        .output;
    assert_eq!(out["saw"], json!(""), "{}", rendered(&out));
}

// ── The resolver path ──────────────────────────────────────────────

/// A resolver that answers per subject from a fixed table and records
/// every request it saw.
struct TableResolver {
    table: Vec<(&'static str, Value)>,
    seen: Mutex<Vec<(String, String, Vec<String>)>>,
}

impl TableResolver {
    fn new(table: Vec<(&'static str, Value)>) -> Arc<Self> {
        Arc::new(Self {
            table,
            seen: Mutex::new(Vec::new()),
        })
    }
}

impl SecretResolver for TableResolver {
    fn resolve<'a>(
        &'a self,
        request: SecretRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<Value, SecretError>> + Send + 'a>> {
        self.seen.lock().expect("lock").push((
            request.subject.to_string(),
            request.executing_plugin.to_string(),
            request.declared_keys.to_vec(),
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

#[tokio::test(flavor = "multi_thread")]
async fn each_plugin_pulls_its_own_secrets_through_the_resolver() {
    let resolver = TableResolver::new(vec![
        ("caller", json!({"apiKey": "CALLERS-KEY"})),
        ("callee", json!({"apiKey": "CALLEES-KEY"})),
    ]);
    let k = boot_with(KernelConfig::default().with_secret_resolver(resolver.clone()));

    let out = k
        .execute("caller", "go", json!({}))
        .run()
        .await
        .expect("runs")
        .output;
    assert_eq!(
        out["out"]["saw"],
        json!("CALLEES-KEY"),
        "the callee must see its OWN credential, not the caller's: {}",
        rendered(&out)
    );

    let seen = resolver.seen.lock().expect("lock").clone();
    assert_eq!(
        seen,
        vec![
            ("caller".into(), "caller".into(), vec!["apiKey".to_string()]),
            ("callee".into(), "callee".into(), vec!["apiKey".to_string()]),
        ],
        "one request per execution, subject == executing plugin, \
         declared keys forwarded"
    );
}

/// The kernel intersects regardless of what the resolver returns — a
/// resolver bug cannot widen a manifest.
#[tokio::test(flavor = "multi_thread")]
async fn a_resolver_answer_is_narrowed_to_the_declared_keys() {
    let resolver = TableResolver::new(vec![(
        "caller",
        json!({"apiKey": "CALLERS-KEY", "undeclared": "WIDENED"}),
    )]);
    let k = boot_with(KernelConfig::default().with_secret_resolver(resolver));
    let out = k
        .execute("caller", "peek_both", json!({}))
        .run()
        .await
        .expect("runs")
        .output;
    assert_eq!(out["declared"], json!("CALLERS-KEY"));
    assert_eq!(out["undeclared"], json!(""), "{}", rendered(&out));
}

/// A resolver that fails for every subject.
struct BrokenResolver(AtomicUsize);

impl SecretResolver for BrokenResolver {
    fn resolve<'a>(
        &'a self,
        request: SecretRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<Value, SecretError>> + Send + 'a>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let subject = request.subject.to_string();
        Box::pin(async move {
            Err(SecretError::Unavailable {
                subject,
                reason: "vault sealed".into(),
            })
        })
    }
}

/// A missing credential must not present as an absent one.
#[tokio::test(flavor = "multi_thread")]
async fn a_resolver_error_fails_the_action() {
    let resolver = Arc::new(BrokenResolver(AtomicUsize::new(0)));
    let k = boot_with(KernelConfig::default().with_secret_resolver(resolver.clone()));
    let err = k
        .execute("caller", "self_go", json!({}))
        .run()
        .await
        .expect_err("must fail, not run without the secret");
    let msg = err.to_string();
    assert!(
        msg.contains("secret resolution failed for 'caller'") && msg.contains("vault sealed"),
        "error must name the subject and carry the resolver's reason: {msg}"
    );
    assert_eq!(resolver.0.load(Ordering::SeqCst), 1);
}

/// A plugin declaring nothing never costs a resolver round trip.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_declaring_no_secrets_does_not_consult_the_resolver() {
    let resolver = Arc::new(BrokenResolver(AtomicUsize::new(0)));
    let mut k =
        Kernel::boot(KernelConfig::default().with_secret_resolver(resolver.clone())).expect("boot");
    k.register_plugin_from_json(
        r#"{"name": "silent", "actions": {"noop": {
            "steps": [{"id": "s", "type": "let", "params": {"value": 1}}],
            "resultMapping": {"v": {"path": "$", "source": "s"}}
        }}}"#,
    )
    .expect("registers");
    let k = k.into_arc();
    k.execute("silent", "noop", json!({}))
        .run()
        .await
        .expect("runs without touching the broken resolver");
    assert_eq!(resolver.0.load(Ordering::SeqCst), 0);
}

/// No resolver, no secrets — anywhere. The absence of a per-request
/// bag is the point: there is one place credentials come from.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_resolver_nothing_resolves() {
    let k = boot_with(KernelConfig::default());
    let out = run(&k, "self_go").await.expect("runs");
    assert_eq!(out["out"], json!(""), "{}", rendered(&out));
}

/// Event subscribers pull through the kernel's resolver like everything
/// else.
#[tokio::test(flavor = "multi_thread")]
async fn an_event_subscriber_pulls_its_own_secrets() {
    let resolver = TableResolver::new(vec![("sub", json!({"token": "SUBS-TOKEN"}))]);
    let mut k =
        Kernel::boot(KernelConfig::default().with_secret_resolver(resolver.clone())).expect("boot");
    k.register_plugin_from_json(
        r#"{"name": "sub", "usesSecrets": ["token"], "actions": {"on_thing": {
            "subscribesTo": ["thing.happened"],
            "steps": [{"id": "s", "type": "let", "params": {"value": "{{$secrets.token}}"}}],
            "resultMapping": {"saw": {"path": "$", "source": "s"}}
        }}}"#,
    )
    .expect("registers");
    let k = k.into_arc();
    let results = k
        .dispatch_event(
            "thing.happened",
            Arc::new(json!({})),
            &Value::Null,
            &Default::default(),
            0,
        )
        .await;
    let out = results
        .into_iter()
        .next()
        .expect("one subscriber")
        .result
        .expect("runs")
        .output;
    assert_eq!(out["saw"], json!("SUBS-TOKEN"));
    let seen = resolver.seen.lock().expect("lock").clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, "sub");
}
