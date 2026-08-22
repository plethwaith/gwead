//! Secret resolution — the embedder-supplied seam the kernel pulls
//! credentials through.
//!
//! # Why pull rather than push
//!
//! The alternative is push: the embedder hands the kernel one secrets
//! bag per invocation and the kernel carries it wherever the execution
//! goes. Two things follow from that shape, and neither is fixable
//! inside it:
//!
//! - **The embedder has to over-supply.** Pushing means handing over
//!   everything the invocation might need before knowing what it needs.
//! - **The kernel cannot answer for anyone else.** It holds exactly one
//!   bag — the one pushed for the executing plugin. When a step body one
//!   plugin supplied runs inside another plugin's execution, there is
//!   nowhere to fetch the *body owner's* secrets from. The whole
//!   shared-capability pattern (a global step type that uses a global
//!   credential, usable by a tenant that must never see it) is
//!   unbuildable on a push model.
//!
//! The kernel knows whose secrets it wants and when. So it asks.
//!
//! # What the kernel does and does not decide
//!
//! It decides *whose* secrets to request and enforces two rules on the
//! answer: the [`subject`](SecretRequest::subject) must be on the
//! executing plugin's own chain, and the returned tree is intersected
//! with the keys the subject's manifest declared.
//!
//! Everything else is the embedder's. Where secrets live, whether a
//! tenant may override a global key, how a credential is fetched — none
//! of it is engine-shaped, and the kernel never learns what a tenant is.
//! [`SecretRequest`] carries enough to implement those policies:
//! `subject` and `executing_plugin` are separate identities precisely so
//! a global body running on a tenant's behalf can be answered with the
//! global bag plus that tenant's overrides.
//!
//! # Where the kernel pulls
//!
//! Every execution start — the invoked plugin, an `invoke` or alias
//! callee, a role dispatch, an event subscriber — goes through
//! `Kernel::pull_secrets`, which asks the invocation's resolver for the
//! executing plugin's own secrets and applies the two rules. A
//! resolver error fails the action; see [`SecretError::Unavailable`].
//!
//! There is exactly one place credentials come from: the resolver
//! registered on [`KernelConfig::secret_resolver`](super::KernelConfig::secret_resolver).
//! No resolver means no secrets, anywhere. There is deliberately no
//! per-request bag beside it — a second path that applies to some
//! invocations is precisely the ambient channel a resolver exists to
//! close, and one spelling means "where do this kernel's secrets come
//! from" has one answer. A single-plugin embedder registers a
//! [`StaticSecretResolver`]; that is the whole cost.
//!
//! Children inherit the tree's resolver, so a callee asks the same
//! source the caller did and gets *its own* answer from it.
//!
//! # Why the request carries two identities
//!
//! Most pulls have `subject == executing_plugin`. The foreign-body case
//! — a step body one plugin supplied running inside another's
//! execution, where `ex.secrets()` must be the *body owner's* view — is
//! why the two are separate: the runtime pulls per step with `subject`
//! set to the body's owner and `executing` to the caller, narrowed to
//! the owner's `usesSecrets`, with the owner's overridable keys
//! surfaced so the resolver may answer those with the executing
//! plugin's own value.

use std::future::Future;
use std::pin::Pin;

use serde_json::Value;

use super::exec_context::ExecutionContext;

/// What the kernel wants credentials for.
///
/// The two identities are the point. In the ordinary case they are
/// equal: plugin `p` is executing and wants `p`'s secrets. They diverge
/// when a step body supplied by one plugin runs inside another's
/// execution, and that divergence is what lets an embedder answer
/// "global secrets, with this tenant's overrides applied".
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SecretRequest<'a> {
    /// Whose secrets these are — a fully-qualified plugin identity.
    ///
    /// Guaranteed by the kernel to be the executing plugin itself or
    /// one of its ancestors, so a resolver is never asked for a sibling
    /// tenant's secrets — see [`subject_is_on_chain`].
    pub subject: &'a str,
    /// The plugin whose execution this is running inside.
    ///
    /// Equal to [`Self::subject`] in the ordinary case. When it differs,
    /// `subject` is above `executing_plugin` on the chain — a shared
    /// capability being used from below.
    pub executing_plugin: &'a str,
    /// The secret keys `subject`'s manifest declared.
    ///
    /// Supplied so a resolver can fetch only what is needed rather than
    /// everything it holds. **The kernel intersects the result with
    /// this list regardless**, so honouring it is an optimisation rather
    /// than a security obligation, and a resolver bug cannot widen what
    /// a manifest declared. See [`intersect_declared`].
    pub declared_keys: &'a [String],
    /// The subset of [`Self::declared_keys`] that `subject`'s manifest
    /// marked `overridable` in `usesSecrets` — keys a level *below* the subject
    /// may supply its own value for.
    ///
    /// Surfaced so the embedder is not hand-maintaining a parallel
    /// list. The kernel does not perform the substitution: it has one
    /// resolver and one answer, and the two bags a substitution merges
    /// both live on the embedder's side. The contract is that when
    /// `executing_plugin` is below `subject`, a resolver *may* answer
    /// each key in this list with the executing plugin's level's value
    /// where one exists, and *must not* do so for any other key — a
    /// global plugin's endpoint or identifier is not a tenant's to
    /// redirect. When `executing_plugin == subject` there is nothing
    /// below to override from, and the list is informational.
    pub overridable_keys: &'a [String],
    /// The embedder's opaque per-invocation blob. Where "which tenant is
    /// this for" lives, if the embedder has such a concept.
    pub exec_ctx: &'a ExecutionContext,
}

/// Why a resolver could not answer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretError {
    /// The backing store failed, timed out, or refused.
    ///
    /// **This fails the action.** A missing credential must not present
    /// as an absent one: an action that runs without the secret it
    /// declared produces a wrong answer quietly, which is worse than not
    /// running. The cost is deliberate — a resolver is a liveness
    /// dependency of every invocation that declares secrets.
    #[error("secret resolution failed for '{subject}': {reason}")]
    Unavailable { subject: String, reason: String },
}

/// Supplies plugin credentials on demand.
///
/// Registered on
/// [`KernelConfig::secret_resolver`](super::KernelConfig::secret_resolver).
/// When none is, no execution sees any secrets.
///
/// Async because a real implementation reaches a vault, a database, or a
/// cloud secrets manager. Mirrors
/// [`DispatchOrchestrator`](super::dispatch::DispatchOrchestrator), the
/// crate's other embedder seam.
///
/// # Contract
///
/// Return the secrets for `request.subject` as a JSON object. Anything
/// the subject did not declare will be discarded by the kernel, so
/// returning a superset is safe but wasteful. Returning [`Value::Null`] means "no
/// secrets", which is different from an error.
pub trait SecretResolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        request: SecretRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<Value, SecretError>> + Send + 'a>>;
}

/// One bag, for one plugin.
///
/// Answers with the supplied value when `subject` matches `plugin`, and
/// [`Value::Null`] for every other subject — so a callee cannot receive
/// that plugin's bag, because the resolver has nothing to give it.
/// Register it on
/// [`KernelConfig::with_secret_resolver`](super::KernelConfig::with_secret_resolver).
///
/// ```
/// use std::sync::Arc;
/// use gwead::kernel::{Kernel, KernelConfig};
/// use gwead::kernel::secrets::StaticSecretResolver;
/// use gwead::serde_json::json;
///
/// let kernel = Kernel::boot(KernelConfig::default().with_secret_resolver(Arc::new(
///     StaticSecretResolver::new("my_plugin", json!({"apiKey": "sk-…"})),
/// )))?;
/// # Ok::<(), gwead::kernel::KernelError>(())
/// ```
///
/// An embedder that genuinely wants every plugin to share one credential
/// set — everything in a single trust domain, every manifest authored by
/// them — writes a resolver that ignores `subject`. That is a
/// deliberate, greppable choice rather than a default nobody noticed.
pub struct StaticSecretResolver {
    plugin: String,
    secrets: Value,
}

impl StaticSecretResolver {
    pub fn new(plugin: impl Into<String>, secrets: Value) -> Self {
        Self {
            plugin: plugin.into(),
            secrets,
        }
    }
}

impl SecretResolver for StaticSecretResolver {
    fn resolve<'a>(
        &'a self,
        request: SecretRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<Value, SecretError>> + Send + 'a>> {
        let answer = if request.subject == self.plugin {
            self.secrets.clone()
        } else {
            Value::Null
        };
        Box::pin(async move { Ok(answer) })
    }
}

/// Pull `subject`'s secrets for a body running inside
/// `executing_plugin`'s execution, applying the two kernel rules.
///
/// The one function every credential pull goes through —
/// `Kernel::pull_secrets` for an execution's own bag and the step
/// dispatcher for a foreign body's. Declaring nothing short-circuits to
/// [`Value::Null`] without a round trip; an off-chain subject is
/// refused before the resolver is asked; a resolver error is returned
/// as an error, never as an empty bag; and the answer is intersected
/// with `declared`.
pub(crate) async fn pull(
    resolver: &dyn SecretResolver,
    subject: &str,
    executing_plugin: &str,
    declared: &[String],
    overridable: &[String],
    exec_ctx: &ExecutionContext,
) -> Result<Value, super::KernelError> {
    if declared.is_empty() {
        return Ok(Value::Null);
    }
    if !subject_is_on_chain(subject, executing_plugin) {
        return Err(super::KernelError::Execution(format!(
            "secret resolution for '{subject}' refused: not on the executing plugin \
             '{executing_plugin}' chain"
        )));
    }
    let answer = resolver
        .resolve(SecretRequest {
            subject,
            executing_plugin,
            declared_keys: declared,
            overridable_keys: overridable,
            exec_ctx,
        })
        .await
        .map_err(|e| super::KernelError::Execution(e.to_string()))?;
    Ok(intersect_declared(answer, declared))
}

/// Whether `subject` is the executing plugin or one of its ancestors.
///
/// The kernel checks this before every resolver call, so a call site
/// that computed the wrong subject cannot cause a resolver to be asked
/// for a sibling tenant's credentials. It is literally the dispatch
/// containment rule, [`is_on_chain`](super::identity::is_on_chain) —
/// asking for secrets is reaching for a capability, and it points the
/// same way.
///
/// Public because it is part of the contract, not an implementation
/// detail: a resolver that wants to assert the same invariant, or a test
/// that wants to pin it, should not have to reimplement it.
pub fn subject_is_on_chain(subject: &str, executing_plugin: &str) -> bool {
    super::identity::is_on_chain(subject, executing_plugin)
}

/// Keep only the keys a manifest declared.
///
/// Applied to every resolver answer. See
/// [`SecretRequest::declared_keys`] for why it runs even though the
/// resolver was told what to fetch.
///
/// Public for the same reason as [`subject_is_on_chain`]: an embedder
/// may want to apply it at the source rather than return a superset.
pub fn intersect_declared(secrets: Value, declared: &[String]) -> Value {
    let Value::Object(map) = secrets else {
        // A non-object answer declares nothing usable. `Null` is the
        // honest reading of "no secrets" and keeps `{{$secrets.x}}`
        // resolving to empty rather than to someone else's shape.
        return Value::Null;
    };
    let kept: serde_json::Map<String, Value> = declared
        .iter()
        .filter_map(|k| map.get(k).map(|v| (k.clone(), v.clone())))
        .collect();
    Value::Object(kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plugin_is_on_its_own_chain() {
        assert!(subject_is_on_chain("vault", "vault"));
        assert!(subject_is_on_chain("t/app", "t/app"));
    }

    #[test]
    fn global_is_everyones_ancestor() {
        assert!(subject_is_on_chain("vault", "tenant_a/app"));
        assert!(subject_is_on_chain("vault", "tenant_a/team/app"));
    }

    #[test]
    fn a_tenant_is_an_ancestor_of_its_own_subdivisions() {
        assert!(subject_is_on_chain("tenant_a/shared", "tenant_a/app"));
        assert!(subject_is_on_chain("tenant_a/shared", "tenant_a/team/app"));
    }

    #[test]
    fn siblings_are_not_on_the_chain() {
        assert!(!subject_is_on_chain("tenant_b/vault", "tenant_a/app"));
        assert!(!subject_is_on_chain("tenant_a/team2/x", "tenant_a/team1/y"));
    }

    /// Prefix matching must respect the separator, or `tenant_a2` reads
    /// as a descendant of `tenant_a`.
    #[test]
    fn a_shared_name_prefix_is_not_an_ancestor() {
        assert!(!subject_is_on_chain("tenant_a2/x", "tenant_a/app"));
    }

    /// Downward is refused too: global code must not be handed a
    /// tenant's credentials.
    #[test]
    fn an_ancestor_cannot_ask_for_a_descendants_secrets() {
        assert!(!subject_is_on_chain("tenant_a/app", "vault"));
    }

    #[test]
    fn intersection_keeps_only_declared_keys() {
        let secrets = serde_json::json!({"a": 1, "b": 2, "c": 3});
        let kept = intersect_declared(secrets, &["a".to_string(), "c".to_string()]);
        assert_eq!(kept, serde_json::json!({"a": 1, "c": 3}));
    }

    #[test]
    fn declaring_nothing_yields_nothing() {
        let secrets = serde_json::json!({"a": 1});
        assert_eq!(intersect_declared(secrets, &[]), serde_json::json!({}));
    }

    #[test]
    fn a_non_object_answer_becomes_null() {
        assert_eq!(
            intersect_declared(serde_json::json!("oops"), &["a".to_string()]),
            Value::Null
        );
    }

    #[tokio::test]
    async fn the_static_resolver_answers_only_for_its_own_plugin() {
        let r = StaticSecretResolver::new("app", serde_json::json!({"k": "v"}));
        let ctx = ExecutionContext::default();
        let mine = r
            .resolve(SecretRequest {
                subject: "app",
                executing_plugin: "app",
                declared_keys: &[],
                overridable_keys: &[],
                exec_ctx: &ctx,
            })
            .await
            .expect("ok");
        assert_eq!(mine, serde_json::json!({"k": "v"}));

        let theirs = r
            .resolve(SecretRequest {
                subject: "other",
                executing_plugin: "app",
                declared_keys: &[],
                overridable_keys: &[],
                exec_ctx: &ctx,
            })
            .await
            .expect("ok");
        assert_eq!(theirs, Value::Null);
    }
}
