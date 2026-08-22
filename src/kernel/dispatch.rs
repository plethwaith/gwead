//! Dispatch orchestration seam.
//!
//! The kernel offers exactly one inversion-of-control hook for dispatch
//! policy: [`DispatchOrchestrator`]. Every dispatch site
//! (`Kernel::dispatch_role`, `Kernel::dispatch_event` per subscriber,
//! the `invoke` step type, the `<alias>` step types, and the script
//! runtime host's `host_invoke` import — the `io.invoke` a guest
//! runtime wraps it in) consults the orchestrator to turn a
//! [`DispatchRequest`] into a [`DispatchPlan`] — the concrete
//! `(plugin, action, config)` tuple the kernel then executes.
//!
//! The kernel itself ships [`DefaultOrchestrator`], which does
//! "first-match by role, caller-namespace config". That is enough for a
//! single-tenant embedder without baking any app-shaped policy
//! (per-tenant selection, per-discriminator filtering, …) into the
//! kernel. Embedders that need that policy register their own
//! implementation on [`super::KernelConfig::dispatch_orchestrator`].
//!
//! Secrets are **not** part of the plan. Whoever the orchestrator
//! selects, the kernel pulls that plugin's own credentials through the
//! invocation's [`SecretResolver`](super::secrets::SecretResolver),
//! narrowed to its manifest's `usesSecrets`. An orchestrator therefore
//! cannot hand a callee the caller's bag, or anyone else's — see
//! [`super::secrets`] for the model.
//!
//! ## Why a single trait instead of multiple slots
//!
//! A single generic dispatch hook keeps the contract engine-shaped
//! ("given a dispatch request, produce a dispatch plan") rather than
//! baking any specific SPI's role name or contract shape into the
//! kernel. Every selection decision (role → plugin, alias → impl,
//! per-tenant overlays an embedder adds) flows through this one seam.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value;

use super::exec_context::ExecutionContext;
use super::registry::PluginRegistry;

/// A request to dispatch into another plugin's action.
///
/// `ByRole` and `ByPlugin` are the two shapes every dispatch site
/// lowers to (alias steps lower to `ByPlugin`). The enum is
/// `non_exhaustive`, so a new shape stays additive for orchestrator
/// implementations — selection is the orchestrator's concern.
///
/// Every variant carries a `hints` blob — opaque to
/// the kernel, surfaced to the orchestrator. Plugin authors pass
/// `{"region": "eu"}` to nudge a METADATA_PROVIDER orchestrator's
/// selection, `{"tier": "fast"}` for an LLM role, and so on.
/// Orchestrators that don't
/// recognise a hint key ignore it; the default impl ignores all of
/// them.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DispatchRequest<'a> {
    /// "Find me a plugin that fulfils this role and dispatch its
    /// action." First-match selection in `DefaultOrchestrator`; per-
    /// tenant or per-discriminator selection in app orchestrators.
    ByRole {
        role: &'a str,
        action: &'a str,
        input: &'a Value,
        hints: &'a Value,
    },
    /// "Dispatch this specific plugin's action." Selection is fixed;
    /// the orchestrator still owns the config decision.
    ByPlugin {
        plugin: &'a str,
        action: &'a str,
        input: &'a Value,
        hints: &'a Value,
    },
}

/// Read-only context handed to the orchestrator alongside the request.
///
/// Carries everything the orchestrator might need to make a selection
/// or resolve config, without forcing it to reach back into
/// the kernel. The fields are intentionally narrow: registry lookup,
/// caller identity for fallback, and the opaque execution context
/// ([`ExecutionContext`]) the kernel itself doesn't introspect.
///
/// `#[non_exhaustive]`: the kernel constructs these and orchestrators
/// only read them, so the attribute costs implementers nothing and
/// keeps future context fields additive.
#[non_exhaustive]
pub struct DispatchContext<'a> {
    /// Registry view for orchestrators that need to introspect — a
    /// manifest, a plugin's actions. **Not** for role selection:
    /// `plugins_for_role` is the unscoped catalogue and lists
    /// fulfillers the caller may not reach; use
    /// [`Self::role_candidates`] instead.
    pub registry: &'a PluginRegistry,
    /// Execution context (tenant, identity, membership, …). Opaque
    /// to the kernel — passed through to the orchestrator
    /// without inspection.
    pub exec_ctx: &'a ExecutionContext,
    /// The plugin invoking the dispatch, as its qualified identity —
    /// `name` in the root namespace, `namespace/name` otherwise — or
    /// `None` when no plugin is calling.
    ///
    /// **Exactly two shapes, and they do not overlap:**
    ///
    /// - `Some(identity)` — a plugin-initiated dispatch: an `invoke`
    ///   step, `io.invoke`, an alias step, `dispatch_role` from a native
    ///   body. A root-namespace caller is `Some("vault")`; a namespaced
    ///   one is `Some("tenant_a/vault")`. There is never a `Some("")`,
    ///   because a plugin always has a name.
    /// - `None` — a kernel- or embedder-initiated dispatch with no plugin
    ///   behind it: each subscriber run by
    ///   [`Kernel::dispatch_event`](crate::kernel::Kernel::dispatch_event).
    ///
    /// So an orchestrator may key on this field safely — derive a
    /// namespace from `Some`, treat `None` as "the embedder" — without
    /// the two readings ever colliding. (`Option`, not `""`, for "no
    /// caller": the empty string is also how the root namespace is
    /// spelled, and that ambiguity must not be part of the contract
    /// embedders implement.)
    ///
    /// Whatever an orchestrator returns is re-checked by the kernel
    /// before it runs — including that the resolved plugin is on the
    /// caller's chain — so a redirect here cannot widen authority even
    /// if this field is misread.
    pub caller_plugin: Option<&'a str>,
    /// Caller's config namespace, used as the fallback when the
    /// orchestrator has no plugin-specific override to supply.
    ///
    /// There is deliberately no `caller_secrets` beside this. The
    /// orchestrator never sees credentials — the callee pulls its own
    /// through the [`SecretResolver`](super::secrets::SecretResolver).
    pub caller_config: &'a Value,
    /// For a [`DispatchRequest::ByRole`] request: the fulfillers the
    /// caller may be dispatched to, nearest first — resolved by the
    /// kernel along the caller's ancestor chain and already filtered to
    /// plugins on that chain (see
    /// [`Kernel::role_candidates`](super::Kernel::role_candidates)).
    /// Select from this list. Empty for a `ByPlugin` request, and empty
    /// when no reachable plugin fulfils the role.
    ///
    /// An orchestrator that picks outside this list is not trusted to
    /// have widened anything: the kernel re-checks the resolved plan
    /// against containment and refuses an off-chain target.
    pub role_candidates: Vec<String>,
}

/// The orchestrator's answer: which plugin + action to execute, with
/// what config.
///
/// Returning a fully-resolved plan rather than just a plugin name lets
/// app-side orchestrators fold per-callee config resolution into the
/// same trip — no second host hook for "now go fetch the callee's
/// config".
///
/// # Construction
///
/// `#[non_exhaustive]`: build with [`DispatchPlan::new`] and the
/// `with_*` setters rather than a struct literal.
///
/// ```
/// use gwead::kernel::dispatch::DispatchPlan;
/// use gwead::serde_json::json;
///
/// let plan = DispatchPlan::new("ffprobe", "probe")
///     .with_config(json!({"binary": "/usr/bin/ffprobe"}));
/// ```
///
/// Every custom [`DispatchOrchestrator`] — the one extension seam the
/// kernel asks embedders to implement — must produce one of these, and
/// it is exactly where per-callee features accrue (permission
/// overrides, timeouts, trace context). Without `non_exhaustive` a
/// single added field would be a breaking change for every orchestrator
/// in existence.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DispatchPlan {
    pub plugin: String,
    pub action: String,
    /// Config namespace the callee sees as `{{$config.*}}`. Defaults to
    /// [`Value::Null`]; [`DefaultOrchestrator`] fills it from the
    /// caller's namespace.
    ///
    /// There is no `secrets` counterpart: a plan names *who* runs, and
    /// the kernel pulls that plugin's own credentials. An orchestrator
    /// cannot attach a bag to a plan, which is what makes an
    /// `invoke:` grant a grant to call rather than a grant to the
    /// caller's credentials.
    pub config: Value,
}

impl DispatchPlan {
    /// A plan targeting `plugin`'s `action`, with null config.
    pub fn new(plugin: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            plugin: plugin.into(),
            action: action.into(),
            config: Value::Null,
        }
    }

    /// Set the callee's config namespace.
    #[must_use]
    pub fn with_config(mut self, config: Value) -> Self {
        self.config = config;
        self
    }
}

/// Failure modes an orchestrator can surface.
///
/// Kept narrow on purpose — the kernel maps these to the same
/// `KernelError::NotFound` / `KernelError::Execution` variants, so
/// dispatch-site error messages stay uniform.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DispatchError {
    /// Role had no candidate plugin registered (or the orchestrator's
    /// selection policy rejected every candidate).
    RoleUnbound(String),
    /// Selection itself failed (e.g. ambiguous candidates, app-side
    /// policy violation). String message is propagated as-is.
    SelectionFailed(String),
    /// Config resolution failed (a config lookup errored, a backing
    /// store was unreachable, …). Kernel surfaces this as
    /// `KernelError::Execution`.
    ConfigResolutionFailed(String),
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RoleUnbound(m) => write!(f, "{m}"),
            Self::SelectionFailed(m) => write!(f, "{m}"),
            Self::ConfigResolutionFailed(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for DispatchError {}

/// The single inversion-of-control hook the kernel offers for
/// dispatch policy. See module docs.
///
/// Implementations must be `Send + Sync` — the kernel holds one
/// `Arc<dyn DispatchOrchestrator>` for its lifetime and calls into it
/// from every dispatch site, including parallel-wave step bodies.
pub trait DispatchOrchestrator: Send + Sync {
    fn prepare_dispatch<'a>(
        &'a self,
        request: DispatchRequest<'a>,
        ctx: DispatchContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<DispatchPlan, DispatchError>> + Send + 'a>>;
}

/// Kernel-shipped default: first-match by role, caller-namespace
/// config.
///
/// What this implementation deliberately does NOT do: consult any
/// SPI plugin for per-tenant config. Embedders that need that policy
/// register a custom orchestrator on [`super::KernelConfig`].
///
/// ## Config crosses the plugin boundary; secrets never do
///
/// Config forwards: it is not credential material and callees
/// routinely need the caller's resolution context. It is nevertheless
/// caller data crossing a boundary, and an embedder who puts sensitive
/// values in `config` rather than `secrets` should register an
/// orchestrator.
///
/// Secrets are not this type's decision — or any orchestrator's. The
/// callee pulls its own through the invocation's resolver. An embedder
/// that genuinely wants every plugin to share one credential set writes
/// a [`SecretResolver`](super::secrets::SecretResolver) that ignores
/// `subject`; that is a deliberate, greppable choice rather than a
/// default nobody noticed.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultOrchestrator;

impl DispatchOrchestrator for DefaultOrchestrator {
    fn prepare_dispatch<'a>(
        &'a self,
        request: DispatchRequest<'a>,
        ctx: DispatchContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<DispatchPlan, DispatchError>> + Send + 'a>> {
        Box::pin(async move {
            let (plugin, action) = match request {
                DispatchRequest::ByRole {
                    role,
                    action,
                    input: _,
                    hints: _,
                } => {
                    // First reachable fulfiller, nearest level first —
                    // the kernel already scoped and ordered the list.
                    let plugin = ctx.role_candidates.first().cloned().ok_or_else(|| {
                        DispatchError::RoleUnbound(format!(
                            "No plugin registered for role '{role}' reachable from {}",
                            match ctx.caller_plugin {
                                Some(caller) => format!("'{caller}'"),
                                None => "the embedder".to_string(),
                            }
                        ))
                    })?;
                    (plugin, action.to_string())
                }
                DispatchRequest::ByPlugin { plugin, action, .. } => {
                    (plugin.to_string(), action.to_string())
                }
            };
            Ok(DispatchPlan {
                plugin,
                action,
                // Config forwards. It is not credential material and
                // callees routinely need the caller's resolution
                // context — but it *is* caller data crossing a boundary,
                // and SECURITY.md says so. Secrets have no slot here at
                // all: a `secrets` field on the plan, filled from the
                // caller's bag, would mean a single granted `invoke:`
                // hands the callee the caller's entire credential
                // bundle. Having no field, rather than a field set to
                // null, is what keeps the next orchestrator from
                // filling it in.
                config: ctx.caller_config.clone(),
            })
        })
    }
}

/// Lazy-initialised process-wide default orchestrator handle.
///
/// `KernelConfig::dispatch_orchestrator` defaults to `None`; `Kernel::boot`
/// promotes that to a clone of this handle so the kernel always holds
/// a non-null `Arc<dyn DispatchOrchestrator>`. Sharing a single `Arc`
/// across kernels is fine — `DefaultOrchestrator` is stateless.
pub(crate) fn default_orchestrator() -> Arc<dyn DispatchOrchestrator> {
    use std::sync::OnceLock;
    static DEFAULT: OnceLock<Arc<dyn DispatchOrchestrator>> = OnceLock::new();
    DEFAULT
        .get_or_init(|| Arc::new(DefaultOrchestrator) as Arc<dyn DispatchOrchestrator>)
        .clone()
}
