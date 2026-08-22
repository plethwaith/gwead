//! Plugin capability model. Manifest-declared permissions
//! enforced at the host-function boundary.
//!
//! ## Surface
//!
//! Permissions are strings in `<category>:<segments>` form. The
//! kernel knows six engine-shaped categories:
//!
//! - `network:egress:<host>` — outbound HTTP to a host pattern.
//!   **Advisory** — see "Who enforces what" below.
//! - `blobs:<op>:<prefix>` — blob storage access. `op` is one of
//!   `read`, `write`, `delete`, `list`, `stat`, `watch`. **Advisory.**
//! - `step_type:<name>` — use of a specific custom step type.
//!   Enforced on both dispatch paths the kernel owns: alias-step
//!   dispatch and direct step dispatch (every non-control-flow step
//!   is checked against its definer's grant before its body runs).
//!   Native/intrinsic step impls the embedder registers are trusted by
//!   construction as *bodies*; using a step type another plugin
//!   defined still needs the grant.
//! - `invoke:plugin:<name|*>` / `invoke:role:<name|*>` — permission to
//!   dispatch into another plugin's action (`invoke` step,
//!   `io.invoke`, `io.invoke_streaming`). A plugin may always invoke
//!   its own actions; everything else is default-deny. Without this
//!   gate, `network:egress` and `blobs` would be bypassable by
//!   invoking a plugin that holds them — the classic confused deputy.
//! - `provide:step_type:<type>[:<selector>]` — declares intent to
//!   *supply* the implementation behind a step type slot, as opposed
//!   to `step_type:` which grants permission to *use* one. Required
//!   for a `stepTypeImpls` claim, and — for kernel-defined step types
//!   such as `script` — insufficient on its own: the plugin must also
//!   appear in the embedder's
//!   [`KernelConfig::trusted_step_type_providers`](super::KernelConfig::trusted_step_type_providers).
//!   See [`Permission::ProvideStepType`].
//! - `bind:native_impl:<implRef>` — declares intent to *bind* a native
//!   step body shipped by another plugin. The mirror image of
//!   `provide:`: that one supplies code others run, this one runs code
//!   somebody else supplied. Not needed to bind your own bodies, and —
//!   like `provide:step_type:` — insufficient on its own: the embedder
//!   must authorise the exact pair via
//!   [`KernelConfig::native_impl_bindings`](super::KernelConfig::native_impl_bindings).
//!   See [`Permission::BindNativeImpl`].
//!
//! ## Category reservation
//!
//! **Dot-free category names are reserved for the kernel.** An
//! unrecognised dot-free category is rejected at parse time
//! ([`PermissionParseError::ReservedCategory`]) rather than silently
//! landing as [`Permission::AppDefined`].
//!
//! Embedder categories must carry a dot-namespaced prefix:
//! `acme.events:publish:catalog.item.created`, not
//! `events:publish:...`. Those parse to [`Permission::AppDefined`],
//! where the kernel stores the raw `(kind, value)` pair and the
//! embedder enforces it in its own layer. The kernel does NOT know
//! about events / audit / storage / etc. — those concerns belong to
//! the app, not the engine.
//!
//! **An embedder category must also be declared to the kernel**, via
//! [`KernelConfig::app_permission_categories`](super::KernelConfig::app_permission_categories).
//! A manifest naming an undeclared category is a load error. Nothing
//! about the engine requires this — the kernel would happily store a
//! grant it will never consult — but a category the embedder does not
//! recognise is a grant that matches nothing, forever, silently, which
//! is the failure mode the dot-free reservation and the glob
//! reservation both exist to prevent. `acme.evets:publish:x` is
//! indistinguishable from a real category to the kernel and obvious to
//! the embedder, so the kernel asks. See [`AppPermissionCategory`].
//!
//! The reason for the dot-free reservation is silent capture. Suppose
//! a later release adds a kernel category `fs:`. Any embedder that had
//! been using `fs:` as its own category would have its grants quietly
//! reinterpreted as kernel grants, and after publish there is no way to
//! know what embedders have deployed. The namespace split makes the
//! collision impossible instead of unlikely. It also turns a
//! misspelled kernel category
//! (`invok:plugin:x`) into a load error rather than a grant that
//! silently never matches anything.
//!
//! ## Pattern syntax
//!
//! [`HostPattern`] and [`PathPattern`] support exactly three shapes,
//! and [`NamePattern`] two:
//!
//! - `*` — match anything
//! - `*.<suffix>` (host) — match anything ending in `.suffix` or
//!   exactly `suffix`
//! - `<prefix>/*` (path) — match anything starting with `prefix/`
//! - otherwise: exact match
//!
//! Deliberately minimal — but the glob *syntax space* is reserved.
//! Any `*`, `?`, or `[` appearing outside those blessed positions is
//! a parse error, not a literal. Without that rule
//! `network:egress:*.example.*` would parse as an exact-match
//! grant on the literal suffix `example.*` — a grant that silently
//! never matches — and would change meaning if fnmatch-style globbing
//! were ever added. Reinterpreting a deployed grant is a security bug
//! in whichever direction it moves, so the shapes that would need
//! reinterpreting are refused up front. Rejecting them costs nothing
//! today and buys the entire glob syntax space for later.
//!
//! ## Who enforces what — read this before trusting a grant
//!
//! The kernel enforces `invoke:`, `step_type:`, and `provide:`
//! itself, on its own dispatch surfaces.
//!
//! `network:egress` and `blobs` are **advisory**. The kernel has zero
//! call sites for [`check_network_egress`] and [`check_blobs`] — it
//! ships no HTTP client and no blob store, so there is no boundary
//! for it to gate. They are parsed, stored, and offered to the
//! embedder. **If your step type performs network or blob I/O, it
//! MUST call the matching `check_*` itself and refuse on `Denied`.**
//! A grant nobody checks restricts nothing.
//!
//! Both are also the weakest kind of gate: a step type that never
//! calls `check_*` is indistinguishable from one that called it and
//! was allowed. Build on them — they are the only answer there is —
//! but treat the `check_*` call shape as provisional.
//!
//! `bind:` is a two-key grant: the manifest half is auditable, the
//! [`KernelConfig`](super::KernelConfig) half is what authorises.
//! `provide:` for a kernel-defined step type is the same. Embedder
//! categories are enforced entirely by the embedder; the kernel checks
//! only that the category was declared.
//!
//! So: **manifest permissions are not, by themselves, the
//! authorization story.** Two of the six kernel categories are
//! enforced by you, two more need an operator's countersignature to
//! mean anything, and the seventh kind is yours end to end.
//!
//! ## Default-deny
//!
//! Where a check does run, it fails closed: an empty grant set denies,
//! and an unknown plugin's grant set reads as empty rather than as
//! absent-so-allow.

use std::fmt;
use std::sync::Arc;

use serde_json::Value;

/// A parsed permission entry from a plugin manifest.
///
/// The engine-shaped variants are `NetworkEgress`, `Blobs`,
/// `StepType`, the two `Invoke*` grants, `ProvideStepType`, and
/// `BindNativeImpl`. Everything else lands as
/// [`Permission::AppDefined`] so the kernel doesn't bake in any
/// app-shaped concepts. Embedders enforce AppDefined entries in their
/// own layer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Permission {
    NetworkEgress(HostPattern),
    Blobs(BlobOp, PathPattern),
    /// Permission to **use** a custom step type, checked at step
    /// dispatch via [`check_step_type`].
    ///
    /// This is a second, differently-named grant for "execute another
    /// plugin's action", so an audit that looks only at `invoke:`
    /// grants is incomplete. It authorises dispatch to the alias
    /// *owner* only; an orchestrator that redirects an alias somewhere
    /// else needs an `invoke:` grant for the resolved target.
    ///
    /// Checked on both the alias path and direct step dispatch — the
    /// same grant gates a `type: "<name>"` step and an alias step
    /// that resolves to one. Native and intrinsic step impls the
    /// embedder registers are trusted by construction as bodies; the
    /// grant is about who may *use* the step type, not who wrote it.
    StepType(String),
    /// `invoke:plugin:<name|*>` — dispatch into the named plugin's
    /// actions.
    ///
    /// Checked on every plugin-initiated dispatch surface, twice: once
    /// against the request before selection, and once against the plan
    /// the orchestrator resolved. The surfaces are the `invoke` step,
    /// `io.invoke`, `io.invoke_streaming`, `Kernel::dispatch_role` /
    /// `PluginExecution::dispatch_role`, and any orchestrator redirect
    /// out of an alias step.
    ///
    /// Alias steps themselves are gated by [`Permission::StepType`]
    /// instead, so an operator auditing `invoke:` grants alone will not
    /// see every path a plugin has to another plugin's code — check
    /// `step_type:` grants too. Event dispatch is ungated by design:
    /// it has no caller plugin, and its subscriber list comes from the
    /// subscribers' own `subscribesTo` declarations.
    InvokePlugin(NamePattern),
    /// `invoke:role:<name|*>` — dispatch by SPI role. Same surfaces
    /// and same two-stage check as [`Permission::InvokePlugin`].
    ///
    /// A role grant deliberately covers *whichever* plugin the
    /// orchestrator selects: delegating selection is the point of
    /// dispatching by role, and the orchestrator is embedder-supplied.
    InvokeRole(NamePattern),
    /// `provide:step_type:<type>` or
    /// `provide:step_type:<type>:<selector>` — declares that this
    /// plugin intends to *supply* the implementation registered
    /// behind a step type slot.
    ///
    /// The distinction from [`Permission::StepType`] matters: that one
    /// grants permission to **use** a step type someone else
    /// implements; this one declares intent to **be** the
    /// implementation every other plugin's steps of that type run
    /// through. Supplying `(script, "lua")` means supplying the
    /// interpreter that executes every plugin's Lua script step.
    ///
    /// `selector` is the `matches` value of the
    /// `stepTypeImpls` entry, omitted for a selector-less claim. No
    /// wildcards: a claim names one exact slot.
    ///
    /// **A declaration is not an authorisation.** Manifests are
    /// self-describing, so this grant on its own proves only that the
    /// plugin asked, which is what makes the claim auditable and
    /// greppable. For step types the *kernel* defines, the plugin must
    /// additionally be listed in
    /// [`KernelConfig::trusted_step_type_providers`](super::KernelConfig::trusted_step_type_providers).
    /// The kernel checks both halves at registration; see
    /// `Kernel::check_step_type_impl_claim`.
    ProvideStepType {
        step_type: String,
        selector: Option<String>,
    },
    /// `bind:native_impl:<implRef>` — declares intent to bind a native
    /// step body **shipped by another plugin**.
    ///
    /// The counterpart to [`Permission::ProvideStepType`], and
    /// deliberately not spelled `provide:`. `provide:` is
    /// supply-shaped: danger flows *outward*, because everyone's steps
    /// of that type then run in your code. Binding is
    /// consumption-shaped: danger flows at the body's **owner**,
    /// because you are running code someone else shipped and
    /// privileged. The two are orthogonal, so `provide:` alone cannot
    /// close this: a plugin can declare its *own* step type, satisfying
    /// `provide:` legitimately, and point `implRef` at another plugin's
    /// body.
    ///
    /// Not needed for the free path: a plugin may bind any implRef
    /// whose `<plugin>` segment is its own local name, without
    /// declaring anything.
    ///
    /// **A declaration is not an authorisation.** As with
    /// `provide:step_type:`, the manifest half only makes the claim
    /// auditable; the embedder must also authorise the exact
    /// `(binder, implRef)` pair via
    /// [`KernelConfig::native_impl_bindings`](super::KernelConfig::native_impl_bindings).
    /// No wildcards — a claim names one exact body.
    BindNativeImpl(String),
    /// App-defined permission. `kind` is the original category string,
    /// which is always dot-namespaced (`"acme.events"`,
    /// `"acme.audit"`) — dot-free categories are reserved for the
    /// kernel and rejected at parse time, so a misspelling of a kernel
    /// category cannot land here silently.
    ///
    /// `value` is intentionally schemaless: the kernel stores
    /// everything after the first `:` as a JSON string and embedders
    /// re-split / re-parse it themselves in their enforcement layer.
    /// The kernel does not validate the part after the namespace
    /// prefix, so `acme.evnets:publish:x` still parses fine and then
    /// silently never matches the embedder's gates —
    /// [`parse_permission`] emits a DEBUG-level log on every
    /// AppDefined entry so that typo is at least visible in logs.
    AppDefined {
        kind: String,
        value: Value,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlobOp {
    Read,
    Write,
    Delete,
    List,
    Stat,
    Watch,
}

impl fmt::Display for BlobOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BlobOp::Read => "read",
            BlobOp::Write => "write",
            BlobOp::Delete => "delete",
            BlobOp::List => "list",
            BlobOp::Stat => "stat",
            BlobOp::Watch => "watch",
        })
    }
}

/// Plugin / role name match pattern for `invoke:*` grants. Names are
/// flat identifiers, so only `*` and exact match apply — no suffix or
/// prefix shapes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NamePattern {
    Any,
    Exact(String),
}

impl NamePattern {
    pub fn matches(&self, name: &str) -> bool {
        match self {
            NamePattern::Any => true,
            NamePattern::Exact(n) => n == name,
        }
    }
}

/// Host-name match pattern. See module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostPattern {
    Any,
    /// `*.suffix` — matches `host == suffix` or `host.ends_with(".suffix")`.
    Suffix(String),
    Exact(String),
}

impl HostPattern {
    pub fn matches(&self, host: &str) -> bool {
        match self {
            HostPattern::Any => true,
            HostPattern::Exact(h) => h.eq_ignore_ascii_case(host),
            HostPattern::Suffix(suffix) => {
                if host.eq_ignore_ascii_case(suffix) {
                    return true;
                }
                let with_dot = format!(".{suffix}");
                let host_lower = host.to_ascii_lowercase();
                let suffix_lower = with_dot.to_ascii_lowercase();
                host_lower.ends_with(&suffix_lower)
            }
        }
    }
}

/// Path-prefix match pattern. See module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathPattern {
    Any,
    /// `prefix/*` — matches `key == prefix` or `key.starts_with("prefix/")`.
    Prefix(String),
    Exact(String),
}

impl PathPattern {
    pub fn matches(&self, key: &str) -> bool {
        match self {
            PathPattern::Any => true,
            PathPattern::Exact(p) => p == key,
            PathPattern::Prefix(prefix) => {
                if key == prefix {
                    return true;
                }
                let with_slash = format!("{prefix}/");
                key.starts_with(&with_slash)
            }
        }
    }
}

/// An embedder-defined permission category the kernel will accept in a
/// manifest.
///
/// Registered on
/// [`KernelConfig`](super::KernelConfig::defining_app_permission_category);
/// a manifest naming a category no embedder declared fails to load.
/// This is the operator half of the same two-key shape as
/// `provide:step_type:` and `bind:native_impl:` — the manifest states
/// what it wants, the embedder states what exists — except that here
/// the kernel enforces nothing at run time. It is checking that the
/// grant is *addressed to somebody*, not that the somebody agrees.
///
/// # Values
///
/// By default the kernel accepts any value after the category. The
/// kernel has no opinion about your grammar and does not want one.
///
/// [`with_validator`](Self::with_validator) closes the same gap one
/// level down: `acme.events:publsh:x` names a declared category and
/// still matches nothing. Only the embedder can judge that, and only at
/// load time — by enforcement time a never-matching grant looks exactly
/// like an absent one.
///
/// ```
/// use gwead::kernel::permissions::AppPermissionCategory;
///
/// let cat = AppPermissionCategory::new("acme.events").with_validator(|value| {
///     match value.split_once(':') {
///         Some(("publish" | "subscribe", topic)) if !topic.is_empty() => Ok(()),
///         _ => Err("expected publish:<topic> or subscribe:<topic>".to_string()),
///     }
/// });
/// assert!(cat.check_value("publish:catalog.item.created").is_ok());
/// assert!(cat.check_value("publsh:catalog.item.created").is_err());
/// ```
#[derive(Clone)]
pub struct AppPermissionCategory {
    name: String,
    #[allow(clippy::type_complexity)]
    validator: Option<Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>>,
}

impl AppPermissionCategory {
    /// Declare a category, accepting any value.
    ///
    /// The name is checked at [`Kernel::boot`](super::Kernel::boot)
    /// rather than here, so a builder chain stays infallible. A
    /// dot-free name is rejected there: dot-free categories are
    /// reserved for the kernel, so declaring one would produce a
    /// category no manifest could ever name — the very thing this
    /// mechanism exists to catch, on the config side.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            validator: None,
        }
    }

    /// Constrain the values this category accepts.
    ///
    /// The closure receives everything after the category's colon —
    /// `"publish:catalog.item.created"` for
    /// `"acme.events:publish:catalog.item.created"` — and returns
    /// `Err(explanation)` to reject the manifest. The explanation is
    /// shown to whoever is installing the plugin, so write it for them.
    #[must_use]
    pub fn with_validator<F>(mut self, validator: F) -> Self
    where
        F: Fn(&str) -> Result<(), String> + Send + Sync + 'static,
    {
        self.validator = Some(Arc::new(validator));
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether a validator was supplied. `false` means every value is
    /// accepted.
    pub fn is_value_checked(&self) -> bool {
        self.validator.is_some()
    }

    /// Run the validator, if any, against a permission value.
    pub fn check_value(&self, value: &str) -> Result<(), String> {
        match &self.validator {
            Some(f) => f(value),
            None => Ok(()),
        }
    }
}

impl fmt::Debug for AppPermissionCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppPermissionCategory")
            .field("name", &self.name)
            .field("validator", &self.validator.as_ref().map(|_| "<fn>"))
            .finish()
    }
}

/// Errors from parsing a `permissions` entry.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum PermissionParseError {
    #[error("empty permission entry")]
    Empty,
    /// A dot-free category the kernel does not define. Dot-free names
    /// are reserved for the kernel so that adding a category later
    /// cannot silently capture an embedder's deployed grants — see the
    /// module docs. Embedder categories must be dot-namespaced.
    #[error(
        "'{0}' uses the unrecognised category '{1}'. Category names without a \
         dot are reserved for the kernel (network, blobs, step_type, invoke, \
         provide, bind); embedder-defined categories must be namespaced, e.g. \
         'acme.{1}:...'"
    )]
    ReservedCategory(String, String),
    /// A dot-namespaced category no embedder declared. The kernel
    /// cannot tell `acme.evets` from a category it simply hasn't heard
    /// of, so it refuses both rather than storing a grant that will
    /// match nothing for the life of the deployment.
    #[error(
        "'{raw}' uses the embedder category '{category}', which this kernel does not \
         define. {known}"
    )]
    UnknownAppCategory {
        raw: String,
        category: String,
        /// Pre-rendered so the message can differ between "you have a
        /// typo, here is the list" and "you have declared none at all,
        /// here is how" — the second is what every embedder sees first.
        known: String,
    },
    /// The category exists and its own validator rejected the value.
    /// The reason is the embedder's words, verbatim.
    #[error("'{raw}' is not a valid '{category}' permission: {reason}")]
    AppValueRejected {
        raw: String,
        category: String,
        reason: String,
    },
    #[error("malformed permission '{0}': {1}")]
    Malformed(String, String),
}

/// Characters reserved for a future fnmatch-style glob syntax. They are
/// permitted only in the exact positions the blessed pattern shapes put
/// them; anywhere else they are a parse error rather than a literal,
/// so that adding globbing later cannot reinterpret a deployed grant.
const GLOB_CHARS: [char; 3] = ['*', '?', '['];

/// Reject any reserved glob character in `s`. Callers strip the blessed
/// wildcard first and pass only the literal remainder.
fn reject_glob_chars(raw: &str, field: &str, s: &str) -> Result<(), PermissionParseError> {
    if let Some(c) = s.chars().find(|c| GLOB_CHARS.contains(c)) {
        return Err(PermissionParseError::Malformed(
            raw.to_string(),
            format!(
                "{field} contains reserved character '{c}' outside a supported \
                 wildcard position. Supported shapes are '*' alone, '*.suffix' \
                 for hosts, and 'prefix/*' for paths; '*', '?' and '[' are \
                 reserved elsewhere for a future glob syntax"
            ),
        ));
    }
    Ok(())
}

/// Apply the [`identity`](super::identity) name grammar to a name
/// appearing inside a permission string, folding the rejection into a
/// [`PermissionParseError`].
///
/// Runs *after* [`reject_glob_chars`] wherever both apply: a `*` in the
/// wrong position is better explained as "reserved for a future glob
/// syntax" than as "invalid character", and whichever check runs first
/// owns the message.
///
/// This is what stops a grant from naming something the registry can
/// never hold. Without it, `invoke:plugin:acme.vault` would parse
/// cleanly and then match nothing, forever, silently — the same
/// never-matching-grant failure mode the glob and dot-free-category
/// reservations prevent.
fn validate_permission_name(
    raw: &str,
    kind: super::identity::NameKind,
    name: &str,
) -> Result<(), PermissionParseError> {
    super::identity::validate_reference(kind, name)
        .map_err(|e| PermissionParseError::Malformed(raw.to_string(), e.to_string()))
}

/// Parse a permission string into a structured [`Permission`].
pub fn parse_permission(raw: &str) -> Result<Permission, PermissionParseError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(PermissionParseError::Empty);
    }
    let mut parts = trimmed.splitn(2, ':');
    let category = parts.next().unwrap_or("");
    let rest = parts.next().unwrap_or("");
    match category {
        "network" => {
            let mut sub = rest.splitn(2, ':');
            let kind = sub.next().unwrap_or("");
            let pattern = sub.next().unwrap_or("");
            if kind != "egress" {
                return Err(PermissionParseError::Malformed(
                    trimmed.to_string(),
                    format!("network category supports 'egress' only, got '{kind}'"),
                ));
            }
            if pattern.is_empty() {
                return Err(PermissionParseError::Malformed(
                    trimmed.to_string(),
                    "network:egress requires a host pattern".to_string(),
                ));
            }
            Ok(Permission::NetworkEgress(parse_host_pattern(
                trimmed, pattern,
            )?))
        }
        "blobs" => {
            let mut sub = rest.splitn(2, ':');
            let op_str = sub.next().unwrap_or("");
            let prefix = sub.next().unwrap_or("");
            let op = match op_str {
                "read" => BlobOp::Read,
                "write" => BlobOp::Write,
                "delete" => BlobOp::Delete,
                "list" => BlobOp::List,
                "stat" => BlobOp::Stat,
                "watch" => BlobOp::Watch,
                _ => {
                    return Err(PermissionParseError::Malformed(
                        trimmed.to_string(),
                        format!(
                            "blobs op must be one of read/write/delete/list/stat/watch, got '{op_str}'"
                        ),
                    ));
                }
            };
            if prefix.is_empty() {
                return Err(PermissionParseError::Malformed(
                    trimmed.to_string(),
                    "blobs permission requires a path pattern".to_string(),
                ));
            }
            Ok(Permission::Blobs(op, parse_path_pattern(trimmed, prefix)?))
        }
        "step_type" => {
            if rest.is_empty() {
                return Err(PermissionParseError::Malformed(
                    trimmed.to_string(),
                    "step_type permission requires a step type name".to_string(),
                ));
            }
            // Step type names are flat identifiers with no pattern
            // shape at all, so every glob character is reserved.
            // `step_type:*` in particular would read as "any step
            // type" to an author and match only the literal name `*`.
            reject_glob_chars(trimmed, "step type name", rest)?;
            // A grant names a step type the way a step does: bare for a
            // kernel type, `<plugin>.<name>` for a plugin-defined one.
            super::identity::validate_step_type_reference(rest)
                .map_err(|e| PermissionParseError::Malformed(trimmed.to_string(), e.to_string()))?;
            Ok(Permission::StepType(rest.to_string()))
        }
        "provide" => parse_provide(trimmed, rest),
        "bind" => {
            let mut sub = rest.splitn(2, ':');
            let what = sub.next().unwrap_or("");
            let target = sub.next().unwrap_or("");
            if what != "native_impl" {
                return Err(PermissionParseError::Malformed(
                    trimmed.to_string(),
                    format!("bind category supports 'native_impl' only, got '{what}'"),
                ));
            }
            if target.is_empty() {
                return Err(PermissionParseError::Malformed(
                    trimmed.to_string(),
                    "bind:native_impl requires an implRef, e.g. \
                     bind:native_impl:myapp.vault.sign"
                        .to_string(),
                ));
            }
            // An implRef names one exact body — no pattern shape at
            // all, so every glob character is reserved.
            reject_glob_chars(trimmed, "bound implRef", target)?;
            super::identity::validate_impl_ref(target)
                .map_err(|e| PermissionParseError::Malformed(trimmed.to_string(), e.to_string()))?;
            Ok(Permission::BindNativeImpl(target.to_string()))
        }
        "invoke" => {
            let mut sub = rest.splitn(2, ':');
            let kind = sub.next().unwrap_or("");
            let name = sub.next().unwrap_or("");
            if name.is_empty() {
                return Err(PermissionParseError::Malformed(
                    trimmed.to_string(),
                    "invoke permission requires a target, e.g. invoke:plugin:<name|*> \
                     or invoke:role:<name|*>"
                        .to_string(),
                ));
            }
            // Resolved before the name is parsed so an unknown target
            // kind is reported as such. Judging the name first would
            // reject `invoke:plugni:vault` for whatever is wrong with
            // the *name*, burying the typo that actually broke it.
            let name_kind = match kind {
                "plugin" => super::identity::NameKind::Plugin,
                "role" => super::identity::NameKind::Role,
                _ => {
                    return Err(PermissionParseError::Malformed(
                        trimmed.to_string(),
                        format!("invoke category supports 'plugin' or 'role', got '{kind}'"),
                    ));
                }
            };
            // Plugin and role names are flat identifiers: `*` alone is
            // the only wildcard shape, so `ff*` must be refused rather
            // than becoming an exact match on a name containing a star.
            let pattern = if name == "*" {
                NamePattern::Any
            } else {
                reject_glob_chars(trimmed, "invoke target name", name)?;
                validate_permission_name(trimmed, name_kind, name)?;
                NamePattern::Exact(name.to_string())
            };
            Ok(match name_kind {
                super::identity::NameKind::Role => Permission::InvokeRole(pattern),
                _ => Permission::InvokePlugin(pattern),
            })
        }
        // Dot-namespaced categories land as AppDefined; dot-free ones
        // are reserved for the kernel and rejected here. See the
        // module docs on category reservation for why the split
        // exists. The embedder pattern-matches on `kind` and parses
        // `value` in its own enforcement layer.
        other => {
            if other.is_empty() {
                return Err(PermissionParseError::Empty);
            }
            if !other.contains('.') {
                return Err(PermissionParseError::ReservedCategory(
                    trimmed.to_string(),
                    other.to_string(),
                ));
            }
            // A category with nothing after it grants nothing that
            // could ever be matched. The meta-schema requires
            // `<category>:<value>`; the parser must as well, because a
            // manifest handed in as a struct never meets the schema.
            // Same never-matching grant, one layer down.
            if rest.is_empty() {
                return Err(PermissionParseError::Malformed(
                    trimmed.to_string(),
                    format!("'{other}' has no value — a permission is '<category>:<value>'"),
                ));
            }
            // Surface the AppDefined landing at DEBUG so the
            // misspelled-permission case (`evnets:publish:...`) is
            // visible in logs — the kernel can't tell typos apart
            // from genuinely embedder-defined categories, but the
            // embedder reading logs can.
            tracing::debug!(
                permission_kind = %other,
                permission_value = %rest,
                "permission parsed as AppDefined — embedder enforcement \
                 layer must recognise this `kind`, or it grants nothing"
            );
            Ok(Permission::AppDefined {
                kind: other.to_string(),
                value: serde_json::Value::String(rest.to_string()),
            })
        }
    }
}

/// `*` | `*.<suffix>` | `<exact>`. Any other appearance of a reserved
/// glob character is an error — see [`reject_glob_chars`].
fn parse_host_pattern(raw: &str, s: &str) -> Result<HostPattern, PermissionParseError> {
    if s == "*" {
        return Ok(HostPattern::Any);
    }
    // `:` is reserved in a host pattern. `example.com:8080` parses
    // as an exact host literal that happens to contain a colon — which
    // matches nothing, since hosts are compared without a port — and
    // the day port syntax is added that deployed grant would silently
    // change meaning. Same reservation as the glob characters, one
    // character over: refuse it while it means nothing.
    if s.contains(':') {
        return Err(PermissionParseError::Malformed(
            raw.to_string(),
            "host pattern contains ':'. Ports are not expressible in a host pattern and \
             ':' is reserved so that port syntax can be added without reinterpreting \
             deployed grants; grant the host alone"
                .to_string(),
        ));
    }
    if let Some(suffix) = s.strip_prefix("*.") {
        // `*.` alone would be `Suffix("")`, which every FQDN ends with —
        // a wildcard spelled so it does not look like one. The schema
        // already refuses it; the struct path must too.
        if suffix.is_empty() {
            return Err(PermissionParseError::Malformed(
                raw.to_string(),
                "`*.` needs a suffix (`*.example.com`); for any host write `*`".to_string(),
            ));
        }
        reject_glob_chars(raw, "host pattern suffix", suffix)?;
        return Ok(HostPattern::Suffix(suffix.to_string()));
    }
    reject_glob_chars(raw, "host pattern", s)?;
    Ok(HostPattern::Exact(s.to_string()))
}

/// `*` | `<prefix>/*` | `<exact>`. Any other appearance of a reserved
/// glob character is an error — see [`reject_glob_chars`].
fn parse_path_pattern(raw: &str, s: &str) -> Result<PathPattern, PermissionParseError> {
    if s == "*" {
        return Ok(PathPattern::Any);
    }
    if let Some(prefix) = s.strip_suffix("/*") {
        reject_glob_chars(raw, "path pattern prefix", prefix)?;
        return Ok(PathPattern::Prefix(prefix.to_string()));
    }
    reject_glob_chars(raw, "path pattern", s)?;
    Ok(PathPattern::Exact(s.to_string()))
}

/// `provide:step_type:<type>` or
/// `provide:step_type:<type>:<selector>`.
///
/// A claim names one exact slot, so no wildcard shape applies and
/// every reserved glob character is refused in both segments.
fn parse_provide(raw: &str, rest: &str) -> Result<Permission, PermissionParseError> {
    let mut sub = rest.splitn(2, ':');
    let what = sub.next().unwrap_or("");
    let target = sub.next().unwrap_or("");
    if what != "step_type" {
        return Err(PermissionParseError::Malformed(
            raw.to_string(),
            format!("provide category supports 'step_type' only, got '{what}'"),
        ));
    }
    if target.is_empty() {
        return Err(PermissionParseError::Malformed(
            raw.to_string(),
            "provide:step_type requires a step type, e.g. \
             provide:step_type:script:lua"
                .to_string(),
        ));
    }
    // The selector is optional and itself may contain no colon, so a
    // single split is the whole grammar.
    let (step_type, selector) = match target.split_once(':') {
        Some((t, "")) => {
            return Err(PermissionParseError::Malformed(
                raw.to_string(),
                format!(
                    "provide:step_type:{t}: has a trailing colon but no \
                     selector — drop the colon for a selector-less claim"
                ),
            ));
        }
        Some((t, sel)) => (t, Some(sel.to_string())),
        None => (target, None),
    };
    reject_glob_chars(raw, "provided step type", step_type)?;
    super::identity::validate_step_type_reference(step_type)
        .map_err(|e| PermissionParseError::Malformed(raw.to_string(), e.to_string()))?;
    if let Some(sel) = &selector {
        reject_glob_chars(raw, "provided step type selector", sel)?;
        validate_permission_name(raw, super::identity::NameKind::StepTypeSelector, sel)?;
    }
    Ok(Permission::ProvideStepType {
        step_type: step_type.to_string(),
        selector,
    })
}

/// Parse every entry in a manifest's `permissions` list.
///
/// This checks the *kernel's* half of the grammar only. Embedder
/// categories land as [`Permission::AppDefined`] without anyone asking
/// whether that category exists — use [`parse_manifest_permissions`]
/// for the load path, which is the version that does.
pub fn parse_permission_list(raw: &[String]) -> Result<Vec<Permission>, PermissionParseError> {
    raw.iter().map(|s| parse_permission(s)).collect()
}

/// Parse a manifest's `permissions` list and hold every embedder
/// category in it to the set the embedder declared.
///
/// The two steps are one function because separating them is how the
/// check gets forgotten: a later caller that parses and stores without
/// checking reintroduces exactly the silent never-matching grant this
/// exists to stop. The kernel's registration path calls this and
/// nothing else.
pub fn parse_manifest_permissions(
    raw: &[String],
    categories: &[AppPermissionCategory],
) -> Result<Vec<Permission>, PermissionParseError> {
    raw.iter()
        .map(|entry| {
            let parsed = parse_permission(entry)?;
            if let Permission::AppDefined { kind, value } = &parsed {
                let raw = entry.trim();
                let Some(category) = categories.iter().find(|c| c.name() == kind) else {
                    return Err(PermissionParseError::UnknownAppCategory {
                        raw: raw.to_string(),
                        category: kind.clone(),
                        known: describe_known_categories(categories),
                    });
                };
                // `value` is always the `Value::String` half of an
                // AppDefined entry; the fallback keeps this total
                // rather than panicking if that ever changes.
                let value = value.as_str().unwrap_or_default();
                category.check_value(value).map_err(|reason| {
                    PermissionParseError::AppValueRejected {
                        raw: raw.to_string(),
                        category: kind.clone(),
                        reason,
                    }
                })?;
            }
            Ok(parsed)
        })
        .collect()
}

/// The tail of an [`UnknownAppCategory`](PermissionParseError::UnknownAppCategory)
/// message.
///
/// The empty case gets the how rather than the what, because it is not
/// a typo — it is an embedder meeting this rule for the first time, and
/// the fix is one line they have never seen.
fn describe_known_categories(categories: &[AppPermissionCategory]) -> String {
    if categories.is_empty() {
        return "This kernel declares no embedder permission categories at all. If the \
                category is yours, declare it at boot: \
                `KernelConfig::default().defining_app_permission_category(\"acme.events\")`"
            .to_string();
    }
    let mut names: Vec<&str> = categories.iter().map(AppPermissionCategory::name).collect();
    names.sort_unstable();
    format!(
        "Declared categories: {}. Check for a typo, or declare this one at boot with \
         `KernelConfig::defining_app_permission_category`",
        names.join(", ")
    )
}

/// Check a category name an embedder registered, at boot.
///
/// A registered name that no manifest could ever match is the same
/// never-matching failure this whole mechanism exists to surface, just
/// pointing the other way — so it is refused at the point the embedder
/// can still fix it.
pub(crate) fn validate_app_category_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("category name is empty".to_string());
    }
    if !name.contains('.') {
        return Err(format!(
            "'{name}' has no dot. Dot-free category names are reserved for the kernel, so \
             no manifest could ever name this one — use a namespaced form such as \
             'acme.{name}'"
        ));
    }
    if name.contains(':') {
        return Err(format!(
            "'{name}' contains ':', which separates the category from its value. Declare \
             the category alone: '{}'",
            name.split(':').next().unwrap_or(name)
        ));
    }
    for segment in name.split('.') {
        super::identity::validate_name(super::identity::NameKind::AppCategorySegment, segment)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Result of a permission check. `Granted` always satisfies; `Denied`
/// carries the requested permission for error reporting.
#[derive(Debug)]
#[non_exhaustive]
pub enum PermissionCheck {
    Granted,
    Denied { requested: String },
}

impl PermissionCheck {
    pub fn is_granted(&self) -> bool {
        matches!(self, PermissionCheck::Granted)
    }
}

/// Does the granted set authorise `network:egress` to `host`?
///
/// **Advisory — the kernel never calls this.** It ships no HTTP
/// client, so there is no boundary for it to gate. If your step type
/// performs network I/O it MUST call this itself and refuse on
/// `Denied`; a grant nobody checks restricts nothing.
///
/// A step type that never calls this is indistinguishable from one
/// that called it and was allowed, which is why the call shape is
/// provisional — see
/// [`PluginExecution::check_network_egress`](super::host_api::PluginExecution::check_network_egress).
pub fn check_network_egress(grants: &[Permission], host: &str) -> PermissionCheck {
    for grant in grants {
        if let Permission::NetworkEgress(pat) = grant
            && pat.matches(host)
        {
            return PermissionCheck::Granted;
        }
    }
    PermissionCheck::Denied {
        requested: format!("network:egress:{host}"),
    }
}

/// Does the granted set authorise the blob `op` against `key`?
///
/// **Advisory — the kernel never calls this**, for the same reason as
/// [`check_network_egress`]. Your step type owns the gate.
pub fn check_blobs(grants: &[Permission], op: BlobOp, key: &str) -> PermissionCheck {
    for grant in grants {
        if let Permission::Blobs(grant_op, pattern) = grant
            && *grant_op == op
            && pattern.matches(key)
        {
            return PermissionCheck::Granted;
        }
    }
    PermissionCheck::Denied {
        requested: format!("blobs:{op}:{key}"),
    }
}

// There is deliberately no `check_invoke_plugin` here. Plugin grants
// resolve along the declaring plugin's ancestor chain against the live
// registry, so the check lives on `Kernel` where the registry is —
// see `Kernel::check_invoke_plugin`. A pattern-only check would answer
// wrongly for `invoke:plugin:*` (which never crosses a level) and for
// bare names (which denote whichever chain candidate is registered).

/// Does the granted set authorise dispatching by the named SPI role?
pub fn check_invoke_role(grants: &[Permission], role: &str) -> PermissionCheck {
    for grant in grants {
        if let Permission::InvokeRole(pat) = grant
            && pat.matches(role)
        {
            return PermissionCheck::Granted;
        }
    }
    PermissionCheck::Denied {
        requested: format!("invoke:role:{role}"),
    }
}

/// Does the granted set authorise use of the named custom step type?
pub fn check_step_type(grants: &[Permission], step_type: &str) -> PermissionCheck {
    for grant in grants {
        if let Permission::StepType(name) = grant
            && name == step_type
        {
            return PermissionCheck::Granted;
        }
    }
    PermissionCheck::Denied {
        requested: format!("step_type:{step_type}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_network_egress() {
        let p = parse_permission("network:egress:*").unwrap();
        assert_eq!(p, Permission::NetworkEgress(HostPattern::Any));

        let p = parse_permission("network:egress:*.example.com").unwrap();
        assert_eq!(
            p,
            Permission::NetworkEgress(HostPattern::Suffix("example.com".to_string()))
        );

        let p = parse_permission("network:egress:api.example.com").unwrap();
        assert_eq!(
            p,
            Permission::NetworkEgress(HostPattern::Exact("api.example.com".to_string()))
        );
    }

    #[test]
    fn parses_blobs() {
        let p = parse_permission("blobs:write:media/*").unwrap();
        assert_eq!(
            p,
            Permission::Blobs(BlobOp::Write, PathPattern::Prefix("media".to_string()))
        );

        let p = parse_permission("blobs:read:*").unwrap();
        assert_eq!(p, Permission::Blobs(BlobOp::Read, PathPattern::Any));

        let p = parse_permission("blobs:delete:tmp/file.bin").unwrap();
        assert_eq!(
            p,
            Permission::Blobs(
                BlobOp::Delete,
                PathPattern::Exact("tmp/file.bin".to_string())
            )
        );

        for op in ["read", "write", "delete", "list", "stat", "watch"] {
            assert!(
                parse_permission(&format!("blobs:{op}:x")).is_ok(),
                "should parse blobs:{op}",
            );
        }
    }

    #[test]
    fn namespaced_category_parses_as_app_defined() {
        // The kernel hardcodes no app-shaped categories. A
        // dot-namespaced category outside the kernel's six becomes
        // `AppDefined`; embedders enforce in their own layer.
        let p = parse_permission("acme.fs:read:foo").unwrap();
        assert_eq!(
            p,
            Permission::AppDefined {
                kind: "acme.fs".to_string(),
                value: serde_json::Value::String("read:foo".to_string()),
            }
        );
    }

    #[test]
    fn events_audit_storage_parse_as_app_defined_when_namespaced() {
        // Documents that app-shaped categories such as events/audit/
        // storage parse as AppDefined once namespaced.
        let p = parse_permission("acme.events:publish:catalog.item.created").unwrap();
        assert_eq!(
            p,
            Permission::AppDefined {
                kind: "acme.events".to_string(),
                value: serde_json::Value::String("publish:catalog.item.created".to_string()),
            }
        );
        let p = parse_permission("acme.audit:write").unwrap();
        assert_eq!(
            p,
            Permission::AppDefined {
                kind: "acme.audit".to_string(),
                value: serde_json::Value::String("write".to_string()),
            }
        );
        let p = parse_permission("acme.storage:inventory:read").unwrap();
        assert_eq!(
            p,
            Permission::AppDefined {
                kind: "acme.storage".to_string(),
                value: serde_json::Value::String("inventory:read".to_string()),
            }
        );
    }

    /// The reservation rule exists so that adding a kernel category
    /// later cannot silently capture an embedder's deployed grants.
    /// Each of these must be a load error, not an AppDefined grant
    /// waiting to change meaning.
    #[test]
    fn dot_free_unknown_categories_are_reserved_and_rejected() {
        for raw in [
            "fs:read:foo",
            "exec:spawn:ffmpeg",
            "env:read:PATH",
            "events:publish:x",
            "audit:write",
            "storage:inventory:read",
        ] {
            let err = parse_permission(raw).unwrap_err();
            assert!(
                matches!(err, PermissionParseError::ReservedCategory(_, _)),
                "{raw} should be rejected as a reserved category, got {err:?}"
            );
        }
    }

    /// A typo in a kernel category name must not parse into an
    /// AppDefined grant that silently matches nothing; it is a
    /// load-time error naming the offending category.
    #[test]
    fn misspelled_kernel_category_is_rejected_not_silently_app_defined() {
        let err = parse_permission("invok:plugin:victim").unwrap_err();
        match err {
            PermissionParseError::ReservedCategory(raw, cat) => {
                assert_eq!(raw, "invok:plugin:victim");
                assert_eq!(cat, "invok");
            }
            other => panic!("expected ReservedCategory, got {other:?}"),
        }
    }

    /// Wildcards outside the blessed shapes must be refused rather
    /// than parsed as literals. Every entry here would otherwise
    /// become an exact-match grant containing a `*` — a grant that
    /// never matches and would change meaning if fnmatch-style
    /// globbing were ever added.
    #[test]
    fn wildcards_outside_blessed_shapes_are_rejected() {
        for raw in [
            "network:egress:*.example.*",
            "network:egress:api.*.example.com",
            "network:egress:*example.com",
            "network:egress:api?.example.com",
            "network:egress:api[12].example.com",
            "blobs:read:a/*/b",
            "blobs:read:*/media",
            "blobs:write:media/*/thumbs",
            "step_type:*",
            "step_type:resize_*",
            "provide:step_type:script:*",
            "provide:step_type:*",
            "invoke:plugin:ff*",
            "invoke:role:LLM_*",
        ] {
            let err = parse_permission(raw).unwrap_err();
            assert!(
                matches!(err, PermissionParseError::Malformed(_, _)),
                "{raw} should be rejected as a reserved glob shape, got {err:?}"
            );
        }
    }

    /// The blessed shapes parse: glob rejection must not swallow the
    /// wildcard forms the grammar does support.
    #[test]
    fn blessed_wildcard_shapes_still_parse() {
        assert_eq!(
            parse_permission("network:egress:*").unwrap(),
            Permission::NetworkEgress(HostPattern::Any)
        );
        assert_eq!(
            parse_permission("network:egress:*.example.com").unwrap(),
            Permission::NetworkEgress(HostPattern::Suffix("example.com".to_string()))
        );
        assert_eq!(
            parse_permission("blobs:read:*").unwrap(),
            Permission::Blobs(BlobOp::Read, PathPattern::Any)
        );
        assert_eq!(
            parse_permission("blobs:write:media/*").unwrap(),
            Permission::Blobs(BlobOp::Write, PathPattern::Prefix("media".to_string()))
        );
        assert_eq!(
            parse_permission("invoke:plugin:*").unwrap(),
            Permission::InvokePlugin(NamePattern::Any)
        );
        assert_eq!(
            parse_permission("invoke:role:*").unwrap(),
            Permission::InvokeRole(NamePattern::Any)
        );
    }

    #[test]
    fn parses_provide_step_type() {
        assert_eq!(
            parse_permission("provide:step_type:script:lua").unwrap(),
            Permission::ProvideStepType {
                step_type: "script".to_string(),
                selector: Some("lua".to_string()),
            }
        );
        assert_eq!(
            parse_permission("provide:step_type:resize_image").unwrap(),
            Permission::ProvideStepType {
                step_type: "resize_image".to_string(),
                selector: None,
            }
        );
    }

    #[test]
    fn rejects_malformed_provide() {
        assert!(parse_permission("provide:").is_err());
        assert!(parse_permission("provide:step_type").is_err());
        assert!(parse_permission("provide:step_type:").is_err());
        assert!(parse_permission("provide:step_type:script:").is_err());
        assert!(parse_permission("provide:action:sign").is_err());
    }

    #[test]
    fn parses_invoke() {
        let p = parse_permission("invoke:plugin:*").unwrap();
        assert_eq!(p, Permission::InvokePlugin(NamePattern::Any));

        let p = parse_permission("invoke:plugin:ffprobe").unwrap();
        assert_eq!(
            p,
            Permission::InvokePlugin(NamePattern::Exact("ffprobe".to_string()))
        );

        let p = parse_permission("invoke:role:LLM_CHAT").unwrap();
        assert_eq!(
            p,
            Permission::InvokeRole(NamePattern::Exact("LLM_CHAT".to_string()))
        );
    }

    #[test]
    fn rejects_malformed_invoke() {
        assert!(parse_permission("invoke:plugin:").is_err());
        assert!(parse_permission("invoke:").is_err());
        assert!(parse_permission("invoke:action:x").is_err());
    }

    /// `:` in a host pattern is reserved for port syntax.
    #[test]
    fn a_port_in_a_host_pattern_is_rejected() {
        let err = parse_permission("network:egress:example.com:8080").expect_err("refused");
        assert!(err.to_string().contains("reserved"), "{err}");
        assert!(parse_permission("network:egress:*.example.com:443").is_err());
    }

    /// `*.` alone would be `Suffix("")` — a match-everything wildcard
    /// that does not look like one.
    #[test]
    fn an_empty_suffix_is_rejected() {
        let err = parse_permission("network:egress:*.").expect_err("refused");
        assert!(err.to_string().contains("needs a suffix"), "{err}");
        assert!(parse_permission("network:egress:*.example.com").is_ok());
    }

    #[test]
    fn check_invoke_role_denies_by_default() {
        assert!(!check_invoke_role(&[], "ANY_ROLE").is_granted());
        // A plugin grant doesn't satisfy a role dispatch.
        let plugin_only = vec![Permission::InvokePlugin(NamePattern::Any)];
        assert!(!check_invoke_role(&plugin_only, "X").is_granted());
    }

    #[test]
    fn check_step_type_exact_match_only() {
        let grants = vec![Permission::StepType("resize_image".to_string())];
        assert!(check_step_type(&grants, "resize_image").is_granted());
        assert!(!check_step_type(&grants, "resize").is_granted());
        assert!(!check_step_type(&[], "resize_image").is_granted());
    }

    #[test]
    fn rejects_bad_blobs_op() {
        let err = parse_permission("blobs:execute:x").unwrap_err();
        assert!(matches!(err, PermissionParseError::Malformed(_, _)));
    }

    #[test]
    fn rejects_empty_pattern() {
        assert!(parse_permission("network:egress:").is_err());
        assert!(parse_permission("blobs:read:").is_err());
    }

    #[test]
    fn host_pattern_any_matches_anything() {
        let p = HostPattern::Any;
        assert!(p.matches("anything.test"));
        assert!(p.matches("localhost"));
        assert!(p.matches("10.0.0.1"));
    }

    #[test]
    fn host_pattern_suffix_matches_subdomains() {
        let p = HostPattern::Suffix("example.com".to_string());
        assert!(p.matches("example.com")); // bare suffix
        assert!(p.matches("api.example.com"));
        assert!(p.matches("a.b.example.com"));
        assert!(!p.matches("notexample.com"));
        assert!(!p.matches("example.org"));
    }

    #[test]
    fn host_pattern_exact_only_matches_exact() {
        let p = HostPattern::Exact("api.example.com".to_string());
        assert!(p.matches("api.example.com"));
        assert!(p.matches("API.EXAMPLE.COM")); // case-insensitive
        assert!(!p.matches("foo.api.example.com"));
        assert!(!p.matches("example.com"));
    }

    #[test]
    fn path_pattern_prefix_matches_children_and_self() {
        let p = PathPattern::Prefix("media".to_string());
        assert!(p.matches("media")); // exact bare prefix
        assert!(p.matches("media/foo"));
        assert!(p.matches("media/a/b/c"));
        assert!(!p.matches("mediator")); // not "media/..."
        assert!(!p.matches("other/path"));
    }

    #[test]
    fn check_network_egress_matches_any() {
        let grants = vec![Permission::NetworkEgress(HostPattern::Any)];
        assert!(check_network_egress(&grants, "anything").is_granted());
    }

    #[test]
    fn check_network_egress_denies_by_default() {
        let grants = vec![];
        let check = check_network_egress(&grants, "evil.com");
        assert!(!check.is_granted());
        match check {
            PermissionCheck::Denied { requested } => {
                assert!(requested.contains("evil.com"));
            }
            _ => panic!("expected Denied"),
        }
    }

    #[test]
    fn check_blobs_only_matches_same_op() {
        let grants = vec![Permission::Blobs(
            BlobOp::Read,
            PathPattern::Prefix("media".to_string()),
        )];
        assert!(check_blobs(&grants, BlobOp::Read, "media/x").is_granted());
        // Write isn't granted just because Read is.
        assert!(!check_blobs(&grants, BlobOp::Write, "media/x").is_granted());
    }

    #[test]
    fn parse_list_collects_errors_on_first_bad_entry() {
        // The list parser fails on the first bad entry; an empty entry
        // in the middle fails the whole list.
        let raw = vec![
            "network:egress:*".to_string(),
            "".to_string(),
            "blobs:read:*".to_string(),
        ];
        let err = parse_permission_list(&raw).unwrap_err();
        assert!(matches!(err, PermissionParseError::Empty));
    }
}
