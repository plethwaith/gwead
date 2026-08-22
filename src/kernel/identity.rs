//! Plugin identity: the name grammar, and the namespace separator it
//! reserves.
//!
//! ## Why names need a grammar
//!
//! A plugin's name is not decoration — it is the registry key, and it
//! appears verbatim inside permission strings (`invoke:plugin:<name>`,
//! `step_type:<name>`, `provide:step_type:<type>`). With "non-empty"
//! as the only constraint, two ambiguities would be live in the
//! *current* grammar rather than a hypothetical future one:
//!
//! - A plugin literally named `*` would be indistinguishable from the
//!   `invoke:plugin:*` wildcard. It could not be granted individually,
//!   and a grant meant as "this one plugin" would read as "all of them".
//! - A name could contain `:`, the permission-string separator, so
//!   `invoke:plugin:a:b` would have two readings and the parser would
//!   silently pick one.
//!
//! Neither is expressible under [`validate_name`]. Both are ruled out
//! by the grammar from the start: tightening a name grammar later
//! would reject manifests that previously loaded.
//!
//! ## The reserved separator
//!
//! [`NAMESPACE_SEPARATOR`] (`/`) divides a plugin's embedder-supplied
//! namespace from its manifest-declared local name. The root namespace
//! is spelled as the empty string, so a root-namespace identity is
//! exactly the local name with no prefix and no separator — so a
//! single-namespace embedder never sees a separator at all.
//!
//! That spelling is only unambiguous because `/` cannot appear in a
//! manifest-declared name. Otherwise a plugin named `foo/bar` in the
//! root namespace would be indistinguishable from a plugin named `bar`
//! in namespace `foo`, and the two would collide on one registry key.
//!
//! References that already carry a separator are rejected as **reserved
//! syntax** rather than accepted as literals — see
//! [`validate_reference`]. This is the same discipline the permission
//! grammar applies to glob characters and to dot-free categories:
//! reserve the syntax while it still means nothing, so that giving it a
//! meaning later cannot silently reinterpret a grant somebody already
//! deployed.

use std::fmt;

/// Separator between a plugin's namespace and its local name.
///
/// Reserved: [`validate_name`] rejects it in every manifest-declared
/// name, so the qualified form has exactly one reading.
pub const NAMESPACE_SEPARATOR: char = '/';

/// Maximum length of a manifest-declared name, in bytes.
///
/// Names are echoed into error messages, log fields, wasm linker import
/// names, and permission strings, so an unbounded one is a log-flooding
/// nuisance with no legitimate use. The cap is deliberately generous —
/// no plausible name approaches it — but it exists now because raising
/// a limit later is additive while introducing one is breaking.
pub const MAX_NAME_LEN: usize = 128;

/// What kind of identifier failed validation. Carried in [`NameError`]
/// so the message names the manifest field the author has to fix,
/// rather than making them guess which of several names was bad.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameKind {
    /// A manifest's top-level `name`.
    Plugin,
    /// An entry of a manifest's `roles`, or the `name` of an SPI
    /// definition.
    Role,
    /// A `stepTypeDefs[].name`, or the `stepType` of a
    /// `stepTypeImpls` entry.
    StepType,
    /// The `matches` selector of a `stepTypeImpls` entry.
    StepTypeSelector,
    /// An embedder-supplied namespace passed at registration.
    Namespace,
    /// A `stepTypeImpls[].implRef` — the dotted name of a native step
    /// body submitted by a plugin crate.
    NativeImplRef,
    /// One dot-separated segment of a [`NameKind::NativeImplRef`].
    NativeImplRefSegment,
    /// One dot-separated segment of an embedder permission category
    /// declared on
    /// [`KernelConfig`](super::KernelConfig::defining_app_permission_category)
    /// — `acme` and `events` in `acme.events`.
    AppCategorySegment,
    /// A step's `id` within an action, top-level or nested. An id is a
    /// reference target — `$steps.<id>` — so it is held to the DSL's
    /// `ident` production: the name grammar, minus a leading digit.
    /// An id the DSL cannot parse would load and then be unreachable
    /// from every expression, template, and dependency edge, silently.
    StepId,
}

impl fmt::Display for NameKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NameKind::Plugin => "plugin name",
            NameKind::Role => "role name",
            NameKind::StepType => "step type name",
            NameKind::StepTypeSelector => "step type selector",
            NameKind::Namespace => "namespace",
            NameKind::NativeImplRef => "native implRef",
            NameKind::NativeImplRefSegment => "native implRef segment",
            NameKind::AppCategorySegment => "permission category segment",
            NameKind::StepId => "step id",
        })
    }
}

/// Rejection reasons from [`validate_name`] / [`validate_reference`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NameError {
    #[error("{kind} must not be empty")]
    Empty { kind: NameKind },

    #[error("{kind} '{name}' is {len} bytes, over the {max}-byte limit")]
    TooLong {
        kind: NameKind,
        name: String,
        len: usize,
        max: usize,
    },

    #[error(
        "{kind} '{name}' contains invalid character '{ch}'; allowed: \
         ASCII letters, digits, '_' and '-' (first character may not \
         be '-')"
    )]
    InvalidChar {
        kind: NameKind,
        name: String,
        ch: char,
    },

    /// A step id starting with a digit. The DSL's `ident` production
    /// — what `$steps.<id>` is parsed with — begins with a letter or
    /// `_`, so such an id could never be referenced.
    #[error(
        "{kind} '{name}' starts with a digit; a step id must start with \
         an ASCII letter or '_' so that `$steps.{name}` is parseable"
    )]
    LeadingDigit { kind: NameKind, name: String },

    /// The name or reference carries [`NAMESPACE_SEPARATOR`].
    ///
    /// Split out from [`NameError::InvalidChar`] because the fix is
    /// different in kind: this character is not merely disallowed, it
    /// is reserved for a syntax the kernel does not interpret, and the
    /// message has to say so or an author will read the rejection as
    /// arbitrary.
    #[error(
        "{kind} '{name}' uses the reserved namespace separator \
         '{sep}'. Qualified names are reserved syntax and are rejected \
         so that deployed manifests cannot change meaning if the \
         syntax is ever defined. References resolve \
         along the referring plugin's own ancestor chain; the embedder \
         supplies that namespace at registration",
        sep = NAMESPACE_SEPARATOR
    )]
    QualifiedReserved { kind: NameKind, name: String },

    /// A plugin declared a step type it does not own: a bare name
    /// (which is the kernel's), or `<other>.<name>` under another
    /// plugin's prefix.
    #[error(
        "step type '{name}' may not be declared by plugin '{plugin}': a plugin-defined \
         step type is named '<plugin>.<name>' under its own local name (here \
         '{plugin}.<name>'); dot-free names are reserved for the kernel"
    )]
    StepTypeNotOwned { name: String, plugin: String },
}

/// Validate a manifest-declared name against the identifier grammar:
/// 1 to [`MAX_NAME_LEN`] bytes of `[A-Za-z0-9_-]`, not starting with
/// `-`.
///
/// Step type names and aliases are built from this grammar too: a
/// plugin-defined one is `<plugin>.<name>`, each half a name — see
/// [`validate_step_type_name`].
///
/// Leading `-` is excluded so a name can never be mistaken for a flag
/// by an embedder's own tooling; `_` leads fine.
pub fn validate_name(kind: NameKind, name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty { kind });
    }
    if name.len() > MAX_NAME_LEN {
        return Err(NameError::TooLong {
            kind,
            name: name.to_string(),
            len: name.len(),
            max: MAX_NAME_LEN,
        });
    }
    // Checked before the per-character scan so a qualified name gets
    // the "reserved syntax" message rather than a generic bad-character
    // one, whichever position the separator is in.
    if name.contains(NAMESPACE_SEPARATOR) {
        return Err(NameError::QualifiedReserved {
            kind,
            name: name.to_string(),
        });
    }
    // A step id is parsed back out of `$steps.<id>` by the DSL, whose
    // `ident` production does not admit a leading digit.
    if kind == NameKind::StepId
        && let Some(first) = name.chars().next()
        && first.is_ascii_digit()
    {
        return Err(NameError::LeadingDigit {
            kind,
            name: name.to_string(),
        });
    }
    for (i, ch) in name.char_indices() {
        let ok = ch.is_ascii_alphanumeric() || ch == '_' || (ch == '-' && i > 0);
        if !ok {
            return Err(NameError::InvalidChar {
                kind,
                name: name.to_string(),
                ch,
            });
        }
    }
    Ok(())
}

/// Validate a *reference* to a name — a permission target, an `invoke`
/// step's `plugin` field, a guest's `io.invoke` target.
///
/// Identical to [`validate_name`]. It exists as a separate entry point
/// because the two are different concepts: a declaration always names
/// something in the declarer's own namespace, whereas a reference
/// resolves along the declarer's ancestor chain. Callers asking "am I
/// allowed to *say* this name here" should use this one, so the
/// distinction has a single home.
pub fn validate_reference(kind: NameKind, reference: &str) -> Result<(), NameError> {
    validate_name(kind, reference)
}

/// Validate an embedder-supplied namespace.
///
/// The empty string is the **root namespace** and is always valid — it
/// is the default, and it is what makes a single-namespace embedder's
/// identities identical to the bare manifest names. Any other value
/// obeys the same grammar as a name, `/` included: nesting is not
/// supported, so a namespace has no internal structure to parse and
/// [`namespace_of`] / [`local_name_of`] can split on the single
/// separator without ambiguity.
pub fn validate_namespace(namespace: &str) -> Result<(), NameError> {
    if namespace.is_empty() {
        return Ok(());
    }
    validate_name(NameKind::Namespace, namespace)
}

/// Compose a namespace and a local name into the qualified identity
/// the registry keys on.
///
/// The root namespace is a **true no-op**: `qualify("", "vault")` is
/// `"vault"`, not `"/vault"`. That is the whole reason root is spelled
/// as the empty string — an embedder that never touches namespaces gets
/// registry keys, permission strings, and error messages that are
/// simply the bare manifest names.
///
/// Both halves are assumed already validated. Because neither may
/// contain [`NAMESPACE_SEPARATOR`], the result has at most one
/// separator and decomposes unambiguously.
pub fn qualify(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        return name.to_string();
    }
    format!("{namespace}{NAMESPACE_SEPARATOR}{name}")
}

/// The namespace half of a qualified identity — `""` for root.
///
/// Total by construction: an identity with no separator is a root-
/// namespace identity, which is the correct reading rather than a
/// parse failure.
pub fn namespace_of(identity: &str) -> &str {
    // `rsplit_once`, not `split_once`. The grammar allows exactly one
    // separator, so the two are byte-identical here — but nesting is a
    // *reserved* syntax, not a forbidden one, and if
    // `tenant/team/billing` ever became legal the first-separator
    // reading would yield namespace `tenant` and local name
    // `team/billing`, silently re-decomposing every identity in the
    // registry. Splitting from the
    // right is correct at any depth. Free now; a breaking change later.
    match identity.rsplit_once(NAMESPACE_SEPARATOR) {
        Some((namespace, _)) => namespace,
        None => "",
    }
}

/// The local-name half of a qualified identity.
///
/// This is the name the manifest author wrote, recovered from the
/// registry key. Ownership rules that key on what a plugin calls itself
/// — the owner check on `implRef` binding — read it from here
/// rather than from the manifest, so they are reading an *authenticated*
/// name: the embedder chose the namespace, and the grammar guarantees
/// the split is unique.
pub fn local_name_of(identity: &str) -> &str {
    // Splits from the right — see [`namespace_of`] for why.
    match identity.rsplit_once(NAMESPACE_SEPARATOR) {
        Some((_, name)) => name,
        None => identity,
    }
}

/// Whether two identities live in the same namespace.
pub fn same_namespace(a: &str, b: &str) -> bool {
    namespace_of(a) == namespace_of(b)
}

/// The namespaces on `namespace`'s ancestor chain, nearest first:
/// itself, then each enclosing namespace, ending with root (`""`).
///
/// This is the walk every chain-scoped resolution performs — plugin
/// references, grants, secrets subjects. At depth two it yields at most
/// two items; it is written as a walk so that a deeper namespace, if
/// the grammar ever admits one, resolves without anyone revisiting the
/// callers.
pub fn ancestor_namespaces(namespace: &str) -> impl Iterator<Item = &str> {
    let mut current = Some(namespace);
    std::iter::from_fn(move || {
        let here = current?;
        current = if here.is_empty() {
            None
        } else {
            Some(
                here.rsplit_once(NAMESPACE_SEPARATOR)
                    .map(|(parent, _)| parent)
                    .unwrap_or(""),
            )
        };
        Some(here)
    })
}

/// Whether `target` is `of` itself or sits on `of`'s ancestor chain —
/// in the same namespace, or in an enclosing one, root included.
///
/// **The containment rule.** Dispatch, step-type use and secrets
/// subjects all point the same way: *upward along your own chain,
/// never down, never sideways.* Upward is safe because everything
/// above you was vouched for on behalf of a wider audience than you.
/// Downward is refused because a plugin at level N is reachable by
/// every descendant, so letting it reach one of them makes it a
/// confused deputy for all the others. Sideways is the isolation
/// boundary itself. None of those arguments mention depth, which is
/// why the rule is scale-free.
///
/// Prefix matching respects the separator: `tenant_a` is an ancestor
/// of `tenant_a/team`, and `tenant_a2` is not.
pub fn is_on_chain(target: &str, of: &str) -> bool {
    let target_ns = namespace_of(target);
    ancestor_namespaces(namespace_of(of)).any(|ns| ns == target_ns)
}

/// Validate a plugin reference made *by* `caller_identity` and spell
/// out the candidate identities it could mean, nearest first.
///
/// A reference is a bare local name; which plugin it denotes is decided
/// by walking the caller's ancestor chain and taking the first
/// candidate that is registered — see
/// [`Kernel::resolve_plugin_reference`](super::Kernel::resolve_plugin_reference),
/// which owns the registry lookup. The same walk is applied to
/// `invoke:plugin:<name>` grants at check time, so a reference and the
/// grant that authorises it can never resolve differently.
///
/// A reference carrying [`NAMESPACE_SEPARATOR`] is rejected rather than
/// resolved. Naming another namespace explicitly is not expressible,
/// and accepting the syntax as a literal would mean
/// deployed manifests silently change target the day it is honoured.
///
/// Targets flow through the template engine, so this also runs on
/// values computed at execution time — which is the point. A dynamic
/// target is exactly where an unvalidated name would otherwise reach
/// the registry.
pub fn plugin_reference_candidates(
    caller_identity: &str,
    reference: &str,
) -> Result<impl Iterator<Item = String>, NameError> {
    validate_reference(NameKind::Plugin, reference)?;
    let reference = reference.to_string();
    Ok(ancestor_namespaces(namespace_of(caller_identity))
        .map(move |ns| qualify(ns, &reference))
        .collect::<Vec<_>>()
        .into_iter())
}

/// The separator between a plugin-defined step type's owner segment
/// and its local name: `vault.sign`.
pub const STEP_TYPE_SEPARATOR: char = '.';

/// Validate a step type name as it appears in a manifest, and say
/// who it belongs to.
///
/// **The shape is the reservation.** A dot-free name — `let`, `ifs`,
/// and any word the kernel has not used yet — is the kernel's. A
/// plugin-defined step type is `<plugin>.<name>`, where `<plugin>` is
/// the defining plugin's own local name. Two consequences, both the
/// point:
///
/// - A future intrinsic can never collide with a deployed manifest,
///   because no manifest can have claimed a bare word.
/// - Ownership is in the name. `vault.sign` is shipped by `vault`,
///   legibly, and a plugin cannot define a step type under someone
///   else's prefix — so a tenant cannot squat `pdf.render` globally,
///   and an operator reading `{"type": "vault.sign"}` knows whose code
///   runs. Resolution follows: `vault` in `vault.sign` is a plugin
///   reference, resolved along the using plugin's ancestor chain like
///   any other.
///
/// `declaring_plugin` is the local name of the manifest declaring or
/// implementing this step type; `kernel_owned` is true only for the
/// engine's own intrinsics manifest.
pub fn validate_step_type_name(
    name: &str,
    declaring_plugin: &str,
    kernel_owned: bool,
) -> Result<(), NameError> {
    match name.split_once(STEP_TYPE_SEPARATOR) {
        None => {
            validate_name(NameKind::StepType, name)?;
            if kernel_owned {
                Ok(())
            } else {
                Err(NameError::StepTypeNotOwned {
                    name: name.to_string(),
                    plugin: declaring_plugin.to_string(),
                })
            }
        }
        Some((owner, local)) => {
            validate_name(NameKind::Plugin, owner)?;
            validate_name(NameKind::StepType, local)?;
            if owner == declaring_plugin {
                Ok(())
            } else {
                Err(NameError::StepTypeNotOwned {
                    name: name.to_string(),
                    plugin: declaring_plugin.to_string(),
                })
            }
        }
    }
}

/// Validate a step type name *used* by a step (`"type": …`) or named in
/// a grant: a bare kernel name, or a well-formed `<plugin>.<name>`.
/// Ownership is not checked here — a user names someone else's step
/// type by design — only the shape.
pub fn validate_step_type_reference(name: &str) -> Result<(), NameError> {
    match name.split_once(STEP_TYPE_SEPARATOR) {
        None => validate_name(NameKind::StepType, name),
        Some((owner, local)) => {
            validate_name(NameKind::Plugin, owner)?;
            validate_name(NameKind::StepType, local)
        }
    }
}

/// Number of dot-separated segments in a fully-formed native implRef:
/// `<owner>.<plugin>.<step>`.
const IMPL_REF_SEGMENTS: usize = 3;

/// Validate a native `implRef` — the dotted name a plugin crate
/// submitted via `inventory::submit!` and a manifest references.
///
/// An implRef is **not** a name: it has its own grammar of
/// dot-separated segments, each of which is a name. `.` is the segment
/// separator here exactly as `/` is the namespace separator for
/// identities, so it is permitted between segments and rejected inside
/// one.
///
/// The shape is not required to be three segments — [`impl_ref_owner`]
/// simply declines to derive an owner from anything else, which fails
/// closed. Requiring it would turn a naming convention into a grammar
/// rule, and the grammar's job here is to keep the string parseable,
/// not to police convention.
pub fn validate_impl_ref(reference: &str) -> Result<(), NameError> {
    if reference.is_empty() {
        return Err(NameError::Empty {
            kind: NameKind::NativeImplRef,
        });
    }
    if reference.contains(NAMESPACE_SEPARATOR) {
        return Err(NameError::QualifiedReserved {
            kind: NameKind::NativeImplRef,
            name: reference.to_string(),
        });
    }
    for segment in reference.split('.') {
        validate_name(NameKind::NativeImplRefSegment, segment)?;
    }
    Ok(())
}

/// The plugin an implRef belongs to: the **middle** segment of
/// `<owner>.<plugin>.<step>`.
///
/// `<owner>` says who *ships* the code (an org or application slug,
/// unrelated to the namespaces plugins are registered into) and
/// `<plugin>` says which plugin within that shipment owns it, so the
/// middle segment is the one that answers "whose body is this". Returns `None` for any
/// reference that is not exactly three segments — an owner that cannot
/// be derived is not an owner that can be matched, so binding such a
/// reference always needs explicit authorisation.
///
/// Deriving ownership from a name is only sound because plugin identity
/// is authenticated: the embedder assigns the namespace at registration
/// and the manifest cannot declare its own. Otherwise a plugin could
/// simply call itself `vault` and own `myapp.vault.*` by assertion.
#[must_use]
pub fn impl_ref_owner(reference: &str) -> Option<&str> {
    let segments: Vec<&str> = reference.split('.').collect();
    if segments.len() != IMPL_REF_SEGMENTS {
        return None;
    }
    Some(segments[1])
}

/// A registered plugin's authenticated identity.
///
/// "Authenticated" is the entire point. A manifest is a self-describing
/// document, so the name inside it proves only what its author chose to
/// write. The namespace is supplied by the **embedder** at registration
/// and cannot be influenced by the manifest, which is what lets the
/// kernel key authorization decisions on identity at all — including
/// [`KernelConfig::trusted_step_type_providers`](super::KernelConfig::trusted_step_type_providers),
/// whose guarantee is exactly as strong as the embedder's control over
/// which manifests land in which namespace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PluginIdentity {
    namespace: String,
    name: String,
}

impl PluginIdentity {
    /// Build an identity from an embedder-supplied namespace and a
    /// manifest-declared local name, validating both.
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Result<Self, NameError> {
        let namespace = namespace.into();
        let name = name.into();
        validate_namespace(&namespace)?;
        validate_name(NameKind::Plugin, &name)?;
        Ok(Self { namespace, name })
    }

    /// Build a root-namespace identity — the single-namespace embedder's
    /// case, where the identity is just the name.
    pub fn root(name: impl Into<String>) -> Result<Self, NameError> {
        Self::new(String::new(), name)
    }

    /// The embedder-supplied namespace; `""` for root.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The manifest-declared local name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether this identity is in the root namespace.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.namespace.is_empty()
    }

    /// The registry key: `name` in root, `namespace/name` otherwise.
    #[must_use]
    pub fn qualified(&self) -> String {
        qualify(&self.namespace, &self.name)
    }
}

impl fmt::Display for PluginIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.namespace.is_empty() {
            f.write_str(&self.name)
        } else {
            write!(f, "{}{NAMESPACE_SEPARATOR}{}", self.namespace, self.name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_names() {
        for name in ["vault", "gwead_intrinsics", "LLM_CHAT", "a-b", "_x", "x9"] {
            assert!(
                validate_name(NameKind::Plugin, name).is_ok(),
                "expected '{name}' to be accepted"
            );
        }
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(
            validate_name(NameKind::Plugin, ""),
            Err(NameError::Empty {
                kind: NameKind::Plugin
            })
        );
    }

    /// The wildcard ambiguity this grammar exists to close: a plugin
    /// named `*` would be indistinguishable from `invoke:plugin:*`.
    #[test]
    fn rejects_the_wildcard_name() {
        let err = validate_name(NameKind::Plugin, "*").unwrap_err();
        assert!(matches!(err, NameError::InvalidChar { ch: '*', .. }));
    }

    /// The other live ambiguity: `:` is the permission-string separator,
    /// so a name containing it gives `invoke:plugin:a:b` two readings.
    #[test]
    fn rejects_the_permission_separator() {
        let err = validate_name(NameKind::Plugin, "a:b").unwrap_err();
        assert!(matches!(err, NameError::InvalidChar { ch: ':', .. }));
    }

    /// A qualified name must be refused as *reserved*, not as a stray
    /// bad character — the message is the only thing telling an author
    /// the syntax is reserved rather than merely forbidden.
    #[test]
    fn rejects_qualified_names_as_reserved() {
        let err = validate_name(NameKind::Plugin, "tenant42/billing").unwrap_err();
        assert!(matches!(err, NameError::QualifiedReserved { .. }));
        assert!(err.to_string().contains("reserved"));
    }

    /// Root-namespace identity is the bare local name, so a leading
    /// separator has to be rejected too — `/bar` and `bar` would
    /// otherwise be two spellings of one registry key.
    #[test]
    fn rejects_leading_separator() {
        assert!(matches!(
            validate_name(NameKind::Plugin, "/bar").unwrap_err(),
            NameError::QualifiedReserved { .. }
        ));
    }

    #[test]
    fn rejects_leading_dash_but_allows_interior() {
        assert!(matches!(
            validate_name(NameKind::Plugin, "-x").unwrap_err(),
            NameError::InvalidChar { ch: '-', .. }
        ));
        assert!(validate_name(NameKind::Plugin, "x-y").is_ok());
    }

    #[test]
    fn rejects_dots_and_whitespace() {
        for bad in ["my.plugin", "my plugin", "my\tplugin", "my\nplugin"] {
            assert!(
                validate_name(NameKind::Plugin, bad).is_err(),
                "expected '{bad}' to be rejected"
            );
        }
    }

    /// Non-ASCII is rejected rather than normalised: confusable
    /// codepoints across scripts would let two visually identical
    /// manifests claim what an operator reads as one name.
    #[test]
    fn rejects_non_ascii() {
        assert!(matches!(
            validate_name(NameKind::Plugin, "vаult").unwrap_err(),
            NameError::InvalidChar { .. }
        ));
    }

    #[test]
    fn enforces_the_length_cap() {
        let ok = "a".repeat(MAX_NAME_LEN);
        assert!(validate_name(NameKind::Plugin, &ok).is_ok());
        let too_long = "a".repeat(MAX_NAME_LEN + 1);
        assert!(matches!(
            validate_name(NameKind::Plugin, &too_long).unwrap_err(),
            NameError::TooLong { .. }
        ));
    }

    #[test]
    fn error_message_names_the_field_kind() {
        let err = validate_name(NameKind::Role, "bad name").unwrap_err();
        assert!(err.to_string().contains("role name"), "{err}");
    }

    /// The root namespace must be a *true* no-op, not an empty-prefix
    /// concatenation. `"/vault"` would be a different registry key, a
    /// different permission string, and a different error message than
    /// the bare manifest name — and it would not
    /// even be expressible as a manifest name, since `/` is reserved.
    #[test]
    fn root_namespace_qualification_is_a_true_no_op() {
        assert_eq!(qualify("", "vault"), "vault");
        assert_eq!(PluginIdentity::root("vault").unwrap().qualified(), "vault");
        assert_eq!(PluginIdentity::root("vault").unwrap().to_string(), "vault");
    }

    #[test]
    fn namespaced_qualification_uses_one_separator() {
        let id = PluginIdentity::new("tenant42", "billing").unwrap();
        assert_eq!(id.qualified(), "tenant42/billing");
        assert_eq!(id.to_string(), "tenant42/billing");
        assert!(!id.is_root());
    }

    /// Decomposition has to be exact, because `implRef` ownership is
    /// derived from the local name. A wrong split would hand one
    /// plugin another's authority.
    #[test]
    fn qualified_identities_decompose_exactly() {
        for (namespace, name) in [("", "vault"), ("tenant42", "billing"), ("", "a-b_c")] {
            let q = qualify(namespace, name);
            assert_eq!(namespace_of(&q), namespace, "namespace of {q:?}");
            assert_eq!(local_name_of(&q), name, "local name of {q:?}");
        }
    }

    /// Two tenants may both call a plugin `inventory`; the whole point
    /// of namespace-qualified identity is that those are different
    /// registry keys.
    #[test]
    fn the_same_local_name_in_two_namespaces_is_two_identities() {
        let a = PluginIdentity::new("tenant_a", "inventory").unwrap();
        let b = PluginIdentity::new("tenant_b", "inventory").unwrap();
        assert_ne!(a.qualified(), b.qualified());
        assert_eq!(a.name(), b.name());
        assert!(!same_namespace(&a.qualified(), &b.qualified()));
    }

    /// The decomposition splits from the RIGHT. At depth two the two
    /// readings agree, so this pins the depth-three case directly —
    /// nesting is reserved syntax, and the day it is legal the local
    /// name must still be the last segment, not everything after the
    /// first separator. A "simplification" to `split_once` fails here
    /// and nowhere else.
    #[test]
    fn decomposition_splits_from_the_right_at_any_depth() {
        assert_eq!(namespace_of("vault"), "");
        assert_eq!(local_name_of("vault"), "vault");
        assert_eq!(namespace_of("tenant/vault"), "tenant");
        assert_eq!(local_name_of("tenant/vault"), "vault");
        assert_eq!(namespace_of("tenant/team/vault"), "tenant/team");
        assert_eq!(local_name_of("tenant/team/vault"), "vault");
    }

    #[test]
    fn the_ancestor_chain_runs_nearest_first_and_ends_at_root() {
        let chain = |ns: &str| {
            ancestor_namespaces(ns)
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        assert_eq!(chain(""), vec![""]);
        assert_eq!(chain("t"), vec!["t", ""]);
        assert_eq!(chain("t/team"), vec!["t/team", "t", ""]);
    }

    #[test]
    fn the_chain_points_up_never_down_or_sideways() {
        // self
        assert!(is_on_chain("vault", "vault"));
        assert!(is_on_chain("t/app", "t/app"));
        assert!(is_on_chain("t/other", "t/app"));
        // up
        assert!(is_on_chain("vault", "t/app"));
        assert!(is_on_chain("t/shared", "t/team/app"));
        assert!(is_on_chain("vault", "t/team/app"));
        // down
        assert!(!is_on_chain("t/app", "vault"));
        assert!(!is_on_chain("t/team/app", "t/shared"));
        // sideways
        assert!(!is_on_chain("t2/app", "t1/app"));
        assert!(!is_on_chain("t/team2/x", "t/team1/y"));
        // a shared name prefix is not an ancestor
        assert!(!is_on_chain("tenant_a2/x", "tenant_a/app"));
    }

    #[test]
    fn reference_candidates_walk_the_callers_chain() {
        let c = |caller: &str| {
            plugin_reference_candidates(caller, "billing")
                .unwrap()
                .collect::<Vec<_>>()
        };
        assert_eq!(c("shop"), vec!["billing"]);
        assert_eq!(c("t/shop"), vec!["t/billing", "billing"]);
        assert!(plugin_reference_candidates("t/shop", "x/billing").is_err());
    }

    #[test]
    fn root_is_a_namespace_like_any_other_for_containment() {
        assert!(same_namespace("vault", "billing"));
        assert!(same_namespace("t/vault", "t/billing"));
        assert!(!same_namespace("vault", "t/billing"));
    }

    #[test]
    fn the_empty_namespace_is_valid_and_others_obey_the_grammar() {
        assert!(validate_namespace("").is_ok());
        assert!(validate_namespace("tenant42").is_ok());
        // Nesting is not supported, so a namespace
        // carrying a separator is rejected rather than silently
        // producing an identity with two of them.
        assert!(matches!(
            validate_namespace("a/b").unwrap_err(),
            NameError::QualifiedReserved { .. }
        ));
        assert!(validate_namespace("bad namespace").is_err());
    }

    /// A manifest cannot smuggle a namespace in through its own name —
    /// that is the core claim of embedder-authenticated identity, and
    /// it holds because the name grammar rejects the separator before
    /// qualification happens.
    #[test]
    fn a_manifest_cannot_forge_a_namespace_via_its_name() {
        assert!(PluginIdentity::root("tenant42/billing").is_err());
        assert!(PluginIdentity::new("tenant_a", "tenant_b/billing").is_err());
    }
}
