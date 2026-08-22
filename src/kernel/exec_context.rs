//! Opaque execution context the kernel threads through every dispatch
//! site.
//!
//! The context is a single `serde_json::Value` blob; embedders own
//! the schema. The kernel never introspects it — identity, tenancy,
//! and authorization are embedder concepts the engine has no business
//! knowing about. It is a *general* invocation context, not tied to
//! any particular step type.

use serde_json::Value;

/// Opaque execution context for a plugin action.
///
/// The kernel carries this blob through every dispatch site without
/// introspecting it. Embedders construct + unpack it via their own
/// helpers in the embedder's domain layer (a multi-tenant embedder
/// might use `tenantId`, `identityId`, `membershipId`, `systemRole`
/// keys, for example).
///
/// Separate from `config` / `secrets` / `input` so it can't be
/// reached by plugin templates — there is no `$context` root, so a
/// plugin author cannot write something like `{{context.tenantId}}`
/// (an embedder-side key the kernel never resolves) to leak scoping
/// into a URL or body.
#[derive(Debug, Clone, Default)]
pub struct ExecutionContext(Value);

impl ExecutionContext {
    /// Wrap an embedder-supplied blob.
    pub fn new(value: Value) -> Self {
        Self(value)
    }

    /// Empty context (`Value::Null`). Equivalent to
    /// `ExecutionContext::default()`; the named constructor reads
    /// better at call sites that intentionally want no scope (unit
    /// tests, calls with no per-invocation scope).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Borrow the opaque payload. Embedder-side helpers use this to
    /// extract typed fields.
    pub fn as_value(&self) -> &Value {
        &self.0
    }

    /// `true` when the blob is `Value::Null` — i.e. nothing was
    /// supplied. Embedder plugin step bodies that require *any*
    /// scope (auditing, row-level scoping) can presence-check before unpacking.
    /// Embedder code should NOT branch on `is_empty` for selection
    /// logic; it tells you nothing about which typed fields are
    /// present.
    pub fn is_empty(&self) -> bool {
        self.0.is_null()
    }
}
