//! Parent-action context handed to a script-runtime sub-instance.
//!
//! The snapshot bundles the parent's dispatch + scope + depth state so
//! the sub-instance's `host_invoke` import (the `io.invoke` a guest
//! runtime wraps it in) recurses into the same kernel with the same
//! scope a DAG-level step would.

use serde_json::Value;

/// Parent-action context handed to the script-runtime sub-instance for
/// its `host_invoke` import (the `io.invoke` a guest runtime wraps it
/// in). Captured once at sub-instance
/// construction; the host imports read from
/// [`super::store_data::ScriptRuntimeStoreData`] (which itself was
/// populated from this struct).
#[derive(Clone)]
pub(crate) struct ScriptRuntimeParentContext {
    pub(crate) kernel: Option<std::sync::Weak<crate::kernel::Kernel>>,
    /// Plugin that owns the script step — passed through to the
    /// dispatch orchestrator so app-shaped orchestrators
    /// can scope selection by caller identity.
    pub(crate) plugin: String,
    pub(crate) config: Value,
    pub(crate) secret_resolver: Option<std::sync::Arc<dyn crate::kernel::secrets::SecretResolver>>,
    pub(crate) exec_ctx: crate::kernel::exec_context::ExecutionContext,
    pub(crate) invoke_depth: u32,
}
