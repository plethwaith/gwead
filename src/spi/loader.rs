//! SPI registry — a uniform home for SPI definitions.
//!
//! The kernel boots with an empty registry. The embedder supplies
//! global SPI definitions via
//! [`crate::kernel::Kernel::register_spi_from_json`] or
//! `load_manifest`, and a tenant's via
//! `load_manifest(..).in_namespace(..)`. Gwead itself ships zero SPI
//! definitions — role contracts are application-shaped, not
//! engine-shaped.

use std::collections::HashMap;

use super::definition::SpiDefinition;
use crate::kernel::KernelError;

/// Holds parsed SPI definitions keyed by **qualified role identity** —
/// `ROLE` for a contract the embedder registered into root,
/// `namespace/ROLE` for one a tenant defined. A role is named the way a
/// plugin is, and it resolves the same way: along the referring
/// plugin's ancestor chain, nearest first. See [`Self::resolve`].
#[derive(Debug, Default)]
pub struct SpiRegistry {
    definitions: HashMap<String, SpiDefinition>,
}

impl SpiRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self {
            definitions: HashMap::new(),
        }
    }

    /// Register a single SPI definition from its JSON source.
    ///
    /// Canonical entry point — every SPI contribution goes through here,
    /// whether from a host's startup walk of its manifests directory or
    /// from `load_manifest`.
    ///
    /// Re-registering a role with an identical definition is an
    /// idempotent `Ok` (manifest reload depends on this). Re-registering
    /// with a *different* definition is rejected — a role's contract can
    /// only change through the explicit unregister/reload path, never by
    /// silent overwrite.
    pub fn register(&mut self, role: &str, json: &str) -> Result<(), KernelError> {
        let def: SpiDefinition = serde_json::from_str(json).map_err(|e| {
            KernelError::Runtime(format!("Failed to parse SPI definition {role:?}: {e}"))
        })?;
        if let Some(existing) = self.definitions.get(role) {
            if *existing == def {
                tracing::debug!(role = %role, "SPI definition re-registered unchanged (idempotent)");
                return Ok(());
            }
            return Err(KernelError::Validation(format!(
                "SPI role {role:?} is already registered with a different definition — \
                 conflicting redefinition rejected; unload/reload the existing definition \
                 to change the contract"
            )));
        }
        tracing::debug!(role = %role, "Registered SPI definition");
        self.definitions.insert(role.to_string(), def);
        Ok(())
    }

    /// Get the SPI definition under exactly this qualified key.
    pub fn get(&self, role: &str) -> Option<&SpiDefinition> {
        self.definitions.get(role)
    }

    /// Resolve a bare role name as written by a plugin in `namespace`:
    /// the nearest definition up the chain — the namespace's own, then
    /// each enclosing one, then root. Returns the qualified key it
    /// landed on alongside the definition, or `None` when nothing on
    /// the chain defines the role.
    ///
    /// This is what makes a tenant-defined contract shadow a global one
    /// of the same name for that tenant only, and what lets a tenant
    /// plugin fulfil a global contract by its bare name.
    pub fn resolve(&self, namespace: &str, role: &str) -> Option<(String, &SpiDefinition)> {
        crate::kernel::identity::ancestor_namespaces(namespace)
            .map(|ns| crate::kernel::identity::qualify(ns, role))
            .find_map(|key| self.definitions.get(&key).map(|def| (key.clone(), def)))
    }

    /// List all registered SPI role names.
    pub fn roles(&self) -> Vec<&str> {
        self.definitions.keys().map(|s| s.as_str()).collect()
    }

    /// Number of loaded SPI definitions.
    pub fn len(&self) -> usize {
        self.definitions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.definitions.is_empty()
    }

    /// Remove an SPI definition by role name.
    ///
    /// The kernel is responsible for rejecting calls that would leave
    /// loaded plugins claiming an undefined contract — this method is
    /// the storage-side primitive only. Returns `false` when the role
    /// wasn't registered.
    pub fn unregister(&mut self, role: &str) -> bool {
        self.definitions.remove(role).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Gwead-internal tests cover registry mechanics only. The set of
    // capability SPIs an embedding application ships is
    // application-shaped and lives with that application; coverage for
    // what's actually loaded at boot lives alongside that data, not here.

    #[test]
    fn register_accepts_an_ad_hoc_spi() {
        let mut registry = SpiRegistry::new();
        let ad_hoc_json = r#"{
            "name": "AD_HOC_TEST",
            "version": "1.0",
            "description": "Synthesized for the uniform-registration test.",
            "actions": {
                "ping": {
                    "input": {"type": "object", "properties": {}},
                    "output": {"type": "object", "properties": {}}
                }
            }
        }"#;
        registry
            .register("AD_HOC_TEST", ad_hoc_json)
            .expect("ad-hoc SPI should register");
        let def = registry.get("AD_HOC_TEST").expect("should be present");
        assert_eq!(def.name, "AD_HOC_TEST");
        assert!(def.actions.contains_key("ping"));
    }

    #[test]
    fn identical_re_registration_is_idempotent_ok() {
        let mut registry = SpiRegistry::new();
        let json = r#"{
            "name": "STABLE_ROLE",
            "version": "1.0",
            "actions": {
                "ping": {
                    "input": {"type": "object"},
                    "output": {"type": "object"}
                }
            }
        }"#;
        registry
            .register("STABLE_ROLE", json)
            .expect("first registration");
        registry
            .register("STABLE_ROLE", json)
            .expect("identical re-registration must stay Ok (manifest reload relies on it)");
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn conflicting_redefinition_is_rejected() {
        let mut registry = SpiRegistry::new();
        let original = r#"{
            "name": "CONTESTED_ROLE",
            "version": "1.0",
            "actions": {
                "ping": {
                    "input": {"type": "object"},
                    "output": {"type": "object"}
                }
            }
        }"#;
        let conflicting = r#"{
            "name": "CONTESTED_ROLE",
            "version": "2.0",
            "actions": {
                "pong": {
                    "input": {"type": "object"},
                    "output": {"type": "object"}
                }
            }
        }"#;
        registry
            .register("CONTESTED_ROLE", original)
            .expect("first registration");
        let err = registry
            .register("CONTESTED_ROLE", conflicting)
            .expect_err("conflicting redefinition must be rejected");
        assert!(matches!(err, KernelError::Validation(_)));
        let msg = format!("{err}");
        assert!(
            msg.contains("CONTESTED_ROLE") && msg.contains("conflicting redefinition"),
            "error should name the role and state the conflict, got: {msg}"
        );
        // The stored definition is untouched.
        let def = registry.get("CONTESTED_ROLE").expect("still present");
        assert_eq!(def.version.as_deref(), Some("1.0"));
        assert!(def.actions.contains_key("ping"));
    }

    #[test]
    fn register_rejects_invalid_json() {
        let mut registry = SpiRegistry::new();
        let err = registry
            .register("BROKEN", "{not valid json")
            .expect_err("invalid JSON should produce KernelError");
        let msg = format!("{err}");
        assert!(
            msg.contains("BROKEN"),
            "error should mention the role name, got: {msg}"
        );
    }
}
