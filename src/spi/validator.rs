//! SPI validator — validates plugin manifests against SPI definitions.
//!
//! What's strict and what's soft, precisely:
//!
//! - **Strict (rejects the plugin at load):** a claimed role whose SPI
//!   definition IS registered but whose required actions the plugin
//!   doesn't provide ([`ValidationError::MissingAction`]).
//! - **Soft (warns, loads anyway):** a claimed role with NO registered
//!   SPI definition ([`ValidationWarning::UnknownRole`]). Roles double
//!   as ad-hoc dispatch labels, so an unknown role may be perfectly
//!   intentional — but it also means load order decides whether a
//!   contract is ever checked. Embedders that want contracts enforced
//!   must register SPI defs before dependent plugins.

use super::definition::SpiDefinition;
use super::loader::SpiRegistry;
use crate::kernel::types::PluginManifest;

/// Validation result for a single plugin.
#[derive(Debug)]
pub struct ValidationResult {
    pub plugin_name: String,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// A validation error — the plugin cannot be loaded.
#[derive(Debug)]
#[non_exhaustive]
pub enum ValidationError {
    /// Plugin claims a role but doesn't provide all required actions.
    MissingAction { role: String, action: String },
}

/// A validation warning — the plugin can be loaded but something is off.
#[derive(Debug)]
#[non_exhaustive]
pub enum ValidationWarning {
    /// Plugin claims a role that has no known SPI definition.
    /// Could be a custom role — warn but don't fail.
    UnknownRole { role: String },
    /// Plugin provides actions beyond what the SPI requires.
    /// Not an error — plugins can extend the contract.
    ExtraAction { role: String, action: String },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::MissingAction { role, action } => {
                write!(
                    f,
                    "Role '{role}' requires action '{action}' but plugin doesn't provide it"
                )
            }
        }
    }
}

impl std::fmt::Display for ValidationWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationWarning::UnknownRole { role } => {
                write!(f, "Unknown SPI role '{role}' — no definition found")
            }
            ValidationWarning::ExtraAction { role, action } => {
                write!(
                    f,
                    "Plugin provides action '{action}' not declared in SPI '{role}'"
                )
            }
        }
    }
}

/// Validate a plugin manifest against the SPI registry.
///
/// `namespace` is the one the plugin is being loaded into; each role it
/// declares resolves along that namespace's ancestor chain
/// ([`SpiRegistry::resolve`]), so a tenant plugin is checked against
/// its tenant's contract where one exists and the global one otherwise.
pub fn validate_manifest(
    manifest: &PluginManifest,
    namespace: &str,
    registry: &SpiRegistry,
) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    for role in &manifest.roles {
        match registry.resolve(namespace, role) {
            Some((_, spi)) => {
                check_actions(manifest, role, spi, &mut errors, &mut warnings);
            }
            None => {
                warnings.push(ValidationWarning::UnknownRole { role: role.clone() });
            }
        }
    }

    ValidationResult {
        plugin_name: manifest.name.clone(),
        errors,
        warnings,
    }
}

/// Check that the plugin provides all actions required by the SPI,
/// and warn about any extra actions not in the SPI.
fn check_actions(
    manifest: &PluginManifest,
    role: &str,
    spi: &SpiDefinition,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<ValidationWarning>,
) {
    // Check required actions are present. Actions marked `optional: true`
    // in the SPI definition may be omitted by plugins — this is how
    // additive minor-version extensions (an action added in a later
    // minor revision of a role) stay backward-compatible with 1.0
    // plugins.
    for (spi_action_name, spi_action) in &spi.actions {
        if spi_action.optional {
            continue;
        }
        if !manifest.actions.contains_key(spi_action_name) {
            errors.push(ValidationError::MissingAction {
                role: role.to_string(),
                action: spi_action_name.clone(),
            });
        }
    }

    // Warn about extra actions (not in SPI — could be intentional extensions)
    for manifest_action_name in manifest.actions.keys() {
        if !spi.actions.contains_key(manifest_action_name) {
            warnings.push(ValidationWarning::ExtraAction {
                role: role.to_string(),
                action: manifest_action_name.clone(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::types::{Action, PluginManifest, StepDef};
    use indexmap::IndexMap;
    use serde_json::json;

    fn step(id: &str) -> StepDef {
        StepDef {
            id: id.to_string(),
            step_type: "log".to_string(),
            params: json!({"message": "test"}),
            store_to_variable: None,
            depends_on: Vec::new(),
            long_running: false,
        }
    }

    fn action() -> Action {
        Action {
            description: None,
            steps: vec![step("s1")],
            results_path: None,
            result_mapping: IndexMap::new(),
            input_schema: None,
            output_schema: None,
            subscribes_to: Vec::new(),
            continuous: false,
            interval_ms: 0,
            parallel_waves: false,
            dataflow: false,
            wallclock_timeout_ms: None,
            tool: None,
        }
    }

    /// Build an SpiRegistry with the three SPI defs these tests exercise.
    /// Inline JSONs because the gwead crate ships no SPI def
    /// resources; the validator's job is to apply the action
    /// contracts a registry hands it, not to know where they came from.
    fn test_registry() -> SpiRegistry {
        let metadata_provider = r#"{
            "name": "METADATA_PROVIDER",
            "version": "1.0",
            "actions": {
                "search": {"input": {"type": "object"}, "output": {"type": "object"}},
                "fetch": {"input": {"type": "object"}, "output": {"type": "object"}}
            }
        }"#;
        let llm_chat = r#"{
            "name": "LLM_CHAT",
            "version": "1.0",
            "actions": {
                "chat": {"input": {"type": "object"}, "output": {"type": "object"}}
            }
        }"#;
        let embedding_provider = r#"{
            "name": "EMBEDDING_PROVIDER",
            "version": "1.0",
            "actions": {
                "embed": {"input": {"type": "object"}, "output": {"type": "object"}}
            }
        }"#;
        let mut r = SpiRegistry::new();
        r.register("METADATA_PROVIDER", metadata_provider).unwrap();
        r.register("LLM_CHAT", llm_chat).unwrap();
        r.register("EMBEDDING_PROVIDER", embedding_provider)
            .unwrap();
        r
    }

    fn manifest(name: &str, roles: &[&str], action_names: &[&str]) -> PluginManifest {
        let mut actions = IndexMap::new();
        for a in action_names {
            actions.insert(a.to_string(), action());
        }
        PluginManifest {
            format_version: None,
            name: name.to_string(),
            display_name: None,
            version: None,
            description: None,
            roles: roles.iter().map(|s| s.to_string()).collect(),
            actions,
            step_types: IndexMap::new(),
            config_schema: None,
            auth: None,
            metadata: IndexMap::new(),
            permissions: vec![],
            uses_secrets: Vec::new(),
            tracking_tag: None,
            step_type_defs: Vec::new(),
            wasm_modules: IndexMap::new(),
            step_type_impls: Vec::new(),
        }
    }

    #[test]
    fn valid_metadata_provider_with_both_actions() {
        let registry = test_registry();
        let m = manifest("test_mp", &["METADATA_PROVIDER"], &["search", "fetch"]);
        let result = validate_manifest(&m, "", &registry);
        assert!(result.is_valid(), "Errors: {:?}", result.errors);
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn missing_action_is_error() {
        let registry = test_registry();
        // METADATA_PROVIDER requires both search and fetch — only provide search
        let m = manifest("incomplete_mp", &["METADATA_PROVIDER"], &["search"]);
        let result = validate_manifest(&m, "", &registry);
        assert!(!result.is_valid());
        assert_eq!(result.errors.len(), 1);
        match &result.errors[0] {
            ValidationError::MissingAction { role, action } => {
                assert_eq!(role, "METADATA_PROVIDER");
                assert_eq!(action, "fetch");
            }
        }
    }

    #[test]
    fn unknown_role_is_warning_not_error() {
        let registry = test_registry();
        let m = manifest("custom_plugin", &["CUSTOM_THING"], &["do_stuff"]);
        let result = validate_manifest(&m, "", &registry);
        assert!(result.is_valid(), "Unknown roles should warn, not error");
        assert_eq!(result.warnings.len(), 1);
        assert!(
            matches!(&result.warnings[0], ValidationWarning::UnknownRole { role } if role == "CUSTOM_THING")
        );
    }

    #[test]
    fn extra_action_is_warning() {
        let registry = test_registry();
        let m = manifest(
            "extended_mp",
            &["METADATA_PROVIDER"],
            &["search", "fetch", "suggest"],
        );
        let result = validate_manifest(&m, "", &registry);
        assert!(result.is_valid());
        assert_eq!(result.warnings.len(), 1);
        assert!(
            matches!(&result.warnings[0], ValidationWarning::ExtraAction { action, .. } if action == "suggest")
        );
    }

    #[test]
    fn plugin_with_no_roles_passes_validation() {
        let registry = test_registry();
        let m = manifest("roleless", &[], &["do_stuff"]);
        let result = validate_manifest(&m, "", &registry);
        assert!(result.is_valid());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn multiple_roles_validated_independently() {
        let registry = test_registry();
        // Plugin claims both LLM_CHAT (needs "chat") and EMBEDDING_PROVIDER (needs "embed")
        let m = manifest(
            "multi_role",
            &["LLM_CHAT", "EMBEDDING_PROVIDER"],
            &["chat", "embed"],
        );
        let result = validate_manifest(&m, "", &registry);
        assert!(result.is_valid(), "Errors: {:?}", result.errors);
    }

    #[test]
    fn multiple_roles_with_missing_action() {
        let registry = test_registry();
        // Has "chat" but missing "embed"
        let m = manifest(
            "incomplete_multi",
            &["LLM_CHAT", "EMBEDDING_PROVIDER"],
            &["chat"],
        );
        let result = validate_manifest(&m, "", &registry);
        assert!(!result.is_valid());
        assert!(result.errors.iter().any(
            |e| matches!(e, ValidationError::MissingAction { action, .. } if action == "embed")
        ));
    }
}
