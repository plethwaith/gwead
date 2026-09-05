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
//! - **Informational (reported, not a finding):** actions the plugin
//!   provides that no resolved role names
//!   ([`ValidationResult::extra_actions`]). A role contract is a floor,
//!   not a ceiling, so these are neither errors nor warnings; they are
//!   returned for tooling that wants them and the kernel notes them at
//!   DEBUG.

use super::definition::SpiDefinition;
use super::loader::SpiRegistry;
use crate::kernel::types::PluginManifest;

/// Validation result for a single plugin.
#[derive(Debug)]
pub struct ValidationResult {
    pub plugin_name: String,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
    /// Actions the plugin provides that none of its *resolved* roles
    /// names, required or optional, in manifest order.
    ///
    /// Not a finding: a role contract says what a plugin must provide,
    /// and a provider whose role action dispatches to private helper
    /// actions is the normal shape, not a mistake. Nothing here needs
    /// changing, so the kernel logs the list at DEBUG rather than WARN.
    ///
    /// Computed against the union of every role that resolved, so a
    /// plugin claiming two roles and providing exactly their actions
    /// has nothing here. A role with no SPI definition contributes no
    /// contract: its actions land here alongside the
    /// [`UnknownRole`](ValidationWarning::UnknownRole) warning. Empty
    /// when no role resolved, since there is then nothing to compare
    /// against.
    ///
    /// One case this cannot tell apart: a misspelled *optional* action.
    /// An optional action may be omitted, so a typo is not a
    /// [`MissingAction`](ValidationError::MissingAction); the misspelt
    /// name simply appears here, and the plugin is found wanting at
    /// runtime instead. Tooling holding both this list and the SPI
    /// definition can flag near misses; the validator does not guess.
    pub extra_actions: Vec<String>,
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

/// A validation warning — the plugin can be loaded but something may
/// need the author's attention. Every variant is logged at WARN;
/// anything that is merely descriptive belongs on [`ValidationResult`]
/// as its own field (see [`ValidationResult::extra_actions`]), not here.
#[derive(Debug)]
#[non_exhaustive]
pub enum ValidationWarning {
    /// Plugin claims a role that has no known SPI definition.
    /// Could be a custom role — warn but don't fail.
    UnknownRole { role: String },
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
    let mut resolved = Vec::new();

    for role in &manifest.roles {
        match registry.resolve(namespace, role) {
            Some((_, spi)) => {
                check_required_actions(manifest, role, spi, &mut errors);
                resolved.push(spi);
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
        extra_actions: extra_actions(manifest, &resolved),
    }
}

/// Check that the plugin provides every action the SPI requires.
fn check_required_actions(
    manifest: &PluginManifest,
    role: &str,
    spi: &SpiDefinition,
    errors: &mut Vec<ValidationError>,
) {
    // Actions marked `optional: true` in the SPI definition may be
    // omitted by plugins — this is how additive minor-version extensions
    // (an action added in a later minor revision of a role) stay
    // backward-compatible with 1.0 plugins.
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
}

/// The plugin's actions that none of `resolved` names — the contract
/// is the union of every resolved role, not any one of them, so a
/// multi-role plugin is not charged one role's actions as extras of
/// another. Empty when nothing resolved: there is no contract to
/// compare against, and a roleless plugin's actions are simply its
/// actions.
fn extra_actions(manifest: &PluginManifest, resolved: &[&SpiDefinition]) -> Vec<String> {
    if resolved.is_empty() {
        return Vec::new();
    }
    manifest
        .actions
        .keys()
        .filter(|name| !resolved.iter().any(|spi| spi.actions.contains_key(*name)))
        .cloned()
        .collect()
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
        assert!(result.extra_actions.is_empty());
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

    /// An action beyond the role contract is reported, in manifest
    /// order, and is neither an error nor a warning.
    #[test]
    fn extra_action_is_reported_not_warned() {
        let registry = test_registry();
        let m = manifest(
            "extended_mp",
            &["METADATA_PROVIDER"],
            &["search", "suggest", "fetch", "fetch_streamed"],
        );
        let result = validate_manifest(&m, "", &registry);
        assert!(result.is_valid());
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        assert_eq!(result.extra_actions, ["suggest", "fetch_streamed"]);
    }

    /// Extras are judged against the union of the plugin's resolved
    /// roles. Per-role bookkeeping would charge `embed` as an extra of
    /// LLM_CHAT and `chat` as an extra of EMBEDDING_PROVIDER, which is
    /// what the validator used to do.
    #[test]
    fn multi_role_plugin_providing_exactly_its_contracts_has_no_extras() {
        let registry = test_registry();
        let m = manifest(
            "multi_role",
            &["LLM_CHAT", "EMBEDDING_PROVIDER"],
            &["chat", "embed"],
        );
        let result = validate_manifest(&m, "", &registry);
        assert!(result.is_valid(), "Errors: {:?}", result.errors);
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        assert!(
            result.extra_actions.is_empty(),
            "one role's action is not another role's extra: {:?}",
            result.extra_actions
        );
    }

    /// A multi-role plugin's genuine extras are still found — the union
    /// is a wider contract, not a blanket pass.
    #[test]
    fn multi_role_plugin_still_reports_actions_outside_every_contract() {
        let registry = test_registry();
        let m = manifest(
            "multi_role_extended",
            &["LLM_CHAT", "EMBEDDING_PROVIDER"],
            &["chat", "embed", "tokenize"],
        );
        let result = validate_manifest(&m, "", &registry);
        assert!(result.is_valid(), "Errors: {:?}", result.errors);
        assert_eq!(result.extra_actions, ["tokenize"]);
    }

    /// An unknown role has no contract to contribute, so its actions
    /// count as extras of the roles that did resolve. The `UnknownRole`
    /// warning alongside says why.
    #[test]
    fn unknown_role_contributes_no_contract_to_extras() {
        let registry = test_registry();
        let m = manifest(
            "half_known",
            &["LLM_CHAT", "CUSTOM_THING"],
            &["chat", "do_stuff"],
        );
        let result = validate_manifest(&m, "", &registry);
        assert!(result.is_valid());
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(result.extra_actions, ["do_stuff"]);
    }

    /// The documented blind spot: an optional action may be omitted, so
    /// misspelling it is not a missing action. The misspelt name shows
    /// up as an extra, and only there.
    #[test]
    fn misspelled_optional_action_is_an_extra_not_an_error() {
        let mut registry = test_registry();
        registry
            .register(
                "SUMMARIZER",
                r#"{
                    "name": "SUMMARIZER",
                    "version": "1.1",
                    "actions": {
                        "summarize": {"input": {"type": "object"}, "output": {"type": "object"}},
                        "outline": {"input": {"type": "object"}, "output": {"type": "object"}, "optional": true}
                    }
                }"#,
            )
            .unwrap();
        let m = manifest("typo", &["SUMMARIZER"], &["summarize", "outlien"]);
        let result = validate_manifest(&m, "", &registry);
        assert!(result.is_valid(), "Errors: {:?}", result.errors);
        assert!(result.warnings.is_empty());
        assert_eq!(result.extra_actions, ["outlien"]);
    }

    #[test]
    fn plugin_with_no_roles_passes_validation() {
        let registry = test_registry();
        let m = manifest("roleless", &[], &["do_stuff"]);
        let result = validate_manifest(&m, "", &registry);
        assert!(result.is_valid());
        assert!(result.warnings.is_empty());
        assert!(
            result.extra_actions.is_empty(),
            "no contract, so nothing is extra"
        );
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
