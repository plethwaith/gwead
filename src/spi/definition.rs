//! SPI definition types — the schema for SPI JSON files.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// An SPI definition — declares the contract that plugins must satisfy.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpiDefinition {
    /// Definition format version. `None` means 1 — the only version
    /// so far. Same forward-compatibility hook as
    /// `PluginManifest::format_version`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format_version: Option<u32>,

    /// SPI role name (e.g., `LLM_CHAT`, `METADATA_PROVIDER`).
    pub name: String,

    /// Human-readable display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Semver version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Required actions with their input/output schemas.
    pub actions: IndexMap<String, SpiAction>,

    /// Shared JSON Schema definitions referenced by `$ref` in action
    /// schemas as `#/$defs/<Name>` (JSON Schema Draft 2020-12 idiom).
    #[serde(rename = "$defs", default, skip_serializing_if = "IndexMap::is_empty")]
    pub definitions: IndexMap<String, Value>,

    /// For streaming roles: a JSON Schema describing the shape of each
    /// streamed event. Purely declarative — consumed by embedder
    /// tooling, not enforced by the kernel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_event_shape: Option<Value>,
}

/// An action declared by an SPI — the input/output contract.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpiAction {
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// JSON Schema for the action's input.
    pub input: Value,

    /// JSON Schema for the action's output.
    pub output: Value,

    /// When true, plugins claiming this SPI role MAY omit this action.
    /// Used for additive minor-version extensions: a 1.0 plugin that omits a
    /// 1.1-introduced action stays valid against the 1.1 SPI def. The
    /// kernel still validates the action's schema for plugins that
    /// DO provide it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub optional: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}
