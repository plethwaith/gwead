//! Load-time meta-schema validation for manifests.
//!
//! The two published meta-schemas under `schemas/` are the manifest format
//! contract: raw manifest JSON is validated against the appropriate one
//! (chosen by [`super::classify_manifest`]'s shape rule) before serde
//! deserialization. This catches misspelled or misplaced keys that serde
//! would otherwise silently drop, and guarantees every embedded JSON Schema
//! slot (action input/output, step-type def schemas, tool parameters, SPI
//! action contracts) is itself well-formed Draft 2020-12.
//!
//! The schemas are embedded at compile time and compiled once per process.

use boon::{Compiler, SchemaIndex, Schemas};
use serde_json::Value;
use std::sync::OnceLock;

const PLUGIN_MANIFEST_SCHEMA: &str = include_str!("../../schemas/plugin-manifest.schema.json");
const SPI_DEFINITION_SCHEMA: &str = include_str!("../../schemas/spi-definition.schema.json");

const PLUGIN_MANIFEST_URL: &str =
    "https://plethwaith.com/schemas/gwead/plugin-manifest.schema.json";
const SPI_DEFINITION_URL: &str = "https://plethwaith.com/schemas/gwead/spi-definition.schema.json";

struct Compiled {
    schemas: Schemas,
    plugin_manifest: SchemaIndex,
    spi_definition: SchemaIndex,
}

fn compiled() -> &'static Compiled {
    static COMPILED: OnceLock<Compiled> = OnceLock::new();
    COMPILED.get_or_init(|| {
        let mut schemas = Schemas::new();
        let mut compiler = Compiler::new();
        for (url, src) in [
            (PLUGIN_MANIFEST_URL, PLUGIN_MANIFEST_SCHEMA),
            (SPI_DEFINITION_URL, SPI_DEFINITION_SCHEMA),
        ] {
            let doc: Value = serde_json::from_str(src)
                .unwrap_or_else(|e| panic!("embedded meta-schema {url} is not valid JSON: {e}"));
            compiler
                .add_resource(url, doc)
                .unwrap_or_else(|e| panic!("embedded meta-schema {url} failed to load: {e}"));
        }
        let plugin_manifest = compiler
            .compile(PLUGIN_MANIFEST_URL, &mut schemas)
            .unwrap_or_else(|e| panic!("plugin-manifest meta-schema failed to compile: {e}"));
        let spi_definition = compiler
            .compile(SPI_DEFINITION_URL, &mut schemas)
            .unwrap_or_else(|e| panic!("spi-definition meta-schema failed to compile: {e}"));
        Compiled {
            schemas,
            plugin_manifest,
            spi_definition,
        }
    })
}

fn validate(value: &Value, index: SchemaIndex, kind: &str) -> Result<(), String> {
    let c = compiled();
    c.schemas
        .validate(value, index)
        .map_err(|e| format!("manifest fails the {kind} meta-schema: {e:#}"))
}

/// Validate a raw manifest `Value` against the plugin-manifest meta-schema.
pub(crate) fn validate_plugin_manifest(value: &Value) -> Result<(), String> {
    validate(value, compiled().plugin_manifest, "plugin-manifest")
}

/// Validate a raw manifest `Value` against the SPI-definition meta-schema.
pub(crate) fn validate_spi_definition(value: &Value) -> Result<(), String> {
    validate(value, compiled().spi_definition, "spi-definition")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn both_meta_schemas_compile() {
        let _ = compiled();
    }

    #[test]
    fn minimal_plugin_manifest_validates() {
        let m = json!({"name": "p"});
        assert!(validate_plugin_manifest(&m).is_ok());
    }

    #[test]
    fn unknown_top_level_key_rejected() {
        let m = json!({"name": "p", "stepTypess": []});
        let err = validate_plugin_manifest(&m).unwrap_err();
        assert!(
            err.contains("stepTypess"),
            "error should name the bad key: {err}"
        );
    }

    #[test]
    fn malformed_embedded_schema_rejected() {
        // properties must be an object in a JSON Schema; a bare string is not.
        let m = json!({
            "name": "p",
            "actions": {"a": {
                "steps": [{"id": "s1", "type": "log", "params": {"message": "hi"}}],
                "inputSchema": {"properties": "nope"}
            }}
        });
        assert!(validate_plugin_manifest(&m).is_err());
    }

    #[test]
    fn wasm_impl_requires_module_and_bans_impl_ref() {
        let m = json!({
            "name": "p",
            "stepTypeImpls": [{"stepType": "t", "kind": "wasm", "implRef": "x.y.z"}]
        });
        assert!(validate_plugin_manifest(&m).is_err());
    }

    #[test]
    fn native_impl_is_selector_less() {
        let m = json!({
            "name": "p",
            "stepTypeImpls": [{"stepType": "t", "kind": "native", "implRef": "x.y.z", "matches": "lua"}]
        });
        assert!(validate_plugin_manifest(&m).is_err());
    }

    #[test]
    fn bad_permission_grammar_rejected() {
        for bad in [
            "network:ingress:example.com",
            "blobs:chmod:/tmp/*",
            "no-colon",
            // Wildcards outside the blessed shapes. The schema must
            // mirror `parse_permission` here — it is the published
            // format contract, so an author validating against it and
            // then hitting a load-time rejection is a schema defect.
            "network:egress:*.example.*",
            "network:egress:api.*.example.com",
            "blobs:read:a/*/b",
            "step_type:*",
            "invoke:plugin:ff*",
            "provide:step_type:script:*",
            // Sub-kinds the parser rejects; the schema's `invoke:`
            // clause must reject them too.
            "invoke:action:sign",
            "invoke:plugin:",
            // Dot-free categories are reserved for the kernel.
            "events:publish",
            "fs:read:foo",
        ] {
            let m = json!({"name": "p", "permissions": [bad]});
            assert!(
                validate_plugin_manifest(&m).is_err(),
                "permission {bad:?} should be rejected"
            );
        }
        let ok = json!({"name": "p", "permissions": [
            "network:egress:*.example.com",
            "network:egress:*",
            "blobs:read:/data/*",
            "step_type:http_call",
            "invoke:plugin:ffprobe",
            "invoke:role:*",
            "provide:step_type:script:lua",
            "acme.events:publish"
        ]});
        assert!(validate_plugin_manifest(&ok).is_ok());
    }

    /// The schema is the published format contract, so every string it
    /// accepts must also survive `parse_permission`, and every string
    /// it rejects must be one the parser would reject too. A
    /// divergence means an author can validate a manifest and still
    /// have it fail at load (or the reverse — a grant the schema bans
    /// that the kernel would honour).
    #[test]
    fn permission_schema_and_parser_agree() {
        use crate::kernel::permissions::parse_permission;

        let cases = [
            "network:egress:*",
            "network:egress:*.example.com",
            "network:egress:api.example.com",
            "network:egress:*.example.*",
            "network:egress:api?.example.com",
            "blobs:read:*",
            "blobs:write:media/*",
            "blobs:read:a/*/b",
            "blobs:chmod:x",
            "step_type:http_call",
            "step_type:*",
            "invoke:plugin:*",
            "invoke:role:LLM_CHAT",
            "invoke:action:sign",
            "invoke:plugin:ff*",
            "provide:step_type:script:lua",
            "provide:step_type:resize_image",
            "provide:step_type:script:*",
            "provide:action:sign",
            "acme.events:publish:x",
            "events:publish:x",
            // An embedder category with no value at all. Both schema and
            // parser require `<category>:<value>`; the struct-based
            // registration path never sees the schema, so the parser
            // has to agree.
            "acme.events",
            "acme.events:",
            "fs:read:foo",
            "invok:plugin:victim",
            // Name-grammar cases. Without the name grammar each of
            // these would parse cleanly and then match nothing, forever,
            // silently — so schema and parser have to agree on exactly
            // where the line is.
            "invoke:plugin:acme.vault",
            "invoke:plugin:my plugin",
            "invoke:role:LLM-CHAT",
            "invoke:plugin:_x",
            "invoke:plugin:-x",
            "step_type:http.call",
            "provide:step_type:script:lu a",
            // Reserved namespace syntax: rejected as a reference, not
            // taken as a literal.
            "invoke:plugin:tenant42/billing",
            "step_type:tenant42/http_call",
            // The length cap is part of the grammar, so the schema has
            // to express it too or a 200-byte name validates and then
            // fails at load.
            "invoke:plugin:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "invoke:plugin:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ];

        for raw in cases {
            let m = json!({"name": "p", "permissions": [raw]});
            let schema_ok = validate_plugin_manifest(&m).is_ok();
            let parser_ok = parse_permission(raw).is_ok();
            assert_eq!(
                schema_ok, parser_ok,
                "{raw:?}: schema accepts={schema_ok} but parser accepts={parser_ok}"
            );
        }
    }

    #[test]
    fn minimal_spi_definition_validates() {
        let m = json!({
            "name": "ROLE",
            "actions": {"do": {"input": {"type": "object"}, "output": {"type": "object"}}}
        });
        assert!(validate_spi_definition(&m).is_ok());
    }

    #[test]
    fn spi_action_missing_output_rejected() {
        let m = json!({
            "name": "ROLE",
            "actions": {"do": {"input": {"type": "object"}}}
        });
        assert!(validate_spi_definition(&m).is_err());
    }

    #[test]
    fn spi_definition_accepts_shared_schemas() {
        let m = json!({
            "name": "ROLE",
            "actions": {"do": {
                "input": {"$ref": "#/$defs/Thing"},
                "output": {"type": "array", "items": {"$ref": "#/$defs/Thing"}}
            }},
            "$defs": {"Thing": {"type": "object"}}
        });
        assert!(validate_spi_definition(&m).is_ok());
    }

    /// Round-trip pin against schema-side typos: a fully-populated
    /// manifest must validate, deserialize, and re-validate after
    /// serialization. With `additionalProperties: false` throughout, a
    /// misspelled property in the SCHEMA rejects valid manifests — this
    /// is the test that notices.
    #[test]
    fn kitchen_sink_manifest_round_trips() {
        let m = json!({
            "$schema": "https://plethwaith.com/schemas/gwead/plugin-manifest.schema.json",
            "formatVersion": 1,
            "name": "kitchen_sink",
            "displayName": "Kitchen Sink",
            "version": "1.2.3",
            "description": "Every field populated",
            "roles": ["SOME_ROLE"],
            "stepTypes": {"my_alias": "go"},
            "configSchema": {
                "systemFields": [{"key": "endpoint", "type": "string", "required": true,
                                   "displayName": "Endpoint", "description": "d",
                                   "defaultValue": "https://example.com", "options": [], "secret": false}],
                "userFields": [{"key": "token", "type": "string", "secret": true}]
            },
            "auth": {"type": "header", "headerName": "X-Key", "configKey": "token"},
            "metadata": {"anything": {"goes": ["here", 1, null]}},
            "permissions": ["network:egress:*.example.com", "acme.custom:whatever"],
            "trackingTag": "KITCHEN",
            "stepTypeDefs": [{"name": "my_step", "inputSchema": {"type": "object"},
                               "outputSchema": true, "metadataSchema": {"properties": {"count": {}}},
                               "selector": "flavor",
                               "references": [{"plugin": "p", "action": "a"}]}],
            "wasmModules": {"inline_mod": {"base64": "AGFzbQ=="}, "path_mod": {"path": "m.wasm"}},
            "stepTypeImpls": [
                {"stepType": "my_step", "matches": "vanilla", "kind": "wasm", "wasmModule": "inline_mod"},
                {"stepType": "my_step", "kind": "native", "implRef": "myapp.kitchen_sink.my_step"}
            ],
            "actions": {"go": {
                "description": "d",
                "steps": [
                    {"id": "s1", "type": "let", "params": {"value": 1}, "storeToVariable": "x", "dependsOn": [], "longRunning": false},
                    {"id": "s2", "type": "try", "params": {"try": [{"id": "t1", "type": "let", "params": {"value": 2}}], "catch": [], "finally": []}}
                ],
                "resultsPath": "$.x", "resultMapping": {"out": "{{$.vars.x}}"},
                "inputSchema": {"type": "object"}, "outputSchema": {"type": "object"},
                "subscribesTo": ["some.event"], "continuous": false, "intervalMs": 0,
                "parallelWaves": true, "wallclockTimeoutMs": 5000,
                "tool": {"name": "go_tool", "description": "d", "parameters": {"type": "object"}}
            }}
        });
        validate_plugin_manifest(&m).expect("kitchen-sink manifest must validate");
        let parsed: crate::kernel::types::PluginManifest =
            serde_json::from_value(m).expect("kitchen-sink manifest must deserialize");
        let back = serde_json::to_value(&parsed).expect("serialize");
        validate_plugin_manifest(&back).expect("serialized form must validate too");
    }

    /// The round-trip above must PRESERVE `formatVersion` — if serde
    /// silently dropped it, the serialized form would revalidate fine
    /// and the drift would be invisible. Pin it explicitly.
    #[test]
    fn format_version_survives_round_trip() {
        let m = json!({"formatVersion": 1, "name": "p"});
        validate_plugin_manifest(&m).expect("v1 validates");
        let parsed: crate::kernel::types::PluginManifest =
            serde_json::from_value(m).expect("deserializes");
        assert_eq!(parsed.format_version, Some(1));
        let back = serde_json::to_value(&parsed).expect("serialize");
        assert_eq!(back.get("formatVersion"), Some(&json!(1)));
    }

    /// A future-format manifest must be rejected up front with a clear
    /// schema error, not misparsed by this kernel.
    #[test]
    fn unknown_format_version_rejected() {
        let m = json!({"formatVersion": 2, "name": "p"});
        assert!(validate_plugin_manifest(&m).is_err());
        let spi = json!({
            "formatVersion": 2,
            "name": "ROLE",
            "actions": {"do": {"input": {"type": "object"}, "output": {"type": "object"}}}
        });
        assert!(validate_spi_definition(&spi).is_err());
    }

    #[test]
    fn kind_absent_impl_requires_wasm_module() {
        let m = json!({"name": "p", "stepTypeImpls": [{"stepType": "t"}]});
        assert!(validate_plugin_manifest(&m).is_err());
    }

    #[test]
    fn native_impl_missing_impl_ref_rejected() {
        let m = json!({"name": "p", "stepTypeImpls": [{"stepType": "t", "kind": "native"}]});
        assert!(validate_plugin_manifest(&m).is_err());
    }

    #[test]
    fn dataflow_and_continuous_mutually_exclusive() {
        let m = json!({"name": "p", "actions": {"a": {
            "steps": [{"id": "s", "type": "let", "params": {"value": 1}, "longRunning": true}],
            "dataflow": true, "continuous": true
        }}});
        assert!(validate_plugin_manifest(&m).is_err());
    }

    #[test]
    fn zero_wallclock_timeout_rejected() {
        let m = json!({"name": "p", "actions": {"a": {
            "steps": [{"id": "s", "type": "let", "params": {"value": 1}}],
            "wallclockTimeoutMs": 0
        }}});
        assert!(validate_plugin_manifest(&m).is_err());
    }

    #[test]
    fn intrinsics_manifest_validates_as_plugin() {
        let v: Value =
            serde_json::from_str(include_str!("../../resources/manifests/intrinsics.json"))
                .unwrap();
        validate_plugin_manifest(&v).expect("intrinsics.json must satisfy its own meta-schema");
    }
}
