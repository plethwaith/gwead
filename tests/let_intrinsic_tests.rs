//! Integration tests for the `let` intrinsic — the kernel's
//! value-origination primitive.
//!
//! `let` resolves its `value` param (templates, `$vars`, `$steps`, `$input`,
//! …) and returns it as the step result; `store_to_variable` names it. It's
//! a real kernel intrinsic — so these run against a bare `Kernel::boot()`
//! with no plugins or mocks registered. That self-containment is the whole
//! point: a kernel-only graph can originate a value, which is what makes
//! structural-`$vars` coverage possible without any plugin.

use gwead::kernel::{Kernel, KernelConfig};
use serde_json::{Value, json};

/// Register `manifest`, run `action` with `input`, return the ActionResult's
/// output. Bare kernel — `let` ships with `Kernel::boot`.
async fn run(manifest: Value, action: &str, input: Value) -> Value {
    let plugin = manifest["name"]
        .as_str()
        .expect("manifest has a name")
        .to_string();
    let mut kernel = Kernel::boot(KernelConfig::default()).expect("kernel boots");
    kernel
        .register_plugin_from_json(&manifest.to_string())
        .expect("manifest registers");
    let kernel = kernel.into_arc();
    kernel
        .execute(&plugin, action, input)
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution")
        .output
}

#[tokio::test(flavor = "multi_thread")]
async fn let_produces_value_as_step_result_preserving_type() {
    // A lone non-string `value` rides through verbatim (no stringification):
    // value origination must preserve JSON type.
    let manifest = json!({
        "name": "let_value_test",
        "version": "0.0.0",
        "description": "let produces a value",
        "roles": [],
        "actions": {
            "go": {
                "steps": [
                    {"id": "v", "type": "let", "params": {"value": ["a", "b", "c"]}}
                ],
                "resultMapping": { "out": { "path": "$", "source": "v" } }
            }
        }
    });
    let out = run(manifest, "go", json!({})).await;
    assert_eq!(out["out"], json!(["a", "b", "c"]));
}

#[tokio::test(flavor = "multi_thread")]
async fn let_resolves_templates_in_value() {
    // `value` is resolved against the context: a lone `{{$.x}}` keeps its
    // type, and templates nested in an object resolve in place.
    let manifest = json!({
        "name": "let_tmpl_test",
        "version": "0.0.0",
        "description": "let resolves templates",
        "roles": [],
        "actions": {
            "go": {
                "steps": [
                    {"id": "scalar", "type": "let", "params": {"value": "{{$.n}}"}},
                    {"id": "nested", "type": "let", "params": {"value": { "wrapped": "{{$.greeting}}" }}}
                ],
                "resultMapping": {
                    "scalar": { "path": "$", "source": "scalar" },
                    "nested": { "path": "$", "source": "nested" }
                }
            }
        }
    });
    let out = run(manifest, "go", json!({ "n": 42, "greeting": "hi" })).await;
    // Lone single-template preserves the JSON number type.
    assert_eq!(out["scalar"], json!(42));
    assert_eq!(out["nested"], json!({ "wrapped": "hi" }));
}

#[tokio::test(flavor = "multi_thread")]
async fn let_plus_store_to_variable_drives_for_each_via_vars() {
    // The payoff of `let` plus structural `$vars`: `let` originates a list
    // and `store_to_variable` names it; an outer `for_each` iterates
    // `$vars.paths`. All in a bare kernel — no plugins, no mocks. `let`
    // is the only kernel-only way to set a variable, and structural
    // `$vars` resolution is what lets it drive a `for_each.path`.
    // Together they make this self-contained.
    let manifest = json!({
        "name": "let_vars_loop_test",
        "version": "0.0.0",
        "description": "let -> store_to_variable -> for_each over $vars",
        "roles": [],
        "actions": {
            "go": {
                "steps": [
                    {"id": "seed", "type": "let", "params": {"value": ["a.jpg", "b.jpg", "c.jpg"]}, "storeToVariable": "paths"},
                    {"id": "loop", "type": "for_each", "params": {"path": "$vars.paths", "collect": "$item", "steps": [
                            {"id": "echo", "type": "let", "params": {"value": "{{$item}}"}}
                        ]}}
                ],
                "resultMapping": { "collected": { "path": "$", "source": "loop" } }
            }
        }
    });
    let out = run(manifest, "go", json!({})).await;
    assert_eq!(
        out["collected"],
        json!(["a.jpg", "b.jpg", "c.jpg"]),
        "let must set the variable and the for_each must iterate it via $vars"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn let_store_to_variable_exposes_variables_in_action_result() {
    // A variable named via `storeToVariable` must surface in
    // `ActionResult::variables`, for both a literal value and a
    // template-resolved one. (`let` preserves JSON types — both
    // values here are strings.)
    let manifest = json!({
        "name": "let_vars_surface_test",
        "version": "0.0.0",
        "description": "let + storeToVariable surfaces in ActionResult::variables",
        "roles": [],
        "actions": {
            "go": {
                "steps": [
                    {"id": "lit", "type": "let", "params": {"value": "hello"}, "storeToVariable": "greeting"},
                    {"id": "tmpl", "type": "let", "params": {"value": "{{$.first}} {{$.last}}"}, "storeToVariable": "full_name"}
                ]
            }
        }
    });
    let mut kernel = Kernel::boot(KernelConfig::default()).expect("kernel boots");
    kernel
        .register_plugin_from_json(&manifest.to_string())
        .expect("manifest registers");
    let kernel = kernel.into_arc();
    let result = kernel
        .execute(
            "let_vars_surface_test",
            "go",
            json!({"first": "Jane", "last": "Doe"}),
        )
        .with_config(&json!({}))
        .run()
        .await
        .expect("execution");
    assert_eq!(
        result.variables.get("greeting"),
        Some(&Value::String("hello".to_string()))
    );
    assert_eq!(
        result.variables.get("full_name"),
        Some(&Value::String("Jane Doe".to_string()))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn let_missing_value_is_null() {
    let manifest = json!({
        "name": "let_null_test",
        "version": "0.0.0",
        "description": "let with no value",
        "roles": [],
        "actions": {
            "go": {
                "steps": [{ "id": "v", "type": "let" }],
                "resultMapping": { "out": { "path": "$", "source": "v" } }
            }
        }
    });
    let out = run(manifest, "go", json!({})).await;
    assert_eq!(out["out"], Value::Null);
}
