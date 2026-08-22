//! Integration tests for the DSL ordered comparison operators —
//! `<`, `<=`, `>`, `>=` across every expression surface.
//!
//! Templates, `ifs` tests, `until`, and `collect` all share
//! `parse_expression`, so the operators land everywhere at once; each
//! test here exercises one surface end-to-end through `Kernel::execute`.
//! All graphs are kernel-only (`let` + intrinsics), so these run against
//! a bare `Kernel::boot()` with no plugins or mocks registered.
//!
//! Semantics under test: numeric-to-numeric only. Any other operand
//! combination — including string-vs-number — evaluates to `false`, with
//! no implicit coercion of `"404"` to `404`.

use gwead::kernel::types::ActionResult;
use gwead::kernel::{Kernel, KernelConfig};
use serde_json::{Value, json};

/// Register `manifest`, run `action` with `input`, return the full
/// ActionResult (output + variables + step results).
async fn run(manifest: Value, action: &str, input: Value) -> ActionResult {
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
}

/// Manifest with an `ifs` step that routes on HTTP-status-class
/// comparisons — the motivating use case for the operators.
fn status_router() -> Value {
    json!({
        "name": "cmp_if_test",
        "version": "0.0.0",
        "description": "if routes on ordered comparisons",
        "roles": [],
        "actions": {
            "go": {
                "steps": [
                    {"id": "route", "type": "ifs", "params": {"ifs": [
                            {
                                "test": "$input.status >= 500",
                                "then": [{"id": "server", "type": "let", "params": {"value": "server_error"}, "storeToVariable": "verdict"}]
                            },
                            {
                                "test": "$input.status >= 400",
                                "then": [{"id": "client", "type": "let", "params": {"value": "client_error"}, "storeToVariable": "verdict"}]
                            },
                            {
                                "then": [{"id": "fine", "type": "let", "params": {"value": "ok"}, "storeToVariable": "verdict"}]
                            }
                        ]}}
                ]
            }
        }
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn if_condition_routes_on_status_class() {
    for (status, want) in [
        (json!(503), "server_error"),
        (json!(500), "server_error"),
        (json!(404), "client_error"),
        (json!(200), "ok"),
    ] {
        let result = run(status_router(), "go", json!({ "status": status })).await;
        assert_eq!(result.variables["verdict"], json!(want), "status {status}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn if_condition_comparison_is_strict_about_types() {
    // A string status never satisfies a numeric comparison — no implicit
    // "503" → 503 coercion — so both branches miss and `else` runs.
    let result = run(status_router(), "go", json!({ "status": "503" })).await;
    assert_eq!(result.variables["verdict"], json!("ok"));
}

#[tokio::test(flavor = "multi_thread")]
async fn repeat_until_exits_on_ordered_comparison() {
    // `repeat` items are JSON numbers (0..count), so `$item >= 2` fires
    // on the third iteration — well before the safety cap.
    let manifest = json!({
        "name": "cmp_until_test",
        "version": "0.0.0",
        "description": "until exits via ordered comparison",
        "roles": [],
        "actions": {
            "go": {
                "steps": [
                    {"id": "loop", "type": "repeat", "params": {"count": 10, "until": "$item >= 2", "collect": "$steps.tick.result", "steps": [{"id": "tick", "type": "let", "params": {"value": "{{$item}}"}}]}}
                ],
                "resultMapping": { "ticks": { "path": "$", "source": "loop" } }
            }
        }
    });
    let result = run(manifest, "go", json!({})).await;
    // Three iterations (0, 1, 2), then `until` is truthy.
    assert_eq!(result.output["ticks"], json!([0, 1, 2]));
}

#[tokio::test(flavor = "multi_thread")]
async fn for_each_collect_evaluates_ordered_comparison() {
    let manifest = json!({
        "name": "cmp_collect_test",
        "version": "0.0.0",
        "description": "collect evaluates ordered comparisons per item",
        "roles": [],
        "actions": {
            "go": {
                "steps": [
                    {"id": "loop", "type": "for_each", "params": {"path": "$input.xs[*]", "collect": "$steps.v.result >= 3", "steps": [{"id": "v", "type": "let", "params": {"value": "{{$item}}"}}]}}
                ],
                "resultMapping": { "flags": { "path": "$", "source": "loop" } }
            }
        }
    });
    let result = run(manifest, "go", json!({ "xs": [1, 5, 2, 7] })).await;
    assert_eq!(result.output["flags"], json!([false, true, false, true]));
}

#[tokio::test(flavor = "multi_thread")]
async fn template_comparison_preserves_type_and_renders_mixed() {
    let manifest = json!({
        "name": "cmp_template_test",
        "version": "0.0.0",
        "description": "templates evaluate ordered comparisons",
        "roles": [],
        "actions": {
            "go": {
                "steps": [
                    // Lone expression: resolved value keeps its JSON type.
                    {"id": "flag", "type": "let", "params": {"value": "{{$input.n >= 3}}"}},
                    // Mixed content: always renders to a string.
                    {"id": "msg", "type": "let", "params": {"value": "n>=3: {{$input.n >= 3}}"}}
                ],
                "resultMapping": {
                    "flag": { "path": "$", "source": "flag" },
                    "msg": { "path": "$", "source": "msg" }
                }
            }
        }
    });
    let result = run(manifest.clone(), "go", json!({ "n": 5 })).await;
    assert_eq!(result.output["flag"], json!(true));
    assert_eq!(result.output["msg"], json!("n>=3: true"));

    let result = run(manifest, "go", json!({ "n": 2 })).await;
    assert_eq!(result.output["flag"], json!(false));
    assert_eq!(result.output["msg"], json!("n>=3: false"));
}
