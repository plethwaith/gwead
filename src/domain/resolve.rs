//! Template resolver — substitutes `{{...}}` placeholders inside step
//! parameter strings (URLs, headers, query params, body templates).
//!
//! The `{{...}}` interior is the Gwead DSL — the same expression
//! language `ifs` tests, `until`, and `collect` use, parsed by
//! [`crate::dsl::parse_expression`] and evaluated by
//! [`crate::dsl::eval_expression`]. Placeholders written in another
//! template engine's syntax (`{{config.X}}`, `{{X | default:Y}}`,
//! `{{item}}`) are not references here and render as the empty
//! string.
//!
//! The DSL roots available from inside `{{...}}`:
//! - `$.X` and `$input.X` — both resolve against the variables bag
//!   itself (input fields are inlined at the top level by
//!   `ExecutionState::resolution_context`).
//! - `$config.X` — `variables["config"]`.
//! - `$secrets.X` — `variables["secrets"]`.
//! - `$trigger.X` — `variables["trigger"]` (event-subscribed actions).
//! - `$vars.X` — `variables["vars"]`.
//! - `$item` / `$item.X` — `variables["item"]` (inside a loop body).
//! - `$steps.<id>.<path>` — `variables["steps"]` carries the wrapped
//!   `{result, …metadata}` view per step, so
//!   `{{$steps.<id>.result.<path>}}` in templates and
//!   `$steps.<id>.result.<path>` in an `ifs` test resolve
//!   identically.
//!
//! The literal placeholder `{{value}}` is preserved verbatim — it's
//! the transform-template's internal substitution marker (handled by
//! an embedder transform plugin), NOT
//! a resolver reference. It only appears inside transform spec
//! objects, which aren't routed through this resolver, but pinning
//! the no-op pass-through here is defense-in-depth.

use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

use crate::dsl::{self, EvalContext};

static TEMPLATE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{\{(.+?)}}").unwrap());

/// Resolve all `{{expression}}` placeholders in a template string.
pub fn resolve(template: &str, variables: &Value) -> String {
    TEMPLATE_RE
        .replace_all(template, |caps: &regex::Captures| {
            resolve_expression_to_string(caps[1].trim(), variables)
        })
        .into_owned()
}

/// Resolve templates within any JSON Value, recursing into nested objects
/// and arrays.
///
/// **Value preservation for single-template strings**: if a string is
/// exactly one `{{$expression}}` (trimmed, with nothing else around it),
/// the resolved value is returned with its original type preserved. So
/// a body like `{"messages": "{{$.messages}}"}` where `messages` is an
/// array yields `{"messages": [...]}` — not the stringified form.
/// Missing-path resolves render as empty string (matches what
/// non-single-template interpolation does for missing variables).
///
/// Mixed content (e.g., `"https://{{$config.host}}/api"`) always
/// produces a `Value::String`. Non-string scalars (numbers, booleans,
/// null) pass through unchanged.
pub fn resolve_value(value: &Value, variables: &Value) -> Value {
    match value {
        Value::String(s) => resolve_string_as_value(s, variables),
        Value::Object(obj) => Value::Object(
            obj.iter()
                .map(|(k, v)| (k.clone(), resolve_value(v, variables)))
                .collect(),
        ),
        Value::Array(arr) => {
            Value::Array(arr.iter().map(|v| resolve_value(v, variables)).collect())
        }
        other => other.clone(),
    }
}

fn resolve_string_as_value(s: &str, variables: &Value) -> Value {
    let Some(expr) = single_template_expression(s) else {
        return Value::String(resolve(s, variables));
    };
    // `{{value}}` is the transform-template placeholder — never a DSL
    // reference. Pass through unchanged.
    if expr == "value" {
        return Value::String(s.to_string());
    }
    let Ok(parsed) = dsl::parse_expression(expr) else {
        return Value::String(resolve(s, variables));
    };
    let ctx = build_dsl_context(variables);
    let value = dsl::eval_expression(&parsed, &ctx);
    if value.is_null() {
        // Match `{{}}` interpolation's "missing → empty string" rule so
        // a single-template body like `{"x":"{{$.missing}}"}` produces
        // `{"x": ""}` instead of `{"x": null}`.
        Value::String(String::new())
    } else {
        value
    }
}

fn single_template_expression(s: &str) -> Option<&str> {
    let trimmed = s.trim();
    let inner = trimmed.strip_prefix("{{")?.strip_suffix("}}")?;
    if inner.contains("{{") || inner.contains("}}") {
        return None;
    }
    Some(inner.trim())
}

fn resolve_expression_to_string(expr: &str, variables: &Value) -> String {
    // `{{value}}` is preserved verbatim (transform-template placeholder).
    if expr == "value" {
        return "{{value}}".to_string();
    }
    match dsl::parse_expression(expr) {
        Ok(parsed) => {
            let ctx = build_dsl_context(variables);
            value_to_string(&dsl::eval_expression(&parsed, &ctx))
        }
        Err(_) => String::new(),
    }
}

/// Build a DSL [`EvalContext`] from the resolver's flat variables bag.
///
/// `steps` comes from `variables["steps"]` which `resolution_context`
/// builds as the wrapped `{result, …metadata}` view per step — the
/// same shape `ifs` tests, `until`, and `collect` see. So
/// `{{$steps.<id>.result.<path>}}` in templates and
/// `$steps.<id>.result.<path>` in an `ifs` test resolve identically.
fn build_dsl_context(variables: &Value) -> EvalContext<'_> {
    EvalContext {
        // `$input.X` and `$.X` both resolve against the variables bag —
        // input fields are inlined at the top level by
        // `ExecutionState::resolution_context`, so the implicit source
        // and the input root are the same Value here.
        input: Some(variables),
        steps: variables.get("steps"),
        config: variables.get("config"),
        secrets: variables.get("secrets"),
        trigger: variables.get("trigger"),
        vars: variables.get("vars"),
        item: variables.get("item"),
        implicit_source: Some(variables),
    }
}

fn value_to_string(val: &Value) -> String {
    match val {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Return every `{{…}}` placeholder in `s` whose inner expression does
/// **not** conform to the template dialect — i.e. it neither
/// starts with a `$`-rooted reference (`$.`, `$config.`, `$steps.`,
/// `$item`, `$secrets`, `$trigger`, `$vars`) nor is the literal transform
/// placeholder `value`.
///
/// Placeholders in another template engine's syntax (`{{config.x}}`,
/// `{{messages}}`, `{{x | default:y}}`) are not resolved — they
/// silently render to empty string (see the module docs and
/// `resolve_expression_to_string`). That silent degrade means a
/// manifest using them can ship looking fine and only break when an
/// action actually runs. This helper turns that into a test-time signal:
/// an embedder's manifest tests can assert it returns empty for every
/// manifest they ship, so a stray placeholder fails in CI rather than
/// at runtime.
///
/// Text-only scan (the same `{{…}}` matcher the resolver uses) — a lint
/// over a manifest's serialized form, not a full parse.
pub fn non_dialect_placeholders(s: &str) -> Vec<&str> {
    TEMPLATE_RE
        .captures_iter(s)
        .filter_map(|caps| caps.get(1))
        .map(|m| m.as_str().trim())
        .filter(|inner| !inner.starts_with('$') && *inner != "value")
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Basic DSL resolution ───────────────────────────────────────────

    #[test]
    fn simple_input_field() {
        let vars = json!({"query": "hello world"});
        assert_eq!(resolve("q={{$.query}}", &vars), "q=hello world");
    }

    #[test]
    fn dsl_config_root() {
        let vars = json!({"config": {"searchLimit": 20}});
        assert_eq!(resolve("limit={{$config.searchLimit}}", &vars), "limit=20");
    }

    #[test]
    fn dsl_secrets_root() {
        let vars = json!({"secrets": {"api_key": "sk-abc"}});
        assert_eq!(
            resolve("Bearer {{$secrets.api_key}}", &vars),
            "Bearer sk-abc"
        );
    }

    #[test]
    fn dsl_input_root_equals_implicit() {
        let vars = json!({"query": "rust"});
        assert_eq!(resolve("q={{$input.query}}", &vars), "q=rust");
    }

    #[test]
    fn dsl_item_bare() {
        let vars = json!({"item": "/authors/OL1A"});
        assert_eq!(
            resolve("https://openlibrary.org{{$item}}.json", &vars),
            "https://openlibrary.org/authors/OL1A.json"
        );
    }

    #[test]
    fn dsl_item_with_path() {
        let vars = json!({"item": {"name": "Asimov"}});
        assert_eq!(resolve("author={{$item.name}}", &vars), "author=Asimov");
    }

    #[test]
    fn dsl_coalesce_with_literal_fallback() {
        let vars = json!({"config": {}});
        assert_eq!(
            resolve("limit={{$config.searchLimit ?? 20}}", &vars),
            "limit=20"
        );
    }

    #[test]
    fn dsl_coalesce_uses_primary_when_present() {
        let vars = json!({"config": {"searchLimit": 50}});
        assert_eq!(
            resolve("limit={{$config.searchLimit ?? 20}}", &vars),
            "limit=50"
        );
    }

    #[test]
    fn dsl_missing_path_renders_empty() {
        let vars = json!({});
        assert_eq!(resolve("x={{$config.missing}}", &vars), "x=");
    }

    #[test]
    fn dsl_multiple_templates() {
        let vars = json!({"a": "1", "b": "2"});
        assert_eq!(resolve("{{$.a}}-{{$.b}}", &vars), "1-2");
    }

    #[test]
    fn dsl_steps_wrapped_view() {
        // `steps` in the variables bag is the wrapped {result, status, headers}
        // form — same shape `ifs` tests, `until` and `collect` see. So
        // `$steps.X.result.Y` works inside `{{}}` identically to an `ifs` test.
        let vars = json!({
            "steps": {
                "search": {
                    "result": {"total": 42},
                    "status": 200
                }
            }
        });
        assert_eq!(
            resolve("count={{$steps.search.result.total}}", &vars),
            "count=42"
        );
        assert_eq!(
            resolve("status={{$steps.search.status}}", &vars),
            "status=200"
        );
    }

    // ── {{value}} preserved as transform-template placeholder ─────────

    #[test]
    fn value_placeholder_preserved() {
        // `{{value}}` is the transform-template internal substitution
        // marker. Never resolved by this resolver.
        let vars = json!({"value": "should not be substituted"});
        assert_eq!(
            resolve("prefix-{{value}}-suffix", &vars),
            "prefix-{{value}}-suffix"
        );
    }

    // ── resolve_value: single-template type preservation ──────────────

    #[test]
    fn resolve_value_string_mixed_content() {
        let vars = json!({"config": {"endpoint": "http://localhost:11434"}});
        let input = json!("{{$config.endpoint}}/api/chat");
        assert_eq!(
            resolve_value(&input, &vars),
            json!("http://localhost:11434/api/chat")
        );
    }

    #[test]
    fn resolve_value_single_template_preserves_array() {
        let vars = json!({"messages": [{"role": "user", "content": "hi"}]});
        let input = json!("{{$.messages}}");
        assert_eq!(
            resolve_value(&input, &vars),
            json!([{"role": "user", "content": "hi"}])
        );
    }

    #[test]
    fn resolve_value_single_template_preserves_number() {
        let vars = json!({"count": 42});
        let input = json!("{{$.count}}");
        assert_eq!(resolve_value(&input, &vars), json!(42));
    }

    #[test]
    fn resolve_value_single_template_preserves_bool() {
        let vars = json!({"flag": true});
        let input = json!("{{$.flag}}");
        assert_eq!(resolve_value(&input, &vars), json!(true));
    }

    #[test]
    fn resolve_value_single_template_preserves_object() {
        let vars = json!({"usage": {"input_tokens": 10}});
        let input = json!("{{$.usage}}");
        assert_eq!(resolve_value(&input, &vars), json!({"input_tokens": 10}));
    }

    #[test]
    fn resolve_value_dsl_coalesce_returns_typed_fallback() {
        let vars = json!({"config": {}});
        let input = json!("{{$config.limit ?? 20}}");
        assert_eq!(resolve_value(&input, &vars), json!(20));
    }

    #[test]
    fn resolve_value_dsl_missing_renders_empty_string() {
        let vars = json!({});
        let input = json!("{{$.missing}}");
        assert_eq!(resolve_value(&input, &vars), json!(""));
    }

    #[test]
    fn resolve_value_recurses_into_object() {
        let vars = json!({
            "model": "llama3",
            "messages": [{"role": "user", "content": "hi"}]
        });
        let input = json!({
            "model": "{{$.model}}",
            "messages": "{{$.messages}}",
            "stream": false
        });
        assert_eq!(
            resolve_value(&input, &vars),
            json!({
                "model": "llama3",
                "messages": [{"role": "user", "content": "hi"}],
                "stream": false
            })
        );
    }

    #[test]
    fn resolve_value_recurses_into_array() {
        let vars = json!({"x": "alpha", "y": "beta"});
        let input = json!(["{{$.x}}", "{{$.y}}", "literal"]);
        assert_eq!(
            resolve_value(&input, &vars),
            json!(["alpha", "beta", "literal"])
        );
    }

    #[test]
    fn resolve_value_passes_through_non_string_scalars() {
        let vars = json!({});
        assert_eq!(resolve_value(&json!(42), &vars), json!(42));
        assert_eq!(resolve_value(&json!(true), &vars), json!(true));
        assert_eq!(resolve_value(&json!(null), &vars), json!(null));
    }

    #[test]
    fn resolve_value_preserves_value_placeholder() {
        // Mirrors `value_placeholder_preserved` for the resolve_value path —
        // the single-template `{{value}}` short-circuits before DSL parse.
        let vars = json!({});
        let input = json!("{{value}}");
        assert_eq!(resolve_value(&input, &vars), json!("{{value}}"));
    }

    #[test]
    fn non_dialect_placeholders_flags_bare_paths_and_allows_rooted() {
        // Dialect-conforming ($-rooted) + the `value` placeholder are clean.
        assert!(
            non_dialect_placeholders(
                "{{$.field}} {{$config.x}} {{$steps.a.result}} {{$.x ?? 'd'}} {{value}}"
            )
            .is_empty()
        );
        // Other engines' bare-path / pipe-filter forms are surfaced.
        assert_eq!(
            non_dialect_placeholders("{{config.x}} {{messages}} {{max_tokens | default:512}}"),
            vec!["config.x", "messages", "max_tokens | default:512"]
        );
    }
}
