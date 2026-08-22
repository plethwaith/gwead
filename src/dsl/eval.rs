//! Evaluator for the Gwead reference DSL.
//!
//! [`EvalContext`] plugs into the execution state: `input` / `steps` /
//! `config` / `secrets` / `trigger` / `vars` / `item` power the rooted
//! references; `implicit_source` powers implicit-source `$.foo` paths.
//!
//! The unwrap-singleton convention matches classic JSONPath extractor
//! behaviour: empty selection → `Value::Null`, single-element selection →
//! the element, otherwise → a `Value::Array` of the selection.

use serde_json::Value;

use super::ast::{BinaryOp, Expression, Literal, PathSegment, Reference, Root, UnaryOp};

/// Per-evaluation context the DSL evaluator sees.
///
/// `steps` is a JSON object whose keys are step ids and whose values
/// are the per-step result Value. Kernel call sites typically pass the
/// "wrapped" form (`{result, …metadata}` per step) via
/// `host_api::ExecutionState::build_dsl_steps_view` — that's what makes
/// `$steps.<id>.result.<path>` work the same across `ifs` `test` /
/// `until` / `collect` expressions AND `{{$steps.<id>.result.<path>}}`
/// templates.
/// The `{{…}}` template resolver ([`crate::domain::resolve`]) builds the
/// same wrapped view, so the two surfaces agree.
pub struct EvalContext<'a> {
    pub input: Option<&'a Value>,
    pub steps: Option<&'a Value>,
    pub config: Option<&'a Value>,
    pub secrets: Option<&'a Value>,
    pub trigger: Option<&'a Value>,
    /// `$vars.*` — action-local variables (`store_to_variable`).
    /// Populated by every call site so `$vars.X` resolves the same in
    /// templates and structural positions (`ifs`/`for_each`).
    pub vars: Option<&'a Value>,
    pub item: Option<&'a Value>,
    pub implicit_source: Option<&'a Value>,
}

impl<'a> EvalContext<'a> {
    pub fn empty() -> Self {
        Self {
            input: None,
            steps: None,
            config: None,
            secrets: None,
            trigger: None,
            vars: None,
            item: None,
            implicit_source: None,
        }
    }

    pub fn with_implicit(source: &'a Value) -> Self {
        Self {
            implicit_source: Some(source),
            ..Self::empty()
        }
    }
}

/// Evaluate a reference against the context. Returns `Value::Null` when the
/// selection is empty, the single element when there's exactly one, and a
/// `Value::Array` otherwise — the classic JSONPath extractor convention.
pub fn eval_reference(r: &Reference, ctx: &EvalContext<'_>) -> Value {
    let Some(root) = resolve_root(&r.root, ctx) else {
        return Value::Null;
    };

    let mut selection: Vec<Value> = vec![root.clone()];
    for seg in &r.path {
        selection = apply_segment(seg, selection);
        if selection.is_empty() {
            break;
        }
    }

    match selection.len() {
        0 => Value::Null,
        1 => selection.into_iter().next().unwrap(),
        _ => Value::Array(selection),
    }
}

fn resolve_root<'a>(root: &'a Root, ctx: &'a EvalContext<'a>) -> Option<&'a Value> {
    match root {
        Root::Implicit => ctx.implicit_source,
        Root::Input => ctx.input,
        Root::Config => ctx.config,
        Root::Secrets => ctx.secrets,
        Root::Trigger => ctx.trigger,
        Root::Vars => ctx.vars,
        Root::Item => ctx.item,
        Root::Steps(id) => ctx
            .steps
            .and_then(|s| s.as_object().and_then(|m| m.get(id))),
    }
}

fn apply_segment(seg: &PathSegment, sel: Vec<Value>) -> Vec<Value> {
    let mut out = Vec::with_capacity(sel.len());
    for v in sel {
        match seg {
            PathSegment::Field(name) => {
                if let Value::Object(map) = v
                    && let Some(child) = map.get(name)
                {
                    out.push(child.clone());
                }
            }
            PathSegment::Index(i) => {
                if let Value::Array(arr) = v
                    && let Some(child) = arr.get(*i)
                {
                    out.push(child.clone());
                }
            }
            PathSegment::Wildcard => {
                if let Value::Array(arr) = v {
                    out.extend(arr);
                }
                // Non-array values yield nothing (standard JSONPath behaviour).
            }
            PathSegment::FilterEq { field, value } => {
                if let Value::Array(arr) = v {
                    for elem in arr {
                        if field_equals_string(&elem, field, value) {
                            out.push(elem);
                        }
                    }
                }
            }
        }
    }
    out
}

fn field_equals_string(v: &Value, field: &str, expected: &str) -> bool {
    let Value::Object(map) = v else {
        return false;
    };
    match map.get(field) {
        Some(Value::String(s)) => s == expected,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Expression evaluator
// ---------------------------------------------------------------------------

/// Evaluate a boolean/value expression.
///
/// Boolean ops return `Value::Bool`. `??` returns the left side unless it's
/// `Null`, in which case it returns the right side.
///
/// Truthiness for logical operators is [`is_truthy`]: `null`, `false`,
/// `0`, empty string, empty array, and empty object are falsy;
/// everything else is truthy. This matches the intuition manifest
/// authors will expect for `ifs` tests.
///
/// Recursion here is bounded by the parser's caps
/// ([`MAX_EXPR_DEPTH`](crate::dsl::parser::MAX_EXPR_DEPTH) on nesting,
/// [`MAX_EXPR_OPS`](crate::dsl::parser::MAX_EXPR_OPS) on operator
/// count) — every expression the kernel evaluates comes through
/// `parse_expression`, which rejects anything deeper. Embedders
/// constructing `Expression` values by hand must bound their own depth.
pub fn eval_expression(e: &Expression, ctx: &EvalContext<'_>) -> Value {
    match e {
        Expression::Literal(l) => literal_to_value(l),
        Expression::Ref(r) => eval_reference(r, ctx),
        Expression::Unary(UnaryOp::Not, inner) => {
            let v = eval_expression(inner, ctx);
            Value::Bool(!is_truthy(&v))
        }
        Expression::Binary(op, l, r) => {
            let left = eval_expression(l, ctx);
            match op {
                BinaryOp::Eq => Value::Bool(values_equal(&left, &eval_expression(r, ctx))),
                BinaryOp::NotEq => Value::Bool(!values_equal(&left, &eval_expression(r, ctx))),
                BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                    Value::Bool(values_ordered(*op, &left, &eval_expression(r, ctx)))
                }
                BinaryOp::And => {
                    if is_truthy(&left) {
                        Value::Bool(is_truthy(&eval_expression(r, ctx)))
                    } else {
                        Value::Bool(false)
                    }
                }
                BinaryOp::Or => {
                    if is_truthy(&left) {
                        Value::Bool(true)
                    } else {
                        Value::Bool(is_truthy(&eval_expression(r, ctx)))
                    }
                }
                BinaryOp::Coalesce => {
                    if left.is_null() {
                        eval_expression(r, ctx)
                    } else {
                        left
                    }
                }
            }
        }
    }
}

fn literal_to_value(l: &Literal) -> Value {
    match l {
        Literal::String(s) => Value::String(s.clone()),
        // Preserve integer-vs-float distinction at the JSON level so a
        // literal like `20` round-trips through templates as "20" rather
        // than "20.0". The AST stores all numbers as f64; we recover
        // the integer type on emission when the f64 is exactly
        // representable as i64 and has no fractional part.
        Literal::Number(n) => {
            let is_integer =
                n.is_finite() && n.fract() == 0.0 && *n >= i64::MIN as f64 && *n <= i64::MAX as f64;
            if is_integer {
                Value::Number((*n as i64).into())
            } else {
                serde_json::Number::from_f64(*n)
                    .map(Value::Number)
                    .unwrap_or(Value::Null)
            }
        }
        Literal::Bool(b) => Value::Bool(*b),
        Literal::Null => Value::Null,
    }
}

fn values_equal(a: &Value, b: &Value) -> bool {
    // Numbers get a value-based comparison through `as_f64` so that
    // `PosInt(429) == Float(429.0)` matches — without this an `ifs`
    // step comparing `$steps.<call>.status == 429` (an HTTP status
    // stored as an integer → PosInt, the `429` literal parsed by the
    // DSL as f64 → Float) would always evaluate false. The fallback handles every other
    // type via serde_json's PartialEq (strings, bools, arrays, etc.).
    if let (Some(la), Some(lb)) = (a.as_f64(), b.as_f64()) {
        return la == lb;
    }
    a == b
}

/// Ordered comparison: numeric-to-numeric only. Any other operand
/// combination — string-vs-number, string-vs-string, null, bool, array,
/// object — evaluates to `false`. No string ordering, no implicit coercion
/// of `"404"` to `404`: the DSL's type-preservation rule means numbers
/// genuinely flow as numbers, and a silently-ordered string is worse than
/// a comparison that visibly never matches.
fn values_ordered(op: BinaryOp, a: &Value, b: &Value) -> bool {
    let (Some(la), Some(lb)) = (a.as_f64(), b.as_f64()) else {
        return false;
    };
    match op {
        BinaryOp::Lt => la < lb,
        BinaryOp::Le => la <= lb,
        BinaryOp::Gt => la > lb,
        BinaryOp::Ge => la >= lb,
        // eval_expression only routes the four ordered operators here.
        _ => false,
    }
}

/// The DSL's truthiness rule: `null`, `false`, `0`, empty string, empty
/// array, and empty object are falsy; everything else is truthy.
///
/// This is the single definition — the kernel's `ifs`-condition coercion
/// calls this same function, so `$input.flag` and `!$input.flag` always
/// negate each other exactly. (Note the string `"false"` is truthy, as
/// in JavaScript: it's a non-empty string. Compare explicitly —
/// `$.flag == 'false'` — when a flag flows as a string.)
pub fn is_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::parser::{parse_expression, parse_reference};
    use serde_json::json;

    fn ev_ref(src: &str, source: &Value) -> Value {
        let r = parse_reference(src).unwrap();
        let ctx = EvalContext::with_implicit(source);
        eval_reference(&r, &ctx)
    }

    // ---------- reference eval, implicit-source shape ----------

    #[test]
    fn just_root_returns_document() {
        let doc = json!({"a": 1});
        assert_eq!(ev_ref("$", &doc), doc);
    }

    #[test]
    fn simple_field() {
        let doc = json!({"title": "Gatsby"});
        assert_eq!(ev_ref("$.title", &doc), json!("Gatsby"));
    }

    #[test]
    fn nested_field() {
        let doc = json!({"a": {"b": {"c": 42}}});
        assert_eq!(ev_ref("$.a.b.c", &doc), json!(42));
    }

    #[test]
    fn missing_field_is_null() {
        let doc = json!({"a": 1});
        assert_eq!(ev_ref("$.missing", &doc), Value::Null);
    }

    #[test]
    fn deeply_missing_is_null() {
        let doc = json!({"a": 1});
        assert_eq!(ev_ref("$.a.b.c", &doc), Value::Null);
    }

    #[test]
    fn array_index() {
        let doc = json!({"xs": [10, 20, 30]});
        assert_eq!(ev_ref("$.xs[0]", &doc), json!(10));
        assert_eq!(ev_ref("$.xs[2]", &doc), json!(30));
    }

    #[test]
    fn array_index_out_of_bounds_is_null() {
        let doc = json!({"xs": [10]});
        assert_eq!(ev_ref("$.xs[5]", &doc), Value::Null);
    }

    #[test]
    fn wildcard_on_array() {
        let doc = json!({"xs": [1, 2, 3]});
        assert_eq!(ev_ref("$.xs[*]", &doc), json!([1, 2, 3]));
    }

    #[test]
    fn wildcard_on_empty_array_is_null() {
        let doc = json!({"xs": []});
        assert_eq!(ev_ref("$.xs[*]", &doc), Value::Null);
    }

    #[test]
    fn wildcard_on_single_item_unwraps() {
        // The unwrap-singleton rule: [*] on a 1-element array yields the element.
        let doc = json!({"xs": [42]});
        assert_eq!(ev_ref("$.xs[*]", &doc), json!(42));
    }

    #[test]
    fn wildcard_then_field() {
        let doc = json!({"authors": [{"name": "A"}, {"name": "B"}]});
        assert_eq!(ev_ref("$.authors[*].name", &doc), json!(["A", "B"]));
    }

    #[test]
    fn nested_index_and_field() {
        let doc = json!({"entries": [{"isbn_13": ["X"]}]});
        assert_eq!(ev_ref("$.entries[0].isbn_13[0]", &doc), json!("X"));
    }

    #[test]
    fn filter_eq_keeps_matches() {
        let doc = json!({
            "crew": [
                {"job": "Director", "name": "Nolan"},
                {"job": "Producer", "name": "Thomas"},
                {"job": "Director", "name": "Coen"},
            ]
        });
        assert_eq!(
            ev_ref("$.crew[?(@.job=='Director')].name", &doc),
            json!(["Nolan", "Coen"])
        );
    }

    #[test]
    fn filter_eq_single_match_unwraps() {
        let doc = json!({
            "crew": [
                {"job": "Director", "name": "Nolan"},
                {"job": "Producer", "name": "Thomas"},
            ]
        });
        assert_eq!(
            ev_ref("$.crew[?(@.job=='Director')].name", &doc),
            json!("Nolan")
        );
    }

    #[test]
    fn filter_eq_no_match_is_null() {
        let doc = json!({
            "crew": [{"job": "Producer", "name": "Thomas"}]
        });
        assert_eq!(
            ev_ref("$.crew[?(@.job=='Director')].name", &doc),
            Value::Null
        );
    }

    // ---------- reference eval, rooted ----------

    #[test]
    fn input_root() {
        let input = json!({"query": "hello"});
        let r = parse_reference("$input.query").unwrap();
        let ctx = EvalContext {
            input: Some(&input),
            ..EvalContext::empty()
        };
        assert_eq!(eval_reference(&r, &ctx), json!("hello"));
    }

    #[test]
    fn steps_root() {
        let steps = json!({
            "search": {"results": [{"id": 1}, {"id": 2}]}
        });
        let r = parse_reference("$steps.search.results[*].id").unwrap();
        let ctx = EvalContext {
            steps: Some(&steps),
            ..EvalContext::empty()
        };
        assert_eq!(eval_reference(&r, &ctx), json!([1, 2]));
    }

    #[test]
    fn config_root() {
        let config = json!({"apiKey": "secret"});
        let r = parse_reference("$config.apiKey").unwrap();
        let ctx = EvalContext {
            config: Some(&config),
            ..EvalContext::empty()
        };
        assert_eq!(eval_reference(&r, &ctx), json!("secret"));
    }

    #[test]
    fn trigger_root() {
        let trig = json!({"status": "ok"});
        let r = parse_reference("$trigger.status").unwrap();
        let ctx = EvalContext {
            trigger: Some(&trig),
            ..EvalContext::empty()
        };
        assert_eq!(eval_reference(&r, &ctx), json!("ok"));
    }

    #[test]
    fn vars_root() {
        // `$vars.*` resolves action-local variables — the bridge a branch
        // uses to hand a list to an outer `for_each`.
        let vars = json!({"imagePaths": ["a.jpg", "b.jpg"]});
        let r = parse_reference("$vars.imagePaths").unwrap();
        let ctx = EvalContext {
            vars: Some(&vars),
            ..EvalContext::empty()
        };
        assert_eq!(eval_reference(&r, &ctx), json!(["a.jpg", "b.jpg"]));
    }

    #[test]
    fn missing_step_is_null() {
        let steps = json!({});
        let r = parse_reference("$steps.nope.foo").unwrap();
        let ctx = EvalContext {
            steps: Some(&steps),
            ..EvalContext::empty()
        };
        assert_eq!(eval_reference(&r, &ctx), Value::Null);
    }

    #[test]
    fn missing_implicit_source_is_null() {
        let r = parse_reference("$.foo").unwrap();
        let ctx = EvalContext::empty();
        assert_eq!(eval_reference(&r, &ctx), Value::Null);
    }

    // ---------- expression eval ----------

    fn ev_expr(src: &str, implicit: &Value) -> Value {
        let e = parse_expression(src).unwrap();
        let ctx = EvalContext::with_implicit(implicit);
        eval_expression(&e, &ctx)
    }

    #[test]
    fn literal_values() {
        let doc = json!({});
        assert_eq!(ev_expr("true", &doc), json!(true));
        assert_eq!(ev_expr("false", &doc), json!(false));
        assert_eq!(ev_expr("null", &doc), Value::Null);
        assert_eq!(ev_expr("'x'", &doc), json!("x"));
        // Integer-valued literals emit JSON integers (so `?? 42` round-trips
        // through templates as "42" not "42.0").
        assert_eq!(ev_expr("42", &doc), json!(42));
        // Fractional literals stay floats.
        assert_eq!(ev_expr("3.5", &doc), json!(3.5));
    }

    #[test]
    fn equality_and_inequality() {
        let doc = json!({"status": "ok"});
        assert_eq!(ev_expr("$.status == 'ok'", &doc), json!(true));
        assert_eq!(ev_expr("$.status == 'err'", &doc), json!(false));
        assert_eq!(ev_expr("$.status != 'err'", &doc), json!(true));
    }

    #[test]
    fn ordered_comparisons_numeric() {
        let doc = json!({"status": 503, "count": 3, "ratio": 0.5});
        assert_eq!(ev_expr("$.status >= 500", &doc), json!(true));
        assert_eq!(ev_expr("$.status >= 503", &doc), json!(true));
        assert_eq!(ev_expr("$.status > 503", &doc), json!(false));
        assert_eq!(ev_expr("$.status < 600", &doc), json!(true));
        assert_eq!(ev_expr("$.status <= 502", &doc), json!(false));
        assert_eq!(ev_expr("$.count < 5", &doc), json!(true));
        // Integer-vs-float comparison goes through as_f64, like equality.
        assert_eq!(ev_expr("$.ratio >= 0.5", &doc), json!(true));
        assert_eq!(ev_expr("$.ratio > 0.5", &doc), json!(false));
        // Both sides may be references.
        let doc2 = json!({"confidence": 0.8, "threshold": 0.75});
        assert_eq!(ev_expr("$.confidence >= $.threshold", &doc2), json!(true));
        assert_eq!(ev_expr("$.confidence < $.threshold", &doc2), json!(false));
    }

    #[test]
    fn ordered_comparisons_non_numeric_are_false() {
        // Strict semantics: anything that isn't number-vs-number is
        // false — no string ordering, no "404" → 404 coercion.
        let doc = json!({
            "str_status": "503",
            "name": "abc",
            "flag": true,
            "list": [1, 2],
        });
        assert_eq!(ev_expr("$.str_status >= 500", &doc), json!(false));
        assert_eq!(ev_expr("$.str_status < 999", &doc), json!(false));
        assert_eq!(ev_expr("$.name < 'abd'", &doc), json!(false));
        assert_eq!(ev_expr("$.flag > 0", &doc), json!(false));
        assert_eq!(ev_expr("$.list > 0", &doc), json!(false));
        assert_eq!(ev_expr("$.missing < 5", &doc), json!(false));
        assert_eq!(ev_expr("null < 5", &doc), json!(false));
        // ...and the negation of a false comparison is true — authors can
        // still express "not provably ≥" if they want it.
        assert_eq!(ev_expr("!($.str_status >= 500)", &doc), json!(true));
    }

    #[test]
    fn logical_and_or() {
        let doc = json!({"a": true, "b": false});
        assert_eq!(ev_expr("$.a && $.b", &doc), json!(false));
        assert_eq!(ev_expr("$.a || $.b", &doc), json!(true));
        assert_eq!(ev_expr("$.a && !$.b", &doc), json!(true));
    }

    #[test]
    fn coalesce() {
        let doc = json!({"a": "first", "b": "second"});
        assert_eq!(ev_expr("$.a ?? $.b", &doc), json!("first"));
        assert_eq!(ev_expr("$.missing ?? $.b", &doc), json!("second"));
        assert_eq!(ev_expr("$.missing ?? 'fallback'", &doc), json!("fallback"));
    }

    #[test]
    fn truthiness_rules() {
        let doc = json!({
            "zero": 0,
            "empty_str": "",
            "empty_arr": [],
            "empty_obj": {},
            "filled": "x",
        });
        assert_eq!(ev_expr("!$.zero", &doc), json!(true));
        assert_eq!(ev_expr("!$.empty_str", &doc), json!(true));
        assert_eq!(ev_expr("!$.empty_arr", &doc), json!(true));
        assert_eq!(ev_expr("!$.empty_obj", &doc), json!(true));
        assert_eq!(ev_expr("!$.filled", &doc), json!(false));
        assert_eq!(ev_expr("!$.missing", &doc), json!(true));
    }

    #[test]
    fn precedence_equality_and_logic() {
        let doc = json!({"a": "x", "b": "y"});
        // (a == 'x') && (b == 'y')
        assert_eq!(ev_expr("$.a == 'x' && $.b == 'y'", &doc), json!(true));
        assert_eq!(ev_expr("$.a == 'x' && $.b == 'z'", &doc), json!(false));
    }

    #[test]
    fn coalesce_is_lower_than_or() {
        let doc = json!({});
        // null ?? (false || true) = null ?? true = true
        assert_eq!(ev_expr("null ?? false || true", &doc), json!(true));
    }

    #[test]
    fn paren_grouping_affects_precedence() {
        let doc = json!({"a": false, "b": false, "c": true});
        // without parens: a || (b && c) → false
        assert_eq!(ev_expr("$.a || $.b && $.c", &doc), json!(false));
        // with parens: (a || b) && c → false
        assert_eq!(ev_expr("($.a || $.b) && $.c", &doc), json!(false));
        // but with a truthy: (a || b) && c  where b true → true
        let doc2 = json!({"a": false, "b": true, "c": true});
        assert_eq!(ev_expr("($.a || $.b) && $.c", &doc2), json!(true));
    }
}
