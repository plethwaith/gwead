//! AST for the Gwead reference DSL.
//!
//! Two top-level surfaces:
//!
//! - `Reference` — a path expression (e.g., `$steps.search.result.results[*].id`,
//!   `$.foo.bar`, `$input.query`). Evaluates to a `serde_json::Value`.
//! - `Expression` — a boolean/value expression over references and literals
//!   (e.g., `$trigger.status == 'ok' && !$config.disabled`). Used by `ifs`
//!   branch `test` strings, `until` / `collect`, and inline by `??` (null
//!   coalesce).
//!
//! The canonical grammar lives in `src/dsl/README.md` as ABNF.

/// Reference root: which part of the execution context the path starts from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Root {
    /// `$input.*` — current action's input arguments.
    Input,
    /// `$steps.<id>.*` — earlier step's output, by step id.
    Steps(String),
    /// `$config.*` — plugin configuration.
    Config,
    /// `$secrets.*` — plugin secrets (api keys, oauth tokens). Kept
    /// separate from `$config` so plugin templates can reference
    /// `$secrets.api_key` without secrets leaking into the `$config`
    /// namespace or audit logs that redact based on namespace.
    Secrets,
    /// `$trigger.*` — triggering event payload (for event-subscribed actions).
    Trigger,
    /// `$vars.*` — action-local variables written by `store_to_variable`
    /// earlier in the same action. Available in templates
    /// AND in structural positions (`ifs[].test` / `for_each.path` / `collect` /
    /// `until`). Variables are linearly visible by manifest order, so a
    /// `$vars.X` reference creates no DAG dependency edge (the scanner in
    /// `kernel/dag.rs` only edges on `$steps.<id>`). Writer-before-reader
    /// ordering instead comes from `runtime::wave_requires_sequential`,
    /// which forces any variable-writer / `for_each` / `repeat` / `ifs` wave
    /// sequential — that fallback is load-bearing for this no-edge contract,
    /// so read its docs before changing it.
    Vars,
    /// `$item` / `$item.*` — current iteration value inside a `for_each`
    /// / `repeat` loop body.
    Item,
    /// `$.*` — implicit source. The evaluator uses
    /// `EvalContext::implicit_source` as the root — the shape
    /// `{path: "$.foo", source: "<step id>"}` manifests use.
    Implicit,
}

/// One step along a path after the root.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum PathSegment {
    /// `.field`
    Field(String),
    /// `[N]`
    Index(usize),
    /// `[*]` — project every element of an array.
    Wildcard,
    /// `[?(@.field == 'literal')]` — keep elements whose field equals the
    /// string literal. Deliberately narrow scope: equality only, string
    /// literal only.
    FilterEq { field: String, value: String },
}

/// A full path expression: root + zero or more path segments.
#[derive(Debug, Clone, PartialEq)]
pub struct Reference {
    pub root: Root,
    pub path: Vec<PathSegment>,
}

/// Literal values accepted inside expressions.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Literal {
    String(String),
    Number(f64),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnaryOp {
    Not,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BinaryOp {
    Eq,
    NotEq,
    /// Ordered comparisons. Numeric-to-numeric only: any other
    /// operand combination evaluates to `false` — no string ordering, no
    /// implicit coercion of `"404"` to `404`.
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    /// Null coalesce: `a ?? b` yields `a` unless `a` is null, in which case `b`.
    Coalesce,
}

/// A boolean/value expression.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Expression {
    Literal(Literal),
    Ref(Reference),
    Unary(UnaryOp, Box<Expression>),
    Binary(BinaryOp, Box<Expression>, Box<Expression>),
}
