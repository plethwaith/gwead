//! Gwead reference DSL.
//!
//! A small, purpose-built expression language for plugin manifests, with
//! JSONPath-style paths, eight reference roots (the implicit-source `$`,
//! `$input`, `$steps.<id>`, `$config`, `$secrets`, `$vars`, `$item`,
//! `$trigger`), and boolean/value operators used by `ifs` branch `test`
//! strings, `until` predicates, and `collect` accumulators.
//!
//! The canonical grammar lives in `README.md` (ABNF). The implementation is
//! a hand-rolled lexer + recursive-descent parser + tree-walking evaluator.
//!
//! See [`ast`] for the data types, [`parser::parse_reference`] and
//! [`parser::parse_expression`] for entry points, and [`eval::eval_reference`]
//! / [`eval::eval_expression`] for the evaluator.

pub mod ast;
pub mod eval;
pub mod lexer;
pub mod parser;

pub use ast::{BinaryOp, Expression, Literal, PathSegment, Reference, Root, UnaryOp};
pub use eval::{EvalContext, eval_expression, eval_reference, is_truthy};
pub use parser::{ParseError, parse_expression, parse_reference};
