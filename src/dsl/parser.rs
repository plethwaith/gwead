//! Recursive-descent parser for the Gwead reference DSL.
//!
//! Two entry points:
//!
//! - [`parse_reference`] — a path expression starting with `$`.
//! - [`parse_expression`] — a boolean/value expression using references,
//!   literals, and operators.
//!
//! The canonical grammar is in `src/dsl/README.md`.

use std::fmt;

use super::ast::{BinaryOp, Expression, Literal, PathSegment, Reference, Root, UnaryOp};
use super::lexer::{LexError, Lexer, Token, TokenKind};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    Lex(LexError),
    Unexpected { message: String, position: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Lex(e) => write!(f, "{e}"),
            ParseError::Unexpected { message, position } => {
                write!(f, "parse error at byte {position}: {message}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

impl From<LexError> for ParseError {
    fn from(e: LexError) -> Self {
        ParseError::Lex(e)
    }
}

/// Maximum recursion depth for the self-recursive productions
/// (`(expr)` nesting and `!` chains). Expressions arrive in manifests,
/// which are untrusted input parsed outside the sandbox — deep nesting
/// must produce a `ParseError`, not a parse-time stack overflow.
pub const MAX_EXPR_DEPTH: usize = 128;

/// Maximum number of binary operators in one expression. This caps the
/// depth of the left-deep tree a flat `a ?? b ?? …` chain builds: that
/// chain parses iteratively (no parser recursion), but an unbounded
/// tree would overflow the stack later — in the recursive evaluator,
/// or in the recursive `Box` drop the moment the tree is discarded.
/// Enforced *while* parsing, so the oversized tree is never built.
pub const MAX_EXPR_OPS: usize = 256;

/// Parse a full reference expression (must consume the entire input).
pub fn parse_reference(src: &str) -> Result<Reference, ParseError> {
    let tokens = Lexer::new(src).tokenize()?;
    let mut p = Parser::new(tokens);
    let r = p.parse_reference()?;
    p.expect_eof()?;
    Ok(r)
}

/// Parse a full boolean/value expression (must consume the entire input).
pub fn parse_expression(src: &str) -> Result<Expression, ParseError> {
    let tokens = Lexer::new(src).tokenize()?;
    let mut p = Parser::new(tokens);
    let e = p.parse_expression()?;
    p.expect_eof()?;
    Ok(e)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    depth: usize,
    ops: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            pos: 0,
            depth: 0,
            ops: 0,
        }
    }

    /// Recursion guard for the two self-recursive productions (`(expr)`
    /// and `!expr`). Callers must pair every successful `descend` with
    /// an `ascend`.
    fn descend(&mut self, position: usize) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_EXPR_DEPTH {
            return Err(ParseError::Unexpected {
                message: format!(
                    "expression nesting exceeds the maximum depth of {MAX_EXPR_DEPTH}"
                ),
                position,
            });
        }
        Ok(())
    }

    fn ascend(&mut self) {
        self.depth -= 1;
    }

    /// Operator-count guard, called once per binary operator as the
    /// precedence loops consume them. Erroring here (rather than after
    /// the parse) means a pathological flat chain never materializes as
    /// a tree deep enough to overflow the evaluator or the `Box` drop.
    fn count_op(&mut self, position: usize) -> Result<(), ParseError> {
        self.ops += 1;
        if self.ops > MAX_EXPR_OPS {
            return Err(ParseError::Unexpected {
                message: format!(
                    "expression uses more than the maximum of {MAX_EXPR_OPS} operators"
                ),
                position,
            });
        }
        Ok(())
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn bump(&mut self) -> Token {
        let t = self.tokens[self.pos].clone();
        if !matches!(t.kind, TokenKind::Eof) {
            self.pos += 1;
        }
        t
    }

    fn expect_eof(&self) -> Result<(), ParseError> {
        if matches!(self.peek().kind, TokenKind::Eof) {
            Ok(())
        } else {
            Err(ParseError::Unexpected {
                message: format!("expected end of input, found `{}`", self.peek().kind),
                position: self.peek().start,
            })
        }
    }

    fn expect(&mut self, want: &TokenKind) -> Result<Token, ParseError> {
        if std::mem::discriminant(&self.peek().kind) == std::mem::discriminant(want) {
            Ok(self.bump())
        } else {
            Err(ParseError::Unexpected {
                message: format!("expected `{}`, found `{}`", want, self.peek().kind),
                position: self.peek().start,
            })
        }
    }

    // ---------------------------------------------------------------------
    // Reference: "$" [root_name] path
    //
    // Where root_name is one of: input, steps.<id>, config, secrets,
    // trigger, vars, item (absent = implicit source, i.e. `$`/`$.foo`).
    // ---------------------------------------------------------------------

    fn parse_reference(&mut self) -> Result<Reference, ParseError> {
        // Leading $
        self.expect(&TokenKind::Dollar)?;

        // Root: determined by what immediately follows the $.
        //   $            → Implicit, empty path
        //   $.foo        → Implicit, path=[foo]
        //   $input.foo   → Input, path=[foo]
        //   $steps.id.x  → Steps("id"), path=[x]
        //   $config.foo  → Config
        //   $secrets.k   → Secrets
        //   $trigger.foo → Trigger
        //   $vars.x      → Vars, path=[x]
        //   $item        → Item, empty path
        //   $item.name   → Item, path=[name]
        //   $[0]         → Implicit, path=[Index(0)]  (covers root-level indexing)
        let root = match &self.peek().kind {
            TokenKind::Ident(name) => {
                let name = name.clone();
                match name.as_str() {
                    "input" => {
                        self.bump();
                        Root::Input
                    }
                    "config" => {
                        self.bump();
                        Root::Config
                    }
                    "secrets" => {
                        self.bump();
                        Root::Secrets
                    }
                    "trigger" => {
                        self.bump();
                        Root::Trigger
                    }
                    "vars" => {
                        self.bump();
                        Root::Vars
                    }
                    "item" => {
                        self.bump();
                        Root::Item
                    }
                    "steps" => {
                        self.bump();
                        // Require `.<step-id>`
                        self.expect(&TokenKind::Dot)?;
                        let id_tok = self.bump();
                        let TokenKind::Ident(id) = id_tok.kind else {
                            return Err(ParseError::Unexpected {
                                message: "expected step id after `$steps.`".to_string(),
                                position: id_tok.start,
                            });
                        };
                        Root::Steps(id)
                    }
                    other => {
                        return Err(ParseError::Unexpected {
                            message: format!(
                                "unknown reference root `${other}` (expected input/steps/config/secrets/trigger/vars/item or `.`)"
                            ),
                            position: self.peek().start,
                        });
                    }
                }
            }
            _ => Root::Implicit,
        };

        let path = self.parse_path_segments()?;
        Ok(Reference { root, path })
    }

    fn parse_path_segments(&mut self) -> Result<Vec<PathSegment>, ParseError> {
        let mut segs = Vec::new();
        loop {
            match &self.peek().kind {
                TokenKind::Dot => {
                    self.bump();
                    let tok = self.bump();
                    let TokenKind::Ident(name) = tok.kind else {
                        return Err(ParseError::Unexpected {
                            message: "expected field name after `.`".to_string(),
                            position: tok.start,
                        });
                    };
                    segs.push(PathSegment::Field(name));
                }
                TokenKind::LBracket => {
                    self.bump();
                    let seg = self.parse_bracket_segment()?;
                    segs.push(seg);
                }
                _ => break,
            }
        }
        Ok(segs)
    }

    fn parse_bracket_segment(&mut self) -> Result<PathSegment, ParseError> {
        // `[` already consumed. Discriminate on the first token.
        let tok = self.bump();
        let seg = match tok.kind {
            TokenKind::Star => PathSegment::Wildcard,
            TokenKind::Number(n) => {
                if n < 0.0 || n.fract() != 0.0 {
                    return Err(ParseError::Unexpected {
                        message: format!("array index must be a non-negative integer, got {n}"),
                        position: tok.start,
                    });
                }
                PathSegment::Index(n as usize)
            }
            TokenKind::Question => {
                // Filter: ?(@.field == 'literal')
                self.expect(&TokenKind::LParen)?;
                self.expect(&TokenKind::At)?;
                self.expect(&TokenKind::Dot)?;
                let field_tok = self.bump();
                let TokenKind::Ident(field) = field_tok.kind else {
                    return Err(ParseError::Unexpected {
                        message: "expected field name in filter".to_string(),
                        position: field_tok.start,
                    });
                };
                self.expect(&TokenKind::Eq)?;
                let lit_tok = self.bump();
                let TokenKind::String(value) = lit_tok.kind else {
                    return Err(ParseError::Unexpected {
                        message: "filter only supports equality against a string literal"
                            .to_string(),
                        position: lit_tok.start,
                    });
                };
                self.expect(&TokenKind::RParen)?;
                PathSegment::FilterEq { field, value }
            }
            other => {
                return Err(ParseError::Unexpected {
                    message: format!("unexpected `{other}` inside `[…]`"),
                    position: tok.start,
                });
            }
        };
        self.expect(&TokenKind::RBracket)?;
        Ok(seg)
    }

    // ---------------------------------------------------------------------
    // Expression: standard precedence climb.
    //   coalesce  (lowest): a ?? b
    //   or       :  a || b
    //   and      :  a && b
    //   equality :  a == b, a != b
    //   comparison: a < b, a <= b, a > b, a >= b
    //   unary    :  !a
    //   primary  :  literal, reference, (expression)
    // ---------------------------------------------------------------------

    fn parse_expression(&mut self) -> Result<Expression, ParseError> {
        self.parse_coalesce()
    }

    fn parse_coalesce(&mut self) -> Result<Expression, ParseError> {
        let mut left = self.parse_or()?;
        while matches!(self.peek().kind, TokenKind::Coalesce) {
            self.count_op(self.peek().start)?;
            self.bump();
            let right = self.parse_or()?;
            left = Expression::Binary(BinaryOp::Coalesce, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_or(&mut self) -> Result<Expression, ParseError> {
        let mut left = self.parse_and()?;
        while matches!(self.peek().kind, TokenKind::Or) {
            self.count_op(self.peek().start)?;
            self.bump();
            let right = self.parse_and()?;
            left = Expression::Binary(BinaryOp::Or, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expression, ParseError> {
        let mut left = self.parse_equality()?;
        while matches!(self.peek().kind, TokenKind::And) {
            self.count_op(self.peek().start)?;
            self.bump();
            let right = self.parse_equality()?;
            left = Expression::Binary(BinaryOp::And, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_equality(&mut self) -> Result<Expression, ParseError> {
        let mut left = self.parse_comparison()?;
        loop {
            let op = match self.peek().kind {
                TokenKind::Eq => BinaryOp::Eq,
                TokenKind::NotEq => BinaryOp::NotEq,
                _ => break,
            };
            self.count_op(self.peek().start)?;
            self.bump();
            let right = self.parse_comparison()?;
            left = Expression::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_comparison(&mut self) -> Result<Expression, ParseError> {
        let mut left = self.parse_unary()?;
        loop {
            let op = match self.peek().kind {
                TokenKind::Lt => BinaryOp::Lt,
                TokenKind::Le => BinaryOp::Le,
                TokenKind::Gt => BinaryOp::Gt,
                TokenKind::Ge => BinaryOp::Ge,
                _ => break,
            };
            self.count_op(self.peek().start)?;
            self.bump();
            let right = self.parse_unary()?;
            left = Expression::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expression, ParseError> {
        if matches!(self.peek().kind, TokenKind::Not) {
            self.descend(self.peek().start)?;
            self.bump();
            let inner = self.parse_unary();
            self.ascend();
            return Ok(Expression::Unary(UnaryOp::Not, Box::new(inner?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expression, ParseError> {
        match &self.peek().kind {
            TokenKind::LParen => {
                self.descend(self.peek().start)?;
                self.bump();
                let e = self.parse_expression();
                self.ascend();
                let e = e?;
                self.expect(&TokenKind::RParen)?;
                Ok(e)
            }
            TokenKind::Dollar => {
                let r = self.parse_reference()?;
                Ok(Expression::Ref(r))
            }
            TokenKind::String(_) => {
                let tok = self.bump();
                let TokenKind::String(s) = tok.kind else {
                    unreachable!()
                };
                Ok(Expression::Literal(Literal::String(s)))
            }
            TokenKind::Number(_) => {
                let tok = self.bump();
                let TokenKind::Number(n) = tok.kind else {
                    unreachable!()
                };
                Ok(Expression::Literal(Literal::Number(n)))
            }
            TokenKind::True => {
                self.bump();
                Ok(Expression::Literal(Literal::Bool(true)))
            }
            TokenKind::False => {
                self.bump();
                Ok(Expression::Literal(Literal::Bool(false)))
            }
            TokenKind::Null => {
                self.bump();
                Ok(Expression::Literal(Literal::Null))
            }
            other => Err(ParseError::Unexpected {
                message: format!("expected expression, found `{other}`"),
                position: self.peek().start,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- References ----------

    #[test]
    fn just_root() {
        let r = parse_reference("$").unwrap();
        assert_eq!(
            r,
            Reference {
                root: Root::Implicit,
                path: vec![]
            }
        );
    }

    #[test]
    fn implicit_single_field() {
        let r = parse_reference("$.foo").unwrap();
        assert_eq!(
            r,
            Reference {
                root: Root::Implicit,
                path: vec![PathSegment::Field("foo".into())]
            }
        );
    }

    #[test]
    fn implicit_nested() {
        let r = parse_reference("$.foo.bar.baz").unwrap();
        assert_eq!(
            r.path,
            vec![
                PathSegment::Field("foo".into()),
                PathSegment::Field("bar".into()),
                PathSegment::Field("baz".into()),
            ]
        );
    }

    #[test]
    fn index_and_wildcard() {
        let r = parse_reference("$.results[0].items[*].name").unwrap();
        assert_eq!(
            r.path,
            vec![
                PathSegment::Field("results".into()),
                PathSegment::Index(0),
                PathSegment::Field("items".into()),
                PathSegment::Wildcard,
                PathSegment::Field("name".into()),
            ]
        );
    }

    #[test]
    fn filter_eq() {
        let r = parse_reference("$.crew[?(@.job=='Director')].name").unwrap();
        assert_eq!(
            r.path,
            vec![
                PathSegment::Field("crew".into()),
                PathSegment::FilterEq {
                    field: "job".into(),
                    value: "Director".into()
                },
                PathSegment::Field("name".into()),
            ]
        );
    }

    #[test]
    fn input_root() {
        let r = parse_reference("$input.query").unwrap();
        assert_eq!(r.root, Root::Input);
        assert_eq!(r.path, vec![PathSegment::Field("query".into())]);
    }

    #[test]
    fn steps_root() {
        let r = parse_reference("$steps.search.results[*].id").unwrap();
        assert_eq!(r.root, Root::Steps("search".into()));
        assert_eq!(
            r.path,
            vec![
                PathSegment::Field("results".into()),
                PathSegment::Wildcard,
                PathSegment::Field("id".into()),
            ]
        );
    }

    #[test]
    fn config_root() {
        let r = parse_reference("$config.apiKey").unwrap();
        assert_eq!(r.root, Root::Config);
    }

    #[test]
    fn trigger_root() {
        let r = parse_reference("$trigger.payload.id").unwrap();
        assert_eq!(r.root, Root::Trigger);
    }

    #[test]
    fn vars_root() {
        let r = parse_reference("$vars.imagePaths").unwrap();
        assert_eq!(r.root, Root::Vars);
        assert_eq!(r.path, vec![PathSegment::Field("imagePaths".to_string())]);
    }

    #[test]
    fn unknown_root_errors() {
        let err = parse_reference("$nope.foo").unwrap_err();
        assert!(matches!(err, ParseError::Unexpected { .. }));
    }

    #[test]
    fn steps_without_id_errors() {
        let err = parse_reference("$steps.").unwrap_err();
        assert!(matches!(err, ParseError::Unexpected { .. }));
    }

    #[test]
    fn hyphenated_field() {
        let r = parse_reference("$.release-groups[*]").unwrap();
        assert_eq!(
            r.path,
            vec![
                PathSegment::Field("release-groups".into()),
                PathSegment::Wildcard,
            ]
        );
    }

    // ---------- Expressions ----------

    #[test]
    fn literal_expr() {
        assert_eq!(
            parse_expression("true").unwrap(),
            Expression::Literal(Literal::Bool(true))
        );
        assert_eq!(
            parse_expression("null").unwrap(),
            Expression::Literal(Literal::Null)
        );
        assert_eq!(
            parse_expression("'hello'").unwrap(),
            Expression::Literal(Literal::String("hello".into()))
        );
    }

    #[test]
    fn equality() {
        let e = parse_expression("$trigger.status == 'ok'").unwrap();
        let Expression::Binary(BinaryOp::Eq, left, right) = e else {
            panic!("expected binary");
        };
        assert!(matches!(*left, Expression::Ref(_)));
        assert!(matches!(*right, Expression::Literal(Literal::String(_))));
    }

    #[test]
    fn precedence_and_over_or() {
        // a || b && c  →  a || (b && c)
        let e = parse_expression("$.a || $.b && $.c").unwrap();
        let Expression::Binary(BinaryOp::Or, left, right) = e else {
            panic!("expected OR at top");
        };
        assert!(matches!(*left, Expression::Ref(_)));
        let Expression::Binary(BinaryOp::And, _, _) = *right else {
            panic!("expected AND nested under OR");
        };
    }

    #[test]
    fn precedence_equality_over_and() {
        // a == b && c  →  (a == b) && c
        let e = parse_expression("$.a == 'x' && $.c").unwrap();
        let Expression::Binary(BinaryOp::And, left, _) = e else {
            panic!("expected AND at top");
        };
        assert!(matches!(*left, Expression::Binary(BinaryOp::Eq, _, _)));
    }

    #[test]
    fn ordered_comparisons() {
        for (src, want) in [
            ("$.status < 400", BinaryOp::Lt),
            ("$.status <= 400", BinaryOp::Le),
            ("$.status > 400", BinaryOp::Gt),
            ("$.status >= 400", BinaryOp::Ge),
        ] {
            let e = parse_expression(src).unwrap();
            let Expression::Binary(op, left, right) = e else {
                panic!("expected binary for {src}");
            };
            assert_eq!(op, want, "{src}");
            assert!(matches!(*left, Expression::Ref(_)));
            assert!(matches!(
                *right,
                Expression::Literal(Literal::Number(n)) if n == 400.0
            ));
        }
    }

    #[test]
    fn precedence_comparison_over_equality() {
        // a >= b == c  →  (a >= b) == c
        let e = parse_expression("$.a >= 1 == true").unwrap();
        let Expression::Binary(BinaryOp::Eq, left, _) = e else {
            panic!("expected EQ at top");
        };
        assert!(matches!(*left, Expression::Binary(BinaryOp::Ge, _, _)));
    }

    #[test]
    fn precedence_comparison_over_and() {
        // a >= 500 && b < 3  →  (a >= 500) && (b < 3)
        let e = parse_expression("$.a >= 500 && $.b < 3").unwrap();
        let Expression::Binary(BinaryOp::And, left, right) = e else {
            panic!("expected AND at top");
        };
        assert!(matches!(*left, Expression::Binary(BinaryOp::Ge, _, _)));
        assert!(matches!(*right, Expression::Binary(BinaryOp::Lt, _, _)));
    }

    #[test]
    fn not_prefix() {
        let e = parse_expression("!$.flag").unwrap();
        assert!(matches!(e, Expression::Unary(UnaryOp::Not, _)));
    }

    #[test]
    fn coalesce_lowest_precedence() {
        // a ?? b || c  →  a ?? (b || c)
        let e = parse_expression("$.a ?? $.b || $.c").unwrap();
        let Expression::Binary(BinaryOp::Coalesce, _, right) = e else {
            panic!("expected coalesce at top");
        };
        assert!(matches!(*right, Expression::Binary(BinaryOp::Or, _, _)));
    }

    #[test]
    fn paren_grouping() {
        // (a || b) && c  →  AND top, OR left
        let e = parse_expression("($.a || $.b) && $.c").unwrap();
        let Expression::Binary(BinaryOp::And, left, _) = e else {
            panic!("expected AND at top");
        };
        assert!(matches!(*left, Expression::Binary(BinaryOp::Or, _, _)));
    }

    #[test]
    fn trailing_junk_errors() {
        let err = parse_reference("$.foo garbage").unwrap_err();
        assert!(matches!(err, ParseError::Unexpected { .. }));
    }

    // ---------- depth limits ----------
    // Manifests are untrusted; deep nesting must produce a ParseError,
    // never a stack overflow (SIGABRT would take down the whole host,
    // not just the parse).

    #[test]
    fn deeply_nested_parens_rejected_not_overflowed() {
        let src = format!("{}1{}", "(".repeat(100_000), ")".repeat(100_000));
        let err = parse_expression(&src).unwrap_err();
        assert!(matches!(err, ParseError::Unexpected { .. }));
    }

    #[test]
    fn deep_not_chain_rejected_not_overflowed() {
        let src = format!("{}true", "!".repeat(100_000));
        let err = parse_expression(&src).unwrap_err();
        assert!(matches!(err, ParseError::Unexpected { .. }));
    }

    #[test]
    fn flat_coalesce_chain_rejected_by_op_cap() {
        // Parses iteratively (no parser recursion) but would build a
        // left-deep tree that overflows the stack at eval — or in the
        // recursive Box drop. The op cap stops it mid-parse, before
        // the tree ever gets that deep.
        let src = format!("null{}", " ?? null".repeat(100_000));
        let err = parse_expression(&src).unwrap_err();
        assert!(matches!(err, ParseError::Unexpected { .. }));
    }

    #[test]
    fn moderate_nesting_still_parses() {
        let src = format!("{}$.a{}", "(".repeat(64), ")".repeat(64));
        parse_expression(&src).unwrap();
        let src = format!("null{} ?? 1", " ?? null".repeat(64));
        parse_expression(&src).unwrap();
    }
}
