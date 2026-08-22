//! Hand-written lexer for the Gwead reference DSL.
//!
//! Operates on byte slices with no regex. Tokens are emitted with their
//! source-span so the parser can point at the offending byte on error.

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum TokenKind {
    Dollar,   // $
    Dot,      // .
    LBracket, // [
    RBracket, // ]
    LParen,   // (
    RParen,   // )
    Question, // ?
    At,       // @
    Star,     // *
    Eq,       // ==
    NotEq,    // !=
    Lt,       // <
    Le,       // <=
    Gt,       // >
    Ge,       // >=
    Not,      // !
    And,      // &&
    Or,       // ||
    Coalesce, // ??
    Ident(String),
    String(String),
    Number(f64),
    True,
    False,
    Null,
    Eof,
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenKind::Dollar => f.write_str("$"),
            TokenKind::Dot => f.write_str("."),
            TokenKind::LBracket => f.write_str("["),
            TokenKind::RBracket => f.write_str("]"),
            TokenKind::LParen => f.write_str("("),
            TokenKind::RParen => f.write_str(")"),
            TokenKind::Question => f.write_str("?"),
            TokenKind::At => f.write_str("@"),
            TokenKind::Star => f.write_str("*"),
            TokenKind::Eq => f.write_str("=="),
            TokenKind::NotEq => f.write_str("!="),
            TokenKind::Lt => f.write_str("<"),
            TokenKind::Le => f.write_str("<="),
            TokenKind::Gt => f.write_str(">"),
            TokenKind::Ge => f.write_str(">="),
            TokenKind::Not => f.write_str("!"),
            TokenKind::And => f.write_str("&&"),
            TokenKind::Or => f.write_str("||"),
            TokenKind::Coalesce => f.write_str("??"),
            TokenKind::Ident(s) => write!(f, "ident({s})"),
            TokenKind::String(s) => write!(f, "\"{s}\""),
            TokenKind::Number(n) => write!(f, "{n}"),
            TokenKind::True => f.write_str("true"),
            TokenKind::False => f.write_str("false"),
            TokenKind::Null => f.write_str("null"),
            TokenKind::Eof => f.write_str("<eof>"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub start: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexError {
    pub message: String,
    pub position: usize,
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lex error at byte {}: {}", self.position, self.message)
    }
}

impl std::error::Error for LexError {}

pub struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a str) -> Self {
        Self {
            src: src.as_bytes(),
            pos: 0,
        }
    }

    pub fn tokenize(mut self) -> Result<Vec<Token>, LexError> {
        let mut out = Vec::new();
        loop {
            let tok = self.next_token()?;
            let is_eof = matches!(tok.kind, TokenKind::Eof);
            out.push(tok);
            if is_eof {
                return Ok(out);
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn peek2(&self) -> Option<u8> {
        self.src.get(self.pos + 1).copied()
    }

    fn skip_whitespace(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn next_token(&mut self) -> Result<Token, LexError> {
        self.skip_whitespace();
        let start = self.pos;
        let Some(b) = self.peek() else {
            return Ok(Token {
                kind: TokenKind::Eof,
                start,
            });
        };

        // Single-char punctuation first.
        let single = match b {
            b'$' => Some(TokenKind::Dollar),
            b'.' => Some(TokenKind::Dot),
            b'[' => Some(TokenKind::LBracket),
            b']' => Some(TokenKind::RBracket),
            b'(' => Some(TokenKind::LParen),
            b')' => Some(TokenKind::RParen),
            b'@' => Some(TokenKind::At),
            b'*' => Some(TokenKind::Star),
            _ => None,
        };
        if let Some(kind) = single {
            self.pos += 1;
            return Ok(Token { kind, start });
        }

        // Two-char operators (and '?' vs '??').
        match (b, self.peek2()) {
            (b'=', Some(b'=')) => {
                self.pos += 2;
                return Ok(Token {
                    kind: TokenKind::Eq,
                    start,
                });
            }
            (b'!', Some(b'=')) => {
                self.pos += 2;
                return Ok(Token {
                    kind: TokenKind::NotEq,
                    start,
                });
            }
            (b'&', Some(b'&')) => {
                self.pos += 2;
                return Ok(Token {
                    kind: TokenKind::And,
                    start,
                });
            }
            (b'|', Some(b'|')) => {
                self.pos += 2;
                return Ok(Token {
                    kind: TokenKind::Or,
                    start,
                });
            }
            (b'?', Some(b'?')) => {
                self.pos += 2;
                return Ok(Token {
                    kind: TokenKind::Coalesce,
                    start,
                });
            }
            (b'<', Some(b'=')) => {
                self.pos += 2;
                return Ok(Token {
                    kind: TokenKind::Le,
                    start,
                });
            }
            (b'>', Some(b'=')) => {
                self.pos += 2;
                return Ok(Token {
                    kind: TokenKind::Ge,
                    start,
                });
            }
            (b'<', _) => {
                self.pos += 1;
                return Ok(Token {
                    kind: TokenKind::Lt,
                    start,
                });
            }
            (b'>', _) => {
                self.pos += 1;
                return Ok(Token {
                    kind: TokenKind::Gt,
                    start,
                });
            }
            (b'!', _) => {
                self.pos += 1;
                return Ok(Token {
                    kind: TokenKind::Not,
                    start,
                });
            }
            (b'?', _) => {
                self.pos += 1;
                return Ok(Token {
                    kind: TokenKind::Question,
                    start,
                });
            }
            _ => {}
        }

        // String literal: single-quoted. (JSONPath-style filter syntax uses
        // single quotes; double quotes would clash with the JSON that hosts
        // the DSL string itself.)
        if b == b'\'' {
            return self.lex_string(start);
        }

        // Number: digit or '-' followed by digit.
        if b.is_ascii_digit() || (b == b'-' && self.peek2().is_some_and(|c| c.is_ascii_digit())) {
            return self.lex_number(start);
        }

        // Identifier / keyword: letter, underscore, and then [A-Za-z0-9_-]
        // (hyphen allowed so hyphenated JSON keys such as
        // `release-groups`, common in third-party APIs, survive
        // verbatim).
        if b.is_ascii_alphabetic() || b == b'_' {
            return self.lex_ident(start);
        }

        Err(LexError {
            message: format!("unexpected byte {:?}", b as char),
            position: start,
        })
    }

    fn lex_string(&mut self, start: usize) -> Result<Token, LexError> {
        // Opening quote already at self.pos.
        self.pos += 1;
        let content_start = self.pos;
        loop {
            let Some(b) = self.peek() else {
                return Err(LexError {
                    message: "unterminated string literal".to_string(),
                    position: start,
                });
            };
            if b == b'\'' {
                let s = std::str::from_utf8(&self.src[content_start..self.pos])
                    .map_err(|e| LexError {
                        message: format!("invalid utf-8 in string: {e}"),
                        position: start,
                    })?
                    .to_string();
                self.pos += 1;
                return Ok(Token {
                    kind: TokenKind::String(s),
                    start,
                });
            }
            // There is no escape syntax: the first `'` after the opening
            // quote terminates the literal.
            self.pos += 1;
        }
    }

    fn lex_number(&mut self, start: usize) -> Result<Token, LexError> {
        let begin = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.peek() == Some(b'.') && self.peek2().is_some_and(|c| c.is_ascii_digit()) {
            self.pos += 1;
            while let Some(b) = self.peek() {
                if b.is_ascii_digit() {
                    self.pos += 1;
                } else {
                    break;
                }
            }
        }
        let raw = std::str::from_utf8(&self.src[begin..self.pos]).map_err(|e| LexError {
            message: format!("invalid utf-8 in number: {e}"),
            position: start,
        })?;
        let n: f64 = raw.parse().map_err(|e| LexError {
            message: format!("invalid number {raw:?}: {e}"),
            position: start,
        })?;
        Ok(Token {
            kind: TokenKind::Number(n),
            start,
        })
    }

    fn lex_ident(&mut self, start: usize) -> Result<Token, LexError> {
        let begin = self.pos;
        while let Some(b) = self.peek() {
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let raw = std::str::from_utf8(&self.src[begin..self.pos]).map_err(|e| LexError {
            message: format!("invalid utf-8 in identifier: {e}"),
            position: start,
        })?;
        let kind = match raw {
            "true" => TokenKind::True,
            "false" => TokenKind::False,
            "null" => TokenKind::Null,
            other => TokenKind::Ident(other.to_string()),
        };
        Ok(Token { kind, start })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str) -> Vec<TokenKind> {
        Lexer::new(src)
            .tokenize()
            .expect("lex ok")
            .into_iter()
            .map(|t| t.kind)
            .collect()
    }

    #[test]
    fn simple_path() {
        assert_eq!(
            kinds("$.foo.bar"),
            vec![
                TokenKind::Dollar,
                TokenKind::Dot,
                TokenKind::Ident("foo".into()),
                TokenKind::Dot,
                TokenKind::Ident("bar".into()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn rooted_path() {
        assert_eq!(
            kinds("$steps.search.results"),
            vec![
                TokenKind::Dollar,
                TokenKind::Ident("steps".into()),
                TokenKind::Dot,
                TokenKind::Ident("search".into()),
                TokenKind::Dot,
                TokenKind::Ident("results".into()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn index_and_wildcard() {
        assert_eq!(
            kinds("$.results[0].data[*]"),
            vec![
                TokenKind::Dollar,
                TokenKind::Dot,
                TokenKind::Ident("results".into()),
                TokenKind::LBracket,
                TokenKind::Number(0.0),
                TokenKind::RBracket,
                TokenKind::Dot,
                TokenKind::Ident("data".into()),
                TokenKind::LBracket,
                TokenKind::Star,
                TokenKind::RBracket,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn filter_expression() {
        assert_eq!(
            kinds("$.crew[?(@.job=='Director')].name"),
            vec![
                TokenKind::Dollar,
                TokenKind::Dot,
                TokenKind::Ident("crew".into()),
                TokenKind::LBracket,
                TokenKind::Question,
                TokenKind::LParen,
                TokenKind::At,
                TokenKind::Dot,
                TokenKind::Ident("job".into()),
                TokenKind::Eq,
                TokenKind::String("Director".into()),
                TokenKind::RParen,
                TokenKind::RBracket,
                TokenKind::Dot,
                TokenKind::Ident("name".into()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn expression_operators() {
        assert_eq!(
            kinds("a == b && c != d || !e ?? f"),
            vec![
                TokenKind::Ident("a".into()),
                TokenKind::Eq,
                TokenKind::Ident("b".into()),
                TokenKind::And,
                TokenKind::Ident("c".into()),
                TokenKind::NotEq,
                TokenKind::Ident("d".into()),
                TokenKind::Or,
                TokenKind::Not,
                TokenKind::Ident("e".into()),
                TokenKind::Coalesce,
                TokenKind::Ident("f".into()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn comparison_operators() {
        assert_eq!(
            kinds("a < b <= c > d >= e"),
            vec![
                TokenKind::Ident("a".into()),
                TokenKind::Lt,
                TokenKind::Ident("b".into()),
                TokenKind::Le,
                TokenKind::Ident("c".into()),
                TokenKind::Gt,
                TokenKind::Ident("d".into()),
                TokenKind::Ge,
                TokenKind::Ident("e".into()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn literals() {
        assert_eq!(
            kinds("true false null 42 -7 2.5 'hello world'"),
            vec![
                TokenKind::True,
                TokenKind::False,
                TokenKind::Null,
                TokenKind::Number(42.0),
                TokenKind::Number(-7.0),
                TokenKind::Number(2.5),
                TokenKind::String("hello world".into()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn hyphenated_ident() {
        // Hyphenated JSON keys such as `release-groups` are common in
        // third-party APIs.
        assert_eq!(
            kinds("$.release-groups"),
            vec![
                TokenKind::Dollar,
                TokenKind::Dot,
                TokenKind::Ident("release-groups".into()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn unterminated_string_errors() {
        let err = Lexer::new("'abc").tokenize().unwrap_err();
        assert!(err.message.contains("unterminated"));
    }

    #[test]
    fn unknown_byte_errors() {
        let err = Lexer::new("$#").tokenize().unwrap_err();
        assert!(err.message.contains("unexpected"));
    }
}
