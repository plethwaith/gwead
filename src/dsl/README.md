# Gwead Reference DSL

A tiny expression language used inside plugin manifests to reference values
in the execution context (`$input`, `$config`, `$trigger`, `$secrets`,
`$vars`, `$item`, `$steps.<id>`, and the implicit-source `$.foo`)
and to express boolean conditions (`ifs` branch `test` strings, `until`
predicates, `collect` accumulators, `??` coalesce, equality filters, …).

The implementation is a hand-rolled
lexer + recursive-descent parser + tree-walking evaluator in
[`lexer.rs`](lexer.rs) / [`parser.rs`](parser.rs) / [`eval.rs`](eval.rs).
The lexer, parser, and AST are `std`-only; the evaluator is built on
`serde_json`, since the values it walks are `serde_json::Value`.

## Why a custom DSL?

- One surface handles **all** path references across the kernel — result
  mapping, `for_each`, `extract`, `resultsPath`, `ifs` branch tests, and
  loop predicates.
- Rooted references make manifests self-describing: a path says where its
  data comes from without needing a separate `source:` field.
- Supply-chain discipline: no parsing dependencies. A full JSONPath library
  would be a much larger surface than the narrow syntactic subset
  manifests actually use.

## Grammar (ABNF)

This block is the canonical spec; the hand-written parser enforces it.

```abnf
; Two top-level productions: references (paths) and expressions.

reference       = "$" [ root-name ] *path-segment
expression      = coalesce-expr

; ---- reference ----

; All eight roots the parser accepts. `$` with no root name is the
; implicit-source form: it resolves against whatever the call site
; supplies as the source (e.g. a result-mapping `source:` field).
root-name       = "input"
                / "config"
                / "trigger"
                / "secrets"
                / "vars"
                / "item"
                / "steps" "." ident        ; step id follows immediately;
                                           ; registration holds step ids
                                           ; to this same `ident`

path-segment    = "." ident
                / "[" ( index / "*" / filter ) "]"

index           = 1*DIGIT                  ; non-negative integer; the parser
                                           ; also tolerates `[1.0]` (an
                                           ; integer-valued float) — tooling
                                           ; should emit plain digits
filter          = "?" "(" "@" "." ident "==" string-literal ")"

; ---- expression (precedence climb: lowest → highest) ----

coalesce-expr   = or-expr         *( "??" or-expr )
or-expr         = and-expr        *( "||" and-expr )
and-expr        = equality-expr   *( "&&" equality-expr )
equality-expr   = comparison-expr *( ( "==" / "!=" ) comparison-expr )
comparison-expr = unary-expr      *( ( "<" / "<=" / ">" / ">=" ) unary-expr )
unary-expr      = *"!" primary             ; `!!x` is legal
primary         = literal
                / reference
                / "(" expression ")"

literal         = "true" / "false" / "null" / number / string-literal
number          = [ "-" ] 1*DIGIT [ "." 1*DIGIT ]
; Single-quoted. The lexer accepts any UTF-8 except the closing quote;
; the byte ranges below describe the printable-ASCII subset that tooling
; can safely restrict itself to. There is no escape syntax, so a literal
; cannot contain a single quote.
string-literal  = "'" *( %x20-26 / %x28-7E ) "'"
ident           = ( ALPHA / "_" ) *( ALPHA / DIGIT / "_" / "-" )

; `true`, `false` and `null` are RESERVED: they always lex as literals,
; so `$.null` is a parse error rather than a field access.
reserved-word   = "true" / "false" / "null"

; Whitespace (space, tab, CR, LF) is insignificant between tokens and
; is not shown in the productions above.
WSP             = %x20 / %x09 / %x0D / %x0A

ALPHA           = %x41-5A / %x61-7A
DIGIT           = %x30-39
```

## Parse limits

Both fire **during parsing**, so a pathological expression is rejected
before it can overflow the stack:

- `MAX_EXPR_DEPTH = 128` — nesting depth. `!` and `(` share one budget
  rather than each getting 128 of their own.
- `MAX_EXPR_OPS = 256` — total *binary* operators (`??`, `||`, `&&`,
  `==`, `!=`, `<`, `<=`, `>`, `>=`) in one expression, which is what
  catches a flat `a ?? b ?? c ?? …` chain that never nests. `!` counts
  against depth instead. Resets per expression.

Both are enforced at **execution**, not at manifest registration: a
manifest carrying an over-limit expression registers successfully and
fails when the step runs.

Note also that inside a `{{…}}` template, *any* DSL parse error —
including tripping one of these caps — resolves to an empty string
rather than surfacing. `ifs` branch `test`, `until`, and `collect`
expressions do surface the error (the step fails with an execution
error).

A `null` result in a template also renders as an empty string; a string
that is exactly one `{{…}}` keeps the resolved value's JSON type (array,
object, number) instead of stringifying.

## Equality semantics

`==` compares across numeric types, so `1 == 1.0` is true. It does not
coerce between strings and numbers: `'404' == 404` is **false**.

## Semantics

### Reference evaluation

A reference selects zero or more values from the context. The result
is collapsed using the **unwrap-singleton rule**:

| Selection  | Result             |
|------------|--------------------|
| empty      | `null`             |
| 1 element  | the element itself |
| 2+ elements| `[e1, e2, …]`      |

This is the classic JSONPath extractor convention.

Segment semantics:

- `.field` on an object → the field value (or skip if absent).
- `.field` on anything else → skip.
- `[N]` on an array → element N (or skip if out of bounds).
- `[*]` on an array → flatten all elements into the selection.
- `[?(@.k=='v')]` on an array of objects → keep objects whose field `k`
  equals the string literal. Equality against a string literal only.

Root semantics:

| Root          | Resolves to |
|---------------|-------------|
| `$`           | *implicit source*. In `path:` positions: the `source:` step's result (or the first step's result when `source` is omitted). In `{{…}}` templates: the resolution bag (input fields at top level, plus `config`, `secrets`, `vars`, `steps`, `item`, `trigger`). In `ifs`/`until`/`collect` expressions there is no implicit source, so `$.x` is `null` — use a named root. |
| `$input`      | Action input arguments. |
| `$steps.<id>` | The `id` step's wrapped record: `{result, …metadata}`. Use `$steps.<id>.result.<path>` for the step's output; metadata such as `status` / `headers` (when the step type emits them) sits alongside `result`. |
| `$config`     | Plugin configuration. |
| `$secrets`    | Plugin secrets (kept separate from `$config`). |
| `$vars`       | Action-local variables written via `storeToVariable`. |
| `$item`       | Current iteration value inside a `for_each` / `repeat` body (`$item` alone is the whole value). |
| `$trigger`    | Triggering event payload (event-subscribed actions). |

Missing root, missing step, or missing field → `null`, silently. Parse
errors surface only from `ifs` `test` / `until` / `collect` expressions;
in `path:` positions a parse error resolves to `null`, and inside
`{{…}}` to an empty string.

### Expression evaluation

Boolean, equality, and comparison operators return `Value::Bool`. `??`
(null coalesce) returns its left operand unless it's `null`, in which
case it returns the right operand.

**Ordered comparisons** (`<`, `<=`, `>`, `>=`) are
**numeric-to-numeric only**: any other operand combination evaluates to
`false`. No string ordering, no implicit coercion of `"404"` to `404` —
the DSL's type-preservation rule means numbers genuinely flow as
numbers, so strict semantics are workable, and silent string-ordering
surprises are worse than no feature. Scope is predicates only — there
is **no arithmetic**; the moment a manifest needs `$x + 1`, that's a
`script` step.

**Truthiness** (for `!`, `&&`, `||`):

- `null`, `false`, `0`, `""`, `[]`, `{}` → falsy
- everything else → truthy

**Precedence**, lowest to highest:

```
??           (coalesce)
||           (or)
&&           (and)
==  !=       (equality)
<  <=  >  >= (comparison)
!            (unary not)
()           (grouping) — primary
```

## Examples

### Result mapping with rooted references

```json
{
  "actions": {
    "probe": {
      "steps": [
        {"id": "search", "type": "http_call", "params": {"url": "https://api/x"}}
      ],
      "resultMapping": {
        "echoed_query":  {"path": "$input.query"},
        "api_key":       {"path": "$config.apiKey"},
        "first_result":  {"path": "$steps.search.result.results[0].name"},
        "all_ids":       {"path": "$steps.search.result.results[*].id"}
      }
    }
  }
}
```

(`http_call` here is an embedder-provided step type, not one shipped
by the kernel.)

### Implicit-source form

```json
{
  "resultMapping": {
    "title":       {"path": "$.title", "source": "details"},
    "first_genre": {"path": "$.genres[0]", "source": "details"}
  }
}
```

The `source` field selects the step result used as the implicit `$`
root. The rooted equivalent — `$steps.details.result.title`,
`$steps.details.result.genres[0]` — is self-describing and needs no
`source` field.

### Filter

```json
{"path": "$.credits.crew[?(@.job=='Director')].name"}
```

### Expressions

```
$trigger.status == 'ok' && !$config.dry_run
$input.override ?? $config.default_value
```

Expressions are consumed by `ifs` branch `test` strings, `repeat`'s
`until` predicate, the `collect` accumulator on `for_each` / `repeat`,
and `{{…}}` template resolution.

## Choosing between the two forms

The implicit-source form `{path: "$.foo", source: "step_id"}` and the
rooted form `{path: "$steps.step_id.result.foo"}` are equivalent; both are
fully supported. Prefer the rooted form — it names its source inline
and reads clearer.
