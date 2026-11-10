#!/usr/bin/env bash
# Regenerates public-api.txt, the reviewed listing of Gwead's public
# API, and fails if the listing names wasmtime, boon, regex or base64,
# or has a `pub use gwead::` line naming anything other than the six
# vocabulary crates.
# CI runs this, then fails on any difference from the committed file.
set -euo pipefail

# rustdoc's JSON output is nightly-only; both pins keep the listing
# reproducible. Move them together: each cargo-public-api release
# reads a range of nightlies. The cargo-public-api version is also
# spelled in the public-api job of .github/workflows/ci.yml.
NIGHTLY=nightly-2026-11-01
CARGO_PUBLIC_API=0.52.0

cd "$(dirname "$0")/.."
rustup toolchain install "$NIGHTLY" --profile minimal --no-self-update >&2
found=$(cargo public-api --version 2>/dev/null || true)
if [ "$found" != "cargo-public-api $CARGO_PUBLIC_API" ]; then
    echo "need cargo-public-api $CARGO_PUBLIC_API, found '${found:-none}':" >&2
    echo "  cargo install cargo-public-api --version $CARGO_PUBLIC_API --locked" >&2
    exit 1
fi
cargo +"$NIGHTLY" public-api --omit blanket-impls > public-api.txt
if grep -nE '(^|[^A-Za-z0-9_])(wasmtime[a-z_]*|boon|regex[a-z_]*|base64)(::|$)' public-api.txt; then
    echo "the public API names wasmtime, boon, regex or base64 (above)" >&2
    exit 1
fi
if grep -nE '^pub use gwead::' public-api.txt \
    | grep -vE ':pub use gwead::(bytes|futures|indexmap|serde_json|tokio|tokio_util)$'; then
    echo "the public API re-exports a crate outside the vocabulary list (above)" >&2
    exit 1
fi
