# Contributing to Gwead

## Build and test

CI runs these commands, and a change should pass them locally first:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo test --locked --release
cargo +1.95 check --locked --all-targets
RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps
cargo audit
scripts/public-api.sh && git diff --exit-code -- public-api.txt
```

`cargo audit` is `cargo install cargo-audit --locked`. The minimum
supported Rust version is the `rust-version` in `Cargo.toml`.

## The public API

[`public-api.txt`](public-api.txt) is the listing of Gwead's public Rust
API, as produced by [cargo-public-api](https://crates.io/crates/cargo-public-api).
It changes only on purpose, in the same pull request as the code that
changes it, so a reviewer reads the API change as a diff of that file.
Items that are not in the listing are not part of the API, and stay
that way until someone needs them: publishing an item later is
additive, and removing one is breaking.

Regenerate it with:

```sh
scripts/public-api.sh
```

The script pins the nightly toolchain that rustdoc's JSON output needs
and the cargo-public-api version, installs the nightly if it is missing,
and prints the `cargo install` command if the cargo-public-api version is
wrong. It also fails if any line of the listing names an implementation
dependency (wasmtime, boon, regex, base64), or if the listing re-exports
a crate outside the vocabulary list (bytes, futures, indexmap,
serde_json, tokio, tokio_util). The `Public API`
CI job runs the script and fails if the committed file differs.

To decide whether a release is a patch or a minor release (Gwead is
0.x, so a breaking change is a minor release), diff the listing against
the last release tag:

```sh
git diff v<last release> -- public-api.txt
```

A removed or changed line is a minor release. An added line can be
breaking too: a new method without a default on a trait that embedders
implement (`SecretResolver`, `DispatchOrchestrator`), or a new `pub`
field on a struct that is not `#[non_exhaustive]` (such as
`ActionResult`). Read added lines for those before calling a release a
patch.

## Scheduled CI

CI also runs every Monday and on `workflow_dispatch`, so an advisory
published against an unchanged lockfile, or a lint a new stable
toolchain adds, turns the run red without a push. GitHub disables
scheduled workflows in a repository with no activity for 60 days.
