# Gwead

**Gwead** (Welsh: *weave*) is a WebAssembly plugin microkernel from
[Plethwaith Labs](https://plethwaith.com): a data-driven engine that loads
plugin manifests and executes their actions, with plugin wasm modules and
script runtimes sandboxed under
[wasmtime](https://github.com/bytecodealliance/wasmtime).

The kernel is deliberately small and application-agnostic. It ships **zero**
plugin implementations and zero SPI definitions of its own — role contracts
are application-shaped, not engine-shaped. Embedding applications declare
their plugins, capabilities, and role contracts in manifests; Gwead resolves,
validates, schedules, and executes them. Dependencies flow strictly inward:
embedders depend on Gwead, never the reverse.

## Status

**0.1.0 — first release.** The manifest format is Gwead's public API; its
contract is the pair of meta-schemas in [`schemas/`](schemas/) (JSON Schema
Draft 2020-12), and every manifest loaded from JSON (`Kernel::load_manifest`,
`register_plugin_from_json`, `register_spi_from_json`) is validated against
them at load, on the raw JSON before deserialization. Manifests may declare
`"formatVersion": 1` (optional; absent means 1). A future revision of the
format gets a new `formatVersion`, so a manifest written for one is rejected
up front with a clear schema error by a kernel that does not speak it, never
misparsed.

The kernel does not validate step or action data against the schemas a
manifest declares at execution time. Those schemas are stored and available
to embedders; enforcing them is the embedder's choice.

The crate is published as [`gwead` on crates.io](https://crates.io/crates/gwead);
this repository is its source.

## Documentation

Crate-level architecture documentation lives in [`src/lib.rs`](src/lib.rs).
See also [`src/dsl/README.md`](src/dsl/README.md) for the expression DSL and
[`src/kernel/STREAMS_ABI.md`](src/kernel/STREAMS_ABI.md) for the streams ABI
contract between kernel and guest runtimes.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
