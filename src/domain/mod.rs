//! Engine-substrate utilities that don't fit anywhere else.
//!
//! Only `resolve` lives here — the `{{var}}` template resolver every
//! step type uses for param interpolation. Manifest types
//! (`PluginManifest`, `AuthSpec`, `ConfigSchema`, …) live in
//! [`crate::kernel::types`]; app-shaped domain types belong to the
//! embedder's domain layer, not this crate.
//!
//! The resolver delegates to the DSL (`src/dsl/`) — the `{{...}}`
//! interior speaks the same expression language DSL clauses do.

pub mod resolve;
