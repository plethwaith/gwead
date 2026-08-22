//! Shared test helpers across the gwead integration test crates.
//!
//! Each integration test file at the root of `tests/` is its own crate
//! and includes this module via `mod common;`. Files inside subdirectories
//! of `tests/` aren't compiled as their own integration tests — they're
//! only reachable through `mod common;` from a top-level file.
//!
//! This module provides `script_runtime_mock`, a mock guest
//! script runtime used by tests that need a `script` step body without
//! shipping a real language runtime.

#![allow(dead_code)]

pub mod script_runtime_mock;
