//! SPI (Service Provider Interface) infrastructure.
//!
//! An SPI is a JSON Schema contract naming the actions a plugin *role*
//! must provide. The kernel ships **zero** SPI definitions: role
//! contracts are application-shaped, so they belong to the embedder.
//! Embedders register them at startup through the same
//! [`Kernel::load_manifest`](crate::kernel::Kernel::load_manifest)
//! entry point plugins use, or directly via
//! [`Kernel::register_spi_from_json`](crate::kernel::Kernel::register_spi_from_json).
//!
//! ## When validation runs, and how strict it is
//!
//! Validation happens **once, at registration** — there is no runtime
//! re-validation. The strict/soft axis is about *what* is wrong, not
//! *when* it is found:
//!
//! - A plugin that claims a role the kernel has an SPI for, and
//!   violates that contract, is **rejected**.
//! - A plugin that claims a role the kernel has never heard of is
//!   **warned about and accepted** — the embedder may legitimately
//!   register the SPI later, or never.
//!
//! That second case makes load order matter, and it is not re-checked:
//! register the SPI *before* the plugins that claim its role, or a
//! contract violation downgrades from a rejection to a log line. See
//! [`validator`] for the implementation.
//!
//! ## No wire types here
//!
//! This module deliberately ships no request/response structs for any
//! particular role — no LLM chat or embedding types, for instance.
//! Nothing in the kernel would reference them, they would bake one
//! vendor's protocol shape into a crate whose whole pitch is that
//! app-shaped concepts live in the embedder, and as closed serde enums
//! over a fast-churning wire surface they would be a standing source
//! of breaking changes. Wire types belong to whoever authors the SPI
//! definition.

pub mod definition;
pub mod loader;
pub mod validator;
