//! The name grammar, enforced where names actually enter the kernel.
//!
//! A plugin's name is the registry key and appears verbatim inside
//! permission strings. If the only constraint were "non-empty", two
//! ambiguities would be live in the grammar:
//!
//! - A plugin named `*` would be indistinguishable from the
//!   `invoke:plugin:*` wildcard: it could not be granted individually,
//!   and a grant meant for that one plugin would read as "all of them".
//! - A name could contain `:`, the permission-string separator, so
//!   `invoke:plugin:a:b` would have two readings and the parser would
//!   silently pick one.
//!
//! It also leaves `/` free to mean something. `/` separates a plugin's
//! embedder-supplied namespace from its manifest-declared local name,
//! and the root namespace is spelled as the empty string — so a
//! root-namespace identity is the bare local name. That is only
//! unambiguous while no manifest-declared name can contain `/`;
//! otherwise `foo/bar` in the root namespace and `bar` in namespace
//! `foo` are two spellings of one registry key.
//!
//! `gwead::kernel::identity` unit-tests the grammar itself. These tests
//! pin the part that matters operationally: that a bad name is refused
//! at the boundary rather than accepted and quietly mis-keyed.

use gwead::kernel::types::PluginManifest;
use gwead::kernel::{Kernel, KernelConfig};
use serde_json::json;

fn kernel() -> Kernel {
    Kernel::boot(KernelConfig::default()).expect("boot")
}

/// A minimal loadable plugin under an arbitrary name.
fn plugin(name: &str) -> String {
    json!({
        "name": name,
        "actions": { "go": { "steps": [{"id": "s", "type": "return", "params": {"value": 1}}] } },
    })
    .to_string()
}

#[test]
fn an_ordinary_name_still_registers() {
    // The grammar is a superset of every name the kernel's own
    // manifests and fixtures use; if this fails the charset is too
    // tight, not the fixture wrong.
    // `gwead_intrinsics` is deliberately absent: the kernel registers
    // it at boot, so a second registration fails on the duplicate-name
    // rule and would pass this test for the wrong reason.
    for name in ["vault", "my-plugin", "p9", "_internal", "A1"] {
        let mut k = kernel();
        k.register_plugin_from_json(&plugin(name))
            .unwrap_or_else(|e| panic!("'{name}' should register: {e}"));
    }
}

/// The wildcard ambiguity, at the boundary. Registering this plugin
/// would create a registry key that `invoke:plugin:*` cannot be
/// distinguished from.
#[test]
fn a_plugin_named_star_is_rejected() {
    let err = kernel()
        .register_plugin_from_json(&plugin("*"))
        .expect_err("a plugin named '*' collides with the invoke wildcard");
    assert!(
        err.to_string().contains('*'),
        "the error should quote the offending name: {err}"
    );
}

/// The separator ambiguity, at the boundary.
#[test]
fn a_plugin_name_containing_a_colon_is_rejected() {
    kernel()
        .register_plugin_from_json(&plugin("a:b"))
        .expect_err("':' is the permission-string separator");
}

/// The reservation, on the manifest path.
///
/// Note which layer answers: the meta-schema matches `name` against the
/// identifier pattern and rejects before the kernel's own validator
/// runs, so the message is the schema's `does not match pattern` rather
/// than the kernel's explanation that the syntax is reserved. Both
/// refuse it, which is what this test pins. The explanatory wording is
/// pinned separately in
/// `the_kernel_validator_explains_the_reservation`, on an entry point
/// the schema does not cover.
#[test]
fn a_qualified_plugin_name_is_rejected() {
    let err = kernel()
        .register_plugin_from_json(&plugin("tenant42/billing"))
        .expect_err("qualified names are reserved");
    assert!(
        err.to_string().contains("tenant42/billing"),
        "the error should quote the offending name: {err}"
    );
}

/// The kernel's own name validator, on an entry point that takes the
/// role as a parameter rather than reading it from a schema-validated
/// document — so this is the message a caller gets, unmediated.
///
/// It has to say *reserved*. An author who reads the rejection as
/// "forbidden forever" will work around it by flattening the name to
/// `tenant42_billing`, which recreates by hand exactly the collision
/// the namespace exists to prevent.
#[test]
fn the_kernel_validator_explains_the_reservation() {
    let def = json!({
        "name": "ROLE",
        "actions": { "do_it": { "input": {}, "output": {} } },
    })
    .to_string();
    let err = kernel()
        .register_spi_from_json("tenant42/ROLE", &def)
        .expect_err("qualified role names are reserved");
    let msg = err.to_string();
    assert!(
        msg.contains("reserved"),
        "the rejection must explain the syntax is reserved, not merely invalid: {msg}"
    );
    assert!(
        msg.contains("namespace"),
        "and it must point at what will eventually give the syntax meaning: {msg}"
    );
}

#[test]
fn an_empty_plugin_name_is_rejected() {
    kernel()
        .register_plugin_from_json(&plugin(""))
        .expect_err("the registry key cannot be empty");
}

/// `register_plugin` takes an already-parsed [`PluginManifest`], so the
/// meta-schema never runs on it. That makes the kernel's own name
/// validator the only gate on this path — the one an embedder
/// constructing manifests programmatically actually hits.
///
/// Without this test the validator would be dead code for every JSON
/// manifest (the schema rejects first) and untested for the one path
/// where it is load-bearing.
#[test]
fn the_struct_entry_point_validates_names_without_the_schema() {
    let manifest: PluginManifest = serde_json::from_str(&plugin("fine_for_now")).expect("parses");

    // Take a manifest that parsed cleanly and give it a name no
    // schema pass will ever see.
    let mut hostile = manifest.clone();
    hostile.name = "tenant42/billing".to_string();
    let err = kernel()
        .register_plugin(hostile)
        .expect_err("the struct entry point must apply the same grammar");
    let msg = err.to_string();
    assert!(
        msg.contains("reserved"),
        "on this path the kernel validator speaks, so the message must \
         explain the reservation: {msg}"
    );

    let mut starred = manifest.clone();
    starred.name = "*".to_string();
    kernel()
        .register_plugin(starred)
        .expect_err("a plugin named '*' collides with the invoke wildcard");

    // The unmodified manifest still registers, so the rejections above
    // are the name and not something else about the fixture.
    kernel()
        .register_plugin(manifest)
        .expect("baseline registers");
}

/// Roles are the SPI dispatch key and appear in `invoke:role:<name>`,
/// so they obey the same grammar as plugin names. A role slipping
/// through would be a grant that matches nothing.
#[test]
fn a_malformed_role_is_rejected() {
    let manifest = json!({
        "name": "p",
        "roles": ["BAD ROLE"],
        "actions": { "go": { "steps": [{"id": "s", "type": "return", "params": {"value": 1}}] } },
    })
    .to_string();
    let err = kernel()
        .register_plugin_from_json(&manifest)
        .expect_err("a role name with a space is not addressable in a permission string");
    assert!(
        err.to_string().contains("roles"),
        "the error should point at the field so the author knows which name to fix: {err}"
    );
}

/// The same rule on the SPI registration entry point, which takes the
/// role as a parameter rather than reading it from a manifest.
#[test]
fn a_malformed_spi_role_is_rejected_at_registration() {
    let def = json!({
        "name": "BAD ROLE",
        "actions": { "do_it": { "input": {}, "output": {} } },
    })
    .to_string();
    kernel()
        .register_spi_from_json("BAD ROLE", &def)
        .expect_err("an SPI role name obeys the identifier grammar");
}

/// Step type names become wasm linker import names and appear in
/// `step_type:<name>` / `provide:step_type:<type>` grants.
#[test]
fn a_malformed_step_type_def_name_is_rejected() {
    let manifest = json!({
        "name": "p",
        "stepTypeDefs": [{"name": "bad:type"}],
    })
    .to_string();
    kernel()
        .register_plugin_from_json(&manifest)
        .expect_err("a step type name containing the permission separator is ambiguous");
}

/// A permission may only name something the registry can actually hold.
/// Without the grammar, `invoke:plugin:acme.vault` would parse cleanly
/// and then match nothing, forever, silently — the same never-matching
/// grant the glob and dot-free-category reservations exist to prevent.
///
/// Both the meta-schema and `parse_permission` refuse it; this
/// pins the outcome at the boundary, and
/// `permission_schema_and_parser_agree` pins that the two layers draw
/// the line in the same place.
#[test]
fn a_grant_naming_an_ungrammatical_plugin_is_rejected() {
    let manifest = json!({
        "name": "caller",
        "permissions": ["invoke:plugin:acme.vault"],
        "actions": { "go": { "steps": [{"id": "s", "type": "return", "params": {"value": 1}}] } },
    })
    .to_string();
    kernel()
        .register_plugin_from_json(&manifest)
        .expect_err("a grant that can never match must be refused at load");
}

/// The wildcard itself is a grammar shape, not a name, so it parses —
/// this is the check that the grammar tightened the right thing.
#[test]
fn the_invoke_wildcard_still_parses() {
    let manifest = json!({
        "name": "caller",
        "permissions": ["invoke:plugin:*", "invoke:role:*"],
        "actions": { "go": { "steps": [{"id": "s", "type": "return", "params": {"value": 1}}] } },
    })
    .to_string();
    kernel()
        .register_plugin_from_json(&manifest)
        .expect("'*' alone is the blessed wildcard shape");
}

/// A qualified *reference* is reserved on the same terms as a qualified
/// declaration. Accepting it as a literal would mean deployed
/// grants silently change target the day the syntax is honoured.
#[test]
fn a_qualified_grant_target_is_rejected_as_reserved() {
    let manifest = json!({
        "name": "caller",
        "permissions": ["invoke:plugin:tenant42/billing"],
        "actions": { "go": { "steps": [{"id": "s", "type": "return", "params": {"value": 1}}] } },
    })
    .to_string();
    let err = kernel()
        .register_plugin_from_json(&manifest)
        .expect_err("qualified grant targets are reserved");
    assert!(
        err.to_string().contains("tenant42/billing"),
        "the error should quote the offending grant: {err}"
    );
}

/// Mid-string wildcards are rejected. The meta-schema catches this one
/// before `parse_permission` runs, so the message here is the schema's
/// — the parser's own glob-reservation message is pinned by
/// `permission_schema_and_parser_agree`, which calls the parser
/// directly. Both layers must refuse it; only their wording differs.
#[test]
fn a_mid_string_wildcard_is_still_rejected() {
    let manifest = json!({
        "name": "caller",
        "permissions": ["invoke:plugin:ff*"],
        "actions": { "go": { "steps": [{"id": "s", "type": "return", "params": {"value": 1}}] } },
    })
    .to_string();
    kernel()
        .register_plugin_from_json(&manifest)
        .expect_err("mid-string wildcards are reserved for a future glob syntax");
}

// ── Step ids ─────────────────────────────────────────────────────────

/// A manifest with a step id outside the grammar, at the given nesting.
fn plugin_with_step_id(id: &str, nested: bool) -> String {
    let step = json!({"id": id, "type": "let", "params": {"value": 1}});
    let steps = if nested {
        json!([{"id": "outer", "type": "try", "params": {"try": [step], "catch": []}}])
    } else {
        json!([step])
    };
    json!({ "name": "p", "actions": { "go": { "steps": steps } } }).to_string()
}

/// A step id is a reference target (`$steps.<id>`), so it is held to
/// the DSL's `ident` — the name grammar minus a leading digit. An id
/// outside it would load and then be unreferenceable — silently — which
/// is the failure the grammar exists to prevent. Checked at both
/// nesting levels and on both entry points.
#[test]
fn a_step_id_outside_the_grammar_is_rejected() {
    for (id, nested) in [
        ("my step", false),
        ("a.b", false),
        ("x:y", true),
        ("", true),
        ("9x", false),
    ] {
        let err = match kernel().register_plugin_from_json(&plugin_with_step_id(id, nested)) {
            Ok(_) => panic!("step id {id:?} (nested={nested}) should be rejected"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("id"),
            "error should name the step id rule: {err}"
        );
    }
    // The struct path skips the meta-schema, so the walker must refuse
    // it on its own.
    let m: gwead::kernel::types::PluginManifest =
        serde_json::from_str(&plugin_with_step_id("my step", true)).expect("deserialises");
    let err = kernel()
        .register_plugin(m)
        .expect_err("struct-path registration must apply the step id grammar");
    assert!(err.to_string().contains("step id"), "{err}");
}

/// A step id is the DSL's `ident`, not the wider name grammar: a
/// plugin may be called `9p`, but a step may not be called `9x`,
/// because `$steps.9x` does not parse and the step could never be
/// referenced. The struct path must say so in its own words.
#[test]
fn a_digit_leading_step_id_is_rejected_with_the_dsl_reason() {
    let m: PluginManifest =
        serde_json::from_str(&plugin_with_step_id("9x", false)).expect("deserialises");
    let err = kernel()
        .register_plugin(m)
        .expect_err("a digit-leading step id cannot be referenced");
    let msg = err.to_string();
    assert!(
        msg.contains("starts with a digit") && msg.contains("$steps.9x"),
        "error should explain the DSL constraint: {msg}"
    );
}

/// Every id the name grammar admits *except* a leading digit is a
/// valid step id, and the ids the tree's own fixtures use all are.
#[test]
fn ordinary_step_ids_register() {
    for id in ["s", "fetch-data", "_internal", "p9", "A1", "step_2"] {
        kernel()
            .register_plugin_from_json(&plugin_with_step_id(id, true))
            .unwrap_or_else(|e| panic!("step id {id:?} should register: {e}"));
    }
}
