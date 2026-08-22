//! Registration either happens completely or not at all.
//!
//! `register_plugin` runs many validations, and if it began mutating
//! kernel state partway through while a later validation could still
//! return `Err` — with no rollback — the result would be a **ghost
//! plugin**: absent from the registry and holding no `ManifestHandle`,
//! so nothing could ever unload it, yet owning its step-type names
//! against all comers, with its actions still executing and no
//! permission set ever stored. Retrying under the same name would then
//! be rejected by the ghost's own leftovers.
//!
//! It would also defeat `reload_manifest`'s rollback: re-registering the
//! retained old manifest would collide with the failed attempt's
//! leftovers and land in the "kernel state is inconsistent" terminal
//! branch, destroying a healthy plugin.
//!
//! Every test here drives a registration to failure at a different
//! point and then asserts the kernel is indistinguishable from one
//! that never saw the manifest.

use gwead::kernel::{Kernel, KernelConfig};
use serde_json::json;

fn boot() -> Kernel {
    Kernel::boot(KernelConfig::default()).expect("kernel boots")
}

/// A manifest that defines `step_type` and then fails validation
/// *after* the defs would have been committed, by referencing a native
/// implRef no crate submitted.
fn fails_after_defs(name: &str, step_type: &str) -> String {
    let step_type = format!("{name}.{step_type}");
    json!({
        "name": name,
        "version": "1.0.0",
        "stepTypeDefs": [{"name": step_type}],
        "stepTypeImpls": [
            {"stepType": step_type, "kind": "native",
             "implRef": "nobody.submitted.this"}
        ],
        "actions": {"go": {"steps": [
            {"id": "s", "type": "let", "params": {"name": "v", "value": 1}}
        ]}},
    })
    .to_string()
}

/// A well-formed manifest claiming the same step type name.
fn healthy(name: &str, step_type: &str) -> String {
    let step_type = format!("{name}.{step_type}");
    json!({
        "name": name,
        "version": "1.0.0",
        "stepTypeDefs": [{"name": step_type}],
        "actions": {"go": {"steps": [
            {"id": "s", "type": "let", "params": {"name": "v", "value": 1}}
        ]}},
    })
    .to_string()
}

#[test]
fn a_failed_registration_leaves_no_step_type_def_behind() {
    let mut k = boot();
    k.register_plugin_from_json(&fails_after_defs("ghost", "ghost_x"))
        .expect_err("the unknown implRef must reject the manifest");

    assert!(
        k.registry().get_step_type_def("ghost.ghost_x").is_none(),
        "a rejected manifest must not leave its step type def claimed"
    );
}

/// Retrying under the same name with a corrected manifest must work.
/// If the failed attempt left its own defs behind, the retry would be
/// rejected by them, and a transient authoring mistake would be
/// unrecoverable without restarting the kernel.
#[test]
fn a_failed_registration_can_be_retried_under_the_same_name() {
    let mut k = boot();
    k.register_plugin_from_json(&fails_after_defs("retry_me", "retry_x"))
        .expect_err("rejected");

    k.register_plugin_from_json(&healthy("retry_me", "retry_x"))
        .expect("a corrected manifest under the same name registers");
}

/// A ghost's actions would stay executable. Nothing should be reachable
/// under a name that failed to register.
#[test]
fn a_failed_registration_leaves_no_executable_actions() {
    let mut k = boot();
    k.register_plugin_from_json(&fails_after_defs("ghost", "ghost_y"))
        .expect_err("rejected");

    assert!(
        k.registry().get_action("ghost", "go").is_none(),
        "a rejected manifest must not leave live actions behind"
    );
    assert!(
        k.registry().get_manifest("ghost").is_none(),
        "and must not appear in the registry at all"
    );
}

/// Two `stepTypeDefs` entries with the same name inside one manifest
/// must be caught up front, not mid-commit after the first has landed.
#[test]
fn duplicate_defs_within_one_manifest_are_rejected_cleanly() {
    let mut k = boot();
    let m = json!({
        "name": "dupdef",
        "version": "1.0.0",
        "stepTypeDefs": [{"name": "twice"}, {"name": "twice"}],
        "actions": {"go": {"steps": []}},
    })
    .to_string();
    let err = k
        .register_plugin_from_json(&m)
        .expect_err("a duplicate def inside one manifest is a manifest bug");
    assert!(
        err.to_string().contains("twice"),
        "the error names the duplicated def: {err}"
    );
    assert!(k.registry().get_step_type_def("twice").is_none());
}

/// The reserved-`result` metadataSchema check must run before any def
/// is committed.
#[test]
fn a_reserved_metadata_key_rejects_without_committing_earlier_defs() {
    let mut k = boot();
    let m = json!({
        "name": "reserved",
        "version": "1.0.0",
        "stepTypeDefs": [
            {"name": "first_def"},
            {"name": "bad_def",
             "metadataSchema": {"properties": {"result": {"type": "string"}}}}
        ],
        "actions": {"go": {"steps": []}},
    })
    .to_string();
    k.register_plugin_from_json(&m)
        .expect_err("the reserved `result` key rejects the manifest");

    assert!(
        k.registry().get_step_type_def("first_def").is_none(),
        "the def declared BEFORE the bad one must not survive the rejection"
    );
}

/// `reload_manifest`'s rollback re-registers the retained old manifest.
/// If a failed new registration leaves debris, that rollback collides
/// with it and the kernel loses a plugin that was working fine.
#[test]
fn a_failed_reload_leaves_the_original_plugin_intact() {
    let mut k = boot();
    let handle = k
        .load_manifest(&healthy("live", "live_x"))
        .register()
        .expect("original loads");

    k.reload_manifest(handle, &fails_after_defs("live", "live_x"))
        .expect_err("the replacement manifest is invalid");

    // The original must still be there and still work.
    assert!(
        k.registry().get_manifest("live").is_some(),
        "a failed reload must not destroy the healthy plugin"
    );
    assert!(
        k.registry().get_action("live", "go").is_some(),
        "the original's actions survive"
    );
    assert!(
        k.registry().get_step_type_def("live.live_x").is_some(),
        "and it still owns its step type def"
    );
}
