//! Who may supply the implementation behind a step type slot.
//!
//! Claiming a `(step_type, matches)` slot is not the same as using a
//! step type: it is *becoming* the code every other plugin's steps of
//! that type run inside. Supplying `(script, "lua")` means supplying
//! the interpreter that executes every plugin's Lua script step, and
//! `step_script` hands that interpreter the calling plugin's
//! resolution context plus a parent context naming it.
//!
//! If the slot were first-come, first-served with no ownership rule, a
//! manifest declaring no permissions and no actions could take
//! `(script, "lua")` and read every other plugin's secrets; the only
//! visible symptom would be that a *legitimate* runtime loading
//! afterwards failed with an error blaming itself.
//!
//! The rule these tests pin: you may implement a step type you define
//! yourself; otherwise you need both a
//! `provide:step_type:<type>[:<selector>]` declaration in the manifest
//! and a place in the embedder's `trusted_step_type_providers`.

use gwead::kernel::{Kernel, KernelConfig, KernelError};
use serde_json::json;

/// Base64 of a minimal wasm module — the claim is rejected before the
/// bytes matter, so any valid module does.
fn runtime_module_b64() -> String {
    use base64::Engine as _;
    let wasm = wat::parse_str(
        r#"(module
             (memory (export "memory") 1)
             (func (export "alloc") (param i32) (result i32) i32.const 0)
             (func (export "execute") (param i32 i32 i32 i32) (result i32) i32.const 1))"#,
    )
    .expect("wat parses");
    base64::engine::general_purpose::STANDARD.encode(&wasm)
}

/// A manifest claiming `(script, "lua")`, optionally declaring the
/// permission that says so.
fn lua_runtime_manifest(name: &str, declares_permission: bool) -> String {
    let mut m = json!({
        "name": name,
        "version": "0.0.0-test",
        "description": "claims the lua language slot",
        "wasmModules": { "runtime": { "base64": runtime_module_b64() } },
        "stepTypeImpls": [
            {"stepType": "script", "matches": "lua", "wasmModule": "runtime"}
        ],
    });
    if declares_permission {
        m["permissions"] = json!(["provide:step_type:script:lua"]);
    }
    m.to_string()
}

#[test]
fn claiming_a_kernel_step_type_without_declaring_it_is_rejected() {
    let mut k = Kernel::boot(KernelConfig::default().trusting_step_type_provider("squatter"))
        .expect("boot");
    let err = k
        .register_plugin_from_json(&lua_runtime_manifest("squatter", false))
        .expect_err("an undeclared claim on a kernel-defined step type must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("provide:step_type:script:lua"),
        "the error must name the permission to add: {msg}"
    );
}

#[test]
fn claiming_a_kernel_step_type_without_embedder_trust_is_rejected() {
    // Declared but not trusted: the manifest asked, the embedder did
    // not agree. This is the half that actually enforces — a manifest
    // is self-describing, so the declaration alone proves only intent.
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    let err = k
        .register_plugin_from_json(&lua_runtime_manifest("squatter", true))
        .expect_err("a declared claim from an untrusted plugin must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("trusted_step_type_providers"),
        "the error must point at the embedder's allowlist: {msg}"
    );
}

/// The two failure modes must be distinguishable. "Did not ask" is a
/// manifest bug the plugin author fixes; "asked and is not trusted" is
/// a deployment decision the operator makes. An operator debugging a
/// plugin that won't load needs to know which one they have.
#[test]
fn the_two_rejections_say_different_things() {
    let mut untrusted = Kernel::boot(KernelConfig::default()).expect("boot");
    let undeclared = untrusted
        .register_plugin_from_json(&lua_runtime_manifest("p", false))
        .expect_err("rejected")
        .to_string();

    let mut trusted =
        Kernel::boot(KernelConfig::default().trusting_step_type_provider("p")).expect("boot");
    let untrusted_msg = Kernel::boot(KernelConfig::default())
        .expect("boot")
        .register_plugin_from_json(&lua_runtime_manifest("p", true))
        .expect_err("rejected")
        .to_string();

    assert_ne!(undeclared, untrusted_msg);
    assert!(!undeclared.contains("trusted_step_type_providers"));
    assert!(!untrusted_msg.contains("does not declare the matching permission"));

    // And with both halves satisfied it registers.
    trusted
        .register_plugin_from_json(&lua_runtime_manifest("p", true))
        .expect("declared + trusted registers");
}

#[test]
fn declared_and_trusted_claim_registers() {
    let mut k =
        Kernel::boot(KernelConfig::default().trusting_step_type_provider("lua_rt")).expect("boot");
    k.register_plugin_from_json(&lua_runtime_manifest("lua_rt", true))
        .expect("a declared claim from a trusted plugin registers");
}

/// A plugin implementing a step type it defined itself needs neither
/// half. Your own extension point is yours — and this is also what
/// lets the kernel's own `intrinsics.json` claim its slots without a
/// special case in the rule.
#[test]
fn implementing_your_own_step_type_needs_no_permission_or_trust() {
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    k.register_plugin_from_json(
        &json!({
            "name": "self_owner",
            "version": "1.0.0",
            "permissions": [],
            "stepTypeDefs": [{"name": "self_owner.my_own_step"}],
            "stepTypeImpls": [
                {"stepType": "self_owner.my_own_step", "matches": "v1",
                 "wasmModule": "runtime"}
            ],
            "wasmModules": { "runtime": { "base64": runtime_module_b64() } },
        })
        .to_string(),
    )
    .expect("a plugin may implement a step type it defines");
}

/// The claim is checked against the exact slot, so a grant for one
/// selector does not authorise another. Without this a runtime trusted
/// for `(script, "lua")` could quietly also take `(script, "python")`.
#[test]
fn a_provide_grant_does_not_extend_to_other_selectors() {
    let mut k =
        Kernel::boot(KernelConfig::default().trusting_step_type_provider("lua_rt")).expect("boot");
    let err = k
        .register_plugin_from_json(
            &json!({
                "name": "lua_rt",
                "version": "0.0.0-test",
                "description": "declares lua, claims python",
                "permissions": ["provide:step_type:script:lua"],
                "wasmModules": { "runtime": { "base64": runtime_module_b64() } },
                "stepTypeImpls": [
                    {"stepType": "script", "matches": "python", "wasmModule": "runtime"}
                ],
            })
            .to_string(),
        )
        .expect_err("a lua grant must not authorise the python slot");
    assert!(
        err.to_string().contains("provide:step_type:script:python"),
        "the error should name the slot actually claimed: {err}"
    );
}

/// Registration is transactional, so a rejected claim must leave the
/// slot free for the plugin that should have had it. Otherwise a
/// failed registration would leave a "ghost": no registry entry and no
/// handle, so it could never be unloaded, yet it would own the name
/// against all comers.
#[test]
fn a_rejected_claim_leaves_the_slot_claimable() {
    let mut k =
        Kernel::boot(KernelConfig::default().trusting_step_type_provider("lua_rt")).expect("boot");
    k.register_plugin_from_json(&lua_runtime_manifest("squatter", false))
        .expect_err("squatter is rejected");
    k.register_plugin_from_json(&lua_runtime_manifest("lua_rt", true))
        .expect("the legitimate runtime still gets the slot");
}

/// A `KernelError` an embedder can branch on, not just a string.
#[test]
fn claim_rejection_is_a_validation_error() {
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    match k.register_plugin_from_json(&lua_runtime_manifest("p", true)) {
        Err(KernelError::Validation(_)) => {}
        other => panic!("expected Validation, got {other:?}"),
    }
}
