//! Integration tests for `Kernel::unload_manifest` / `reload_manifest`.
//!
//! Covers:
//! - hot-reload of a plugin: action invocable, reload changes behaviour,
//!   action invocable again with new behaviour
//! - unload of an SPI def with no dependents: succeeds
//! - unload of an SPI def with a dependent plugin: rejected, dependent
//!   named in error, SPI stays loaded and validatable
//! - reload-failure rollback: a malformed new manifest leaves the old
//!   manifest registered and invocable; the handle stays valid
//! - unknown-handle paths report `NotFound`
//!
//! The actions used here lean on the `throw_error` intrinsic so the
//! tests are fully self-contained — no script runtime mock, no
//! capability step types, no plugin crate deps.

use std::future::Future;
use std::pin::Pin;

use gwead::kernel::host_api::{PluginExecution, StepError, StepOutput};
use gwead::kernel::{Kernel, KernelConfig, KernelError, ManifestKind};
use serde_json::Value;

fn boot() -> Kernel {
    Kernel::boot(KernelConfig::default()).expect("kernel boots")
}

/// Manifest whose single action throws a `PluginError` with the given code.
fn thrower_manifest(plugin_name: &str, code: &str) -> String {
    serde_json::json!({
        "name": plugin_name,
        "version": "0.1.0",
        "actions": {
            "fire": {
                "steps": [
                    {"id": "boom", "type": "throw_error", "params": {"code": code, "message": format!("from {plugin_name} v={code}")}}
                ]
            }
        }
    })
    .to_string()
}

#[tokio::test]
async fn hot_reload_swaps_action_behaviour() {
    let mut k = boot();

    let handle = k
        .load_manifest(&thrower_manifest("hot", "BEFORE"))
        .register()
        .expect("v1 loads");

    let v1_err = k
        .execute("hot", "fire", serde_json::Value::Null)
        .with_config(&serde_json::Value::Null)
        .run()
        .await
        .expect_err("throw_error always errors");
    match v1_err {
        KernelError::PluginError { code, .. } => assert_eq!(code, "BEFORE"),
        other => panic!("expected PluginError(BEFORE), got {other:?}"),
    }

    k.reload_manifest(handle, &thrower_manifest("hot", "AFTER"))
        .expect("reload succeeds");

    let v2_err = k
        .execute("hot", "fire", serde_json::Value::Null)
        .with_config(&serde_json::Value::Null)
        .run()
        .await
        .expect_err("throw_error always errors");
    match v2_err {
        KernelError::PluginError { code, .. } => assert_eq!(code, "AFTER"),
        other => panic!("expected PluginError(AFTER), got {other:?}"),
    }
}

/// Test-only native step body: returns a constant.
fn const_step<'a>(
    _ex: &'a mut (dyn PluginExecution + Send),
    _params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move { Ok(StepOutput::from(serde_json::json!(7))) })
}

/// Several fixture plugins here bind the *same* body, so at most one of
/// them could ever own it under the implRef ownership rule. That makes
/// this genuine cross-plugin binding rather than a naming accident, and
/// it takes the two-key path: each manifest declares
/// `bind:native_impl:test.lifecycle.const` (see `native_step_manifest`)
/// and the embedder authorises each binder here.
fn boot_with_const_impl() -> Kernel {
    let mut config = KernelConfig::default();
    config
        .native_step_impls
        .insert("test.lifecycle.const", const_step)
        .expect("fresh table has no collision");
    for binder in ["hot_native", "owner_a", "owner_b"] {
        config = config.allowing_native_impl_binding(binder, "test.lifecycle.const");
    }
    Kernel::boot(config).expect("kernel boots")
}

/// Manifest declaring a native-impl step type plus an action using it.
fn native_step_manifest(plugin: &str, step_type: &str, with_def: bool) -> String {
    let mut m = serde_json::json!({
        "name": plugin,
        "version": "0.1.0",
        // The body is shared across several fixture plugins, so none of
        // them owns it by name; the binding is declared here and
        // authorised in `boot_with_const_impl`.
        "permissions": ["bind:native_impl:test.lifecycle.const"],
        "stepTypeImpls": [
            {"stepType": step_type, "kind": "native", "implRef": "test.lifecycle.const"}
        ],
        "actions": {
            "go": {"steps": [{"id": "s1", "type": step_type}]}
        }
    });
    if with_def {
        m["stepTypeDefs"] = serde_json::json!([{"name": step_type}]);
    }
    m.to_string()
}

/// Reloading a plugin whose manifest wires a native step type must NOT
/// poison the kernel. The runtime replays its import table onto a fresh
/// Linker on every `execute_dag`, so a reload that pushed a duplicate
/// `step_<name>` entry would make every subsequent execution — for
/// every plugin — fail with a duplicate-registration error.
#[tokio::test]
async fn hot_reload_of_native_step_type_does_not_brick_kernel() {
    let mut k = boot_with_const_impl();

    let bystander = k
        .load_manifest(&thrower_manifest("bystander", "OK"))
        .register()
        .expect("bystander loads");
    let _ = bystander;

    let handle = k
        .load_manifest(&native_step_manifest(
            "hot_native",
            "hot_native.const_step",
            true,
        ))
        .register()
        .expect("v1 loads");
    let v1 = k
        .execute("hot_native", "go", serde_json::Value::Null)
        .with_config(&serde_json::Value::Null)
        .run()
        .await
        .expect("v1 executes");
    assert_eq!(v1.step_results["s1"], serde_json::json!(7));

    k.reload_manifest(
        handle,
        &native_step_manifest("hot_native", "hot_native.const_step", true),
    )
    .expect("reload succeeds");

    // The reloaded plugin still executes…
    let v2 = k
        .execute("hot_native", "go", serde_json::Value::Null)
        .with_config(&serde_json::Value::Null)
        .run()
        .await
        .expect("v2 executes after reload — kernel must not be poisoned");
    assert_eq!(v2.step_results["s1"], serde_json::json!(7));

    // …and so does every OTHER plugin (a poisoned linker would affect
    // all of them).
    let bystander_err = k
        .execute("bystander", "fire", serde_json::Value::Null)
        .with_config(&serde_json::Value::Null)
        .run()
        .await
        .expect_err("throw_error always errors");
    match bystander_err {
        KernelError::PluginError { code, .. } => assert_eq!(code, "OK"),
        other => panic!("expected PluginError(OK), got {other:?}"),
    }
}

/// Two live plugins claiming one step type must be rejected at
/// registration, naming the current owner — not silently accepted to
/// detonate (or silently shadow) at first execution.
#[tokio::test]
async fn second_plugin_claiming_live_step_type_rejected() {
    let mut k = boot_with_const_impl();

    k.load_manifest(&native_step_manifest(
        "owner_a",
        "owner_a.shared_step",
        true,
    ))
    .register()
    .expect("first claim loads");

    let err = k
        .load_manifest(&native_step_manifest(
            "owner_b",
            "owner_a.shared_step",
            false,
        ))
        .register()
        .expect_err("second claim on a live step type must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("owner_a") && msg.contains("shared_step"),
        "conflict error should name the owning plugin and step type: {msg}"
    );
}

/// Registering the same plugin name twice is an error, not a silent
/// registry overwrite — replacement is `reload_manifest`'s job.
#[tokio::test]
async fn duplicate_plugin_name_rejected() {
    let mut k = boot();
    k.load_manifest(&thrower_manifest("dup", "V1"))
        .register()
        .expect("first load ok");
    let err = k
        .load_manifest(&thrower_manifest("dup", "V2"))
        .register()
        .expect_err("duplicate plugin name must be rejected");
    assert!(
        err.to_string().contains("already registered"),
        "expected duplicate-name rejection: {err}"
    );
}

#[tokio::test]
async fn unload_plugin_makes_action_unreachable() {
    let mut k = boot();
    let handle = k
        .load_manifest(&thrower_manifest("ephemeral", "X"))
        .register()
        .expect("loads");

    k.unload_manifest(handle).expect("unload succeeds");

    let err = k
        .execute("ephemeral", "fire", serde_json::Value::Null)
        .with_config(&serde_json::Value::Null)
        .run()
        .await
        .expect_err("action no longer registered");
    assert!(
        matches!(err, KernelError::NotFound(_)),
        "post-unload invoke should be NotFound, got {err:?}"
    );
    // Re-using the same handle is also rejected — it's been retired.
    let err = k.unload_manifest(handle).expect_err("handle is gone");
    assert!(matches!(err, KernelError::NotFound(_)));
}

#[tokio::test]
async fn unload_spi_with_dependent_is_rejected() {
    let mut k = boot();
    let spi_json = r#"{
        "name": "TEST_CONTRACT",
        "version": "1.0",
        "actions": {
            "ping": {"input": {"type": "object"}, "output": {"type": "object"}}
        }
    }"#;
    let spi_handle = k.load_manifest(spi_json).register().expect("SPI loads");
    assert_eq!(
        Kernel::manifest_kind(spi_json).unwrap(),
        ManifestKind::SpiDef,
        "fixture sanity check"
    );

    let plugin_json = serde_json::json!({
        "name": "dep_plugin",
        "version": "0.1.0",
        "roles": ["TEST_CONTRACT"],
        "actions": {
            "ping": {
                "steps": [{"id": "boom", "type": "throw_error", "params": {"code": "NEVER"}}],
            }
        }
    })
    .to_string();
    let _plugin_handle = k
        .load_manifest(&plugin_json)
        .register()
        .expect("plugin loads");

    let err = k
        .unload_manifest(spi_handle)
        .expect_err("SPI still has a dependent");
    match err {
        KernelError::Validation(msg) => {
            assert!(
                msg.contains("TEST_CONTRACT") && msg.contains("dep_plugin"),
                "error names both SPI and dependent: {msg}"
            );
        }
        other => panic!("expected Validation, got {other:?}"),
    }

    // SPI still loaded — re-validating the same plugin manifest should
    // still succeed (would fail if SPI def had actually been removed).
    let plugin2 = plugin_json.replace("dep_plugin", "dep_plugin_v2");
    k.load_manifest(&plugin2)
        .register()
        .expect("SPI still backs validation");
}

#[tokio::test]
async fn unload_spi_after_dependent_unloaded_succeeds() {
    let mut k = boot();
    let spi_handle = k
        .load_manifest(r#"{"name":"TEST_CONTRACT2","version":"1.0","actions":{}}"#)
        .register()
        .expect("SPI loads");
    let plugin_handle = k
        .load_manifest(
            &serde_json::json!({
                "name": "dep",
                "roles": ["TEST_CONTRACT2"],
                "actions": {
                    "noop": {"steps": [{"id": "e", "type": "throw_error", "params": {"code": "NEVER"}}]}
                }
            })
            .to_string(),
        )
        .register()
        .expect("plugin loads");

    k.unload_manifest(plugin_handle).expect("plugin unload");
    k.unload_manifest(spi_handle)
        .expect("SPI unload now allowed");
}

#[tokio::test]
async fn reload_with_invalid_json_rolls_back_to_old_manifest() {
    let mut k = boot();
    let handle = k
        .load_manifest(&thrower_manifest("durable", "ORIGINAL"))
        .register()
        .expect("v1 loads");

    let err = k
        .reload_manifest(handle, "{not valid json")
        .expect_err("malformed JSON rejected");
    assert!(
        matches!(err, KernelError::Validation(_)),
        "expected Validation, got {err:?}"
    );

    // Original manifest still resolves — action invokes and produces
    // the v1 PluginError code.
    let action_err = k
        .execute("durable", "fire", serde_json::Value::Null)
        .with_config(&serde_json::Value::Null)
        .run()
        .await
        .expect_err("throw_error");
    match action_err {
        KernelError::PluginError { code, .. } => assert_eq!(code, "ORIGINAL"),
        other => panic!("expected PluginError(ORIGINAL), got {other:?}"),
    }

    // Handle still good — a second valid reload still works.
    k.reload_manifest(handle, &thrower_manifest("durable", "RECOVERED"))
        .expect("subsequent reload works");
}

#[tokio::test]
async fn reload_with_validation_failure_rolls_back() {
    let mut k = boot();
    let handle = k
        .load_manifest(&thrower_manifest("solid", "V1"))
        .register()
        .expect("loads");

    // `wallclock_timeout_ms: 0` is one of register_plugin's loud
    // validation rejects (would otherwise trip ExecutionTimeout
    // instantly). Reload must surface it without unloading v1.
    let bad = serde_json::json!({
        "name": "solid",
        "actions": {
            "fire": {
                "wallclockTimeoutMs": 0,
                "steps": [{"id": "boom", "type": "throw_error", "params": {"code": "WONT_RUN"}}],
            }
        }
    })
    .to_string();

    let err = k
        .reload_manifest(handle, &bad)
        .expect_err("plugin validation rejects");
    assert!(matches!(err, KernelError::Validation(_)));

    // Old plugin still answers.
    let action_err = k
        .execute("solid", "fire", serde_json::Value::Null)
        .with_config(&serde_json::Value::Null)
        .run()
        .await
        .expect_err("throw_error");
    match action_err {
        KernelError::PluginError { code, .. } => assert_eq!(code, "V1"),
        other => panic!("expected PluginError(V1), got {other:?}"),
    }
}

#[test]
fn unload_unknown_handle_is_not_found() {
    let mut k = boot();
    let real = k
        .load_manifest(&thrower_manifest("present", "X"))
        .register()
        .expect("a real handle");
    // Unload it once to confirm Ok, then unload the same (now-retired)
    // handle again — it must report NotFound rather than succeed twice.
    k.unload_manifest(real).expect("first unload ok");
    let err = k.unload_manifest(real).expect_err("second unload");
    assert!(matches!(err, KernelError::NotFound(_)));
}

/// Reload a plugin where the new manifest declares a different set
/// of `roles` than v1. After reload, the old SPI role's user set
/// should no longer include this handle, and the new SPI role's set
/// should. Exercises the track / untrack interaction inside
/// `reload_manifest`.
#[tokio::test]
async fn reload_changes_plugin_roles() {
    let mut k = boot();
    k.load_manifest(r#"{"name":"ROLE_A","version":"1.0","actions":{}}"#)
        .register()
        .expect("SPI A loads");
    k.load_manifest(r#"{"name":"ROLE_B","version":"1.0","actions":{}}"#)
        .register()
        .expect("SPI B loads");

    let v1 = serde_json::json!({
        "name": "shifter",
        "roles": ["ROLE_A"],
        "actions": {
            "fire": {"steps": [{"id": "e", "type": "throw_error", "params": {"code": "V1"}}]},
        }
    })
    .to_string();
    let handle = k.load_manifest(&v1).register().expect("v1 loads");

    let registered_for =
        |k: &Kernel, role: &str| -> Vec<String> { k.registry().plugins_for_role(role) };
    assert_eq!(registered_for(&k, "ROLE_A"), vec!["shifter".to_string()]);
    assert!(registered_for(&k, "ROLE_B").is_empty());

    let v2 = serde_json::json!({
        "name": "shifter",
        "roles": ["ROLE_B"],
        "actions": {
            "fire": {"steps": [{"id": "e", "type": "throw_error", "params": {"code": "V2"}}]},
        }
    })
    .to_string();
    k.reload_manifest(handle, &v2).expect("v2 loads");

    assert!(
        registered_for(&k, "ROLE_A").is_empty(),
        "old role should no longer name this plugin"
    );
    assert_eq!(registered_for(&k, "ROLE_B"), vec!["shifter".to_string()]);

    // A second plugin claiming ROLE_B still validates against that
    // contract and unloads cleanly, so the role index is consistent
    // after the swap.
    let spi_b_handle_lookup_ok = k
        .load_manifest(
            &serde_json::json!({
                "name": "ROLE_B_PROBE",
                "roles": ["ROLE_B"],
                "actions": {"e": {"steps":[{"id": "x", "type": "throw_error", "params": {"code": "N"}}]}}
            })
            .to_string(),
        )
        .register()
        .expect("probe plugin loads");
    // Cleanup so test doesn't leak state.
    k.unload_manifest(spi_b_handle_lookup_ok).unwrap();
}

/// Reloading an SPI def while plugins claim the role is allowed —
/// kernel emits a `tracing::warn!` and proceeds. The new SPI def
/// lands and dependent plugins continue to validate (no
/// revalidation, per the documented caveat).
#[tokio::test]
async fn reload_spi_with_dependents_proceeds_without_revalidation() {
    let mut k = boot();
    let spi_v1 = r#"{"name":"DEPENDED","version":"1.0","actions":{}}"#;
    let spi_handle = k.load_manifest(spi_v1).register().expect("SPI v1");

    let plugin = serde_json::json!({
        "name": "claimer",
        "roles": ["DEPENDED"],
        "actions": {
            "fire": {"steps": [{"id": "e", "type": "throw_error", "params": {"code": "X"}}]}
        }
    })
    .to_string();
    k.load_manifest(&plugin)
        .register()
        .expect("dependent plugin loads");

    // New SPI def under same role name — kernel allows it but emits
    // the documented warn. We can't capture the warn here without a
    // tracing-test subscriber, but we can verify the reload succeeds
    // and the dependent plugin is still invocable.
    let spi_v2 = r#"{
        "name":"DEPENDED",
        "version":"2.0",
        "actions":{
            "added_action":{"input":{"type":"object"},"output":{"type":"object"}}
        }
    }"#;
    k.reload_manifest(spi_handle, spi_v2)
        .expect("SPI reload with dependent");

    let err = k
        .execute("claimer", "fire", serde_json::Value::Null)
        .with_config(&serde_json::Value::Null)
        .run()
        .await
        .expect_err("throw_error");
    assert!(matches!(err, KernelError::PluginError { .. }));
}

/// Declaring aliases or subscriptions binds the plugin to no role —
/// alias and subscriber resolution flow through their own registries
/// only.
#[test]
fn marker_roles_are_not_attached_to_plugins() {
    let mut k = boot();
    let m = serde_json::json!({
        "name": "marker_probe",
        "stepTypes": {"marker_probe.my_alias": "real"},
        "actions": {
            "real": {"steps": [{"id": "e", "type": "throw_error", "params": {"code": "X"}}]},
            "on_evt": {
                "subscribesTo": ["any.event"],
                "steps": [{"id": "e", "type": "throw_error", "params": {"code": "Y"}}],
            }
        }
    })
    .to_string();
    k.load_manifest(&m).register().expect("loads");

    assert!(
        k.registry().plugins_for_role("STEP_TYPE").is_empty(),
        "declaring an alias binds no role"
    );
    assert!(
        k.registry().plugins_for_role("EVENT_HANDLER").is_empty(),
        "subscribing binds no role"
    );
    // Underlying indices still work.
    assert_eq!(
        k.registry()
            .step_type_alias_candidates("marker_probe.my_alias"),
        vec![("marker_probe".to_string(), "real".to_string())]
    );
    let subs = k.registry().subscribers_for("any.event");
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0], ("marker_probe".to_string(), "on_evt".to_string()));
}

/// Pins the documented behaviour for the empty-extensions corner
/// case: a manifest with no `actions`, no `metadata`, and an empty
/// `stepTypeDefs` (or `wasmModules`) array is accepted
/// and registers as a content-less plugin under its
/// `name`. This corner case is pinned deliberately rather than left
/// undefined.
#[tokio::test]
async fn empty_extension_manifests_register_as_no_op_plugins() {
    let mut k = boot();
    let m = r#"{"name":"empty_probe","stepTypeDefs":[]}"#;
    let handle = k
        .load_manifest(m)
        .register()
        .expect("empty stepTypeDefs accepted");
    let names = k.registry().plugin_names();
    assert!(
        names.contains(&"empty_probe"),
        "empty-extension manifest registers as a no-op plugin"
    );
    // Unload is allowed (it's not kernel-immutable).
    k.unload_manifest(handle).expect("unloads cleanly");
}

// Intrinsics-manifest immutable-rejection test lives in
// `src/kernel/mod.rs` (search for
// `intrinsics_manifest_rejects_unload_and_reload`) — it needs to
// fabricate a `ManifestHandle` for the boot-time intrinsics manifest,
// which only the internal constructor exposes.

/// `formatVersion` is gated on the struct path as well as the JSON one.
/// A manifest built in code skips the meta-schema, so without an
/// explicit check a v2 struct would register on a v1 kernel.
#[test]
fn the_struct_path_rejects_an_unsupported_format_version() {
    use gwead::kernel::types::{PluginManifest, SUPPORTED_FORMAT_VERSION};
    let mut k = gwead::kernel::Kernel::boot(gwead::kernel::KernelConfig::default()).expect("boot");
    let mut m = PluginManifest::new("future");
    m.format_version = Some(SUPPORTED_FORMAT_VERSION + 1);
    let err = k.register_plugin(m).expect_err("refused");
    assert!(err.to_string().contains("formatVersion"), "{err}");

    let mut m = PluginManifest::new("current");
    m.format_version = Some(SUPPORTED_FORMAT_VERSION);
    k.register_plugin(m)
        .expect("the supported version registers");
}
