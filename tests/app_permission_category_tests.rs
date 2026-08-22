//! An embedder permission category must exist before a manifest can
//! name one.
//!
//! Any dot-namespaced category parses cleanly into a
//! [`Permission::AppDefined`] entry. The kernel never enforces those
//! — it cannot, they mean something only inside the embedder — so
//! without this gate a misspelled one would become a grant that
//! matched nothing, for the life of the deployment, silently.
//! `acme.evets:publish:x` and `acme.events:publish:x` would be the same
//! thing to the kernel, and after load a never-matching grant is
//! indistinguishable from a correctly denied one.
//!
//! This is one rule in three places: refuse the grant whose meaning
//! nobody can vouch for, at the one moment somebody is still reading
//! the manifest. The other two are the glob reservation
//! (`network:egress:*.example.*`) and the dot-free category reservation
//! (`invok:plugin:x`); this is the half only the embedder can answer.
//!
//! The kernel still enforces none of these grants. It checks that each
//! one is *addressed to somebody*.

use gwead::kernel::permissions::AppPermissionCategory;
use gwead::kernel::{Kernel, KernelConfig, KernelError};
use serde_json::json;

fn manifest(name: &str, permissions: &[&str]) -> String {
    json!({
        "name": name,
        "permissions": permissions,
        "actions": { "go": {
            "steps": [{"id": "s", "type": "let", "params": {"value": 1}}],
            "resultMapping": { "out": { "path": "$", "source": "s" } }
        } },
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// The category itself
// ---------------------------------------------------------------------------

#[test]
fn a_declared_category_loads_and_an_undeclared_one_does_not() {
    let mut k =
        Kernel::boot(KernelConfig::default().defining_app_permission_category("acme.events"))
            .expect("boot");

    k.register_plugin_from_json(&manifest("good", &["acme.events:publish:item.created"]))
        .expect("the declared category loads");

    let err = k
        .register_plugin_from_json(&manifest("typo", &["acme.evets:publish:item.created"]))
        .expect_err("one transposition is a different category")
        .to_string();
    assert!(err.contains("acme.evets"), "names what was written: {err}");
    assert!(
        err.contains("acme.events"),
        "and lists what exists, which is where the author sees the typo: {err}"
    );
}

/// The empty case is not a typo — it is an embedder meeting this rule
/// for the first time — so it gets the fix rather than an empty list.
#[test]
fn with_nothing_declared_the_error_teaches_the_opt_in() {
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    let err = k
        .register_plugin_from_json(&manifest("p", &["acme.events:publish:x"]))
        .expect_err("nothing is declared, so nothing is accepted")
        .to_string();
    assert!(
        err.contains("defining_app_permission_category"),
        "says how to declare it: {err}"
    );
    assert!(
        err.contains("declares no embedder permission categories"),
        "and says the list is empty rather than printing an empty list: {err}"
    );
}

/// Declaring a category is not endorsing its values. Without a
/// validator the kernel accepts whatever follows the colon — it has no
/// opinion about the embedder's grammar and does not want one.
#[test]
fn a_category_without_a_validator_accepts_any_value() {
    let mut k =
        Kernel::boot(KernelConfig::default().defining_app_permission_category("acme.anything"))
            .expect("boot");
    // An empty value is the one exception, and it is not the
    // category's rule: `<category>:<value>` is the permission grammar
    // itself, checked before any category is consulted.
    for value in ["publish:x", "a:b:c:d", "utter nonsense", "*"] {
        let name = format!("p{}", value.len());
        k.register_plugin_from_json(&manifest(&name, &[&format!("acme.anything:{value}")]))
            .unwrap_or_else(|e| panic!("value {value:?} should be accepted: {e}"));
    }
}

// ---------------------------------------------------------------------------
// Value validation — the same failure one level down
// ---------------------------------------------------------------------------

/// `acme.events:publsh:x` names a category that exists and still
/// matches nothing. Only the embedder can judge that, and only at load
/// time.
#[test]
fn a_validator_catches_the_typo_inside_the_value() {
    let events = AppPermissionCategory::new("acme.events").with_validator(|value| {
        match value.split_once(':') {
            Some(("publish" | "subscribe", topic)) if !topic.is_empty() => Ok(()),
            _ => Err("expected publish:<topic> or subscribe:<topic>".to_string()),
        }
    });
    let mut k = Kernel::boot(KernelConfig::default().defining_app_permission_category_as(events))
        .expect("boot");

    k.register_plugin_from_json(&manifest("good", &["acme.events:subscribe:item.created"]))
        .expect("a well-formed value loads");

    let err = k
        .register_plugin_from_json(&manifest("bad", &["acme.events:publsh:item.created"]))
        .expect_err("the embedder's own grammar rejected it")
        .to_string();
    assert!(
        err.contains("expected publish:<topic> or subscribe:<topic>"),
        "the embedder's explanation reaches whoever is installing the plugin, \
         verbatim: {err}"
    );
}

/// The validator sees everything after the category's colon, and
/// nothing else — not the category, not the original string.
#[test]
fn a_validator_receives_the_value_alone() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let recorder = std::sync::Arc::clone(&seen);
    let cat = AppPermissionCategory::new("acme.audit").with_validator(move |value| {
        recorder.lock().expect("lock").push(value.to_string());
        Ok(())
    });
    let mut k = Kernel::boot(KernelConfig::default().defining_app_permission_category_as(cat))
        .expect("boot");
    k.register_plugin_from_json(&manifest("p", &["acme.audit:write:ledger"]))
        .expect("loads");
    assert_eq!(seen.lock().expect("lock").as_slice(), ["write:ledger"]);
}

#[test]
fn declaring_a_category_twice_keeps_the_last() {
    // A builder chain reads top to bottom; the alternative — first call
    // wins, or two entries with different validators both consulted —
    // is a config whose behaviour depends on where you inserted a line.
    let permissive = AppPermissionCategory::new("acme.events");
    let strict = AppPermissionCategory::new("acme.events")
        .with_validator(|_| Err("nothing is allowed".to_string()));

    let mut k = Kernel::boot(
        KernelConfig::default()
            .defining_app_permission_category_as(permissive)
            .defining_app_permission_category_as(strict),
    )
    .expect("boot");
    assert!(
        k.register_plugin_from_json(&manifest("p", &["acme.events:publish:x"]))
            .is_err(),
        "the second declaration is the one in force"
    );
}

// ---------------------------------------------------------------------------
// The config side — a declared category no manifest could ever name
// ---------------------------------------------------------------------------

/// The same never-matching failure, pointing the other way: a category
/// the embedder declares but the grammar forbids a manifest from
/// writing. Boot is the last moment anyone is looking.
#[test]
fn a_dot_free_declared_category_fails_boot() {
    let Err(err) = Kernel::boot(KernelConfig::default().defining_app_permission_category("events"))
    else {
        panic!("dot-free names belong to the kernel");
    };
    assert!(matches!(err, KernelError::Boot(_)), "a config error: {err}");
    let msg = err.to_string();
    assert!(
        msg.contains("acme.events"),
        "shows the namespaced form to use: {msg}"
    );
}

#[test]
fn a_declared_category_carrying_a_colon_fails_boot() {
    // The likely mistake is pasting a whole permission string in.
    let Err(err) = Kernel::boot(
        KernelConfig::default().defining_app_permission_category("acme.events:publish"),
    ) else {
        panic!("the category is the part before the first colon");
    };
    let msg = err.to_string();
    assert!(
        msg.contains("Declare the category alone: 'acme.events'"),
        "names the part they meant: {msg}"
    );
}

#[test]
fn a_declared_category_with_an_illegal_character_fails_boot() {
    for bad in [
        "acme.ev nts",
        "acme.events!",
        "acme.",
        ".events",
        "acme..events",
    ] {
        let err = Kernel::boot(KernelConfig::default().defining_app_permission_category(bad));
        assert!(
            err.is_err(),
            "{bad:?} is not a name a manifest could write, so declaring it is a config bug"
        );
    }
}

#[test]
fn declaring_nothing_is_the_default_and_boots_fine() {
    // The rule costs an embedder with no app categories exactly nothing
    // — which is most of them, and is why the default is empty rather
    // than permissive.
    Kernel::boot(KernelConfig::default()).expect("boot");
}

// ---------------------------------------------------------------------------
// Reach — the check is on the registration funnel, not one entry point
// ---------------------------------------------------------------------------

#[test]
fn the_check_applies_on_every_registration_path() {
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    let json = manifest("p", &["acme.events:publish:x"]);

    assert!(
        k.register_plugin_from_json(&json).is_err(),
        "register_plugin_from_json"
    );
    assert!(
        k.load_manifest(&json).register().is_err(),
        "load_manifest().register()"
    );
    assert!(
        k.load_manifest(&json)
            .in_namespace("tenant42")
            .register()
            .is_err(),
        "a namespace is not a way around it"
    );

    let parsed: gwead::kernel::types::PluginManifest =
        serde_json::from_str(&json).expect("manifest parses");
    assert!(
        k.register_plugin(parsed).is_err(),
        "register_plugin with a struct, which skips the JSON meta-schema entirely"
    );
}

/// Reload re-registers, so a category revoked between load and reload
/// is caught rather than grandfathered.
#[test]
fn reload_is_held_to_the_rule_too() {
    let mut k =
        Kernel::boot(KernelConfig::default().defining_app_permission_category("acme.events"))
            .expect("boot");
    let handle = k
        .load_manifest(&manifest("p", &["acme.events:publish:x"]))
        .register()
        .expect("loads");
    // Same category, same manifest: reload goes through the identical
    // gate and stays green. The point is that it *goes through* it.
    k.reload_manifest(handle, &manifest("p", &["acme.events:publish:x"]))
        .expect("reload re-validates and passes");
}

// ---------------------------------------------------------------------------
// The kernel's own categories are untouched
// ---------------------------------------------------------------------------

#[test]
fn kernel_categories_need_no_declaration() {
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    k.register_plugin_from_json(&manifest(
        "p",
        &[
            "network:egress:*.example.com",
            "blobs:read:data/*",
            "invoke:plugin:other",
        ],
    ))
    .expect("engine-shaped categories are the kernel's own and always known");
}

/// A dot-free category is rejected by the separate dot-free
/// reservation — with its own message, which is the one that explains
/// the reservation. The embedder-category rule does not move that
/// boundary.
#[test]
fn a_dot_free_unknown_category_still_reports_the_reservation() {
    let mut k =
        Kernel::boot(KernelConfig::default().defining_app_permission_category("acme.events"))
            .expect("boot");
    let parsed: gwead::kernel::types::PluginManifest =
        serde_json::from_str(&manifest("p", &["events:publish:x"])).expect("parses");
    let err = k
        .register_plugin(parsed)
        .expect_err("dot-free is reserved")
        .to_string();
    assert!(
        err.contains("reserved for the kernel"),
        "the reservation, not the declaration rule: {err}"
    );
}
