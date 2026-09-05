//! What the kernel logs, unprompted, when SPI validation has something
//! to say at plugin registration.
//!
//! The validator's return value is covered by its own unit tests; these
//! pin the *level* each finding reaches the log at, because that is
//! what an operator sees. A plugin that provides actions beyond what
//! its roles name is doing exactly what the SPI intends, so it is noted
//! at DEBUG. A plugin claiming a role no SPI has been registered for
//! may be a misconfiguration, so it stays at WARN — and it doubles as
//! the positive control proving the recorder below sees WARN events.

use std::fmt;
use std::sync::{Arc, Mutex};

use gwead::kernel::types::{Action, PluginManifest, StepDef};
use gwead::kernel::{Kernel, KernelConfig};
use indexmap::IndexMap;
use serde_json::json;
use tracing::Level;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

mod common;

// ---------------------------------------------------------------------------
// Event recording
// ---------------------------------------------------------------------------

/// One recorded event: its level, its message, and its other fields
/// rendered with `Debug`, so a test can look at what was logged without
/// depending on how a formatter would have laid it out.
#[derive(Debug)]
struct Recorded {
    level: Level,
    message: String,
    fields: Vec<(&'static str, String)>,
}

impl Recorded {
    fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }
}

impl Visit for Recorded {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        match field.name() {
            "message" => self.message = format!("{value:?}"),
            name => self.fields.push((name, format!("{value:?}"))),
        }
    }
}

/// A `Layer` that keeps every event it sees.
#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<Recorded>>>);

impl<S: tracing::Subscriber> Layer<S> for Recorder {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut recorded = Recorded {
            level: *event.metadata().level(),
            message: String::new(),
            fields: Vec::new(),
        };
        event.record(&mut recorded);
        self.0.lock().unwrap().push(recorded);
    }
}

/// Run `f` with every event recorded, and return them in order. The
/// subscriber is installed as the thread-local default, which overrides
/// any global one another test installed; `register_plugin` logs on the
/// calling thread, so nothing escapes.
fn record_events(f: impl FnOnce()) -> Vec<Recorded> {
    let recorder = Recorder::default();
    let subscriber = tracing_subscriber::registry().with(recorder.clone());
    tracing::subscriber::with_default(subscriber, f);
    std::mem::take(&mut *recorder.0.lock().unwrap())
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ROLE: &str = "METADATA_PROVIDER";

fn boot() -> Kernel {
    let mut kernel = Kernel::boot(KernelConfig::default()).expect("kernel should boot");
    kernel
        .register_spi_from_json(
            ROLE,
            r#"{
                "name": "METADATA_PROVIDER",
                "version": "1.0",
                "actions": {
                    "search": { "input": { "type": "object" }, "output": { "type": "array" } },
                    "fetch": { "input": { "type": "object" }, "output": { "type": "object" } }
                }
            }"#,
        )
        .expect("SPI registers");
    kernel
}

fn manifest(name: &str, roles: &[&str], action_names: &[&str]) -> PluginManifest {
    let mut m = PluginManifest::new(name.to_string());
    m.roles = roles.iter().map(|s| s.to_string()).collect();
    m.actions = action_names
        .iter()
        .map(|a| {
            let step = StepDef::new("s1".to_string(), "let".to_string(), json!({"value": 1}));
            (a.to_string(), Action::new(vec![step]))
        })
        .collect::<IndexMap<_, _>>();
    m
}

/// Events that mention `needle` anywhere: in the message or a field.
/// Deliberately broad — the kernel's own "Plugin registered" event lists
/// the plugin's actions too, and a level check has to cover it.
fn mentioning<'a>(events: &'a [Recorded], needle: &str) -> Vec<&'a Recorded> {
    events
        .iter()
        .filter(|e| e.message.contains(needle) || e.fields.iter().any(|(_, v)| v.contains(needle)))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Issue #2: a provider with helper actions beyond its role used to
/// produce one WARN per extra action on every boot, with nothing for
/// the author to change. The extras still reach the log — once per
/// plugin, listed together — but at DEBUG, and no WARN so much as
/// mentions them.
#[test]
fn extra_actions_are_logged_once_at_debug_and_never_warned_about() {
    let mut kernel = boot();
    let events = record_events(|| {
        kernel
            .register_plugin(manifest(
                "extended_mp",
                &[ROLE],
                &["search", "fetch", "fetch_buffered", "fetch_streamed"],
            ))
            .expect("extra actions do not fail registration");
    });

    let noted: Vec<&Recorded> = events
        .iter()
        .filter(|e| e.field("extra_actions").is_some())
        .collect();
    assert_eq!(
        noted.len(),
        1,
        "the extras are reported in exactly one event; got {events:#?}"
    );
    let noted = noted[0];
    assert_eq!(
        noted.level,
        Level::DEBUG,
        "extras are informational: {noted:?}"
    );
    assert_eq!(noted.field("plugin"), Some("extended_mp"));
    assert_eq!(
        noted.field("extra_actions"),
        Some(r#"["fetch_buffered", "fetch_streamed"]"#),
        "both extras, in manifest order, on the one event: {noted:?}"
    );

    for extra in ["fetch_buffered", "fetch_streamed"] {
        assert!(
            mentioning(&events, extra)
                .iter()
                .all(|e| e.level > Level::WARN),
            "no WARN or ERROR mentions '{extra}'; got {events:#?}"
        );
    }
}

/// Positive control for the test above, and the contract the change
/// leaves alone: an unknown role can be a real misconfiguration, so it
/// still lands at WARN — which also proves the recorder sees WARN.
#[test]
fn unknown_role_is_still_logged_at_warn() {
    let mut kernel = boot();
    let events = record_events(|| {
        kernel
            .register_plugin(manifest("custom_plugin", &["CUSTOM_THING"], &["do_stuff"]))
            .expect("an unknown role does not fail registration");
    });

    let warned = mentioning(&events, "Unknown SPI role 'CUSTOM_THING'");
    assert_eq!(
        warned.len(),
        1,
        "the unknown role is reported exactly once; got {events:#?}"
    );
    assert_eq!(
        warned[0].level,
        Level::WARN,
        "an unknown role may need the author's attention: {:?}",
        warned[0]
    );
    assert_eq!(warned[0].field("plugin"), Some("custom_plugin"));
}
