//! What the kernel logs, unprompted, when SPI validation has something
//! to say at plugin registration.
//!
//! The validator's return value is covered by its own unit tests; these
//! pin the *level* each finding reaches the log at, because that is
//! what an operator sees. A plugin that provides an action beyond what
//! its role requires is doing exactly what the SPI intends, so it is
//! noted at DEBUG. A plugin claiming a role no SPI has been registered
//! for may be a misconfiguration, so it stays at WARN — and it doubles
//! as the positive control proving the capture below sees WARN lines.

use std::io;
use std::sync::{Arc, Mutex};

use gwead::kernel::types::{Action, PluginManifest, StepDef};
use gwead::kernel::{Kernel, KernelConfig};
use indexmap::IndexMap;
use serde_json::json;
use tracing_subscriber::fmt::MakeWriter;

mod common;

// ---------------------------------------------------------------------------
// Log capture
// ---------------------------------------------------------------------------

/// A `MakeWriter` that appends every formatted event to a shared buffer,
/// so a test can install a subscriber for the duration of a registration
/// and read back what was logged, level and all.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn lines(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .expect("fmt output is UTF-8")
            .lines()
            .map(str::to_string)
            .collect()
    }
}

struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = CaptureWriter;

    fn make_writer(&'a self) -> Self::Writer {
        CaptureWriter(Arc::clone(&self.0))
    }
}

/// Run `f` with every `gwead` event down to TRACE captured, and return
/// the formatted lines. The subscriber is installed as the thread-local
/// default, which overrides any global one another test installed;
/// `register_plugin` logs on the calling thread, so nothing escapes.
fn capture_logs(f: impl FnOnce()) -> Vec<String> {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .without_time()
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    capture.lines()
}

/// The level a formatted line was emitted at: `fmt` puts it first once
/// timestamps are off.
fn level_of(line: &str) -> &str {
    line.split_whitespace()
        .next()
        .expect("a log line names its level")
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

fn lines_mentioning<'a>(lines: &'a [String], needle: &str) -> Vec<&'a String> {
    lines.iter().filter(|l| l.contains(needle)).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Issue #2: a provider with helper actions beyond its role used to
/// produce one WARN per extra action on every boot, with nothing for
/// the author to change. The finding is still made — it reaches the
/// log — but at DEBUG.
#[test]
fn extra_action_is_logged_at_debug_not_warn() {
    let mut kernel = boot();
    let lines = capture_logs(|| {
        kernel
            .register_plugin(manifest(
                "extended_mp",
                &[ROLE],
                &["search", "fetch", "fetch_buffered", "fetch_streamed"],
            ))
            .expect("extra actions do not fail registration");
    });

    for extra in ["fetch_buffered", "fetch_streamed"] {
        let needle = format!("Plugin provides action '{extra}' not declared in SPI '{ROLE}'");
        let mentions = lines_mentioning(&lines, &needle);
        assert_eq!(
            mentions.len(),
            1,
            "the extra action '{extra}' is reported exactly once; got {lines:#?}"
        );
        assert_eq!(
            level_of(mentions[0]),
            "DEBUG",
            "an extra action is informational: {}",
            mentions[0]
        );
    }
    assert!(
        !lines.iter().any(|l| level_of(l) == "WARN"),
        "a plugin extending its role has nothing to warn about; got {lines:#?}"
    );
}

/// Positive control for the test above, and the contract the demotion
/// leaves alone: an unknown role can be a real misconfiguration, so it
/// still lands at WARN — which also proves the capture sees WARN lines.
#[test]
fn unknown_role_is_still_logged_at_warn() {
    let mut kernel = boot();
    let lines = capture_logs(|| {
        kernel
            .register_plugin(manifest("custom_plugin", &["CUSTOM_THING"], &["do_stuff"]))
            .expect("an unknown role does not fail registration");
    });

    let mentions = lines_mentioning(&lines, "Unknown SPI role 'CUSTOM_THING'");
    assert_eq!(
        mentions.len(),
        1,
        "the unknown role is reported exactly once; got {lines:#?}"
    );
    assert_eq!(
        level_of(mentions[0]),
        "WARN",
        "an unknown role may need the author's attention: {}",
        mentions[0]
    );
}
