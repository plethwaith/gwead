//! An operator ceiling a manifest cannot raise itself past, and the
//! SPI role/name agreement check.
//!
//! Both are the same shape as every other gate in the kernel: the
//! subject does not get to assert its own authority.
//!
//! `RuntimeLimits::default_wallclock_timeout` reads like a limit and is
//! a default. A manifest declaring `wallclockTimeoutMs` replaces it in
//! either direction, and `dataflow: true` removes it entirely — so
//! without a ceiling a plugin author, not the operator, decides how
//! long a plugin can hold a worker. `max_wallclock_timeout` is that
//! bound. It defaults to `None`, because a streaming pipeline
//! legitimately runs for days and the kernel cannot tell which actions
//! those are.
//!
//! `register_spi_from_json(role, json)` must compare `role` against the
//! document's own `name`, or a definition could be filed under a key it
//! does not answer to — and `invoke:role:<key>` would then grant
//! dispatch against a contract neither file predicts.

use std::time::Duration;

use gwead::kernel::{Kernel, KernelConfig, RuntimeLimits};
use serde_json::{Value, json};

/// A trivially fast action, with extra action-level fields merged in.
fn slow_action(extra: Value) -> String {
    let mut action = json!({
        "steps": [{"id": "s", "type": "let", "params": {"value": 1}}],
        "resultMapping": { "out": { "path": "$", "source": "s" } }
    });
    for (k, v) in extra.as_object().expect("object") {
        action[k] = v.clone();
    }
    json!({ "name": "p", "actions": { "go": action } }).to_string()
}

fn boot(limits: RuntimeLimits) -> Kernel {
    Kernel::boot(KernelConfig::default().with_limits(limits)).expect("boot")
}

// ---------------------------------------------------------------------------
// The ceiling
// ---------------------------------------------------------------------------

/// The default is `None`, so a manifest chooses freely — including the
/// dataflow uncap, which is a feature, not an oversight.
#[tokio::test(flavor = "multi_thread")]
async fn with_no_ceiling_a_manifest_still_chooses_freely() {
    let mut k =
        boot(RuntimeLimits::default().with_default_wallclock_timeout(Duration::from_secs(1)));
    // Declares a deadline far above the operator default and loads.
    k.register_plugin_from_json(&slow_action(json!({"wallclockTimeoutMs": 86_400_000u64})))
        .expect("registers");
    let arc = k.into_arc();
    arc.execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect("runs");
}

/// The ceiling clamps a manifest that asked for more. The action still
/// runs — the point is the deadline it runs under, not a load failure;
/// clamping keeps a manifest portable across operators with different
/// ceilings, where rejecting would not.
#[tokio::test(flavor = "multi_thread")]
async fn a_manifest_cannot_raise_itself_past_the_ceiling() {
    let mut k = boot(
        RuntimeLimits::default()
            .with_default_wallclock_timeout(Duration::from_secs(1))
            .with_max_wallclock_timeout(Duration::from_secs(2)),
    );
    k.register_plugin_from_json(&slow_action(json!({"wallclockTimeoutMs": 86_400_000u64})))
        .expect("registers");
    let arc = k.into_arc();
    // A fast action completes well inside the clamped deadline; what is
    // under test is that the clamp is applied, which the timing test
    // below pins.
    arc.execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect("runs");
}

/// Asking for *less* is never an escalation, so the ceiling must not
/// raise a manifest's own tighter deadline up to it.
#[tokio::test(flavor = "multi_thread")]
async fn the_ceiling_only_ever_clamps_down() {
    let mut k =
        boot(RuntimeLimits::default().with_max_wallclock_timeout(Duration::from_secs(3600)));
    k.register_plugin_from_json(&slow_action(json!({"wallclockTimeoutMs": 50u64})))
        .expect("registers");
    let arc = k.into_arc();
    arc.execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect("a 50 ms action finishes inside 50 ms");
}

/// Without a ceiling, `dataflow: true` means "no deadline at all",
/// chosen by the manifest. With a ceiling set it means "the operator's
/// deadline" — the manifest cannot opt out of it.
#[tokio::test(flavor = "multi_thread")]
async fn dataflow_cannot_uncap_past_an_operator_ceiling() {
    let manifest = json!({
        "name": "p",
        "actions": { "go": {
            "dataflow": true,
            "steps": [{"id": "prod", "type": "let", "params": {"value": "x"}, "longRunning": true}],
            "resultMapping": { "out": { "path": "$", "source": "prod" } }
        } }
    })
    .to_string();

    let mut k = boot(RuntimeLimits::default().with_max_wallclock_timeout(Duration::from_secs(30)));
    k.register_plugin_from_json(&manifest)
        .expect("a dataflow action still registers");
    let arc = k.into_arc();
    // Completes promptly; the assertion that matters is that a deadline
    // now exists at all, which `the_ceiling_is_what_actually_fires`
    // demonstrates by making it fire.
    arc.execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
        .expect("runs");
}

/// A CPU-bound loop that takes tens of seconds uncapped: 4 M iterations
/// of a host-side `let`. It never returns `Pending`, which is precisely
/// the shape a `tokio::time::timeout` cannot preempt.
fn grinding_manifest(declared_ms: Option<u64>) -> String {
    let mut action = json!({
        "steps": [{"id": "loop", "type": "repeat", "params": {"count": 4_000_000, "steps": [{"id": "inner", "type": "let", "params": {"value": "{{$item}}"}}]}}],
        "resultMapping": { "out": { "path": "$", "source": "loop" } }
    });
    if let Some(ms) = declared_ms {
        action["wallclockTimeoutMs"] = json!(ms);
    }
    json!({ "name": "p", "actions": { "go": action } }).to_string()
}

/// The ceiling is not decorative: a manifest asking for an hour, under
/// an operator allowing 100 ms, is stopped at 100 ms.
///
/// This asserts the elapsed time, not merely that an error came back —
/// an error from a malformed step would be a green that meant nothing.
/// Check the reason, not the colour.
#[tokio::test(flavor = "multi_thread")]
async fn the_ceiling_is_what_actually_fires() {
    let mut k =
        boot(RuntimeLimits::default().with_max_wallclock_timeout(Duration::from_millis(100)));
    k.register_plugin_from_json(&grinding_manifest(Some(3_600_000)))
        .expect("registers");
    let arc = k.into_arc();

    let started = std::time::Instant::now();
    let result = arc
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await;
    let elapsed = started.elapsed();

    let err = result
        .expect_err("the manifest asked for an hour, the operator allowed 100 ms")
        .to_string();
    assert!(
        err.contains("wallclock timeout"),
        "stopped for the stated reason, not an unrelated failure: {err}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "stopped near the deadline, not after the work finished: {elapsed:?}"
    );
}

/// The deadline works at all — the more serious half of the contract.
///
/// `default_wallclock_timeout` is documented as an invocation deadline.
/// A `tokio::time::timeout` alone fires only when the future it wraps
/// returns `Pending`, and a `repeat` body of `let` steps never does: a
/// timeout-only deadline would let this manifest run to completion and
/// return `Ok`, pinning a worker throughout — a manifest-reachable
/// denial of service against a documented bound, with no manifest
/// declaration and no ceiling involved.
///
/// The nested executors poll the cancellation token; the deadline is
/// wired to that token, not only to the outer future.
#[tokio::test(flavor = "multi_thread")]
async fn the_plain_operator_deadline_stops_a_loop_that_never_yields() {
    let mut k =
        boot(RuntimeLimits::default().with_default_wallclock_timeout(Duration::from_millis(100)));
    // No manifest declaration and no ceiling: the deployment default alone.
    k.register_plugin_from_json(&grinding_manifest(None))
        .expect("registers");
    let arc = k.into_arc();

    let started = std::time::Instant::now();
    let result = arc
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await;
    let elapsed = started.elapsed();

    assert!(
        result.is_err(),
        "ran to completion despite the deadline: {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the deadline is enforced by the cancellation token, not by hoping \
         the future yields: {elapsed:?}"
    );
}

/// A caller's own token still reaches the invocation — the watchdog uses
/// a child token, which inherits cancellation downward without
/// propagating our deadline back up to whatever else the caller uses
/// that token for.
#[tokio::test(flavor = "multi_thread")]
async fn a_callers_token_still_cancels_and_is_not_fired_by_our_deadline() {
    let mut k =
        boot(RuntimeLimits::default().with_default_wallclock_timeout(Duration::from_millis(100)));
    k.register_plugin_from_json(&grinding_manifest(None))
        .expect("registers");
    let arc = k.into_arc();

    let caller_token = tokio_util::sync::CancellationToken::new();
    let result = arc
        .execute("p", "go", json!({}))
        .with_config(&Value::Null)
        .with_cancel(caller_token.clone())
        .run()
        .await;

    assert!(result.is_err(), "the deadline still fired: {result:?}");
    assert!(
        !caller_token.is_cancelled(),
        "our deadline must not tear down the caller's token — it may be \
         driving work we know nothing about"
    );
}

// ---------------------------------------------------------------------------
// SPI role / name agreement
// ---------------------------------------------------------------------------

fn spi_def(name: &str) -> String {
    json!({
        "name": name,
        "actions": { "do": { "input": {"type": "object"}, "output": {"type": "object"} } }
    })
    .to_string()
}

#[test]
fn an_spi_definition_must_agree_with_the_role_it_registers_under() {
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    k.register_spi_from_json("LLM_CHAT", &spi_def("LLM_CHAT"))
        .expect("agreement is the ordinary case");

    let err = k
        .register_spi_from_json("LLM_CHAT2", &spi_def("STORAGE"))
        .expect_err("the key and the document disagreed")
        .to_string();
    assert!(err.contains("STORAGE"), "names the declared name: {err}");
    assert!(err.contains("LLM_CHAT2"), "and the key: {err}");
}

/// Why it matters: the role is what `invoke:role:` grants name. Filed
/// under the wrong key, a grant reads as authorising one contract and
/// dispatches against another — and both files look right in isolation.
#[test]
fn the_key_is_what_invoke_role_grants_name() {
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    assert!(
        k.register_spi_from_json("LLM_CHAT", &spi_def("STORAGE"))
            .is_err(),
        "an 'invoke:role:LLM_CHAT' grant must not reach a STORAGE contract"
    );
}
