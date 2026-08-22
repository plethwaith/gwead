//! `gwead::native_step_impl!` from the outside.
//!
//! This file is compiled as its own crate that depends on `gwead` and
//! **not** on `inventory` — `inventory` is not in gwead's
//! `[dev-dependencies]`. So if the macro expands here at all, it proves
//! the thing it exists to provide: a plugin crate can submit a native
//! step body without taking on the dependency itself, and without ever
//! naming `NativeStepImplEntry`'s fields.
//!
//! That second half is the point. `NativeStepImplEntry` is constructed
//! by external crates at link time, so a struct literal in every plugin
//! crate would freeze its shape forever — a literal names every field,
//! and the type cannot be `#[non_exhaustive]` because literal
//! construction was the whole mechanism. Routing through a macro makes
//! the layout an implementation detail that can still change.

use std::future::Future;
use std::pin::Pin;

use gwead::kernel::host_api::{PluginExecution, StepError, StepOutput};
use gwead::kernel::native_impls::NativeStepImplTable;
use gwead::kernel::{Kernel, KernelConfig};
use serde_json::{Value, json};

const MARKER: &str = "SUBMITTED-VIA-MACRO";

fn macro_submitted_body<'a>(
    _ex: &'a mut (dyn PluginExecution + Send),
    _params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move { Ok(StepOutput::from(json!(MARKER))) })
}

// The middle segment matches the plugin name below, so this body is
// bound on the free path — the arrangement the macro's docs tell plugin
// authors to use.
gwead::native_step_impl!("gwead-tests.macro_fixture.body", macro_submitted_body);

/// Trailing comma accepted, so the macro reads like a normal call.
fn second_body<'a>(
    _ex: &'a mut (dyn PluginExecution + Send),
    _params: &'a Value,
) -> Pin<Box<dyn Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
    Box::pin(async move { Ok(StepOutput::from(json!("second"))) })
}

gwead::native_step_impl!("gwead-tests.macro_fixture.second", second_body,);

#[test]
fn the_macro_submits_into_the_inventory_slice() {
    let table = NativeStepImplTable::discover().expect("no collisions");
    assert!(
        table.get("gwead-tests.macro_fixture.body").is_some(),
        "the macro-submitted body should be discoverable at boot"
    );
    assert!(
        table.get("gwead-tests.macro_fixture.second").is_some(),
        "the trailing-comma form should submit too"
    );
}

/// End to end: submitted by the macro, resolved from a manifest, and
/// actually executed. Discovery alone would not prove the fn pointer
/// survived the round trip.
#[tokio::test]
async fn a_macro_submitted_body_executes_from_a_manifest() {
    let mut k = Kernel::boot(
        KernelConfig::default()
            .with_native_step_impls(NativeStepImplTable::discover().expect("discover")),
    )
    .expect("boot");

    k.register_plugin_from_json(
        &json!({
            "name": "macro_fixture",
            "stepTypeDefs": [{"name": "macro_fixture.macro_step"}],
            "stepTypeImpls": [{
                "stepType": "macro_fixture.macro_step",
                "kind": "native",
                "implRef": "gwead-tests.macro_fixture.body"
            }],
            "actions": { "go": {
                "steps": [{"id": "s", "type": "macro_fixture.macro_step"}],
                "resultMapping": { "out": { "path": "$", "source": "s" } }
            } },
        })
        .to_string(),
    )
    .expect("registers on the free path — the middle segment is its own name");

    let k = k.into_arc();
    let out = k
        .execute("macro_fixture", "go", json!({}))
        .run()
        .await
        .expect("runs")
        .output;
    assert_eq!(out, json!({"out": MARKER}));
}
