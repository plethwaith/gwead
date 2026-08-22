//! Strict parsing of nested sub-block step arrays at
//! `register_plugin` time.
//!
//! A typo'd step inside `try`/`catch`/`finally`, `parallel.branches[*]`,
//! `ifs[*].then`, or `for_each`/`repeat.steps` must never be
//! silently skipped by the validation walker or silently dropped by the
//! runtime — a step that just never runs. Registration rejects the
//! manifest with the action / parent step / key path and the underlying
//! serde error.

use gwead::kernel::types::PluginManifest;
use gwead::kernel::{Kernel, KernelConfig};
use serde_json::{Value, json};

fn manifest_json(steps: Value) -> Value {
    json!({
        "name": "p",
        "version": "0.0.1",
        "actions": { "go": { "steps": steps } }
    })
}

/// Register through the struct entry point, which the load-time
/// meta-schema doesn't guard — these tests pin the kernel walker's own
/// path-naming errors. (The JSON entry points reject the same shapes
/// earlier, at the meta-schema layer; `register_err` asserts that too.)
fn register_err(steps: Value) -> String {
    let manifest = manifest_json(steps);

    let mut kernel = Kernel::boot(KernelConfig::default()).expect("kernel boots");
    kernel
        .register_plugin_from_json(&manifest.to_string())
        .expect_err("malformed sub-block step must be rejected at the JSON entry point");

    let parsed: PluginManifest =
        serde_json::from_value(manifest).expect("top-level manifest shape parses");
    let mut kernel = Kernel::boot(KernelConfig::default()).expect("kernel boots");
    kernel
        .register_plugin(parsed)
        .expect_err("malformed sub-block step must be rejected")
        .to_string()
}

fn register_ok(steps: Value) {
    let mut kernel = Kernel::boot(KernelConfig::default()).expect("kernel boots");
    kernel
        .register_plugin_from_json(&manifest_json(steps).to_string())
        .expect("valid manifest must register");
}

/// A step that fails StepDef parsing — `type` is required.
fn missing_type() -> Value {
    json!({ "id": "oops" })
}

#[test]
fn malformed_step_in_try_body_rejected() {
    let msg = register_err(json!([
        {"id": "guard", "type": "try", "params": {"try": [ {"id": "ok1", "type": "let", "params": {"value": 1}}, missing_type() ], "catch": []}}
    ]));
    assert!(
        msg.contains("step 'guard'") && msg.contains("try[1]"),
        "error must name the failing path: {msg}"
    );
}

#[test]
fn malformed_step_in_catch_rejected() {
    let msg = register_err(json!([
        {"id": "guard", "type": "try", "params": {"try": [ {"id": "ok1", "type": "let", "params": {"value": 1}} ], "catch": [ missing_type() ]}}
    ]));
    assert!(
        msg.contains("step 'guard'") && msg.contains("catch[0]"),
        "error must name the failing path: {msg}"
    );
}

#[test]
fn malformed_step_in_finally_rejected() {
    let msg = register_err(json!([
        {"id": "guard", "type": "try", "params": {"try": [ {"id": "ok1", "type": "let", "params": {"value": 1}} ], "finally": [ missing_type() ]}}
    ]));
    assert!(
        msg.contains("step 'guard'") && msg.contains("finally[0]"),
        "error must name the failing path: {msg}"
    );
}

#[test]
fn malformed_step_in_parallel_branch_rejected_with_branch_index() {
    let msg = register_err(json!([
        {"id": "fan", "type": "parallel", "params": {"branches": [
              [ {"id": "ok1", "type": "let", "params": {"value": 1}} ],
              [ missing_type() ],
          ]}}
    ]));
    assert!(
        msg.contains("step 'fan'") && msg.contains("branches[1]"),
        "error must name the branch index: {msg}"
    );
}

#[test]
fn non_array_parallel_branch_rejected() {
    // A non-array branch is a registration error — never silently
    // treated as an empty branch.
    let msg = register_err(json!([
        {"id": "fan", "type": "parallel", "params": {"branches": [
              [ {"id": "ok1", "type": "let", "params": {"value": 1}} ],
              {"id": "not-a-branch", "type": "let", "params": {"value": 2}},
          ]}}
    ]));
    assert!(
        msg.contains("branches[1]") && msg.contains("array"),
        "error must point at the non-array branch: {msg}"
    );
}

#[test]
fn malformed_step_in_if_then_rejected() {
    let msg = register_err(json!([
        {"id": "route", "type": "ifs", "params": {"ifs": [
              { "test": "true", "then": [ {"id": "ok1", "type": "let", "params": {"value": 1}} ] },
              { "test": "false", "then": [ missing_type() ] },
          ]}}
    ]));
    assert!(
        msg.contains("step 'route'") && msg.contains("ifs[1].then[0]"),
        "error must name the branch + index: {msg}"
    );
}

#[test]
fn malformed_step_in_ifs_else_branch_rejected() {
    let msg = register_err(json!([
        {"id": "route", "type": "ifs", "params": {"ifs": [
            { "test": "true", "then": [ {"id": "ok1", "type": "let", "params": {"value": 1}} ] },
            { "then": [ missing_type() ] }
        ]}}
    ]));
    assert!(
        msg.contains("step 'route'") && msg.contains("ifs[1].then[0]"),
        "error must name the failing path: {msg}"
    );
}

/// A branch with no `test` always matches, so anything after it is
/// unreachable. That is a manifest bug, and it is refused at load
/// rather than left as silently dead steps.
#[test]
fn untested_branch_not_last_rejected() {
    let msg = register_err(json!([
        {"id": "route", "type": "ifs", "params": {"ifs": [
            { "then": [ {"id": "e", "type": "let", "params": {"value": 0}} ] },
            { "test": "true", "then": [ {"id": "t", "type": "let", "params": {"value": 1}} ] }
        ]}}
    ]));
    assert!(
        msg.contains("step 'route'") && msg.contains("ifs[0]") && msg.contains("last"),
        "untested branch before a tested one must be rejected: {msg}"
    );
}

/// `test: null` is the same as omitting it — both spell the else
/// branch — so it is accepted in last position and refused elsewhere.
#[test]
fn null_test_is_else_branch() {
    register_ok(json!([
        {"id": "route", "type": "ifs", "params": {"ifs": [
            { "test": "false", "then": [ {"id": "t", "type": "let", "params": {"value": 1}} ] },
            { "test": null, "then": [ {"id": "e", "type": "let", "params": {"value": 2}} ] }
        ]}}
    ]));
    let msg = register_err(json!([
        {"id": "route", "type": "ifs", "params": {"ifs": [
            { "test": null, "then": [ {"id": "e", "type": "let", "params": {"value": 2}} ] },
            { "test": "false", "then": [ {"id": "t", "type": "let", "params": {"value": 1}} ] }
        ]}}
    ]));
    assert!(msg.contains("ifs[0]") && msg.contains("last"), "{msg}");
}

#[test]
fn ifs_missing_ifs_array_rejected() {
    let msg = register_err(json!([
        {"id": "route", "type": "ifs", "params": {}}
    ]));
    assert!(
        msg.contains("step 'route'") && msg.contains("`ifs` array"),
        "ifs step without an ifs array must be rejected: {msg}"
    );
}

#[test]
fn malformed_step_in_for_each_steps_rejected() {
    let msg = register_err(json!([
        {"id": "loop", "type": "for_each", "params": {"path": "$.items[*]", "steps": [ "not even an object" ]}}
    ]));
    assert!(
        msg.contains("step 'loop'") && msg.contains("steps[0]"),
        "error must name the failing path: {msg}"
    );
}

#[test]
fn deeply_nested_malformed_step_rejected() {
    // The walker recurses: a malformed step inside a try nested in a
    // parallel branch is still caught, with the inner step's path.
    let msg = register_err(json!([
        {"id": "fan", "type": "parallel", "params": {"branches": [
              [ {"id": "guard", "type": "try", "params": {"try": [ missing_type() ], "catch": []}} ],
          ]}}
    ]));
    assert!(
        msg.contains("step 'guard'") && msg.contains("try[0]"),
        "error must name the innermost failing path: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Wrong-typed sub-block keys (the same footgun one level up)
// ---------------------------------------------------------------------------

#[test]
fn try_body_as_object_instead_of_array_rejected() {
    // The easy mistake: forgotten array brackets must not
    // turn the whole try body into a silent no-op.
    let msg = register_err(json!([
        {"id": "guard", "type": "try", "params": {"try": {"id": "body", "type": "let", "params": {"value": 1}}, "catch": []}}
    ]));
    assert!(
        msg.contains("step 'guard'") && msg.contains("try") && msg.contains("array"),
        "wrong-typed try body must be rejected: {msg}"
    );
}

#[test]
fn test_as_non_string_rejected() {
    let msg = register_err(json!([
        {"id": "route", "type": "ifs", "params": {"ifs": [ { "test": 42, "then": [ {"id": "t", "type": "let", "params": {"value": 1}} ] } ]}}
    ]));
    assert!(
        msg.contains("step 'route'") && msg.contains("ifs[0].test") && msg.contains("string"),
        "wrong-typed test must be rejected: {msg}"
    );
}

#[test]
fn ifs_as_object_rejected() {
    let msg = register_err(json!([
        {"id": "route", "type": "ifs", "params": {"ifs": { "test": "true", "then": [] }}}
    ]));
    assert!(
        msg.contains("step 'route'") && msg.contains("ifs"),
        "wrong-typed ifs must be rejected: {msg}"
    );
}

#[test]
fn non_object_ifs_entry_rejected() {
    let msg = register_err(json!([
        {"id": "route", "type": "ifs", "params": {"ifs": [ "not a branch object" ]}}
    ]));
    assert!(
        msg.contains("ifs[0]") && msg.contains("branch object"),
        "non-object ifs entry must be rejected: {msg}"
    );
}

#[test]
fn then_as_object_rejected() {
    let msg = register_err(json!([
        {"id": "route", "type": "ifs", "params": {"ifs": [ { "test": "true", "then": {"id": "t", "type": "let", "params": {"value": 1}} } ]}}
    ]));
    assert!(
        msg.contains("ifs[0].then") && msg.contains("array"),
        "wrong-typed then must be rejected: {msg}"
    );
}

#[test]
fn for_each_steps_as_object_rejected() {
    let msg = register_err(json!([
        {"id": "loop", "type": "for_each", "params": {"path": "$.items[*]", "steps": {"id": "v", "type": "let", "params": {"value": 1}}}}
    ]));
    assert!(
        msg.contains("step 'loop'") && msg.contains("steps") && msg.contains("array"),
        "wrong-typed steps must be rejected: {msg}"
    );
}

#[test]
fn branches_as_object_rejected() {
    let msg = register_err(json!([
        {"id": "fan", "type": "parallel", "params": {"branches": { "0": [ {"id": "b", "type": "let", "params": {"value": 1}} ] }}}
    ]));
    assert!(
        msg.contains("step 'fan'") && msg.contains("branches") && msg.contains("array"),
        "wrong-typed branches must be rejected: {msg}"
    );
}

#[test]
fn valid_manifest_with_every_block_type_registers() {
    register_ok(json!([
        {"id": "loop", "type": "for_each", "params": {"path": "$.items[*]", "steps": [ {"id": "v", "type": "let", "params": {"value": "{{$item}}"}} ]}},
        {"id": "route", "type": "ifs", "params": {"ifs": [
            { "test": "true", "then": [ {"id": "t", "type": "let", "params": {"value": 1}} ] },
            { "then": [ {"id": "e", "type": "let", "params": {"value": 2}} ] }
        ]}},
        {"id": "guard", "type": "try", "params": {"try": [ {"id": "body", "type": "let", "params": {"value": 3}} ], "catch": [ {"id": "rec", "type": "let", "params": {"value": 4}} ], "finally": [ {"id": "fin", "type": "let", "params": {"value": 5}} ]}},
        {"id": "fan", "type": "parallel", "params": {"branches": [
              [ {"id": "b0", "type": "let", "params": {"value": 6}} ],
              [ {"id": "b1", "type": "let", "params": {"value": 7}} ],
          ]}}
    ]));
}

/// A `script` step must name its language. The kernel is
/// language-agnostic and ships no runtime, so there is no default to
/// fall back to; an omitted `language` is refused at registration on
/// both entry points rather than silently routed anywhere.
#[test]
fn script_step_without_language_rejected() {
    let msg = register_err(json!([
        {"id": "s", "type": "script", "params": {"source": "return 1"}}
    ]));
    assert!(
        msg.contains("step 's'") && msg.contains("`language`"),
        "missing language must be rejected by name: {msg}"
    );
}
