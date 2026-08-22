//! A dataflow step waits for the values it declared a dependency on.
//!
//! It is tempting for a dataflow scheduler to spawn every step at once
//! and ignore `plan.deps` entirely, on the reasoning that dataflow
//! consumers synchronise through stream reads. That is true of a
//! dependency on a **long-running** producer — its handle is
//! pre-provisioned before any task spawns — and false of a dependency
//! on an ordinary step, whose result is a value that does not exist
//! until it has run.
//!
//! A scheduler that ignored value dependencies would make the identical
//! manifest yield `42` in wave mode and `""` under `dataflow: true`.
//! Deterministically, with no error, from a `dependsOn` the author
//! wrote down and the scheduler read. A silent wrong answer, which is
//! worse than a loud one.
//!
//! The guarantee is a scheduling rule, not a check: a step is spawned once
//! its non-long-running dependencies have merged, forking the canonical
//! state *after* the merge. Steps with no dependencies, or only
//! long-running ones, still all start at t=0 — so the pipeline shape
//! this scheduler exists to run is untouched, that being the shape with
//! no value dependencies in it.

use gwead::kernel::{Kernel, KernelConfig};
use serde_json::{Value, json};

/// Run the same action under both schedulers and return
/// `(wave_output, dataflow_output)`.
async fn both_modes(steps_json: impl Fn(bool) -> Value, mapping: Value) -> (Value, Value) {
    let mut outputs = Vec::new();
    for dataflow in [false, true] {
        let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
        let manifest = json!({
            "name": "p",
            "actions": { "go": {
                "dataflow": dataflow,
                "steps": steps_json(dataflow),
                "resultMapping": mapping,
            } }
        });
        k.register_plugin_from_json(&manifest.to_string())
            .expect("registers");
        let arc = k.into_arc();
        let result = arc
            .execute("p", "go", json!({}))
            .with_config(&Value::Null)
            .run()
            .await
            .unwrap_or_else(|e| panic!("dataflow={dataflow} failed: {e}"));
        outputs.push(result.output);
    }
    (outputs.remove(0), outputs.remove(0))
}

/// The minimal case. A `longRunning` step is
/// present because it is what selects the dataflow scheduler's
/// interesting path; the assertion is about `a` and `b`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_declared_dependency_is_honoured_in_both_schedulers() {
    let (wave, dataflow) = both_modes(
        |is_dataflow| {
            let mut steps = vec![
                json!({"id": "a", "type": "let", "params": {"value": 42}}),
                json!({"id": "b", "type": "let", "params": {"value": "{{$steps.a.result}}"}, "dependsOn": ["a"]}),
            ];
            if is_dataflow {
                steps.insert(
                    0,
                    json!({"id": "prod", "type": "let", "params": {"value": "p"}, "longRunning": true}),
                );
            }
            json!(steps)
        },
        json!({"a": {"path": "$", "source": "a"}, "b": {"path": "$", "source": "b"}}),
    )
    .await;

    assert_eq!(wave["b"], json!(42), "wave mode honours the dependency");
    assert_eq!(
        dataflow["b"], wave["b"],
        "the two schedulers must agree; dataflow must not answer \"\""
    );
}

/// An implicit dependency — a `{{$steps.a.result}}` reference with no
/// `dependsOn` — is a real edge in the plan (the planner records it for
/// `try`/`parallel` bodies as well), so it must gate the spawn too. If
/// only explicit `dependsOn` were honoured, the rule would cover the
/// case authors write down and miss the case they don't.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_implicit_reference_gates_the_spawn_too() {
    let (wave, dataflow) = both_modes(
        |is_dataflow| {
            let mut steps = vec![
                json!({"id": "a", "type": "let", "params": {"value": "computed"}}),
                json!({"id": "b", "type": "let", "params": {"value": "saw-{{$steps.a.result}}"}}),
            ];
            if is_dataflow {
                steps.insert(
                    0,
                    json!({"id": "prod", "type": "let", "params": {"value": "p"}, "longRunning": true}),
                );
            }
            json!(steps)
        },
        json!({"b": {"path": "$", "source": "b"}}),
    )
    .await;

    assert_eq!(wave["b"], json!("saw-computed"));
    assert_eq!(
        dataflow["b"], wave["b"],
        "an inferred edge gates the spawn exactly like a declared one"
    );
}

/// Chained value dependencies: `c` waits on `b` waits on `a`. The
/// release of one step must be able to release the next, or a chain
/// deeper than one link would hang or resolve empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chain_of_value_dependencies_resolves_in_order() {
    let (wave, dataflow) = both_modes(
        |is_dataflow| {
            let mut steps = vec![
                json!({"id": "a", "type": "let", "params": {"value": "1"}}),
                json!({"id": "b", "type": "let", "params": {"value": "{{$steps.a.result}}2"}, "dependsOn": ["a"]}),
                json!({"id": "c", "type": "let", "params": {"value": "{{$steps.b.result}}3"}, "dependsOn": ["b"]}),
            ];
            if is_dataflow {
                steps.insert(
                    0,
                    json!({"id": "prod", "type": "let", "params": {"value": "p"}, "longRunning": true}),
                );
            }
            json!(steps)
        },
        json!({"c": {"path": "$", "source": "c"}}),
    )
    .await;

    assert_eq!(wave["c"], json!("123"));
    assert_eq!(dataflow["c"], wave["c"], "the chain resolved link by link");
}

/// Two independent steps both depending on one producer must each be
/// released by it — a fan-out on the release side, not just the first
/// consumer found.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_step_releases_every_consumer() {
    let (wave, dataflow) = both_modes(
        |is_dataflow| {
            let mut steps = vec![
                json!({"id": "a", "type": "let", "params": {"value": "x"}}),
                json!({"id": "b", "type": "let", "params": {"value": "b-{{$steps.a.result}}"}, "dependsOn": ["a"]}),
                json!({"id": "c", "type": "let", "params": {"value": "c-{{$steps.a.result}}"}, "dependsOn": ["a"]}),
            ];
            if is_dataflow {
                steps.insert(
                    0,
                    json!({"id": "prod", "type": "let", "params": {"value": "p"}, "longRunning": true}),
                );
            }
            json!(steps)
        },
        json!({"b": {"path": "$", "source": "b"}, "c": {"path": "$", "source": "c"}}),
    )
    .await;

    assert_eq!((&wave["b"], &wave["c"]), (&json!("b-x"), &json!("c-x")));
    assert_eq!(dataflow["b"], wave["b"]);
    assert_eq!(dataflow["c"], wave["c"]);
}

/// The property that must NOT regress: a consumer of a long-running
/// producer is not gated on it. Waiting for a producer to finish would
/// deadlock every streaming pipeline — the producer's whole point is
/// that it outlives its consumers' first read.
///
/// The producer here never completes on its own; the consumer reads the
/// pre-provisioned handle and the pipeline terminates. If long-running
/// deps were counted, this test would hang rather than fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_consumer_of_a_long_running_producer_still_starts_immediately() {
    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    k.register_plugin_from_json(
        &json!({
            "name": "p",
            "actions": { "go": {
                "dataflow": true,
                "steps": [
                    {"id": "prod", "type": "let", "params": {"value": "payload"}, "longRunning": true},
                    // Declares the dependency explicitly, which is the
                    // case that would deadlock if long-running deps were
                    // treated as value deps.
                    {"id": "cons", "type": "let", "params": {"value": "ran"}, "dependsOn": ["prod"]}
                ],
                "resultMapping": { "cons": {"path": "$", "source": "cons"} }
            } }
        })
        .to_string(),
    )
    .expect("registers");
    let arc = k.into_arc();

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        arc.execute("p", "go", json!({}))
            .with_config(&Value::Null)
            .run(),
    )
    .await
    .expect("must not hang — a long-running dep is satisfied by pre-provisioning")
    .expect("pipeline ran");

    assert_eq!(result.output["cons"], json!("ran"));
}
