//! DAG construction and validation for action step graphs.
//!
//! Actions execute as a true DAG built from the dependency relation
//! `step B reads from step A's output`, rather than as a flat
//! linear-sequential step list.
//!
//! Dependencies are extracted by scanning each step's parameters for
//! `$steps.<id>` references — bare in a `path` or `test` expression, or
//! inside a `{{$steps.<id>.…}}` template. Both spellings contain the
//! same `$steps.` token, so one scan covers both.
//!
//! A `{{steps.<id>}}` template **without** the `$` is not a reference
//! form: the expression parser has no such root, so it renders as the
//! empty string at execution. Building a dependency edge from it would
//! order the steps correctly and then hand the consumer blank data, so
//! it is rejected here at plan time instead — see
//! [`DagError::UnrootedStepsReference`].
//!
//! Validation is run at plugin-registration time so misconfigured manifests
//! never reach the runtime.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use super::types::{Action, StepDef};

/// Matches `$steps.<id>` anywhere in a string — bare or inside a
/// `{{…}}` template. The DSL grammar lets path segments follow, but for
/// dep extraction we only need the step id. The id class is exactly the
/// DSL's `ident` production — a leading letter or `_`, then letters,
/// digits, `_` and `-` — which is also what registration holds every
/// step id to ([`NameKind::StepId`](super::identity::NameKind::StepId)).
/// So the regex always captures the whole id: a narrower class would
/// extract `fetch` from `$steps.fetch-data` (a spurious unknown-step
/// rejection, or a silent wrong edge when a step called `fetch`
/// exists), and nothing wider can be registered.
static DSL_REF_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$steps\.([A-Za-z_][A-Za-z0-9_-]*)").unwrap());

/// Matches a `{{ steps.… }}` template missing its `$` — not a reference
/// form; see the module docs.
static UNROOTED_TMPL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{\{\s*steps\.").unwrap());

/// Errors surfaced while building or validating a step DAG.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DagError {
    #[error("duplicate step id: '{0}'")]
    DuplicateStepId(String),

    #[error("step '{from}' references unknown step '{to}'")]
    UnknownStepRef { from: String, to: String },

    #[error(
        "step '{from}' references step '{to}' which appears later in the manifest (forward references are not allowed)"
    )]
    ForwardRef { from: String, to: String },

    #[error("step '{0}' references itself")]
    SelfRef(String),

    #[error("step graph contains a cycle involving: {0}")]
    Cycle(String),

    /// A `{{steps.<id>…}}` template without the `$`. Not a reference
    /// form — it renders as the empty string — so it is refused rather
    /// than silently ordered-then-blanked.
    #[error(
        "step '{step}' uses `{{{{steps.…}}}}` without the `$`: write `{{{{$steps.<id>.result…}}}}`. \
         The unrooted form is not a reference and would render as an empty string"
    )]
    UnrootedStepsReference { step: String },
}

/// A precomputed plan for executing an action's steps in DAG order.
///
/// `waves` is a topological layering: every step in `waves[i]` has all of its
/// dependencies satisfied by some earlier wave, and steps within a wave have
/// no dependency on each other (they may run in parallel).
///
/// `deps` retains the per-step dependency list for runtime lookups (e.g.,
/// detecting stream fan-out by counting how many later steps read a given
/// step's output).
#[derive(Debug, Clone)]
pub struct DagPlan {
    /// Topologically layered execution order. `waves[0]` are the sources.
    pub waves: Vec<Vec<usize>>,
    /// Per-step dependency set (step indices, not ids).
    pub deps: Vec<Vec<usize>>,
    /// Per-step downstream consumers (inverse of `deps`).
    pub consumers: Vec<Vec<usize>>,
}

impl DagPlan {
    /// Number of steps in the plan.
    pub fn step_count(&self) -> usize {
        self.deps.len()
    }

    /// True when the plan executes strictly one step at a time — i.e., every
    /// wave has exactly one step. Useful for opting out of parallel scheduling
    /// overhead when nothing in the manifest can actually run in parallel.
    pub fn is_linear(&self) -> bool {
        self.waves.iter().all(|w| w.len() == 1)
    }
}

/// Build the execution plan for an action's step sequence.
///
/// Validates step id uniqueness, resolves dep references, rejects unknown
/// refs / forward refs / cycles, and emits the topological wave layering.
pub fn build_plan(action: &Action) -> Result<DagPlan, DagError> {
    // 1. Index step ids and check uniqueness.
    let mut id_to_index: HashMap<&str, usize> = HashMap::with_capacity(action.steps.len());
    for (i, step) in action.steps.iter().enumerate() {
        if id_to_index.insert(step.id.as_str(), i).is_some() {
            return Err(DagError::DuplicateStepId(step.id.clone()));
        }
    }

    // 2. Extract deps per step and validate they point to known, earlier steps.
    let n = action.steps.len();
    let mut deps: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut consumers: Vec<Vec<usize>> = vec![Vec::new(); n];

    for (i, step) in action.steps.iter().enumerate() {
        if contains_unrooted_steps_template(&step.params) {
            return Err(DagError::UnrootedStepsReference {
                step: step.id.clone(),
            });
        }
        let mut seen: BTreeSet<usize> = BTreeSet::new();
        for ref_id in extract_step_deps(step) {
            if ref_id == step.id {
                return Err(DagError::SelfRef(step.id.clone()));
            }
            let Some(&target) = id_to_index.get(ref_id.as_str()) else {
                return Err(DagError::UnknownStepRef {
                    from: step.id.clone(),
                    to: ref_id,
                });
            };
            if target > i {
                return Err(DagError::ForwardRef {
                    from: step.id.clone(),
                    to: ref_id,
                });
            }
            if seen.insert(target) {
                deps[i].push(target);
                consumers[target].push(i);
            }
        }
    }

    // 3. Topological sort by repeatedly draining steps whose deps are
    //    already scheduled. Because we reject forward refs at extraction
    //    time, a cycle would manifest as steps that never get scheduled —
    //    but that can only happen if the dep graph references later steps,
    //    which the extraction pass already excluded. The check is kept
    //    so that relaxing the forward-ref rule cannot silently accept
    //    cycles.
    let waves = layer_into_waves(&deps, &action.steps)?;

    Ok(DagPlan {
        waves,
        deps,
        consumers,
    })
}

fn layer_into_waves(deps: &[Vec<usize>], steps: &[StepDef]) -> Result<Vec<Vec<usize>>, DagError> {
    let n = deps.len();
    let mut scheduled: Vec<bool> = vec![false; n];
    let mut waves: Vec<Vec<usize>> = Vec::new();
    let mut remaining = n;

    while remaining > 0 {
        let mut wave: Vec<usize> = Vec::new();
        for (i, step_deps) in deps.iter().enumerate() {
            if scheduled[i] {
                continue;
            }
            if step_deps.iter().all(|&d| scheduled[d]) {
                wave.push(i);
            }
        }
        if wave.is_empty() {
            let stuck: Vec<&str> = (0..n)
                .filter(|i| !scheduled[*i])
                .map(|i| steps[i].id.as_str())
                .collect();
            return Err(DagError::Cycle(stuck.join(", ")));
        }
        for &i in &wave {
            scheduled[i] = true;
        }
        remaining -= wave.len();
        waves.push(wave);
    }

    Ok(waves)
}

/// Extract the set of step ids referenced by a single step's params, merged
/// with any explicit `depends_on` declarations.
///
/// Returns ids in source-order with duplicates removed (preserving first
/// occurrence). The caller resolves these to step indices.
///
/// Control-flow step types (`ifs`, `for_each`, `repeat`, `try`, `parallel`)
/// carry inner step bodies whose step ids are *scoped-local* — they're
/// spliced onto `action.steps` at runtime, not visible from outer scope.
///
/// There is one rule, applied to every step type: a reference is an
/// outer-scope dependency unless it names a step defined inside this
/// step's own bodies. Scoped-local refs resolve at runtime against the
/// spliced `step_results`, so surfacing them here would reject natural
/// manifests with `UnknownStepRef` at registration. Everything else is a
/// real edge — including a ref from *inside* a body out to an earlier
/// step, which must be ordered or the body reads an unwritten result.
pub fn extract_step_deps(step: &StepDef) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    // Explicit declarations come first so a manifest's intent is preserved
    // in the visible order. Useful for `script` steps that read step results
    // through the script runtime's own API rather than via templated params.
    for dep in &step.depends_on {
        push_unique(dep, &mut seen, &mut out);
    }

    // Note the step's own id is NOT excluded here: a step referencing
    // itself — including from inside one of its own bodies — is a real
    // cycle, and `build_plan` reports it as `DagError::SelfRef`. Dropping
    // it would trade a loud rejection for a silently missing edge.
    let mut scoped_local: HashSet<String> = HashSet::new();
    collect_inner_step_ids(&step.params, &mut scoped_local);

    let mut local_seen: HashSet<String> = HashSet::new();
    let mut local_out: Vec<String> = Vec::new();
    scan_value(&step.params, &mut local_seen, &mut local_out);
    for id in local_out {
        if scoped_local.contains(&id) {
            continue;
        }
        push_unique(&id, &mut seen, &mut out);
    }
    out
}

/// Keys whose value is an array of inner step definitions. `ifs` (per-branch
/// objects) and `branches` (array *of arrays*) have their own shapes and are
/// handled separately in [`collect_inner_step_ids`].
const INNER_BODY_KEYS: &[&str] = &[
    "steps",   // for_each, repeat
    "then",    // ifs (per-branch)
    "try",     // try
    "catch",   // try
    "finally", // try
];

/// Collect every step id defined inside `params`, at any depth.
///
/// Inner steps may themselves be control-flow steps, so this recurses:
/// a `parallel` branch holding a `try` holding a `for_each` contributes
/// all three levels' ids. Body keys live under a step's `params`, so a
/// nested step's bodies are reached through its `params` object.
fn collect_inner_step_ids(params: &Value, out: &mut HashSet<String>) {
    // `ifs[]` holds per-branch objects, each carrying its own `then` body.
    if let Some(arr) = params.get("ifs").and_then(|v| v.as_array()) {
        for branch in arr {
            collect_inner_step_ids(branch, out);
        }
    }
    // `branches[]` is an array of step arrays.
    if let Some(arr) = params.get("branches").and_then(|v| v.as_array()) {
        for branch in arr {
            collect_step_ids_in_array(branch, out);
        }
    }
    for key in INNER_BODY_KEYS {
        if let Some(v) = params.get(*key) {
            collect_step_ids_in_array(v, out);
        }
    }
}

/// Add the ids of an array of step definitions, recursing into each one's
/// own inner bodies. A non-array value is ignored: `try`/`catch` and the
/// rest are arrays by schema, and a malformed manifest is rejected by
/// validation before it reaches the DAG.
fn collect_step_ids_in_array(v: &Value, out: &mut HashSet<String>) {
    let Some(arr) = v.as_array() else {
        return;
    };
    for item in arr {
        if let Some(id) = item.get("id").and_then(|i| i.as_str()) {
            out.insert(id.to_string());
        }
        // A nested step's own bodies are under its `params`.
        if let Some(params) = item.get("params") {
            collect_inner_step_ids(params, out);
        }
    }
}

// Only `$steps.<id>` (bare or templated) creates dependency edges. References
// rooted at `$input`, `$config`, `$trigger` and `$vars` are deliberately
// ignored because none of them is a step output: input/config/trigger are
// loaded before any step runs, and variables are linearly visible by
// manifest order (`store_to_variable` writes a value that any later step can
// read via `{{$vars.x}}`). Object *keys* are not scanned because the
// reference grammar never uses them as a host for refs.
fn scan_value(v: &Value, seen: &mut HashSet<String>, out: &mut Vec<String>) {
    match v {
        Value::String(s) => scan_string(s, seen, out),
        Value::Array(arr) => {
            for item in arr {
                scan_value(item, seen, out);
            }
        }
        Value::Object(map) => {
            for val in map.values() {
                scan_value(val, seen, out);
            }
        }
        _ => {}
    }
}

fn scan_string(s: &str, seen: &mut HashSet<String>, out: &mut Vec<String>) {
    for caps in DSL_REF_RE.captures_iter(s) {
        push_unique(&caps[1], seen, out);
    }
}

/// Whether any string in `v` carries a `{{steps.…}}` template missing
/// its `$`. Same walk as [`scan_value`], including nested bodies.
fn contains_unrooted_steps_template(v: &Value) -> bool {
    match v {
        Value::String(s) => UNROOTED_TMPL_RE.is_match(s),
        Value::Array(arr) => arr.iter().any(contains_unrooted_steps_template),
        Value::Object(map) => map.values().any(contains_unrooted_steps_template),
        _ => false,
    }
}

fn push_unique(id: &str, seen: &mut HashSet<String>, out: &mut Vec<String>) {
    if seen.insert(id.to_string()) {
        out.push(id.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn step(id: &str, params: Value) -> StepDef {
        StepDef {
            id: id.to_string(),
            step_type: "noop".to_string(),
            params,
            store_to_variable: None,
            depends_on: Vec::new(),
            long_running: false,
        }
    }

    fn step_with_deps(id: &str, params: Value, depends_on: Vec<&str>) -> StepDef {
        StepDef {
            id: id.to_string(),
            step_type: "noop".to_string(),
            params,
            store_to_variable: None,
            depends_on: depends_on.into_iter().map(String::from).collect(),
            long_running: false,
        }
    }

    fn action(steps: Vec<StepDef>) -> Action {
        Action {
            description: None,
            steps,
            results_path: None,
            result_mapping: Default::default(),
            input_schema: None,
            output_schema: None,
            subscribes_to: Vec::new(),
            continuous: false,
            interval_ms: 0,
            parallel_waves: false,
            dataflow: false,
            wallclock_timeout_ms: None,
            tool: None,
        }
    }

    #[test]
    fn extract_dsl_ref_from_string() {
        let s = step("b", json!({ "url": "http://x/{{x}}?id=$steps.a.id" }));
        assert_eq!(extract_step_deps(&s), vec!["a"]);
    }

    /// A step inside a `try` body referencing its sibling (scoped-local,
    /// spliced at runtime) must not surface as an outer-scope
    /// dependency — that would reject the manifest with UnknownStepRef
    /// at registration.
    #[test]
    fn try_inner_sibling_refs_are_not_outer_deps() {
        let mut s = step(
            "guarded",
            json!({
                "try": [
                    { "id": "fetch", "type": "noop", "params": {} },
                    { "id": "use_it", "type": "noop",
                      "params": { "v": "{{$steps.fetch.result}}" } },
                ],
                "catch": [
                    { "id": "recover", "type": "noop",
                      "params": { "v": "$steps.fetch.status" } },
                ],
                "finally": [
                    { "id": "cleanup", "type": "noop", "params": {} },
                ],
            }),
        );
        s.step_type = "try".to_string();
        assert!(extract_step_deps(&s).is_empty());
        // And the whole plan builds — no UnknownStepRef for `fetch`.
        build_plan(&action(vec![s])).expect("try with intra-body sibling refs plans");
    }

    /// Same scoping rule for `parallel` branches.
    #[test]
    fn parallel_intra_branch_refs_are_not_outer_deps() {
        let mut s = step(
            "fan",
            json!({
                "branches": [
                    [
                        { "id": "a1", "type": "noop", "params": {} },
                        { "id": "a2", "type": "noop",
                          "params": { "v": "$steps.a1.result" } },
                    ],
                    [
                        { "id": "b1", "type": "noop", "params": {} },
                    ],
                ],
            }),
        );
        s.step_type = "parallel".to_string();
        assert!(extract_step_deps(&s).is_empty());
        build_plan(&action(vec![s])).expect("parallel with intra-branch refs plans");
    }

    /// The other direction: a body step reaching OUT to an earlier step
    /// must produce an edge on the containing construct. Without it the
    /// construct is scheduled in the producer's own wave under
    /// `parallelWaves` and the body reads an unwritten result — a silent
    /// wrong answer, not an error.
    #[test]
    fn try_body_outer_ref_creates_edge() {
        let producer = step("producer", json!({}));
        let mut guarded = step(
            "guarded",
            json!({
                "try": [
                    { "id": "reader", "type": "noop",
                      "params": { "v": "{{$steps.producer.result.value}}" } },
                ],
            }),
        );
        guarded.step_type = "try".to_string();
        assert_eq!(extract_step_deps(&guarded), vec!["producer"]);
        let plan = build_plan(&action(vec![producer, guarded])).expect("plans");
        assert_eq!(plan.deps[1], vec![0], "try must depend on the producer");
        assert!(plan.is_linear(), "the two steps cannot share a wave");
    }

    /// Same for a `parallel` branch body.
    #[test]
    fn parallel_branch_outer_ref_creates_edge() {
        let producer = step("producer", json!({}));
        let mut fan = step(
            "fan",
            json!({
                "branches": [
                    [ { "id": "reader", "type": "noop",
                        "params": { "v": "$steps.producer.result.value" } } ],
                ],
            }),
        );
        fan.step_type = "parallel".to_string();
        assert_eq!(extract_step_deps(&fan), vec!["producer"]);
        assert_eq!(
            build_plan(&action(vec![producer, fan]))
                .expect("plans")
                .deps[1],
            vec![0]
        );
    }

    /// The rule is not special to try/parallel: an `ifs` branch body
    /// reaching out to an earlier step has the same requirement.
    #[test]
    fn if_branch_body_outer_ref_creates_edge() {
        let producer = step("producer", json!({}));
        let mut branch = step(
            "choose",
            json!({
                "ifs": [
                    { "test": "true",
                      "then": [ { "id": "inner", "type": "noop",
                                  "params": { "v": "$steps.producer.result" } } ] },
                ],
            }),
        );
        branch.step_type = "ifs".to_string();
        assert_eq!(extract_step_deps(&branch), vec!["producer"]);
        assert_eq!(
            build_plan(&action(vec![producer, branch]))
                .expect("plans")
                .deps[1],
            vec![0]
        );
    }

    /// Nesting: ids are scoped-local at every depth, so an inner `try`
    /// inside a `parallel` branch contributes its own ids (no edge) while
    /// its outer ref still surfaces.
    #[test]
    fn nested_bodies_scope_locally_but_outer_refs_surface() {
        let producer = step("producer", json!({}));
        let mut fan = step(
            "fan",
            json!({
                "branches": [
                    [
                        { "id": "guarded", "type": "try", "params": {
                          "try": [
                              { "id": "deep", "type": "noop", "params": {} },
                              { "id": "reads_sibling", "type": "noop",
                                "params": { "v": "$steps.deep.result" } },
                              { "id": "reads_outer", "type": "noop",
                                "params": { "v": "$steps.producer.result" } },
                          ] } },
                    ],
                ],
            }),
        );
        fan.step_type = "parallel".to_string();
        // `deep` is scoped-local even two levels down; `producer` is not.
        assert_eq!(extract_step_deps(&fan), vec!["producer"]);
        assert_eq!(
            build_plan(&action(vec![producer, fan]))
                .expect("plans")
                .deps[1],
            vec![0]
        );
    }

    /// A step referencing itself from inside its own body is a real
    /// cycle and must be rejected, not silently dropped as scoped-local.
    #[test]
    fn self_ref_from_inside_body_still_rejected() {
        let mut guarded = step(
            "guarded",
            json!({
                "try": [
                    { "id": "inner", "type": "noop",
                      "params": { "v": "$steps.guarded.result" } },
                ],
            }),
        );
        guarded.step_type = "try".to_string();
        assert_eq!(
            build_plan(&action(vec![guarded])).unwrap_err(),
            DagError::SelfRef("guarded".to_string())
        );
    }

    /// Explicit `depends_on` on a try/parallel step still creates the
    /// outer edge, and is reported ahead of any params-derived ref.
    #[test]
    fn try_explicit_depends_on_still_counts() {
        let first = step("first", json!({}));
        let mut guarded = step_with_deps("guarded", json!({ "try": [] }), vec!["first"]);
        guarded.step_type = "try".to_string();
        assert_eq!(extract_step_deps(&guarded), vec!["first"]);
        let plan = build_plan(&action(vec![first, guarded])).expect("plans");
        assert_eq!(plan.deps[1], vec![0]);
    }

    #[test]
    fn extract_template_ref_from_string() {
        let s = step("b", json!({ "url": "http://x/{{ $steps.a.id }}" }));
        assert_eq!(extract_step_deps(&s), vec!["a"]);
    }

    #[test]
    fn extract_dedupes_within_step() {
        let s = step(
            "b",
            json!({
                "url": "http://x/{{$steps.a.id}}/$steps.a.name",
                "headers": { "X-Ref": "$steps.a.token" }
            }),
        );
        assert_eq!(extract_step_deps(&s), vec!["a"]);
    }

    #[test]
    fn extract_multiple_distinct_refs() {
        let s = step(
            "z",
            json!({
                "body": { "x": "$steps.a.val", "y": "{{$steps.b.val}}" }
            }),
        );
        let deps = extract_step_deps(&s);
        let set: HashSet<_> = deps.iter().map(|s| s.as_str()).collect();
        assert_eq!(set, HashSet::from(["a", "b"]));
    }

    #[test]
    fn extract_ignores_other_namespaces() {
        let s = step(
            "b",
            json!({
                "url": "{{config.host}}/$input.q?trigger=$trigger.id"
            }),
        );
        assert!(extract_step_deps(&s).is_empty());
    }

    #[test]
    fn vars_ref_creates_no_dep_edge() {
        // `$vars.x` is an action-local variable, linearly visible by
        // manifest order — it must NOT create a DAG dependency edge (only
        // `$steps.<id>` does). This is what lets a branch write
        // `storeToVariable` and an outer `for_each` read `$vars.X` without
        // an illegal cross-scope reference.
        let s = step("b", json!({ "path": "$vars.imagePaths" }));
        assert!(extract_step_deps(&s).is_empty());
    }

    /// The id charset matches the DSL's `ident`: `-` is legal in a step
    /// id, so `$steps.fetch-data` must extract `fetch-data`, not `fetch`.
    #[test]
    fn hyphenated_step_ids_extract_whole() {
        let s = step("c", json!({ "v": "$steps.fetch-data.result" }));
        assert_eq!(extract_step_deps(&s), vec!["fetch-data"]);
        let s = step("c", json!({ "v": "{{$steps.fetch-data.result}}" }));
        assert_eq!(extract_step_deps(&s), vec!["fetch-data"]);
    }

    /// `{{steps.x}}` without the `$` is not a reference form — it would
    /// render as `""` — so the plan refuses it rather than ordering the
    /// steps and then handing the consumer blank data.
    #[test]
    fn unrooted_steps_template_is_rejected() {
        let a = action(vec![
            step("a", json!({})),
            step("b", json!({ "v": "{{steps.a.result}}" })),
        ]);
        assert_eq!(
            build_plan(&a).unwrap_err(),
            DagError::UnrootedStepsReference {
                step: "b".to_string()
            }
        );
        // Nested bodies are scanned too.
        let a = action(vec![
            step("a", json!({})),
            step(
                "t",
                json!({ "try": [{"id": "in", "type": "let", "params": {"value": "{{ steps.a.result }}"}}] }),
            ),
        ]);
        assert!(matches!(
            build_plan(&a),
            Err(DagError::UnrootedStepsReference { .. })
        ));
    }

    #[test]
    fn build_plan_linear_two_steps() {
        let a = action(vec![
            step("a", json!({ "url": "http://x" })),
            step("b", json!({ "url": "{{$steps.a.url}}" })),
        ]);
        let plan = build_plan(&a).unwrap();
        assert_eq!(plan.waves, vec![vec![0], vec![1]]);
        assert!(plan.is_linear());
        assert_eq!(plan.deps[1], vec![0]);
        assert_eq!(plan.consumers[0], vec![1]);
    }

    #[test]
    fn build_plan_parallel_branches() {
        // a → b, a → c, [b, c] → d
        let a = action(vec![
            step("a", json!({ "url": "http://root" })),
            step("b", json!({ "url": "$steps.a.url/b" })),
            step("c", json!({ "url": "$steps.a.url/c" })),
            step(
                "d",
                json!({ "body": { "x": "$steps.b.val", "y": "$steps.c.val" } }),
            ),
        ]);
        let plan = build_plan(&a).unwrap();
        assert_eq!(plan.waves, vec![vec![0], vec![1, 2], vec![3]]);
        assert!(!plan.is_linear());
    }

    #[test]
    fn build_plan_no_refs_is_all_parallel_first_wave() {
        // Three independent steps with no references — they all sit in wave 0.
        let a = action(vec![
            step("a", json!({ "url": "http://a" })),
            step("b", json!({ "url": "http://b" })),
            step("c", json!({ "url": "http://c" })),
        ]);
        let plan = build_plan(&a).unwrap();
        assert_eq!(plan.waves, vec![vec![0, 1, 2]]);
    }

    #[test]
    fn duplicate_step_id_rejected() {
        let a = action(vec![step("a", json!({})), step("a", json!({}))]);
        assert_eq!(
            build_plan(&a).unwrap_err(),
            DagError::DuplicateStepId("a".to_string())
        );
    }

    #[test]
    fn unknown_step_ref_rejected() {
        let a = action(vec![step("a", json!({ "url": "$steps.ghost.x" }))]);
        assert_eq!(
            build_plan(&a).unwrap_err(),
            DagError::UnknownStepRef {
                from: "a".to_string(),
                to: "ghost".to_string()
            }
        );
    }

    #[test]
    fn forward_ref_rejected() {
        let a = action(vec![
            step("a", json!({ "url": "$steps.b.x" })),
            step("b", json!({ "url": "http://x" })),
        ]);
        assert_eq!(
            build_plan(&a).unwrap_err(),
            DagError::ForwardRef {
                from: "a".to_string(),
                to: "b".to_string()
            }
        );
    }

    #[test]
    fn explicit_depends_on_creates_dep_edge() {
        // No scannable refs anywhere — drain's dep on forward is only
        // expressible via depends_on (a script reading step results
        // through its runtime's own API).
        let a = action(vec![
            step("fetch", json!({ "url": "http://x" })),
            step(
                "forward",
                json!({ "url": "http://y", "body": "{{$steps.fetch.result}}" }),
            ),
            step_with_deps(
                "drain",
                json!({ "language": "lua", "source": "args.steps.forward.result" }),
                vec!["forward"],
            ),
        ]);
        let plan = build_plan(&a).unwrap();
        assert_eq!(plan.waves, vec![vec![0], vec![1], vec![2]]);
    }

    #[test]
    fn depends_on_unknown_step_rejected() {
        let a = action(vec![step_with_deps("a", json!({}), vec!["ghost"])]);
        assert_eq!(
            build_plan(&a).unwrap_err(),
            DagError::UnknownStepRef {
                from: "a".to_string(),
                to: "ghost".to_string()
            }
        );
    }

    #[test]
    fn self_ref_rejected() {
        let a = action(vec![step("a", json!({ "url": "$steps.a.x" }))]);
        assert_eq!(
            build_plan(&a).unwrap_err(),
            DagError::SelfRef("a".to_string())
        );
    }
}
