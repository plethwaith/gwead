//! Static analysis of `invoke` step graphs across plugins.
//!
//! Paired structural+runtime cycle protection. This
//! module owns the *structural* check: walking the by-plugin-name edges
//! every registered action declares via `invoke` steps and rejecting any
//! cycle that would be statically guaranteed regardless of which plugin
//! fulfils a role. By-role edges are not statically resolvable (they
//! depend on which plugin the orchestrator selects) and skip this
//! check — the [`super::host_api::INVOKE_MAX_DEPTH`] runtime cap is
//! their safety net.
//!
//! The graph is `(plugin_name, action_name) → (plugin_name, action_name)*`.
//! Cycle detection uses an iterative DFS with explicit gray/black colouring:
//! no recursion, and the cycle's contributing nodes are carried back to
//! the caller for the error message.

use std::collections::HashMap;

use super::types::{Action, StepDef, StepReference, StepTypeDef};

/// One (plugin, action) tuple used as a graph node key.
pub type NodeRef = (String, String);

/// A statically-resolvable by-plugin invoke edge from one action into
/// another. By-role edges are not represented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokeEdge {
    pub from: NodeRef,
    pub to: NodeRef,
}

/// Errors from structural cycle detection.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvokeCycleError {
    #[error(
        "invoke graph contains a structural cycle through by-plugin edges: {}",
        format_cycle(.0)
    )]
    Cycle(Vec<NodeRef>),

    #[error(
        "invoke edge collection: action '{action}' contains a malformed inner \
         step in a `{step_type}` body that failed to parse as StepDef: {error}"
    )]
    MalformedInnerStep {
        action: String,
        step_type: String,
        error: String,
    },
}

fn format_cycle(cycle: &[NodeRef]) -> String {
    cycle
        .iter()
        .map(|(p, a)| format!("{p}.{a}"))
        .collect::<Vec<_>>()
        .join(" → ")
}

/// Step types whose `params.steps` array contains nested `StepDef`s that
/// can themselves declare `invoke` edges. Keep in lockstep with the
/// control-flow step types `runtime::run_step` splices; a step type
/// missing from this list silently skips the
/// structural check on its body, deferring cycle detection to the
/// runtime depth cap.
const STEP_TYPES_WITH_INNER_STEPS: &[&str] = &["for_each", "repeat", "ifs", "try", "parallel"];

/// Resolver for step-type aliases — maps alias names to the
/// `(plugin, action)` pair they dispatch into. Used by [`collect_edges`]
/// to extend cycle detection across alias chains. Returns `None` for
/// unknown names; the caller treats those the same way it treats by-role
/// invokes (left to the runtime depth cap).
pub trait AliasResolver {
    fn resolve(&self, alias: &str) -> Option<(String, String)>;
}

impl<F> AliasResolver for F
where
    F: Fn(&str) -> Option<(String, String)>,
{
    fn resolve(&self, alias: &str) -> Option<(String, String)> {
        (self)(alias)
    }
}

/// An [`AliasResolver`] that never resolves anything. Useful for tests
/// that don't exercise aliases and for callers that don't want alias
/// resolution.
pub struct NoAliases;

impl AliasResolver for NoAliases {
    fn resolve(&self, _alias: &str) -> Option<(String, String)> {
        None
    }
}

/// Collect every statically-resolvable invoke edge declared by `action`.
///
/// Covers two shapes:
/// - **`invoke` steps with a `plugin` name** — emit a direct edge.
/// - **Plugin-supplied step-type aliases** — when `aliases.resolve(name)`
///   returns `Some((plugin, action))`, emit the same edge as if the
///   author had written the equivalent `invoke` step.
///
/// By-role invokes (`{"type":"invoke","role":"X"}`) and unresolved
/// aliases are deliberately skipped: they're only resolvable at runtime,
/// and the [`super::host_api::INVOKE_MAX_DEPTH`] cap is their safety net.
pub fn collect_edges(
    plugin: &str,
    action_name: &str,
    action: &Action,
    aliases: &dyn AliasResolver,
) -> Result<Vec<InvokeEdge>, InvokeCycleError> {
    let mut edges = Vec::new();
    collect_from_steps(plugin, action_name, &action.steps, aliases, &mut edges)?;
    Ok(edges)
}

fn walk_inner_array(
    plugin: &str,
    action_name: &str,
    step_type: &str,
    inner: &[serde_json::Value],
    aliases: &dyn AliasResolver,
    out: &mut Vec<InvokeEdge>,
) -> Result<(), InvokeCycleError> {
    let mut inner_parsed: Vec<StepDef> = Vec::with_capacity(inner.len());
    for v in inner {
        let parsed =
            StepDef::from_inner_value(v).map_err(|e| InvokeCycleError::MalformedInnerStep {
                action: action_name.to_string(),
                step_type: step_type.to_string(),
                error: e.to_string(),
            })?;
        inner_parsed.push(parsed);
    }
    collect_from_steps(plugin, action_name, &inner_parsed, aliases, out)
}

fn collect_from_steps(
    plugin: &str,
    action_name: &str,
    steps: &[StepDef],
    aliases: &dyn AliasResolver,
    out: &mut Vec<InvokeEdge>,
) -> Result<(), InvokeCycleError> {
    for step in steps {
        // Failure-handler bodies live inside
        // `{type: "try", catch: [...]}` step instances, which the
        // sub-block walk picks up via `step.params["catch"]` (handled
        // by the per-step-type cases below).
        if step.step_type == "invoke" {
            if let Some(target_plugin) = step.params.get("plugin").and_then(|v| v.as_str())
                && let Some(target_action) = step.params.get("action").and_then(|v| v.as_str())
            {
                out.push(InvokeEdge {
                    from: (plugin.to_string(), action_name.to_string()),
                    to: (target_plugin.to_string(), target_action.to_string()),
                });
            }
            continue;
        }
        if STEP_TYPES_WITH_INNER_STEPS.contains(&step.step_type.as_str()) {
            // `ifs` carries its inner steps under `ifs[].then` rather
            // than the flat `params.steps` shape `for_each` / `repeat`
            // use. Walk every branch.
            if step.step_type == "ifs" {
                if let Some(ifs) = step.params.get("ifs").and_then(|v| v.as_array()) {
                    for branch in ifs {
                        if let Some(then_arr) = branch.get("then").and_then(|v| v.as_array()) {
                            walk_inner_array(
                                plugin,
                                action_name,
                                &step.step_type,
                                then_arr,
                                aliases,
                                out,
                            )?;
                        }
                    }
                }
                continue;
            }
            // `try` — three sibling arrays.
            if step.step_type == "try" {
                for key in ["try", "catch", "finally"] {
                    if let Some(arr) = step.params.get(key).and_then(|v| v.as_array()) {
                        walk_inner_array(plugin, action_name, &step.step_type, arr, aliases, out)?;
                    }
                }
                continue;
            }
            // `parallel` — branches is an array of
            // arrays. Each branch is a sequential sub-block.
            if step.step_type == "parallel" {
                if let Some(branches) = step.params.get("branches").and_then(|v| v.as_array()) {
                    for branch in branches {
                        if let Some(branch_steps) = branch.as_array() {
                            walk_inner_array(
                                plugin,
                                action_name,
                                &step.step_type,
                                branch_steps,
                                aliases,
                                out,
                            )?;
                        }
                    }
                }
                continue;
            }
            if let Some(inner) = step.params.get("steps").and_then(|v| v.as_array()) {
                walk_inner_array(plugin, action_name, &step.step_type, inner, aliases, out)?;
                continue;
            }
        }
        // Any other step type might be a plugin-supplied alias. Ask the
        // resolver; if it doesn't know the name, leave it to the runtime
        // cap (could be an embedder step type like `http_call`, an alias registered
        // by a plugin not yet loaded, or a genuinely unknown name that
        // execute_action will reject).
        if let Some((target_plugin, target_action)) = aliases.resolve(&step.step_type) {
            out.push(InvokeEdge {
                from: (plugin.to_string(), action_name.to_string()),
                to: (target_plugin, target_action),
            });
        }
    }
    Ok(())
}

/// Resolver for [`StepTypeDef`]s. Maps a step type
/// name to its def, consulted by [`collect_declared_references`].
/// Returns `None` for step types without a registered def (intrinsics,
/// types contributed by a not-yet-loaded plugin); those skip the
/// declarative-references walk entirely.
pub trait StepTypeDefResolver {
    fn resolve(&self, step_type: &str) -> Option<StepTypeDef>;
}

impl<F> StepTypeDefResolver for F
where
    F: Fn(&str) -> Option<StepTypeDef>,
{
    fn resolve(&self, step_type: &str) -> Option<StepTypeDef> {
        (self)(step_type)
    }
}

/// Errors from declared-reference validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeclaredReferenceError {
    #[error(
        "action '{action}' step type '{step_type}' references unknown \
         plugin '{plugin}' (from key '{plugin_key}')"
    )]
    UnknownPlugin {
        action: String,
        step_type: String,
        plugin: String,
        plugin_key: String,
    },
    #[error(
        "action '{action}' step type '{step_type}' references unknown \
         action '{plugin}.{action_target}' (plugin key '{plugin_key}', \
         action key '{action_key}')"
    )]
    UnknownAction {
        action: String,
        step_type: String,
        plugin: String,
        action_target: String,
        plugin_key: String,
        action_key: String,
    },
}

/// Walk a single [`Action`]'s steps and collect every cross-plugin
/// reference declared on a [`StepTypeDef::references`] entry whose
/// keys point at literal-string values in the step's params.
/// Templated references — values that start with
/// `{{` or `$` — are skipped; they're runtime-resolvable and fall
/// under the depth cap. Missing keys also skip.
///
/// `def_resolver` looks up step type defs (local manifest first, then
/// registry). `plugin_exists` reports whether a target plugin name is
/// known (local plugin name OR an already-registered plugin); when it
/// returns `false`, the walker raises [`DeclaredReferenceError::UnknownPlugin`].
/// `action_exists` is checked only when the plugin lookup succeeds.
///
/// Returns the [`InvokeEdge`]s emitted for cycle detection alongside
/// any references whose targets failed validation.
pub fn collect_declared_references<R, P, A>(
    plugin: &str,
    action_name: &str,
    action: &Action,
    def_resolver: &R,
    plugin_exists: &P,
    action_exists: &A,
) -> Result<Vec<InvokeEdge>, Box<DeclaredReferenceError>>
where
    R: StepTypeDefResolver,
    P: Fn(&str) -> bool,
    A: Fn(&str, &str) -> bool,
{
    let mut edges = Vec::new();
    for step in &action.steps {
        let Some(def) = def_resolver.resolve(&step.step_type) else {
            continue;
        };
        if def.references.is_empty() {
            continue;
        }
        for reference in &def.references {
            let Some(target) = literal_reference_target(&step.params, reference, plugin) else {
                continue;
            };
            if !plugin_exists(&target.plugin) {
                return Err(Box::new(DeclaredReferenceError::UnknownPlugin {
                    action: action_name.to_string(),
                    step_type: step.step_type.clone(),
                    plugin: target.plugin,
                    plugin_key: reference.plugin.clone(),
                }));
            }
            if !action_exists(&target.plugin, &target.action) {
                return Err(Box::new(DeclaredReferenceError::UnknownAction {
                    action: action_name.to_string(),
                    step_type: step.step_type.clone(),
                    plugin: target.plugin.clone(),
                    action_target: target.action.clone(),
                    plugin_key: reference.plugin.clone(),
                    action_key: reference.action.clone(),
                }));
            }
            edges.push(InvokeEdge {
                from: (plugin.to_string(), action_name.to_string()),
                to: (target.plugin, target.action),
            });
        }
    }
    Ok(edges)
}

struct ReferenceTarget {
    plugin: String,
    action: String,
}

/// Pull the literal-string `(plugin, action)` target out of a step's
/// params, if both keys resolve to non-templated string values.
/// Templated values (anything starting with `{{` or `$`) and missing
/// keys both return `None`.
fn literal_reference_target(
    params: &serde_json::Value,
    reference: &StepReference,
    _local_plugin: &str,
) -> Option<ReferenceTarget> {
    let plugin = params.get(&reference.plugin).and_then(|v| v.as_str())?;
    let action = params.get(&reference.action).and_then(|v| v.as_str())?;
    if is_templated(plugin) || is_templated(action) {
        return None;
    }
    Some(ReferenceTarget {
        plugin: plugin.to_string(),
        action: action.to_string(),
    })
}

fn is_templated(s: &str) -> bool {
    s.contains("{{") || s.starts_with('$')
}

/// Check the combined invoke graph for cycles. `existing` is the union of
/// edges from every plugin already registered; `new_edges` is what the
/// plugin-under-registration adds. Returns the first cycle found (the
/// caller doesn't try to enumerate all of them — one is enough to reject
/// the registration).
pub fn check_acyclic(
    existing: &[InvokeEdge],
    new_edges: &[InvokeEdge],
) -> Result<(), InvokeCycleError> {
    let mut adj: HashMap<NodeRef, Vec<NodeRef>> = HashMap::new();
    for edge in existing.iter().chain(new_edges.iter()) {
        adj.entry(edge.from.clone())
            .or_default()
            .push(edge.to.clone());
    }

    // Iterative DFS with explicit colours (white = unvisited, gray = on
    // current stack, black = fully explored). Re-encountering a gray
    // node is a back edge — a cycle.
    let mut color: HashMap<NodeRef, Color> = HashMap::new();

    for start in adj.keys() {
        if color.contains_key(start) {
            continue;
        }
        if let Some(cycle) = dfs_find_cycle(start, &adj, &mut color) {
            return Err(InvokeCycleError::Cycle(cycle));
        }
    }

    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Color {
    Gray,
    Black,
}

fn dfs_find_cycle(
    start: &NodeRef,
    adj: &HashMap<NodeRef, Vec<NodeRef>>,
    color: &mut HashMap<NodeRef, Color>,
) -> Option<Vec<NodeRef>> {
    // Stack entries: (node, index of next neighbour to visit).
    let mut stack: Vec<(NodeRef, usize)> = vec![(start.clone(), 0)];
    color.insert(start.clone(), Color::Gray);

    while let Some((node, next_idx)) = stack.last().cloned() {
        let neighbours: &[NodeRef] = adj.get(&node).map(|v| v.as_slice()).unwrap_or(&[]);
        if next_idx >= neighbours.len() {
            color.insert(node.clone(), Color::Black);
            stack.pop();
            continue;
        }
        // Advance the parent's index before we descend so we resume
        // at the right neighbour when we backtrack.
        let last = stack.last_mut().unwrap();
        last.1 = next_idx + 1;

        let next = neighbours[next_idx].clone();
        match color.get(&next).copied() {
            None => {
                color.insert(next.clone(), Color::Gray);
                stack.push((next, 0));
            }
            Some(Color::Gray) => {
                // Back edge — cycle. Slice the stack from `next`'s
                // first occurrence to the current node, then close
                // the loop back to `next`. A Gray colour means the
                // node is on the current DFS stack by definition, so
                // `position` must find it; if it doesn't, the colour
                // map and the stack have diverged and we'd rather
                // crash loudly than report a misleading cycle.
                let cycle_start = stack
                    .iter()
                    .position(|(n, _)| n == &next)
                    .expect("gray node must be present on the DFS stack");
                let mut cycle: Vec<NodeRef> = stack[cycle_start..]
                    .iter()
                    .map(|(n, _)| n.clone())
                    .collect();
                cycle.push(next);
                return Some(cycle);
            }
            Some(Color::Black) => { /* already explored, skip */ }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexmap::IndexMap;
    use serde_json::{Value, json};

    fn step(id: &str, params: Value) -> StepDef {
        StepDef {
            id: id.to_string(),
            step_type: "invoke".to_string(),
            params,
            store_to_variable: None,
            depends_on: Vec::new(),
            long_running: false,
        }
    }

    fn action(steps: Vec<StepDef>) -> Action {
        Action {
            description: None,
            steps,
            results_path: None,
            result_mapping: IndexMap::new(),
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
    fn collect_skips_by_role_edges() {
        let a = action(vec![step("a", json!({"role": "DIGSIG", "action": "sign"}))]);
        assert!(
            collect_edges("p", "act", &a, &NoAliases)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn collect_skips_invokes_without_action() {
        let a = action(vec![step("a", json!({"plugin": "x"}))]);
        assert!(
            collect_edges("p", "act", &a, &NoAliases)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn collect_finds_by_plugin_edge() {
        let a = action(vec![step(
            "a",
            json!({"plugin": "ffprobe", "action": "analyze"}),
        )]);
        let edges = collect_edges("video", "process", &a, &NoAliases).unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].from, ("video".into(), "process".into()));
        assert_eq!(edges[0].to, ("ffprobe".into(), "analyze".into()));
    }

    #[test]
    fn collect_walks_into_for_each() {
        let inner = json!({"id": "inner_invoke", "type": "invoke", "params": {"plugin": "ffprobe", "action": "analyze"}});
        let a = action(vec![StepDef {
            id: "loop".to_string(),
            step_type: "for_each".to_string(),
            params: json!({"path": "$.items[*]", "steps": [inner]}),
            store_to_variable: None,
            depends_on: Vec::new(),
            long_running: false,
        }]);
        let edges = collect_edges("video", "process", &a, &NoAliases).unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].to, ("ffprobe".into(), "analyze".into()));
    }

    #[test]
    fn collect_surfaces_malformed_inner_step() {
        // for_each body contains an entry that's an array, not an object —
        // can't deserialize as StepDef. Should error rather than skip.
        let a = action(vec![StepDef {
            id: "loop".to_string(),
            step_type: "for_each".to_string(),
            params: json!({"path": "$.items[*]", "steps": [["not", "a", "step"]]}),
            store_to_variable: None,
            depends_on: Vec::new(),
            long_running: false,
        }]);
        let err = collect_edges("p", "act", &a, &NoAliases).unwrap_err();
        assert!(matches!(err, InvokeCycleError::MalformedInnerStep { .. }));
    }

    #[test]
    fn acyclic_passes() {
        let edges = vec![
            InvokeEdge {
                from: ("a".into(), "x".into()),
                to: ("b".into(), "y".into()),
            },
            InvokeEdge {
                from: ("b".into(), "y".into()),
                to: ("c".into(), "z".into()),
            },
        ];
        assert!(check_acyclic(&edges, &[]).is_ok());
    }

    #[test]
    fn direct_self_loop_rejected() {
        let new = vec![InvokeEdge {
            from: ("a".into(), "x".into()),
            to: ("a".into(), "x".into()),
        }];
        let err = check_acyclic(&[], &new).unwrap_err();
        let InvokeCycleError::Cycle(c) = err else {
            panic!("expected Cycle, got {err:?}")
        };
        assert!(c.contains(&("a".into(), "x".into())));
    }

    #[test]
    fn two_node_cycle_rejected() {
        // Existing: a.x → b.y. New: b.y → a.x.
        let existing = vec![InvokeEdge {
            from: ("a".into(), "x".into()),
            to: ("b".into(), "y".into()),
        }];
        let new = vec![InvokeEdge {
            from: ("b".into(), "y".into()),
            to: ("a".into(), "x".into()),
        }];
        let err = check_acyclic(&existing, &new).unwrap_err();
        let InvokeCycleError::Cycle(c) = err else {
            panic!("expected Cycle, got {err:?}")
        };
        assert!(c.len() >= 2);
    }

    #[test]
    fn three_node_cycle_rejected() {
        let existing = vec![
            InvokeEdge {
                from: ("a".into(), "x".into()),
                to: ("b".into(), "y".into()),
            },
            InvokeEdge {
                from: ("b".into(), "y".into()),
                to: ("c".into(), "z".into()),
            },
        ];
        let new = vec![InvokeEdge {
            from: ("c".into(), "z".into()),
            to: ("a".into(), "x".into()),
        }];
        assert!(matches!(
            check_acyclic(&existing, &new),
            Err(InvokeCycleError::Cycle(_))
        ));
    }

    #[test]
    fn diamond_is_acyclic() {
        // a → b, a → c, b → d, c → d. No cycle.
        let edges = vec![
            InvokeEdge {
                from: ("p".into(), "a".into()),
                to: ("p".into(), "b".into()),
            },
            InvokeEdge {
                from: ("p".into(), "a".into()),
                to: ("p".into(), "c".into()),
            },
            InvokeEdge {
                from: ("p".into(), "b".into()),
                to: ("p".into(), "d".into()),
            },
            InvokeEdge {
                from: ("p".into(), "c".into()),
                to: ("p".into(), "d".into()),
            },
        ];
        assert!(check_acyclic(&edges, &[]).is_ok());
    }

    // ── declared references ───────────────────────────────────

    fn ref_step(step_type: &str, params: Value) -> StepDef {
        StepDef {
            id: "s".to_string(),
            step_type: step_type.to_string(),
            params,
            store_to_variable: None,
            depends_on: Vec::new(),
            long_running: false,
        }
    }

    fn make_def(name: &str, references: Vec<StepReference>) -> StepTypeDef {
        StepTypeDef {
            name: name.to_string(),
            freely_usable: false,
            input_schema: None,
            output_schema: None,
            metadata_schema: None,
            selector: None,
            references,
        }
    }

    #[test]
    fn declared_reference_emits_edge_when_literal_targets_exist() {
        let def = make_def(
            "tool_call",
            vec![StepReference {
                plugin: "target_plugin".to_string(),
                action: "target_action".to_string(),
            }],
        );
        let act = action(vec![ref_step(
            "tool_call",
            json!({"target_plugin": "other", "target_action": "do_thing"}),
        )]);
        let resolver = |t: &str| (t == "tool_call").then(|| def.clone());
        let edges = collect_declared_references("p", "a", &act, &resolver, &|_| true, &|_, _| true)
            .expect("validation passes");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].from, ("p".into(), "a".into()));
        assert_eq!(edges[0].to, ("other".into(), "do_thing".into()));
    }

    #[test]
    fn declared_reference_rejects_unknown_plugin() {
        let def = make_def(
            "tool_call",
            vec![StepReference {
                plugin: "target_plugin".to_string(),
                action: "target_action".to_string(),
            }],
        );
        let act = action(vec![ref_step(
            "tool_call",
            json!({"target_plugin": "missing", "target_action": "x"}),
        )]);
        let resolver = |t: &str| (t == "tool_call").then(|| def.clone());
        let err =
            collect_declared_references("p", "a", &act, &resolver, &|name| name == "p", &|_, _| {
                true
            })
            .expect_err("should reject unknown plugin");
        match *err {
            DeclaredReferenceError::UnknownPlugin { plugin, .. } => {
                assert_eq!(plugin, "missing");
            }
            other => panic!("expected UnknownPlugin, got {other:?}"),
        }
    }

    #[test]
    fn declared_reference_rejects_unknown_action_on_known_plugin() {
        let def = make_def(
            "tool_call",
            vec![StepReference {
                plugin: "target_plugin".to_string(),
                action: "target_action".to_string(),
            }],
        );
        let act = action(vec![ref_step(
            "tool_call",
            json!({"target_plugin": "other", "target_action": "no_such"}),
        )]);
        let resolver = |t: &str| (t == "tool_call").then(|| def.clone());
        let err =
            collect_declared_references("p", "a", &act, &resolver, &|_| true, &|_p, action| {
                action == "exists"
            })
            .expect_err("should reject unknown action");
        match *err {
            DeclaredReferenceError::UnknownAction { action_target, .. } => {
                assert_eq!(action_target, "no_such");
            }
            other => panic!("expected UnknownAction, got {other:?}"),
        }
    }

    #[test]
    fn declared_reference_skips_templated_targets() {
        let def = make_def(
            "tool_call",
            vec![StepReference {
                plugin: "target_plugin".to_string(),
                action: "target_action".to_string(),
            }],
        );
        let act = action(vec![ref_step(
            "tool_call",
            json!({"target_plugin": "{{$vars.x}}", "target_action": "$.y"}),
        )]);
        let resolver = |t: &str| (t == "tool_call").then(|| def.clone());
        let edges = collect_declared_references(
            "p",
            "a",
            &act,
            &resolver,
            &|_| false, // would error if checked
            &|_, _| false,
        )
        .expect("templated targets are skipped silently");
        assert!(edges.is_empty());
    }

    #[test]
    fn declared_reference_skips_step_type_without_def() {
        let act = action(vec![ref_step(
            "no_def",
            json!({"plugin": "x", "action": "y"}),
        )]);
        let resolver = |_: &str| None;
        let edges =
            collect_declared_references("p", "a", &act, &resolver, &|_| false, &|_, _| false)
                .expect("missing def silently skipped");
        assert!(edges.is_empty());
    }

    #[test]
    fn declared_reference_recognises_self_plugin() {
        let def = make_def(
            "tool_call",
            vec![StepReference {
                plugin: "target_plugin".to_string(),
                action: "target_action".to_string(),
            }],
        );
        let act = action(vec![ref_step(
            "tool_call",
            json!({"target_plugin": "p", "target_action": "a"}),
        )]);
        let resolver = |t: &str| (t == "tool_call").then(|| def.clone());
        // plugin_exists allows only "p"; action_exists allows only
        // "p"+"a" — emulates the in-flight registration where the
        // referencing plugin is itself the target.
        let edges = collect_declared_references(
            "p",
            "a",
            &act,
            &resolver,
            &|name| name == "p",
            &|plugin, action| plugin == "p" && action == "a",
        )
        .expect("self-reference is allowed");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].to, ("p".into(), "a".into()));
    }
}
