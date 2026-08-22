//! Plugin registry — action plans, SPI role bindings, and the indices
//! built from each manifest.
//!
//! The registry holds:
//! 1. Action registrations (definition + DAG plan) keyed by
//!    `(plugin_name, action_name)`
//! 2. SPI role → plugin name mappings for role-based dispatch
//! 3. Plugin manifests for introspection
//! 4. The step-type, alias, subscription, permission, and wasm-module
//!    indices populated from each manifest

use std::collections::HashMap;

use super::dag::DagPlan;
use super::invoke::InvokeEdge;
use super::permissions::Permission;
use super::types::{Action, PluginManifest, StepTypeDef};

/// A registered action — holds the action definition (needed by host
/// functions at execution time) and the precomputed DAG plan that drives
/// step scheduling.
///
/// Step order is driven entirely by the host-side DAG scheduler; wasm
/// modules enter at the *step* level (scripted step types), not the
/// action level.
pub struct ActionRegistration {
    pub action: Action,
    pub plan: DagPlan,
}

/// Discovery record for an action exposed as an LLM-callable tool.
///
/// Yielded by [`PluginRegistry::get_tool_descriptors`] for every action
/// whose manifest carries a `tool` block. Bundles the LLM-facing surface
/// (`tool_name`, `description`, `parameters`) with the engine-facing
/// dispatch pair (`plugin_key`, `action_name`), so a single iteration
/// produces everything a tool-using LLM integration needs: prompt copy,
/// schema-constrained sampling input, and the lookup table that maps a tool call back to an
/// invocable action.
#[derive(Debug, Clone)]
pub struct ToolDescriptor {
    /// Tool name as advertised to the LLM (from `action.tool.name`).
    pub tool_name: String,
    /// One-paragraph description shown to the LLM (from `action.tool.description`).
    pub description: String,
    /// JSON Schema for the tool's arguments (from `action.tool.parameters`).
    pub parameters: serde_json::Value,
    /// Plugin name registered with this kernel — passed to
    /// [`super::Kernel::execute`] for dispatch.
    pub plugin_key: String,
    /// Action name on that plugin — pairs with `plugin_key`.
    pub action_name: String,
}

/// The plugin registry.
#[derive(Default)]
pub struct PluginRegistry {
    /// Action registrations: `(plugin_name, action_name) → ActionRegistration`
    modules: HashMap<(String, String), ActionRegistration>,

    /// SPI role → list of plugin names that fulfil the role, in
    /// registration order; the default orchestrator picks the first
    /// reachable one.
    roles: HashMap<String, Vec<String>>,

    /// Plugin manifests for introspection.
    manifests: HashMap<String, PluginManifest>,

    /// Statically-resolvable `invoke` edges declared across every
    /// registered plugin. Walked by [`super::invoke::check_acyclic`] at
    /// registration time to reject structural cycles. By-role edges are
    /// not captured here (they're not statically resolvable); the
    /// runtime depth cap is their safety net.
    invoke_edges: Vec<InvokeEdge>,

    /// Event subscription index: `event_type → [(plugin, action)]`.
    /// Populated from each registered action's `subscribes_to` field.
    /// Walked by [`super::Kernel::dispatch_event`]
    /// at event-firing time.
    ///
    /// Cleaned up by [`Self::unregister_plugin`], which hot-reload and
    /// `unload_manifest` both go through — this index included.
    subscriptions: HashMap<String, Vec<(String, String)>>,

    /// Step-type alias map: `alias → (plugin, action)`. Populated from
    /// each registered manifest's `step_types` field.
    /// Looked up by [`super::host_api::step_alias_dispatch`] at
    /// step execution and by [`super::invoke::collect_edges`] for
    /// static cycle detection.
    step_type_aliases: HashMap<String, (String, String)>,

    /// Parsed permission set per plugin. Populated from the
    /// manifest's `permissions: Vec<String>` field at registration —
    /// malformed entries reject the whole plugin load. Consulted by the
    /// kernel's own gates (`invoke:`, `step_type:`) and offered to
    /// embedder step types for the advisory categories
    /// (`network:egress`, `blobs:*`). Default-deny: a plugin missing
    /// from this map, or present with an empty set, gets no external
    /// access.
    permissions: HashMap<String, Vec<Permission>>,

    /// Pre-compiled wasm modules contributed by plugin manifests.
    /// Populated from a manifest's `wasm_modules`
    /// field at `register_plugin` time. Looked up by the `wasm` step
    /// type body, keyed by `(plugin_name, module_name)`. The
    /// `Arc<Module>` clone is cheap (wasmtime stores the compiled
    /// code centrally), so per-invocation instantiation costs an
    /// `Arc` bump rather than a recompile.
    plugin_wasm_modules: HashMap<(String, String), std::sync::Arc<wasmtime::Module>>,

    /// Step type definitions contributed by plugin manifests.
    /// Populated from each manifest's `step_type_defs`
    /// field. Keyed by def name; the registering plugin is tracked so
    /// later diagnostics can attribute the def. Records the defs as
    /// declarative metadata only — runtime dispatch goes through
    /// `step_type_impls` (every step *body*, intrinsic or external, is
    /// wired via the `stepTypeImpls` block on its manifest; the
    /// control-flow intrinsics are dispatched by the runtime directly).
    step_type_defs: HashMap<String, (String, StepTypeDef)>,

    /// `kind: "wasm"` step type implementations contributed by
    /// manifests. This table holds only the wasm kind: `native` and
    /// `intrinsic` bodies never land here — they are registered as
    /// wasmtime linker imports keyed by the step-type key when the
    /// manifest is registered, which is why an entry carries just a
    /// plugin and a module name.
    ///
    /// Keyed by `(step_type, matches_value)` so dispatch is one
    /// `HashMap` lookup. Value is the registering plugin's name +
    /// the wasm module name to instantiate. The kernel never needs
    /// to know which language sits behind the wasm — just routes
    /// the step instance to the matching impl.
    step_type_impls: HashMap<(String, Option<String>), StepTypeImplEntry>,
}

/// One row of the step-type implementation registry — the value the
/// kernel needs to dispatch a step to the right wasm module.
#[derive(Debug, Clone)]
pub struct StepTypeImplEntry {
    /// The plugin that registered this impl. Used to find the
    /// matching `wasm_modules` entry via
    /// [`PluginRegistry::get_plugin_wasm_module`].
    pub plugin: String,

    /// Name of the wasm module entry in `plugin`'s manifest.
    pub wasm_module: String,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
            roles: HashMap::new(),
            manifests: HashMap::new(),
            invoke_edges: Vec::new(),
            subscriptions: HashMap::new(),
            step_type_aliases: HashMap::new(),
            permissions: HashMap::new(),
            plugin_wasm_modules: HashMap::new(),
            step_type_defs: HashMap::new(),
            step_type_impls: HashMap::new(),
        }
    }

    /// The registry key for a step type as a plugin wrote it.
    ///
    /// Step-type tables are keyed by **owner-qualified** name so two
    /// namespaces may each define `vault.sign`: a dotted (plugin-
    /// defined) name is qualified into the declaring plugin's
    /// namespace — `tenant_a/vault.sign` — and a bare (kernel) name is
    /// the key as-is, since the kernel's step types live in root and
    /// are visible from everywhere. In the root namespace the key is
    /// the written name itself.
    ///
    /// A *user* of a step type computes the same key by resolving the
    /// owner segment along its own chain — see
    /// `Kernel::step_type_access_for`.
    pub fn step_type_key(plugin: &str, written: &str) -> String {
        if written.contains(super::identity::STEP_TYPE_SEPARATOR) {
            super::identity::qualify(super::identity::namespace_of(plugin), written)
        } else {
            written.to_string()
        }
    }

    /// Who currently owns a `(step_type, matches)` implementation
    /// slot, as `(plugin, wasm_module)`. `None` means the slot is
    /// free. `step_type` is a registry key — see [`Self::step_type_key`].
    ///
    /// Registration is split into this query and
    /// [`Self::commit_step_type_impl`] so the whole of a manifest can
    /// be checked before any of it is applied — see
    /// `Kernel::prepare_step_types`.
    pub fn step_type_impl_owner(
        &self,
        step_type: &str,
        matches: Option<&str>,
    ) -> Option<(&str, &str)> {
        let key = (step_type.to_string(), matches.map(String::from));
        self.step_type_impls
            .get(&key)
            .map(|e| (e.plugin.as_str(), e.wasm_module.as_str()))
    }

    /// Claim a `(step_type, matches)` implementation slot.
    ///
    /// **Overwrites** any existing entry, so callers must have checked
    /// [`Self::step_type_impl_owner`] first. This is the commit half
    /// of a checked registration, not a safe standalone operation.
    pub fn commit_step_type_impl(
        &mut self,
        plugin: &str,
        step_type: &str,
        matches: Option<&str>,
        wasm_module: &str,
    ) {
        let key = (
            Self::step_type_key(plugin, step_type),
            matches.map(String::from),
        );
        self.step_type_impls.insert(
            key,
            StepTypeImplEntry {
                plugin: plugin.to_string(),
                wasm_module: wasm_module.to_string(),
            },
        );
    }

    /// Candidate impls registered for a `(step_type, matches)` lookup.
    ///
    /// The registry stores at most one entry per pair, so this returns
    /// 0 or 1 candidates — callers `.first()` or `.into_iter().next()`
    /// to pick. The `Vec` shape matches [`Self::plugins_for_role`]: the
    /// kernel exposes catalogue queries, the caller picks.
    pub fn step_type_impl_candidates(
        &self,
        step_type: &str,
        matches: Option<&str>,
    ) -> Vec<&StepTypeImplEntry> {
        let key = (step_type.to_string(), matches.map(String::from));
        self.step_type_impls.get(&key).into_iter().collect()
    }

    /// All `matches` values registered for a given step type. Used by
    /// `validate_step_shapes` to produce the supported-list
    /// in the "no impl registered" error message. Selector-less impls
    /// (those with `matches = None`) are skipped — the caller is
    /// querying by selector value, so only selector-bearing impls
    /// matter.
    pub fn step_type_impl_matches(&self, step_type: &str) -> Vec<&str> {
        self.step_type_impls
            .keys()
            .filter(|(t, _)| t == step_type)
            .filter_map(|(_, m)| m.as_deref())
            .collect()
    }

    /// Register a step type definition contributed by a plugin
    /// manifest.
    ///
    /// **Overwrites** any existing entry. Check
    /// [`Self::get_step_type_def`] first; this is the commit half of a
    /// checked registration — see `Kernel::prepare_step_types`.
    pub fn commit_step_type_def(&mut self, plugin: &str, def: StepTypeDef) {
        let key = Self::step_type_key(plugin, &def.name);
        self.step_type_defs.insert(key, (plugin.to_string(), def));
    }

    /// Look up a step type definition by registry key (see
    /// [`Self::step_type_key`]). Returns `Some((registering_plugin,
    /// &def))` when present; `def.name` is the name as written.
    pub fn get_step_type_def(&self, key: &str) -> Option<(&str, &StepTypeDef)> {
        self.step_type_defs.get(key).map(|(p, d)| (p.as_str(), d))
    }

    /// Every registered step type def as `(key, registering_plugin,
    /// &def)`.
    ///
    /// Used by `Kernel::step_type_access_for` to resolve one plugin's
    /// usable set at invocation setup. Iteration order is unspecified
    /// (a `HashMap`), which is fine — the caller builds a set.
    pub fn step_type_defs_iter(&self) -> impl Iterator<Item = (&str, &str, &StepTypeDef)> {
        self.step_type_defs
            .iter()
            .map(|(name, (plugin, def))| (name.as_str(), plugin.as_str(), def))
    }

    /// Every registered step-type alias as `(key, registering_plugin)`.
    ///
    /// Aliases live in their own table but share the step-type *name*
    /// space, so `Kernel::step_type_access_for` has to consider both or
    /// it would deny every alias step.
    pub fn step_type_aliases_iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.step_type_aliases
            .iter()
            .map(|(alias, (plugin, _))| (alias.as_str(), plugin.as_str()))
    }

    /// How many step type defs are registered — the boot-time
    /// intrinsics plus every def contributed since.
    pub fn step_type_def_count(&self) -> usize {
        self.step_type_defs.len()
    }

    /// Cache a wasm module a plugin manifest carried as a
    /// `wasm_modules` entry. Keyed by `(plugin, module)` so
    /// each plugin keeps its own namespace.
    pub fn register_plugin_wasm_module(
        &mut self,
        plugin: &str,
        module_name: &str,
        module: std::sync::Arc<wasmtime::Module>,
    ) {
        self.plugin_wasm_modules
            .insert((plugin.to_string(), module_name.to_string()), module);
    }

    /// Look up a wasm module registered via
    /// [`Self::register_plugin_wasm_module`]. Returns `None` when the
    /// plugin or module name isn't recognised — the `wasm` step type's
    /// body translates that to a structured `StepError::Failed`.
    pub fn get_plugin_wasm_module(
        &self,
        plugin: &str,
        module_name: &str,
    ) -> Option<std::sync::Arc<wasmtime::Module>> {
        self.plugin_wasm_modules
            .get(&(plugin.to_string(), module_name.to_string()))
            .cloned()
    }

    /// Add a `(plugin, action)` entry to the subscription map for the
    /// given event type. Idempotent on `(event, plugin, action)` so
    /// re-registering a plugin doesn't duplicate dispatches.
    pub fn register_subscription(&mut self, event_type: &str, plugin: &str, action: &str) {
        let bucket = self
            .subscriptions
            .entry(event_type.to_string())
            .or_default();
        let pair = (plugin.to_string(), action.to_string());
        if !bucket.iter().any(|p| p == &pair) {
            bucket.push(pair);
        }
    }

    /// All `(plugin, action)` pairs subscribed to `event_type`. Returns
    /// an empty slice when nothing matches.
    pub fn subscribers_for(&self, event_type: &str) -> &[(String, String)] {
        self.subscriptions
            .get(event_type)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Snapshot of the by-plugin invoke edges declared by every action
    /// already registered. Used by `register_plugin` to combine the
    /// existing graph with the new plugin's edges before checking for
    /// structural cycles.
    pub fn invoke_edges(&self) -> &[InvokeEdge] {
        &self.invoke_edges
    }

    /// Append edges produced by [`super::invoke::collect_edges`].
    pub fn extend_invoke_edges(&mut self, edges: impl IntoIterator<Item = InvokeEdge>) {
        self.invoke_edges.extend(edges);
    }

    /// Register an action's execution plan.
    pub fn register_action(
        &mut self,
        plugin_name: &str,
        action_name: &str,
        action: Action,
        plan: DagPlan,
    ) {
        self.modules.insert(
            (plugin_name.to_string(), action_name.to_string()),
            ActionRegistration { action, plan },
        );
    }

    /// Register a plugin's manifest for introspection.
    pub fn register_manifest(&mut self, manifest: &PluginManifest) {
        self.manifests
            .insert(manifest.name.clone(), manifest.clone());
    }

    /// Register a plugin's SPI role mapping.
    pub fn register_role(&mut self, role: &str, plugin_name: &str) {
        self.roles
            .entry(role.to_string())
            .or_default()
            .push(plugin_name.to_string());
    }

    /// Get a registered action.
    pub fn get_action(&self, plugin_name: &str, action_name: &str) -> Option<&ActionRegistration> {
        self.modules
            .get(&(plugin_name.to_string(), action_name.to_string()))
    }

    /// Get all plugin names registered for a given SPI role.
    ///
    /// The registry is a catalogue: it lists who is registered,
    /// nothing more. Selection — first-match, per-tenant overlays,
    /// caller-keyed routing — lives in the dispatch orchestrator
    /// ([`super::dispatch::DispatchOrchestrator`]). Returns an empty
    /// `Vec` when no plugin is bound.
    pub fn plugins_for_role(&self, role: &str) -> Vec<String> {
        self.roles.get(role).cloned().unwrap_or_default()
    }

    /// Whether a plugin with exactly this qualified identity is registered.
    pub fn has_plugin(&self, plugin_name: &str) -> bool {
        self.manifests.contains_key(plugin_name)
    }

    /// Get a plugin's manifest.
    pub fn get_manifest(&self, plugin_name: &str) -> Option<&PluginManifest> {
        self.manifests.get(plugin_name)
    }

    /// List all registered plugin names.
    pub fn plugin_names(&self) -> Vec<&str> {
        self.manifests.keys().map(|s| s.as_str()).collect()
    }

    /// List all registered action names for a plugin.
    pub fn action_names(&self, plugin_name: &str) -> Vec<String> {
        self.modules
            .keys()
            .filter(|(p, _)| p == plugin_name)
            .map(|(_, a)| a.clone())
            .collect()
    }

    /// Iterate every registered plugin and return a descriptor for each
    /// action whose manifest carries a `tool` block. This is the source
    /// of truth a tool-using LLM integration queries to (a) build the
    /// tool list it shows the model, (b) build the JSON Schema list
    /// passed to a schema-constrained sampler, and
    /// (c) resolve a tool-call name back to a `(plugin, action)` for
    /// dispatch.
    ///
    /// Iteration order is unspecified (HashMap); callers that need
    /// deterministic ordering for prompt stability should sort by
    /// `tool_name` themselves.
    pub fn get_tool_descriptors(&self) -> Vec<ToolDescriptor> {
        let mut out = Vec::new();
        for (plugin_name, manifest) in &self.manifests {
            for (action_name, action) in &manifest.actions {
                let Some(tool) = &action.tool else { continue };
                out.push(ToolDescriptor {
                    tool_name: tool.name.clone(),
                    description: tool.description.clone(),
                    parameters: tool.parameters.clone(),
                    plugin_key: plugin_name.clone(),
                    action_name: action_name.clone(),
                });
            }
        }
        out
    }

    /// Publish a step-type alias declared by a plugin manifest. The
    /// caller is expected to have already validated the alias name
    /// format, that the target action exists in the plugin, and that
    /// the alias is unclaimed.
    ///
    /// **Overwrites** any existing entry. Check
    /// [`Self::step_type_alias_candidates`] first; this is the commit
    /// half of a checked registration — see
    /// `Kernel::register_plugin`'s pre-flight block.
    pub fn commit_step_type_alias(&mut self, alias: &str, plugin: &str, action: &str) {
        let key = Self::step_type_key(plugin, alias);
        self.step_type_aliases
            .insert(key, (plugin.to_string(), action.to_string()));
    }

    /// Candidate `(plugin, action)` pairs registered for a step-type
    /// alias. The registry stores at most one entry per alias
    /// (duplicates rejected at registration), so this returns 0 or 1
    /// candidates — callers `.first()` to pick. The `Vec` shape matches
    /// [`Self::plugins_for_role`] and [`Self::step_type_impl_candidates`].
    /// `alias` is a registry key — see [`Self::step_type_key`].
    pub fn step_type_alias_candidates(&self, alias: &str) -> Vec<(String, String)> {
        self.step_type_aliases
            .get(alias)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Record the parsed permission set for a plugin. Called once per
    /// plugin at registration after the raw strings have been
    /// validated. Overwrites any prior entry; the kernel rejects
    /// re-registration of a live plugin, and reload goes through
    /// [`Self::unregister_plugin`] first.
    pub fn set_permissions(&mut self, plugin: &str, perms: Vec<Permission>) {
        self.permissions.insert(plugin.to_string(), perms);
    }

    /// Look up the permission set granted to a plugin. Returns an
    /// empty slice for unregistered plugins or plugins that declared
    /// no permissions — both translate to default-deny at the host
    /// step boundary.
    pub fn permissions_for(&self, plugin: &str) -> &[Permission] {
        self.permissions
            .get(plugin)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Remove every trace of a plugin from this registry.
    ///
    /// Scrubs (in order):
    /// - `modules` (per-action plans), `manifests` (introspection),
    ///   `permissions`, `plugin_wasm_modules`, `step_type_aliases`
    /// - `roles` bindings naming this plugin (entries that empty out get
    ///   removed so `plugins_for_role` returns empty)
    /// - `subscriptions` entries pointing at this plugin (empty buckets
    ///   removed)
    /// - `invoke_edges` whose `from_plugin` matches
    /// - `step_type_defs` registered by this plugin
    /// - `step_type_impls` registered by this plugin
    ///
    /// Returns `false` when no manifest by that name was registered —
    /// callers translate that to a clear "not loaded" error rather than
    /// silently succeeding.
    pub fn unregister_plugin(&mut self, plugin_name: &str) -> bool {
        if !self.manifests.contains_key(plugin_name) {
            return false;
        }

        self.modules.retain(|(p, _), _| p != plugin_name);
        self.manifests.remove(plugin_name);
        self.permissions.remove(plugin_name);
        self.plugin_wasm_modules
            .retain(|(p, _), _| p != plugin_name);
        self.step_type_aliases.retain(|_, (p, _)| p != plugin_name);
        self.step_type_defs.retain(|_, (p, _)| p != plugin_name);
        self.step_type_impls
            .retain(|_, entry| entry.plugin != plugin_name);

        for plugins in self.roles.values_mut() {
            plugins.retain(|p| p != plugin_name);
        }
        self.roles.retain(|_, plugins| !plugins.is_empty());

        for bucket in self.subscriptions.values_mut() {
            bucket.retain(|(p, _)| p != plugin_name);
        }
        self.subscriptions.retain(|_, bucket| !bucket.is_empty());

        // Filter on `from` only. Edges where this plugin was the
        // *target* (`e.to.0 == plugin_name`) are intentionally
        // retained: a reload of the same name later will re-resolve
        // them, and at execution time the runtime invoke step
        // surfaces a clear "plugin not found" when the dangling
        // target is actually called. Cycle detection on subsequent
        // `register_plugin` calls walks these by-name edges and
        // tolerates dangling targets — they just don't form cycles
        // until something registers under the missing name again.
        self.invoke_edges.retain(|e| e.from.0 != plugin_name);

        true
    }
}
