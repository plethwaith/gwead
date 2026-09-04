//! Core types for the Gwead wasm microkernel.
//!
//! These types define the plugin manifest format, action definitions, step
//! definitions, SPI roles, and execution results. The model is
//! general-purpose: any plugin can declare any number of named actions,
//! each composed of typed steps.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Plugin manifest
// ---------------------------------------------------------------------------

/// The one manifest format version this kernel reads. A manifest
/// declaring any other `formatVersion` is rejected at registration on
/// every path — the JSON meta-schema pins it, and the struct path checks
/// it explicitly — so a future revision fails loudly on an old kernel
/// rather than being misparsed.
pub const SUPPORTED_FORMAT_VERSION: u32 = 1;

/// A plugin manifest — the unified format for all plugin types.
///
/// The format supports arbitrary named actions, each with a typed step
/// sequence executed by the host-side DAG scheduler.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PluginManifest {
    /// Manifest format version. `None` means 1 — the only version so
    /// far. The meta-schema pins the declared value to `1`, so a
    /// future format revision is rejected up front with a clear
    /// schema error instead of misparsed by an older kernel — and
    /// [`register_plugin`](super::Kernel::register_plugin) applies the
    /// same check to a struct built in code, so the gate is not
    /// JSON-only. See [`SUPPORTED_FORMAT_VERSION`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format_version: Option<u32>,

    /// The plugin's local name.
    ///
    /// Constrained to the identifier grammar in
    /// [`kernel::identity`](crate::kernel::identity) — ASCII letters,
    /// digits, `_` and `-`, not leading `-`, at most
    /// [`MAX_NAME_LEN`](crate::kernel::identity::MAX_NAME_LEN) bytes —
    /// because it is the registry key *and* appears verbatim inside
    /// permission strings. `/` is rejected as reserved namespace
    /// syntax.
    ///
    /// Validated by every registration entry point, including the ones
    /// taking an already-parsed manifest that the meta-schema never
    /// sees.
    pub name: String,

    /// Human-readable display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Semver version string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// SPI roles this plugin fulfils (e.g., `["METADATA_PROVIDER"]`).
    #[serde(default)]
    pub roles: Vec<String>,

    /// Named actions this plugin exposes. Each action has a step sequence
    /// the kernel plans into a DAG at registration.
    #[serde(default)]
    pub actions: IndexMap<String, Action>,

    /// Step-type aliases this plugin contributes. Maps `alias_name → action_name`.
    /// When another manifest writes `{"type": "alias_name", ...}` in a step,
    /// the kernel dispatches into this plugin's `action_name` with the step
    /// params resolved as the action's input. Pure ergonomic shorthand over
    /// `{"type":"invoke","params":{"plugin":"<this_plugin>",
    /// "action":"<action_name>","input":{...}}}`. Resolution flows through the dedicated
    /// `PluginRegistry::step_type_aliases` index.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub step_types: IndexMap<String, String>,

    /// Configuration schema (system + user fields). Opaque to the
    /// kernel: carried verbatim for the embedder, never interpreted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_schema: Option<ConfigSchema>,

    /// Authentication specification. Opaque to the kernel: carried
    /// verbatim for the embedder, never interpreted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthSpec>,

    /// App-specific metadata, opaque to the kernel.
    ///
    /// Embedders namespace their entries by application — e.g. an app
    /// called Acme keeps its declarations under `metadata["acme"]`.
    /// The kernel carries this map verbatim and never interprets it; each
    /// embedder deserializes its own namespace into its own types.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub metadata: IndexMap<String, Value>,

    /// Permissions requested by the plugin.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,

    /// Secret keys this plugin uses, as they appear in
    /// `{{$secrets.<key>}}`.
    ///
    /// A ceiling, not a request. The kernel intersects whatever the
    /// [`SecretResolver`](super::secrets::SecretResolver) returns
    /// with this list, so a
    /// plugin can never see a key it did not declare, even if the
    /// resolver hands over more and even if the embedder's bag holds a
    /// whole tenant's credentials. See
    /// [`intersect_declared`](super::secrets::intersect_declared).
    ///
    /// Declaring nothing means seeing nothing, and costs no resolver
    /// round trip. That is the safe default and it is also the honest
    /// one: a plugin that reads `{{$secrets.apiKey}}` without declaring
    /// `apiKey` was relying on ambient authority, and the declaration
    /// is what turns "what does this plugin touch" into a question with
    /// an answer in the document an operator reviews.
    ///
    /// Keys are embedder-defined strings and are deliberately not held
    /// to the identifier grammar — a secret store may well use dotted or
    /// slashed paths.
    ///
    /// Each entry is either a bare key or a [`SecretDecl`] object; the
    /// object form is how a key is marked `overridable` (see there).
    /// Keys must be unique across the list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uses_secrets: Vec<SecretDecl>,

    /// Embedder-defined tag, opaque to the kernel. The kernel carries
    /// it and hands it back through [`Self::tracking_tag`]; what it
    /// labels (outgoing requests, audit rows, …) is the embedder's
    /// business.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracking_tag: Option<String>,

    /// Step type definitions contributed by this manifest.
    ///
    /// A manifest can ship step type definitions alongside its plugin
    /// declaration — the "self-contained bundle" pattern. The kernel
    /// registers each def at `register_plugin` time, exposing its name
    /// to subsequent validation passes. A def is declarative (name,
    /// schemas, selector, references); the implementation behind it is
    /// supplied separately by a [`Self::step_type_impls`] entry, in
    /// this manifest or another.
    ///
    /// Names in this list must not shadow a kernel intrinsic or another
    /// plugin's contribution; registration fails otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub step_type_defs: Vec<StepTypeDef>,

    /// Pre-compiled wasm modules this manifest carries.
    ///
    /// Keyed by module name (referenced by `wasm` step type instances
    /// inside this plugin's actions). Each value is either a base64-
    /// encoded `.wasm` byte sequence or a path relative to the manifest
    /// location (the path form is rejected at registration — see
    /// [`WasmModuleSpec`]). The kernel compiles each entry to an `Arc<wasmtime::Module>`
    /// at registration time so `wasm` step bodies can instantiate
    /// cheaply per invocation.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub wasm_modules: IndexMap<String, WasmModuleSpec>,

    /// Step type implementations this manifest provides.
    ///
    /// Each entry declares that this plugin implements an existing step
    /// type for a specific selector value (e.g. `script` for
    /// `language: "lua"`), backed by one of the manifest's
    /// [`Self::wasm_modules`] entries. The kernel routes a step instance
    /// to the right plugin via the `(step_type, matches)` lookup the
    /// entries build up — fully data-driven; the kernel never grows a
    /// line of code per language/runtime.
    ///
    /// Conflict semantics: two manifests cannot both claim the same
    /// `(step_type, matches)` pair. Registration fails on the second.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub step_type_impls: Vec<StepTypeImpl>,
}

/// Step type definition. Declared via [`PluginManifest::step_type_defs`].
///
/// A def is the declarative half of a step type — name, optional
/// schemas, an optional selector, and any static cross-plugin
/// references its params carry. The implementation is supplied
/// separately by a [`StepTypeImpl`]. The kernel uses the declaration
/// for registration-time validation (e.g., the `script` def's check
/// that a `language: X` resolves to a registered implementation) and
/// for the metadata allow-list enforced at dispatch.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct StepTypeDef {
    /// The step type name as it appears in step definitions
    /// (`{"type": "<this>"}`).
    pub name: String,

    /// Whether other plugins may use this step type **without** holding a
    /// `step_type:<name>` grant.
    ///
    /// **Default `false` — using another plugin's step type requires the
    /// grant.** Set this to `true` on shared utilities that are safe for
    /// anyone to call: a pure-compute `resize_image`, a formatter, a
    /// codec. The author of the capability is the one who knows.
    ///
    /// Leave it `false` on anything that holds a credential, performs
    /// I/O, or reaches a privileged host resource. A grant then makes
    /// every consumer of that capability greppable in the manifest an
    /// operator reviews, which is the point.
    ///
    /// Defaulting to "grant required" means forgetting to think about it
    /// fails closed. It also means opening up a shared utility is one
    /// line on the *provider* rather than a grant on every consumer.
    ///
    /// This is the third of three orthogonal axes, and it is easy to
    /// confuse them:
    ///
    /// - `provide:step_type:` — who may **supply** an implementation.
    /// - `bind:native_impl:` — who may **bind** a specific native body.
    /// - `step_type:` — who may **use** the type. *Only this one is
    ///   what `freelyUsable` waives.*
    ///
    /// A plugin may always use step types it defined itself, and the
    /// kernel's own reserved intrinsics (`let`, `ifs`, `script`, …) are
    /// usable by everyone regardless of this flag — see
    /// [`super::host_api::RESERVED_STEP_TYPE_NAMES`].
    #[serde(default)]
    pub freely_usable: bool,

    /// Optional JSON schema for the params object a step of this type
    /// accepts. Declarative: stored and exposed to embedders; the kernel
    /// does not validate step params against it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,

    /// Optional JSON schema for the value the step's output produces.
    /// Declarative: stored and exposed to embedders; the kernel does not
    /// validate step output against it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,

    /// Optional JSON schema for the sidecar metadata a step of this type
    /// emits via [`super::host_api::StepOutput::metadata`]. The
    /// schema's `properties` keys are the metadata keys the step type is
    /// allowed to emit; they surface flat as `{{$steps.<id>.<key>}}`. A
    /// step that emits a key not declared here fails — the contract is
    /// enforced at dispatch by `super::runtime::dispatch_trait_step_core`.
    /// `None` (the default) means the step type emits no metadata at all;
    /// emitting any sidecar is then an error. The reserved key `result`
    /// (the value slot) is rejected at registration.
    ///
    /// Only the declared key *set* is enforced (a cheap set-difference);
    /// values are not type-checked. The allow-list is **exactly** the
    /// top-level `.properties` key-set, so the schema must be a flat
    /// object schema: write the keys under `properties`, not behind
    /// `$ref` / `allOf` / `oneOf`, and don't rely on
    /// `additionalProperties` — see
    /// `ExecutionState::declared_metadata_keys`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_schema: Option<Value>,

    /// Optional selector field name. When present,
    /// step instances are routed to one of several implementations based
    /// on the named input field — e.g., the `script` def uses
    /// `selector: "language"` so `{type: "script", language: "lua"}`
    /// resolves to the `lua` implementation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,

    /// Static cross-plugin references this step type's params carry.
    /// Each entry names two top-level keys in the
    /// step's params object — one resolving to a plugin name, the
    /// other to that plugin's action name. The kernel walks them at
    /// registration: if both keys are present as literal
    /// strings (not templates), the kernel rejects registration when
    /// the target doesn't exist, and emits an [`super::invoke::InvokeEdge`]
    /// for cycle detection — same shape the hardcoded `invoke`
    /// walker emits for `{type: "invoke", plugin: …, action: …}`.
    /// Generalises that walker to custom step types whose authors
    /// declare their reference shape declaratively.
    ///
    /// Templated values (`{plugin: "{{$vars.x}}", action: "foo"}`) and
    /// missing keys are skipped — those are runtime-resolvable and
    /// fall under [`super::host_api::INVOKE_MAX_DEPTH`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<StepReference>,
}

/// One declared cross-plugin reference on a [`StepTypeDef`].
///
/// Both fields name top-level keys in the step's params object whose
/// values resolve to a plugin name and action name respectively. The
/// minimal shape supports the common case (`invoke`-shaped step types
/// with a flat params object); deeper paths (`$.target.plugin`) are
/// not supported — only flat top-level keys are walked.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StepReference {
    /// Top-level params key whose value is the target plugin name.
    pub plugin: String,
    /// Top-level params key whose value is the target action name.
    pub action: String,
}

/// Step type implementation contributed by a manifest.
///
/// Declared on a [`PluginManifest::step_type_impls`] entry. Each impl
/// names:
/// - the step type it implements (must already exist — either an
///   intrinsic or a [`PluginManifest::step_type_defs`] entry)
/// - the selector value it matches (e.g. `"lua"` for the `script` step
///   type's `language` selector — `None` for selector-less step types)
/// - HOW the implementation is provided — a wasm module in this
///   manifest's [`PluginManifest::wasm_modules`] (`kind: "wasm"`), a
///   native Rust function pointer the embedder submitted via
///   `inventory::submit!` (`kind: "native"`), or a kernel-internal body
///   (`kind: "intrinsic"`, engine-only).
///
/// At dispatch time the kernel looks up `(step_type, matches)` in its
/// impl registry, finds the registering plugin, and either:
/// - instantiates the named wasm module through the script-runtime
///   host ABI (wasm kind), or
/// - calls the resolved native fn pointer through the trait-shaped
///   step type dispatch path (native kind), or
/// - runs the kernel's own body through that same path (intrinsic
///   kind).
///
/// ## Native and intrinsic impls are selector-less
///
/// `matches` MUST be `None` when `kind` is `"native"` or
/// `"intrinsic"`. Dispatch for those kinds goes through the wasmtime
/// linker by step type *name*, which has no notion of per-selector
/// routing. The `script` step type's language selector is served by
/// wasm-kind impls.
///
/// ## Name validation
///
/// `step_type` is validated as a step type *reference*: a bare kernel
/// name, or a well-formed `<plugin>.<name>` — see
/// [`identity::validate_step_type_reference`](super::identity::validate_step_type_reference).
/// Ownership of the claim is checked separately at registration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StepTypeImpl {
    /// The step type this impl handles (e.g. `"script"`).
    pub step_type: String,

    /// The selector value this impl matches. `None` for step types
    /// without a selector — the impl claims the type unconditionally.
    /// For `script` the selector is `language`, so a Lua runtime sets
    /// `matches: Some("lua")`. **Native-kind impls must use `None`**
    /// (see struct-level docs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matches: Option<String>,

    /// How this impl is provided. Defaults to [`StepTypeImplKind::Wasm`]
    /// when absent.
    #[serde(default)]
    pub kind: StepTypeImplKind,

    /// Name of an entry in this manifest's [`PluginManifest::wasm_modules`]
    /// map. Required when `kind == Wasm`; must be absent when
    /// `kind == Native`. The kernel resolves the name to the cached
    /// `Arc<wasmtime::Module>` at dispatch time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wasm_module: Option<String>,

    /// Reference to a native impl submitted via
    /// `inventory::submit!` in some plugin crate. Required when
    /// `kind == Native`; must be absent when `kind == Wasm`. The
    /// kernel resolves the string against `Kernel::native_step_impls`
    /// at `register_plugin` time; missing references error clearly.
    ///
    /// Convention: dotted-namespaced by the providing crate, e.g.
    /// `"myapp.my-plugin.my_step"`. Convention only — table lookup is
    /// exact-match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impl_ref: Option<String>,
}

/// Discriminator for [`StepTypeImpl::kind`] — how a step-type
/// implementation is supplied.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StepTypeImplKind {
    /// Implementation is a wasm module in this manifest's
    /// `wasmModules` block. Default when `kind` is absent.
    #[default]
    Wasm,
    /// Implementation is a native Rust fn pointer submitted by some
    /// plugin crate via `inventory::submit!`.
    /// Resolved against `Kernel::native_step_impls` at registration.
    Native,
    /// Implementation is a kernel-internal Rust fn pointer submitted via
    /// `inventory::submit!` as an `IntrinsicStepImplEntry`. Like
    /// [`Self::Native`] but the body receives the concrete
    /// `&mut ExecutionState` instead of the narrow
    /// `&mut dyn PluginExecution`, so it can reach engine internals the
    /// plugin surface deliberately hides. Only the engine's own
    /// `gwead.intrinsics.*` bodies (`invoke`, `wasm`, `script`) use this;
    /// external plugins cannot supply intrinsic bodies (they can't name
    /// `ExecutionState`). Resolved against `Kernel::intrinsic_step_impls`
    /// at registration.
    Intrinsic,
}

/// A wasm module entry inside [`PluginManifest::wasm_modules`].
///
/// Two carrier forms:
/// - `Inline(base64)` — the wasm bytes encoded directly in the manifest
/// - `Path(rel)` — a path relative to the manifest's resource directory
///
/// The kernel decodes/loads the bytes and compiles to `Arc<wasmtime::Module>`
/// at registration time.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum WasmModuleSpec {
    /// Inline base64-encoded wasm bytes.
    Inline { base64: String },
    /// Path to a `.wasm` file relative to the manifest's resource dir.
    ///
    /// Registration rejects manifests using this form with a
    /// Validation error: this kernel has no manifest-resource-directory
    /// resolver, so only the inline form is loadable. The variant is
    /// part of the format (and accepted by the meta-schema) so a
    /// manifest using it fails with a clear error rather than a parse
    /// error.
    Path { path: String },
}

impl PluginManifest {
    /// The embedder-defined tag for this plugin: the manifest's
    /// override if set, otherwise a default derived from the name.
    /// Opaque to the kernel.
    pub fn tracking_tag(&self) -> String {
        if let Some(t) = self.tracking_tag.as_ref() {
            return t.clone();
        }
        let derived: String = self
            .name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(8)
            .collect::<String>()
            .to_uppercase();
        if derived.is_empty() {
            "PLUGIN".to_string()
        } else {
            derived
        }
    }
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/// An action definition — a named operation with a step sequence.
///
/// Actions are the unit of invocation: `execute_action(plugin, "search", input)`.
/// Each action's step sequence is validated and planned into a DAG at
/// plugin-registration time.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Action {
    /// Ordered sequence of steps.
    pub steps: Vec<StepDef>,

    /// Human-readable description of what the action does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// DSL path expression to extract the final result from step outputs.
    /// When absent, the last step's output is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results_path: Option<String>,

    /// Field mapping from step outputs to the action's result shape.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub result_mapping: IndexMap<String, Value>,

    /// JSON Schema for the action's input. Declarative: stored and
    /// exposed to embedders; the kernel does not validate input against it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,

    /// JSON Schema for the action's output. Declarative: stored and
    /// exposed to embedders; the kernel does not validate output against it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,

    /// Domain-event types this action subscribes to.
    ///
    /// When an event of one of these types fires, the kernel's event
    /// dispatcher invokes this action with the event payload bound to
    /// the `$trigger` reference. Empty for actions that aren't event
    /// handlers (the common case). Resolution flows through the
    /// dedicated `PluginRegistry::subscriptions` index.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subscribes_to: Vec<String>,

    /// Marks the action as continuous. When `true`, the
    /// kernel runs the action's DAG repeatedly via
    /// [`ExecuteActionRequest::into_continuous_handle`](crate::kernel::execute_request::ExecuteActionRequest::into_continuous_handle), emitting one
    /// [`ActionResult`] per iteration on a result channel until
    /// cancelled. Use for folder watchers, webhook listeners, message
    /// queue consumers, and other long-running source patterns.
    ///
    /// Pair with `interval_ms` (below) to throttle the loop between
    /// iterations, or leave it 0 if the action's first step does the
    /// blocking itself (e.g., a long-poll http_call).
    #[serde(default, skip_serializing_if = "is_false")]
    pub continuous: bool,

    /// Milliseconds to sleep between continuous iterations.
    /// Ignored when `continuous` is false. A value of 0 means
    /// "iterate as fast as the DAG completes" — sensible only when the
    /// DAG itself blocks (long-poll, awaiting a queue, etc.) so the
    /// loop doesn't spin.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub interval_ms: u64,

    /// Opt-in to parallel-wave execution. When `true`, steps
    /// in the same DAG wave are fanned out across tokio tasks; each
    /// task gets its own forked `ExecutionState`
    /// and its writes are merged at join.
    ///
    /// Defaults to `false` because the DAG planner only follows
    /// `$steps.<id>` / `{{$steps.<id>}}` references — `extract`/`transform`
    /// step types that reference upstream steps via a plain `source`
    /// field, variable reads (`{{$vars.X}}`), and iteration step types
    /// (`for_each`, `repeat`, `ifs`) carry communication channels the
    /// planner can't see, so unconditional parallelism would race.
    /// Manifests that want concurrency (the obvious one being the
    /// streaming-dataflow form) opt in explicitly.
    #[serde(default, skip_serializing_if = "is_false")]
    pub parallel_waves: bool,

    /// Streaming-dataflow scheduler opt-in. When `true`, the
    /// kernel routes execution to `execute_dag_dataflow` instead of the
    /// wave-based scheduler. Every step in the action runs concurrently
    /// in its own tokio task from the start; steps marked
    /// [`StepDef::long_running`] stay alive until their stream source
    /// closes (or cancellation fires); downstream consumers loop on
    /// `stream_read` against pre-provisioned readable branches and
    /// terminate naturally on EOF.
    ///
    /// Produces a single [`ActionResult`] at pipeline termination, with
    /// per-step results reflecting the final state of each long-running
    /// stage — the per-chunk events flow through the stream registry,
    /// not the action's return value.
    ///
    /// Mutually exclusive with [`Self::continuous`]: a dataflow pipeline
    /// IS the long-running form. Setting both is rejected at
    /// `register_plugin` time.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dataflow: bool,

    /// Per-action wallclock budget in milliseconds. Overrides the
    /// deployment default — `RuntimeLimits::default_wallclock_timeout`,
    /// or the `defaultWallclockTimeoutMs` key of `KernelConfig::settings`
    /// when the embedder supplies one.
    ///
    /// Precedence for a top-level invocation (an `ExecuteActionRequest`
    /// terminal, or an event dispatch):
    ///
    /// 0. `RuntimeLimits::max_wallclock_timeout`, when the operator set
    ///    one, clamps whatever the rest of this list produces.
    /// 1. Action declares its own value → use it.
    /// 2. Action is [`Self::dataflow`] `true` with no declaration →
    ///    **no automatic cap.** Cooperative cancellation via the
    ///    action's `CancellationToken` is the only tear-down primitive
    ///    for streaming pipelines. Plugin authors who
    ///    don't honour the cancellation token are the bug to fix; operators
    ///    have the cancel token + monitoring as the practical
    ///    backstop.
    /// 3. Else → deployment default (60 s out of the box, settings-tunable).
    ///
    /// Manifests that genuinely need a cap on a dataflow action
    /// (e.g. "this transcoding should never legitimately take more
    /// than 2 hours; if it does, kill it") declare the cap here
    /// explicitly. The two-hour case is `wallclockTimeoutMs: 7200000`.
    ///
    /// **Invoked as a callee** — reached through an `invoke` or alias
    /// step, `dispatch_role`, or a guest's `io.invoke` or
    /// `io.invoke_streaming` — and the caller
    /// has a deadline, the action is bounded by the caller's
    /// *remaining* budget instead of cases 2 and 3: a declaration still
    /// applies (clamped to what the caller has left), but a dataflow
    /// callee is not uncapped and an undeclared callee is not cut to
    /// the deployment default. A callee of an *uncapped* caller has no
    /// budget to inherit and is bounded exactly as at top level. A
    /// callee's own deadline surfaces in the caller as a failed step
    /// (`CalleeFailed` wrapping `ExecutionTimeout`), not as the
    /// caller's cancellation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallclock_timeout_ms: Option<u64>,

    /// Exposes this action as a callable tool to an embedder that
    /// drives a tool-using LLM. When set, the registry-side
    /// `get_tool_descriptors()` query surfaces the action with its
    /// JSON Schema and a `(plugin_key, action_name)` dispatch pair,
    /// from which such an embedder builds its tool list and any
    /// schema-constrained sampling input.
    ///
    /// Omitted on actions that aren't callable by the LLM (engine
    /// internals, event handlers, plumbing actions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<ToolDef>,
}

/// Tool-call surface for an [`Action`] that wants to be exposed to an
/// embedder's LLM.
///
/// The triplet (name, description, parameters) is exactly what the LLM
/// sees when deciding whether to call the tool, so write each field for
/// the model — not for humans.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDef {
    /// Tool name as advertised to the LLM (e.g. `search_catalog`).
    /// Becomes the key the embedder's tool-call parser looks up to
    /// resolve which `(plugin_key, action_name)` to dispatch, so it must
    /// be unique across all tools the embedder enables together. Use
    /// `snake_case` to match common LLM tool-call conventions.
    pub name: String,

    /// One-paragraph natural-language description: what the tool does,
    /// when the LLM should call it, what shape it returns. The LLM
    /// reads this verbatim — phrase it as instruction, not API docs.
    pub description: String,

    /// JSON Schema for the tool's arguments object. An embedder that
    /// constrains sampling to this schema will refuse undeclared fields,
    /// so any field the LLM might want to pass MUST be declared here.
    /// Use `required` to
    /// flag mandatory fields; the LLM treats anything else as optional.
    pub parameters: Value,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

/// A step definition — a reference to a step type with parameters.
///
/// Steps are the atomic units of execution within an action. Each step
/// references a step type (e.g., `http_call`, `let`, `ifs`) and provides
/// parameters specific to that step type.
///
/// **Error recovery**: manifest authors express failure handling
/// through the `try` step type:
///
/// - To swallow a step's failure and continue, wrap it in
///   `{type: "try", try: [step], catch: []}`. An explicit (even empty)
///   `catch` block tells the engine to swallow the failure and continue
///   with the next step.
/// - To run recovery handlers on failure, wrap the step in
///   `{type: "try", try: [step], catch: [...handlers...]}`. The
///   `{{$.error}}` binding is available inside `catch`.
///
/// The kernel's `try` runtime handles both the recovery and the
/// finally-block needed for cleanup; manifest authors get full
/// expressiveness with a single uniform shape.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct StepDef {
    /// Step identifier, unique within the action's step sequence.
    pub id: String,

    /// Step type name (e.g., `http_call`, `let`, `extract`, `ifs`).
    /// Resolved against the kernel's intrinsics, plugin-supplied step
    /// type aliases, and step_type_impls at registration time.
    #[serde(rename = "type")]
    pub step_type: String,

    /// Step-type-specific parameters, under an explicit `"params"` key.
    ///
    /// An object; absent means `{}`. Everything the step *type* reads
    /// lives here — `http_call`'s `url`, `let`'s `value`, `script`'s
    /// `language` and `source`, and the bodies of the control-flow
    /// intrinsics (`try`/`catch`/`finally`, `then`/`else`, `steps`,
    /// `branches`).
    ///
    /// # Why not flattened
    ///
    /// If params were `#[serde(flatten)]`ed into the step object, the
    /// set of step-level keywords would be open: every key that was
    /// not one of the reserved step-level keys would belong to the step
    /// type. Every future step-level feature — `retry`, `timeout`,
    /// `onError`, `when` — would then be a new key that silently
    /// *captured* any deployed manifest already using that name as a
    /// param, and `formatVersion` could not save it cheaply because the
    /// serde layout is version-blind. That is the same
    /// silent-reinterpretation failure the permission grammar spends
    /// hundreds of lines preventing, at the most-authored surface in
    /// the format. The explicit key closes it: step-level keywords and
    /// step-type params are different namespaces, and the step object
    /// rejects anything it does not know (`deny_unknown_fields`,
    /// mirrored by `additionalProperties: false` in the meta-schema).
    #[serde(default = "empty_object", skip_serializing_if = "Value::is_null")]
    pub params: Value,

    /// Bind the step's result to a named variable in addition to
    /// `{{$steps.<id>.result}}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_to_variable: Option<String>,

    /// Explicit dependencies on other steps in the same action, by id.
    ///
    /// The DAG planner derives most dependencies automatically by scanning
    /// step params for `$steps.<id>.<field>` references (bare or templated).
    /// Use `depends_on` only when a dependency can't be observed there — most
    /// notably when a `script` step reads a previous step's output through
    /// the script runtime's own API rather than via a templated param.
    /// Without this declaration, the planner would place such a step
    /// in the first wave (no observable deps) and run it before its
    /// producers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,

    /// Marks this step as a long-running producer in a streaming-dataflow
    /// action. The dataflow scheduler pre-provisions an output
    /// stream for the step (writable handle on the producer side, readable
    /// handle on each consumer's side, fanned-out when there are >1
    /// consumers) and spawns the step's task expecting it to run until
    /// either the upstream source closes or the action's cancellation
    /// token fires.
    ///
    /// Ignored when the parent action's [`Action::dataflow`] is `false`.
    /// Setting `long_running: true` in a non-dataflow action is a
    /// `register_plugin` validation error.
    ///
    /// Pure consumer steps (those that read from upstream until EOF and
    /// then return) do NOT need this marker — they terminate naturally
    /// when their upstream stream closes.
    #[serde(default, skip_serializing_if = "is_false")]
    pub long_running: bool,
}

// ---------------------------------------------------------------------------
// Step type parameters (well-known step types)
// ---------------------------------------------------------------------------

/// Parameters for the `http_call` step type. `http_call` is an
/// embedder-provided step type — the kernel ships only its intrinsics —
/// but the parameter shape is defined here so embedder impls and the
/// kernel agree on it.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpCallParams {
    pub url: String,
    #[serde(default = "default_get")]
    pub method: String,
    #[serde(default)]
    pub query_params: IndexMap<String, String>,
    #[serde(default)]
    pub headers: IndexMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

fn default_get() -> String {
    "GET".to_string()
}

/// Parameters for the `for_each` step type.
///
/// **Inner step result lifecycle.** The runtime clears each inner
/// step's `step_results` / metadata entry at the top of every
/// iteration, so an iteration body that skips a step (a step inside an
/// `ifs` branch not taken this time, a `try` body that failed early)
/// sees a clean slate rather than the previous iteration's
/// value. The **last** iteration's inner step results survive the
/// loop — they're never cleared by a next-iteration top-of-loop
/// because no next iteration runs — and outer-scope steps and
/// `resultMapping` can read them like any other step output. Use
/// `collect` (below) when you need every iteration's values, not
/// just the last one.
///
/// **`collect`.** When set, each iteration evaluates the DSL
/// expression and pushes the value onto a per-loop accumulator.
/// Once the loop exits, the for_each step's own result is set to the
/// assembled array (readable via `$steps.<for_each_id>.result`).
/// Without `collect`, the for_each step's own result is an empty
/// array — reach for the last iteration's inner-step results
/// directly, or add a `collect` expression.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForEachParams {
    /// DSL path expression to extract iteration items.
    pub path: String,
    /// Source step ID to iterate over. Defaults to first step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Steps to execute for each item.
    pub steps: Vec<StepDef>,
    /// Optional DSL expression evaluated after each iteration's body.
    /// The resulting value is pushed onto an accumulator; the
    /// for_each step's own result becomes the assembled array.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collect: Option<String>,
}

/// Parameters for the `repeat` step type. Executes `steps` `count`
/// times. The current iteration number (0-based) is bound to `{{$item}}`
/// in inner steps, reusing the same surface `for_each` exposes.
///
/// When `until` is set, after each iteration body runs the DSL
/// expression is evaluated against the action's full resolution
/// context (input, config, steps, vars, secrets). If truthy, the loop
/// exits early — `count` keeps acting as the safety cap. The body
/// always runs at least once (unless `count` is 0): `until` is a
/// do-until, not a while.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepeatParams {
    /// Number of iterations. May be a JSON number or a string template
    /// (e.g. `"{{$config.iterations}}"`) that resolves to a non-negative
    /// integer at execution time.
    pub count: Value,
    /// Steps to execute on each iteration.
    pub steps: Vec<StepDef>,
    /// Optional DSL expression evaluated after each iteration's body.
    /// If truthy, the loop exits before the next iteration. References
    /// to inner-step results (e.g., `$steps.last_inner.result.done`)
    /// resolve against the just-completed iteration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    /// Optional DSL expression evaluated after each iteration's body
    /// (mirrors `ForEachParams.collect`). The value is pushed onto a
    /// per-loop accumulator; the repeat step's own result becomes the
    /// assembled array, readable via `$steps.<id>.result`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collect: Option<String>,
}

/// Parameters for the `extract` step type. `extract` (like the
/// `transform` pipeline it can carry) is an embedder-provided step
/// type — the kernel ships only its intrinsics — but the parameter
/// shape is defined here so embedder impls and the kernel agree on it.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractParams {
    /// DSL path expression.
    pub path: String,
    /// Source step ID. Defaults to first step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Transforms to apply after extraction.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transforms: Vec<TransformDef>,
    /// Fallback extraction if primary path returns null.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<Box<ExtractParams>>,
}

/// A transform in the extraction pipeline.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransformDef {
    #[serde(rename = "type")]
    pub transform_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub separator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

/// Parameters for the `set_var` step type — embedder-provided, like
/// `extract`; the kernel's own variable-write primitive is `let` with
/// `storeToVariable`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetVarParams {
    /// Variable name to set.
    pub name: String,
    /// Value expression (supports `{{template}}` resolution).
    pub value: Value,
}

/// One entry of a manifest's `usesSecrets`.
///
/// In JSON this is either a bare string — the key, not overridable —
/// or an object `{ "key": "...", "overridable": true }`. A single list
/// with a per-entry flag means a key cannot be marked overridable
/// without also being declared: there is no second list to drift out
/// of step with the first.
///
/// `overridable` is how a root-level plugin holding a default credential
/// lets a level below it bring a better one: a metadata plugin marks
/// `apiToken` overridable, and when its body runs on behalf of a
/// namespaced caller the embedder's resolver may answer with that
/// level's token in place of the root one. The marking lives in the
/// manifest so it is auditable; the substitution happens in the embedder's
/// [`SecretResolver`](super::secrets::SecretResolver), which is handed
/// the marked keys as
/// [`SecretRequest::overridable_keys`](super::secrets::SecretRequest::overridable_keys).
///
/// Only the level that owns a key may mark it, for the levels below —
/// which at depth two means a root-namespace manifest. A namespaced
/// manifest marking anything overridable is rejected at load.
///
/// Mark only keys where "a lower level can silently change what this
/// plugin does" is the intent — credentials that level owns. Not
/// endpoints, not identifiers, not anything that redirects the plugin's
/// behaviour: marking `webhookUrl` overridable lets a lower level point
/// a root-credentialed plugin at itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretDecl {
    /// The key as it appears in `{{$secrets.<key>}}`.
    pub key: String,
    /// Whether a level below the declaring plugin may supply its own
    /// value for this key.
    pub overridable: bool,
}

impl SecretDecl {
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            overridable: false,
        }
    }

    pub fn overridable(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            overridable: true,
        }
    }
}

impl<'de> Deserialize<'de> for SecretDecl {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Key(String),
            Full {
                key: String,
                #[serde(default)]
                overridable: bool,
            },
        }
        let decl = match Raw::deserialize(d)? {
            Raw::Key(key) => SecretDecl {
                key,
                overridable: false,
            },
            Raw::Full { key, overridable } => SecretDecl { key, overridable },
        };
        if decl.key.is_empty() {
            return Err(serde::de::Error::custom(
                "usesSecrets: a secret key must be non-empty",
            ));
        }
        Ok(decl)
    }
}

impl Serialize for SecretDecl {
    /// Round-trips to the shortest spelling: a bare string unless the
    /// key is overridable.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.overridable {
            use serde::ser::SerializeStruct;
            let mut st = s.serialize_struct("SecretDecl", 2)?;
            st.serialize_field("key", &self.key)?;
            st.serialize_field("overridable", &true)?;
            st.end()
        } else {
            s.serialize_str(&self.key)
        }
    }
}

impl PluginManifest {
    /// Every declared secret key, in manifest order.
    pub fn declared_secret_keys(&self) -> Vec<String> {
        self.uses_secrets.iter().map(|d| d.key.clone()).collect()
    }

    /// The declared keys marked overridable, in manifest order.
    pub fn overridable_secret_keys(&self) -> Vec<String> {
        self.uses_secrets
            .iter()
            .filter(|d| d.overridable)
            .map(|d| d.key.clone())
            .collect()
    }
}

/// Parameters for the `ifs` step type.
///
/// Shaped like a `match`: an ordered list of branches, the first whose
/// `test` is truthy runs. A branch with no `test` always matches, so an
/// "else" is simply a final untested branch; manifest validation
/// requires such a branch to be last, since anything after it would be
/// unreachable.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IfsParams {
    /// Branches evaluated in order. First matching branch executes.
    pub ifs: Vec<IfBranch>,
}

/// A single branch in an `ifs` step.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IfBranch {
    /// Bare DSL condition. `None` (omitted or `null`) always matches —
    /// the "else" branch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test: Option<String>,
    /// Steps to execute when the branch is chosen.
    #[serde(rename = "then")]
    pub then_steps: Vec<StepDef>,
}

/// Parameters for the `log` step type (embedder-provided, like
/// `extract`).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogParams {
    #[serde(default = "default_info")]
    pub level: String,
    pub message: String,
}

fn default_info() -> String {
    "info".to_string()
}

// ---------------------------------------------------------------------------
// Execution results
// ---------------------------------------------------------------------------

/// The result of executing an action through the kernel.
#[derive(Debug, Clone)]
pub struct ActionResult {
    /// The action's output value (extracted via results_path + result_mapping).
    pub output: Value,
    /// All variable bindings at the end of execution.
    pub variables: IndexMap<String, Value>,
    /// Per-step results keyed by step ID.
    pub step_results: IndexMap<String, Value>,
}

// ---------------------------------------------------------------------------
// Shared sub-types
// ---------------------------------------------------------------------------

/// Configuration schema — system-provided and user-configurable fields.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSchema {
    #[serde(default)]
    pub system_fields: Vec<ConfigField>,
    #[serde(default)]
    pub user_fields: Vec<ConfigField>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigField {
    pub key: String,
    pub display_name: Option<String>,
    #[serde(rename = "type")]
    pub field_type: String,
    #[serde(default)]
    pub required: bool,
    pub default_value: Option<Value>,
    pub description: Option<String>,
    #[serde(default)]
    pub options: Vec<String>,
    #[serde(default)]
    pub secret: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthSpec {
    #[serde(rename = "type")]
    pub auth_type: String,
    pub header_name: Option<String>,
    pub config_key: Option<String>,
}

// ---------------------------------------------------------------------------
// Constructors for the `#[non_exhaustive]` manifest tree
// ---------------------------------------------------------------------------
//
// The manifest format grows, and every field added to it must not be a
// semver break for embedders that build one in Rust. Each of these
// types is `#[non_exhaustive]`, so a struct literal is impossible
// outside the crate; construct with `new` and assign the fields you
// need — they are all `pub`. Deserializing from JSON is the normal path
// and is unaffected.

impl PluginManifest {
    /// An empty manifest named `name`: no actions, no roles, no
    /// permissions, nothing declared. Assign fields to fill it in.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }
}

impl StepTypeDef {
    /// A step type named `name` with no schemas, no selector, no
    /// references, and `freely_usable: false`.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }
}

impl Action {
    /// An action running `steps` in order, with no result mapping,
    /// schemas, subscriptions, or timing flags.
    pub fn new(steps: Vec<StepDef>) -> Self {
        Self {
            steps,
            ..Default::default()
        }
    }
}

fn empty_object() -> Value {
    Value::Object(Default::default())
}

impl StepDef {
    /// Parse an inner-body step (an element of a `try`/`catch`/`then`/
    /// `steps`/`branches` array) from its JSON value.
    ///
    /// Insists on an object. `serde` would otherwise accept an *array*
    /// positionally — `["a", "b", {}]` as `id: "a", type: "b"` — which
    /// is never what a manifest author meant.
    pub fn from_inner_value(v: &Value) -> Result<Self, serde_json::Error> {
        if !v.is_object() {
            return Err(serde::de::Error::custom(format!(
                "a step must be an object with `id` and `type`, got {}",
                match v {
                    Value::Array(_) => "an array",
                    Value::String(_) => "a string",
                    Value::Number(_) => "a number",
                    Value::Bool(_) => "a boolean",
                    Value::Null => "null",
                    Value::Object(_) => unreachable!(),
                }
            )));
        }
        serde_json::from_value(v.clone())
    }

    /// A step `id` of type `step_type` with the given raw `params`.
    pub fn new(id: impl Into<String>, step_type: impl Into<String>, params: Value) -> Self {
        Self {
            id: id.into(),
            step_type: step_type.into(),
            params,
            ..Default::default()
        }
    }
}
