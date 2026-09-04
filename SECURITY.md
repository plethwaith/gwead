# Security Policy

## Reporting a vulnerability

Please report suspected security vulnerabilities privately to
**security@plethwaith.com**. Do not open a public issue for security reports.

You should receive an acknowledgement within a few days. Please include enough
detail to reproduce the issue (a minimal manifest, wasm module, or test case
helps enormously).

## Scope

Gwead sandboxes plugin wasm modules and script runtimes under WebAssembly.
In scope: anything that lets a guest escape that sandbox, exceed its resource
limits, or reach a **kernel-enforced** capability it was not granted — see
below for exactly which those are.

Native step implementations registered by the embedder are trusted host code
and out of scope.

## What the kernel enforces, and what it does not

Manifest permissions are not, by themselves, the authorization story. The
categories divide three ways, and the difference is not cosmetic:

**Enforced by the kernel.** `invoke:plugin:` / `invoke:role:` (cross-plugin
dispatch, default-deny), and `step_type:` (using a step type another plugin
defined — on both the alias path and the direct one). A guest cannot reach
these by not asking; the check is on the dispatch path itself. A bypass here
is a vulnerability — report it.

A step type's own definition may waive the `step_type:` requirement by
declaring `"freelyUsable": true`, which is how a shared pure-compute utility
stays cheap to reuse. The default is grant-required, so a step type that holds
a credential or performs I/O is gated unless its author deliberately opened it.

**Structural: enforced by the kernel, and no grant can relax it.** Two rules.

*Step-type naming.* A dot-free step type name is the kernel's — every bare word,
used or not — and a plugin-defined step type is `<plugin>.<name>` under the
defining plugin's own local name. The loader rejects a def or alias under any
other prefix, so no plugin can squat a future intrinsic or another plugin's
name, and `{"type": "vault.sign"}` says whose code runs. The owner segment
resolves along the using plugin's chain like a plugin reference; two
namespaces may each ship a `vault.sign`, and a tenant's shadows root's for that
tenant only.

*Namespace containment.* A plugin may dispatch only *upward along its own
ancestor chain* — into its own namespace or one enclosing it (root included),
never into a sibling namespace and never into a descendant. References and
`invoke:plugin:` grants resolve along that same chain, nearest namespace first,
so a tenant reaches a global plugin by naming it (with the grant), a tenant's
own plugin shadows a global one of the same name for that tenant only, and
`invoke:plugin:*` means "any plugin in my own namespace" and never reaches a
level above. Downward is refused because a plugin reachable by every tenant
must not be usable as a deputy into one of them; an orchestrator redirect
pointing down or sideways is rejected after the orchestrator runs. Roles follow
the same rule: a contract loads into a namespace, a fulfiller binds to the
nearest contract up its chain, and role dispatch sees only fulfillers on the
*caller's* chain — so a tenant registering a fulfiller for a global role can
never capture a global plugin's role dispatch. A bypass here is a
vulnerability — report it.

**Two-key: enforced by the kernel, but only if the operator countersigns.**
`provide:step_type:` for a kernel-defined step type such as `script`, and
`bind:native_impl:`. The manifest half makes the claim auditable in the
document an operator reviews; the authorising half is
`KernelConfig::trusted_step_type_providers` / `KernelConfig::native_impl_bindings`.
A manifest cannot assert its own authority here. If an embedder never sets
the config half, the claim is simply refused.

**Advisory: enforced by you, or by nobody.** `network:egress:` and `blobs:`.
Gwead ships no HTTP client and no blob store, so it has no boundary of its
own to gate and **never calls these checks**. They are parsed, stored, and
offered to the embedder via `PluginExecution::check_network_egress` /
`check_blobs`. If your step type performs network or blob I/O and does not
call them, the grants restrict nothing and nothing in the engine will notice.
Both are provisional: treat the check-call shape as subject to change in a
later release.

**Embedder-defined (`acme.*`) categories** are yours end to end. The kernel
checks at load only that the category was declared on `KernelConfig` (and, if
the category registered a validator, that the value passes it), so a
misspelled one is refused at load rather than becoming a grant that matches
nothing forever. It never consults the grant at run time.

## Known limitations

Deliberate, documented, and not treated as vulnerabilities in the current
release. Each is a boundary the kernel does not draw — tell us if one of them
is wrong for a real deployment, but do not report it as a bypass.

- **Events cross namespace boundaries.** `dispatch_event` fans out to every
  subscribing action in every namespace. An event has no calling plugin, so
  there is no namespace to bound the fan-out by. Chain containment (above)
  applies to `invoke` dispatch, not to event delivery. Do not treat
  namespaces as an isolation boundary for event payloads.
- **`ExecuteActionRequest::with_streams` grants the whole handle table.** Streams
  registered in the table you pass are reachable by the plugin you invoke.
  Handles are per-execution and a callee cannot reach its caller's, but the
  table you hand in at the top is the one the top-level plugin gets. Pass a
  table containing only what that plugin should hold.
- **Advisory capability checks** — see above. A step type that performs I/O
  without calling them is an embedder bug, not an engine bypass.
- **Root-namespace names are first-come.** A manifest loaded into the root
  namespace can call itself anything, including a name the embedder trusts in
  `KernelConfig`. Load manifests you did not author with
  `load_manifest(..).in_namespace(..)`; a namespaced plugin can never match a
  root-namespace config entry.
- **Cross-plugin dispatch forwards the caller's `config`.** Secrets never
  cross: every execution pulls its *own* credentials through the kernel's
  `SecretResolver`, narrowed to the keys its manifest declares in
  `usesSecrets`. That resolver is the only way credentials enter the kernel —
  there is no per-request bag — and with none registered nothing resolves.
  A dispatch plan has no secrets slot, so no orchestrator can attach one.
  Config still forwards, because callees routinely need the caller's
  resolution context — but it is caller data crossing a boundary, so do not
  put credential material in `config`.
  Register a custom `DispatchOrchestrator` if you need per-callee config
  resolution.
- **A step body sees its owner's secrets, not the caller's.** A native step
  type used from another plugin's action gets `ex.secrets()` = the defining
  plugin's bag, pulled per step through the resolver with `subject` = owner and
  `executing_plugin` = caller. The caller's bag is never ambient in foreign
  code; a caller delegates a secret deliberately by resolving it into a param.
  The two kernel intrinsics that run the caller's own code — `script` (narrowed
  by `passSecrets`) and `wasm` — see the caller's view, as they should. A global
  plugin may mark a `usesSecrets` entry `overridable`; the kernel hands those
  keys to the resolver, which may answer those keys — and only those — with
  the executing tenant's value. Mark credentials, never endpoints.
- **A `SecretResolver` is a liveness dependency.** A resolver error fails the
  action — or, for a foreign body's pull, the step — rather than running it
  without the credential, because a missing secret that presents as an absent
  one produces a wrong answer quietly.
- **Expression complexity caps fire at execution, not registration.** The DSL
  bounds nesting depth and operator count, and a manifest carrying a
  100k-paren condition registers cleanly and fails when that expression is
  first evaluated. The failure mode depends on where the expression sits: in
  template position it renders as `""`, in a `path` it yields `null` (the same
  as any unparsable expression), and as an `ifs` test, `until` clause, or
  `collect` expression it fails the step with a parse error. None of these is
  a bypass, and all apply only to a manifest the operator already loaded.
  Enforcing at load would mean parsing every expression in every manifest at
  registration.

## Resource bounds you may need to set

Gwead ships bounds on wasm memory, tables, memories, table elements,
instances, fuel, parallel fan-out width, action
wallclock, and cumulative step-result bytes. Three of them have deliberately
permissive defaults, because a safe default would break a legitimate
workload — if you run manifests you did not author, set them:

- **`RuntimeLimits::max_wallclock_timeout`** — default `None`. Without it,
  `RuntimeLimits::default_wallclock_timeout` is only what an action gets when
  it asks for nothing: a
  manifest declaring `wallclockTimeoutMs` replaces it in either direction, and
  a top-level `dataflow: true` action runs unbounded. That default exists
  because a streaming pipeline legitimately runs for days and the kernel cannot
  tell which of your actions those are. A callee is bounded by its caller's
  remaining budget when the caller has one — but a callee of an *unbounded*
  pipeline has nothing to inherit and is bounded as at top level, so an
  undeclared dataflow callee under it is unbounded too: one unbounded pipeline
  can hold an unbounded tree of them. The ceiling clamps all of it, the dataflow
  uncap included; that is the reason to set it. A manifest under the ceiling
  may still lower its own deadline but not raise it.
- **`RuntimeLimits::max_step_results_bytes`** — default 64 MiB. Step results
  are host memory, not wasm memory, and they compose: a chain of steps each
  referencing the previous result twice doubles per line. The bound is
  cumulative across sequential steps, parallel branches, parallel waves, the
  dataflow scheduler, and `collect` accumulators. Lower it if your actions do
  not legitimately hold tens of megabytes.
- **`RuntimeLimits::max_parallel_branches`** — default 64. Each branch of a
  `parallel` step forks the whole execution state, so width multiplies
  transient host memory; the worst case is roughly
  `max_parallel_branches x max_step_results_bytes`.

## Supported versions

Gwead is pre-1.0; only the latest release line receives security fixes.
