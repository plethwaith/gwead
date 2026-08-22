//! Native step-type implementation discovery via the `inventory` crate.
//!
//! Plugin crates push their step-body fn pointers into a global slice
//! at link time using `inventory::submit!`. The kernel walks the slice
//! once at boot via [`NativeStepImplTable::discover`] and resolves
//! manifest references against the resulting table.
//!
//! This is the *only* path for native step type implementations:
//! every step body, kernel intrinsic or external plugin, declares its
//! impl in a manifest's `stepTypeImpls` block with `kind: "native"`
//! (the engine's own engine-internal bodies use `kind: "intrinsic"`
//! through the same block) and submits the fn pointer via
//! `inventory::submit!`. There is no imperative registration API on
//! `Kernel`.
//!
//! ## Plugin author usage
//!
//! ```ignore
//! pub fn step_my_thing<'a>(
//!     ex: &'a mut (dyn gwead::kernel::PluginExecution + Send),
//!     params: &'a serde_json::Value,
//! ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<StepOutput, StepError>> + Send + 'a>> { /* … */ }
//!
//! gwead::native_step_impl!("myapp.my_plugin.my_thing", step_my_thing);
//! ```
//!
//! Plus the corresponding manifest entry:
//!
//! ```json
//! {"stepType": "my_thing", "kind": "native", "implRef": "myapp.my_plugin.my_thing"}
//! ```
//!
//! [`native_step_impl!`](crate::native_step_impl) is the supported way
//! to submit. It wraps `inventory::submit!`, so plugin crates need no
//! `inventory` dependency of their own, and — the reason it exists —
//! [`NativeStepImplEntry`] stays an implementation detail the kernel
//! can add fields to instead of a shape frozen by every struct literal
//! ever written against it.
//!
//! ## Naming: the middle segment is the owner
//!
//! Naming here is **not** merely convention. The `<plugin>` segment is
//! what the kernel treats as a body's owner:
//!
//! - A plugin may bind any implRef whose `<plugin>` segment matches its
//!   own manifest name, declaring nothing — but only in the root
//!   namespace, where the manifest and the compiled-in body come from
//!   the same party.
//! - Anything else needs `bind:native_impl:<implRef>` in the manifest
//!   **and** the exact pair in
//!   [`KernelConfig::native_impl_bindings`](super::KernelConfig::native_impl_bindings).
//! - An implRef that is not three dot-separated segments has no
//!   derivable owner, so it is never freely bindable.
//!
//! The owner check is what makes binding safe: resolving `implRef` by
//! exact string match against one global table with no owner check
//! would let a manifest declaring no permissions bind another plugin's
//! privileged body as its own step type.
//!
//! ## Naming convention (the rest of it, still convention)
//!
//! `implRef` strings follow the dotted three-segment form:
//!
//! ```text
//! <owner>.<plugin>.<step>
//! ```
//!
//! - **`<owner>`** — who *ships* this code: an org or application
//!   slug. (Not a plugin's registration namespace, which is the `/`
//!   prefix the embedder supplies.) Reserved namespaces:
//!   - **`gwead`** — the engine itself. The only legitimate
//!     `gwead.*` submissions come from this crate's own
//!     intrinsics manifest (loaded via `load_manifest` at boot).
//!     Plugin crates outside this crate MUST
//!     NOT submit `gwead.*` names.
//!   - **The embedding application's namespace** (`myapp` in
//!     the examples here) — plugins the host application ships in
//!     its own binary. The host that ships the binary is what counts.
//!   - **Anything else** — third-party plugins shipped independently
//!     of the host. Convention is reverse-DNS or org slug:
//!     `acme-corp.payments.charge`, `com.example.audit.log`.
//! - **`<plugin>`** — the plugin crate's short name (drop any
//!   `<owner>-plugin-` prefix from the crate name —
//!   `myapp.s3.store`, not `myapp.myapp-plugin-s3.store`).
//! - **`<step>`** — the step type's logical name. Match the
//!   `stepType` value in the manifest's `stepTypeImpls` entry; the
//!   step type's full identifier need not appear in the implRef
//!   (manifest says `s3_store` → implRef can be `myapp.s3.store`,
//!   no need to encode `s3_` twice).
//!
//! The convention is convention only — table lookup is exact-match.
//! But disciplined naming catches typos cleanly: a manifest that
//! references `myapp.sigv4.singn` errors at register time
//! because nothing submitted that name, naming the missing impl in
//! the error message.

use std::collections::HashMap;

use super::runtime::{IntrinsicStepFn, StepFn};

/// A Rust-shaped native step-type implementation. Type alias for
/// [`StepFn`] — the wasmtime adapter shape every step body returning
/// `Result<StepOutput, StepError>` conforms to.
pub type NativeStepImpl = StepFn;

/// One inventory entry — pushed by a plugin crate via
/// `inventory::submit!` and collected by
/// [`NativeStepImplTable::discover`] at kernel-boot time.
///
/// The `name` is the string a manifest's `stepTypeImpls[].implRef`
/// references; convention is dotted-namespaced (see module docs).
///
/// ## Convention: impls resolve their own params
///
/// The `params: &Value` argument the impl receives is the **raw**
/// step body from the manifest — `{{template}}` strings are still
/// unresolved. Impls that read templated fields (the common case)
/// must call:
///
/// ```ignore
/// let ctx = ex.resolution_context();
/// let resolved = ex.resolve_value_with(params, &ctx);
/// // …read fields off `resolved`, not `params`
/// ```
///
/// Every native step impl follows this same shape. The kernel does
/// not pre-resolve before calling — by design, so impls that need
/// access to the unresolved template (rare) can opt out of the work.
///
/// ## Construct with [`native_step_impl!`](crate::native_step_impl)
///
/// The fields are private on purpose. This type is constructed by
/// external crates at link time, which would otherwise freeze its shape
/// permanently: `inventory::submit!` takes a struct literal, a literal
/// names every field, and so adding one would break every plugin crate
/// that ever submitted a body. It cannot be `#[non_exhaustive]` either
/// — literal construction is the whole point.
///
/// Routing construction through a macro makes the layout an
/// implementation detail that can gain fields whenever the kernel needs
/// one. Recording a body's owner at submission time — so ownership
/// comes from the crate that shipped the code rather than being derived
/// from the manifest's name — is the kind of field this keeps addable
/// without a breaking release.
pub struct NativeStepImplEntry {
    name: &'static str,
    impl_: NativeStepImpl,
    /// Set only by [`Self::kernel`], which is crate-private. This is
    /// what makes the `gwead.` prefix a *mechanical* reservation: a
    /// table refuses any `gwead.*` entry without it, so an outside
    /// crate cannot submit one — neither to collide with the kernel's
    /// (a boot failure by dependency) nor to shadow it.
    kernel_owned: bool,
}

/// The implRef prefix reserved for the engine's own bodies.
pub const KERNEL_IMPL_REF_PREFIX: &str = "gwead.";

impl NativeStepImplEntry {
    /// Build an entry. Prefer
    /// [`native_step_impl!`](crate::native_step_impl), which wraps this
    /// together with the `inventory::submit!` boilerplate.
    ///
    /// `const` because `inventory::submit!` places the value in a
    /// static.
    #[must_use]
    pub const fn new(name: &'static str, impl_: NativeStepImpl) -> Self {
        Self {
            name,
            impl_,
            kernel_owned: false,
        }
    }

    /// An entry the engine itself ships — the only way to submit a
    /// `gwead.*` name.
    #[must_use]
    pub(crate) const fn kernel(name: &'static str, impl_: NativeStepImpl) -> Self {
        Self {
            name,
            impl_,
            kernel_owned: true,
        }
    }

    /// Refuse a `gwead.*` name from anyone but the engine.
    fn check_reservation(name: &str, kernel_owned: bool) -> Result<(), NativeImplCollision> {
        if name.starts_with(KERNEL_IMPL_REF_PREFIX) && !kernel_owned {
            return Err(NativeImplCollision::Reserved {
                name: name.to_string(),
            });
        }
        Ok(())
    }

    /// The `implRef` string a manifest uses to reference this body.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }
}

inventory::collect!(NativeStepImplEntry);

/// Submit a native step-type implementation for the kernel to discover
/// at boot.
///
/// Wraps `inventory::submit!` so plugin crates neither depend on
/// `inventory` directly nor construct
/// [`NativeStepImplEntry`] by hand — which is what lets that type
/// evolve without breaking every plugin crate.
///
/// ```ignore
/// use gwead::kernel::host_api::{PluginExecution, StepError, StepOutput};
///
/// pub fn step_my_thing<'a>(
///     ex: &'a mut (dyn PluginExecution + Send),
///     params: &'a serde_json::Value,
/// ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<StepOutput, StepError>> + Send + 'a>> {
///     /* … */
/// }
///
/// gwead::native_step_impl!("myapp.my_plugin.my_thing", step_my_thing);
/// ```
///
/// Plus the matching manifest entry:
///
/// ```json
/// {"stepType": "my_thing", "kind": "native", "implRef": "myapp.my_plugin.my_thing"}
/// ```
///
/// # Name the middle segment after your plugin
///
/// The `<plugin>` segment of `<owner>.<plugin>.<step>` is what the
/// kernel treats as the body's owner. A plugin may bind a body whose
/// middle segment matches its own manifest name without declaring
/// anything; binding anything else needs
/// `bind:native_impl:<implRef>` plus embedder authorisation. Matching
/// the two is therefore not merely tidy — it is the difference between
/// a manifest that loads and one that needs an operator's involvement.
#[macro_export]
macro_rules! native_step_impl {
    ($name:expr, $impl_:expr $(,)?) => {
        $crate::__private::inventory::submit! {
            $crate::kernel::native_impls::NativeStepImplEntry::new($name, $impl_)
        }
    };
}

/// Built at kernel-boot time from the inventory slice; holds every
/// Rust-shaped step body any compiled-in plugin crate submitted.
/// Manifest loading resolves `implRef` strings against this table.
///
/// `Default` produces an empty table — useful for tests that don't
/// need any native impls and don't want to walk the inventory slice.
#[derive(Default, Debug)]
pub struct NativeStepImplTable {
    impls: HashMap<String, NativeStepImpl>,
}

impl NativeStepImplTable {
    /// Walk the global inventory slice and build the table. Returns
    /// [`NativeImplCollision`] if two crates submitted the same name
    /// — the kernel can't pick a winner safely so it refuses at boot
    /// rather than silently choosing one.
    ///
    /// Typically called once at host bootstrap:
    /// ```ignore
    /// let kernel = Kernel::boot(
    ///     KernelConfig::default().with_native_step_impls(NativeStepImplTable::discover()?),
    /// )?;
    /// ```
    pub fn discover() -> Result<Self, NativeImplCollision> {
        Self::from_entries(inventory::iter::<NativeStepImplEntry>())
    }

    /// Build a table from an arbitrary iterator of entries. Same
    /// collision semantics as [`Self::discover`], but takes the input
    /// explicitly so tests can exercise the collision path without
    /// polluting the global inventory slice.
    pub fn from_entries<'a, I>(entries: I) -> Result<Self, NativeImplCollision>
    where
        I: IntoIterator<Item = &'a NativeStepImplEntry>,
    {
        let mut impls = HashMap::new();
        for entry in entries {
            NativeStepImplEntry::check_reservation(entry.name, entry.kernel_owned)?;
            if impls.insert(entry.name.to_string(), entry.impl_).is_some() {
                return Err(NativeImplCollision::Duplicate {
                    name: entry.name.to_string(),
                });
            }
        }
        Ok(Self { impls })
    }

    /// Empty table — equivalent to `Self::default()`. Spelled out as
    /// a named constructor so test code reads intent at the call site.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Insert a single impl after construction. Used by test fixtures
    /// that need to register ad-hoc step bodies which don't make
    /// sense to submit via `inventory::submit!` (test-only closures,
    /// per-test variants of a body). Returns
    /// [`NativeImplCollision`] if the name is already taken — same
    /// guarantee as [`Self::from_entries`].
    ///
    /// Production code SHOULD NOT call this. The expected pattern is:
    /// `inventory::submit!` from the providing crate, then
    /// `NativeStepImplTable::discover()` at host boot. This method
    /// exists so test fixtures don't need a separate kernel-mutation
    /// back-door.
    pub fn insert(&mut self, name: &str, impl_: NativeStepImpl) -> Result<(), NativeImplCollision> {
        // An embedder table entry is never the engine's, so this also
        // closes the override path: a pre-seeded `gwead.intrinsics.let`
        // would otherwise win over the real one in
        // `ensure_from_inventory`.
        NativeStepImplEntry::check_reservation(name, false)?;
        if self.impls.insert(name.to_string(), impl_).is_some() {
            return Err(NativeImplCollision::Duplicate {
                name: name.to_string(),
            });
        }
        Ok(())
    }

    /// Insert every inventory entry that isn't already present.
    /// Called from `Kernel::boot` to top up an embedder-supplied
    /// table with any submissions the embedder didn't explicitly
    /// pull in — most importantly the kernel's own
    /// `gwead.intrinsics.*` impls, which `Kernel::boot` needs to wire
    /// dispatch for the intrinsics manifest.
    ///
    /// Entries the embedder already populated (via [`Self::insert`]
    /// or [`Self::discover`]) win — this is insert-if-absent. That
    /// lets test fixtures override an inventory submission with a
    /// test-only variant while still getting all the other inventory
    /// entries for free.
    pub(crate) fn ensure_from_inventory(&mut self) -> Result<(), NativeImplCollision> {
        self.ensure_from_entries(inventory::iter::<NativeStepImplEntry>())
    }

    /// [`Self::ensure_from_inventory`] over an explicit iterator, so
    /// the top-up semantics can be tested without the global slice.
    pub(crate) fn ensure_from_entries<'a, I>(
        &mut self,
        entries: I,
    ) -> Result<(), NativeImplCollision>
    where
        I: IntoIterator<Item = &'a NativeStepImplEntry>,
    {
        for entry in entries {
            NativeStepImplEntry::check_reservation(entry.name, entry.kernel_owned)?;
            // Skip if the embedder already provided this name (their
            // entry wins — see method docs).
            self.impls
                .entry(entry.name.to_string())
                .or_insert(entry.impl_);
        }
        Ok(())
    }

    /// Resolve an `implRef` to its registered impl. Returns `None`
    /// when the manifest references a name no plugin crate submitted
    /// — manifest registration surfaces this as a clear error.
    pub fn get(&self, name: &str) -> Option<NativeStepImpl> {
        self.impls.get(name).copied()
    }

    /// Number of registered impls. Mostly useful for boot-time
    /// telemetry / tests.
    pub fn len(&self) -> usize {
        self.impls.len()
    }

    /// Whether the table holds zero entries — handy for the common
    /// "no native plugins compiled in" check.
    pub fn is_empty(&self) -> bool {
        self.impls.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Intrinsic (kernel-internal) step impls
// ---------------------------------------------------------------------------

/// A kernel-internal native step body — type alias for [`IntrinsicStepFn`]
/// (concrete `&mut ExecutionState`). Distinct from [`NativeStepImpl`]:
/// these bodies need engine internals the public plugin surface doesn't
/// expose, so external crates can't supply them (they can't even name
/// `ExecutionState`). Only the engine's own `gwead.intrinsics.*` bodies
/// register here.
pub(crate) type IntrinsicStepImpl = IntrinsicStepFn;

/// One inventory entry for a kernel-internal step body. Mirrors
/// [`NativeStepImplEntry`] but carries an [`IntrinsicStepImpl`]; the
/// `intrinsics.json` manifest resolves these through `stepTypeImpls`
/// entries with `kind: "intrinsic"`.
pub(crate) struct IntrinsicStepImplEntry {
    pub name: &'static str,
    pub impl_: IntrinsicStepImpl,
}

inventory::collect!(IntrinsicStepImplEntry);

/// Built at kernel-boot time from the inventory slice; holds every
/// kernel-internal step body the engine submitted. Manifest loading
/// resolves `kind: "intrinsic"` `implRef` strings against this table.
///
/// Unlike [`NativeStepImplTable`] this is never embedder-supplied — the
/// only legitimate contributors are gwead's own intrinsics — so
/// `Kernel::boot` builds it purely from inventory via [`Self::discover`].
#[derive(Default, Debug)]
pub(crate) struct IntrinsicStepImplTable {
    impls: HashMap<String, IntrinsicStepImpl>,
}

impl IntrinsicStepImplTable {
    /// Walk the global inventory slice and build the table. Same
    /// collision semantics as [`NativeStepImplTable::discover`] — two
    /// submissions of the same name is an engine bug, so refuse at boot.
    pub(crate) fn discover() -> Result<Self, NativeImplCollision> {
        Self::from_entries(inventory::iter::<IntrinsicStepImplEntry>())
    }

    /// Build a table from an explicit iterator of entries — lets tests
    /// exercise the collision path without touching the global slice.
    pub(crate) fn from_entries<'a, I>(entries: I) -> Result<Self, NativeImplCollision>
    where
        I: IntoIterator<Item = &'a IntrinsicStepImplEntry>,
    {
        let mut impls = HashMap::new();
        for entry in entries {
            if impls.insert(entry.name.to_string(), entry.impl_).is_some() {
                return Err(NativeImplCollision::Duplicate {
                    name: entry.name.to_string(),
                });
            }
        }
        Ok(Self { impls })
    }

    /// Resolve an `implRef` to its registered intrinsic body. `None`
    /// when no engine submission used that name — manifest registration
    /// surfaces this as a clear error.
    pub(crate) fn get(&self, name: &str) -> Option<IntrinsicStepImpl> {
        self.impls.get(name).copied()
    }
}

/// Two `inventory::submit!` entries with the same name — the kernel
/// can't pick a winner without smuggling ordering semantics in, so
/// [`NativeStepImplTable::discover`] refuses at boot. Surface this to
/// the embedder as a boot-time error rather than letting the wrong
/// impl silently win.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeImplCollision {
    /// Two submissions used the same name.
    #[error(
        "two crates registered native step impl '{name}' via inventory::submit!; \
         pick distinct names (convention: <owner>.<plugin>.<step> — see \
         gwead::kernel::native_impls module docs for the full rule)"
    )]
    Duplicate { name: String },
    /// A crate other than the engine submitted a `gwead.*` name.
    #[error(
        "native step impl '{name}' uses the reserved `gwead.` prefix, which only the \
         engine may submit; name it <your-namespace>.<plugin>.<step>"
    )]
    Reserved { name: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;

    // Trivial body that conforms to the StepFn shape — we don't
    // execute it, just need a fn pointer for the entries.
    fn dummy_impl<'a>(
        _ex: &'a mut (dyn super::super::host_api::PluginExecution + Send),
        _params: &'a serde_json::Value,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        super::super::host_api::StepOutput,
                        super::super::host_api::StepError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move { Ok(super::super::host_api::StepOutput::default()) })
    }

    fn other_impl<'a>(
        _ex: &'a mut (dyn super::super::host_api::PluginExecution + Send),
        _params: &'a serde_json::Value,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        super::super::host_api::StepOutput,
                        super::super::host_api::StepError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move { Ok(super::super::host_api::StepOutput::default()) })
    }

    // Intrinsic-shaped dummy: takes the concrete `ExecutionState`. Never
    // executed — just a fn pointer for the intrinsic-table entries.
    fn dummy_intrinsic<'a>(
        _ex: &'a mut super::super::host_api::ExecutionState,
        _params: &'a serde_json::Value,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        super::super::host_api::StepOutput,
                        super::super::host_api::StepError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move { Ok(super::super::host_api::StepOutput::default()) })
    }

    #[test]
    fn from_entries_builds_table_from_distinct_names() {
        let entries = [
            NativeStepImplEntry::new("crate-a.alpha", dummy_impl),
            NativeStepImplEntry::new("crate-b.beta", dummy_impl),
        ];
        let table =
            NativeStepImplTable::from_entries(&entries).expect("distinct names build cleanly");
        assert_eq!(table.len(), 2);
        assert!(table.get("crate-a.alpha").is_some());
        assert!(table.get("crate-b.beta").is_some());
        assert!(table.get("nonexistent").is_none());
    }

    #[test]
    fn from_entries_rejects_duplicate_names() {
        let entries = [
            NativeStepImplEntry::new("duplicate.name", dummy_impl),
            NativeStepImplEntry::new("other.name", dummy_impl),
            NativeStepImplEntry::new("duplicate.name", dummy_impl),
        ];
        let err = NativeStepImplTable::from_entries(&entries)
            .expect_err("duplicate name should produce a collision error");
        assert!(
            matches!(&err, NativeImplCollision::Duplicate { name } if name == "duplicate.name"),
            "{err:?}"
        );
        // Error message names the collision so the embedder can fix it.
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate.name"),
            "error message should name the collision: {msg}"
        );
        assert!(
            msg.contains("inventory::submit!"),
            "error message should point at the cause: {msg}"
        );
    }

    #[test]
    fn empty_table_constructs_and_reports_zero() {
        let table = NativeStepImplTable::empty();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert!(table.get("anything").is_none());
    }

    /// `ensure_from_inventory` must implement insert-if-absent: the
    /// embedder-supplied entry wins on collision, and any inventory
    /// entries not already present get added.
    ///
    /// Locks the precedence rule documented on the method —
    /// `Kernel::boot` relies on it to (a) guarantee gwead's own
    /// intrinsics show up even when the embedder supplies an empty
    /// table, and (b) let test fixtures override an inventory
    /// submission with a per-test variant.
    #[test]
    fn ensure_from_inventory_preserves_existing_and_tops_up_missing() {
        let mut table = NativeStepImplTable::empty();
        assert!(
            table.get("gwead.intrinsics.let").is_none(),
            "empty table has no inventory entries until ensure_from_inventory runs"
        );

        // Pre-seed an embedder name, then top up from an explicit entry
        // list that ALSO carries that name: the pre-seeded entry must
        // win, and the other entry must arrive.
        table
            .insert("myapp.x.a", dummy_impl)
            .expect("fresh table, insert succeeds");
        let entries = [
            NativeStepImplEntry::new("myapp.x.a", other_impl),
            NativeStepImplEntry::new("myapp.x.b", other_impl),
        ];
        table
            .ensure_from_entries(entries.iter())
            .expect("no reserved names");
        let resolved = table.get("myapp.x.a").expect("pre-seeded entry survives");
        assert!(
            std::ptr::fn_addr_eq(resolved, dummy_impl as NativeStepImpl),
            "ensure_from_entries must NOT overwrite the embedder's pre-existing entry"
        );
        assert!(
            table.get("myapp.x.b").is_some(),
            "missing entries are topped up"
        );

        // And the real inventory top-up brings the kernel's own bodies.
        let before_len = table.len();
        table
            .ensure_from_inventory()
            .expect("inventory holds no foreign gwead.* names");
        assert!(table.get("gwead.intrinsics.let").is_some());
        assert!(table.get("gwead.intrinsics.throw_error").is_some());
        assert!(table.len() > before_len);
    }

    /// The `gwead.` prefix is the engine's, mechanically: an embedder
    /// cannot pre-seed one (which would let a table override
    /// `gwead.intrinsics.let`), and a foreign submission of one fails
    /// the table build with a reason rather than as a bare collision.
    #[test]
    fn the_gwead_prefix_is_reserved_for_the_engine() {
        let mut table = NativeStepImplTable::empty();
        let err = table
            .insert("gwead.intrinsics.let", dummy_impl)
            .expect_err("embedders may not seed gwead.* names");
        assert!(matches!(err, NativeImplCollision::Reserved { .. }), "{err}");

        let foreign = [NativeStepImplEntry::new(
            "gwead.anything.at_all",
            dummy_impl,
        )];
        assert!(matches!(
            NativeStepImplTable::from_entries(foreign.iter()),
            Err(NativeImplCollision::Reserved { .. })
        ));
        assert!(matches!(
            NativeStepImplTable::empty().ensure_from_entries(foreign.iter()),
            Err(NativeImplCollision::Reserved { .. })
        ));

        let kernels = [NativeStepImplEntry::kernel(
            "gwead.intrinsics.probe",
            dummy_impl,
        )];
        NativeStepImplTable::from_entries(kernels.iter()).expect("the engine's own are fine");
    }

    /// Defensive test: the body-shaped intrinsics that are genuine
    /// plugins (`throw_error`, `let`) live in the NATIVE table; the
    /// kernel-internal ones (`invoke`, `wasm`, `script`) live in the
    /// INTRINSIC table. A refactor that drops, misfiles, or
    /// recategorises an `inventory::submit!` would make `intrinsics.json`
    /// fail to register at boot — this catches it at compile-test time.
    /// `script`'s submission in particular lives in
    /// `script_runtime_host/mod.rs` (cohesion with its impl), so it's
    /// the easiest to lose in a module move.
    #[test]
    fn intrinsic_submissions_land_in_the_right_tables() {
        let native = NativeStepImplTable::discover().expect("no collisions");
        assert!(
            native.get("gwead.intrinsics.throw_error").is_some(),
            "throw_error is a native (host-pluggable) intrinsic"
        );
        assert!(
            native.get("gwead.intrinsics.let").is_some(),
            "let is a native (host-pluggable) intrinsic"
        );
        // The kernel-internal trio must NOT be in the native table.
        assert!(native.get("gwead.intrinsics.invoke").is_none());
        assert!(native.get("gwead.intrinsics.wasm").is_none());
        assert!(native.get("gwead.intrinsics.script").is_none());

        let intrinsic = IntrinsicStepImplTable::discover().expect("no collisions");
        assert!(
            intrinsic.get("gwead.intrinsics.invoke").is_some(),
            "invoke needs the kernel back-ref — must be an intrinsic body"
        );
        assert!(
            intrinsic.get("gwead.intrinsics.wasm").is_some(),
            "wasm needs the wasmtime Engine — must be an intrinsic body"
        );
        assert!(
            intrinsic.get("gwead.intrinsics.script").is_some(),
            "script needs script_runtimes — must be submitted via \
             inventory::submit! from script_runtime_host/mod.rs as an \
             IntrinsicStepImplEntry; otherwise intrinsics.json fails at boot"
        );
        // And the native bodies must NOT leak into the intrinsic table.
        assert!(intrinsic.get("gwead.intrinsics.throw_error").is_none());
        assert!(intrinsic.get("gwead.intrinsics.let").is_none());
    }

    #[test]
    fn intrinsic_from_entries_rejects_duplicates() {
        let entries = [
            IntrinsicStepImplEntry {
                name: "dup.intrinsic",
                impl_: dummy_intrinsic,
            },
            IntrinsicStepImplEntry {
                name: "dup.intrinsic",
                impl_: dummy_intrinsic,
            },
        ];
        let err = IntrinsicStepImplTable::from_entries(&entries)
            .expect_err("duplicate intrinsic name should collide");
        assert!(
            matches!(&err, NativeImplCollision::Duplicate { name } if name == "dup.intrinsic"),
            "{err:?}"
        );
    }
}
