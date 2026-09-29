//! Coverage for `return` unwinding out of try sub-blocks and for the
//! wasm resource caps / module registry.
//!
//! Pins documented invariants the core intrinsics suite
//! (`intrinsics_tests.rs`) leaves unexercised:
//!
//! - `return` from inside `try.try` / `try.catch` / `try.finally`
//!   unwinds the whole action (skipping catch+finally / finally
//!   respectively). The parallel-branch `return` case lives in
//!   `parallel_concurrency_tests.rs`, as does the sleep-based
//!   concurrency proof.
//! - Wasm resource caps: a CPU-bound module trips the fuel budget
//!   cleanly, and a `memory.grow` loop is denied by the
//!   `ResourceLimiter` instead of OOMing the host.
//! - Multi-module wasm: one plugin shipping several modules, and two
//!   plugins shipping same-named modules — the registry key is
//!   `(plugin, module)`, not the bare name.
//!
//! All graphs are kernel-only (intrinsics + tiny WAT fixtures); no
//! plugins or mocks.

use std::sync::Arc;

use base64::Engine as _;
use gwead::kernel::types::*;
use gwead::kernel::{Kernel, KernelConfig, KernelError, RuntimeLimits};
use indexmap::IndexMap;
use serde_json::{Value, json};

fn step(id: &str, step_type: &str, params: Value) -> StepDef {
    StepDef::new(id.to_string(), step_type.to_string(), params)
}

fn action(steps: Vec<StepDef>) -> Action {
    Action::new(steps)
}

fn manifest(name: &str, steps: Vec<StepDef>) -> PluginManifest {
    let mut actions = IndexMap::new();
    actions.insert("go".to_string(), action(steps));
    {
        let mut m = PluginManifest::new(name.to_string());
        m.actions = actions;
        m
    }
}

fn boot(plugins: Vec<PluginManifest>) -> Arc<Kernel> {
    boot_with_limits(plugins, RuntimeLimits::default())
}

fn boot_with_limits(plugins: Vec<PluginManifest>, limits: RuntimeLimits) -> Arc<Kernel> {
    let mut k = Kernel::boot(KernelConfig::default().with_limits(limits)).expect("kernel boot");
    for p in plugins {
        k.register_plugin(p).expect("register");
    }
    k.into_arc()
}

async fn run(kernel: &Arc<Kernel>, plugin: &str) -> Result<ActionResult, KernelError> {
    kernel
        .execute(plugin, "go", json!({}))
        .with_config(&Value::Null)
        .run()
        .await
}

// ---------------------------------------------------------------------------
// `return` from inside try sub-blocks
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn return_from_try_body_skips_catch_and_finally_and_unwinds() {
    let kernel = boot(vec![manifest(
        "p",
        vec![
            step(
                "guard",
                "try",
                json!({
                    "try": [
                        {"id": "early", "type": "return", "params": {"value": { "from": "try" }}},
                        // Must NOT run — return stops the try body.
                        {"id": "after_ret", "type": "let", "params": {"value": "no"}},
                    ],
                    "catch": [
                        {"id": "rec", "type": "let", "params": {"value": "no"}, "storeToVariable": "vc"}
                    ],
                    "finally": [
                        {"id": "fin", "type": "let", "params": {"value": "no"}, "storeToVariable": "vf"}
                    ],
                }),
            ),
            // Must NOT run — return unwinds the whole action.
            step("never", "let", json!({ "value": "no" })),
        ],
    )]);

    let result = run(&kernel, "p").await.expect("ok");
    assert_eq!(result.output, json!({ "from": "try" }));
    for id in ["after_ret", "rec", "fin", "never"] {
        assert!(
            !result.step_results.contains_key(id),
            "step '{id}' must not run after return-from-try"
        );
    }
    assert!(result.variables.get("vc").is_none(), "catch skipped");
    assert!(result.variables.get("vf").is_none(), "finally skipped");
}

#[tokio::test(flavor = "multi_thread")]
async fn return_from_catch_skips_finally_and_unwinds() {
    let kernel = boot(vec![manifest(
        "p",
        vec![
            step(
                "guard",
                "try",
                json!({
                    "try": [
                        {"id": "boom", "type": "throw_error", "params": {"code": "X", "message": "fail into catch"}}
                    ],
                    "catch": [
                        {"id": "early", "type": "return", "params": {"value": { "from": "catch" }}},
                        {"id": "after_ret", "type": "let", "params": {"value": "no"}},
                    ],
                    "finally": [
                        {"id": "fin", "type": "let", "params": {"value": "no"}, "storeToVariable": "vf"}
                    ],
                }),
            ),
            step("never", "let", json!({ "value": "no" })),
        ],
    )]);

    let result = run(&kernel, "p").await.expect("ok");
    assert_eq!(result.output, json!({ "from": "catch" }));
    for id in ["after_ret", "fin", "never"] {
        assert!(
            !result.step_results.contains_key(id),
            "step '{id}' must not run after return-from-catch"
        );
    }
    assert!(result.variables.get("vf").is_none(), "finally skipped");
}

#[tokio::test(flavor = "multi_thread")]
async fn return_from_finally_unwinds() {
    // The documented corner: the early-exit-on-return guard inside the
    // finally-block loop itself.
    let kernel = boot(vec![manifest(
        "p",
        vec![
            step(
                "guard",
                "try",
                json!({
                    "try": [ {"id": "body", "type": "let", "params": {"value": "ok"}} ],
                    "catch": [],
                    "finally": [
                        {"id": "early", "type": "return", "params": {"value": { "from": "finally" }}},
                        {"id": "after_ret", "type": "let", "params": {"value": "no"}},
                    ],
                }),
            ),
            step("never", "let", json!({ "value": "no" })),
        ],
    )]);

    let result = run(&kernel, "p").await.expect("ok");
    assert_eq!(result.output, json!({ "from": "finally" }));
    assert!(result.step_results.contains_key("body"), "try body ran");
    for id in ["after_ret", "never"] {
        assert!(
            !result.step_results.contains_key(id),
            "step '{id}' must not run after return-from-finally"
        );
    }
}

// ---------------------------------------------------------------------------
// Wasm resource caps
// ---------------------------------------------------------------------------

fn wat_module_base64(wat: &str) -> String {
    let wasm = wat::parse_str(wat).expect("WAT parse");
    base64::engine::general_purpose::STANDARD.encode(&wasm)
}

fn wasm_manifest(
    name: &str,
    modules: IndexMap<String, WasmModuleSpec>,
    steps: Vec<StepDef>,
) -> PluginManifest {
    let mut actions = IndexMap::new();
    actions.insert("go".to_string(), action(steps));
    {
        let mut m = PluginManifest::new(name.to_string());
        m.actions = actions;
        m.wasm_modules = modules;
        m
    }
}

fn one_module(name: &str, wat: &str) -> IndexMap<String, WasmModuleSpec> {
    let mut modules = IndexMap::new();
    modules.insert(
        name.to_string(),
        WasmModuleSpec::Inline {
            base64: wat_module_base64(wat),
        },
    );
    modules
}

#[tokio::test(flavor = "multi_thread")]
async fn wasm_infinite_loop_trips_fuel_budget() {
    // CPU-bound tight loop, no exit condition: only the fuel meter can
    // stop it. A small budget keeps the test fast; the assertion is
    // that it traps CLEANLY instead of wedging the worker (the
    // wallclock timeout would be the symptom of a broken fuel wire).
    let kernel = boot_with_limits(
        vec![wasm_manifest(
            "p",
            one_module("spin", r#"(module (func (export "run") (loop $l br $l)))"#),
            vec![step("exec", "wasm", json!({ "module": "spin" }))],
        )],
        RuntimeLimits::default().with_fuel_budget(100_000),
    );

    let err = run(&kernel, "p").await.expect_err("must trip fuel budget");
    let msg = err.to_string();
    assert!(
        msg.contains("exhausted its fuel budget (100000 units) during 'run'"),
        "error should name the fuel cap and the phase: {msg}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wasm_start_function_tripping_fuel_budget_names_the_cap() {
    // The same loop in the module's `start` function runs at
    // instantiation, before the entry is called. The cap is the same
    // cap and the error names it the same way, saying where.
    let kernel = boot_with_limits(
        vec![wasm_manifest(
            "p",
            one_module(
                "spin",
                r#"(module (func $init (loop $l br $l)) (start $init) (func (export "run")))"#,
            ),
            vec![step("exec", "wasm", json!({ "module": "spin" }))],
        )],
        RuntimeLimits::default().with_fuel_budget(100_000),
    );

    let err = run(&kernel, "p").await.expect_err("must trip fuel budget");
    let msg = err.to_string();
    assert!(
        msg.contains("exhausted its fuel budget (100000 units) at instantiation"),
        "error should name the fuel cap and the phase: {msg}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wasm_declared_minimum_past_cap_fails_instantiation_as_the_modules_own_failure() {
    // 64 pages is 4 MiB, declared up front, under a 1 MiB cap. The
    // limiter refuses it and the module never instantiates. That is
    // the `wasm` step's own plain failure naming the module, not the
    // typed memory cap the `script` step reports for the same shape.
    let kernel = boot_with_limits(
        vec![wasm_manifest(
            "p",
            one_module("hungry", r#"(module (memory 64) (func (export "run")))"#),
            vec![step("exec", "wasm", json!({ "module": "hungry" }))],
        )],
        RuntimeLimits::default().with_max_memory_bytes(1024 * 1024),
    );

    let err = run(&kernel, "p")
        .await
        .expect_err("must fail to instantiate");
    assert!(
        matches!(&err, KernelError::Execution(msg)
            if msg.starts_with("wasm step: module 'hungry' instantiation failed: ")),
        "{err:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wasm_memory_grow_past_cap_is_denied() {
    // Grows one 64 KiB page per iteration until the ResourceLimiter
    // says no (memory.grow returns -1), then traps via `unreachable`.
    // With a 1 MiB cap that's ~15 grows; without the limiter the loop
    // would balloon the host process until fuel ran out.
    let wat = r#"
        (module
          (memory 1)
          (func (export "run")
            (loop $l
              (if (i32.eq (memory.grow (i32.const 1)) (i32.const -1))
                (then unreachable))
              (br $l))))
    "#;
    let kernel = boot_with_limits(
        vec![wasm_manifest(
            "p",
            one_module("hog", wat),
            vec![step("exec", "wasm", json!({ "module": "hog" }))],
        )],
        RuntimeLimits::default()
            .with_max_memory_bytes(1024 * 1024)
            // Small enough that a BROKEN limiter fails this test as
            // "fuel" instead of passing by accident: without the
            // limiter, the loop grows to wasm32's 4 GiB ceiling
            // (~65k iterations) before memory.grow returns -1 on its
            // own — far beyond this budget — while the ~16 legitimate
            // grows under a working limiter fit easily.
            .with_fuel_budget(50_000),
    );

    let err = run(&kernel, "p").await.expect_err("must trap at the cap");
    let msg = err.to_string();
    assert!(
        msg.contains("trapped") && !msg.contains("fuel"),
        "growth denial must surface as a clean (non-fuel) trap: {msg}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wasm_table_grow_past_cap_is_denied() {
    // Same decision tree as the memory test, but for `table.grow` —
    // table elements commit host memory outside the linear-memory
    // budget, so they get their own cap. Grows 64 funcref slots per
    // iteration until the ResourceLimiter says no (table.grow returns
    // -1), then traps via `unreachable`.
    let wat = r#"
        (module
          (table 1 funcref)
          (func (export "run")
            (loop $l
              (if (i32.eq (table.grow (ref.null func) (i32.const 64)) (i32.const -1))
                (then unreachable))
              (br $l))))
    "#;
    let kernel = boot_with_limits(
        vec![wasm_manifest(
            "p",
            one_module("table_hog", wat),
            vec![step("exec", "wasm", json!({ "module": "table_hog" }))],
        )],
        RuntimeLimits::default()
            .with_max_table_elements(1024)
            // Sized like the memory test's budget: ~16 legitimate
            // grows under a working limiter fit easily, while a
            // BROKEN limiter loops until fuel runs out and fails
            // this test as "fuel" instead of passing by accident.
            .with_fuel_budget(50_000),
    );

    let err = run(&kernel, "p").await.expect_err("must trap at the cap");
    let msg = err.to_string();
    assert!(
        msg.contains("trapped") && !msg.contains("fuel"),
        "table-growth denial must surface as a clean (non-fuel) trap: {msg}"
    );
}

/// Register one plugin holding a single module and a `wasm` step that
/// runs it, on a kernel with default limits. Registration is where the
/// module compiles, so a refused feature surfaces here.
fn register_wasm_module(wat: &str) -> Result<Arc<Kernel>, KernelError> {
    let mut k = Kernel::boot(KernelConfig::default()).expect("kernel boot");
    k.register_plugin(wasm_manifest(
        "p",
        one_module("m", wat),
        vec![step("exec", "wasm", json!({ "module": "m" }))],
    ))?;
    Ok(k.into_arc())
}

/// Pins the "Wasm features" section of the `kernel::abi` docs from the
/// guest's side: a module for each of 18 of the 20 listed features
/// registers (`call_indirect_overlong` and `gc_types` have no case of
/// their own). Dropping any one flag from `WASM_FEATURES` fails this
/// test.
#[tokio::test(flavor = "multi_thread")]
async fn each_listed_wasm_feature_compiles_at_registration() {
    let cases: &[(&str, &str)] = &[
        (
            "mutable_global",
            r#"(module (global (export "g") (mut i32) (i32.const 0)) (func (export "run") (global.set 0 (i32.const 1))))"#,
        ),
        (
            "saturating_float_to_int",
            r#"(module (func (export "run") (drop (i32.trunc_sat_f32_s (f32.const 1)))))"#,
        ),
        (
            "sign_extension",
            r#"(module (func (export "run") (drop (i32.extend8_s (i32.const 1)))))"#,
        ),
        (
            "reference_types",
            r#"(module (table 1 funcref) (table 1 funcref) (func (export "run") (drop (table.get 1 (i32.const 0)))))"#,
        ),
        (
            "multi_value",
            r#"(module (func $two (result i32 i32) (i32.const 1) (i32.const 2)) (func (export "run") (call $two) (drop) (drop)))"#,
        ),
        (
            "bulk_memory",
            r#"(module (memory 1) (data $d "ab") (func (export "run") (memory.init $d (i32.const 0) (i32.const 0) (i32.const 2)) (data.drop $d)))"#,
        ),
        (
            "bulk_memory_opt",
            r#"(module (memory 1) (func (export "run") (memory.fill (i32.const 0) (i32.const 0) (i32.const 1)) (memory.copy (i32.const 0) (i32.const 1) (i32.const 1))))"#,
        ),
        (
            "simd",
            r#"(module (func (export "run") (drop (i32x4.add (v128.const i32x4 0 0 0 0) (v128.const i32x4 1 1 1 1)))))"#,
        ),
        (
            "relaxed_simd",
            r#"(module (func (export "run") (drop (i32x4.relaxed_trunc_f32x4_s (v128.const f32x4 0 0 0 0)))))"#,
        ),
        (
            "threads",
            r#"(module (memory 1 1 shared) (func (export "run") (drop (i32.atomic.load (i32.const 0)))))"#,
        ),
        (
            "tail_call",
            r#"(module (func $g) (func (export "run") (return_call $g)))"#,
        ),
        (
            "floats",
            r#"(module (func (export "run") (drop (f64.add (f64.const 1) (f64.const 2)))))"#,
        ),
        (
            "multi_memory",
            r#"(module (memory 1) (memory 1) (func (export "run") (drop (i32.load 1 (i32.const 0)))))"#,
        ),
        (
            "exceptions",
            r#"(module (tag $e) (func (export "run") (block $c (try_table (catch $e $c) (throw $e)))))"#,
        ),
        (
            "memory64",
            r#"(module (memory i64 1) (func (export "run") (drop (i32.load (i64.const 0)))))"#,
        ),
        (
            "extended_const",
            r#"(module (global i32 (i32.add (i32.const 1) (i32.const 2))) (func (export "run")))"#,
        ),
        (
            "function_references",
            r#"(module (type $t (func)) (func $f) (elem declare func $f) (func (export "run") (call_ref $t (ref.func $f))))"#,
        ),
        (
            "gc",
            r#"(module (type $s (struct (field i32))) (func (export "run") (drop (struct.new $s (i32.const 1)))))"#,
        ),
    ];
    for (feature, wat) in cases {
        if let Err(e) = register_wasm_module(wat) {
            panic!("a module using `{feature}` must register: {e}");
        }
    }
}

/// Pins the "Wasm features" section of the `kernel::abi` docs: a
/// feature outside the list is refused when the plugin registers, with
/// the compile error naming the plugin and the module, never at run
/// time. Shared memory, which those docs list under `threads`, is the
/// exception: it registers and fails at instantiation.
#[tokio::test(flavor = "multi_thread")]
async fn a_wasm_feature_outside_the_list_is_refused_at_registration() {
    let cases: &[(&str, &str)] = &[
        (
            "wide_arithmetic",
            r#"(module (func (export "run") i64.const 0 i64.const 0 i64.const 0 i64.const 0 i64.add128 drop drop))"#,
        ),
        (
            "custom_page_sizes",
            r#"(module (memory 1 (pagesize 1)) (func (export "run")))"#,
        ),
        (
            "legacy_exceptions",
            r#"(module (tag $e) (func (export "run") try catch $e end))"#,
        ),
    ];
    for (feature, wat) in cases {
        match register_wasm_module(wat) {
            Ok(_) => panic!("a module using `{feature}` must be refused at registration"),
            Err(KernelError::Validation(msg)) => assert!(
                msg.starts_with("Plugin 'p' wasm_module 'm': compile failed:"),
                "`{feature}`: {msg}"
            ),
            Err(other) => panic!("`{feature}`: expected a validation error, got {other:?}"),
        }
    }
}

/// Run `wat` under a fuel budget of 100,000 units and require the run
/// to end by exhausting it. Both callers spend on the order of a
/// million units, an order of magnitude past the budget, but only when
/// every callee's spending is counted.
async fn assert_exhausts_a_small_budget(wat: &str) {
    let kernel = boot_with_limits(
        vec![wasm_manifest(
            "p",
            one_module("m", wat),
            vec![step("exec", "wasm", json!({ "module": "m" }))],
        )],
        RuntimeLimits::default().with_fuel_budget(100_000),
    );
    let err = run(&kernel, "p")
        .await
        .expect_err("the callees' fuel must exhaust the budget");
    let msg = err.to_string();
    assert!(
        msg.contains("exhausted its fuel budget (100000 units) during 'run'"),
        "error should name the fuel cap and the phase: {msg}"
    );
}

/// Pins the "Fuel" section of the `kernel::abi` docs: fuel spent by a
/// callee reached through `call_ref` counts against the run's budget.
/// The function calls itself twice through `call_ref` and calls an
/// empty function twice, over 2^17 calls in all.
#[tokio::test(flavor = "multi_thread")]
async fn wasm_call_ref_callee_fuel_counts_toward_the_budget() {
    assert_exhausts_a_small_budget(
        r#"(module
          (type $t (func (param i32)))
          (func $noop)
          (func $f (type $t) (param $n i32)
            (if (i32.eqz (local.get $n)) (then (return)))
            (call_ref $t (i32.sub (local.get $n) (i32.const 1)) (ref.func $f))
            (call $noop)
            (call_ref $t (i32.sub (local.get $n) (i32.const 1)) (ref.func $f))
            (call $noop))
          (elem declare func $f)
          (func (export "run") (call $f (i32.const 16))))"#,
    )
    .await;
}

/// Pins the "Fuel" section of the `kernel::abi` docs: fuel spent by a
/// callee that throws to a `try_table` catch in its caller counts
/// against the run's budget. The function catches two calls to itself
/// and throws again, 2^17 - 1 calls in all.
#[tokio::test(flavor = "multi_thread")]
async fn wasm_caught_exception_keeps_the_throwers_fuel() {
    assert_exhausts_a_small_budget(
        r#"(module
          (tag $e)
          (func $g (param $n i32)
            (if (i32.eqz (local.get $n)) (then (throw $e)))
            (block $c1
              (try_table (catch $e $c1)
                (call $g (i32.sub (local.get $n) (i32.const 1)))))
            (block $c2
              (try_table (catch $e $c2)
                (call $g (i32.sub (local.get $n) (i32.const 1)))))
            (throw $e))
          (func (export "run")
            (block $c (try_table (catch $e $c) (call $g (i32.const 16))))))"#,
    )
    .await;
}

/// Pins the "Fuel" section of the `kernel::abi` docs: a bulk operation
/// whose length is not a small constant is checked against the fuel
/// left before it runs, so one longer than the fuel left ends in fuel
/// exhaustion. The same module under a budget larger than the length
/// reaches the operation and traps out of bounds, so the length against
/// the fuel left decides which failure a guest sees.
#[tokio::test(flavor = "multi_thread")]
async fn wasm_oversized_memory_fill_exhausts_fuel_rather_than_trapping() {
    let wat = r#"(module (memory 1)
        (func (export "run")
          (memory.fill (i32.const 0) (i32.const 0) (i32.const 0x7fffffff))))"#;
    let kernel_with = |budget: u64| {
        boot_with_limits(
            vec![wasm_manifest(
                "p",
                one_module("m", wat),
                vec![step("exec", "wasm", json!({ "module": "m" }))],
            )],
            RuntimeLimits::default().with_fuel_budget(budget),
        )
    };

    let err = run(&kernel_with(1_000_000), "p")
        .await
        .expect_err("the fill must exhaust the budget");
    let msg = err.to_string();
    assert!(
        msg.contains("exhausted its fuel budget (1000000 units) during 'run'"),
        "an oversized fill under a small budget is fuel exhaustion: {msg}"
    );

    let err = run(&kernel_with(10_000_000_000), "p")
        .await
        .expect_err("the fill must trap out of bounds");
    let msg = err.to_string();
    assert!(
        msg.contains("trapped during 'run'") && !msg.contains("fuel"),
        "an oversized fill under a large budget is a plain trap: {msg}"
    );
}

/// Pins the "Fuel" section of the `kernel::abi` docs: a `table.grow`
/// whose length is not a small constant is checked against the fuel
/// left before it runs, so an oversized one ends in fuel exhaustion
/// rather than returning `-1` to the guest.
#[tokio::test(flavor = "multi_thread")]
async fn wasm_oversized_table_grow_exhausts_fuel_rather_than_returning_minus_one() {
    let wat = r#"(module (table 1 funcref)
        (func (export "run")
          (if (i32.eq (table.grow (ref.null func) (i32.const 0x7fffffff)) (i32.const -1))
            (then unreachable))))"#;
    let kernel = boot_with_limits(
        vec![wasm_manifest(
            "p",
            one_module("m", wat),
            vec![step("exec", "wasm", json!({ "module": "m" }))],
        )],
        RuntimeLimits::default().with_fuel_budget(1_000_000),
    );

    let err = run(&kernel, "p")
        .await
        .expect_err("the grow must exhaust the budget");
    let msg = err.to_string();
    assert!(
        msg.contains("exhausted its fuel budget (1000000 units) during 'run'"),
        "an oversized table.grow is fuel exhaustion, not -1: {msg}"
    );
}

/// Pins the "Fuel" section of the `kernel::abi` docs: `memory.grow` is
/// not charged by the number of pages it asks for. A grow of 32,767
/// pages under a 10,000-unit budget reaches the memory cap and returns
/// `-1`, which the guest turns into a plain trap.
#[tokio::test(flavor = "multi_thread")]
async fn wasm_memory_grow_is_not_charged_by_size() {
    let wat = r#"(module (memory 1)
        (func (export "run")
          (if (i32.eq (memory.grow (i32.const 0x7fff)) (i32.const -1))
            (then unreachable))))"#;
    let kernel = boot_with_limits(
        vec![wasm_manifest(
            "p",
            one_module("m", wat),
            vec![step("exec", "wasm", json!({ "module": "m" }))],
        )],
        RuntimeLimits::default().with_fuel_budget(10_000),
    );

    let err = run(&kernel, "p")
        .await
        .expect_err("the denied grow must trap");
    let msg = err.to_string();
    assert!(
        msg.contains("trapped during 'run'") && !msg.contains("fuel"),
        "a grow past the cap is a plain trap, not fuel exhaustion: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Guest-supplied pointers into host imports
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn script_host_import_oob_pointer_traps_cleanly() {
    // A hostile script runtime calls `host_set_result(1_000_000, 16)`
    // against a one-page (64 KiB) memory. The host import must
    // bounds-check the guest-supplied range and trap the GUEST —
    // failing the step with an error — rather than panicking the
    // host task on the slice.
    use base64::Engine as _;
    let evil_wat = r#"
        (module
          (import "gwead1" "host_set_result" (func $host_set_result (param i32 i32)))
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 32))
          (func (export "alloc") (param $len i32) (result i32)
            (local $ptr i32)
            global.get $next
            local.set $ptr
            global.get $next
            local.get $len
            i32.add
            global.set $next
            local.get $ptr)
          (func (export "execute") (param i32 i32 i32 i32) (result i32)
            i32.const 1000000
            i32.const 16
            call $host_set_result
            i32.const 1))
    "#;
    let wasm = wat::parse_str(evil_wat).expect("WAT parse");
    let base64_bytes = base64::engine::general_purpose::STANDARD.encode(&wasm);

    // The point of this test is a hostile *runtime module*, so it has
    // to get past the slot-claim rule the same way a real runtime
    // plugin would: declare `provide:step_type:script:lua` and be
    // named in the embedder's trusted list. That is the threat model —
    // a trusted-to-supply runtime whose wasm still misbehaves.
    let mut k = Kernel::boot(KernelConfig::default().trusting_step_type_provider("evil_runtime"))
        .expect("kernel boot");
    let runtime_manifest = serde_json::json!({
        "name": "evil_runtime",
        "version": "0.0.0-test",
        "description": "Test-only script runtime that passes an out-of-bounds pointer to host_set_result.",
        "permissions": ["provide:step_type:script:lua"],
        "wasmModules": { "runtime": {"base64": base64_bytes} },
        "stepTypeImpls": [
            {"stepType": "script", "matches": "lua", "wasmModule": "runtime"}
        ],
    });
    k.register_plugin_from_json(&runtime_manifest.to_string())
        .expect("evil runtime registers");
    k.register_plugin(manifest(
        "p",
        vec![step(
            "code",
            "script",
            json!({ "language": "lua", "source": "return 1" }),
        )],
    ))
    .expect("register");
    let kernel = k.into_arc();

    let err = run(&kernel, "p")
        .await
        .expect_err("OOB host_set_result must fail the step");
    let msg = err.to_string();
    assert!(
        msg.contains("out of bounds"),
        "expected a bounds-check trap, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Multi-module wasm
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn one_plugin_many_modules_each_callable() {
    // Module `a` exports the default entry; module `b` exports a
    // custom one — both registered under the same plugin, both
    // invoked from separate wasm steps in the same action.
    let mut modules = IndexMap::new();
    modules.insert(
        "a".to_string(),
        WasmModuleSpec::Inline {
            base64: wat_module_base64(r#"(module (func (export "run")))"#),
        },
    );
    modules.insert(
        "b".to_string(),
        WasmModuleSpec::Inline {
            base64: wat_module_base64(r#"(module (func (export "boot")))"#),
        },
    );

    let kernel = boot(vec![wasm_manifest(
        "p",
        modules,
        vec![
            step("exec_a", "wasm", json!({ "module": "a" })),
            step("exec_b", "wasm", json!({ "module": "b", "entry": "boot" })),
        ],
    )]);

    let result = run(&kernel, "p").await.expect("ok");
    assert_eq!(result.step_results.get("exec_a"), Some(&Value::Null));
    assert_eq!(result.step_results.get("exec_b"), Some(&Value::Null));
}

#[tokio::test(flavor = "multi_thread")]
async fn same_module_name_across_plugins_resolves_per_plugin() {
    // The registry key is (plugin, module): p_ok's `my_module` is a
    // no-op; p_trap's `my_module` traps immediately. If the bare name
    // were the key, one would shadow the other and exactly one of
    // these assertions would flip.
    let kernel = boot(vec![
        wasm_manifest(
            "p_ok",
            one_module("my_module", r#"(module (func (export "run")))"#),
            vec![step("exec", "wasm", json!({ "module": "my_module" }))],
        ),
        wasm_manifest(
            "p_trap",
            one_module("my_module", r#"(module (func (export "run") unreachable))"#),
            vec![step("exec", "wasm", json!({ "module": "my_module" }))],
        ),
    ]);

    let ok = run(&kernel, "p_ok").await;
    assert!(ok.is_ok(), "p_ok must resolve its own no-op module: {ok:?}");

    let err = run(&kernel, "p_trap")
        .await
        .expect_err("p_trap must resolve its own trapping module");
    assert!(
        err.to_string().contains("trapped"),
        "expected p_trap's module to trap: {err}"
    );
}

// ── host→guest pointer bounds ──────────────────────────────────────
//
// Every guest→host import bounds-checks the pointers a guest passes
// in. The reverse direction — where the host trusts the offset the
// guest's own `alloc` returned and slices linear memory at it — must
// be checked too. A guest returning -1, an offset past the end of
// memory, or one near i32::MAX would otherwise panic the host process
// on the slice index. There is no `catch_unwind` anywhere in the
// crate, so that panic would be a host kill, not a failed step.

/// Build a script-runtime manifest whose `alloc` returns `bad_ptr`
/// regardless of the requested length.
fn hostile_alloc_runtime(bad_ptr: &str) -> String {
    use base64::Engine as _;
    let wat = format!(
        r#"(module
             (memory (export "memory") 1)
             (func (export "alloc") (param $len i32) (result i32)
               i32.const {bad_ptr})
             (func (export "execute") (param i32 i32 i32 i32) (result i32)
               i32.const 1))"#
    );
    let wasm = wat::parse_str(&wat).expect("WAT parse");
    let b64 = base64::engine::general_purpose::STANDARD.encode(&wasm);
    serde_json::json!({
        "name": "hostile_alloc_runtime",
        "version": "0.0.0-test",
        "description": "Returns an out-of-range pointer from `alloc`.",
        "permissions": ["provide:step_type:script:lua"],
        "wasmModules": { "runtime": {"base64": b64} },
        "stepTypeImpls": [
            {"stepType": "script", "matches": "lua", "wasmModule": "runtime"}
        ],
    })
    .to_string()
}

async fn run_with_hostile_alloc(bad_ptr: &str) -> Result<ActionResult, KernelError> {
    let mut k =
        Kernel::boot(KernelConfig::default().trusting_step_type_provider("hostile_alloc_runtime"))
            .expect("kernel boot");
    k.register_plugin_from_json(&hostile_alloc_runtime(bad_ptr))
        .expect("runtime registers");
    k.register_plugin(manifest(
        "p",
        vec![step(
            "code",
            "script",
            json!({ "language": "lua", "source": "return 1" }),
        )],
    ))
    .expect("register");
    let kernel = k.into_arc();
    run(&kernel, "p").await
}

/// A negative `alloc` result must be a step error, not a host panic.
/// The test surviving to make an assertion IS the assertion — a panic
/// here takes the whole test process down.
#[tokio::test(flavor = "multi_thread")]
async fn negative_alloc_pointer_fails_the_step_without_panicking_the_host() {
    let err = run_with_hostile_alloc("-1")
        .await
        .expect_err("a negative alloc pointer must fail the step");
    assert!(
        err.to_string().contains("negative"),
        "the error should say what the guest did: {err}"
    );
}

/// An offset past the end of the guest's linear memory.
#[tokio::test(flavor = "multi_thread")]
async fn out_of_bounds_alloc_pointer_fails_the_step_without_panicking_the_host() {
    let err = run_with_hostile_alloc("65530")
        .await
        .expect_err("an out-of-bounds alloc pointer must fail the step");
    assert!(
        err.to_string().contains("out-of-bounds"),
        "the error should say what the guest did: {err}"
    );
}

/// An offset large enough that `ptr + len` would also overflow.
#[tokio::test(flavor = "multi_thread")]
async fn huge_alloc_pointer_fails_the_step_without_panicking_the_host() {
    let err = run_with_hostile_alloc("2147483647")
        .await
        .expect_err("a huge alloc pointer must fail the step");
    let msg = err.to_string();
    assert!(
        msg.contains("out-of-bounds") || msg.contains("overflows"),
        "the error should say what the guest did: {msg}"
    );
}
