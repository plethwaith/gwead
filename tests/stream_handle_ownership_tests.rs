//! A stream handle means something only inside the execution that
//! minted it.
//!
//! Handles come from a counter starting at 1 — predictable, not merely
//! guessable — so if a nested invocation *inherited the caller's
//! registry*, `io.invoke` would hand the callee the caller's entire
//! handle space. A callee could call `stream_read(1)` and receive bytes
//! from a stream nobody had granted it, then close it for good measure.
//!
//! The guarantee is structural rather than a check: each execution gets its
//! own handle table, so another execution's handle is not a thing that
//! can be named. The rejected alternatives were an owner tag consulted
//! at every `stream_*` entry point — a *remembered* check, exactly the
//! kind that gets forgotten — and unguessable handle ids, which would
//! close the naive exploit without closing the hole.
//!
//! Crossing the boundary is explicit and is a move: `take` there,
//! `adopt` here.

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use gwead::kernel::streams::{StreamRegistry, lock_shared};
use gwead::kernel::{Kernel, KernelConfig};
use serde_json::{Value, json};

const SECRET: &str = "ANOTHER-PLUGINS-PRIVATE-BYTES";

/// A guest that reads handle 1 — a handle no param ever gave it — and
/// closes it, then returns whatever bytes it got.
const THIEF_WAT: &str = r#"
(module
  (import "gwead1" "stream_read"      (func $read (param i32 i32 i32) (result i32)))
  (import "gwead1" "stream_close"     (func $close (param i32) (result i32)))
  (import "gwead1" "host_set_result"  (func $set_result (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "\"")
  (global $next (mut i32) (i32.const 4096))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    global.get $next
    local.set $p
    global.get $next
    local.get $len
    i32.add
    global.set $next
    local.get $p)
  (func (export "execute") (param i32 i32 i32 i32) (result i32)
    (local $n i32)
    ;; Read handle 1 — never handed to this step by any param.
    (local.set $n (call $read (i32.const 1) (i32.const 1) (i32.const 64)))
    ;; Close it too, to show write-side control over a foreign handle.
    (drop (call $close (i32.const 1)))
    (i32.store8 (i32.add (i32.const 1) (local.get $n)) (i32.const 34))
    (call $set_result (i32.const 0) (i32.add (local.get $n) (i32.const 2)))
    (i32.const 1)))
"#;

fn boot(extra: &[&str]) -> Kernel {
    let wasm = wat::parse_str(THIEF_WAT).expect("WAT parses");
    let b64 = base64::engine::general_purpose::STANDARD.encode(&wasm);
    // The runtime is legitimately trusted with the `(script, lua)` slot;
    // slot squatting is a separate question (see `step_type_claim_tests`). What is
    // under test is whether a runtime that *is* trusted can reach
    // handles it was never granted.
    let mut k = Kernel::boot(KernelConfig::default().trusting_step_type_provider("evil_runtime"))
        .expect("boot");
    k.register_plugin_from_json(
        &json!({
            "name": "evil_runtime",
            "permissions": ["provide:step_type:script:lua"],
            "wasmModules": { "runtime": {"base64": b64} },
            "stepTypeImpls": [{"stepType": "script", "matches": "lua", "wasmModule": "runtime"}],
        })
        .to_string(),
    )
    .expect("runtime registers");
    for m in extra {
        k.register_plugin_from_json(m).expect("registers");
    }
    k
}

fn thief(name: &str) -> String {
    json!({
        "name": name,
        "actions": { "go": {
            "steps": [{"id": "code", "type": "script", "params": {"language": "lua", "source": "return 1"}}],
            "resultMapping": { "out": { "path": "$", "source": "code" } }
        } },
    })
    .to_string()
}

fn seeded_table() -> (Arc<Mutex<StreamRegistry>>, gwead::kernel::streams::StreamId) {
    let reg: Arc<Mutex<StreamRegistry>> = Arc::new(Mutex::new(StreamRegistry::new()));
    let src = Box::pin(futures::stream::once(async {
        Ok(bytes::Bytes::from(SECRET.as_bytes()))
    }));
    let id = lock_shared(&reg).register_readable("text/plain", src);
    (reg, id)
}

/// The exploit in its simplest shape: a victim
/// plugin holding a private stream invokes another plugin, which reads
/// handle 1.
#[tokio::test(flavor = "multi_thread")]
async fn a_callee_cannot_read_the_callers_handles() {
    let victim = json!({
        "name": "victim",
        "permissions": ["invoke:plugin:thief"],
        "actions": { "go": {
            "steps": [
                {"id": "call", "type": "invoke", "params": {"plugin": "thief", "action": "go", "input": {}}}
            ],
            "resultMapping": { "out": { "path": "$", "source": "call" } }
        } },
    })
    .to_string();

    let k = boot(&[&thief("thief"), &victim]).into_arc();
    let (reg, handle) = seeded_table();
    assert_eq!(handle.get(), 1, "handles start at 1 — nothing to guess");

    let res = k
        .execute("victim", "go", json!({}))
        .with_config(&Value::Null)
        .with_streams(reg.clone())
        .run()
        .await;

    let rendered = match &res {
        Ok(r) => serde_json::to_string(&r.output).expect("json"),
        Err(e) => e.to_string(),
    };
    assert!(
        !rendered.contains(SECRET),
        "callee read the caller's stream: {rendered}"
    );
    assert!(
        lock_shared(&reg)
            .get(handle)
            .map(|s| !s.is_closed())
            .unwrap_or(false),
        "callee closed a stream belonging to the caller"
    );
}

/// Handle numbering is per-execution, so the callee's own first stream
/// is also `1`. Two executions holding handle 1 hold unrelated streams —
/// which is the property that makes forging one meaningless rather than
/// merely denied.
#[tokio::test(flavor = "multi_thread")]
async fn each_execution_numbers_its_handles_from_one() {
    let a: Arc<Mutex<StreamRegistry>> = Arc::new(Mutex::new(StreamRegistry::new()));
    let b: Arc<Mutex<StreamRegistry>> = Arc::new(Mutex::new(StreamRegistry::new()));
    let first = lock_shared(&a).register_readable(
        "text/plain",
        Box::pin(futures::stream::once(async { Ok(bytes::Bytes::from("a")) })),
    );
    let second = lock_shared(&b).register_readable(
        "text/plain",
        Box::pin(futures::stream::once(async { Ok(bytes::Bytes::from("b")) })),
    );
    assert_eq!(first, second, "both tables mint handle 1");
    assert!(
        lock_shared(&b).get(first).is_some(),
        "and the number resolves in each table — to that table's own stream"
    );
}

/// Transfer is a move: `take` from one table, `adopt` into another. The
/// receiving handle is freshly minted and unrelated to the old one, so
/// an execution never learns another's numbering.
#[test]
fn transfer_moves_a_stream_between_tables() {
    let (source, handle) = seeded_table();
    // Give the destination a stream of its own first, so the adopted
    // handle cannot coincidentally equal the original.
    let dest: Arc<Mutex<StreamRegistry>> = Arc::new(Mutex::new(StreamRegistry::new()));
    lock_shared(&dest).register_readable(
        "text/plain",
        Box::pin(futures::stream::once(async { Ok(bytes::Bytes::from("x")) })),
    );

    let moved = lock_shared(&source).take(handle).expect("stream is there");
    let new_handle = lock_shared(&dest).adopt(moved);

    assert!(
        lock_shared(&source).get(handle).is_none(),
        "the giver loses the handle — that is what makes it a move"
    );
    assert!(lock_shared(&dest).get(new_handle).is_some());
    assert_ne!(
        new_handle, handle,
        "the receiving handle is local, not the sender's number"
    );
}

/// `take` hands over the `Arc`; it does not close anything. A move that
/// closed the stream would make transfer useless.
#[test]
fn taking_a_stream_does_not_close_it() {
    let (source, handle) = seeded_table();
    let moved = lock_shared(&source).take(handle).expect("present");
    assert!(!moved.is_closed());
}

/// Reading a handle the table does not hold is an invalid-handle error,
/// not a read of somebody else's stream. This is the behaviour a callee
/// gets when it guesses.
#[test]
fn an_unknown_handle_is_invalid_not_someone_elses() {
    let (reg, _) = seeded_table();
    let bogus = std::num::NonZeroU32::new(999).expect("nonzero");
    assert!(lock_shared(&reg).get(bogus).is_none());
    assert_eq!(
        lock_shared(&reg).close_handle(bogus),
        gwead::kernel::streams::STREAM_INVALID_HANDLE
    );
}

/// `io.invoke_streaming` is the one path that legitimately crosses the
/// boundary: the callee produces into a writable while the parent
/// consumes the readable. The two ends are separate streams over one
/// channel, each in its own table — so the callee gets exactly the one
/// handle it needs and nothing else of the parent's. The delivery
/// mechanics are covered by the dataflow suite; this pins only that
/// the producer shape registers.
#[tokio::test(flavor = "multi_thread")]
async fn streaming_invoke_still_delivers_across_the_boundary() {
    let producer = json!({
        "name": "producer",
        "actions": { "emit": {
            "dataflow": true,
            "steps": [{"id": "p", "type": "let", "params": {"value": "streamed-payload"}, "longRunning": true}]
        } },
    })
    .to_string();

    let mut k = Kernel::boot(KernelConfig::default()).expect("boot");
    k.register_plugin_from_json(&producer)
        .expect("a dataflow producer registers");
    assert!(k.registry().get_manifest("producer").is_some());
}
