# Gwead Streams ABI

**ABI version: 1.**

## How the version is carried

The version is **in-band**, not a number in this document. Every host
function is registered under the wasm import module name `"gwead1"` —
the literal `"gwead"` with the ABI version appended — exposed in Rust
as [`gwead::kernel::abi::ABI_MODULE`](abi.rs) alongside
[`ABI_VERSION`](abi.rs). A guest imports from that exact name:

```wat
(import "gwead1" "host_set_result" (func (param i32 i32)))
```

That is the whole handshake, and it is what a machine checks. A module
built against a different ABI version imports a module name this
kernel never registers, so it fails deterministically at
instantiation with an unknown-import error naming what it asked for —
rather than trapping, or silently misbehaving, partway through
execution. Because the version is a module name, a future kernel could
register `gwead1` and `gwead2` shims side by side and run a mixed fleet
through a migration.

`formatVersion` on the plugin manifest does **not** cover this. The
manifest carries wasm modules as opaque base64, so a format-1 manifest
can carry a module compiled against any ABI.

**Scope.** One namespace covers both guest→host ABIs and they version
together: the script-runtime ABI documented here, and the wasm
step-type ABI (`step_success`, `begin_foreach`, `next_foreach`,
`end_foreach`, `begin_repeat`, plus one import per registered step
type). They run on separate stores with separate linkers and never
mix.

## Evolution policy

Until Gwead 1.0 the import set and return-code contract below may
change in breaking ways between pre-1.0 releases; runtime wasm modules must be
rebuilt against the kernel version that hosts them.

Post-1.0: adding an import is additive and does **not** bump the
version — a module that doesn't import it is unaffected. Removing an
import, changing a signature, or changing the meaning of a return code
bumps `ABI_VERSION`, `ABI_MODULE`, and the kernel's major version
together.

Two tests pin this. `register_all_binds_expected_host_imports` in
[`script_runtime_host/mod.rs`](script_runtime_host/mod.rs) enumerates
the linker's actual registered set and instantiates a module importing
every name at its documented signature.
`streams_abi_doc_matches_registered_imports` holds this document
against that same set, so an import added in code without a line here
(or vice versa) fails the test suite.

## Overview

Byte streams are the kernel's pipe abstraction for data flow between
plugins under the host-side DAG scheduler.

A stream is an opaque `StreamId` owned by a per-invocation
[`StreamRegistry`](streams.rs). Plugins hold the integer handle and
call three host functions to pull bytes in, push bytes out, or signal
EOF.

## Zero-copy data flow

Chunks are [`bytes::Bytes`](https://docs.rs/bytes) — ref-counted
slices. Cloning is a refcount bump; slicing is a refcount bump plus a
window. Everything host-side that routes, tees, slices, or forwards a
stream operates on refcounted views; no byte copies appear anywhere
on the host side.

The wasm-boundary copy (when a sandboxed plugin calls `stream_read` /
`stream_write`) is inherent to wasm isolation, not to streaming. Rust
host-native step types that want to consume or produce bytes can do
so without any boundary crossing.

See [`streams.rs`](streams.rs) module-level docs for the
implementation details.

## Handle model

- `StreamId` is `NonZeroU32`, handed to plugins as positive `i32`
  (via JSON number on the resolution-context boundary).
- Handles are allocated monotonically within a single action
  invocation, from a counter starting at 1, and never exceed
  `MAX_STREAM_HANDLE` (`i32::MAX`, [`streams.rs`](streams.rs)); the
  registry asserts this at allocation so a handle can never wrap into
  the negative error-code space.
- Each invocation gets its own registry (an embedder may supply one via
  `ExecuteActionRequest::with_streams`); a handle is an index into that
  registry only. A stream can be moved between registries with
  `StreamRegistry::take`/`adopt`, which mints a fresh handle in the
  receiving table — handle numbers themselves never cross invocations.
- One reader per handle is the intended contract: producers with
  several consumers are split by the fan-out helpers. Two concurrent
  `stream_read` calls on the same handle are not an error — the kernel
  serialises them on a per-stream async gate and logs a warning — but
  the interleaving of bytes between the two readers is unspecified.
- A handle is either **Readable** (host provides a source, plugin
  pulls) or **Writable** (plugin pushes, host consumes from a paired
  receiver). One direction per handle — the reverse call returns
  `DIRECTION_MISMATCH`.

## Host functions (wasm imports, `"gwead1"` module)

The complete script-runtime import set for ABI 1. This list is pinned
against the linker by `streams_abi_doc_matches_registered_imports` —
it is not a summary that can drift.

```text
host_call_result_read(buf_ptr: i32, buf_len: i32) -> i32
host_call_result_size() -> i32
host_invoke(target_ptr: i32, target_len: i32, action_ptr: i32, action_len: i32, input_ptr: i32, input_len: i32) -> i32
host_invoke_streaming(target_ptr: i32, target_len: i32, action_ptr: i32, action_len: i32, input_ptr: i32, input_len: i32) -> i32
host_log(level: i32, ptr: i32, len: i32)
host_set_error(ptr: i32, len: i32)
host_set_result(ptr: i32, len: i32)
is_cancelled() -> i32
stream_close(handle: i32) -> i32
stream_output() -> i32
stream_read(handle: i32, buf_ptr: i32, buf_len: i32) -> i32
stream_write(handle: i32, buf_ptr: i32, buf_len: i32) -> i32
```

The sections below detail the three core stream calls. The result,
invoke, and call-result-protocol imports are registered and documented
in [`script_runtime_host/imports/`](script_runtime_host/imports/).

### `stream_read`

Copies up to `buf_len` bytes from the next `Bytes` chunk of the
readable stream into wasm linear memory at `buf_ptr`. Returns bytes
written (`0` only when `buf_len` is `0`), `STREAM_EOF` (source
exhausted), or another negative code.

Internals (the host import is registered with `func_wrap_async`, so
the `.await` happens directly on the wasmtime fiber — no `block_on`,
no `block_in_place`, and no registry-wide mutex held across the
await — only the per-stream async read gate that serialises readers
of the same handle; see `read_async_shared` in
[`streams.rs`](streams.rs)):
1. Bounds-check `buf_ptr .. buf_ptr + buf_len` against linear memory
   → `STREAM_OOB` on overrun.
2. If the leftover cursor is empty, swap the source out of the
   registry entry and `source.next().await` with the lock released,
   skipping any empty `Bytes` chunks (an empty chunk is never reported
   as EOF or as a zero-length read), then put the source back. `None`
   from the source returns `STREAM_EOF`; `Err` returns
   `STREAM_IO_ERROR`.
3. Copy `min(buf_len, leftover.len())` bytes into `buf_ptr`.
4. Advance the cursor: `leftover = Some(chunk.slice(n..))` if bytes
   remain; otherwise `None`.
5. Return `n`.

The leftover cursor is what keeps the host-side zero-copy invariant:
a 64 KiB network chunk backs up to 16 × 4 KiB wasm reads by handing
out refcounted `Bytes::slice` views — the underlying allocation is
never duplicated.

### `stream_write`

Copies `buf_len` bytes out of wasm linear memory (snapshotted before
the await) into a new `Bytes` and pushes it to the paired
`WritableReceiver`. Returns bytes committed (`= buf_len`, so `0` for a
zero-length buffer) on success, or a negative code. If the paired
consumer has gone away the write returns `STREAM_CLOSED`.

The channel is bounded; a slow consumer backpressures the producer
naturally via `mpsc::Sender::send().await`. Like `stream_read`, the
import is async (`func_wrap_async` → `write_async_shared`): the
wasmtime fiber suspends until the receiver makes space, without
tying up a blocking thread.

A write waiting for room on a full channel is raced against the
step's cancellation token — the one `is_cancelled` reports, which
the wallclock watchdog also fires. If the token fires while the
write is waiting, the write returns `STREAM_CANCELLED` and the chunk
is not committed; the guest should stop producing and return. Only
the wait is released: the send is polled first, so a write the
channel has room for is committed even after the token has fired
(a producer that has already noticed the cancel can still push the
chunk it holds), and a receiver that has gone away is
`STREAM_CLOSED` whatever the token says, even when both happened
while the write was waiting.

### `stream_close`

Marks the handle closed, drops the underlying source/sender, and
returns 0. Idempotent — closing an already-closed handle returns 0
too. A handle of `0` or one not in the registry returns
`STREAM_INVALID_HANDLE` (the same holds for every handle-taking
import).

## Return-code contract

| Code | Constant | Meaning |
|-----:|----------|---------|
| `>=0` | — | Bytes transferred (`0` only for a zero-length buffer). |
| `-1` | `STREAM_EOF` | Successful EOF on a readable. |
| `-2` | `STREAM_INVALID_HANDLE` | Handle not in the registry. |
| `-3` | `STREAM_DIRECTION_MISMATCH` | Read on writable, write on readable. |
| `-4` | `STREAM_CLOSED` | Handle closed via `stream_close`, or (on write) the paired consumer has gone away. |
| `-5` | `STREAM_IO_ERROR` | Readable source returned an I/O error, or the guest exports no `memory`. |
| `-6` | `STREAM_OOB` | `buf_ptr + buf_len` exceeded linear memory. |
| `-7` | `STREAM_CANCELLED` | A write waiting for room on a full channel was released by the step's cancellation token (caller cancel or wallclock deadline). Nothing was committed. |

Defined in [`streams.rs`](streams.rs). Any guest-side binding, ABI
doc, or host function impl must reference these constants by name to
stay aligned.

## Lifetime & cleanup

The registry is per-invocation. `WasmRuntime::execute_dag` (and the
dataflow scheduler) drains the stream registry after the action
returns, unless the caller supplied and owns the registry or the
invocation is a nested `invoke` call, so:

- Forgotten readable streams release their underlying source (an
  HTTP connection, a `BoxStream<Bytes>`, …) immediately when the
  action ends.
- Forgotten writable streams drop their `mpsc::Sender`, which signals
  EOF to any consumer (e.g. a `reqwest::Body::wrap_stream`).

Plugin authors don't have to call `stream_close` — they can rely on
post-invocation drain. They still should, because closing explicitly
unblocks a paired consumer before the rest of their action runs.

## Example guest binding (non-normative)

No script runtime ships in this repository — the kernel exposes only
the language-agnostic host imports above, and language interpreters
(Lua, JavaScript, …) are separate wasm modules registered by
embedder plugins (see
[`script_runtime_host/mod.rs`](script_runtime_host/mod.rs)). As an
illustration, a Lua runtime module might expose the three calls under
`io.stream.*`:

```lua
local chunk = io.stream.read(handle, 4096)     -- string | nil (EOF)
io.stream.write(handle, chunk)                 -- bytes committed | false (cancelled)
io.stream.close(handle)
```

A binding like this would raise a language-level error on any
non-EOF negative code from `read` and any negative code from `write`
other than `STREAM_CANCELLED`, leaving the guest's usual
error-recovery idiom (`pcall` in Lua) to plugins that want to treat
failures non-fatally. `STREAM_CANCELLED` is not a failure: it is the
step's own cancel reaching a parked write, the same fact
`is_cancelled` reports, and a binding should surface it the same way
— `write` returning `false`, say, so the script stops producing and
returns normally. A guest has no typed cancellation of its own; a
script error raised after the step's token has fired is reported by
the host as the cancellation rather than as a failure — provided a
host import told the guest about the cancel first (`STREAM_CANCELLED`
from a write, or `is_cancelled` answering 1); a guest that never
asked keeps its own failure. So a binding that does raise on the code
still winds down correctly, but the guest's own error text is then
only logged.

## Example: a streaming HTTP step (embedder-provided)

An HTTP step type (`http_call` in the examples elsewhere in this
repo) is embedder-provided, not shipped by the kernel. A streaming
implementation integrates with this ABI naturally in both
directions:

- **Response mode** — the step registers the response body as a
  readable stream and returns the handle (positive integer) as its
  step result; later steps read it or forward it as a request body.
- **Request mode** — the step accepts a stream handle as its body,
  moves the source out of the registry with `take_readable`, and
  wraps it as a streaming request body (e.g.
  `reqwest::Body::wrap_stream`) so the HTTP client pulls chunks as
  it transmits. Zero host-side body buffering.

## Beyond the three calls

- **Fan-out (tee)** — a single producer feeding multiple consumers
  is handled host-side when a producer has more than one consumer.
  The sequential-wave scheduler uses the eager free function
  `fan_out_readable_shared`; the parallel-wave and dataflow paths use
  `StreamRegistry::fan_out_readable_streaming` (bounded-buffer,
  per-branch backpressure). Both live in
  [`streams.rs`](streams.rs). Streaming fan-out buffers up to
  `STREAM_FANOUT_CAPACITY` (16) chunks per branch before
  backpressuring the forwarder; the same constant sizes the writable
  pipes the dataflow scheduler pre-provisions. Transparent to plugins
  — each consumer just reads its own handle.
- **Concurrent producer/consumer pipelines** — the streaming
  dataflow scheduler ([`runtime_dataflow.rs`](runtime_dataflow.rs))
  runs steps of a `dataflow: true` action as concurrent tasks with
  stage-to-stage backpressure, including writable-backed outputs for
  `long_running` steps (`stream_output`).
- **Event streams** — event-semantic framing over the same byte-pipe
  ABI is not part of this ABI.
