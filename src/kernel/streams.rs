//! Stream primitives for the Gwead kernel.
//!
//! Streams are the kernel's byte-pipe abstraction. A stream is an opaque
//! handle owned by `ExecutionState`; plugins receive the handle as an integer
//! and call host functions to read, write, or close it.
//!
//! ## Zero-copy data flow
//!
//! Stream chunks are [`bytes::Bytes`] — a ref-counted slice type. Cloning
//! a chunk is a refcount bump (no byte copy); slicing is a refcount bump
//! plus a window. Host-native steps that route, tee, or slice streams
//! operate entirely on refcounted views: no byte copies anywhere on the
//! host side.
//!
//! The wasm-boundary copy (when a sandboxed plugin calls `stream_read`)
//! is the cost of sandboxing, not of streaming. Rust-native step types
//! that want to consume bytes can do so without any boundary crossing.
//!
//! ## SPSC + transparent fan-out
//!
//! By construction each readable stream has one upstream source. When more
//! than one downstream step reads from the same producer, the DAG scheduler
//! calls [`fan_out_readable_shared`] (sequential waves, eager drain) or
//! [`StreamRegistry::fan_out_readable_streaming`] (parallel waves /
//! dataflow) to convert the producer into N
//! branch readables. A forwarder task pulls chunks from the original source
//! and sends each `Bytes` (refcount-bumped, not byte-copied) to N
//! per-branch mpsc channels. Each channel is bounded — a slow consumer
//! blocks the forwarder on `send().await`, which in turn stops pulling from
//! the upstream source. That's the natural backpressure path: producer slows
//! to match the slowest consumer, no buffer grows without bound.
//!
//! ## Direction
//!
//! A stream is either [`StreamDirection::Readable`] (host provides a
//! source, plugin pulls via `stream_read`) or
//! [`StreamDirection::Writable`] (plugin pushes via `stream_write`,
//! host consumes from a receiver). One direction per handle — attempting
//! `stream_write` on a readable returns `DIRECTION_MISMATCH`.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, MutexGuard};

use bytes::Bytes;
use futures::stream::BoxStream;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Default per-branch chunk-count capacity for the streaming fan-out
/// tee (`fan_out_readable_streaming`) and for the writable→
/// readable pipes pre-provisioned by the dataflow scheduler
/// (`runtime_dataflow::provision_dataflow_streams`).
///
/// 16 chunks at typical media chunk sizes (64 KiB-ish) buffers around
/// 1 MiB per consumer — small enough to apply backpressure quickly,
/// large enough that the forwarder isn't synchronously stalled on
/// every chunk. Shared from one place so the wave-scheduled fan-out
/// path and the dataflow pre-flight can't drift.
pub const STREAM_FANOUT_CAPACITY: usize = 16;

/// Largest stream handle the registry will ever allocate.
///
/// The wasm ABI hands handles to guests as `i32`, with the negative
/// space reserved for `STREAM_*` error codes, so every id the kernel
/// issues must fit in a positive `i32`. [`StreamRegistry`] enforces
/// this at allocation time; the ABI import layer debug-asserts it as a
/// tripwire.
pub const MAX_STREAM_HANDLE: u32 = i32::MAX as u32;

/// One execution's stream handle table, shared between the host
/// operations running inside that execution.
///
/// The inner `Mutex` is held only briefly around each host operation —
/// long enough to look a handle up, never across an `.await`.
/// Per-stream state sits behind its own lock (see [`StreamState`]), so
/// operations on different streams never contend on this one.
///
/// **Not shared across executions.** A nested invocation does not
/// inherit the caller's registry: if it did, it would inherit the
/// caller's entire handle space — handles are small integers from a
/// counter starting at 1, so a callee could read handle `1` and get
/// bytes belonging to a plugin that never granted it anything. Each
/// execution gets its own table and a handle is an index into it, so
/// naming another execution's handle is not a thing that can be
/// expressed rather than a thing that is refused. See
/// [`StreamRegistry`].
pub type SharedStreamRegistry = Arc<Mutex<StreamRegistry>>;

/// Lock a `SharedStreamRegistry`, recovering from poisoning rather than
/// panicking.
///
/// The registry holds a `HashMap` of well-typed `StreamState` entries
/// plus a monotonic id counter; none of the host operations leave it in
/// a partially-valid state, so taking the inner data after a poison is
/// safe and avoids turning a stray panic in one step into a kernel kill
/// switch in a long-lived host process.
pub fn lock_shared(arc: &SharedStreamRegistry) -> MutexGuard<'_, StreamRegistry> {
    arc.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// The unit of data flow — a ref-counted slice.
pub type StreamChunk = Bytes;

/// Opaque stream handle. Non-zero so `0` stays available as an
/// "invalid/null" sentinel if any caller ever needs one. Handed to
/// plugins as `i32` via JSON (the u32 fits safely in positive i32).
pub type StreamId = NonZeroU32;

/// Readable source: an async stream of `Bytes` chunks.
pub type ReadableSource = BoxStream<'static, Result<Bytes, std::io::Error>>;

/// Writable sender: mpsc channel the consumer (e.g. reqwest's
/// `Body::wrap_stream`) drains.
pub type WritableSender = mpsc::Sender<Result<Bytes, std::io::Error>>;

/// Paired receiver type for `register_writable`.
pub type WritableReceiver = mpsc::Receiver<Result<Bytes, std::io::Error>>;

/// Direction-specific state for a stream.
///
/// Publicly reachable via [`StreamRegistry::get`], so it is
/// `#[non_exhaustive]` — both at the enum level (a third direction
/// stays additive) and per variant (the cursor fields are kernel
/// bookkeeping; nothing outside the kernel should be building one).
#[non_exhaustive]
pub enum StreamDirection {
    /// Host → plugin. The plugin calls `stream_read` to pull bytes.
    #[non_exhaustive]
    Readable {
        /// The async source of chunks (HTTP response body, file, channel, …).
        source: ReadableSource,
        /// A partially-consumed chunk carried over between `stream_read`
        /// calls. Keeping the `Bytes` here lets a single 64KB network
        /// chunk back many smaller wasm reads with no host-side copies —
        /// each read just slices off the head and advances the cursor.
        /// `None` means "pull the next chunk from `source` on the next read".
        leftover: Option<Bytes>,
    },
    /// Plugin → host. The plugin calls `stream_write`; the host's
    /// consumer reads from the paired `WritableReceiver`.
    #[non_exhaustive]
    Writable { sink: WritableSender },
}

/// A single stream's state, keyed by `StreamId` in the registry.
///
/// The mutable fields (`direction`, `closed`) live behind a per-stream
/// [`Mutex`] so concurrent operations on **different** streams never
/// serialize against each other — only operations against the *same*
/// stream do, and even those go through the swap-out / put-back pattern
/// in [`Self::read_async`] so no mutex is held across the `.await`.
/// That's the property that lets parallel-wave fan-out
/// ([`StreamRegistry::fan_out_readable_streaming`]) and dataflow
/// pipelines scale without contention.
pub struct StreamState {
    pub id: StreamId,
    pub content_type: String,
    inner: Mutex<StreamInner>,
    /// Serialises [`Self::read_async`] calls on **this** stream.
    ///
    /// The kernel's DAG planner is supposed to guarantee one reader
    /// per handle (multi-consumer producers are split via
    /// `fan_out_readable*`), but that guarantee cannot be left to a
    /// `debug_assert!` alone: a plugin can violate it from two steps
    /// in one parallel wave, and without this gate two overlapping
    /// reads would silently corrupt the transfer. The first swaps the
    /// real source out and leaves `futures::stream::empty()` behind,
    /// so the second would read the placeholder and be told
    /// `STREAM_EOF` with bytes still pending. A well-behaved consumer
    /// then does the textbook correct thing and closes on EOF, which
    /// makes the in-flight reader's put-back get skipped, dropping the
    /// live source mid-transfer — a short read reported as success.
    ///
    /// This is a `tokio::sync::Mutex` rather than a `std` one because
    /// it is held across the source's `.await`. Different streams
    /// never contend on it; only two readers of the same handle do,
    /// and they serialise instead of corrupting.
    read_gate: tokio::sync::Mutex<()>,
}

/// Per-stream mutable state, reachable only under
/// [`StreamState::lock_inner`]. Going through the lock is what keeps a
/// caller from accidentally holding the per-stream mutex across an
/// await.
#[non_exhaustive]
pub struct StreamInner {
    pub direction: StreamDirection,
    /// True once closed by either side. Both reads and writes past
    /// close return `STREAM_CLOSED` (-4) — *not* `STREAM_EOF`. EOF
    /// means "this source is exhausted"; CLOSED means "this handle is
    /// gone". A guest that conflates them will treat a use-after-close
    /// bug as a normal end of stream.
    pub closed: bool,
}

impl StreamState {
    fn new(id: StreamId, content_type: String, direction: StreamDirection) -> Arc<Self> {
        Arc::new(StreamState {
            id,
            content_type,
            inner: Mutex::new(StreamInner {
                direction,
                closed: false,
            }),
            read_gate: tokio::sync::Mutex::new(()),
        })
    }

    /// Lock the per-stream inner state. Recovers from poisoning rather
    /// than panicking — see the rationale on [`lock_shared`].
    pub fn lock_inner(&self) -> MutexGuard<'_, StreamInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Is this stream readable? Takes the per-stream lock briefly.
    pub fn is_readable(&self) -> bool {
        matches!(
            self.lock_inner().direction,
            StreamDirection::Readable { .. }
        )
    }

    /// Is this stream writable? Takes the per-stream lock briefly.
    pub fn is_writable(&self) -> bool {
        matches!(
            self.lock_inner().direction,
            StreamDirection::Writable { .. }
        )
    }

    /// Has this stream been closed? Takes the per-stream lock briefly.
    pub fn is_closed(&self) -> bool {
        self.lock_inner().closed
    }
}

/// One execution's stream handle table, owned by its `ExecutionState`.
///
/// # Handles are capabilities, and this table is what makes them so
///
/// A handle is an index into **this** table and means nothing outside
/// it. Two executions each holding handle `1` hold two unrelated
/// streams, and neither can name the other's — not because a check
/// refuses it, but because the number does not identify anything over
/// there.
///
/// That structural property is what rules out a whole class of leak.
/// Handles come
/// from a counter starting at 1, so they are entirely predictable; if
/// a nested invocation *inherited the caller's registry*, a callee
/// could call `stream_read(1)` and receive bytes from a stream
/// belonging to a plugin that had granted it nothing — exfiltrating
/// another plugin's data and leaving the victim's stream closed behind
/// it.
///
/// The two obvious alternatives are both rejected:
///
/// - **An owner tag checked at every `stream_*` entry point.** That is
///   a *remembered* check: each new entry point is another chance to
///   forget it, and a single forgotten one reopens the leak.
/// - **Unguessable handle ids.** Obscurity. It would defeat the naive
///   exploit without closing the hole.
///
/// # Crossing the boundary is explicit and is a move
///
/// A stream reaches another execution only by being placed in that
/// execution's table — [`Self::adopt`] mints a handle there, and
/// [`Self::take`] removes it here. Caller loses access as the callee
/// gains it. Borrowing (both sides live at once) is deliberately not
/// offered: it would reintroduce two live readers of one stream, which
/// is exactly what [`StreamState`]'s read gate exists to prevent, and
/// it needs generation checks to avoid a use-after-revoke. Move →
/// borrow stays additive if a real proxying case ever turns up; borrow
/// → move would be breaking.
///
/// The registry-wide outer mutex (via [`SharedStreamRegistry`]) is
/// held only briefly for HashMap insert / lookup / clear ops. All
/// stream-state mutation goes through the per-stream
/// [`StreamState::lock_inner`] mutex, so a slow read on one stream
/// never blocks operations on another.
pub struct StreamRegistry {
    streams: HashMap<StreamId, Arc<StreamState>>,
    next_id: u32,
}

impl Default for StreamRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamRegistry {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            next_id: 1,
        }
    }

    /// Allocate the next handle. Monotonic, and bounded by
    /// [`MAX_STREAM_HANDLE`]: the wasm ABI returns handles as `i32`,
    /// so an id at or above `0x8000_0000` would cross to the guest as
    /// a negative number and be misread as a `STREAM_*` error code.
    /// Exceeding the bound is a fatal error — two billion streams in
    /// one action invocation means something is very wrong — and
    /// enforcing it here, at the only allocation site, is what lets
    /// the ABI boundary's `debug_assert!`s stay debug-only.
    fn next_handle(&mut self) -> StreamId {
        assert!(
            self.next_id <= MAX_STREAM_HANDLE,
            "stream id counter exceeded MAX_STREAM_HANDLE ({MAX_STREAM_HANDLE}) within one action — bug"
        );
        let id = NonZeroU32::new(self.next_id).expect("next_id starts at 1 and only increments");
        self.next_id += 1;
        id
    }

    /// Register a readable stream backed by an async source.
    pub fn register_readable(
        &mut self,
        content_type: impl Into<String>,
        source: ReadableSource,
    ) -> StreamId {
        let id = self.next_handle();
        let state = StreamState::new(
            id,
            content_type.into(),
            StreamDirection::Readable {
                source,
                leftover: None,
            },
        );
        self.streams.insert(id, state);
        id
    }

    /// Register a writable stream. Returns the handle the plugin gets
    /// plus the receiver the host-side consumer drains.
    /// The channel is bounded so a slow consumer backpressures the
    /// plugin's `stream_write` naturally.
    pub fn register_writable(
        &mut self,
        content_type: impl Into<String>,
        channel_capacity: usize,
    ) -> (StreamId, WritableReceiver) {
        let (tx, rx) = mpsc::channel(channel_capacity);
        let id = self.next_handle();
        let state = StreamState::new(
            id,
            content_type.into(),
            StreamDirection::Writable { sink: tx },
        );
        self.streams.insert(id, state);
        (id, rx)
    }

    /// A sender of your own for a writable stream — a clone of the one
    /// the stream's owner writes through. The paired receiver sees EOF
    /// only once *every* sender is gone, so holding this keeps the
    /// stream open past the owner's `close`: the kernel holds one for
    /// a spawned streaming callee until the callee has ended, so that
    /// EOF means the outcome is known (the outcome itself travels
    /// beside the channel, not through this). Drop it when the stream
    /// may end. `None` for an unknown handle, a readable, or a closed
    /// stream. Crate-private: an embedder holding senders would defer
    /// every EOF it forgot to drop, and nothing outside needs one.
    pub(crate) fn writable_sender(&self, id: StreamId) -> Option<WritableSender> {
        let state = self.streams.get(&id)?;
        let inner = state.lock_inner();
        if inner.closed {
            return None;
        }
        match &inner.direction {
            StreamDirection::Writable { sink } => Some(sink.clone()),
            StreamDirection::Readable { .. } => None,
        }
    }

    /// Mark a stream closed and drop its direction state. Subsequent
    /// lookups still find the state (so handle errors map to `CLOSED`
    /// rather than `INVALID_HANDLE`), but the underlying source /
    /// sender is released.
    ///
    /// Locks the per-stream mutex only — outer registry mutex callers
    /// can hold this through close because the inner mutex is the only
    /// thing actually serialised against concurrent stream ops.
    pub fn close(&mut self, id: StreamId) {
        if let Some(state) = self.streams.get(&id) {
            let mut inner = state.lock_inner();
            inner.closed = true;
            // Replace direction with an already-exhausted Readable so
            // the original `source` or `sink` is dropped immediately.
            inner.direction = StreamDirection::Readable {
                source: Box::pin(futures::stream::empty()),
                leftover: None,
            };
        }
    }

    /// Drop every remaining stream. Called post-execution so no HTTP
    /// connection or mpsc sender leaks past an action's lifetime.
    ///
    /// `Arc<StreamState>` entries that another task still holds (e.g.
    /// a forwarder task spawned by `fan_out_readable_streaming`) stay
    /// alive until that task drops its handle — the registry just
    /// stops being the owner.
    pub fn drain(&mut self) {
        self.streams.clear();
        self.next_id = 1;
    }

    /// Read-only lookup. Returns a clone of the `Arc` so the caller can
    /// drop the registry-wide lock before doing any stream work.
    pub fn get(&self, id: StreamId) -> Option<Arc<StreamState>> {
        self.streams.get(&id).cloned()
    }

    /// Mint a handle in **this** table for a stream that already exists.
    ///
    /// The receiving half of a transfer. The returned handle is fresh
    /// and local: it bears no relation to whatever handle the stream had
    /// in the table it came from, which is the point — an execution
    /// never learns another execution's numbering.
    ///
    /// Pair with [`Self::take`] on the source table to make the transfer
    /// a move. Calling this alone leaves the stream reachable from both
    /// tables, which is a borrow, and is not a shape the kernel offers:
    /// two live readers of one stream is precisely what
    /// [`StreamState`]'s read gate exists to serialise around.
    pub fn adopt(&mut self, state: Arc<StreamState>) -> StreamId {
        let id = self.next_handle();
        self.streams.insert(id, state);
        id
    }

    /// Remove `id` from this table and return the stream behind it.
    ///
    /// The giving half of a transfer. The handle is invalid here
    /// afterwards — a later `stream_read` on it reports
    /// `STREAM_INVALID_HANDLE` rather than reaching a stream somebody
    /// else now owns.
    ///
    /// The stream itself is untouched: this hands over the `Arc`, it
    /// does not close anything.
    pub fn take(&mut self, id: StreamId) -> Option<Arc<StreamState>> {
        self.streams.remove(&id)
    }

    /// How many streams are currently registered.
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// No streams registered.
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// Synchronous close — the core of `stream_close` across the wasm
    /// boundary. Idempotent: closing an already-closed stream returns 0.
    /// Unknown handle returns `STREAM_INVALID_HANDLE`.
    pub fn close_handle(&mut self, id: StreamId) -> i32 {
        if !self.streams.contains_key(&id) {
            return STREAM_INVALID_HANDLE;
        }
        self.close(id);
        0
    }

    /// Take ownership of the readable source for `id`, replacing it
    /// with an exhausted stub so subsequent reads see EOF. Returns the
    /// content-type alongside the source so callers (e.g. streaming
    /// `http_call` request bodies) can forward it downstream.
    ///
    /// Returns `None` if the id is unknown, points at a writable
    /// stream, or the stream is already closed. The stream itself
    /// stays in the registry — we just take its payload, so
    /// `close_handle` / `drain` semantics stay consistent.
    pub fn take_readable(&mut self, id: StreamId) -> Option<(String, ReadableSource)> {
        let state = self.streams.get(&id)?.clone();
        let ct = state.content_type.clone();
        let mut inner = state.lock_inner();
        if inner.closed {
            return None;
        }
        match &mut inner.direction {
            StreamDirection::Writable { .. } => None,
            StreamDirection::Readable { source, leftover } => {
                // Pull out whatever's left of the leftover cursor as a
                // prefix, so a caller that read part of the stream and
                // then took it still sees a seamless byte sequence.
                let prefix = leftover.take();
                let drained = std::mem::replace(source, Box::pin(futures::stream::empty()));
                inner.closed = true;
                let full: ReadableSource = if let Some(prefix_bytes) = prefix {
                    use futures::StreamExt;
                    let head = futures::stream::once(async move { Ok(prefix_bytes) });
                    Box::pin(head.chain(drained))
                } else {
                    drained
                };
                Some((ct, full))
            }
        }
    }

    /// Convert a readable stream into `n_branches` independent readable
    /// branches that each see the same byte sequence — the streaming
    /// variant of [`fan_out_readable_shared`], with bounded-buffer
    /// per-branch backpressure instead of eager drain.
    ///
    /// The producer stream's source is taken (subsequent reads on the
    /// original handle return EOF). Used by the DAG scheduler when a
    /// stream-producing step has more than one consumer in
    /// [`super::dag::DagPlan::consumers`]. Each consumer's reference to
    /// the producer is rewritten to point at its own branch.
    ///
    /// Spawns a forwarder task that pulls one chunk at a time from the
    /// upstream source and broadcasts a refcount-bumped clone (`Bytes::clone`)
    /// to each of `n_branches` bounded mpsc channels. The forwarder uses
    /// `join_all` to wait for **every** sender to accept the chunk before
    /// pulling the next, so the producer paces itself off the slowest
    /// consumer — true bounded-memory backpressure.
    ///
    /// Requires concurrent consumers — i.e. the parallel-wave
    /// path (`Action::parallel_waves: true`). Under sequential within-wave
    /// execution, the forwarder fills the first consumer's channel and
    /// blocks waiting for the second consumer to drain its (also full)
    /// channel — deadlock. Callers in sequential-wave actions should use
    /// [`fan_out_readable_shared`] (eager) instead.
    ///
    /// `channel_capacity` is the per-branch chunk-count cap; values
    /// around 16 are reasonable for typical chunk sizes (64 KiB-ish).
    /// Errors midstream propagate to every branch as
    /// `STREAM_IO_ERROR`, then the forwarder exits and senders drop —
    /// consumers reading after the error see EOF on the next read.
    pub fn fan_out_readable_streaming(
        &mut self,
        producer: StreamId,
        n_branches: usize,
        channel_capacity: usize,
    ) -> Result<Vec<StreamId>, &'static str> {
        if n_branches == 0 {
            return Err("fan_out_readable_streaming: n_branches must be > 0");
        }
        if channel_capacity == 0 {
            return Err("fan_out_readable_streaming: channel_capacity must be > 0");
        }
        let (content_type, source) = self
            .take_readable(producer)
            .ok_or("fan_out_readable_streaming: producer is not an open readable")?;

        let mut senders: Vec<WritableSender> = Vec::with_capacity(n_branches);
        let mut branch_ids: Vec<StreamId> = Vec::with_capacity(n_branches);
        for _ in 0..n_branches {
            let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(channel_capacity);
            // Fused: a consumer that takes this branch out of the
            // registry polls it directly, and an `Unfold` panics if
            // polled past its end. Reads through the registry are
            // guarded separately, in `read_async`, and that guard also
            // covers sources an embedder registers unfused — so
            // neither guard makes the other redundant.
            let recv_source: ReadableSource = Box::pin(futures::StreamExt::fuse(
                futures::stream::unfold(rx, |mut rx| async move {
                    rx.recv().await.map(|item| (item, rx))
                }),
            ));
            let id = self.next_handle();
            let state = StreamState::new(
                id,
                content_type.clone(),
                StreamDirection::Readable {
                    source: recv_source,
                    leftover: None,
                },
            );
            self.streams.insert(id, state);
            senders.push(tx);
            branch_ids.push(id);
        }

        // Forwarder task: read upstream → broadcast to every branch
        // sender, paced by the slowest one. Errors propagate to all
        // branches as io::Error before the task exits.
        tokio::spawn(async move {
            use futures::StreamExt;
            let mut source = source;
            while let Some(item) = source.next().await {
                match item {
                    Ok(chunk) => {
                        let sends: Vec<_> = senders
                            .iter()
                            .map(|s| {
                                let chunk = chunk.clone();
                                async move { s.send(Ok(chunk)).await }
                            })
                            .collect();
                        let outcomes = futures::future::join_all(sends).await;
                        // Every consumer dropped — nothing left to feed.
                        if outcomes.iter().all(|r| r.is_err()) {
                            return;
                        }
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        let sends: Vec<_> = senders
                            .iter()
                            .map(|s| {
                                let msg = msg.clone();
                                async move { s.send(Err(std::io::Error::other(msg))).await }
                            })
                            .collect();
                        let _ = futures::future::join_all(sends).await;
                        // Drop senders to deliver EOF behind the error.
                        return;
                    }
                }
            }
            // Source EOF — dropping senders signals EOF to every branch.
            drop(senders);
        });

        Ok(branch_ids)
    }
}

/// Eager-drain fan-out (sequential-wave variant). Async free function
/// rather than a method on [`StreamRegistry`] so the registry mutex is
/// released across the source-drain `.await` — holding the std
/// `MutexGuard` across an await would (1) make the surrounding future
/// `!Send` and (2) block every other registry op while we drain.
///
/// Two-phase: lock briefly to `take_readable(producer)`, drain async
/// with no lock held, lock again briefly to insert the branch
/// [`StreamState`]s. Same shape as [`read_async_shared`]. A
/// midstream error is preserved so each branch can re-emit it after
/// the accumulated chunks; silently truncating would let consumers
/// treat a faulted source as a clean EOF.
///
/// Used for the sequential-wave fan-out path —
/// `Action::parallel_waves: false`. Parallel-wave fan-out goes through
/// [`StreamRegistry::fan_out_readable_streaming`] (sync, just spawns
/// a forwarder task) since that variant runs concurrent consumers
/// against a bounded mpsc per branch.
pub async fn fan_out_readable_shared(
    arc: &SharedStreamRegistry,
    producer: StreamId,
    n_branches: usize,
) -> Result<Vec<StreamId>, &'static str> {
    if n_branches == 0 {
        return Err("fan_out_readable_shared: n_branches must be > 0");
    }
    let (content_type, source) = {
        let mut reg = lock_shared(arc);
        reg.take_readable(producer)
            .ok_or("fan_out_readable_shared: producer is not an open readable")?
    };

    let (chunks, error_msg): (Vec<Bytes>, Option<String>) = {
        use futures::StreamExt;
        let mut buf = Vec::new();
        let mut err: Option<String> = None;
        let mut src = source;
        while let Some(item) = src.next().await {
            match item {
                Ok(chunk) => buf.push(chunk),
                Err(e) => {
                    let msg = e.to_string();
                    tracing::warn!(
                        error = %msg,
                        "Fan-out source faulted midstream after {} chunks; \
                         branches will surface STREAM_IO_ERROR",
                        buf.len()
                    );
                    err = Some(msg);
                    break;
                }
            }
        }
        (buf, err)
    };

    let mut reg = lock_shared(arc);
    let mut branch_ids: Vec<StreamId> = Vec::with_capacity(n_branches);
    for _ in 0..n_branches {
        let chunks_for_branch = chunks.clone();
        let error_for_branch = error_msg.clone();
        let recv_source: ReadableSource = {
            let head = futures::stream::iter(
                chunks_for_branch
                    .into_iter()
                    .map(Ok::<Bytes, std::io::Error>),
            );
            if let Some(msg) = error_for_branch {
                use futures::StreamExt;
                let tail = futures::stream::once(async move { Err(std::io::Error::other(msg)) });
                Box::pin(head.chain(tail))
            } else {
                Box::pin(head)
            }
        };
        let id = reg.next_handle();
        let state = StreamState::new(
            id,
            content_type.clone(),
            StreamDirection::Readable {
                source: recv_source,
                leftover: None,
            },
        );
        reg.streams.insert(id, state);
        branch_ids.push(id);
    }

    Ok(branch_ids)
}

impl StreamState {
    /// Per-stream async read. Holds only the per-stream mutex briefly
    /// (to swap the `source` cursor out and put it back), not across
    /// the `.await`. Different streams' reads never block each other.
    ///
    /// **Kernel invariant: one reader per `StreamId`.** Multi-consumer
    /// producers get split into independent branches by
    /// `fan_out_readable*` so no two consumers ever share a handle.
    /// Concurrent calls on the same `StreamState` are a kernel bug —
    /// the DAG planner failed to install a fan-out, or a step type is
    /// forwarding a handle it shouldn't.
    ///
    /// Overlapping reads are **serialised** by a per-stream async
    /// read gate in every build, so a violation costs latency rather
    /// than data, and the contention is logged at `warn` so the
    /// underlying planner or plugin bug still surfaces.
    pub async fn read_async(&self, buf: &mut [u8]) -> i32 {
        use futures::StreamExt;

        // Serialise against any other reader of this same handle. The
        // uncontended path is a `try_lock`, so the common case costs
        // one atomic.
        //
        // Contention is deliberately not a `debug_assert!`. It is not
        // only a kernel planner bug: two script steps running in the
        // same parallel wave can both call `stream_read` on the same
        // handle, so a *plugin* decides whether this fires. An assert
        // here would let a guest panic its host on a debug build — a
        // plugin crashing the process it runs inside, which is the
        // opposite of what a sandbox is for.
        //
        // So it warns and waits, in every build. The contention is still
        // worth surfacing: it is either a planner bug or a plugin
        // reading one handle from two places, and both want fixing. It
        // is just not worth aborting over, and the wait already makes it
        // harmless.
        let _gate = match self.read_gate.try_lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!(
                    stream_id = self.id.get(),
                    "Concurrent read on one stream handle — serialising. \
                     Expect one reader per stream; multi-consumer producers \
                     should go through fan_out_readable*, and a plugin reading \
                     the same handle from two steps should read it from one"
                );
                self.read_gate.lock().await
            }
        };

        // Step 1: swap source + leftover out under the per-stream lock.
        let (mut source, mut leftover) = {
            let mut inner = self.lock_inner();
            if inner.closed {
                return STREAM_CLOSED;
            }
            match &mut inner.direction {
                StreamDirection::Writable { .. } => return STREAM_DIRECTION_MISMATCH,
                StreamDirection::Readable { source, leftover } => {
                    let s = std::mem::replace(source, Box::pin(futures::stream::empty()));
                    let l = leftover.take();
                    (s, l)
                }
            }
        };

        // Step 2: pull next chunk if needed, no lock held.
        let mut io_error = false;
        let mut eof = false;
        if leftover.is_none() {
            // Skip empty chunks rather than reporting them as EOF.
            //
            // Reporting an empty `Bytes` mid-stream as `STREAM_EOF`
            // while the source is put back intact would let a later
            // read return more data — an EOF that does not stick. The
            // ABI defines `STREAM_EOF` as "source exhausted", so a
            // guest treating the first `-1` as terminal (the correct
            // reading) would silently truncate. Sources that emit empty
            // chunks are legal — a chunked HTTP body can produce one —
            // so they are consumed and ignored here. Each
            // iteration awaits, so a source that only ever yields empty
            // chunks parks this task rather than spinning a core.
            loop {
                match source.next().await {
                    Some(Ok(chunk)) if chunk.is_empty() => continue,
                    Some(Ok(chunk)) => {
                        leftover = Some(chunk);
                        break;
                    }
                    Some(Err(_)) => {
                        io_error = true;
                        break;
                    }
                    None => {
                        eof = true;
                        break;
                    }
                }
            }
        }

        // Step 3: copy leftover into buf.
        let mut bytes_written: i32 = 0;
        let new_leftover = if !eof
            && !io_error
            && let Some(chunk) = leftover.take()
        {
            let n = buf.len().min(chunk.len());
            buf[..n].copy_from_slice(&chunk[..n]);
            bytes_written = n as i32;
            if n < chunk.len() {
                Some(chunk.slice(n..))
            } else {
                None
            }
        } else {
            None
        };

        // Step 4: put source + leftover back unless closed. EOF is
        // sticky: an exhausted source is replaced by an empty one, so a
        // guest that reads past EOF gets `STREAM_EOF` again rather than
        // polling a finished stream. A source an embedder registers
        // through `register_readable` may be anything — a bare
        // `Unfold` panics when polled past its end — and a guest must
        // not be able to panic its host with a loop that reads one
        // time too many. The kernel's own channel-backed readables are
        // fused at construction for the consumers that *take* the
        // source and poll it directly, bypassing this path; that does
        // not make this guard redundant, nor this guard those fuses.
        //
        // Only EOF sticks. After an IO error the source goes back as it
        // is, on purpose: an error item does not end a source, and the
        // `None` that follows it is what ends the stream — the guest
        // sees the error code once and then EOF, which
        // `read_reports_an_error_item_once_and_then_eof` pins. Making
        // the error sticky too would turn one failed read into a
        // stream that can never report its EOF.
        {
            let mut inner = self.lock_inner();
            if !inner.closed
                && let StreamDirection::Readable {
                    source: cur_source,
                    leftover: cur_leftover,
                } = &mut inner.direction
            {
                *cur_source = if eof {
                    Box::pin(futures::stream::empty())
                } else {
                    source
                };
                *cur_leftover = new_leftover;
            }
        }

        if io_error {
            STREAM_IO_ERROR
        } else if eof {
            STREAM_EOF
        } else {
            bytes_written
        }
    }

    /// Per-stream async write. Clones the `mpsc::Sender` under the
    /// per-stream lock, drops it, then `.await`s the send.
    ///
    /// The channel is bounded, and a send that finds it full waits
    /// for the consumer to take something — that is the backpressure
    /// a writable exists to apply. A consumer that keeps its receiver
    /// open but stops reading would otherwise hold the writer here
    /// for good, and a writer parked inside a host import never gets
    /// back to its own code to notice it was cancelled, so a parked
    /// send is raced against `cancel`: when the token fires first the
    /// write returns [`STREAM_CANCELLED`] with nothing committed, and
    /// the channel is left as it was. The wallclock watchdog fires
    /// the same token, so a deadline reaches a parked writer the same
    /// way.
    ///
    /// Only a *parked* write is released. A write the channel has room
    /// for is committed even under a fired token, so a producer that
    /// has noticed the cancel can still push the chunk it was holding
    /// before it stops; the token is a backstop for the wait, not a
    /// gate on the data. A receiver that has gone away is
    /// [`STREAM_CLOSED`] whether or not the token has fired.
    pub async fn write_async(&self, data: &[u8], cancel: &CancellationToken) -> i32 {
        let sink = {
            let inner = self.lock_inner();
            if inner.closed {
                return STREAM_CLOSED;
            }
            match &inner.direction {
                StreamDirection::Readable { .. } => return STREAM_DIRECTION_MISMATCH,
                StreamDirection::Writable { sink } => sink.clone(),
            }
        };
        let bytes = Bytes::copy_from_slice(data);
        let bytes = match sink.try_send(Ok(bytes)) {
            Ok(()) => return data.len() as i32,
            Err(mpsc::error::TrySendError::Closed(_)) => return STREAM_CLOSED,
            Err(mpsc::error::TrySendError::Full(bytes)) => bytes,
        };
        // `biased` so a token that fires while the send is parked wins
        // the very next poll, and so the outcome under a token that
        // is already fired does not depend on which arm the select
        // happens to try first. `Sender::send` reserves a slot and
        // commits in one poll, so losing the race never leaves a
        // half-sent chunk behind.
        tokio::select! {
            biased;
            () = cancel.cancelled() => STREAM_CANCELLED,
            sent = sink.send(bytes) => match sent {
                Ok(()) => data.len() as i32,
                Err(_) => STREAM_CLOSED,
            },
        }
    }
}

/// Shared-registry entry point for the wasm `stream_read` host
/// import. Briefly takes the outer registry mutex just
/// long enough to clone the `Arc<StreamState>` for the handle out,
/// then delegates to [`StreamState::read_async`] which uses the
/// per-stream mutex with the swap-out / put-back pattern.
///
/// Two locking levels:
///
/// - **Outer** (`SharedStreamRegistry`): held only for the HashMap
///   lookup. Synchronous, no `.await` underneath.
/// - **Inner** ([`StreamState::lock_inner`]): held only across the
///   swap-out / put-back of the `source` cursor, never across the
///   `source.next().await`.
///
/// That's the property that lets parallel-wave fan-out
/// ([`StreamRegistry::fan_out_readable_streaming`]) and dataflow
/// pipelines scale: a slow `recv()` on
/// stream X doesn't block reads on stream Y, and even reads on
/// the same stream serialize cleanly rather than racing.
pub async fn read_async_shared(arc: &SharedStreamRegistry, id: StreamId, buf: &mut [u8]) -> i32 {
    let state = {
        let reg = lock_shared(arc);
        match reg.streams.get(&id) {
            Some(s) => s.clone(),
            None => return STREAM_INVALID_HANDLE,
        }
    };
    state.read_async(buf).await
}

/// Shared-registry entry point for the wasm `stream_write` host
/// import. Same outer-lock + delegate pattern as
/// [`read_async_shared`]; the send runs under the per-stream mutex
/// (dropped before the `.await`). `cancel` is the writing
/// invocation's token; see [`StreamState::write_async`] for what it
/// does to a parked send.
pub async fn write_async_shared(
    arc: &SharedStreamRegistry,
    id: StreamId,
    data: &[u8],
    cancel: &CancellationToken,
) -> i32 {
    let state = {
        let reg = lock_shared(arc);
        match reg.streams.get(&id) {
            Some(s) => s.clone(),
            None => return STREAM_INVALID_HANDLE,
        }
    };
    state.write_async(data, cancel).await
}

// ---------------------------------------------------------------------------
// Error codes returned across the wasm boundary.
//
// The ABI contract: `stream_read`/`stream_write` return bytes transferred
// on success (>0) or one of these negative codes. Kept in one place so
// guest runtime bindings, the host functions, and the ABI docs stay
// aligned.
// ---------------------------------------------------------------------------

/// Successful EOF on a readable stream.
pub const STREAM_EOF: i32 = -1;
/// Handle does not refer to a known stream.
pub const STREAM_INVALID_HANDLE: i32 = -2;
/// Read on a writable stream, or write on a readable stream.
pub const STREAM_DIRECTION_MISMATCH: i32 = -3;
/// Stream has been closed by `stream_close` or the paired consumer.
pub const STREAM_CLOSED: i32 = -4;
/// A readable source returned an I/O error, or the guest module
/// exports no `memory`. A write whose paired consumer has gone away
/// is [`STREAM_CLOSED`], not this.
pub const STREAM_IO_ERROR: i32 = -5;
/// Buffer pointer + length exceeds the wasm module's linear memory.
pub const STREAM_OOB: i32 = -6;
/// A write parked on a full channel was released by the invocation's
/// cancellation token — the caller's cancel or the wallclock
/// watchdog — before the consumer made room. Nothing was committed.
/// Distinct from [`STREAM_CLOSED`] so a guest can tell a consumer that
/// went away (finish cleanly) from a stop it was told to make.
pub const STREAM_CANCELLED: i32 = -7;

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;

    fn bytes_source(chunks: Vec<Bytes>) -> ReadableSource {
        Box::pin(stream::iter(chunks.into_iter().map(Ok)))
    }

    /// A token nobody fires, for writes whose cancellation path is
    /// not under test.
    fn never() -> CancellationToken {
        CancellationToken::new()
    }

    #[test]
    fn registry_starts_empty() {
        let reg = StreamRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn register_readable_returns_increasing_ids() {
        let mut reg = StreamRegistry::new();
        let a = reg.register_readable("application/octet-stream", bytes_source(vec![]));
        let b = reg.register_readable("application/octet-stream", bytes_source(vec![]));
        assert!(b.get() > a.get());
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn register_writable_yields_paired_receiver() {
        let mut reg = StreamRegistry::new();
        let (id, mut rx) = reg.register_writable("application/octet-stream", 4);
        // Write into the sink via the state; the paired receiver should see it.
        let state = reg.get(id).expect("registered stream");
        let inner = state.lock_inner();
        match &inner.direction {
            StreamDirection::Writable { sink } => {
                sink.try_send(Ok(Bytes::from_static(b"hi"))).unwrap();
            }
            _ => panic!("expected writable direction"),
        }
        drop(inner);
        let got = rx.try_recv().expect("should receive");
        assert_eq!(got.unwrap(), Bytes::from_static(b"hi"));
    }

    #[test]
    fn is_readable_is_writable_classifies_direction() {
        let mut reg = StreamRegistry::new();
        let r = reg.register_readable("application/octet-stream", bytes_source(vec![]));
        let (w, _rx) = reg.register_writable("application/octet-stream", 1);
        assert!(reg.get(r).unwrap().is_readable());
        assert!(!reg.get(r).unwrap().is_writable());
        assert!(reg.get(w).unwrap().is_writable());
        assert!(!reg.get(w).unwrap().is_readable());
    }

    #[test]
    fn close_marks_closed_and_releases_backing() {
        let mut reg = StreamRegistry::new();
        let id = reg.register_readable(
            "application/octet-stream",
            bytes_source(vec![Bytes::from_static(b"abc")]),
        );
        assert!(!reg.get(id).unwrap().is_closed());
        reg.close(id);
        assert!(reg.get(id).unwrap().is_closed());
        // Direction is still Readable (with an empty source) rather than
        // removed, so callers see CLOSED rather than INVALID_HANDLE.
        assert!(reg.get(id).unwrap().is_readable());
    }

    #[test]
    fn drain_clears_every_stream_and_resets_counter() {
        let mut reg = StreamRegistry::new();
        let _a = reg.register_readable("application/octet-stream", bytes_source(vec![]));
        let _b = reg.register_readable("application/octet-stream", bytes_source(vec![]));
        assert_eq!(reg.len(), 2);
        reg.drain();
        assert!(reg.is_empty());
        // The next handle after a drain starts back at 1 because each
        // action invocation gets a fresh registry; no cross-invocation
        // handle reuse is ever visible to plugins.
        let c = reg.register_readable("application/octet-stream", bytes_source(vec![]));
        assert_eq!(c.get(), 1);
    }

    // --- Bytes semantics contract: zero-copy slicing ---

    #[test]
    fn bytes_slice_is_refcounted_not_copied() {
        // Design invariant: `Bytes::slice` must NOT allocate a new
        // backing store — pinned here by asserting the original and
        // every slice share the same underlying ptr.
        let original = Bytes::from(vec![0u8; 4096]);
        let first_half = original.slice(0..2048);
        let second_half = original.slice(2048..4096);
        // All three point at offsets within the same allocation.
        assert_eq!(first_half.as_ptr(), original.as_ptr());
        assert_eq!(
            second_half.as_ptr() as usize,
            original.as_ptr() as usize + 2048
        );
        // Dropping one does not invalidate the others.
        drop(original);
        assert_eq!(first_half.len(), 2048);
        assert_eq!(second_half.len(), 2048);
    }

    #[test]
    fn leftover_cursor_advances_without_copying() {
        // Contract for the "leftover" field: a 64KB source chunk
        // feeding 4KB reads should hand out 16 refcounted slices of
        // the same allocation, not copy the chunk 16 times.
        let backing = Bytes::from(vec![42u8; 65536]);
        let original_ptr = backing.as_ptr();

        let mut leftover: Option<Bytes> = Some(backing);
        let mut handed_out = Vec::new();
        while let Some(chunk) = leftover.take() {
            let n = 4096.min(chunk.len());
            let slice = chunk.slice(0..n);
            // Every slice points into the original allocation.
            assert_eq!(slice.as_ptr(), handed_out_start(original_ptr, &handed_out));
            handed_out.push(slice);
            if n < chunk.len() {
                leftover = Some(chunk.slice(n..));
            }
        }
        assert_eq!(handed_out.len(), 16);
        assert_eq!(handed_out.iter().map(|b| b.len()).sum::<usize>(), 65536);
    }

    /// Compute where the next slice's `as_ptr()` should land given
    /// the accumulated lengths we've already handed out.
    fn handed_out_start(base: *const u8, handed: &[Bytes]) -> *const u8 {
        let offset: usize = handed.iter().map(|b| b.len()).sum();
        // SAFETY: the pointer still lives within the backing allocation;
        // we're just computing an offset for the assertion. The allocation
        // outlives this test because at least one slice is still held.
        unsafe { base.add(offset) }
    }

    // --- Async read/write: the wasm-facing ABI surface ---
    //
    // These go through `read_async` / `write_async`, the path the host
    // imports use. `#[tokio::test]` gives each test its own
    // current-thread runtime.

    /// Helper: produce an `Arc<StreamState>` for a freshly-registered
    /// readable. Tests work directly against the per-stream state so
    /// they exercise the same code path the host imports use via
    /// `read_async_shared`.
    fn register_readable(reg: &mut StreamRegistry, chunks: Vec<Bytes>) -> Arc<StreamState> {
        let id = reg.register_readable("text/plain", bytes_source(chunks));
        reg.get(id).expect("just registered")
    }

    #[tokio::test]
    async fn read_async_chunks_across_multiple_reads() {
        let mut reg = StreamRegistry::new();
        let state = register_readable(&mut reg, vec![Bytes::from_static(b"hello world")]);

        // Ask for 5, then 5, then the rest, then EOF.
        let mut buf = [0u8; 5];
        assert_eq!(state.read_async(&mut buf).await, 5);
        assert_eq!(&buf, b"hello");
        assert_eq!(state.read_async(&mut buf).await, 5);
        assert_eq!(&buf, b" worl");
        // Only "d" remains; 1 byte returned.
        assert_eq!(state.read_async(&mut buf[..1]).await, 1);
        assert_eq!(buf[0], b'd');
        // Source exhausted → EOF.
        assert_eq!(state.read_async(&mut buf).await, STREAM_EOF);
    }

    #[tokio::test]
    async fn read_async_pulls_next_chunk_when_leftover_drained() {
        let mut reg = StreamRegistry::new();
        let state = register_readable(
            &mut reg,
            vec![Bytes::from_static(b"AAAA"), Bytes::from_static(b"BBBB")],
        );
        let mut buf = [0u8; 4];
        assert_eq!(state.read_async(&mut buf).await, 4);
        assert_eq!(&buf, b"AAAA");
        assert_eq!(state.read_async(&mut buf).await, 4);
        assert_eq!(&buf, b"BBBB");
        assert_eq!(state.read_async(&mut buf).await, STREAM_EOF);
    }

    #[tokio::test]
    async fn read_async_on_writable_returns_direction_mismatch() {
        let mut reg = StreamRegistry::new();
        let (id, _rx) = reg.register_writable("application/octet-stream", 1);
        let state = reg.get(id).unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(state.read_async(&mut buf).await, STREAM_DIRECTION_MISMATCH);
    }

    #[tokio::test]
    async fn read_async_shared_invalid_handle_returns_invalid_handle() {
        let arc: SharedStreamRegistry = Arc::new(Mutex::new(StreamRegistry::new()));
        let bogus = NonZeroU32::new(42).unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(
            read_async_shared(&arc, bogus, &mut buf).await,
            STREAM_INVALID_HANDLE
        );
    }

    #[tokio::test]
    async fn read_async_on_closed_stream_returns_closed() {
        let mut reg = StreamRegistry::new();
        let id = reg.register_readable(
            "application/octet-stream",
            bytes_source(vec![Bytes::from_static(b"x")]),
        );
        reg.close(id);
        let state = reg.get(id).unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(state.read_async(&mut buf).await, STREAM_CLOSED);
    }

    /// EOF sticks. An embedder may register any source, and a bare
    /// `Unfold` — used here on purpose, unfused — panics if polled
    /// after it finishes; a guest reading one time too many must get
    /// `STREAM_EOF` again, not a host panic.
    #[tokio::test]
    async fn read_past_eof_returns_eof_again_without_polling_the_source() {
        let mut reg = StreamRegistry::new();
        let source: ReadableSource = Box::pin(futures::stream::unfold(
            Some(Bytes::from_static(b"hi")),
            |state| async move { state.map(|chunk| (Ok(chunk), None)) },
        ));
        let id = reg.register_readable("application/octet-stream", source);
        let state = reg.streams.get(&id).unwrap().clone();
        let mut buf = [0u8; 8];
        assert_eq!(state.read_async(&mut buf).await, 2);
        assert_eq!(state.read_async(&mut buf).await, STREAM_EOF);
        assert_eq!(state.read_async(&mut buf).await, STREAM_EOF);
        assert_eq!(state.read_async(&mut buf).await, STREAM_EOF);
    }

    /// What a guest sees of a producer that fails: the error code once,
    /// then EOF, and EOF again — an error item does not end the source,
    /// so it is the following `None` that sticks.
    #[tokio::test]
    async fn read_reports_an_error_item_once_and_then_eof() {
        let mut reg = StreamRegistry::new();
        // An unfused `Unfold`, like the sibling test above, so the
        // reads past its end are load-bearing: without the sticky EOF
        // the fourth read would panic rather than return `STREAM_EOF`.
        let items = vec![
            Ok(Bytes::from_static(b"ab")),
            Err(std::io::Error::other("upstream fell over")),
        ];
        let source: ReadableSource = Box::pin(futures::stream::unfold(
            items.into_iter(),
            |mut items| async move { items.next().map(|item| (item, items)) },
        ));
        let id = reg.register_readable("application/octet-stream", source);
        let state = reg.streams.get(&id).unwrap().clone();
        let mut buf = [0u8; 8];
        assert_eq!(state.read_async(&mut buf).await, 2);
        assert_eq!(state.read_async(&mut buf).await, STREAM_IO_ERROR);
        assert_eq!(state.read_async(&mut buf).await, STREAM_EOF);
        assert_eq!(state.read_async(&mut buf).await, STREAM_EOF);
    }

    #[tokio::test]
    async fn write_async_sends_bytes_to_paired_receiver() {
        let mut reg = StreamRegistry::new();
        let (id, mut rx) = reg.register_writable("application/octet-stream", 4);
        let state = reg.get(id).unwrap();
        assert_eq!(state.write_async(b"hello", &never()).await, 5);
        let got = rx.try_recv().unwrap().unwrap();
        assert_eq!(got, Bytes::from_static(b"hello"));
    }

    #[tokio::test]
    async fn write_async_on_readable_returns_direction_mismatch() {
        let mut reg = StreamRegistry::new();
        let id = reg.register_readable("application/octet-stream", bytes_source(vec![]));
        let state = reg.get(id).unwrap();
        assert_eq!(
            state.write_async(b"nope", &never()).await,
            STREAM_DIRECTION_MISMATCH
        );
    }

    #[tokio::test]
    async fn write_async_after_receiver_dropped_returns_closed() {
        let mut reg = StreamRegistry::new();
        let (id, rx) = reg.register_writable("application/octet-stream", 1);
        drop(rx);
        let state = reg.get(id).unwrap();
        assert_eq!(state.write_async(b"late", &never()).await, STREAM_CLOSED);
    }

    /// A token that fires while a write is parked on a full channel
    /// releases the write: it returns `STREAM_CANCELLED`, and the
    /// chunk it was holding is not committed. The consumer is still
    /// there, so this is not `STREAM_CLOSED`.
    #[tokio::test]
    async fn parked_write_is_released_when_the_token_fires() {
        let mut reg = StreamRegistry::new();
        let (id, mut rx) = reg.register_writable("application/octet-stream", 1);
        let state = reg.get(id).unwrap();
        let cancel = CancellationToken::new();
        assert_eq!(state.write_async(b"fits", &cancel).await, 4);

        let firing = {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                cancel.cancel();
            })
        };
        assert_eq!(
            state.write_async(b"parked", &cancel).await,
            STREAM_CANCELLED
        );
        firing.await.unwrap();

        let queued = rx.try_recv().unwrap().unwrap();
        assert_eq!(queued, Bytes::from_static(b"fits"));
        assert!(
            rx.try_recv().is_err(),
            "the released chunk was not committed behind the consumer's back"
        );
    }

    /// A token that has already fired releases a would-be-parked write
    /// without waiting at all.
    #[tokio::test]
    async fn write_under_a_fired_token_does_not_park() {
        let mut reg = StreamRegistry::new();
        let (id, _rx) = reg.register_writable("application/octet-stream", 1);
        let state = reg.get(id).unwrap();
        let cancel = CancellationToken::new();
        assert_eq!(state.write_async(b"fits", &cancel).await, 4);
        cancel.cancel();
        assert_eq!(
            state.write_async(b"parked", &cancel).await,
            STREAM_CANCELLED
        );
    }

    /// The token releases a wait; it does not refuse data. A write the
    /// channel has room for is committed under a fired token, so a
    /// producer that noticed the cancel can still flush the chunk it
    /// holds before it stops.
    #[tokio::test]
    async fn write_that_fits_is_committed_under_a_fired_token() {
        let mut reg = StreamRegistry::new();
        let (id, mut rx) = reg.register_writable("application/octet-stream", 1);
        let state = reg.get(id).unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert_eq!(state.write_async(b"last", &cancel).await, 4);
        assert_eq!(rx.try_recv().unwrap().unwrap(), Bytes::from_static(b"last"));
    }

    /// A receiver that has gone away is `STREAM_CLOSED` even under a
    /// fired token: the consumer's departure is the more specific
    /// fact, and a guest finishing on `STREAM_CLOSED` stays correct.
    #[tokio::test]
    async fn write_to_a_departed_receiver_is_closed_even_under_a_fired_token() {
        let mut reg = StreamRegistry::new();
        let (id, rx) = reg.register_writable("application/octet-stream", 1);
        drop(rx);
        let state = reg.get(id).unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert_eq!(state.write_async(b"late", &cancel).await, STREAM_CLOSED);
    }

    /// The property the kernel's streaming-callee EOF contract relies
    /// on: a held sender keeps the receiver from EOF past the owner's
    /// close, and the channel stays usable until it is dropped.
    #[tokio::test]
    async fn held_writable_sender_outlives_close_and_delivers() {
        let mut reg = StreamRegistry::new();
        let (id, mut rx) = reg.register_writable("application/octet-stream", 4);
        let held = reg.writable_sender(id).expect("a writable has a sender");
        reg.close(id);
        assert!(reg.writable_sender(id).is_none(), "none after close");
        assert!(held.send(Err(std::io::Error::other("boom"))).await.is_ok());
        match rx.recv().await {
            Some(Err(e)) => assert_eq!(e.to_string(), "boom"),
            other => panic!("expected the error item, got: {other:?}"),
        }
        drop(held);
        assert!(
            rx.recv().await.is_none(),
            "EOF once the last sender is gone"
        );
    }

    #[test]
    fn close_handle_idempotent_and_rejects_invalid() {
        let mut reg = StreamRegistry::new();
        let id = reg.register_readable("application/octet-stream", bytes_source(vec![]));
        assert_eq!(reg.close_handle(id), 0);
        assert_eq!(reg.close_handle(id), 0); // double-close is fine
        let bogus = NonZeroU32::new(999).unwrap();
        assert_eq!(reg.close_handle(bogus), STREAM_INVALID_HANDLE);
    }

    // --- Streaming fan-out ---------------------------------------------

    /// Streaming fan-out: two branches drained concurrently see the same
    /// byte sequence. The forwarder task pulls chunks from the source
    /// one at a time and broadcasts to both bounded mpsc channels;
    /// receivers asynchronously drain in parallel via `tokio::spawn`.
    /// Exercises the function without the wasmtime / guest-runtime / Mutex layer
    /// that the runtime integration adds on top.
    #[tokio::test(flavor = "multi_thread")]
    async fn fan_out_streaming_two_branches_drain_concurrently() {
        use futures::StreamExt;
        let chunks: Vec<Bytes> = (0..32)
            .map(|i| Bytes::from(vec![i as u8 % 26 + b'a'; 64]))
            .collect();
        let expected: Vec<u8> = chunks.iter().flat_map(|b| b.iter().copied()).collect();

        let mut reg = StreamRegistry::new();
        let producer = reg.register_readable("application/octet-stream", bytes_source(chunks));
        let branches = reg.fan_out_readable_streaming(producer, 2, 4).unwrap();
        assert_eq!(branches.len(), 2);

        // Pull each branch's source out for concurrent draining.
        let (_ct_a, src_a) = reg.take_readable(branches[0]).unwrap();
        let (_ct_b, src_b) = reg.take_readable(branches[1]).unwrap();

        let drain = |mut src: ReadableSource| async move {
            let mut buf = Vec::new();
            while let Some(item) = src.next().await {
                buf.extend_from_slice(&item.unwrap());
            }
            // A taken branch is polled directly, past the read path's
            // guard: its fuse is what keeps one poll past the end from
            // panicking.
            assert!(src.next().await.is_none(), "fused: stays None past the end");
            buf
        };

        let (a, b) = tokio::join!(drain(src_a), drain(src_b));
        assert_eq!(a, expected);
        assert_eq!(b, expected);
    }

    /// Backpressure / order check: with a small per-branch capacity, a
    /// slow consumer paces the producer without losing or reordering
    /// chunks. The fast consumer drains in tight succession; the slow
    /// consumer sleeps between reads — the test passes iff both end up
    /// with the same byte sequence and the producer never drops a chunk.
    #[tokio::test(flavor = "multi_thread")]
    async fn fan_out_streaming_slow_consumer_paces_producer() {
        use futures::StreamExt;
        let chunks: Vec<Bytes> = (0..16).map(|i| Bytes::from(vec![i as u8; 32])).collect();
        let expected: Vec<u8> = chunks.iter().flat_map(|b| b.iter().copied()).collect();

        let mut reg = StreamRegistry::new();
        let producer = reg.register_readable("application/octet-stream", bytes_source(chunks));
        // Capacity 2 — small enough that the slow consumer immediately
        // backpressures the producer once it gets behind.
        let branches = reg.fan_out_readable_streaming(producer, 2, 2).unwrap();
        let (_ct_a, src_a) = reg.take_readable(branches[0]).unwrap();
        let (_ct_b, src_b) = reg.take_readable(branches[1]).unwrap();

        let fast = tokio::spawn(async move {
            let mut src = src_a;
            let mut buf = Vec::new();
            while let Some(item) = src.next().await {
                buf.extend_from_slice(&item.unwrap());
            }
            buf
        });
        let slow = tokio::spawn(async move {
            let mut src = src_b;
            let mut buf = Vec::new();
            while let Some(item) = src.next().await {
                buf.extend_from_slice(&item.unwrap());
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            buf
        });

        assert_eq!(fast.await.unwrap(), expected);
        assert_eq!(slow.await.unwrap(), expected);
    }

    /// Source error propagation: the upstream source faults midstream;
    /// every branch should observe the chunks that arrived before the
    /// fault followed by an `io::Error`.
    #[tokio::test(flavor = "multi_thread")]
    async fn fan_out_streaming_propagates_midstream_error() {
        use futures::StreamExt;
        let good_chunk = Bytes::from_static(b"ok-data");
        let source: ReadableSource = Box::pin(stream::iter(vec![
            Ok(good_chunk.clone()),
            Err(std::io::Error::other("oh no")),
        ]));

        let mut reg = StreamRegistry::new();
        let producer = reg.register_readable("text/plain", source);
        let branches = reg.fan_out_readable_streaming(producer, 2, 4).unwrap();
        let (_ct_a, src_a) = reg.take_readable(branches[0]).unwrap();
        let (_ct_b, src_b) = reg.take_readable(branches[1]).unwrap();

        let collect = |mut src: ReadableSource| async move {
            let mut chunks: Vec<Bytes> = Vec::new();
            let mut errored = false;
            while let Some(item) = src.next().await {
                match item {
                    Ok(c) => chunks.push(c),
                    Err(_) => {
                        errored = true;
                        break;
                    }
                }
            }
            (chunks, errored)
        };

        let (a, b) = tokio::join!(collect(src_a), collect(src_b));
        assert_eq!(a.0, vec![good_chunk.clone()]);
        assert!(a.1, "branch A must observe the upstream error");
        assert_eq!(b.0, vec![good_chunk]);
        assert!(b.1, "branch B must observe the upstream error");
    }
}
