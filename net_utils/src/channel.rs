//! Recovered internal channels for
//! `/home/ubuntu/hl/code_Mainnet/net_utils/src/channel.rs`.
//!
//! Confidence: high for the public wrapper shape around Tokio unbounded MPSC and
//! oneshot request/response channels; medium for the select/fanout retry helpers;
//! medium-high for the 32-slot lock-free enqueue path because it is corroborated
//! by the prior queue routine and by network handler call sites.
//!
//! Seed EAs expanded:
//! - `0x47B05F0`, `0x47B12D0`, `0x47B1930`, `0x47B3B80`, `0x47B3F50`,
//!   `0x47B6F90`, `0x47B75E0`, `0x4B31030`, `0x4B3C560`: monomorphized
//!   `Receiver<T>::recv` futures; they poll Tokio `UnboundedReceiver::recv` and
//!   unwrap the `Option<T>` at `channel.rs:93:47`.
//! - `0x474BFA0`: request/response future; allocates a Tokio oneshot, enqueues
//!   `(request, reply_to)`, awaits the reply, and unwraps at `channel.rs:117:30`.
//! - `0x1FD5B30`, `0x1FD5EC0`: send -> recv -> optional retry-sleep async state
//!   machines over unbounded and bounded channels.
//! - `0x2017C80`, `0x20312D0`: fair select over seven channel/timer branches.
//! - `0x432E4D0`, `0x432F680`, `0x438CB90`, `0x4391840`, `0x4399360`: timed
//!   receiver/fanout branches with queue-latency counters.
//!
//! IDA tag plan attempted for this wave; the IDA worker rejected new work with a
//! full queue during this task, so these names/comments are recorded here for the
//! next open pass:
//! - `0x1FD5B30` -> `net_utils_channel__poll_unbounded_send_retry_response`
//! - `0x1FD5EC0` -> `net_utils_channel__poll_bounded_send_retry_response`
//! - `0x2017C80` -> `net_utils_channel__poll_fair_select7_dispatch`
//! - `0x20312D0` -> `net_utils_channel__poll_fair_select7_branch_body`
//! - `0x432E4D0` -> `net_utils_channel__poll_timed_stats_loop`
//! - `0x432F680` -> `net_utils_channel__poll_fanout_receiver`
//! - `0x438CB90` -> `net_utils_channel__poll_select_recv_large`
//! - `0x4391840` -> `net_utils_channel__poll_select_recv_with_retry`
//! - `0x4399360` -> `net_utils_channel__poll_critical_message_branch`
//! - `0x474BFA0` -> `net_utils_channel__request_sender_request`
//! - `0x47B05F0`, `0x47B12D0`, `0x47B1930`, `0x47B3B80`, `0x47B3F50`,
//!   `0x47B6F90`, `0x47B75E0`, `0x4B31030`, `0x4B3C560` ->
//!   `net_utils_channel__receiver_recv__mono_*`.
//!
//! [INFERENCE] Most original generic names are not preserved. The Rust below
//! names recovered roles while keeping the observed panic/closed-channel policy.

use core::cell::UnsafeCell;
use core::future::Future;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::array;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};

pub const LOCKFREE_RING_SLOTS: usize = 32;
pub const GOSSIP_RPC_REQUEST_BYTES: usize = 64;
pub const LOCKFREE_CLOSED_BIT: u64 = 1;
pub const LOCKFREE_STATE_INCREMENT: u64 = 2;
pub const LOCKFREE_STATE_OVERFLOW_SENTINEL: u64 = u64::MAX - 1;
pub const LOCKFREE_WAKE_FLAG: u64 = 2;
pub const SELECT_BRANCHES: usize = 7;
pub const QUEUE_LATENCY_BUCKET_NS: u64 = 1_000_000_000;
pub const SLOW_RECV_SLEEP_NS: u64 = 1_000_000_000;
pub const RETRY_LOG_INTERVAL_NS: u64 = 70_000_000;
pub const DEFAULT_RUNTIME_BACKOFF_NS: u64 = 2_000_000;

/// Sending half of the recovered unbounded channel wrapper.
#[derive(Debug)]
pub struct Sender<T> {
    tx: mpsc::UnboundedSender<T>,
}

/// Receiving half of the recovered unbounded channel wrapper.
#[derive(Debug)]
pub struct Receiver<T> {
    rx: mpsc::UnboundedReceiver<T>,
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self { tx: self.tx.clone() }
    }
}

/// Construct an unbounded internal channel.
///
/// The seed functions consistently use Tokio's unbounded MPSC channel. Closed
/// channels are treated as logic errors by `send`/`recv` rather than converted to
/// recoverable results.
pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let (tx, rx) = mpsc::unbounded_channel();
    (Sender { tx }, Receiver { rx })
}

impl<T> Sender<T> {
    /// Enqueue one message.
    ///
    /// Recovered behavior is `UnboundedSender::send(message).unwrap()`: a closed
    /// receiver panics at the callsite.
    pub fn send(&self, message: T) {
        self.tx.send(message).unwrap();
    }

    pub fn try_send(&self, message: T) -> Result<(), mpsc::error::SendError<T>> {
        self.tx.send(message)
    }

    /// Return the wrapped Tokio sender for structs that store raw channel halves.
    pub fn raw(&self) -> &mpsc::UnboundedSender<T> {
        &self.tx
    }
}

impl<T> Receiver<T> {
    /// Receive the next message, panicking if all senders are gone.
    ///
    /// The high seed futures all poll this pattern: await Tokio `recv`, unwrap
    /// the `Option<T>`, and resume the async state machine with the payload.
    pub async fn recv(&mut self) -> T {
        self.rx.recv().await.unwrap()
    }

    pub async fn maybe_recv(&mut self) -> Option<T> {
        self.rx.recv().await
    }

    /// Return the wrapped Tokio receiver for callers that need explicit polling.
    pub fn raw_mut(&mut self) -> &mut mpsc::UnboundedReceiver<T> {
        &mut self.rx
    }
}

/// Bounded channel wrapper used by the `0x1FD5EC0` retry/send state machine.
#[derive(Debug)]
pub struct BoundedSender<T> {
    tx: mpsc::Sender<T>,
}

#[derive(Debug)]
pub struct BoundedReceiver<T> {
    rx: mpsc::Receiver<T>,
}

impl<T> Clone for BoundedSender<T> {
    fn clone(&self) -> Self {
        Self { tx: self.tx.clone() }
    }
}

pub fn bounded_channel<T>(capacity: usize) -> (BoundedSender<T>, BoundedReceiver<T>) {
    let (tx, rx) = mpsc::channel(capacity);
    (BoundedSender { tx }, BoundedReceiver { rx })
}

impl<T> BoundedSender<T> {
    pub async fn send(&self, message: T) {
        self.tx.send(message).await.unwrap();
    }

    pub async fn try_send_async(&self, message: T) -> Result<(), mpsc::error::SendError<T>> {
        self.tx.send(message).await
    }
}

impl<T> BoundedReceiver<T> {
    pub async fn recv(&mut self) -> T {
        self.rx.recv().await.unwrap()
    }

    pub async fn maybe_recv(&mut self) -> Option<T> {
        self.rx.recv().await
    }
}

/// Queue entry carried by request/response dispatch channels.
pub type RequestEntry<Request, Response> = (Request, oneshot::Sender<Response>);

/// Sending half of an internal request/response channel.
pub type RequestSender<Request, Response> = Sender<RequestEntry<Request, Response>>;

/// Receiving half of an internal request/response channel.
pub type RequestReceiver<Request, Response> = Receiver<RequestEntry<Request, Response>>;

/// Construct an unbounded request/response channel.
pub fn request_channel<Request, Response>() -> (
    RequestSender<Request, Response>,
    RequestReceiver<Request, Response>,
) {
    channel()
}

impl<Request, Response> Sender<RequestEntry<Request, Response>> {
    /// Dispatch a request and wait for its response.
    ///
    /// Recovered logic:
    /// 1. Allocate a Tokio oneshot channel.
    /// 2. Enqueue `(request, response_sender)` on the unbounded request queue.
    /// 3. Await the oneshot receiver.
    /// 4. `unwrap()` the result; dropping the responder before sending is fatal.
    pub async fn request(&self, request: Request) -> Response {
        let (reply_to, reply_rx) = oneshot::channel();
        self.send((request, reply_to));
        reply_rx.await.unwrap()
    }
}

/// Complete a received request.
///
/// Tokio oneshot `send` fails only when the requester gave up. The recovered
/// responder-side logic does not propagate that error.
pub fn respond<Response>(reply_to: oneshot::Sender<Response>, response: Response) {
    let _ = reply_to.send(response);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetryResponse<T> {
    Done(T),
    RetryAfter(Duration),
}

impl<T> RetryResponse<T> {
    #[inline]
    pub fn retry_after_nanos(nanos: u64) -> Self {
        Self::RetryAfter(Duration::from_nanos(nanos))
    }
}

/// Recovered from the `0x1FD5B30` family: send a cloneable request, await a
/// response, and repeat after a response-selected sleep when the response tag is
/// non-zero.
pub async fn send_then_recv_retrying_response<Request, Response>(
    tx: &Sender<Request>,
    request: Request,
    rx: &mut Receiver<RetryResponse<Response>>,
) -> Option<Response>
where
    Request: Clone,
{
    loop {
        if tx.try_send(request.clone()).is_err() {
            return None;
        }

        match rx.maybe_recv().await? {
            RetryResponse::Done(response) => return Some(response),
            RetryResponse::RetryAfter(delay) => tokio::time::sleep(delay).await,
        }
    }
}

/// Bounded-send variant recovered from `0x1FD5EC0`.
pub async fn bounded_send_then_recv_retrying_response<Request, Response>(
    tx: &BoundedSender<Request>,
    request: Request,
    rx: &mut BoundedReceiver<RetryResponse<Response>>,
) -> Option<Response>
where
    Request: Clone,
{
    loop {
        if tx.try_send_async(request.clone()).await.is_err() {
            return None;
        }

        match rx.maybe_recv().await? {
            RetryResponse::Done(response) => return Some(response),
            RetryResponse::RetryAfter(delay) => tokio::time::sleep(delay).await,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchEvent<A, B, C> {
    Branch0(A),
    Branch1(B),
    Branch2(C),
    CancelA,
    CancelB,
    TimerA,
    TimerB,
}

/// Poll seven independent branches in a randomized/fair starting order.
///
/// The recovered state machine chooses a start branch, then probes all seven
/// branches modulo seven. The actual binary uses thread-local RNG; callers can
/// pass the already sampled start branch here, which also makes the behavior
/// deterministic for reconstruction review.
pub fn poll_fair_select7<A, B, C, F0, F1, F2, F5, F6>(
    cx: &mut Context<'_>,
    start_branch: usize,
    branch0: Pin<&mut F0>,
    branch1: Pin<&mut F1>,
    branch2: Pin<&mut F2>,
    cancel_a: &AtomicBool,
    cancel_b: &AtomicBool,
    timer_a: Pin<&mut F5>,
    timer_b: Pin<&mut F6>,
) -> Poll<DispatchEvent<A, B, C>>
where
    F0: Future<Output = Option<A>>,
    F1: Future<Output = Option<B>>,
    F2: Future<Output = Option<C>>,
    F5: Future<Output = ()>,
    F6: Future<Output = ()>,
{
    let mut branch0 = branch0;
    let mut branch1 = branch1;
    let mut branch2 = branch2;
    let mut timer_a = timer_a;
    let mut timer_b = timer_b;

    for offset in 0..SELECT_BRANCHES {
        match (start_branch + offset) % SELECT_BRANCHES {
            0 => {
                if let Poll::Ready(Some(value)) = branch0.as_mut().poll(cx) {
                    return Poll::Ready(DispatchEvent::Branch0(value));
                }
            }
            1 => {
                if let Poll::Ready(Some(value)) = branch1.as_mut().poll(cx) {
                    return Poll::Ready(DispatchEvent::Branch1(value));
                }
            }
            2 => {
                if let Poll::Ready(Some(value)) = branch2.as_mut().poll(cx) {
                    return Poll::Ready(DispatchEvent::Branch2(value));
                }
            }
            3 => {
                if cancel_a.load(Ordering::Acquire) {
                    return Poll::Ready(DispatchEvent::CancelA);
                }
            }
            4 => {
                if cancel_b.load(Ordering::Acquire) {
                    return Poll::Ready(DispatchEvent::CancelB);
                }
            }
            5 => {
                if timer_a.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(DispatchEvent::TimerA);
                }
            }
            6 => {
                if timer_b.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(DispatchEvent::TimerB);
                }
            }
            _ => unreachable!(),
        }
    }

    Poll::Pending
}

#[derive(Debug, Default)]
pub struct ChannelStats {
    /// Observed at recovered stats offset `+0x18`.
    pub first_poll_count: AtomicU64,
    /// Observed at recovered stats offset `+0x20`.
    pub backlog_drain_count: AtomicU64,
    /// Observed at recovered stats offset `+0x28`.
    pub non_empty_backlog_count: AtomicU64,
    /// Observed at offsets `+0x40/+0x78` as bucket counters.
    pub current_bucket_count: AtomicU64,
    /// Observed at offsets `+0x48/+0x80` as older bucket counters.
    pub previous_bucket_count: AtomicU64,
    /// Observed at recovered stats offset `+0x58`.
    pub first_poll_latency_ns: AtomicU64,
    /// Observed at recovered stats offset `+0x60`.
    pub backlog_drained_units: AtomicU64,
    /// Observed at recovered stats offset `+0x68`.
    pub total_backlog_wait_ns: AtomicU64,
    current_bucket: AtomicU64,
}

impl ChannelStats {
    pub fn record_first_poll(&self, created_at: Instant, now: Instant) {
        let age = now.saturating_duration_since(created_at);
        self.first_poll_count.fetch_add(1, Ordering::Relaxed);
        self.first_poll_latency_ns
            .fetch_add(saturated_ns(age), Ordering::Relaxed);
        self.record_bucket(age);
    }

    pub fn record_backlog(&self, waited: Duration, drained_units: u64) {
        self.backlog_drain_count.fetch_add(1, Ordering::Relaxed);
        if drained_units != 0 {
            self.non_empty_backlog_count.fetch_add(1, Ordering::Relaxed);
            self.backlog_drained_units.fetch_add(drained_units, Ordering::Relaxed);
        }
        self.total_backlog_wait_ns
            .fetch_add(saturated_ns(waited), Ordering::Relaxed);
    }

    fn record_bucket(&self, age: Duration) {
        let bucket = saturated_ns(age) / QUEUE_LATENCY_BUCKET_NS;
        let previous = self.current_bucket.load(Ordering::Relaxed);
        if previous != bucket
            && self
                .current_bucket
                .compare_exchange(previous, bucket, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            let current = self.current_bucket_count.swap(0, Ordering::AcqRel);
            self.previous_bucket_count.store(current, Ordering::Release);
        }
        self.current_bucket_count.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline]
pub fn saturated_ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

pub async fn timed_recv<T>(
    receiver: &mut Receiver<T>,
    stats: &ChannelStats,
    created_at: Instant,
) -> Option<T> {
    let first_poll = Instant::now();
    stats.record_first_poll(created_at, first_poll);
    let value = receiver.maybe_recv().await;
    stats.record_backlog(first_poll.elapsed(), u64::from(value.is_some()));
    value
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Routed<T> {
    Normal(T),
    Critical(T),
    Compact(T),
    Closed,
}

/// Recovered fanout behavior from `0x432F680`/`0x4399360`: receive routed
/// messages, clone critical traffic to a side channel, forward non-terminal
/// messages to the primary channel, and exit on the terminal variant.
pub async fn fanout_receiver<T>(
    input: &mut Receiver<Routed<T>>,
    primary: &Sender<T>,
    critical: &Sender<T>,
) where
    T: Clone,
{
    loop {
        match input.recv().await {
            Routed::Normal(message) | Routed::Compact(message) => primary.send(message),
            Routed::Critical(message) => {
                critical.send(message.clone());
                primary.send(message);
            }
            Routed::Closed => return,
        }
    }
}

pub async fn recv_with_retry_notification<T>(
    input: &mut Receiver<T>,
    retry_notify: &Sender<RetryResponse<()>>,
    default_backoff: Duration,
) -> Option<T> {
    match input.maybe_recv().await {
        Some(value) => Some(value),
        None => {
            let delay = if default_backoff.is_zero() {
                Duration::from_nanos(DEFAULT_RUNTIME_BACKOFF_NS)
            } else {
                default_backoff
            };
            let _ = retry_notify.try_send(RetryResponse::RetryAfter(delay));
            None
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum LockFreeSend<T> {
    /// Queue is closed/terminated; the caller should process the value directly.
    Direct(T),
    /// Value was copied into a ring slot and the receiver waker was notified.
    Queued,
}

struct RingSlot<T> {
    value: UnsafeCell<MaybeUninit<T>>,
}

impl<T> RingSlot<T> {
    fn new() -> Self {
        Self { value: UnsafeCell::new(MaybeUninit::uninit()) }
    }

    unsafe fn write(&self, value: T) {
        unsafe { (*self.value.get()).write(value) };
    }

    unsafe fn read(&self) -> T {
        unsafe { (*self.value.get()).assume_init_read() }
    }
}

unsafe impl<T: Send> Send for RingSlot<T> {}
unsafe impl<T: Send> Sync for RingSlot<T> {}

#[derive(Default)]
struct WakerCell {
    state: AtomicU64,
    waker: Mutex<Option<Waker>>,
}

impl WakerCell {
    fn register(&self, waker: &Waker) {
        let mut guard = self.waker.lock();
        match guard.as_ref() {
            Some(old) if old.will_wake(waker) => {}
            _ => *guard = Some(waker.clone()),
        }
        self.state.store(0, Ordering::Release);
    }

    fn wake(&self) {
        let previous = self.state.fetch_or(LOCKFREE_WAKE_FLAG, Ordering::AcqRel);
        if previous == 0 {
            if let Some(waker) = self.waker.lock().take() {
                self.state.fetch_and(!LOCKFREE_WAKE_FLAG, Ordering::AcqRel);
                waker.wake();
            }
        }
    }
}

/// Best-fit reconstruction of the lock-free queue helper used by gossip RPC
/// request dispatch.
///
/// Layout evidence from the enqueue routine:
/// - `+0x88`: producer slot counter, atomically incremented.
/// - `+0x100/+0x108/+0x110`: stored task waker and wake flag.
/// - `+0x1C0`: state word; bit 0 means closed, even values count activity.
/// - ring slots are masked by `0x1f`, and gossip request slots are 64 bytes.
pub struct LockFreeQueue<T> {
    slots: [RingSlot<T>; LOCKFREE_RING_SLOTS],
    ready_bitmap: AtomicU32,
    enqueue_index: AtomicU64,
    state: AtomicU64,
    waker: WakerCell,
}

impl<T> LockFreeQueue<T> {
    pub fn new() -> Self {
        Self {
            slots: array::from_fn(|_| RingSlot::new()),
            ready_bitmap: AtomicU32::new(0),
            enqueue_index: AtomicU64::new(0),
            state: AtomicU64::new(0),
            waker: WakerCell::default(),
        }
    }

    pub fn close(&self) {
        self.state.fetch_or(LOCKFREE_CLOSED_BIT, Ordering::AcqRel);
        self.waker.wake();
    }

    pub fn is_closed(&self) -> bool {
        self.state.load(Ordering::Acquire) & LOCKFREE_CLOSED_BIT != 0
    }

    /// Enqueue one item or return it for direct processing when the state word is
    /// already closed. This mirrors the recovered return tags: direct path tag 0,
    /// queued path tag 2.
    pub fn send(&self, value: T) -> LockFreeSend<T> {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if state & LOCKFREE_CLOSED_BIT != 0 {
                return LockFreeSend::Direct(value);
            }
            if state == LOCKFREE_STATE_OVERFLOW_SENTINEL {
                panic!("lock-free channel state overflow");
            }

            match self.state.compare_exchange_weak(
                state,
                state.wrapping_add(LOCKFREE_STATE_INCREMENT),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => state = observed,
            }
        }

        let sequence = self.enqueue_index.fetch_add(1, Ordering::AcqRel);
        let slot_index = (sequence as usize) & (LOCKFREE_RING_SLOTS - 1);
        unsafe { self.slots[slot_index].write(value) };
        self.ready_bitmap
            .fetch_or(1_u32 << slot_index, Ordering::Release);
        self.waker.wake();
        LockFreeSend::Queued
    }

    pub fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        loop {
            let ready = self.ready_bitmap.load(Ordering::Acquire);
            if ready != 0 {
                let slot_index = ready.trailing_zeros() as usize;
                let bit = 1_u32 << slot_index;
                if self
                    .ready_bitmap
                    .compare_exchange_weak(ready, ready & !bit, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    self.state.fetch_sub(LOCKFREE_STATE_INCREMENT, Ordering::AcqRel);
                    let value = unsafe { self.slots[slot_index].read() };
                    return Poll::Ready(Some(value));
                }
                continue;
            }

            if self.is_closed() {
                return Poll::Ready(None);
            }

            self.waker.register(cx.waker());
            if self.ready_bitmap.load(Ordering::Acquire) == 0 && !self.is_closed() {
                return Poll::Pending;
            }
        }
    }
}

impl<T> Default for LockFreeQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for LockFreeQueue<T> {
    fn drop(&mut self) {
        let mut ready = self.ready_bitmap.load(Ordering::Acquire);
        while ready != 0 {
            let slot_index = ready.trailing_zeros() as usize;
            let bit = 1_u32 << slot_index;
            ready &= !bit;
            unsafe { drop(self.slots[slot_index].read()) };
        }
    }
}

pub type GossipRpcRequestBytes = [u8; GOSSIP_RPC_REQUEST_BYTES];
pub type GossipRpcRequestQueue = LockFreeQueue<GossipRpcRequestBytes>;

pub fn send_gossip_rpc_request_bytes(
    queue: &GossipRpcRequestQueue,
    request: GossipRpcRequestBytes,
) -> LockFreeSend<GossipRpcRequestBytes> {
    queue.send(request)
}
