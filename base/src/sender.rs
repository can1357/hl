use std::any::Any;
use std::fmt::Debug;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::thread;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

pub const CHANNEL_BLOCK_SLOTS: usize = 32;
pub const CHANNEL_READY_CLOSED_MASK: u64 = 1;
pub const CHANNEL_READY_INCREMENT: u64 = 2;
pub const CHANNEL_WAKE_FLAG: u64 = 2;
pub const CHANNEL_OVERFLOW_SENTINEL: u64 = u64::MAX - 1;
pub const DEFAULT_LATENCY_BUCKET_NS: u64 = 1_000_000;

const TOKIO_OK_ENDED: &str = "tokio_spawn_forever ended in an Ok variant";
const THREAD_OK_ENDED: &str = "crashing because thread_spawn_forever ended";
const TOKIO_END_PREFIX: &str = "crashing process because tokio_spawn_forever ended";
const TOKIO_ERROR_PREFIX: &str = "tokio_spawn_forever error ";
const THREAD_ERROR_PREFIX: &str = "crashing because thread_spawn_forever ended with error, err=";

pub type CrashSender = Sender<String>;
pub type CrashReceiver = mpsc::UnboundedReceiver<String>;

#[derive(Debug)]
pub struct Sender<T> {
    tx: mpsc::UnboundedSender<T>,
}

#[derive(Debug)]
pub struct Receiver<T> {
    rx: mpsc::UnboundedReceiver<T>,
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self { tx: self.tx.clone() }
    }
}

pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let (tx, rx) = mpsc::unbounded_channel();
    (Sender { tx }, Receiver { rx })
}

pub fn crash_channel() -> (CrashSender, CrashReceiver) {
    let (tx, rx) = mpsc::unbounded_channel();
    (Sender { tx }, rx)
}

impl<T> Sender<T> {
    pub fn from_unbounded(tx: mpsc::UnboundedSender<T>) -> Self {
        Self { tx }
    }

    pub fn into_inner(self) -> mpsc::UnboundedSender<T> {
        self.tx
    }

    pub fn raw(&self) -> &mpsc::UnboundedSender<T> {
        &self.tx
    }

    /// Enqueue a message and panic if the receiver has been closed.
    ///
    /// The recovered monomorphs reserve a slot by compare-exchanging the Tokio
    /// unbounded channel state from `state` to `state + 2`; a low closed bit
    /// drops the unsent payload and reaches the same `unwrap()` panic on
    /// `SendError<T>`. A successful reservation stores one payload into a
    /// 32-entry block, sets the ready bit, and wakes the stored receiver waker
    /// when the wake flag transitions from clear to set.
    #[inline]
    pub fn send(&self, message: T) {
        self.tx.send(message).unwrap();
    }

    #[inline]
    pub fn try_send(&self, message: T) -> Result<(), mpsc::error::SendError<T>> {
        self.tx.send(message)
    }

    #[inline]
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

impl<T> Receiver<T> {
    pub fn from_unbounded(rx: mpsc::UnboundedReceiver<T>) -> Self {
        Self { rx }
    }

    pub fn raw_mut(&mut self) -> &mut mpsc::UnboundedReceiver<T> {
        &mut self.rx
    }

    pub async fn recv(&mut self) -> T {
        self.rx.recv().await.unwrap()
    }

    pub async fn maybe_recv(&mut self) -> Option<T> {
        self.rx.recv().await
    }
}

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
    pub fn from_bounded(tx: mpsc::Sender<T>) -> Self {
        Self { tx }
    }

    pub fn raw(&self) -> &mpsc::Sender<T> {
        &self.tx
    }

    pub async fn send(&self, message: T) {
        self.tx.send(message).await.unwrap();
    }

    pub async fn try_send_async(&self, message: T) -> Result<(), mpsc::error::SendError<T>> {
        self.tx.send(message).await
    }

    pub fn try_send_now(&self, message: T) -> Result<(), mpsc::error::TrySendError<T>> {
        self.tx.try_send(message)
    }

    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

impl<T> BoundedReceiver<T> {
    pub fn raw_mut(&mut self) -> &mut mpsc::Receiver<T> {
        &mut self.rx
    }

    pub async fn recv(&mut self) -> T {
        self.rx.recv().await.unwrap()
    }

    pub async fn maybe_recv(&mut self) -> Option<T> {
        self.rx.recv().await
    }
}

pub type RequestEntry<Request, Response> = (Request, oneshot::Sender<Response>);
pub type RequestSender<Request, Response> = Sender<RequestEntry<Request, Response>>;
pub type RequestReceiver<Request, Response> = Receiver<RequestEntry<Request, Response>>;

pub fn request_channel<Request, Response>() -> (
    RequestSender<Request, Response>,
    RequestReceiver<Request, Response>,
) {
    channel()
}

impl<Request, Response> Sender<RequestEntry<Request, Response>> {
    /// Send a request through the unbounded dispatch channel and unwrap the
    /// oneshot response. Dropping the responder is fatal in the recovered code.
    pub async fn request(&self, request: Request) -> Response {
        let (reply_to, reply_rx) = oneshot::channel();
        self.send((request, reply_to));
        reply_rx.await.unwrap()
    }
}

pub fn respond<Response>(reply_to: oneshot::Sender<Response>, response: Response) {
    let _ = reply_to.send(response);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetryResponse<T> {
    Done(T),
    RetryAfter(Duration),
}

pub async fn send_then_recv_retrying<Request, Response>(
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

pub async fn bounded_send_then_recv_retrying<Request, Response>(
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

pub trait LatencySink: Send + Sync + 'static {
    fn record_latency(&self, elapsed: Duration);
}

impl<F> LatencySink for F
where
    F: Fn(Duration) + Send + Sync + 'static,
{
    fn record_latency(&self, elapsed: Duration) {
        self(elapsed);
    }
}

pub async fn send_timed<T, S>(tx: &Sender<T>, message: T, latency_sink: Option<&S>)
where
    S: LatencySink + ?Sized,
{
    let started_at = Instant::now();
    tx.send(message);
    if let Some(sink) = latency_sink {
        sink.record_latency(started_at.elapsed());
    }
}

pub async fn bounded_send_timed<T, S>(tx: &BoundedSender<T>, message: T, latency_sink: Option<&S>)
where
    S: LatencySink + ?Sized,
{
    let started_at = Instant::now();
    tx.send(message).await;
    if let Some(sink) = latency_sink {
        sink.record_latency(started_at.elapsed());
    }
}

/// Spawn a Tokio task that is expected never to return normally.
///
/// Recovered supervisor futures allocate a task-local latency/timer record,
/// await a Tokio `JoinHandle<Result<(), E>>`, then always send a `String` to the
/// crash channel once the watched task ends. `Err` payloads are formatted with
/// the `tokio_spawn_forever error ` prefix; an unexpected `Ok(())` becomes the
/// fixed `tokio_spawn_forever ended in an Ok variant` message. The final crash
/// report includes the caller-supplied task name.
pub fn tokio_spawn_forever<F, E>(name: impl Into<String>, future: F, crash_sender: CrashSender) -> JoinHandle<()>
where
    F: Future<Output = Result<(), E>> + Send + 'static,
    E: Debug + Send + 'static,
{
    let name = name.into();
    tokio::spawn(async move {
        let ending = match future.await {
            Ok(()) => TOKIO_OK_ENDED.to_owned(),
            Err(error) => format!("{TOKIO_ERROR_PREFIX}{error:?}"),
        };
        crash_sender.send(format!("{TOKIO_END_PREFIX}, name={name} err={ending}"));
    })
}

/// Monitor an existing Tokio join handle that should not finish.
pub fn tokio_join_handle_forever<E>(
    name: impl Into<String>,
    join_handle: JoinHandle<Result<(), E>>,
    crash_sender: CrashSender,
) -> JoinHandle<()>
where
    E: Debug + Send + 'static,
{
    let name = name.into();
    tokio::spawn(async move {
        let ending = match join_handle.await {
            Ok(Ok(())) => TOKIO_OK_ENDED.to_owned(),
            Ok(Err(error)) => format!("{TOKIO_ERROR_PREFIX}{error:?}"),
            Err(error) => format!("{TOKIO_ERROR_PREFIX}{error:?}"),
        };
        crash_sender.send(format!("{TOKIO_END_PREFIX}, name={name} err={ending}"));
    })
}

/// Spawn a blocking thread that is expected never to return normally.
///
/// The recovered thread supervisor sends either the returned `Err` formatted
/// with `crashing because thread_spawn_forever ended with error, err=` or the
/// fixed `crashing because thread_spawn_forever ended` message if the closure
/// returns `Ok(())`. Panics are caught and routed through the same crash sender.
pub fn thread_spawn_forever<F, E>(name: impl Into<String>, f: F, crash_sender: CrashSender) -> thread::JoinHandle<()>
where
    F: FnOnce() -> Result<(), E> + Send + 'static,
    E: Debug + Send + 'static,
{
    let name = name.into();
    thread::Builder::new()
        .name(name)
        .spawn(move || {
            let message = match panic::catch_unwind(AssertUnwindSafe(f)) {
                Ok(Ok(())) => THREAD_OK_ENDED.to_owned(),
                Ok(Err(error)) => format!("{THREAD_ERROR_PREFIX}{error:?}"),
                Err(payload) => format!("{THREAD_ERROR_PREFIX}{}", panic_payload_message(&payload)),
            };
            crash_sender.send(message);
        })
        .unwrap()
}

fn panic_payload_message(payload: &(dyn Any + Send)) -> &str {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        message
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.as_str()
    } else {
        "non-string panic payload"
    }
}
pub fn send_crash(sender: &CrashSender, message: impl Into<String>) {
    sender.send(message.into());
}

pub fn send_tokio_ok(sender: &CrashSender, name: &str) {
    sender.send(format!("{TOKIO_END_PREFIX}, name={name} err={TOKIO_OK_ENDED}"));
}

pub fn send_thread_ok(sender: &CrashSender) {
    sender.send(THREAD_OK_ENDED.to_owned());
}
