use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll};
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tokio::time::{self, Sleep};

use crate::consensus::server::{
    ConsensusMessage, ConsensusRpcResponse, ExternalTx, PeerEndpoint,
};

pub const NODE_RETRY_LOG_INTERVAL: Duration = Duration::from_millis(70);
pub const NODE_CHANNEL_BUCKET_NS: u64 = 1_000_000_000;
pub const NODE_SELECT_BRANCHES: usize = 6;

#[derive(Debug)]
pub struct NodeRequestSender<Request, Response> {
    tx: mpsc::UnboundedSender<(Request, oneshot::Sender<Response>)>,
}

#[derive(Debug)]
pub struct NodeRequestReceiver<Request, Response> {
    rx: mpsc::UnboundedReceiver<(Request, oneshot::Sender<Response>)>,
}

impl<Request, Response> Clone for NodeRequestSender<Request, Response> {
    fn clone(&self) -> Self {
        Self { tx: self.tx.clone() }
    }
}

pub fn request_channel<Request, Response>() -> (
    NodeRequestSender<Request, Response>,
    NodeRequestReceiver<Request, Response>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    (NodeRequestSender { tx }, NodeRequestReceiver { rx })
}

impl<Request, Response> NodeRequestSender<Request, Response> {
    pub fn try_dispatch(
        &self,
        request: Request,
        reply_to: oneshot::Sender<Response>,
    ) -> Result<(), mpsc::error::SendError<(Request, oneshot::Sender<Response>)>> {
        self.tx.send((request, reply_to))
    }

    pub async fn request(&self, request: Request) -> Response {
        let (reply_to, reply_rx) = oneshot::channel();
        self.tx.send((request, reply_to)).unwrap();
        reply_rx.await.unwrap()
    }
}

impl<Request, Response> NodeRequestReceiver<Request, Response> {
    pub async fn recv(&mut self) -> (Request, oneshot::Sender<Response>) {
        self.rx.recv().await.unwrap()
    }

    pub fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<(Request, oneshot::Sender<Response>)>> {
        self.rx.poll_recv(cx)
    }
}

#[derive(Debug)]
pub struct NodeBoundedRequestSender<Request, Response> {
    tx: mpsc::Sender<(Request, oneshot::Sender<Response>)>,
}

#[derive(Debug)]
pub struct NodeBoundedRequestReceiver<Request, Response> {
    rx: mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
}

impl<Request, Response> Clone for NodeBoundedRequestSender<Request, Response> {
    fn clone(&self) -> Self {
        Self { tx: self.tx.clone() }
    }
}

pub fn bounded_request_channel<Request, Response>(
    capacity: usize,
) -> (
    NodeBoundedRequestSender<Request, Response>,
    NodeBoundedRequestReceiver<Request, Response>,
) {
    let (tx, rx) = mpsc::channel(capacity);
    (NodeBoundedRequestSender { tx }, NodeBoundedRequestReceiver { rx })
}

impl<Request, Response> NodeBoundedRequestSender<Request, Response> {
    pub async fn request(&self, request: Request) -> Response {
        let (reply_to, reply_rx) = oneshot::channel();
        self.tx.send((request, reply_to)).await.unwrap();
        reply_rx.await.unwrap()
    }
}

impl<Request, Response> NodeBoundedRequestReceiver<Request, Response> {
    pub async fn recv(&mut self) -> (Request, oneshot::Sender<Response>) {
        self.rx.recv().await.unwrap()
    }

    pub fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<(Request, oneshot::Sender<Response>)>> {
        self.rx.poll_recv(cx)
    }
}

pub fn respond<Response>(reply_to: oneshot::Sender<Response>, response: Response) {
    let _ = reply_to.send(response);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeRetryResponse<Response> {
    Done(Response),
    RetryAfter(Duration),
}

impl<Response> NodeRetryResponse<Response> {
    pub fn retry_after_nanos(nanos: u64) -> Self {
        Self::RetryAfter(Duration::from_nanos(nanos))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetryPollResult<Response> {
    Completed(Response),
    ChannelClosed,
}

#[derive(Clone, Debug, Default)]
pub struct DelayedRetry {
    next_retry_at: Option<Instant>,
}

impl DelayedRetry {
    pub fn arm(&mut self, delay: Duration) {
        self.next_retry_at = Some(Instant::now() + delay);
    }

    pub fn clear(&mut self) {
        self.next_retry_at = None;
    }

    pub async fn wait_if_armed(&mut self) {
        if let Some(deadline) = self.next_retry_at.take() {
            let now = Instant::now();
            if deadline > now {
                time::sleep(deadline.duration_since(now)).await;
            }
        }
    }
}

pub async fn delayed_unbounded_retry<Request, Response>(
    delay: &mut DelayedRetry,
    tx: &mpsc::UnboundedSender<Request>,
    request: Request,
    rx: &mut mpsc::UnboundedReceiver<NodeRetryResponse<Response>>,
) -> RetryPollResult<Response>
where
    Request: Clone,
{
    loop {
        delay.wait_if_armed().await;

        if tx.send(request.clone()).is_err() {
            return RetryPollResult::ChannelClosed;
        }

        match rx.recv().await {
            Some(NodeRetryResponse::Done(response)) => {
                delay.clear();
                return RetryPollResult::Completed(response);
            }
            Some(NodeRetryResponse::RetryAfter(backoff)) => delay.arm(backoff),
            None => return RetryPollResult::ChannelClosed,
        }
    }
}

pub async fn delayed_bounded_retry<Request, Response>(
    delay: &mut DelayedRetry,
    tx: &mpsc::Sender<Request>,
    request: Request,
    rx: &mut mpsc::Receiver<NodeRetryResponse<Response>>,
) -> RetryPollResult<Response>
where
    Request: Clone,
{
    loop {
        delay.wait_if_armed().await;

        if tx.send(request.clone()).await.is_err() {
            return RetryPollResult::ChannelClosed;
        }

        match rx.recv().await {
            Some(NodeRetryResponse::Done(response)) => {
                delay.clear();
                return RetryPollResult::Completed(response);
            }
            Some(NodeRetryResponse::RetryAfter(backoff)) => delay.arm(backoff),
            None => return RetryPollResult::ChannelClosed,
        }
    }
}

pub trait LockFreeNodeSender<Request> {
    fn enqueue_or_closed(&self, request: Request) -> Result<(), Request>;
}

pub async fn delayed_lockfree_retry<Request, Response, Sender>(
    delay: &mut DelayedRetry,
    tx: &Sender,
    request: Request,
    rx: &mut mpsc::UnboundedReceiver<NodeRetryResponse<Response>>,
) -> RetryPollResult<Response>
where
    Request: Clone,
    Sender: LockFreeNodeSender<Request>,
{
    loop {
        delay.wait_if_armed().await;

        if tx.enqueue_or_closed(request.clone()).is_err() {
            return RetryPollResult::ChannelClosed;
        }

        match rx.recv().await {
            Some(NodeRetryResponse::Done(response)) => {
                delay.clear();
                return RetryPollResult::Completed(response);
            }
            Some(NodeRetryResponse::RetryAfter(backoff)) => delay.arm(backoff),
            None => return RetryPollResult::ChannelClosed,
        }
    }
}

#[derive(Debug, Default)]
pub struct NodeChannelStats {
    pub first_poll_count: AtomicU64,
    pub backlog_drain_count: AtomicU64,
    pub non_empty_backlog_count: AtomicU64,
    pub current_bucket_count: AtomicU64,
    pub previous_bucket_count: AtomicU64,
    pub first_poll_latency_ns: AtomicU64,
    pub backlog_drained_units: AtomicU64,
    pub total_backlog_wait_ns: AtomicU64,
    current_bucket: AtomicU64,
}

impl NodeChannelStats {
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
        let bucket = saturated_ns(age) / NODE_CHANNEL_BUCKET_NS;
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

pub fn saturated_ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

#[derive(Clone, Debug)]
pub enum NodeChannelPayload {
    ExternalTx(ExternalTx),
    ConsensusMessage(ConsensusMessage),
    RefresherRequest(Vec<u8>),
    RpcResponse {
        peer: PeerEndpoint,
        response: ConsensusRpcResponse,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PayloadRoute {
    ExternalTxQueued { tx_hash: [u8; 32], seq_num: u64 },
    ConsensusMessageQueued,
    RefresherRequestQueued,
    RpcResponseQueued,
}

#[derive(Debug, Default)]
pub struct NodePayloadRouter {
    pub tx_hash_to_seq_num: BTreeMap<[u8; 32], u64>,
    pub external_txs: VecDeque<ExternalTx>,
    pub consensus_messages: VecDeque<ConsensusMessage>,
    pub refresher_requests: VecDeque<Vec<u8>>,
    pub rpc_responses: VecDeque<(PeerEndpoint, ConsensusRpcResponse)>,
    next_seq_num: u64,
}

impl NodePayloadRouter {
    pub fn route(&mut self, payload: NodeChannelPayload) -> PayloadRoute {
        match payload {
            NodeChannelPayload::ExternalTx(mut tx) => {
                let seq_num = self.assign_external_tx_seq_num(&mut tx);
                let tx_hash = tx.tx_hash;
                self.tx_hash_to_seq_num.insert(tx_hash, seq_num);
                self.external_txs.push_back(tx);
                PayloadRoute::ExternalTxQueued { tx_hash, seq_num }
            }
            NodeChannelPayload::ConsensusMessage(message) => {
                self.consensus_messages.push_back(message);
                PayloadRoute::ConsensusMessageQueued
            }
            NodeChannelPayload::RefresherRequest(bytes) => {
                self.refresher_requests.push_back(bytes);
                PayloadRoute::RefresherRequestQueued
            }
            NodeChannelPayload::RpcResponse { peer, response } => {
                self.rpc_responses.push_back((peer, response));
                PayloadRoute::RpcResponseQueued
            }
        }
    }

    fn assign_external_tx_seq_num(&mut self, tx: &mut ExternalTx) -> u64 {
        if tx.seq_num != 0 {
            self.next_seq_num = self.next_seq_num.max(tx.seq_num.saturating_add(1));
            return tx.seq_num;
        }

        let seq_num = self.next_seq_num;
        tx.seq_num = seq_num;
        self.next_seq_num = self.next_seq_num.saturating_add(1);
        seq_num
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectDispatch {
    Routed(PayloadRoute),
    RetryTimer,
    Cancelled,
    Closed,
}

pub struct NodeSelectDispatcher {
    pub router: NodePayloadRouter,
    pub retry_interval: Duration,
}

impl Default for NodeSelectDispatcher {
    fn default() -> Self {
        Self {
            router: NodePayloadRouter::default(),
            retry_interval: NODE_RETRY_LOG_INTERVAL,
        }
    }
}

impl NodeSelectDispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn route_payload(&mut self, payload: NodeChannelPayload) -> PayloadRoute {
        self.router.route(payload)
    }

    pub fn poll_select_dispatch<F>(
        &mut self,
        cx: &mut Context<'_>,
        start_branch: usize,
        payload_rx: &mut mpsc::UnboundedReceiver<NodeChannelPayload>,
        retry_sleep: Option<Pin<&mut Sleep>>,
        cancel: &AtomicBool,
        fallback: Pin<&mut F>,
    ) -> Poll<SelectDispatch>
    where
        F: Future<Output = Option<NodeChannelPayload>>,
    {
        let mut retry_sleep = retry_sleep;
        let mut fallback = fallback;

        for offset in 0..NODE_SELECT_BRANCHES {
            match (start_branch + offset) % NODE_SELECT_BRANCHES {
                0 => match payload_rx.poll_recv(cx) {
                    Poll::Ready(Some(payload)) => {
                        return Poll::Ready(SelectDispatch::Routed(self.route_payload(payload)));
                    }
                    Poll::Ready(None) => return Poll::Ready(SelectDispatch::Closed),
                    Poll::Pending => {}
                },
                1 => {
                    if let Poll::Ready(Some(payload)) = fallback.as_mut().poll(cx) {
                        return Poll::Ready(SelectDispatch::Routed(self.route_payload(payload)));
                    }
                }
                2 => {
                    if cancel.load(Ordering::Acquire) {
                        return Poll::Ready(SelectDispatch::Cancelled);
                    }
                }
                3 => {
                    if let Some(sleep) = retry_sleep.as_mut() {
                        if sleep.as_mut().poll(cx).is_ready() {
                            return Poll::Ready(SelectDispatch::RetryTimer);
                        }
                    }
                }
                4 | 5 => {}
                _ => unreachable!(),
            }
        }

        Poll::Pending
    }

    pub async fn dispatch_next_with_retry(
        &mut self,
        payload_rx: &mut mpsc::UnboundedReceiver<NodeChannelPayload>,
    ) -> Option<PayloadRoute> {
        let payload = payload_rx.recv().await?;
        let routed = self.route_payload(payload);
        if matches!(routed, PayloadRoute::ExternalTxQueued { .. }) {
            time::sleep(self.retry_interval).await;
        }
        Some(routed)
    }
}

pub async fn route_receiver_to_sender<T>(
    input: &mut mpsc::UnboundedReceiver<T>,
    output: &mpsc::UnboundedSender<T>,
    stats: &NodeChannelStats,
    created_at: Instant,
) -> bool {
    let first_poll = Instant::now();
    stats.record_first_poll(created_at, first_poll);

    match input.recv().await {
        Some(value) => {
            let waited = first_poll.elapsed();
            let sent = output.send(value).is_ok();
            stats.record_backlog(waited, u64::from(sent));
            sent
        }
        None => {
            stats.record_backlog(first_poll.elapsed(), 0);
            false
        }
    }
}
