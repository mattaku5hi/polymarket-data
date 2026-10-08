//! Read-only market-wide trade activity WebSocket adapter.
//!
//! The public activity stream can contain protocol chatter and malformed vendor
//! rows. Empty or non-JSON frames are ignored as expected chatter. A JSON
//! message identifying itself as an activity/trades event but lacking a usable
//! trade payload is dropped and counted in [`PolymarketTradeFirehose`]'s
//! malformed-row counter. It also signals incomplete coverage so a scanner
//! cannot mistake subsequent valid trades for a complete history.

use std::{
    collections::{HashSet, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::{SinkExt, StreamExt};
use rust_decimal::Decimal;
use serde_json::{Value, json};
use tokio::sync::{Barrier, Mutex, mpsc, watch};
use tokio_util::sync::CancellationToken;

/// Production endpoint for Polymarket's unauthenticated live activity stream.
pub const TRADE_FIREHOSE_WEBSOCKET_URL: &str = "wss://ws-live-data.polymarket.com";
const WEBSOCKET_RECONNECT_BASE_DELAY: Duration = Duration::from_secs(1);
const WEBSOCKET_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(60);
const WEBSOCKET_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TRADE_CHANNEL_CAPACITY: usize = 1_024;
const RTDS_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
// A healthy WebSocket pong is not evidence that the market-wide trade feed
// is still delivering. A quiet interval is a coverage gap, not a reconnect.
const RTDS_READ_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const WEBSOCKET_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const DEDUP_WINDOW_SIZE: usize = 3_000;
const DUAL_MATCH_TIMEOUT: Duration = Duration::from_secs(30);
const DUAL_MATCH_MAX_PENDING: usize = 1_024;

/// One activity/trades payload from Polymarket's market-wide WebSocket stream.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FirehoseTrade {
    pub proxy_wallet: String,
    pub condition_id: String,
    pub token_id: String,
    pub side: String,
    pub price: Decimal,
    pub size: Decimal,
    pub slug: String,
    pub event_slug: String,
    pub outcome: String,
    pub timestamp: DateTime<Utc>,
    pub transaction_hash: String,
}

/// Original vendor payload is kept until missing market fields are resolved.
/// An incomplete row is never equivalent to a qualified source trade.
#[derive(Clone, Debug, PartialEq)]
pub enum FirehoseObservation {
    Trade(FirehoseTrade),
    MissingMarket {
        raw: Value,
        candidate: FirehoseTrade,
    },
}

impl From<FirehoseTrade> for FirehoseObservation {
    fn from(trade: FirehoseTrade) -> Self {
        Self::Trade(trade)
    }
}

/// Why a purported activity/trades payload could not become a [`FirehoseTrade`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FirehoseTradeParseError {
    #[error("activity/trades message has no object payload")]
    MissingPayload,
    #[error("required firehose trade field `{field}` is missing, blank, or of the wrong type")]
    InvalidField { field: &'static str },
    #[error("firehose trade field `timestamp` is not a valid epoch-seconds integer")]
    InvalidTimestamp,
}

/// Single-consumer, read-only stream of market-wide Polymarket trades.
#[async_trait]
pub trait TradeFirehose: Send + Sync {
    /// Awaits the next valid trade. Transient socket failures reconnect internally.
    async fn next_trade(&self) -> FirehoseTrade;
}

/// Public activity/trades subscriber. It has no credential or order capability.
pub struct PolymarketTradeFirehose {
    trades: Mutex<mpsc::Receiver<FirehoseObservation>>,
    seen_fills: Mutex<RollingTradeDedup>,
    malformed_rows: Arc<AtomicU64>,
    ambiguous_duplicates: AtomicU64,
    unpaired_observations: Arc<AtomicU64>,
    disruption_sender: watch::Sender<u64>,
    disruptions: watch::Receiver<u64>,
    cancel: CancellationToken,
}

impl Default for PolymarketTradeFirehose {
    fn default() -> Self {
        Self::new()
    }
}

impl PolymarketTradeFirehose {
    /// Connect to the production market-wide activity stream.
    #[must_use]
    pub fn new() -> Self {
        Self::with_websocket_urls(TRADE_FIREHOSE_WEBSOCKET_URL, TRADE_FIREHOSE_WEBSOCKET_URL)
    }

    /// Compare two raw streams *before* deduplication. No observation reaches
    /// the scanner until both sockets report an equal payload. An unpaired
    /// observation or connection failure is an unrecoverable coverage gap.
    #[must_use]
    pub fn with_websocket_urls(first: impl Into<String>, second: impl Into<String>) -> Self {
        let (output, receiver) = mpsc::channel(TRADE_CHANNEL_CAPACITY);
        let (first_sender, first_receiver) = mpsc::channel(TRADE_CHANNEL_CAPACITY);
        let (second_sender, second_receiver) = mpsc::channel(TRADE_CHANNEL_CAPACITY);
        let malformed_rows = Arc::new(AtomicU64::new(0));
        let cancel = CancellationToken::new();
        let (disruption_sender, disruptions) = watch::channel(0_u64);
        let barrier = Arc::new(Barrier::new(2));
        let unpaired_observations = Arc::new(AtomicU64::new(0));
        for (url, sender) in [(first.into(), first_sender), (second.into(), second_sender)] {
            tokio::spawn(run_trade_socket_reporting(
                url,
                sender,
                malformed_rows.clone(),
                disruption_sender.clone(),
                cancel.clone(),
                RTDS_READ_IDLE_TIMEOUT,
                Some(barrier.clone()),
            ));
        }
        tokio::spawn(compare_trade_sockets(
            first_receiver,
            second_receiver,
            output,
            DualCoverageSignal {
                gap: disruption_sender.clone(),
                unpaired: unpaired_observations.clone(),
            },
            disruptions.clone(),
            cancel.clone(),
            DUAL_MATCH_TIMEOUT,
        ));
        Self {
            trades: Mutex::new(receiver),
            seen_fills: Mutex::new(RollingTradeDedup::new()),
            malformed_rows,
            ambiguous_duplicates: AtomicU64::new(0),
            unpaired_observations,
            disruption_sender,
            disruptions,
            cancel,
        }
    }

    /// Single-socket local-test seam only. Production scanner uses two sockets.
    #[must_use]
    pub fn with_websocket_url(websocket_url: impl Into<String>) -> Self {
        let (sender, receiver) = mpsc::channel(TRADE_CHANNEL_CAPACITY);
        let malformed_rows = Arc::new(AtomicU64::new(0));
        let cancel = CancellationToken::new();
        let (disruption_sender, disruptions) = watch::channel(0_u64);
        tokio::spawn(run_trade_socket_reporting(
            websocket_url.into(),
            sender,
            malformed_rows.clone(),
            disruption_sender.clone(),
            cancel.clone(),
            RTDS_READ_IDLE_TIMEOUT,
            None,
        ));
        Self {
            trades: Mutex::new(receiver),
            seen_fills: Mutex::new(RollingTradeDedup::new()),
            malformed_rows,
            ambiguous_duplicates: AtomicU64::new(0),
            unpaired_observations: Arc::new(AtomicU64::new(0)),
            disruption_sender,
            disruptions,
            cancel,
        }
    }

    /// Returns the next observation in socket order. Partial rows retain the
    /// original payload and must be admitted durably before Gamma lookup.
    pub async fn next_observation(&self) -> FirehoseObservation {
        loop {
            let event = self.trades.lock().await.recv().await;
            let Some(event) = event else {
                // The comparator closes output only after signaling a coverage
                // disruption (or cancellation). Let the caller's disruption
                // watcher win rather than panicking inside scanner intake.
                return std::future::pending().await;
            };
            if let FirehoseObservation::Trade(ref trade) = event {
                if !self.seen_fills.lock().await.insert_if_new(trade) {
                    // A redelivery and a distinct equal-tuple fill are
                    // indistinguishable. Skipping it is not coverage evidence.
                    self.ambiguous_duplicates.fetch_add(1, Ordering::Relaxed);
                    self.disruption_sender
                        .send_modify(|n| *n = n.saturating_add(1));
                    continue;
                }
            }
            return event;
        }
    }

    /// Number of invalid activity/trades payloads skipped since construction.
    #[must_use]
    pub fn malformed_row_count(&self) -> u64 {
        self.malformed_rows.load(Ordering::Relaxed)
    }

    /// Number of detected comparison deadlines or bounded-buffer overflows.
    /// This is not the number of missing fills; the entire interval is unknown.
    #[must_use]
    pub fn unpaired_observation_count(&self) -> u64 {
        self.unpaired_observations.load(Ordering::Relaxed)
    }

    /// Count of equal-fingerprint RTDS observations that cannot be classified
    /// as redelivery versus distinct fills; the scanner must open a gap.
    #[must_use]
    pub fn ambiguous_duplicate_count(&self) -> u64 {
        self.ambiguous_duplicates.load(Ordering::Relaxed)
    }

    /// Every socket interruption, ambiguous duplicate or unparseable activity/trades row may
    /// conceal a fill. Subscribers must not infer complete coverage.
    #[must_use]
    pub fn subscribe_disruptions(&self) -> watch::Receiver<u64> {
        self.disruptions.clone()
    }
}

impl Drop for PolymarketTradeFirehose {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[async_trait]
impl TradeFirehose for PolymarketTradeFirehose {
    async fn next_trade(&self) -> FirehoseTrade {
        loop {
            match self.next_observation().await {
                FirehoseObservation::Trade(trade) => return trade,
                FirehoseObservation::MissingMarket { .. } => {
                    // Legacy trade-only consumers have no durable raw admission;
                    // skipping this row must therefore invalidate coverage.
                    self.malformed_rows.fetch_add(1, Ordering::Relaxed);
                    self.disruption_sender
                        .send_modify(|n| *n = n.saturating_add(1));
                }
            }
        }
    }
}

struct PendingPrimary {
    key: String,
    observation: FirehoseObservation,
    received_at: tokio::time::Instant,
    matched: bool,
}

struct PendingSecondary {
    key: String,
    received_at: tokio::time::Instant,
}

#[derive(Default)]
struct DualTradeMatcher {
    primary: VecDeque<PendingPrimary>,
    secondary: VecDeque<PendingSecondary>,
}

impl DualTradeMatcher {
    fn key(observation: &FirehoseObservation) -> String {
        // A normalized trade or immutable raw partial payload must match
        // exactly. Different metadata is a discrepancy, never a valid replay.
        match observation {
            FirehoseObservation::Trade(trade) => format!(
                "trade:{}",
                serde_json::to_string(trade).expect("firehose trade serializes")
            ),
            FirehoseObservation::MissingMarket { raw, .. } => format!(
                "vendor:{}",
                serde_json::to_string(raw).expect("vendor payload serializes")
            ),
        }
    }

    fn primary(
        &mut self,
        observation: FirehoseObservation,
        now: tokio::time::Instant,
    ) -> Vec<FirehoseObservation> {
        let key = Self::key(&observation);
        let matched = self
            .secondary
            .iter()
            .position(|row| row.key == key)
            .and_then(|position| self.secondary.remove(position))
            .is_some();
        self.primary.push_back(PendingPrimary {
            key,
            observation,
            received_at: now,
            matched,
        });
        self.drain_matched()
    }

    fn secondary(
        &mut self,
        observation: FirehoseObservation,
        now: tokio::time::Instant,
    ) -> Vec<FirehoseObservation> {
        let key = Self::key(&observation);
        if let Some(row) = self
            .primary
            .iter_mut()
            .find(|row| !row.matched && row.key == key)
        {
            row.matched = true;
        } else {
            self.secondary.push_back(PendingSecondary {
                key,
                received_at: now,
            });
        }
        self.drain_matched()
    }

    fn drain_matched(&mut self) -> Vec<FirehoseObservation> {
        // Do not mark the scanner ready while the second socket has an
        // unmatched earlier row (or the first has any known unpaired row).
        // A matched later row cannot certify a complete prefix of both feeds.
        if !self.secondary.is_empty() || self.primary.iter().any(|row| !row.matched) {
            return Vec::new();
        }
        let mut ready = Vec::new();
        while self.primary.front().is_some_and(|row| row.matched) {
            ready.push(self.primary.pop_front().expect("matched front").observation);
        }
        ready
    }

    fn unhealthy(&self, now: tokio::time::Instant, match_timeout: Duration) -> bool {
        self.primary.len() + self.secondary.len() > DUAL_MATCH_MAX_PENDING
            || self
                .primary
                .front()
                .is_some_and(|row| now.duration_since(row.received_at) >= match_timeout)
            || self
                .secondary
                .front()
                .is_some_and(|row| now.duration_since(row.received_at) >= match_timeout)
    }
}

struct DualCoverageSignal {
    gap: watch::Sender<u64>,
    unpaired: Arc<AtomicU64>,
}

async fn compare_trade_sockets(
    mut first: mpsc::Receiver<FirehoseObservation>,
    mut second: mpsc::Receiver<FirehoseObservation>,
    output: mpsc::Sender<FirehoseObservation>,
    signal: DualCoverageSignal,
    mut disruptions: watch::Receiver<u64>,
    cancel: CancellationToken,
    match_timeout: Duration,
) {
    let mut matcher = DualTradeMatcher::default();
    let mut tick = tokio::time::interval(Duration::from_secs(1).min(match_timeout / 2));
    loop {
        let ready = tokio::select! {
            _ = cancel.cancelled() => return,
            result = disruptions.changed() => {
                if result.is_err() || *disruptions.borrow() > 0 { return; }
                continue;
            },
            _ = tick.tick() => Vec::new(),
            event = first.recv() => match event {
                Some(event) => matcher.primary(event, tokio::time::Instant::now()),
                None => { signal.gap.send_modify(|n| *n = n.saturating_add(1)); return; }
            },
            event = second.recv() => match event {
                Some(event) => matcher.secondary(event, tokio::time::Instant::now()),
                None => { signal.gap.send_modify(|n| *n = n.saturating_add(1)); return; }
            },
        };
        if matcher.unhealthy(tokio::time::Instant::now(), match_timeout) {
            signal.unpaired.fetch_add(1, Ordering::Relaxed);
            signal.gap.send_modify(|n| *n = n.saturating_add(1));
            return;
        }
        for observation in ready {
            let sent = tokio::select! {
                biased;
                _ = cancel.cancelled() => return,
                _ = disruptions.changed() => return,
                result = tokio::time::timeout(match_timeout, output.send(observation)) => result,
            };
            if !matches!(sent, Ok(Ok(()))) {
                signal.gap.send_modify(|n| *n = n.saturating_add(1));
                return;
            }
        }
    }
}

/// Bounded, insertion-ordered fill-fingerprint set for reconnect replays.
struct RollingTradeDedup {
    order: VecDeque<String>,
    fingerprints: HashSet<String>,
}

impl RollingTradeDedup {
    fn new() -> Self {
        Self {
            order: VecDeque::with_capacity(DEDUP_WINDOW_SIZE),
            fingerprints: HashSet::with_capacity(DEDUP_WINDOW_SIZE),
        }
    }

    /// Match the wallet scanner's event identity; transaction hash alone loses
    /// distinct fills in the same transaction. Identical tuples remain ambiguous.
    fn insert_if_new(&mut self, trade: &FirehoseTrade) -> bool {
        let fingerprint = format!(
            "firehose:{}:{}:{}:{}:{}:{}:{}",
            trade.proxy_wallet,
            trade.transaction_hash,
            trade.token_id,
            trade.side,
            trade.timestamp.timestamp(),
            trade.price,
            trade.size
        );
        if !self.fingerprints.insert(fingerprint.clone()) {
            return false;
        }
        self.order.push_back(fingerprint);
        if self.order.len() > DEDUP_WINDOW_SIZE {
            let oldest = self.order.pop_front().expect("window is non-empty");
            self.fingerprints.remove(&oldest);
        }
        true
    }
}

#[cfg(test)]
async fn run_trade_socket(
    websocket_url: String,
    sender: mpsc::Sender<FirehoseObservation>,
    malformed_rows: Arc<AtomicU64>,
    cancel: CancellationToken,
    read_idle_timeout: Duration,
) {
    let (disruptions, _observer) = watch::channel(0_u64);
    run_trade_socket_reporting(
        websocket_url,
        sender,
        malformed_rows,
        disruptions,
        cancel,
        read_idle_timeout,
        None,
    )
    .await;
}

async fn run_trade_socket_reporting(
    websocket_url: String,
    sender: mpsc::Sender<FirehoseObservation>,
    malformed_rows: Arc<AtomicU64>,
    disruption_sender: watch::Sender<u64>,
    cancel: CancellationToken,
    read_idle_timeout: Duration,
    subscription_barrier: Option<Arc<Barrier>>,
) {
    let mut failures = 0_u32;
    loop {
        let connected = tokio::select! {
            _ = cancel.cancelled() => return,
            result = tokio::time::timeout(WEBSOCKET_CONNECT_TIMEOUT, tokio_tungstenite::connect_async(&websocket_url)) => result,
        };
        let Ok(Ok((socket, _))) = connected else {
            disruption_sender.send_modify(|n| *n = n.saturating_add(1));
            failures = failures.saturating_add(1);
            if !sleep_reconnect(failures, &cancel).await {
                return;
            }
            continue;
        };
        let (mut writer, mut reader) = socket.split();
        if let Some(barrier) = &subscription_barrier {
            // Both TCP/WS handshakes complete before either subscription is
            // sent. This narrows, but cannot eliminate, startup feed skew.
            if !matches!(
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    result = tokio::time::timeout(WEBSOCKET_CONNECT_TIMEOUT, barrier.wait()) => Some(result),
                },
                Some(Ok(_))
            ) {
                disruption_sender.send_modify(|n| *n = n.saturating_add(1));
                failures = failures.saturating_add(1);
                if !sleep_reconnect(failures, &cancel).await {
                    return;
                }
                continue;
            }
        }
        if !matches!(
            tokio::time::timeout(WEBSOCKET_WRITE_TIMEOUT, send_subscription(&mut writer)).await,
            Ok(Ok(()))
        ) {
            disruption_sender.send_modify(|n| *n = n.saturating_add(1));
            failures = failures.saturating_add(1);
            if !sleep_reconnect(failures, &cancel).await {
                return;
            }
            continue;
        }
        failures = 0;
        let mut last_trade_activity = tokio::time::Instant::now();
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + RTDS_HEARTBEAT_INTERVAL,
            RTDS_HEARTBEAT_INTERVAL,
        );
        'socket: loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep_until(last_trade_activity + read_idle_timeout) => break,
                _ = heartbeat.tick() => {
                    if send_heartbeat(&mut writer).await.is_err() {
                        break;
                    }
                },
                message = reader.next() => match message {
                    Some(Ok(message)) => {
                        if message.is_close() {
                            break;
                        }
                        match parse_socket_message(message) {
                            Ok(Some(observation)) => {
                                last_trade_activity = tokio::time::Instant::now();
                                // A full consumer queue must not suppress RTDS PINGs or shutdown.
                                let delivery = sender.send(observation);
                                tokio::pin!(delivery);
                                loop {
                                    tokio::select! {
                                        _ = cancel.cancelled() => return,
                                        _ = heartbeat.tick() => {
                                            if send_heartbeat(&mut writer).await.is_err() {
                                                break 'socket;
                                            }
                                        },
                                        _ = tokio::time::sleep_until(last_trade_activity + read_idle_timeout) => break 'socket,
                                        result = &mut delivery => {
                                            if result.is_err() { return; }
                                            break;
                                        }
                                    }
                                }
                            }
                            Ok(None) => {}
                            Err(_) => {
                                malformed_rows.fetch_add(1, Ordering::Relaxed);
                                disruption_sender.send_modify(|n| *n = n.saturating_add(1));
                            }
                        }
                    }
                    Some(Err(_)) | None => break,
                },
            }
        }
        disruption_sender.send_modify(|n| *n = n.saturating_add(1));
        failures = failures.saturating_add(1);
        if !sleep_reconnect(failures, &cancel).await {
            return;
        }
    }
}

async fn send_heartbeat<S>(writer: &mut S) -> Result<(), ()>
where
    S: futures_util::Sink<
            tokio_tungstenite::tungstenite::Message,
            Error = tokio_tungstenite::tungstenite::Error,
        > + Unpin,
{
    tokio::time::timeout(
        WEBSOCKET_WRITE_TIMEOUT,
        // Match Polymarket/real-time-data-client's application heartbeat;
        // a WebSocket control Ping/Pong is not the same application message.
        writer.send(tokio_tungstenite::tungstenite::Message::Text("ping".into())),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())
}

async fn send_subscription<S>(writer: &mut S) -> Result<(), ()>
where
    S: futures_util::Sink<
            tokio_tungstenite::tungstenite::Message,
            Error = tokio_tungstenite::tungstenite::Error,
        > + Unpin,
{
    writer
        .send(tokio_tungstenite::tungstenite::Message::Text(
            json!({"action": "subscribe", "subscriptions": [{"topic": "activity", "type": "trades"}]})
                .to_string()
                .into(),
        ))
        .await
        .map_err(|_| ())
}

fn parse_socket_message(
    message: tokio_tungstenite::tungstenite::Message,
) -> Result<Option<FirehoseObservation>, FirehoseTradeParseError> {
    let Ok(text) = message.into_text() else {
        return Ok(None);
    };
    if text.trim().is_empty() {
        return Ok(None);
    }
    let Ok(event) = serde_json::from_str::<Value>(&text) else {
        return Ok(None);
    };
    if event.get("topic").and_then(Value::as_str) != Some("activity")
        || event.get("type").and_then(Value::as_str) != Some("trades")
    {
        return Ok(None);
    }
    let raw = event
        .get("payload")
        .ok_or(FirehoseTradeParseError::MissingPayload)?;
    match parse_trade_payload(raw) {
        Ok(trade) => Ok(Some(FirehoseObservation::Trade(trade))),
        Err(FirehoseTradeParseError::InvalidField { field }) if MARKET_FIELDS.contains(&field) => {
            let mut candidate = raw.clone();
            let object = candidate
                .as_object_mut()
                .ok_or(FirehoseTradeParseError::MissingPayload)?;
            for key in MARKET_FIELDS {
                match object.get(key) {
                    None | Some(Value::Null) => {}
                    Some(Value::String(value)) if value.trim().is_empty() => {}
                    Some(Value::String(_)) => continue,
                    _ => return Err(FirehoseTradeParseError::InvalidField { field: key }),
                }
                object.insert(key.to_owned(), Value::String("__unresolved__".to_owned()));
            }
            let candidate = parse_trade_payload(&candidate)?;
            Ok(Some(FirehoseObservation::MissingMarket {
                raw: raw.clone(),
                candidate,
            }))
        }
        Err(error) => Err(error),
    }
}

const MARKET_FIELDS: [&str; 4] = ["conditionId", "slug", "eventSlug", "outcome"];

/// Parse the observed activity/trades envelope's nested `payload`.
pub fn parse_trade_payload(payload: &Value) -> Result<FirehoseTrade, FirehoseTradeParseError> {
    let object = payload
        .as_object()
        .ok_or(FirehoseTradeParseError::MissingPayload)?;
    let timestamp = object
        .get("timestamp")
        .ok_or(FirehoseTradeParseError::InvalidField { field: "timestamp" })?;
    let seconds = parse_epoch_seconds(timestamp)?;
    let timestamp =
        DateTime::from_timestamp(seconds, 0).ok_or(FirehoseTradeParseError::InvalidTimestamp)?;

    Ok(FirehoseTrade {
        proxy_wallet: required_string(object, "proxyWallet")?.to_ascii_lowercase(),
        condition_id: required_string(object, "conditionId")?.to_owned(),
        token_id: required_string(object, "asset")?.to_owned(),
        side: required_string(object, "side")?.to_owned(),
        price: decimal_field(object, "price")?,
        size: decimal_field(object, "size")?,
        slug: required_string(object, "slug")?.to_owned(),
        event_slug: required_string(object, "eventSlug")?.to_owned(),
        outcome: required_string(object, "outcome")?.to_owned(),
        timestamp,
        transaction_hash: required_string(object, "transactionHash")?.to_owned(),
    })
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, FirehoseTradeParseError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(FirehoseTradeParseError::InvalidField { field })
}

fn decimal_field(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<Decimal, FirehoseTradeParseError> {
    let raw = match object.get(field) {
        Some(Value::String(value)) if !value.trim().is_empty() => value,
        Some(Value::Number(value)) => {
            return value
                .to_string()
                .parse()
                .map_err(|_| FirehoseTradeParseError::InvalidField { field });
        }
        _ => return Err(FirehoseTradeParseError::InvalidField { field }),
    };
    raw.parse()
        .map_err(|_| FirehoseTradeParseError::InvalidField { field })
}

fn parse_epoch_seconds(value: &Value) -> Result<i64, FirehoseTradeParseError> {
    let seconds = match value {
        Value::Number(value) => value.as_i64(),
        Value::String(value) => value.parse().ok(),
        _ => None,
    };
    seconds.ok_or(FirehoseTradeParseError::InvalidTimestamp)
}

async fn sleep_reconnect(failures: u32, cancel: &CancellationToken) -> bool {
    let delay = WEBSOCKET_RECONNECT_BASE_DELAY
        .saturating_mul(2_u32.saturating_pow(failures.saturating_sub(1)))
        .min(WEBSOCKET_RECONNECT_MAX_DELAY);
    tokio::select! { _ = cancel.cancelled() => false, _ = tokio::time::sleep(delay) => true }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trade_message(price: Value) -> String {
        trade_message_with_hash(price, "0xtx")
    }

    fn trade_message_with_hash(price: Value, transaction_hash: &str) -> String {
        json!({
            "connection_id": "test", "timestamp": 1_700_000_000_123_i64,
            "topic": "activity", "type": "trades",
            "payload": {
                "asset": "123", "conditionId": "0xcondition", "eventSlug": "event",
                "outcome": "Yes", "outcomeIndex": 0, "price": price,
                "proxyWallet": "0xAbCd", "side": "BUY", "size": 12.5,
                "slug": "market", "timestamp": 1_700_000_000_i64,
                "title": "Market", "transactionHash": transaction_hash
            }
        })
        .to_string()
    }

    fn parsed_trade(transaction_hash: &str) -> FirehoseTrade {
        match parse_socket_message(tokio_tungstenite::tungstenite::Message::Text(
            trade_message_with_hash(json!(0.55), transaction_hash).into(),
        ))
        .expect("parse trade message")
        .expect("trade payload")
        {
            FirehoseObservation::Trade(trade) => trade,
            FirehoseObservation::MissingMarket { .. } => panic!("complete fixture"),
        }
    }

    #[tokio::test]
    #[ignore = "manual read-only dual RTDS smoke; needs internet"]
    async fn live_dual_rtds_emits_only_matched_observations() {
        let feed = PolymarketTradeFirehose::new();
        let gap = feed.subscribe_disruptions();
        for _ in 0..100 {
            tokio::time::timeout(Duration::from_secs(20), feed.next_observation())
                .await
                .expect("both RTDS sockets should deliver matching trades");
            assert_eq!(*gap.borrow(), 0, "live stream lost coverage");
        }
    }

    #[tokio::test]
    #[ignore = "manual five-minute read-only dual RTDS stability probe"]
    async fn live_dual_rtds_five_minute_stability() {
        let feed = PolymarketTradeFirehose::new();
        let mut gap = feed.subscribe_disruptions();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
        let mut matched = 0_usize;
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break,
                result = gap.changed() => {
                    result.expect("coverage watcher");
                    panic!("dual feed disrupted after {matched} matched observations");
                },
                _ = feed.next_observation() => matched += 1,
            }
        }
        assert!(matched > 1_000, "dual feed made insufficient progress");
    }

    #[test]
    fn dual_matcher_reorders_peers_but_never_emits_unpaired_or_conflicting_rows() {
        let now = tokio::time::Instant::now();
        let a = FirehoseObservation::Trade(parsed_trade("0xfirst"));
        let b = FirehoseObservation::Trade(parsed_trade("0xsecond"));
        let mut matcher = DualTradeMatcher::default();
        assert!(matcher.primary(a.clone(), now).is_empty());
        assert!(matcher.primary(b.clone(), now).is_empty());
        assert!(matcher.secondary(b.clone(), now).is_empty());
        assert_eq!(
            matcher.secondary(a.clone(), now),
            vec![a.clone(), b.clone()]
        );
        let mut matcher = DualTradeMatcher::default();
        assert!(matcher.secondary(b.clone(), now).is_empty());
        assert!(matcher.primary(a.clone(), now).is_empty());
        assert_eq!(
            matcher.secondary(a.clone(), now),
            Vec::<FirehoseObservation>::new()
        );
        assert_eq!(matcher.primary(b.clone(), now), vec![a.clone(), b.clone()]);
        assert!(!matcher.unhealthy(now, Duration::from_secs(30)));
        assert!(matcher.primary(a.clone(), now).is_empty());
        assert!(matcher.unhealthy(now + Duration::from_secs(30), Duration::from_secs(30)));

        let mut different = parsed_trade("0xfirst");
        different.condition_id = "different-market".to_owned();
        let mut matcher = DualTradeMatcher::default();
        assert!(matcher.primary(a, now).is_empty());
        assert!(
            matcher
                .secondary(FirehoseObservation::Trade(different), now)
                .is_empty()
        );
        assert!(matcher.unhealthy(now + Duration::from_secs(30), Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn unmatched_second_stream_opens_gap_without_emitting_an_observation() {
        let (first_tx, first_rx) = mpsc::channel(2);
        let (second_tx, second_rx) = mpsc::channel(2);
        let (output_tx, mut output_rx) = mpsc::channel(2);
        let (gap_tx, mut gap_rx) = watch::channel(0_u64);
        let cancel = CancellationToken::new();
        let unpaired = Arc::new(AtomicU64::new(0));
        let task = tokio::spawn(compare_trade_sockets(
            first_rx,
            second_rx,
            output_tx,
            DualCoverageSignal {
                gap: gap_tx.clone(),
                unpaired: unpaired.clone(),
            },
            gap_rx.clone(),
            cancel,
            Duration::from_millis(100),
        ));
        first_tx
            .send(FirehoseObservation::Trade(parsed_trade("0xmissing")))
            .await
            .unwrap();
        let _keep_second_open = second_tx;
        tokio::time::timeout(Duration::from_secs(2), gap_rx.changed())
            .await
            .expect("unpaired trade must interrupt coverage")
            .unwrap();
        assert!(*gap_rx.borrow() > 0);
        assert_eq!(unpaired.load(Ordering::Relaxed), 1);
        assert!(
            output_rx.try_recv().is_err(),
            "unpaired trade never reaches scanner"
        );
        task.await.unwrap();
    }

    fn firehose_for_receiver(
        receiver: mpsc::Receiver<FirehoseObservation>,
    ) -> PolymarketTradeFirehose {
        let (disruption_sender, disruptions) = watch::channel(0);
        PolymarketTradeFirehose {
            trades: Mutex::new(receiver),
            seen_fills: Mutex::new(RollingTradeDedup::new()),
            malformed_rows: Arc::new(AtomicU64::new(0)),
            ambiguous_duplicates: AtomicU64::new(0),
            unpaired_observations: Arc::new(AtomicU64::new(0)),
            disruption_sender,
            disruptions,
            cancel: CancellationToken::new(),
        }
    }

    async fn expect_subscription(
        socket: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    ) {
        let subscription = socket
            .next()
            .await
            .expect("subscription")
            .expect("message")
            .into_text()
            .expect("text");
        assert_eq!(
            serde_json::from_str::<Value>(&subscription).expect("JSON"),
            json!({"action": "subscribe", "subscriptions": [{"topic": "activity", "type": "trades"}]})
        );
    }

    #[tokio::test]
    async fn parses_well_formed_trade_and_normalizes_wallet() {
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let url = format!("ws://{}", listener.local_addr().expect("address"));
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("upgrade");
            expect_subscription(&mut socket).await;
            socket
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    trade_message(json!(0.55)).into(),
                ))
                .await
                .expect("trade");
        });
        let feed = PolymarketTradeFirehose::with_websocket_url(url);
        let trade = tokio::time::timeout(Duration::from_secs(3), feed.next_trade())
            .await
            .expect("trade before deadline");
        assert_eq!(trade.proxy_wallet, "0xabcd");
        assert_eq!(trade.price, Decimal::new(55, 2));
        assert_eq!(trade.size, Decimal::new(125, 1));
        assert_eq!(
            trade.timestamp,
            DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp")
        );
        assert_eq!(trade.transaction_hash, "0xtx");
    }

    #[tokio::test]
    async fn skips_malformed_trade_then_yields_the_next_valid_trade() {
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let url = format!("ws://{}", listener.local_addr().expect("address"));
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("upgrade");
            expect_subscription(&mut socket).await;
            socket
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    json!({"topic":"activity", "type":"trades", "payload":{"asset":"123"}})
                        .to_string()
                        .into(),
                ))
                .await
                .expect("bad trade");
            socket
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    trade_message(json!("0.55")).into(),
                ))
                .await
                .expect("good trade");
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let feed = PolymarketTradeFirehose::with_websocket_url(url);
        let coverage_failures = feed.subscribe_disruptions();
        let trade = tokio::time::timeout(Duration::from_secs(3), feed.next_trade())
            .await
            .expect("trade before deadline");
        assert_eq!(trade.price, Decimal::new(55, 2));
        assert_eq!(feed.malformed_row_count(), 1);
        assert!(
            *coverage_failures.borrow() > 0,
            "a skipped trade must signal incomplete scanner coverage"
        );
    }

    #[tokio::test]
    async fn missing_market_fields_keep_raw_vendor_payload_in_socket_order() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            expect_subscription(&mut socket).await;
            let mut envelope: Value = serde_json::from_str(&trade_message(json!(0.55))).unwrap();
            envelope["payload"]
                .as_object_mut()
                .unwrap()
                .remove("conditionId");
            envelope["payload"].as_object_mut().unwrap().remove("slug");
            socket
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    envelope.to_string().into(),
                ))
                .await
                .unwrap();
            socket
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    trade_message_with_hash(json!(0.55), "0xnext").into(),
                ))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(3)).await;
        });
        let feed = PolymarketTradeFirehose::with_websocket_url(url);
        let mut gap = feed.subscribe_disruptions();
        match feed.next_observation().await {
            FirehoseObservation::MissingMarket { raw, candidate } => {
                assert_eq!(raw.get("asset").and_then(Value::as_str), Some("123"));
                assert!(raw.get("conditionId").is_none());
                assert_eq!(candidate.transaction_hash, "0xtx");
            }
            _ => panic!("missing market must not silently disappear"),
        }
        assert_eq!(feed.next_trade().await.transaction_hash, "0xnext");
        assert_eq!(*gap.borrow_and_update(), 0);
        server.abort();
    }

    #[tokio::test]
    async fn sends_rtds_protocol_ping_and_keeps_receiving_trades() {
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let url = format!("ws://{}", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("upgrade");
            expect_subscription(&mut socket).await;
            let ping = tokio::time::timeout(Duration::from_secs(7), socket.next())
                .await
                .expect("application heartbeat before deadline")
                .expect("socket stays open")
                .expect("heartbeat frame");
            assert_eq!(
                ping,
                tokio_tungstenite::tungstenite::Message::Text("ping".into()),
                "RTDS heartbeat must match the official client's application text ping"
            );
            socket
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    trade_message(json!(0.55)).into(),
                ))
                .await
                .expect("trade after heartbeat");
        });
        let feed = PolymarketTradeFirehose::with_websocket_url(url);
        let trade = tokio::time::timeout(Duration::from_secs(8), feed.next_trade())
            .await
            .expect("trade after heartbeat");
        assert_eq!(trade.transaction_hash, "0xtx");
        server.await.expect("heartbeat server assertions");
    }

    #[tokio::test]
    async fn full_consumer_queue_does_not_starve_heartbeat_or_shutdown() {
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let url = format!("ws://{}", listener.local_addr().expect("address"));
        let (sender, _receiver) = mpsc::channel(1);
        let cancel = CancellationToken::new();
        let runner = tokio::spawn(run_trade_socket(
            url,
            sender,
            Arc::new(AtomicU64::new(0)),
            cancel.clone(),
            Duration::from_secs(8),
        ));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("upgrade");
            expect_subscription(&mut socket).await;
            for hash in ["0xfirst", "0xsecond"] {
                socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        trade_message_with_hash(json!(0.55), hash).into(),
                    ))
                    .await
                    .expect("trade");
            }
            let ping = tokio::time::timeout(Duration::from_secs(7), socket.next())
                .await
                .expect("heartbeat during backpressure")
                .expect("socket remains open")
                .expect("heartbeat frame");
            assert_eq!(
                ping,
                tokio_tungstenite::tungstenite::Message::Text("ping".into()),
                "RTDS application text ping must continue during backpressure"
            );
        });
        server.await.expect("heartbeat assertions");
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), runner)
            .await
            .expect("cancellable blocked delivery")
            .expect("socket task");
    }

    #[tokio::test]
    async fn handshake_timeout_reconnects_and_receives_trade() {
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let url = format!("ws://{}", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move {
            let (hung, _) = listener.accept().await.expect("hung handshake accepted");
            // Keep the TCP connection open but never answer its WebSocket upgrade.
            let (stream, _) = tokio::time::timeout(Duration::from_secs(8), listener.accept())
                .await
                .expect("client reconnects after handshake deadline")
                .expect("second accept");
            drop(hung);
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("second upgrade");
            expect_subscription(&mut socket).await;
            socket
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    trade_message(json!(0.77)).into(),
                ))
                .await
                .expect("trade after reconnect");
        });
        let feed = PolymarketTradeFirehose::with_websocket_url(url);
        let trade = tokio::time::timeout(Duration::from_secs(9), feed.next_trade())
            .await
            .expect("trade after bounded handshake");
        assert_eq!(trade.price, Decimal::new(77, 2));
        server.await.expect("server assertions");
    }

    #[tokio::test]
    async fn silent_socket_idle_reconnects_and_receives_trade() {
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let url = format!("ws://{}", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("first accept");
            let mut first_socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("upgrade");
            expect_subscription(&mut first_socket).await;
            let (stream, _) = tokio::time::timeout(Duration::from_secs(4), listener.accept())
                .await
                .expect("idle reconnect")
                .expect("second accept");
            drop(first_socket);
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("second upgrade");
            expect_subscription(&mut socket).await;
            socket
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    trade_message(json!(0.77)).into(),
                ))
                .await
                .expect("trade");
        });
        let (sender, mut receiver) = mpsc::channel(1);
        let (gap_sender, gap) = watch::channel(0_u64);
        let cancel = CancellationToken::new();
        let runner = tokio::spawn(run_trade_socket_reporting(
            url,
            sender,
            Arc::new(AtomicU64::new(0)),
            gap_sender,
            cancel.clone(),
            Duration::from_millis(200),
            None,
        ));
        let trade = tokio::time::timeout(Duration::from_secs(4), receiver.recv())
            .await
            .expect("trade after idle reconnect")
            .expect("trade");
        assert!(matches!(trade, FirehoseObservation::Trade(t) if t.price == Decimal::new(77, 2)));
        assert!(*gap.borrow() > 0, "silent socket is a coverage gap");
        server.await.expect("server assertions");
        cancel.cancel();
        runner.await.expect("socket task");
    }

    #[tokio::test]
    async fn inbound_chatter_and_pongs_do_not_hide_a_trade_feed_stall() {
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let url = format!("ws://{}", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("first accept");
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("upgrade");
            expect_subscription(&mut socket).await;
            for _ in 0..4 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let _ = socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        "chatter".into(),
                    ))
                    .await;
                let _ = socket
                    .send(tokio_tungstenite::tungstenite::Message::Pong(
                        Vec::new().into(),
                    ))
                    .await;
            }
            let (stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
                .await
                .expect("trade-idle reconnect")
                .expect("second accept");
            let mut next = tokio_tungstenite::accept_async(stream)
                .await
                .expect("second upgrade");
            expect_subscription(&mut next).await;
            next.send(tokio_tungstenite::tungstenite::Message::Text(
                trade_message(json!(0.66)).into(),
            ))
            .await
            .expect("trade");
        });
        let (sender, mut receiver) = mpsc::channel(1);
        let (gap_sender, gap) = watch::channel(0_u64);
        let cancel = CancellationToken::new();
        let runner = tokio::spawn(run_trade_socket_reporting(
            url,
            sender,
            Arc::new(AtomicU64::new(0)),
            gap_sender,
            cancel.clone(),
            Duration::from_millis(200),
            None,
        ));
        let trade = tokio::time::timeout(Duration::from_secs(4), receiver.recv())
            .await
            .expect("trade after reconnect")
            .expect("trade");
        assert!(matches!(trade, FirehoseObservation::Trade(t) if t.price == Decimal::new(66, 2)));
        assert!(
            *gap.borrow() > 0,
            "healthy pongs cannot certify trade coverage"
        );
        server.await.expect("server assertions");
        cancel.cancel();
        runner.await.expect("socket task");
    }

    #[tokio::test]
    async fn reconnects_and_resumes_after_a_dropped_connection() {
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let url = format!("ws://{}", listener.local_addr().expect("address"));
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("first accept");
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("first upgrade");
            expect_subscription(&mut socket).await;
            socket.close(None).await.expect("close");

            let (stream, _) = listener.accept().await.expect("second accept");
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("second upgrade");
            expect_subscription(&mut socket).await;
            socket
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    trade_message(json!(0.77)).into(),
                ))
                .await
                .expect("trade");
        });
        let feed = PolymarketTradeFirehose::with_websocket_url(url);
        let mut disruptions = feed.subscribe_disruptions();
        tokio::time::timeout(Duration::from_secs(4), disruptions.changed())
            .await
            .expect("socket interruption must be observable")
            .expect("status sender alive");
        assert!(*disruptions.borrow() > 0);
        let trade = tokio::time::timeout(Duration::from_secs(4), feed.next_trade())
            .await
            .expect("trade after reconnect");
        assert_eq!(trade.price, Decimal::new(77, 2));
    }

    #[tokio::test]
    async fn ambiguous_duplicate_signals_coverage_loss_before_next_trade() {
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let url = format!("ws://{}", listener.local_addr().expect("address"));
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("upgrade");
            expect_subscription(&mut socket).await;
            for message in [
                trade_message_with_hash(json!(0.55), "0xduplicate"),
                trade_message_with_hash(json!(0.55), "0xduplicate"),
                trade_message_with_hash(json!(0.56), "0xnew"),
            ] {
                socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        message.into(),
                    ))
                    .await
                    .expect("trade");
            }
        });

        let feed = PolymarketTradeFirehose::with_websocket_url(url);
        let mut disruptions = feed.subscribe_disruptions();
        assert_eq!(feed.next_trade().await.transaction_hash, "0xduplicate");
        assert_eq!(feed.next_trade().await.transaction_hash, "0xnew");
        tokio::time::timeout(Duration::from_secs(2), disruptions.changed())
            .await
            .expect("ambiguous duplicate must signal coverage loss")
            .expect("feed owns the sender");
        assert_eq!(feed.ambiguous_duplicate_count(), 1);
    }

    #[tokio::test]
    async fn evicts_the_oldest_hash_after_the_dedup_window_rolls_over() {
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let url = format!("ws://{}", listener.local_addr().expect("address"));
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("upgrade");
            expect_subscription(&mut socket).await;
            for number in 0..=DEDUP_WINDOW_SIZE {
                let message = trade_message_with_hash(json!(0.55), &format!("0x{number}"));
                socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        message.into(),
                    ))
                    .await
                    .expect("trade");
            }
            socket
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    trade_message_with_hash(json!(0.55), "0x0").into(),
                ))
                .await
                .expect("rolled-over trade");
        });

        let feed = PolymarketTradeFirehose::with_websocket_url(url);
        for number in 0..=DEDUP_WINDOW_SIZE {
            assert_eq!(
                feed.next_trade().await.transaction_hash,
                format!("0x{number}")
            );
        }
        assert_eq!(feed.next_trade().await.transaction_hash, "0x0");
    }

    #[tokio::test]
    async fn trade_only_consumer_must_report_undurable_missing_market_row_as_gap() {
        let (sender, receiver) = mpsc::channel(2);
        sender
            .send(FirehoseObservation::MissingMarket {
                raw: json!({"asset":"123"}),
                candidate: parsed_trade("0xpartial"),
            })
            .await
            .unwrap();
        sender.send(parsed_trade("0xnext").into()).await.unwrap();
        let feed = firehose_for_receiver(receiver);
        let gap = feed.subscribe_disruptions();
        assert_eq!(feed.next_trade().await.transaction_hash, "0xnext");
        assert_eq!(*gap.borrow(), 1);
    }

    #[tokio::test]
    async fn next_trade_drops_a_duplicate_parsed_trade() {
        let (sender, receiver) = mpsc::channel(3);
        sender
            .send(parsed_trade("0xduplicate").into())
            .await
            .unwrap();
        sender
            .send(parsed_trade("0xduplicate").into())
            .await
            .unwrap();
        sender.send(parsed_trade("0xnew").into()).await.unwrap();
        let feed = firehose_for_receiver(receiver);

        assert_eq!(feed.next_trade().await.transaction_hash, "0xduplicate");
        assert_eq!(feed.next_trade().await.transaction_hash, "0xnew");
    }

    #[tokio::test]
    async fn next_trade_keeps_distinct_fills_from_one_transaction() {
        let (sender, receiver) = mpsc::channel(3);
        let first = parsed_trade("0xshared");
        let mut second = first.clone();
        second.price = Decimal::new(56, 2);
        sender.send(first.into()).await.unwrap();
        sender.send(second.clone().into()).await.unwrap();
        sender.send(parsed_trade("0xnext").into()).await.unwrap();
        let feed = firehose_for_receiver(receiver);
        assert_eq!(feed.next_trade().await.price, Decimal::new(55, 2));
        assert_eq!(feed.next_trade().await, second);
    }

    #[tokio::test]
    async fn next_trade_preserves_different_wallets_with_identical_trade_economics() {
        let (sender, receiver) = mpsc::channel(3);
        let first = parsed_trade("0xshared");
        let mut second = first.clone();
        second.proxy_wallet = "0xother".to_owned();
        sender.send(first.clone().into()).await.unwrap();
        sender.send(second.clone().into()).await.unwrap();
        sender.send(parsed_trade("0xnext").into()).await.unwrap();
        let feed = firehose_for_receiver(receiver);
        assert_eq!(feed.next_trade().await, first);
        assert_eq!(feed.next_trade().await, second);
    }

    #[tokio::test]
    async fn next_trade_reaccepts_a_hash_evicted_from_the_rolling_window() {
        let (sender, receiver) = mpsc::channel(DEDUP_WINDOW_SIZE + 2);
        for number in 0..=DEDUP_WINDOW_SIZE {
            sender
                .send(parsed_trade(&format!("0x{number}")).into())
                .await
                .unwrap();
        }
        sender.send(parsed_trade("0x0").into()).await.unwrap();
        let feed = firehose_for_receiver(receiver);

        for number in 0..=DEDUP_WINDOW_SIZE {
            assert_eq!(
                feed.next_trade().await.transaction_hash,
                format!("0x{number}")
            );
        }
        assert_eq!(feed.next_trade().await.transaction_hash, "0x0");
    }
}
