//! Read-only CLOB market-channel best-bid observations.
//!
//! The cache is cleared whenever the websocket reconnects, so callers never
//! mistake a price from a prior connection for a current mark.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use rust_decimal::Decimal;
use serde_json::{Value, json};
use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;

pub const CLOB_MARKET_WEBSOCKET_URL: &str = "wss://ws-subscriptions-clob.polymarket.com/ws/market";

const WEBSOCKET_RECONNECT_BASE_DELAY: Duration = Duration::from_secs(1);
const WEBSOCKET_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(60);

/// Read-only CLOB market websocket cache for best-bid marks.
pub struct MarketPriceStream {
    prices: Arc<RwLock<HashMap<String, Decimal>>>,
    subscriptions: Arc<RwLock<HashSet<String>>>,
    additions: mpsc::UnboundedSender<String>,
    cancel: CancellationToken,
}

impl MarketPriceStream {
    #[must_use]
    pub fn new(token_ids: impl IntoIterator<Item = String>) -> Self {
        Self::with_websocket_url(CLOB_MARKET_WEBSOCKET_URL, token_ids)
    }

    /// Local-test seam; production uses [`CLOB_MARKET_WEBSOCKET_URL`].
    #[must_use]
    pub fn with_websocket_url(
        websocket_url: impl Into<String>,
        token_ids: impl IntoIterator<Item = String>,
    ) -> Self {
        let prices = Arc::new(RwLock::new(HashMap::new()));
        let subscriptions = Arc::new(RwLock::new(
            token_ids
                .into_iter()
                .filter(|id| !id.trim().is_empty())
                .collect(),
        ));
        let (additions, receiver) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        tokio::spawn(run_market_socket(
            websocket_url.into(),
            prices.clone(),
            subscriptions.clone(),
            receiver,
            cancel.clone(),
        ));
        Self {
            prices,
            subscriptions,
            additions,
            cancel,
        }
    }

    /// Returns the latest valid best bid, if this connection has observed one.
    pub async fn best_bid(&self, token_id: &str) -> Option<Decimal> {
        self.prices.read().await.get(token_id).copied()
    }

    /// Adds a token subscription once. Blank tokens are ignored.
    pub fn watch_token(&self, token_id: &str) {
        if token_id.trim().is_empty() {
            return;
        }
        let subscriptions = self.subscriptions.clone();
        let additions = self.additions.clone();
        let token_id = token_id.to_owned();
        tokio::spawn(async move {
            if subscriptions.write().await.insert(token_id.clone()) {
                let _ = additions.send(token_id);
            }
        });
    }
}

impl Drop for MarketPriceStream {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn run_market_socket(
    websocket_url: String,
    prices: Arc<RwLock<HashMap<String, Decimal>>>,
    subscriptions: Arc<RwLock<HashSet<String>>>,
    mut additions: mpsc::UnboundedReceiver<String>,
    cancel: CancellationToken,
) {
    let mut failures = 0_u32;
    loop {
        prices.write().await.clear();
        let connected = tokio::select! {
            _ = cancel.cancelled() => return,
            result = tokio_tungstenite::connect_async(&websocket_url) => result,
        };
        let Ok((socket, _)) = connected else {
            failures = failures.saturating_add(1);
            if !sleep_reconnect(failures, &cancel).await {
                return;
            }
            continue;
        };
        let (mut writer, mut reader) = socket.split();
        let initial: Vec<String> = subscriptions.read().await.iter().cloned().collect();
        if send_subscription(&mut writer, true, initial).await.is_err() {
            failures = failures.saturating_add(1);
            if !sleep_reconnect(failures, &cancel).await {
                return;
            }
            continue;
        }
        failures = 0;
        let mut heartbeat = tokio::time::interval(Duration::from_secs(10));
        heartbeat.tick().await;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = heartbeat.tick() => if writer.send(tokio_tungstenite::tungstenite::Message::Text("PING".into())).await.is_err() { break },
                requested = additions.recv() => match requested {
                    Some(token) => if send_subscription(&mut writer, false, vec![token]).await.is_err() { break },
                    None => return,
                },
                message = reader.next() => match message {
                    Some(Ok(message)) => update_price(&prices, message).await,
                    Some(Err(_)) | None => break,
                },
            }
        }
        failures = failures.saturating_add(1);
        if !sleep_reconnect(failures, &cancel).await {
            return;
        }
    }
}

async fn send_subscription<S>(
    writer: &mut S,
    initial: bool,
    asset_ids: Vec<String>,
) -> Result<(), ()>
where
    S: futures_util::Sink<
            tokio_tungstenite::tungstenite::Message,
            Error = tokio_tungstenite::tungstenite::Error,
        > + Unpin,
{
    let payload = if initial {
        json!({"assets_ids": asset_ids, "type": "market"})
    } else {
        json!({"operation": "subscribe", "assets_ids": asset_ids})
    };
    writer
        .send(tokio_tungstenite::tungstenite::Message::Text(
            payload.to_string().into(),
        ))
        .await
        .map_err(|_| ())
}

async fn update_price(
    prices: &RwLock<HashMap<String, Decimal>>,
    message: tokio_tungstenite::tungstenite::Message,
) {
    let Ok(text) = message.into_text() else {
        return;
    };
    let Ok(event) = serde_json::from_str::<Value>(&text) else {
        return;
    };
    match event.get("event_type").and_then(Value::as_str) {
        Some("book") => {
            if let (Some(asset), Some(bids)) = (
                event.get("asset_id").and_then(Value::as_str),
                event.get("bids").and_then(Value::as_array),
            ) {
                let mut best = None;
                let mut valid = true;
                for bid in bids {
                    match (decimal_field(bid, "price"), decimal_field(bid, "size")) {
                        (Some(price), Some(size))
                            if price > Decimal::ZERO
                                && price <= Decimal::ONE
                                && size > Decimal::ZERO =>
                        {
                            best = Some(best.map_or(price, |current: Decimal| current.max(price)));
                        }
                        _ => {
                            valid = false;
                            break;
                        }
                    }
                }
                let mut map = prices.write().await;
                if valid {
                    if let Some(price) = best {
                        map.insert(asset.to_owned(), price);
                    } else {
                        map.remove(asset);
                    }
                } else {
                    map.remove(asset);
                }
            }
        }
        Some("price_change") => {
            if let Some(changes) = event.get("price_changes").and_then(Value::as_array) {
                let mut map = prices.write().await;
                for change in changes {
                    if let Some(asset) = change.get("asset_id").and_then(Value::as_str) {
                        match decimal_field(change, "best_bid") {
                            Some(price) if price > Decimal::ZERO && price <= Decimal::ONE => {
                                map.insert(asset.to_owned(), price);
                            }
                            _ => {
                                map.remove(asset);
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

fn decimal_field(value: &Value, field: &str) -> Option<Decimal> {
    match value.get(field)? {
        Value::String(v) => v.parse().ok(),
        Value::Number(v) => v.to_string().parse().ok(),
        _ => None,
    }
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

    #[tokio::test]
    async fn empty_bid_book_invalidates_previous_websocket_sell_mark() {
        let prices = RwLock::new(HashMap::new());
        let book = |bids: Value| {
            tokio_tungstenite::tungstenite::Message::Text(
                json!({"event_type":"book", "asset_id":"token", "bids": bids})
                    .to_string()
                    .into(),
            )
        };
        update_price(&prices, book(json!([{"price":"0.45", "size":"1"}]))).await;
        assert_eq!(prices.read().await.get("token"), Some(&Decimal::new(45, 2)));
        update_price(&prices, book(json!([]))).await;
        assert_eq!(prices.read().await.get("token"), None);
        update_price(&prices, book(json!([{"price":"0.45", "size":"1"}]))).await;
        update_price(&prices, book(json!([{"price":"0.45", "size":"0"}]))).await;
        assert_eq!(prices.read().await.get("token"), None);
        update_price(&prices, book(json!([{"price":"0.45", "size":"1"}]))).await;
        update_price(
            &prices,
            tokio_tungstenite::tungstenite::Message::Text(
                json!({"event_type":"price_change", "price_changes":[{"asset_id":"token", "best_bid":"0"}]})
                    .to_string()
                    .into(),
            ),
        )
        .await;
        assert_eq!(prices.read().await.get("token"), None);
    }

    async fn wait_for(stream: &MarketPriceStream, expected: Decimal) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if stream.best_bid("token").await == Some(expected) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("price update before deadline");
    }

    #[tokio::test]
    async fn websocket_updates_best_bid_and_reconnects_fail_closed() {
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            // Some hermetic CI sandboxes deny loopback binds.
            return;
        };
        let url = format!("ws://{}", listener.local_addr().expect("address"));
        tokio::spawn(async move {
            for (price, close) in [("0.72", true), ("0.88", false)] {
                let (stream, _) = listener.accept().await.expect("accept");
                let mut socket = tokio_tungstenite::accept_async(stream)
                    .await
                    .expect("upgrade");
                let subscription = socket
                    .next()
                    .await
                    .expect("subscription")
                    .expect("message")
                    .into_text()
                    .expect("text");
                assert!(subscription.contains("assets_ids") && subscription.contains("market"));
                socket.send(tokio_tungstenite::tungstenite::Message::Text(format!(r#"{{"event_type":"book","asset_id":"token","bids":[{{"price":"{price}","size":"1"}}]}}"#).into())).await.expect("book");
                if close {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    socket.close(None).await.expect("close");
                } else {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        });
        let stream = MarketPriceStream::with_websocket_url(url, vec!["token".to_owned()]);
        assert_eq!(stream.best_bid("token").await, None);
        wait_for(&stream, Decimal::new(72, 2)).await;
        wait_for(&stream, Decimal::new(88, 2)).await;
    }
}
