#![forbid(unsafe_code)]
//! Bounded read-only Polymarket data, book depth, streams and rooted evidence.
//! No order submission, wallet spending or qualified P&L claims.

pub mod clob;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Map, Value};

pub const DEFAULT_BASE_URL: &str = "https://data-api.polymarket.com";
pub const V2_TRADES_PATH: &str = "/v2/trades";
pub const MAX_BATCH_LIMIT: usize = 1_000;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MILLISECOND_THRESHOLD: i64 = 1_000_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TradeSide {
    Buy,
    Sell,
}

impl TradeSide {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Buy => "buy",
            Self::Sell => "sell",
        }
    }
}

#[cfg(feature = "streams")]
pub mod trade_firehose;
#[cfg(feature = "streams")]
pub use trade_firehose::FirehoseTrade;
#[cfg(feature = "streams")]
pub mod market_stream;

#[cfg(feature = "chain-audit")]
pub mod chain_log_audit;

#[cfg(feature = "chain-audit")]
pub mod activity_hints;
pub mod resolutions;
pub mod v2_reconciliation;

#[cfg(feature = "gamma")]
pub mod gamma_index;
#[cfg(feature = "gamma")]
pub mod gamma_market_metadata;
pub mod http_client;
#[cfg(feature = "gamma")]
pub mod ttl_cache;
#[cfg(feature = "gamma")]
pub use gamma_index::GAMMA_DEFAULT_BASE_URL;

/// A vendor observation, not a unique fill, wallet P&L or a trade to execute.
#[derive(Clone, Debug, PartialEq)]
pub struct TradeObservation {
    pub proxy_wallet: String,
    pub condition_id: String,
    pub token_id: String,
    pub transaction_hash: String,
    pub side: TradeSide,
    pub price: String,
    pub size: String,
    pub observed_at: DateTime<Utc>,
    vendor_row: Value,
}

impl TradeObservation {
    #[must_use]
    pub fn vendor_row(&self) -> &Value {
        &self.vendor_row
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TradeRowError {
    #[error("trade row is not a JSON object")]
    NotAnObject,
    #[error("required trade field `{field}` is missing, blank, or of the wrong type")]
    InvalidField { field: &'static str },
    #[error("trade field `timestamp` is not a valid epoch-seconds integer")]
    InvalidTimestamp,
    #[error("trade field `side` is `{value}`, expected `BUY` or `SELL`")]
    UnknownSide { value: String },
}

/// Parse a vendor row while retaining the unmodified JSON evidence.
///
/// # Errors
///
/// Rejects missing/ill-typed fields, unknown sides and invalid timestamps.
pub fn parse_v2_trade(trade: &Value) -> Result<TradeObservation, TradeRowError> {
    let object = trade.as_object().ok_or(TradeRowError::NotAnObject)?;
    let proxy_wallet = require_string(object, "proxy_wallet")?.to_owned();
    let condition_id = require_string(object, "condition_id")?.to_owned();
    let token_id = require_string(object, "token_id")?.to_owned();
    let transaction_hash = require_string(object, "transaction_hash")?.to_owned();
    let price = require_number_string(object, "price")?;
    let size = require_number_string(object, "size")?;
    let side = match require_string(object, "side")?
        .to_ascii_lowercase()
        .as_str()
    {
        "buy" => TradeSide::Buy,
        "sell" => TradeSide::Sell,
        other => {
            return Err(TradeRowError::UnknownSide {
                value: other.to_owned(),
            });
        }
    };
    let timestamp = object
        .get("timestamp")
        .ok_or(TradeRowError::InvalidField { field: "timestamp" })?;
    let observed_at = DateTime::from_timestamp(parse_epoch_seconds(timestamp)?, 0)
        .ok_or(TradeRowError::InvalidTimestamp)?;
    Ok(TradeObservation {
        proxy_wallet,
        condition_id,
        token_id,
        transaction_hash,
        side,
        price,
        size,
        observed_at,
        vendor_row: trade.clone(),
    })
}

#[derive(Debug)]
pub struct TradesPage {
    pub observations: Vec<TradeObservation>,
    /// Vendor cursor, not a guarantee that historical coverage is complete.
    pub next_cursor: Option<String>,
}

/// Unmodified global-feed rows, including products without ordinary market
/// metadata. Rows are not validated trades, unique fills or executable signals.
#[derive(Debug)]
pub struct RawTradesPage {
    pub rows: Vec<Value>,
    /// Opaque vendor seek cursor; not a per-row identity or coverage proof.
    pub next_cursor: Option<String>,
    /// Parsed HTTP Age header. Missing/invalid is unknown, NOT a cache miss or
    /// zero age. Even zero age supplies no upstream publication guarantee.
    pub cache_age_seconds: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PageError {
    #[error("Data API trades limit must be in 1..={MAX_BATCH_LIMIT}, got {0}")]
    InvalidLimit(usize),
    #[error(
        "Data API trades minimum token size must be an exact positive decimal (zero means the provider default)"
    )]
    InvalidMinimumSize,
    #[error("Data API trades endpoint must use HTTPS (loopback HTTP only for local tests)")]
    InvalidEndpoint,
    #[error("Data API trades request failed")]
    RequestFailed,
    #[error("Data API trades returned http 429 (retry after {0} seconds)")]
    RateLimitedWithDelay(u64),
    #[error("Data API trades returned http 429 (rate limited)")]
    RateLimited,
    #[error("Data API trades returned http {0}")]
    HttpStatus(u16),
    #[error("Data API trades response exceeded the size limit")]
    ResponseTooLarge,
    #[error("Data API trades response could not be read")]
    ResponseUnreadable,
    #[error("Data API trades response was not a valid envelope")]
    InvalidEnvelope,
    #[error("Data API trade row is invalid: {0}")]
    InvalidTrade(TradeRowError),
}

/// Fetch one bounded page, including maker-side fills (`taker_only=false`).
/// Inject the HTTP client; no global runtime, retries, state or credentials.
///
/// # Errors
///
/// Rejects invalid requests, unsuccessful status, oversized/malformed pages
/// and any invalid row without returning a partial page. Errors omit URLs.
pub async fn fetch_v2_trades_page(
    client: &reqwest::Client,
    base_url: &str,
    user: &str,
    limit: usize,
    cursor: Option<&str>,
) -> Result<TradesPage, PageError> {
    let page = fetch_raw_trades_page(client, base_url, Some(user), limit, cursor, None).await?;
    let observations = page
        .rows
        .iter()
        .map(parse_v2_trade)
        .collect::<Result<Vec<_>, _>>()
        .map_err(PageError::InvalidTrade)?;
    Ok(TradesPage {
        observations,
        next_cursor: page.next_cursor,
    })
}

/// Fetch one global v2 page, omitting `user` and including maker rows.
/// Keeps every vendor row in order, including equal tuples and unenriched
/// products. No market mapping, deduplication, time bounds or retries.
/// Global `start/end` bounds are unsupported by the provider and are not sent.
///
/// # Errors
///
/// Rejects invalid limits/endpoints, unsuccessful status, oversized bodies and
/// malformed envelopes. Row validation belongs to the consumer; raw JSON is
/// evidence only. Errors omit URLs and response bodies.
pub async fn fetch_v2_global_trades_page(
    client: &reqwest::Client,
    base_url: &str,
    limit: usize,
    cursor: Option<&str>,
) -> Result<RawTradesPage, PageError> {
    fetch_raw_trades_page(client, base_url, None, limit, cursor, None).await
}

/// Read a global page with an explicit positive `TOKENS` minimum. In particular,
/// zero is rejected because the provider treats zero as its default 0.01 floor,
/// not as an unfiltered request. The caller owns the selected product precision
/// and must retain the same filter on every cursor request. No coverage claim.
///
/// # Errors
/// Rejects zero, negative or inexact/unparseable minimums before requesting,
/// plus the same bounded transport/envelope errors as the default global reader.
pub async fn fetch_v2_global_trades_page_with_min_size(
    client: &reqwest::Client,
    base_url: &str,
    min_size: &str,
    limit: usize,
    cursor: Option<&str>,
) -> Result<RawTradesPage, PageError> {
    let minimum = rust_decimal::Decimal::from_str_exact(min_size)
        .map_err(|_| PageError::InvalidMinimumSize)?;
    if minimum <= rust_decimal::Decimal::ZERO {
        return Err(PageError::InvalidMinimumSize);
    }
    let minimum = minimum.normalize().to_string();
    fetch_raw_trades_page(client, base_url, None, limit, cursor, Some(&minimum)).await
}

async fn fetch_raw_trades_page(
    client: &reqwest::Client,
    base_url: &str,
    user: Option<&str>,
    limit: usize,
    cursor: Option<&str>,
    min_size: Option<&str>,
) -> Result<RawTradesPage, PageError> {
    if !(1..=MAX_BATCH_LIMIT).contains(&limit) {
        return Err(PageError::InvalidLimit(limit));
    }
    let endpoint = format!("{}{}", base_url.trim_end_matches('/'), V2_TRADES_PATH);
    let url = reqwest::Url::parse(&endpoint).map_err(|_| PageError::InvalidEndpoint)?;
    if url.scheme() != "https"
        && !(url.scheme() == "http"
            && url
                .host_str()
                .is_some_and(|host| host == "localhost" || host == "127.0.0.1" || host == "[::1]"))
    {
        return Err(PageError::InvalidEndpoint);
    }
    let mut query = vec![("taker_only", "false".to_owned())];
    if let Some(user) = user {
        query.push(("user", user.to_owned()));
    }
    if let Some(minimum) = min_size {
        query.push(("filter_type", "TOKENS".to_owned()));
        query.push(("filter_amount", minimum.to_owned()));
    }
    if let Some(cursor) = cursor {
        query.push(("cursor", cursor.to_owned()));
    } else {
        query.push(("limit", limit.to_string()));
    }
    let mut response = client
        .get(url)
        .query(&query)
        .send()
        .await
        .map_err(|_| PageError::RequestFailed)?;
    let status = response.status();
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err(
            match response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
            {
                Some(seconds) => PageError::RateLimitedWithDelay(seconds),
                None => PageError::RateLimited,
            },
        );
    }
    if !status.is_success() {
        return Err(PageError::HttpStatus(status.as_u16()));
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RESPONSE_BYTES as u64)
    {
        return Err(PageError::ResponseTooLarge);
    }
    let cache_age_seconds = response
        .headers()
        .get(reqwest::header::AGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| PageError::ResponseUnreadable)?
    {
        if chunk.len() > MAX_RESPONSE_BYTES - body.len() {
            return Err(PageError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    let page: VendorPage = serde_json::from_slice(&body).map_err(|_| PageError::InvalidEnvelope)?;
    let next_cursor = match page.pagination.next_cursor {
        Value::Null => None,
        Value::String(cursor) if !cursor.trim().is_empty() => Some(cursor),
        _ => return Err(PageError::InvalidEnvelope),
    };
    if page
        .pagination
        .has_more
        .is_some_and(|has_more| has_more != next_cursor.is_some())
    {
        return Err(PageError::InvalidEnvelope);
    }
    Ok(RawTradesPage {
        rows: page.data,
        next_cursor,
        cache_age_seconds,
    })
}

#[derive(Deserialize)]
struct VendorPage {
    data: Vec<Value>,
    pagination: Pagination,
}

#[derive(Deserialize)]
struct Pagination {
    next_cursor: Value,
    #[serde(default)]
    has_more: Option<bool>,
}

fn require_string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, TradeRowError> {
    match object.get(field).and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(TradeRowError::InvalidField { field }),
    }
}

fn require_number_string(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<String, TradeRowError> {
    match object.get(field) {
        Some(Value::Number(number)) => Ok(number.to_string()),
        Some(Value::String(text)) if !text.trim().is_empty() => Ok(text.trim().to_owned()),
        _ => Err(TradeRowError::InvalidField { field }),
    }
}

fn parse_epoch_seconds(value: &Value) -> Result<i64, TradeRowError> {
    let raw = match value {
        Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_u64().and_then(|n| i64::try_from(n).ok()))
            .ok_or(TradeRowError::InvalidTimestamp)?,
        Value::String(text) => text
            .trim()
            .parse::<i64>()
            .map_err(|_| TradeRowError::InvalidTimestamp)?,
        _ => return Err(TradeRowError::InvalidTimestamp),
    };
    Ok(if raw > MILLISECOND_THRESHOLD {
        raw / 1_000
    } else {
        raw
    })
}
