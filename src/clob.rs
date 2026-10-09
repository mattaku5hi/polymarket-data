//! Public CLOB book reads, not executable quotes, simulated fills or fees.
pub mod depth;
pub mod execution_context;
pub mod execution_quote;

use rust_decimal::Decimal;
use serde_json::Value;

pub const DEFAULT_BASE_URL: &str = "https://clob.polymarket.com";
const MAX_BOOK_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BookLevel {
    pub price: String,
    pub size: String,
}

/// Vendor order, decimal text, and timestamp text are preserved. The timestamp
/// unit is undocumented and its presence does not establish freshness or a
/// continuous WebSocket history.
#[derive(Clone, Debug, PartialEq)]
pub struct BookObservation {
    pub asset_id: String,
    pub hash: String,
    pub timestamp: String,
    pub bids: Vec<BookLevel>,
    pub asks: Vec<BookLevel>,
    vendor_book: Value,
}

impl BookObservation {
    #[must_use]
    pub fn vendor_book(&self) -> &Value {
        &self.vendor_book
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BookError {
    #[error("CLOB endpoint must use HTTPS (loopback HTTP only for local tests)")]
    InvalidEndpoint,
    #[error("CLOB book request failed")]
    RequestFailed,
    #[error("CLOB book rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("CLOB book returned http {0}")]
    HttpStatus(u16),
    #[error("CLOB book response exceeded the size limit")]
    ResponseTooLarge,
    #[error("CLOB book response could not be read")]
    ResponseUnreadable,
    #[error("CLOB book identity or payload is malformed")]
    MalformedBook,
}

/// Read one bounded book using the caller's HTTP timeout, proxy and pool policy.
/// No retries, signing, storage, price inference or order submission occur.
///
/// # Errors
/// Rejects insecure endpoints, failed/oversized responses, wrong token identity,
/// missing provenance and invalid levels. Errors never include URLs or payloads.
pub async fn fetch_book(
    client: &reqwest::Client,
    base_url: &str,
    token_id: &str,
) -> Result<BookObservation, BookError> {
    let url = reqwest::Url::parse(&format!("{}/book", base_url.trim_end_matches('/')))
        .map_err(|_| BookError::InvalidEndpoint)?;
    if url.scheme() != "https"
        && !(url.scheme() == "http"
            && url
                .host_str()
                .is_some_and(|h| matches!(h, "localhost" | "127.0.0.1" | "[::1]")))
    {
        return Err(BookError::InvalidEndpoint);
    }
    let mut response = client
        .get(url)
        .query(&[("token_id", token_id)])
        .send()
        .await
        .map_err(|_| BookError::RequestFailed)?;
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err(BookError::RateLimited {
            retry_after_seconds: response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok()),
        });
    }
    if !response.status().is_success() {
        return Err(BookError::HttpStatus(response.status().as_u16()));
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_BOOK_BYTES as u64)
    {
        return Err(BookError::ResponseTooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| BookError::ResponseUnreadable)?
    {
        if chunk.len() > MAX_BOOK_BYTES - body.len() {
            return Err(BookError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    let raw: Value = serde_json::from_slice(&body).map_err(|_| BookError::MalformedBook)?;
    parse_book(raw, token_id)
}

pub(super) fn parse_book(raw: Value, token_id: &str) -> Result<BookObservation, BookError> {
    let asset_id = text(&raw, "asset_id")?;
    if asset_id != token_id {
        return Err(BookError::MalformedBook);
    }
    let hash = text(&raw, "hash")?;
    let timestamp = text(&raw, "timestamp")?;
    if timestamp.is_empty()
        || timestamp.len() > 20
        || !timestamp.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(BookError::MalformedBook);
    }
    Ok(BookObservation {
        asset_id,
        hash,
        timestamp,
        bids: levels(&raw, "bids")?,
        asks: levels(&raw, "asks")?,
        vendor_book: raw,
    })
}

fn text(raw: &Value, field: &str) -> Result<String, BookError> {
    raw.get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_owned)
        .ok_or(BookError::MalformedBook)
}

fn levels(raw: &Value, field: &str) -> Result<Vec<BookLevel>, BookError> {
    raw.get(field)
        .and_then(Value::as_array)
        .ok_or(BookError::MalformedBook)?
        .iter()
        .map(|row| {
            let price = text(row, "price")?;
            let size = text(row, "size")?;
            let p = Decimal::from_str_exact(&price).map_err(|_| BookError::MalformedBook)?;
            let s = Decimal::from_str_exact(&size).map_err(|_| BookError::MalformedBook)?;
            if p <= Decimal::ZERO || p > Decimal::ONE || s <= Decimal::ZERO {
                return Err(BookError::MalformedBook);
            }
            Ok(BookLevel { price, size })
        })
        .collect()
}
