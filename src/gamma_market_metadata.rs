//! Read-only, cached Gamma market metadata used by pre-audit scan filters.

use std::{sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde_json::Value;

use crate::{
    gamma_index::{GAMMA_DEFAULT_BASE_URL, GAMMA_MARKETS_PATH},
    ttl_cache::TtlCache,
};

const MARKET_METADATA_CACHE_CAPACITY: usize = 4_096;
const MAX_MARKETS_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Exact Gamma token-to-market metadata only; never a fill or P&L source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GammaTokenMarket {
    pub condition_id: String,
    pub slug: String,
    pub event_slug: String,
    pub outcome: String,
}

#[derive(Clone)]
pub struct GammaTokenMarketLookup {
    client: reqwest::Client,
    base_url: String,
    cache: Arc<TtlCache<String, GammaTokenMarket>>,
}

impl GammaTokenMarketLookup {
    #[must_use]
    pub fn new(cache_ttl: Duration) -> Self {
        Self::with_client(
            crate::http_client::default_http_client(),
            GAMMA_DEFAULT_BASE_URL,
            cache_ttl,
        )
    }

    #[must_use]
    pub fn with_client(
        client: reqwest::Client,
        base_url: impl Into<String>,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            client,
            base_url: base_url.into(),
            cache: Arc::new(TtlCache::new(cache_ttl, MARKET_METADATA_CACHE_CAPACITY)),
        }
    }
}

impl GammaTokenMarketLookup {
    pub async fn market_for_token(
        &self,
        token: &str,
    ) -> Result<GammaTokenMarket, GammaMarketMetadataError> {
        if token.trim().is_empty() {
            return Err(GammaMarketMetadataError::InvalidField { field: "asset" });
        }
        if let Some(market) = self.cache.get(&token.to_owned()).await {
            return Ok(market);
        }
        let response = self
            .client
            .get(format!(
                "{}{}",
                self.base_url.trim_end_matches('/'),
                GAMMA_MARKETS_PATH
            ))
            .query(&[("clob_token_ids", token)])
            .send()
            .await
            .map_err(|_| GammaMarketMetadataError::RequestFailed)?;
        if !response.status().is_success() {
            return Err(GammaMarketMetadataError::HttpStatus(
                response.status().as_u16(),
            ));
        }
        let markets: Vec<Value> = read_markets(response).await?;
        let mut found = None;
        for market in markets {
            let ids = parse_gamma_strings(&market, "clobTokenIds")?;
            let outcomes = parse_gamma_strings(&market, "outcomes")?;
            if ids.len() != outcomes.len() {
                return Err(GammaMarketMetadataError::InvalidField { field: "outcomes" });
            }
            for (id, outcome) in ids.iter().zip(outcomes) {
                if id != token {
                    continue;
                }
                if found.is_some() {
                    return Err(GammaMarketMetadataError::AmbiguousToken);
                }
                let field = |value: &Value, key| {
                    value
                        .get(key)
                        .and_then(Value::as_str)
                        .filter(|s| !s.trim().is_empty())
                        .map(str::to_owned)
                        .ok_or(GammaMarketMetadataError::InvalidField {
                            field: "market identity",
                        })
                };
                let events = market
                    .get("events")
                    .and_then(Value::as_array)
                    .ok_or(GammaMarketMetadataError::InvalidField { field: "events" })?;
                if events.len() != 1 {
                    return Err(GammaMarketMetadataError::AmbiguousToken);
                }
                found = Some(GammaTokenMarket {
                    condition_id: field(&market, "conditionId")?,
                    slug: field(&market, "slug")?,
                    event_slug: field(&events[0], "slug")?,
                    outcome: if outcome.trim().is_empty() {
                        return Err(GammaMarketMetadataError::InvalidField { field: "outcome" });
                    } else {
                        outcome
                    },
                });
            }
        }
        let market =
            found.ok_or_else(|| GammaMarketMetadataError::MissingMarket("token".into()))?;
        self.cache.insert(token.to_owned(), market.clone()).await;
        Ok(market)
    }
}

async fn read_markets(
    mut response: reqwest::Response,
) -> Result<Vec<Value>, GammaMarketMetadataError> {
    if response
        .content_length()
        .is_some_and(|size| size > MAX_MARKETS_RESPONSE_BYTES as u64)
    {
        return Err(GammaMarketMetadataError::ResponseTooLarge);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| GammaMarketMetadataError::ReadBody)?
    {
        if chunk.len() > MAX_MARKETS_RESPONSE_BYTES - bytes.len() {
            return Err(GammaMarketMetadataError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| GammaMarketMetadataError::MalformedEnvelope("invalid JSON".to_owned()))
}

fn parse_gamma_strings(
    market: &Value,
    field: &'static str,
) -> Result<Vec<String>, GammaMarketMetadataError> {
    let value = market
        .get(field)
        .ok_or(GammaMarketMetadataError::InvalidField { field })?;
    let array: Vec<Value> = match value {
        Value::String(encoded) => serde_json::from_str(encoded)
            .map_err(|_| GammaMarketMetadataError::InvalidField { field })?,
        Value::Array(array) => array.clone(),
        _ => return Err(GammaMarketMetadataError::InvalidField { field }),
    };
    array
        .into_iter()
        .map(|value| {
            value
                .as_str()
                .filter(|s| !s.trim().is_empty())
                .map(str::to_owned)
                .ok_or(GammaMarketMetadataError::InvalidField { field })
        })
        .collect()
}

/// The fields needed for scanner market-quality filters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GammaMarketMetadata {
    pub volume_usd: Decimal,
    pub liquidity_usd: Decimal,
    pub end_date: DateTime<Utc>,
    pub category: Option<String>,
}

/// A read-only source of market metadata, kept separate from wallet auditing.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GammaMarketMetadataError {
    #[error("Gamma market metadata request failed")]
    RequestFailed,
    #[error("Gamma market metadata returned HTTP {0}")]
    HttpStatus(u16),
    #[error("Gamma market metadata response could not be read")]
    ReadBody,
    #[error("Gamma market metadata response exceeded the size limit")]
    ResponseTooLarge,
    #[error("Gamma market metadata response was malformed: {0}")]
    MalformedEnvelope(String),
    #[error("Gamma market metadata for condition `{0}` was unavailable")]
    MissingMarket(String),
    #[error("Gamma market metadata field `{field}` was invalid")]
    InvalidField { field: &'static str },
    #[error("Gamma token mapped to multiple markets or events")]
    AmbiguousToken,
}

/// Cached Gamma `/markets` lookup keyed by condition id.
#[derive(Clone)]
pub struct GammaMarketMetadataLookup {
    client: reqwest::Client,
    base_url: String,
    cache: Arc<TtlCache<String, GammaMarketMetadata>>,
}

impl GammaMarketMetadataLookup {
    #[must_use]
    pub fn new(cache_ttl: Duration) -> Self {
        Self::with_client(
            crate::http_client::default_http_client(),
            GAMMA_DEFAULT_BASE_URL,
            cache_ttl,
        )
    }

    #[must_use]
    pub fn with_client(
        client: reqwest::Client,
        base_url: impl Into<String>,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            client,
            base_url: base_url.into(),
            cache: Arc::new(TtlCache::new(cache_ttl, MARKET_METADATA_CACHE_CAPACITY)),
        }
    }

    async fn fetch(
        &self,
        condition_id: &str,
    ) -> Result<GammaMarketMetadata, GammaMarketMetadataError> {
        if condition_id.trim().is_empty() {
            return Err(GammaMarketMetadataError::InvalidField {
                field: "condition_id",
            });
        }
        let response = self
            .client
            .get(format!(
                "{}{}",
                self.base_url.trim_end_matches('/'),
                GAMMA_MARKETS_PATH
            ))
            .query(&[("condition_ids", condition_id)])
            .send()
            .await
            .map_err(|_| GammaMarketMetadataError::RequestFailed)?;
        if !response.status().is_success() {
            return Err(GammaMarketMetadataError::HttpStatus(
                response.status().as_u16(),
            ));
        }
        let markets: Vec<Value> = read_markets(response).await?;
        let market = markets
            .iter()
            .find(|market| market.get("conditionId").and_then(Value::as_str) == Some(condition_id))
            .ok_or_else(|| GammaMarketMetadataError::MissingMarket(condition_id.to_owned()))?;
        parse_market_metadata(market)
    }
}

impl GammaMarketMetadataLookup {
    pub async fn market_metadata(
        &self,
        condition_id: &str,
    ) -> Result<GammaMarketMetadata, GammaMarketMetadataError> {
        if let Some(metadata) = self.cache.get(&condition_id.to_owned()).await {
            return Ok(metadata);
        }
        let metadata = self.fetch(condition_id).await?;
        self.cache
            .insert(condition_id.to_owned(), metadata.clone())
            .await;
        Ok(metadata)
    }
}

fn parse_market_metadata(market: &Value) -> Result<GammaMarketMetadata, GammaMarketMetadataError> {
    let object = market
        .as_object()
        .ok_or(GammaMarketMetadataError::InvalidField { field: "market" })?;
    let decimal = |field| match object.get(field) {
        Some(Value::String(value)) => value.parse().ok(),
        Some(Value::Number(value)) => value.to_string().parse().ok(),
        _ => None,
    };
    let volume_usd = decimal("volumeNum")
        .ok_or(GammaMarketMetadataError::InvalidField { field: "volumeNum" })?;
    let liquidity_usd = decimal("liquidityNum").ok_or(GammaMarketMetadataError::InvalidField {
        field: "liquidityNum",
    })?;
    let end_date = ["endDate", "endDateIso"]
        .into_iter()
        .find_map(|field| object.get(field).and_then(Value::as_str))
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
        .ok_or(GammaMarketMetadataError::InvalidField { field: "endDate" })?;
    let category = object
        .get("category")
        .and_then(Value::as_str)
        .or_else(|| {
            object
                .get("events")
                .and_then(Value::as_array)
                .and_then(|events| events.first())
                .and_then(|event| event.get("category"))
                .and_then(Value::as_str)
        })
        .map(str::trim)
        .filter(|category| !category.is_empty())
        .map(str::to_owned);
    Ok(GammaMarketMetadata {
        volume_usd,
        liquidity_usd,
        end_date,
        category,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, body::Body, routing::get};
    use serde_json::json;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn parses_market_and_event_categories() {
        let metadata = parse_market_metadata(&json!({
            "volumeNum": "50000", "liquidityNum": 10000,
            "endDate": "2030-01-01T00:00:00Z", "events": [{"category": "Crypto"}]
        }))
        .unwrap();
        assert_eq!(metadata.volume_usd, Decimal::new(50_000, 0));
        assert_eq!(metadata.liquidity_usd, Decimal::new(10_000, 0));
        assert_eq!(metadata.category.as_deref(), Some("Crypto"));
    }

    #[test]
    fn rejects_missing_required_market_quality_fields() {
        for field in ["volumeNum", "liquidityNum", "endDate"] {
            let mut market = json!({
                "volumeNum": "50000", "liquidityNum": "10000", "endDate": "2030-01-01T00:00:00Z"
            });
            market.as_object_mut().unwrap().remove(field);
            assert!(matches!(
                parse_market_metadata(&market),
                Err(GammaMarketMetadataError::InvalidField { .. })
            ));
        }
    }

    #[tokio::test]
    async fn token_lookup_requires_a_unique_exact_token_and_one_event() {
        for (markets, expected) in [
            (
                json!([{"conditionId":"0xcondition","slug":"market","events":[{"slug":"event"}],"clobTokenIds":"[\"123\",\"456\"]","outcomes":"[\"Yes\",\"No\"]"}]),
                true,
            ),
            (
                json!([{"conditionId":"0xcondition","slug":"market","events":[{"slug":"event"}],"clobTokenIds":"[\"456\"]","outcomes":"[\"No\"]"}]),
                false,
            ),
            (
                json!([{"conditionId":"0xcondition","slug":"market","events":[{"slug":"event"},{"slug":"other"}],"clobTokenIds":"[\"123\"]","outcomes":"[\"Yes\"]"}]),
                false,
            ),
            (
                json!([{"conditionId":"0xcondition","slug":"market","events":[{"slug":"event"}],"clobTokenIds":"[\"123\"]","outcomes":"[\"Yes\"]"},{"conditionId":"0xother","slug":"other","events":[{"slug":"other"}],"clobTokenIds":"[\"123\"]","outcomes":"[\"No\"]"}]),
                false,
            ),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let app = Router::new().route(
                "/markets",
                get(move || {
                    let markets = markets.clone();
                    async move { Json(markets) }
                }),
            );
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let lookup = GammaTokenMarketLookup::with_client(
                reqwest::Client::new(),
                format!("http://{address}"),
                Duration::from_secs(60),
            );
            let result = lookup.market_for_token("123").await;
            if expected {
                assert_eq!(
                    result.unwrap(),
                    GammaTokenMarket {
                        condition_id: "0xcondition".into(),
                        slug: "market".into(),
                        event_slug: "event".into(),
                        outcome: "Yes".into()
                    }
                );
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[tokio::test]
    async fn request_errors_do_not_expose_endpoint_credentials_or_query_values() {
        let endpoint = "http://user:private-password@127.0.0.1:1";
        let token_lookup = GammaTokenMarketLookup::with_client(
            reqwest::Client::new(),
            endpoint,
            Duration::from_secs(1),
        );
        let metadata_lookup = GammaMarketMetadataLookup::with_client(
            reqwest::Client::new(),
            endpoint,
            Duration::from_secs(1),
        );
        let token_error = token_lookup
            .market_for_token("sensitive-token")
            .await
            .unwrap_err();
        let condition_error = metadata_lookup
            .market_metadata("sensitive-condition")
            .await
            .unwrap_err();
        for error in [token_error, condition_error] {
            assert_eq!(error, GammaMarketMetadataError::RequestFailed);
            let displayed = error.to_string();
            assert!(!displayed.contains("private-password"));
            assert!(!displayed.contains("sensitive-"));
        }
    }

    #[tokio::test]
    async fn market_lookups_reject_oversized_declared_and_chunked_responses() {
        for chunked in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let app = Router::new().route(
                "/markets",
                get(move || async move {
                    let oversized = vec![b'x'; MAX_MARKETS_RESPONSE_BYTES + 1];
                    if chunked {
                        let parts = oversized
                            .chunks(MAX_MARKETS_RESPONSE_BYTES / 2)
                            .map(|chunk| Ok::<_, std::io::Error>(chunk.to_vec()))
                            .collect::<Vec<_>>();
                        Body::from_stream(futures_util::stream::iter(parts))
                    } else {
                        Body::from(oversized)
                    }
                }),
            );
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let base_url = format!("http://{address}");
            let client = reqwest::Client::new();
            let token_lookup = GammaTokenMarketLookup::with_client(
                client.clone(),
                &base_url,
                Duration::from_secs(60),
            );
            let metadata_lookup =
                GammaMarketMetadataLookup::with_client(client, base_url, Duration::from_secs(60));
            assert_eq!(
                token_lookup.market_for_token("123").await.unwrap_err(),
                GammaMarketMetadataError::ResponseTooLarge
            );
            assert_eq!(
                metadata_lookup
                    .market_metadata("condition")
                    .await
                    .unwrap_err(),
                GammaMarketMetadataError::ResponseTooLarge
            );
        }
    }

    #[tokio::test]
    async fn caches_successful_lookups_by_condition_id() {
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let address = listener.local_addr().expect("listener address");
        let calls = Arc::new(AtomicUsize::new(0));
        let app = Router::new().route(
            "/markets",
            get({
                let calls = calls.clone();
                move || {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Json(json!([{
                            "conditionId": "condition", "volumeNum": "50000",
                            "liquidityNum": "10000", "endDate": "2030-01-01T00:00:00Z"
                        }]))
                    }
                }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let lookup = GammaMarketMetadataLookup::with_client(
            reqwest::Client::new(),
            format!("http://{address}"),
            Duration::from_secs(600),
        );
        assert!(lookup.market_metadata("condition").await.is_ok());
        assert!(lookup.market_metadata("condition").await.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
