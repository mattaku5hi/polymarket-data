//! Bounded, read-only access to venue-reported wallet economics.
//!
//! Raw response bytes and retrieval time are retained for every successful
//! response. Parsed JSON numbers are convenience values; the raw bytes remain
//! authoritative for decimal spelling and provenance.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

pub const V2_POSITIONS_PATH: &str = "/v2/positions";
pub const V2_USER_STATS_PATH: &str = "/v2/user-stats";
pub const V2_USER_PNL_PATH: &str = "/v2/user-pnl";
pub const MAX_ECONOMICS_PAGE_LIMIT: usize = 1_000;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// This reader reports venue-published values; it does not verify them on-chain.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EconomicsSource {
    VenueReported,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ResponseEvidence {
    pub source: EconomicsSource,
    /// Route path used (one of the three v2 constants in this module).
    pub route_path: String,
    pub request_started_at: DateTime<Utc>,
    pub retrieved_at: DateTime<Utc>,
    /// HTTP freshness headers as served; their absence remains unknown.
    pub response_age: Option<String>,
    pub response_date: Option<String>,
    pub cache_control: Option<String>,
    /// Exact query key/value pairs sent for this request.
    pub request_params: Vec<(String, String)>,
    /// Exact successful HTTP response bytes, before JSON parsing.
    pub raw_body: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PositionsPage {
    pub evidence: ResponseEvidence,
    pub rows: Vec<PositionRow>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
/// One raw venue position row with a small identity/economics projection.
/// The projected economic fields are unvalidated provider atoms.
pub struct PositionRow {
    pub proxy_wallet: Option<String>,
    pub token_id: Option<String>,
    pub condition_id: Option<String>,
    pub economics: PositionEconomics,
    /// Complete vendor row, including fields not projected above.
    pub raw: Value,
}

/// Raw, unvalidated venue atoms. JSON null and malformed scalar values are
/// retained as received; these fields are not verified or suitable for money
/// arithmetic. Use ResponseEvidence::raw_body as the exact decimal record.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default)]
pub struct PositionEconomics {
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub avg_price: Option<Value>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub entry_cost_usdc: Option<Value>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub entry_fees_usdc: Option<Value>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub total_cost_usdc: Option<Value>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub realized_pnl: Option<Value>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub unrealized_pnl: Option<Value>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub total_pnl: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct UserStats {
    pub evidence: ResponseEvidence,
    /// `None` means the API returned `data: null` (unknown wallet).
    /// A present object retains nullable fields such as `join_date` and
    /// `all_time_pnl` in its raw form.
    pub data: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct UserPnlSeries {
    pub evidence: ResponseEvidence,
    pub proxy_wallet: Option<String>,
    pub interval: Option<String>,
    pub fidelity: Option<String>,
    pub source_fidelity: Option<String>,
    pub points: Vec<PnlPoint>,
    /// Full `data` object, including fields added by the venue in future.
    pub raw_data: Value,
}

/// Unvalidated provider atoms for one PnL observation. Values remain JSON
/// values, including nulls; this projection is not verified money data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PnlPoint {
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub timestamp: Option<Value>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub realized_pnl: Option<Value>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub unrealized_pnl: Option<Value>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub economic_pnl: Option<Value>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub settled_pnl: Option<Value>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub cashflow_net: Option<Value>,
    /// Complete vendor point. Values are unvalidated provider atoms;
    /// nullable atoms remain JSON null, not zero. Do not use them as verified
    /// money inputs. Exact decimal spelling is in the raw response.
    pub raw: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PositionsRequest {
    pub user: String,
    pub limit: usize,
    pub cursor: Option<String>,
    pub status: Option<String>,
    pub condition: Option<String>,
    pub event_id: Option<String>,
    pub title: Option<String>,
    pub filter_type: Option<String>,
    pub filter_amount: Option<String>,
    pub include_archived: Option<bool>,
    pub sort_by: Option<String>,
    pub sort_direction: Option<String>,
    pub start: Option<i64>,
    pub end: Option<i64>,
}

impl PositionsRequest {
    #[must_use]
    pub fn new(user: impl Into<String>, limit: usize) -> Self {
        Self {
            user: user.into(),
            limit,
            cursor: None,
            status: None,
            condition: None,
            event_id: None,
            title: None,
            filter_type: None,
            filter_amount: None,
            include_archived: None,
            sort_by: None,
            sort_direction: None,
            start: None,
            end: None,
        }
    }

    /// Return a copy for the next page while retaining every filter.
    #[must_use]
    pub fn with_cursor(&self, cursor: impl Into<String>) -> Self {
        let mut next = self.clone();
        next.cursor = Some(cursor.into());
        next
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct UserPnlRequest {
    pub user: String,
    pub interval: Option<String>,
    pub fidelity: Option<String>,
}

impl UserPnlRequest {
    #[must_use]
    pub fn new(user: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            interval: None,
            fidelity: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EconomicsError {
    #[error("Data API wallet must be a 0x-prefixed 20-byte address")]
    InvalidUser,
    #[error("Data API positions limit must be in 1..={MAX_ECONOMICS_PAGE_LIMIT}, got {0}")]
    InvalidLimit(usize),
    #[error("Data API positions rejects include_archived=true with status=CLOSED")]
    InvalidPositionFilters,
    #[error("Data API endpoint must use HTTPS (loopback HTTP only for local tests)")]
    InvalidEndpoint,
    #[error("Data API request failed")]
    RequestFailed,
    #[error("Data API request or response body exceeded 30 seconds")]
    Timeout,
    #[error("Data API response exceeded the size limit")]
    ResponseTooLarge,
    #[error("Data API response could not be read")]
    ResponseUnreadable,
    #[error("Data API returned http {status} (retry after {retry_after:?})")]
    HttpStatus {
        status: u16,
        retry_after: Option<String>,
        venue_error: Option<Box<VenueErrorBody>>,
    },
    #[error("Data API response was not a valid positions envelope")]
    InvalidPositionsEnvelope,
    #[error("Data API response was not a valid user-stats envelope")]
    InvalidUserStatsEnvelope,
    #[error("Data API response was not a valid user-PnL envelope")]
    InvalidUserPnlEnvelope,
}

/// Structured error fields documented by the production Data API OpenAPI.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct VenueErrorBody {
    pub error: String,
    pub code: String,
    pub retryable: bool,
    pub trace_id: String,
    #[serde(default)]
    pub parameter: Option<String>,
}

/// Read only the three wallet-economics routes used for published economics.
/// The caller supplies its client; this type has no credentials, retries, or
/// mutable state.
#[derive(Clone, Debug)]
pub struct EconomicsReader {
    client: reqwest::Client,
    base_url: String,
}

impl EconomicsReader {
    /// # Errors
    /// Returns `InvalidEndpoint` for a malformed or non-HTTPS, non-loopback URL.
    pub fn new(
        client: reqwest::Client,
        base_url: impl Into<String>,
    ) -> Result<Self, EconomicsError> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        validate_endpoint(&base_url)?;
        Ok(Self { client, base_url })
    }

    /// Fetch one positions page. Every filter remains in `request_params` and
    /// `with_cursor` changes only the cursor for a subsequent page.
    pub async fn positions(
        &self,
        request: &PositionsRequest,
    ) -> Result<PositionsPage, EconomicsError> {
        validate_user(&request.user)?;
        if !(1..=MAX_ECONOMICS_PAGE_LIMIT).contains(&request.limit) {
            return Err(EconomicsError::InvalidLimit(request.limit));
        }
        if request.status.as_deref() == Some("CLOSED") && request.include_archived == Some(true) {
            return Err(EconomicsError::InvalidPositionFilters);
        }
        let mut params = vec![
            ("user".to_owned(), request.user.clone()),
            ("limit".to_owned(), request.limit.to_string()),
        ];
        push_opt(&mut params, "cursor", request.cursor.as_deref());
        push_opt(&mut params, "status", request.status.as_deref());
        push_opt(&mut params, "condition", request.condition.as_deref());
        push_opt(&mut params, "event_id", request.event_id.as_deref());
        push_opt(&mut params, "title", request.title.as_deref());
        push_opt(&mut params, "filter_type", request.filter_type.as_deref());
        push_opt(
            &mut params,
            "filter_amount",
            request.filter_amount.as_deref(),
        );
        if let Some(value) = request.include_archived {
            params.push(("include_archived".to_owned(), value.to_string()));
        }
        push_opt(&mut params, "sort_by", request.sort_by.as_deref());
        push_opt(
            &mut params,
            "sort_direction",
            request.sort_direction.as_deref(),
        );
        if let Some(value) = request.start {
            params.push(("start".to_owned(), value.to_string()));
        }
        if let Some(value) = request.end {
            params.push(("end".to_owned(), value.to_string()));
        }

        let response = self.get(V2_POSITIONS_PATH, &params).await?;
        let envelope: PositionsEnvelope = serde_json::from_slice(&response.body)
            .map_err(|_| EconomicsError::InvalidPositionsEnvelope)?;
        let next_cursor = match envelope.pagination.next_cursor {
            Value::Null => None,
            Value::String(cursor) if !cursor.trim().is_empty() => Some(cursor),
            _ => return Err(EconomicsError::InvalidPositionsEnvelope),
        };
        if envelope.pagination.has_more != next_cursor.is_some() {
            return Err(EconomicsError::InvalidPositionsEnvelope);
        }
        let rows = envelope
            .data
            .into_iter()
            .map(parse_position_row)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PositionsPage {
            evidence: evidence(V2_POSITIONS_PATH, params, response),
            rows,
            next_cursor,
            has_more: envelope.pagination.has_more,
        })
    }

    /// Fetch one user profile-statistics object; API `data: null` is preserved.
    pub async fn user_stats(&self, user: &str) -> Result<UserStats, EconomicsError> {
        validate_user(user)?;
        let params = vec![("user".to_owned(), user.to_owned())];
        let response = self.get(V2_USER_STATS_PATH, &params).await?;
        let envelope: DataEnvelope = serde_json::from_slice(&response.body)
            .map_err(|_| EconomicsError::InvalidUserStatsEnvelope)?;
        if !envelope.data.is_null() && !envelope.data.is_object() {
            return Err(EconomicsError::InvalidUserStatsEnvelope);
        }
        Ok(UserStats {
            evidence: evidence(V2_USER_STATS_PATH, params, response),
            data: (!envelope.data.is_null()).then_some(envelope.data),
        })
    }

    /// Fetch the cumulative PnL series at the requested venue interval/grid.
    pub async fn user_pnl(
        &self,
        request: &UserPnlRequest,
    ) -> Result<UserPnlSeries, EconomicsError> {
        validate_user(&request.user)?;
        let mut params = vec![("user".to_owned(), request.user.clone())];
        push_opt(&mut params, "interval", request.interval.as_deref());
        push_opt(&mut params, "fidelity", request.fidelity.as_deref());
        let response = self.get(V2_USER_PNL_PATH, &params).await?;
        let envelope: DataEnvelope = serde_json::from_slice(&response.body)
            .map_err(|_| EconomicsError::InvalidUserPnlEnvelope)?;
        let data = envelope.data;
        let Some(object) = data.as_object() else {
            return Err(EconomicsError::InvalidUserPnlEnvelope);
        };
        let points_value = object
            .get("points")
            .and_then(Value::as_array)
            .ok_or(EconomicsError::InvalidUserPnlEnvelope)?;
        let points = points_value
            .iter()
            .map(parse_pnl_point)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(UserPnlSeries {
            evidence: evidence(V2_USER_PNL_PATH, params, response),
            proxy_wallet: string_field(object, "proxy_wallet"),
            interval: string_field(object, "interval"),
            fidelity: string_field(object, "fidelity"),
            source_fidelity: string_field(object, "source_fidelity"),
            points,
            raw_data: data,
        })
    }

    async fn get(
        &self,
        path: &str,
        params: &[(String, String)],
    ) -> Result<RawHttpResponse, EconomicsError> {
        self.get_with_timeout(path, params, REQUEST_TIMEOUT).await
    }

    async fn get_with_timeout(
        &self,
        path: &str,
        params: &[(String, String)],
        timeout: Duration,
    ) -> Result<RawHttpResponse, EconomicsError> {
        let endpoint = format!("{}{path}", self.base_url);
        let url = reqwest::Url::parse(&endpoint).map_err(|_| EconomicsError::InvalidEndpoint)?;
        let work = async {
            let request_started_at = Utc::now();
            let mut response = self
                .client
                .get(url)
                .query(params)
                .send()
                .await
                .map_err(|_| EconomicsError::RequestFailed)?;
            let status = response.status();
            if !status.is_success() {
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let bytes = read_body(&mut response).await?;
                let venue_error = serde_json::from_slice::<VenueErrorBody>(&bytes)
                    .ok()
                    .map(Box::new);
                return Err(EconomicsError::HttpStatus {
                    status: status.as_u16(),
                    retry_after,
                    venue_error,
                });
            }
            let response_age = header_value(&response, reqwest::header::AGE);
            let response_date = header_value(&response, reqwest::header::DATE);
            let cache_control = header_value(&response, reqwest::header::CACHE_CONTROL);
            let bytes = read_body(&mut response).await?;
            Ok(RawHttpResponse {
                body: bytes,
                request_started_at,
                retrieved_at: Utc::now(),
                response_age,
                response_date,
                cache_control,
            })
        };
        tokio::time::timeout(timeout, work)
            .await
            .map_err(|_| EconomicsError::Timeout)?
    }
}

fn validate_user(user: &str) -> Result<(), EconomicsError> {
    let address = user.strip_prefix("0x").ok_or(EconomicsError::InvalidUser)?;
    if address.len() != 40 || !address.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EconomicsError::InvalidUser);
    }
    Ok(())
}

fn validate_endpoint(base_url: &str) -> Result<(), EconomicsError> {
    let url = reqwest::Url::parse(base_url).map_err(|_| EconomicsError::InvalidEndpoint)?;
    let allowed_transport = url.scheme() == "https"
        || (url.scheme() == "http"
            && url
                .host_str()
                .is_some_and(|host| host == "localhost" || host == "127.0.0.1" || host == "[::1]"));
    let has_userinfo = base_url
        .split_once("://")
        .and_then(|(_, remainder)| remainder.split(['/', '?', '#']).next())
        .is_some_and(|authority| authority.contains('@'));
    if allowed_transport
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && !has_userinfo
    {
        Ok(())
    } else {
        Err(EconomicsError::InvalidEndpoint)
    }
}

async fn read_body(response: &mut reqwest::Response) -> Result<Vec<u8>, EconomicsError> {
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RESPONSE_BYTES as u64)
    {
        return Err(EconomicsError::ResponseTooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| EconomicsError::ResponseUnreadable)?
    {
        if chunk.len() > MAX_RESPONSE_BYTES - body.len() {
            return Err(EconomicsError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn push_opt(params: &mut Vec<(String, String)>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        params.push((key.to_owned(), value.to_owned()));
    }
}

#[derive(Debug, PartialEq)]
struct RawHttpResponse {
    body: Vec<u8>,
    request_started_at: DateTime<Utc>,
    retrieved_at: DateTime<Utc>,
    response_age: Option<String>,
    response_date: Option<String>,
    cache_control: Option<String>,
}

fn evidence(
    route_path: &str,
    params: Vec<(String, String)>,
    response: RawHttpResponse,
) -> ResponseEvidence {
    ResponseEvidence {
        source: EconomicsSource::VenueReported,
        route_path: route_path.to_owned(),
        request_started_at: response.request_started_at,
        retrieved_at: response.retrieved_at,
        response_age: response.response_age,
        response_date: response.response_date,
        cache_control: response.cache_control,
        request_params: params,
        raw_body: response.body,
    }
}

fn header_value(
    response: &reqwest::Response,
    header: reqwest::header::HeaderName,
) -> Option<String> {
    response
        .headers()
        .get(header)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn parse_position_row(raw: Value) -> Result<PositionRow, EconomicsError> {
    let Some(object) = raw.as_object() else {
        return Err(EconomicsError::InvalidPositionsEnvelope);
    };
    Ok(PositionRow {
        proxy_wallet: string_field(object, "proxy_wallet"),
        token_id: string_field(object, "token_id"),
        condition_id: string_field(object, "condition_id"),
        economics: PositionEconomics {
            avg_price: raw_field(object, "avg_price"),
            entry_cost_usdc: raw_field(object, "entry_cost_usdc"),
            entry_fees_usdc: raw_field(object, "entry_fees_usdc"),
            total_cost_usdc: raw_field(object, "total_cost_usdc"),
            realized_pnl: raw_field(object, "realized_pnl"),
            unrealized_pnl: raw_field(object, "unrealized_pnl"),
            total_pnl: raw_field(object, "total_pnl"),
        },
        raw,
    })
}

fn parse_pnl_point(raw: &Value) -> Result<PnlPoint, EconomicsError> {
    let Some(object) = raw.as_object() else {
        return Err(EconomicsError::InvalidUserPnlEnvelope);
    };
    Ok(PnlPoint {
        timestamp: raw_field(object, "timestamp"),
        realized_pnl: raw_field(object, "realized_pnl"),
        unrealized_pnl: raw_field(object, "unrealized_pnl"),
        economic_pnl: raw_field(object, "economic_pnl"),
        settled_pnl: raw_field(object, "settled_pnl"),
        cashflow_net: raw_field(object, "cashflow_net"),
        raw: raw.clone(),
    })
}

fn raw_field(object: &Map<String, Value>, key: &str) -> Option<Value> {
    object.get(key).cloned()
}

fn deserialize_present_value<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

fn string_field(object: &Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).and_then(Value::as_str).map(str::to_owned)
}

#[derive(Deserialize)]
struct PositionsEnvelope {
    data: Vec<Value>,
    pagination: PositionsPagination,
}

#[derive(Deserialize)]
struct PositionsPagination {
    next_cursor: Value,
    has_more: bool,
}

#[derive(Deserialize)]
struct DataEnvelope {
    data: Value,
}

#[cfg(test)]
mod tests {
    use axum::{
        Json, Router,
        body::{Body, Bytes},
        extract::{Query, State},
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::get,
    };
    use serde_json::{Value, json};
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };
    use tokio::net::TcpListener;

    use super::*;

    type SeenRequests = Vec<(String, BTreeMap<String, String>)>;

    #[derive(Clone, Default)]
    struct Seen(Arc<Mutex<SeenRequests>>);

    async fn positions_route(
        State(seen): State<Seen>,
        Query(query): Query<BTreeMap<String, String>>,
    ) -> impl IntoResponse {
        let cursor = query.get("cursor").cloned().unwrap_or_default();
        let malformed_page = query.get("user").map(String::as_str) == Some(MALFORMED_PAGE_USER);
        seen.0.lock().unwrap().push(("positions".to_owned(), query));
        let body = if cursor.is_empty() {
            if malformed_page {
                return Json(json!({
                    "data": [],
                    "pagination": {"next_cursor": null, "has_more": true}
                }));
            }
            json!({
                "data": [{
                    "proxy_wallet": "0x1111111111111111111111111111111111111111",
                    "token_id": "42", "condition_id": "0xabc",
                    "avg_price": 0.42, "entry_cost_usdc": 1.25,
                    "entry_fees_usdc": null, "total_cost_usdc": "malformed",
                    "realized_pnl": 0.10, "unrealized_pnl": null, "total_pnl": 0.10
                }],
                "pagination": {"next_cursor": "next+cursor/==", "has_more": true}
            })
        } else {
            json!({"data": [], "pagination": {"next_cursor": null, "has_more": false}})
        };
        Json(body)
    }

    async fn stats_route(
        Query(query): Query<BTreeMap<String, String>>,
    ) -> axum::response::Response {
        match query.get("user").map(String::as_str) {
            Some(RATE_LIMIT_USER) => error_route(),
            Some(MISSING_USER) => StatusCode::NOT_FOUND.into_response(),
            Some(OVERSIZED_USER) => oversized_route(),
            Some(SLOW_USER) => slow_body_response(),
            _ => stats_response(),
        }
    }

    fn stats_response() -> axum::response::Response {
        let mut headers = HeaderMap::new();
        headers.insert("age", "12".parse().unwrap());
        headers.insert("date", "Tue, 13 Oct 2026 12:00:00 GMT".parse().unwrap());
        headers.insert("cache-control", "max-age=5".parse().unwrap());
        (
            StatusCode::OK,
            headers,
            Bytes::from_static(br#"{"data":null}"#),
        )
            .into_response()
    }

    async fn pnl_route() -> impl IntoResponse {
        (
            StatusCode::OK,
            Bytes::from_static(br#"{"data":{"proxy_wallet":"0x1111111111111111111111111111111111111111","interval":"1w","fidelity":"1d","source_fidelity":"1d","points":[{"timestamp":10,"realized_pnl":0.125,"unrealized_pnl":null,"economic_pnl":null,"settled_pnl":0,"cashflow_net":null}]}}"#),
        )
    }

    fn error_route() -> axum::response::Response {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", "7".parse().unwrap());
        (
            StatusCode::TOO_MANY_REQUESTS,
            headers,
            Json(json!({
                "error": "busy", "code": "rate_limited", "retryable": true,
                "trace_id": "trace-123", "parameter": null
            })),
        )
            .into_response()
    }

    fn oversized_route() -> axum::response::Response {
        Bytes::from(vec![b'x'; MAX_RESPONSE_BYTES + 1]).into_response()
    }

    fn slow_body_response() -> axum::response::Response {
        let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(1);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = sender
                .send(Ok(Bytes::from_static(br#"{"data":null}"#)))
                .await;
        });
        axum::response::Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from_stream(
                tokio_stream::wrappers::ReceiverStream::new(receiver),
            ))
            .unwrap()
    }

    async fn server() -> (String, Seen) {
        let seen = Seen::default();
        let app = Router::new()
            .route(V2_POSITIONS_PATH, get(positions_route))
            .route(V2_USER_STATS_PATH, get(stats_route))
            .route(V2_USER_PNL_PATH, get(pnl_route))
            .with_state(seen.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), seen)
    }

    const USER: &str = "0x1111111111111111111111111111111111111111";
    const RATE_LIMIT_USER: &str = "0x2222222222222222222222222222222222222222";
    const MISSING_USER: &str = "0x3333333333333333333333333333333333333333";
    const OVERSIZED_USER: &str = "0x4444444444444444444444444444444444444444";
    const MALFORMED_PAGE_USER: &str = "0x5555555555555555555555555555555555555555";
    const SLOW_USER: &str = "0x6666666666666666666666666666666666666666";

    #[tokio::test]
    async fn cursor_walk_repeats_filters_and_keeps_evidence_and_nulls() {
        let (base, seen) = server().await;
        let reader = EconomicsReader::new(reqwest::Client::new(), base).unwrap();
        let mut request = PositionsRequest::new(USER, 17);
        request.status = Some("CLOSED".to_owned());
        request.title = Some("sample title".to_owned());
        request.filter_type = Some("TOKENS".to_owned());
        request.filter_amount = Some("0.01".to_owned());
        request.sort_by = Some("REALIZED_PNL".to_owned());
        request.sort_direction = Some("DESC".to_owned());
        let first = reader.positions(&request).await.unwrap();
        assert!(first.has_more);
        assert_eq!(first.next_cursor.as_deref(), Some("next+cursor/=="));
        assert_eq!(first.evidence.source, EconomicsSource::VenueReported);
        assert_eq!(first.evidence.route_path, V2_POSITIONS_PATH);
        assert!(first.evidence.request_started_at <= first.evidence.retrieved_at);
        assert!(!first.evidence.retrieved_at.timestamp().is_negative());
        assert!(
            std::str::from_utf8(&first.evidence.raw_body)
                .unwrap()
                .contains("entry_fees_usdc")
        );
        let economics = &first.rows[0].economics;
        assert_eq!(economics.entry_fees_usdc, Some(Value::Null));
        assert_eq!(economics.unrealized_pnl, Some(Value::Null));
        assert_eq!(economics.total_cost_usdc, Some(json!("malformed")));

        let second = reader
            .positions(&request.with_cursor(first.next_cursor.unwrap()))
            .await
            .unwrap();
        assert!(!second.has_more);
        let requests = seen.0.lock().unwrap();
        let first_params = &requests[0].1;
        let second_params = &requests[1].1;
        for key in [
            "user",
            "status",
            "title",
            "filter_type",
            "filter_amount",
            "sort_by",
            "sort_direction",
            "limit",
        ] {
            assert_eq!(first_params.get(key), second_params.get(key));
        }
        assert!(!first_params.contains_key("cursor"));
        assert_eq!(
            second_params.get("cursor").map(String::as_str),
            Some("next+cursor/==")
        );
    }

    #[tokio::test]
    async fn stats_null_and_pnl_nullable_atoms_are_preserved() {
        let (base, _) = server().await;
        let reader = EconomicsReader::new(reqwest::Client::new(), base).unwrap();
        let stats = reader.user_stats(USER).await.unwrap();
        assert_eq!(stats.data, None);
        assert_eq!(stats.evidence.raw_body, br#"{"data":null}"#);
        assert_eq!(stats.evidence.response_age.as_deref(), Some("12"));
        assert_eq!(
            stats.evidence.response_date.as_deref(),
            Some("Tue, 13 Oct 2026 12:00:00 GMT")
        );
        assert_eq!(stats.evidence.cache_control.as_deref(), Some("max-age=5"));
        let mut request = UserPnlRequest::new(USER);
        request.interval = Some("1w".to_owned());
        request.fidelity = Some("1d".to_owned());
        let pnl = reader.user_pnl(&request).await.unwrap();
        assert_eq!(pnl.source_fidelity.as_deref(), Some("1d"));
        assert_eq!(pnl.points[0].unrealized_pnl, Some(Value::Null));
        assert_eq!(pnl.points[0].cashflow_net, Some(Value::Null));
        assert_eq!(pnl.points[0].realized_pnl, Some(json!(0.125)));
        assert!(
            pnl.evidence
                .raw_body
                .windows(5)
                .any(|window| window == b"0.125")
        );
    }

    #[tokio::test]
    async fn structured_rate_limit_error_keeps_retry_after_and_trace() {
        let (base, _) = server().await;
        let reader = EconomicsReader::new(reqwest::Client::new(), base).unwrap();
        let error = reader.user_stats(RATE_LIMIT_USER).await.unwrap_err();
        assert_eq!(
            error,
            EconomicsError::HttpStatus {
                status: 429,
                retry_after: Some("7".to_owned()),
                venue_error: Some(Box::new(VenueErrorBody {
                    error: "busy".to_owned(),
                    code: "rate_limited".to_owned(),
                    retryable: true,
                    trace_id: "trace-123".to_owned(),
                    parameter: None,
                })),
            }
        );
    }

    #[tokio::test]
    async fn malformed_envelopes_and_non_success_status_are_errors() {
        let malformed = parse_position_row(json!("not an object"));
        assert_eq!(malformed, Err(EconomicsError::InvalidPositionsEnvelope));
        assert_eq!(
            parse_pnl_point(&json!(null)),
            Err(EconomicsError::InvalidUserPnlEnvelope)
        );

        let (base, _) = server().await;
        let reader = EconomicsReader::new(reqwest::Client::new(), base).unwrap();
        assert_eq!(
            reader.user_stats(MISSING_USER).await.unwrap_err(),
            EconomicsError::HttpStatus {
                status: 404,
                retry_after: None,
                venue_error: None,
            }
        );
    }

    #[tokio::test]
    async fn request_limits_and_wallet_validation_fail_before_network() {
        let reader = EconomicsReader::new(reqwest::Client::new(), "http://127.0.0.1:1").unwrap();
        assert_eq!(
            reader.user_stats("not-a-wallet").await,
            Err(EconomicsError::InvalidUser)
        );
        assert_eq!(
            reader.positions(&PositionsRequest::new(USER, 0)).await,
            Err(EconomicsError::InvalidLimit(0))
        );
        let mut closed = PositionsRequest::new(USER, 1);
        closed.status = Some("CLOSED".to_owned());
        closed.include_archived = Some(true);
        assert_eq!(
            reader.positions(&closed).await,
            Err(EconomicsError::InvalidPositionFilters)
        );
    }

    #[tokio::test]
    async fn response_body_cap_is_enforced() {
        let (base, _) = server().await;
        let reader = EconomicsReader::new(reqwest::Client::new(), base).unwrap();
        assert_eq!(
            reader.user_stats(OVERSIZED_USER).await,
            Err(EconomicsError::ResponseTooLarge)
        );
    }

    #[tokio::test]
    async fn whole_request_deadline_includes_response_body() {
        let (base, _) = server().await;
        let reader = EconomicsReader::new(reqwest::Client::new(), base).unwrap();
        let params = vec![("user".to_owned(), SLOW_USER.to_owned())];
        assert_eq!(
            reader
                .get_with_timeout(V2_USER_STATS_PATH, &params, Duration::from_millis(10),)
                .await,
            Err(EconomicsError::Timeout)
        );
    }

    #[tokio::test]
    async fn malformed_pagination_is_rejected() {
        let (base, _) = server().await;
        let reader = EconomicsReader::new(reqwest::Client::new(), base).unwrap();
        assert_eq!(
            reader
                .positions(&PositionsRequest::new(MALFORMED_PAGE_USER, 1))
                .await,
            Err(EconomicsError::InvalidPositionsEnvelope)
        );
    }

    #[test]
    fn endpoint_requires_clean_root_base_and_allows_loopback_fixtures() {
        assert!(EconomicsReader::new(reqwest::Client::new(), "http://127.0.0.1:8080").is_ok());
        for endpoint in [
            "http://127.0.0.1:8080/base",
            "http://user@127.0.0.1:8080",
            "http://@127.0.0.1:8080",
            "https://data-api.polymarket.com?token=x",
            "https://data-api.polymarket.com#fragment",
        ] {
            assert!(matches!(
                EconomicsReader::new(reqwest::Client::new(), endpoint),
                Err(EconomicsError::InvalidEndpoint)
            ));
        }
    }

    #[test]
    fn capture_dtos_round_trip_nulls_and_snake_case_source() {
        let economics: PositionEconomics =
            serde_json::from_value(json!({"entry_fees_usdc": null})).unwrap();
        assert_eq!(economics.entry_fees_usdc, Some(Value::Null));
        let economics = PositionEconomics {
            entry_fees_usdc: Some(Value::Null),
            realized_pnl: Some(json!(0.125)),
            ..PositionEconomics::default()
        };
        let economics_copy: PositionEconomics =
            serde_json::from_value(serde_json::to_value(&economics).unwrap()).unwrap();
        assert_eq!(economics_copy, economics);

        let point = PnlPoint {
            timestamp: Some(json!(10)),
            realized_pnl: Some(json!(0.125)),
            unrealized_pnl: None,
            economic_pnl: Some(Value::Null),
            settled_pnl: None,
            cashflow_net: Some(Value::Null),
            raw: json!({
                "timestamp": 10,
                "realized_pnl": 0.125,
                "economic_pnl": null,
                "cashflow_net": null
            }),
        };
        let point_copy: PnlPoint =
            serde_json::from_value(serde_json::to_value(&point).unwrap()).unwrap();
        assert_eq!(point_copy, point);
        let source = serde_json::to_value(EconomicsSource::VenueReported).unwrap();
        assert_eq!(source, json!("venue_reported"));
    }
}
