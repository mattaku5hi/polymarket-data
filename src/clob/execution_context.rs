//! Bounded, read-only acquisition of market metadata and one order book.
//!
//! These sequential provider reads are observations, not an atomic exchange
//! snapshot, canonical identity proof, fee quote, or execution guarantee.

use std::{net::IpAddr, time::Duration};

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::Deserialize;
use serde_json::{Value, value::RawValue};

use super::{BookObservation, parse_book};

const MAX_CONTEXT_BODY_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionContextStage {
    GammaMarket,
    ClobMarket,
    Book,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionContextError {
    #[error("execution context input is invalid")]
    InvalidInput,
    #[error("execution context HTTP client could not be built")]
    ClientBuild,
    #[error("execution context request budget exhausted")]
    RequestBudgetExceeded,
    #[error("execution context timed out at {0:?}")]
    Timeout(ExecutionContextStage),
    #[error("execution context request failed at {0:?}")]
    RequestFailed(ExecutionContextStage),
    #[error("execution context was rate limited at {stage:?}")]
    RateLimited {
        stage: ExecutionContextStage,
        retry_after_seconds: Option<u64>,
    },
    #[error("execution context returned HTTP {status} at {stage:?}")]
    HttpStatus {
        stage: ExecutionContextStage,
        status: u16,
    },
    #[error("execution context response exceeded 2 MiB at {0:?}")]
    ResponseTooLarge(ExecutionContextStage),
    #[error("execution context response could not be read at {0:?}")]
    ResponseUnreadable(ExecutionContextStage),
    #[error("execution context response was malformed at {0:?}")]
    MalformedResponse(ExecutionContextStage),
    #[error("execution context identity did not match the request at {0:?}")]
    IdentityMismatch(ExecutionContextStage),
    #[error("execution context market is unsupported or not accepting orders")]
    MarketUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionContextValidityError {
    #[error("execution context max age is invalid")]
    InvalidMaxAge,
    #[error("execution context has expired under the caller max age")]
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservedMarketVersion {
    V1,
    V2,
}

/// Endpoint-documented minimum-size units; no collateral-token or FX binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservedMinimumOrderSizeUnit {
    DocumentedUsdcNotional,
    Shares,
    Unspecified,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionContextRequest {
    pub api_condition_id: String,
    pub selected_asset_id: String,
    pub max_requests: usize,
    pub total_timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionContextOutcome {
    index: usize,
    label: String,
    asset_id: String,
}

impl ExecutionContextOutcome {
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
    #[must_use]
    pub fn asset_id(&self) -> &str {
        &self.asset_id
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExecutionContextObservation {
    api_condition_id: String,
    selected_asset_id: String,
    selected_outcome_index: usize,
    outcomes: [ExecutionContextOutcome; 2],
    protocol_version: ObservedMarketVersion,
    min_order_size: String,
    min_tick_size: String,
    gamma_min_order_size: Option<String>,
    gamma_min_tick_size: Option<String>,
    book_min_order_size: Option<String>,
    book_min_tick_size: Option<String>,
    maker_base_fee_bps: Option<u64>,
    taker_base_fee_bps: Option<u64>,
    fee_curve_rate_lexeme: Option<String>,
    fee_curve_exponent_lexeme: Option<String>,
    fee_curve_taker_only: Option<bool>,
    gamma_raw_body: String,
    clob_market_raw_body: String,
    book_raw_body: String,
    book: BookObservation,
    started_at: DateTime<Utc>,
    started_monotonic: tokio::time::Instant,
    completed_at: DateTime<Utc>,
    elapsed: Duration,
    request_count: usize,
}

impl ExecutionContextObservation {
    #[must_use]
    pub fn api_condition_id(&self) -> &str {
        &self.api_condition_id
    }
    #[must_use]
    pub fn selected_asset_id(&self) -> &str {
        &self.selected_asset_id
    }
    #[must_use]
    pub const fn selected_outcome_index(&self) -> usize {
        self.selected_outcome_index
    }
    #[must_use]
    pub fn outcomes(&self) -> &[ExecutionContextOutcome; 2] {
        &self.outcomes
    }
    #[must_use]
    pub const fn protocol_version(&self) -> ObservedMarketVersion {
        self.protocol_version
    }
    #[must_use]
    pub fn min_order_size(&self) -> &str {
        &self.min_order_size
    }
    /// Compact CLOB `mos` has no documented unit.
    #[must_use]
    pub const fn min_order_size_unit(&self) -> ObservedMinimumOrderSizeUnit {
        ObservedMinimumOrderSizeUnit::Unspecified
    }
    /// Gamma documentation labels `orderMinSize` as USDC notional.
    #[must_use]
    pub const fn gamma_min_order_size_unit(&self) -> ObservedMinimumOrderSizeUnit {
        ObservedMinimumOrderSizeUnit::DocumentedUsdcNotional
    }
    /// Book documentation labels `min_order_size` as a share quantity.
    #[must_use]
    pub const fn book_min_order_size_unit(&self) -> ObservedMinimumOrderSizeUnit {
        ObservedMinimumOrderSizeUnit::Shares
    }
    #[must_use]
    pub fn min_tick_size(&self) -> &str {
        &self.min_tick_size
    }
    #[must_use]
    pub fn gamma_min_order_size(&self) -> Option<&str> {
        self.gamma_min_order_size.as_deref()
    }
    #[must_use]
    pub fn gamma_min_tick_size(&self) -> Option<&str> {
        self.gamma_min_tick_size.as_deref()
    }
    #[must_use]
    pub fn book_min_order_size(&self) -> Option<&str> {
        self.book_min_order_size.as_deref()
    }
    #[must_use]
    pub fn book_min_tick_size(&self) -> Option<&str> {
        self.book_min_tick_size.as_deref()
    }
    #[must_use]
    pub const fn maker_base_fee_bps(&self) -> Option<u64> {
        self.maker_base_fee_bps
    }
    #[must_use]
    pub const fn taker_base_fee_bps(&self) -> Option<u64> {
        self.taker_base_fee_bps
    }
    #[must_use]
    pub fn fee_curve_rate_lexeme(&self) -> Option<&str> {
        self.fee_curve_rate_lexeme.as_deref()
    }
    #[must_use]
    pub fn fee_curve_exponent_lexeme(&self) -> Option<&str> {
        self.fee_curve_exponent_lexeme.as_deref()
    }
    #[must_use]
    pub const fn fee_curve_taker_only(&self) -> Option<bool> {
        self.fee_curve_taker_only
    }
    #[must_use]
    pub fn gamma_raw_body(&self) -> &str {
        &self.gamma_raw_body
    }
    #[must_use]
    pub fn clob_market_raw_body(&self) -> &str {
        &self.clob_market_raw_body
    }
    #[must_use]
    pub fn book_raw_body(&self) -> &str {
        &self.book_raw_body
    }
    #[must_use]
    pub fn book(&self) -> &BookObservation {
        &self.book
    }
    /// Returns the original local-acquisition deadline for this caller age.
    /// No vendor timestamp or later call changes the stored monotonic origin.
    pub fn local_valid_until(
        &self,
        max_age: Duration,
    ) -> Result<tokio::time::Instant, ExecutionContextValidityError> {
        if max_age.is_zero() {
            return Err(ExecutionContextValidityError::InvalidMaxAge);
        }
        let deadline = self
            .started_monotonic
            .checked_add(max_age)
            .ok_or(ExecutionContextValidityError::InvalidMaxAge)?;
        if tokio::time::Instant::now() >= deadline {
            return Err(ExecutionContextValidityError::Expired);
        }
        Ok(deadline)
    }
    #[must_use]
    pub fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }
    #[must_use]
    pub fn completed_at(&self) -> DateTime<Utc> {
        self.completed_at
    }
    #[must_use]
    pub const fn elapsed(&self) -> Duration {
        self.elapsed
    }
    #[must_use]
    pub const fn request_count(&self) -> usize {
        self.request_count
    }
}

pub struct ClobExecutionContextReader {
    client: reqwest::Client,
    clob_base_url: reqwest::Url,
    gamma_base_url: reqwest::Url,
}

impl ClobExecutionContextReader {
    /// Build a reader around caller-configured transport settings and endpoints.
    /// Redirects and reqwest retries are disabled for these bounded reads.
    pub fn with_client_builder(
        builder: reqwest::ClientBuilder,
        clob_base_url: &str,
        gamma_base_url: &str,
    ) -> Result<Self, ExecutionContextError> {
        let clob_base_url = validate_base_url(clob_base_url)?;
        let gamma_base_url = validate_base_url(gamma_base_url)?;
        let client = builder
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .map_err(|_| ExecutionContextError::ClientBuild)?;
        Ok(Self {
            client,
            clob_base_url,
            gamma_base_url,
        })
    }

    /// Acquire Gamma metadata, CLOB market details, then one selected book.
    /// Every request and body read shares the same request-attempt budget and
    /// absolute deadline. Cancellation drops the in-flight request immediately.
    pub async fn read_context(
        &self,
        request: &ExecutionContextRequest,
    ) -> Result<ExecutionContextObservation, ExecutionContextError> {
        validate_request(request)?;
        let started_monotonic = tokio::time::Instant::now();
        let deadline = started_monotonic
            .checked_add(request.total_timeout)
            .ok_or(ExecutionContextError::InvalidInput)?;
        let started_at = Utc::now();
        let mut request_count = 0;

        let mut gamma_url = endpoint(&self.gamma_base_url, "markets")?;
        gamma_url
            .query_pairs_mut()
            .append_pair("condition_ids", &request.api_condition_id);
        let gamma_body = self
            .get_body(
                gamma_url,
                ExecutionContextStage::GammaMarket,
                deadline,
                request.max_requests,
                &mut request_count,
            )
            .await?;
        check_deadline(deadline, ExecutionContextStage::GammaMarket)?;
        let gamma_text = std::str::from_utf8(&gamma_body).map_err(|_| {
            ExecutionContextError::MalformedResponse(ExecutionContextStage::GammaMarket)
        })?;
        let (version, outcomes, gamma_min_order_size, gamma_min_tick_size) =
            parse_gamma_market(gamma_text, request)?;

        let clob_url = market_info_endpoint(&self.clob_base_url, &request.api_condition_id)?;
        let clob_body = self
            .get_body(
                clob_url,
                ExecutionContextStage::ClobMarket,
                deadline,
                request.max_requests,
                &mut request_count,
            )
            .await?;
        check_deadline(deadline, ExecutionContextStage::ClobMarket)?;
        let clob_text = std::str::from_utf8(&clob_body).map_err(|_| {
            ExecutionContextError::MalformedResponse(ExecutionContextStage::ClobMarket)
        })?;
        let clob = parse_clob_market(
            clob_text,
            request,
            &outcomes,
            gamma_min_tick_size.as_deref(),
        )?;

        let mut book_url = endpoint(&self.clob_base_url, "book")?;
        book_url
            .query_pairs_mut()
            .append_pair("token_id", &request.selected_asset_id);
        let book_body = self
            .get_body(
                book_url,
                ExecutionContextStage::Book,
                deadline,
                request.max_requests,
                &mut request_count,
            )
            .await?;
        check_deadline(deadline, ExecutionContextStage::Book)?;
        let raw_book_body = String::from_utf8(book_body)
            .map_err(|_| ExecutionContextError::MalformedResponse(ExecutionContextStage::Book))?;
        let book_raw: Value = serde_json::from_str(&raw_book_body)
            .map_err(|_| ExecutionContextError::MalformedResponse(ExecutionContextStage::Book))?;
        let book = parse_book(book_raw, &request.selected_asset_id)
            .map_err(|_| ExecutionContextError::MalformedResponse(ExecutionContextStage::Book))?;
        if book.vendor_book().get("market").and_then(Value::as_str)
            != Some(request.api_condition_id.as_str())
        {
            return Err(ExecutionContextError::IdentityMismatch(
                ExecutionContextStage::Book,
            ));
        }
        let book_min_order_size = optional_decimal_text(
            book.vendor_book(),
            "min_order_size",
            ExecutionContextStage::Book,
        )?;
        let book_min_tick_size =
            optional_decimal_text(book.vendor_book(), "tick_size", ExecutionContextStage::Book)?;
        if book_min_tick_size.as_deref().is_some_and(|value| {
            Decimal::from_str_exact(value).ok() != Decimal::from_str_exact(&clob.min_tick_size).ok()
        }) {
            return Err(ExecutionContextError::IdentityMismatch(
                ExecutionContextStage::Book,
            ));
        }
        check_deadline(deadline, ExecutionContextStage::Book)?;

        let completed_at = Utc::now();
        Ok(ExecutionContextObservation {
            api_condition_id: request.api_condition_id.clone(),
            selected_asset_id: request.selected_asset_id.clone(),
            selected_outcome_index: outcomes
                .iter()
                .position(|outcome| outcome.asset_id == request.selected_asset_id)
                .expect("Gamma outcome selection validated"),
            outcomes,
            protocol_version: version,
            min_order_size: clob.min_order_size,
            min_tick_size: clob.min_tick_size,
            gamma_min_order_size,
            gamma_min_tick_size,
            book_min_order_size,
            book_min_tick_size,
            maker_base_fee_bps: clob.maker_base_fee_bps,
            taker_base_fee_bps: clob.taker_base_fee_bps,
            fee_curve_rate_lexeme: clob.fee_curve_rate_lexeme,
            fee_curve_exponent_lexeme: clob.fee_curve_exponent_lexeme,
            fee_curve_taker_only: clob.fee_curve_taker_only,
            gamma_raw_body: gamma_text.to_owned(),
            clob_market_raw_body: clob_text.to_owned(),
            book_raw_body: raw_book_body,
            book,
            started_at,
            started_monotonic,
            completed_at,
            elapsed: tokio::time::Instant::now() - started_monotonic,
            request_count,
        })
    }

    async fn get_body(
        &self,
        url: reqwest::Url,
        stage: ExecutionContextStage,
        deadline: tokio::time::Instant,
        max_requests: usize,
        request_count: &mut usize,
    ) -> Result<Vec<u8>, ExecutionContextError> {
        check_deadline(deadline, stage)?;
        if *request_count >= max_requests {
            return Err(ExecutionContextError::RequestBudgetExceeded);
        }
        *request_count += 1;
        let future = async {
            let mut response = self
                .client
                .get(url)
                .timeout(deadline.saturating_duration_since(tokio::time::Instant::now()))
                .send()
                .await
                .map_err(|error| request_error(error, stage, deadline))?;
            if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                return Err(ExecutionContextError::RateLimited {
                    stage,
                    retry_after_seconds: response
                        .headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.parse().ok()),
                });
            }
            if !response.status().is_success() {
                return Err(ExecutionContextError::HttpStatus {
                    stage,
                    status: response.status().as_u16(),
                });
            }
            if response
                .content_length()
                .is_some_and(|length| length > MAX_CONTEXT_BODY_BYTES as u64)
            {
                return Err(ExecutionContextError::ResponseTooLarge(stage));
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|error| {
                if error.is_timeout() || tokio::time::Instant::now() >= deadline {
                    ExecutionContextError::Timeout(stage)
                } else {
                    ExecutionContextError::ResponseUnreadable(stage)
                }
            })? {
                if chunk.len() > MAX_CONTEXT_BODY_BYTES - body.len() {
                    return Err(ExecutionContextError::ResponseTooLarge(stage));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(body)
        };
        tokio::time::timeout_at(deadline, future)
            .await
            .map_err(|_| ExecutionContextError::Timeout(stage))?
    }
}

#[derive(Debug)]
struct ParsedClobMarket {
    min_order_size: String,
    min_tick_size: String,
    maker_base_fee_bps: Option<u64>,
    taker_base_fee_bps: Option<u64>,
    fee_curve_rate_lexeme: Option<String>,
    fee_curve_exponent_lexeme: Option<String>,
    fee_curve_taker_only: Option<bool>,
}

fn validate_base_url(value: &str) -> Result<reqwest::Url, ExecutionContextError> {
    let url = reqwest::Url::parse(value).map_err(|_| ExecutionContextError::InvalidInput)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || (url.scheme() == "http" && is_loopback(&url)))
    {
        return Err(ExecutionContextError::InvalidInput);
    }
    Ok(url)
}

fn is_loopback(url: &reqwest::Url) -> bool {
    url.host_str().is_some_and(|host| {
        let ip_host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        host.eq_ignore_ascii_case("localhost")
            || ip_host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    })
}

fn request_error(
    error: reqwest::Error,
    stage: ExecutionContextStage,
    deadline: tokio::time::Instant,
) -> ExecutionContextError {
    if error.is_timeout() || tokio::time::Instant::now() >= deadline {
        ExecutionContextError::Timeout(stage)
    } else {
        ExecutionContextError::RequestFailed(stage)
    }
}

fn endpoint(base: &reqwest::Url, path: &str) -> Result<reqwest::Url, ExecutionContextError> {
    let base = format!("{}/", base.as_str().trim_end_matches('/'));
    reqwest::Url::parse(&base)
        .and_then(|url| url.join(path))
        .map_err(|_| ExecutionContextError::InvalidInput)
}

fn market_info_endpoint(
    base: &reqwest::Url,
    condition_id: &str,
) -> Result<reqwest::Url, ExecutionContextError> {
    let mut url = endpoint(base, "")?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| ExecutionContextError::InvalidInput)?;
        segments
            .pop_if_empty()
            .push("clob-markets")
            .push(condition_id);
    }
    Ok(url)
}

fn validate_request(request: &ExecutionContextRequest) -> Result<(), ExecutionContextError> {
    if !valid_selector(&request.api_condition_id, 256)
        || !valid_asset_id(&request.selected_asset_id)
        || request.total_timeout.is_zero()
    {
        return Err(ExecutionContextError::InvalidInput);
    }
    if request.max_requests == 0 {
        return Err(ExecutionContextError::InvalidInput);
    }
    if request.max_requests < 3 {
        return Err(ExecutionContextError::RequestBudgetExceeded);
    }
    Ok(())
}

fn valid_selector(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'x' | b'X'))
}

fn valid_asset_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.bytes().any(|byte| byte != b'0')
}

type ParsedGammaMarket = (
    ObservedMarketVersion,
    [ExecutionContextOutcome; 2],
    Option<String>,
    Option<String>,
);

fn parse_gamma_market(
    raw: &str,
    request: &ExecutionContextRequest,
) -> Result<ParsedGammaMarket, ExecutionContextError> {
    let rows: Vec<Box<RawValue>> = serde_json::from_str(raw).map_err(|_| {
        ExecutionContextError::MalformedResponse(ExecutionContextStage::GammaMarket)
    })?;
    let mut matches = Vec::new();
    for row in &rows {
        let value: Value = serde_json::from_str(row.get()).map_err(|_| {
            ExecutionContextError::MalformedResponse(ExecutionContextStage::GammaMarket)
        })?;
        let condition = value
            .get("conditionId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(ExecutionContextError::MalformedResponse(
                ExecutionContextStage::GammaMarket,
            ))?;
        if condition == request.api_condition_id {
            matches.push(row);
        }
    }
    if matches.len() != 1 {
        return Err(ExecutionContextError::IdentityMismatch(
            ExecutionContextStage::GammaMarket,
        ));
    }
    let market_raw = matches[0].get();
    let market: Value = serde_json::from_str(market_raw).map_err(|_| {
        ExecutionContextError::MalformedResponse(ExecutionContextStage::GammaMarket)
    })?;
    let version = match market.get("version").and_then(Value::as_str) {
        Some("v1") => ObservedMarketVersion::V1,
        Some("v2") => ObservedMarketVersion::V2,
        _ => return Err(ExecutionContextError::MarketUnavailable),
    };
    for (name, expected) in [
        ("active", true),
        ("closed", false),
        ("acceptingOrders", true),
        ("enableOrderBook", true),
    ] {
        if market.get(name).and_then(Value::as_bool) != Some(expected) {
            return Err(ExecutionContextError::MarketUnavailable);
        }
    }
    let labels = parse_string_array(
        market.get("outcomes"),
        "outcomes",
        ExecutionContextStage::GammaMarket,
    )?;
    if labels.len() != 2 || labels[0].is_empty() || labels[1].is_empty() || labels[0] == labels[1] {
        return Err(ExecutionContextError::MalformedResponse(
            ExecutionContextStage::GammaMarket,
        ));
    }
    let id_field = if version == ObservedMarketVersion::V1 {
        "clobTokenIds"
    } else {
        "positionIds"
    };
    let ids = parse_string_array(
        market.get(id_field),
        id_field,
        ExecutionContextStage::GammaMarket,
    )?;
    if ids.len() != 2 || ids[0] == ids[1] || ids.iter().any(|id| !valid_asset_id(id)) {
        return Err(ExecutionContextError::MalformedResponse(
            ExecutionContextStage::GammaMarket,
        ));
    }
    let selected_index = ids
        .iter()
        .position(|id| id == &request.selected_asset_id)
        .ok_or(ExecutionContextError::IdentityMismatch(
            ExecutionContextStage::GammaMarket,
        ))?;
    let outcomes = [
        ExecutionContextOutcome {
            index: 0,
            label: labels[0].clone(),
            asset_id: ids[0].clone(),
        },
        ExecutionContextOutcome {
            index: 1,
            label: labels[1].clone(),
            asset_id: ids[1].clone(),
        },
    ];
    debug_assert_eq!(outcomes[selected_index].asset_id, request.selected_asset_id);
    validate_gamma_fees(market_raw)?;
    let gamma_min_order_size =
        optional_decimal_text(&market, "orderMinSize", ExecutionContextStage::GammaMarket)?;
    let gamma_min_tick_size = optional_decimal_text(
        &market,
        "orderPriceMinTickSize",
        ExecutionContextStage::GammaMarket,
    )?;
    if let Some(enabled) = market.get("feesEnabled") {
        if !enabled.is_null() && !enabled.is_boolean() {
            return Err(ExecutionContextError::MalformedResponse(
                ExecutionContextStage::GammaMarket,
            ));
        }
    }
    Ok((version, outcomes, gamma_min_order_size, gamma_min_tick_size))
}

fn parse_string_array(
    value: Option<&Value>,
    _field: &str,
    stage: ExecutionContextStage,
) -> Result<Vec<String>, ExecutionContextError> {
    let value = value.ok_or(ExecutionContextError::MalformedResponse(stage))?;
    let parsed: Value = match value {
        Value::Array(_) => value.clone(),
        Value::String(encoded) => serde_json::from_str(encoded)
            .map_err(|_| ExecutionContextError::MalformedResponse(stage))?,
        _ => return Err(ExecutionContextError::MalformedResponse(stage)),
    };
    parsed
        .as_array()
        .ok_or(ExecutionContextError::MalformedResponse(stage))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .filter(|text| !text.trim().is_empty())
                .map(str::to_owned)
                .ok_or(ExecutionContextError::MalformedResponse(stage))
        })
        .collect()
}

fn optional_decimal_text(
    market: &Value,
    field: &str,
    stage: ExecutionContextStage,
) -> Result<Option<String>, ExecutionContextError> {
    match market.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => {
            let value = Decimal::from_str_exact(text)
                .map_err(|_| ExecutionContextError::MalformedResponse(stage))?;
            if value <= Decimal::ZERO {
                return Err(ExecutionContextError::MalformedResponse(stage));
            }
            Ok(Some(text.clone()))
        }
        Some(Value::Number(number)) => {
            let text = number.to_string();
            let value = Decimal::from_str_exact(&text)
                .map_err(|_| ExecutionContextError::MalformedResponse(stage))?;
            if value <= Decimal::ZERO {
                return Err(ExecutionContextError::MalformedResponse(stage));
            }
            Ok(Some(text))
        }
        Some(_) => Err(ExecutionContextError::MalformedResponse(stage)),
    }
}

fn validate_gamma_fees(raw: &str) -> Result<(), ExecutionContextError> {
    let wire: GammaFeeWire = serde_json::from_str(raw).map_err(|_| {
        ExecutionContextError::MalformedResponse(ExecutionContextStage::GammaMarket)
    })?;
    if let Some(value) = wire.fee_schedule {
        let schedule: Value = serde_json::from_str(value.get()).map_err(|_| {
            ExecutionContextError::MalformedResponse(ExecutionContextStage::GammaMarket)
        })?;
        if !schedule.is_null() && !schedule.is_object() {
            return Err(ExecutionContextError::MalformedResponse(
                ExecutionContextStage::GammaMarket,
            ));
        }
        if schedule.is_object() {
            let parsed: GammaFeeFields<'_> = serde_json::from_str(value.get()).map_err(|_| {
                ExecutionContextError::MalformedResponse(ExecutionContextStage::GammaMarket)
            })?;
            validate_gamma_fee_fields(parsed)?;
        }
    }
    Ok(())
}

fn parse_clob_market(
    raw: &str,
    request: &ExecutionContextRequest,
    outcomes: &[ExecutionContextOutcome; 2],
    gamma_min_tick_size: Option<&str>,
) -> Result<ParsedClobMarket, ExecutionContextError> {
    let market: Value = serde_json::from_str(raw)
        .map_err(|_| ExecutionContextError::MalformedResponse(ExecutionContextStage::ClobMarket))?;
    for field in ["condition_id", "c"] {
        if let Some(value) = market.get(field) {
            let Some(condition_id) = value.as_str() else {
                return Err(ExecutionContextError::MalformedResponse(
                    ExecutionContextStage::ClobMarket,
                ));
            };
            if condition_id != request.api_condition_id.as_str() {
                return Err(ExecutionContextError::IdentityMismatch(
                    ExecutionContextStage::ClobMarket,
                ));
            }
        }
    }
    let tokens = market.get("t").and_then(Value::as_array).ok_or(
        ExecutionContextError::MalformedResponse(ExecutionContextStage::ClobMarket),
    )?;
    if tokens.len() != 2 {
        return Err(ExecutionContextError::MalformedResponse(
            ExecutionContextStage::ClobMarket,
        ));
    }
    for outcome in outcomes {
        let matching = tokens
            .iter()
            .filter(|token| {
                token.get("t").and_then(Value::as_str) == Some(outcome.asset_id.as_str())
            })
            .collect::<Vec<_>>();
        if matching.len() != 1
            || matching[0].get("o").and_then(Value::as_str) != Some(outcome.label.as_str())
        {
            return Err(ExecutionContextError::IdentityMismatch(
                ExecutionContextStage::ClobMarket,
            ));
        }
    }
    let min_order_size = decimal_field(&market, "mos", false)?;
    let min_tick_size = decimal_field(&market, "mts", true)?;
    if let Some(gamma) = gamma_min_tick_size {
        if Decimal::from_str_exact(gamma).ok() != Decimal::from_str_exact(&min_tick_size).ok() {
            return Err(ExecutionContextError::IdentityMismatch(
                ExecutionContextStage::ClobMarket,
            ));
        }
    }
    let maker_base_fee_bps = optional_u64(&market, "mbf", ExecutionContextStage::ClobMarket)?;
    let taker_base_fee_bps = optional_u64(&market, "tbf", ExecutionContextStage::ClobMarket)?;
    let fee_wire: ClobFeeWire<'_> = serde_json::from_str(raw)
        .map_err(|_| ExecutionContextError::MalformedResponse(ExecutionContextStage::ClobMarket))?;
    let fee_curve = match fee_wire.fd {
        None => None,
        Some(raw_value)
            if serde_json::from_str::<Value>(raw_value.get())
                .is_ok_and(|value| value.is_object()) =>
        {
            Some(raw_value)
        }
        Some(_) => {
            return Err(ExecutionContextError::MalformedResponse(
                ExecutionContextStage::ClobMarket,
            ));
        }
    };
    let (fee_curve_rate_lexeme, fee_curve_exponent_lexeme, fee_curve_taker_only) =
        if let Some(curve) = fee_curve {
            let parsed: FeeFields<'_> = serde_json::from_str(curve.get()).map_err(|_| {
                ExecutionContextError::MalformedResponse(ExecutionContextStage::ClobMarket)
            })?;
            validate_fee_fields(parsed, ExecutionContextStage::ClobMarket)?
        } else {
            (None, None, None)
        };
    Ok(ParsedClobMarket {
        min_order_size,
        min_tick_size,
        maker_base_fee_bps,
        taker_base_fee_bps,
        fee_curve_rate_lexeme,
        fee_curve_exponent_lexeme,
        fee_curve_taker_only,
    })
}

fn decimal_field(
    market: &Value,
    field: &str,
    at_most_one: bool,
) -> Result<String, ExecutionContextError> {
    let stage = ExecutionContextStage::ClobMarket;
    let value = market
        .get(field)
        .ok_or(ExecutionContextError::MalformedResponse(stage))?;
    let text = match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        _ => return Err(ExecutionContextError::MalformedResponse(stage)),
    };
    let decimal = Decimal::from_str_exact(&text)
        .map_err(|_| ExecutionContextError::MalformedResponse(stage))?;
    if decimal <= Decimal::ZERO || (at_most_one && decimal > Decimal::ONE) {
        return Err(ExecutionContextError::MalformedResponse(stage));
    }
    Ok(text)
}

fn optional_u64(
    value: &Value,
    field: &str,
    stage: ExecutionContextStage,
) -> Result<Option<u64>, ExecutionContextError> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number
            .as_u64()
            .map(Some)
            .ok_or(ExecutionContextError::MalformedResponse(stage)),
        Some(_) => Err(ExecutionContextError::MalformedResponse(stage)),
    }
}

#[derive(Deserialize)]
struct GammaFeeWire<'a> {
    #[serde(borrow, rename = "feeSchedule")]
    fee_schedule: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct ClobFeeWire<'a> {
    #[serde(borrow)]
    fd: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct GammaFeeFields<'a> {
    #[serde(borrow)]
    rate: Option<&'a RawValue>,
    #[serde(borrow)]
    exponent: Option<&'a RawValue>,
    #[serde(borrow, rename = "takerOnly")]
    taker_only: Option<&'a RawValue>,
    #[serde(borrow, rename = "rebateRate")]
    rebate_rate: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct FeeFields<'a> {
    #[serde(borrow)]
    r: Option<&'a RawValue>,
    #[serde(borrow)]
    e: Option<&'a RawValue>,
    #[serde(borrow)]
    to: Option<&'a RawValue>,
}

type ParsedFeeCurve = (Option<String>, Option<String>, Option<bool>);

fn validate_fee_fields(
    fields: FeeFields<'_>,
    stage: ExecutionContextStage,
) -> Result<ParsedFeeCurve, ExecutionContextError> {
    let rate = parse_optional_rate(fields.r, stage)?;
    let exponent = parse_optional_exponent(fields.e, stage)?;
    let taker_only = parse_optional_bool(fields.to, stage)?;
    Ok((rate, exponent, taker_only))
}

fn validate_gamma_fee_fields(fields: GammaFeeFields<'_>) -> Result<(), ExecutionContextError> {
    let stage = ExecutionContextStage::GammaMarket;
    parse_optional_rate(fields.rate, stage)?;
    parse_optional_exponent(fields.exponent, stage)?;
    parse_optional_bool(fields.taker_only, stage)?;
    parse_optional_rate(fields.rebate_rate, stage)?;
    Ok(())
}

fn parse_optional_rate(
    raw: Option<&RawValue>,
    stage: ExecutionContextStage,
) -> Result<Option<String>, ExecutionContextError> {
    let Some(raw) = raw else { return Ok(None) };
    if raw.get() == "null" {
        return Ok(None);
    }
    let rate = Decimal::from_str_exact(raw.get())
        .map_err(|_| ExecutionContextError::MalformedResponse(stage))?;
    if rate < Decimal::ZERO || rate > Decimal::ONE {
        return Err(ExecutionContextError::MalformedResponse(stage));
    }
    Ok(Some(raw.get().to_owned()))
}

fn parse_optional_exponent(
    raw: Option<&RawValue>,
    stage: ExecutionContextStage,
) -> Result<Option<String>, ExecutionContextError> {
    let Some(raw) = raw else { return Ok(None) };
    if raw.get() == "null" {
        return Ok(None);
    }
    let exponent = raw
        .get()
        .parse::<u64>()
        .map_err(|_| ExecutionContextError::MalformedResponse(stage))?;
    Ok(Some(exponent.to_string()))
}

fn parse_optional_bool(
    raw: Option<&RawValue>,
    stage: ExecutionContextStage,
) -> Result<Option<bool>, ExecutionContextError> {
    let Some(raw) = raw else { return Ok(None) };
    if raw.get() == "null" {
        return Ok(None);
    }
    serde_json::from_str(raw.get())
        .map(Some)
        .map_err(|_| ExecutionContextError::MalformedResponse(stage))
}

fn check_deadline(
    deadline: tokio::time::Instant,
    stage: ExecutionContextStage,
) -> Result<(), ExecutionContextError> {
    if tokio::time::Instant::now() >= deadline {
        Err(ExecutionContextError::Timeout(stage))
    } else {
        Ok(())
    }
}
