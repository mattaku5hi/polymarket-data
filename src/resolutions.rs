//! Bounded, read-only public Data API v2 resolution rows.
//!
//! Rows stay raw so each consumer can apply its own terminal-state and identity
//! policy without coupling this reader to a host application's contracts.

use serde::Deserialize;
use serde_json::Value;

pub const V2_RESOLUTIONS_PATH: &str = "/v2/resolutions";
pub const MAX_CONDITION_SELECTORS: usize = 20;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ResolutionReadError {
    #[error("polymarket data api v2 resolutions selector is invalid")]
    InvalidSelector,
    #[error("polymarket data api v2 resolutions request failed")]
    RequestFailed,
    #[error("polymarket data api v2 resolutions returned http 429 (retry after {0} seconds)")]
    RateLimitedWithDelay(u64),
    #[error("polymarket data api v2 resolutions returned http 429 (rate limited)")]
    RateLimited,
    #[error("polymarket data api v2 resolutions returned http {0}")]
    HttpStatus(u16),
    #[error("polymarket data api v2 resolutions response exceeded the size limit")]
    ResponseTooLarge,
    #[error("polymarket data api v2 resolutions response body could not be read")]
    ResponseUnreadable,
    #[error("polymarket data api v2 resolutions response was not a valid envelope")]
    InvalidEnvelope,
}

/// Fetch one unpaginated page for 1–20 nonblank condition selectors.
///
/// # Errors
/// Returns body-free errors for invalid selectors, transport/status failures,
/// oversized responses, and malformed envelopes.
pub async fn fetch_v2_resolution_rows(
    client: &reqwest::Client,
    base_url: &str,
    conditions: &[String],
) -> Result<Vec<Value>, ResolutionReadError> {
    if conditions.is_empty()
        || conditions.len() > MAX_CONDITION_SELECTORS
        || conditions
            .iter()
            .any(|condition| condition.trim().is_empty())
    {
        return Err(ResolutionReadError::InvalidSelector);
    }
    let url = format!("{}{}", base_url.trim_end_matches('/'), V2_RESOLUTIONS_PATH);
    let mut response = client
        .get(url)
        .query(&[("condition", conditions.join(","))])
        .send()
        .await
        .map_err(|_| ResolutionReadError::RequestFailed)?;
    let status = response.status();
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err(
            match response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
            {
                Some(seconds) => ResolutionReadError::RateLimitedWithDelay(seconds),
                None => ResolutionReadError::RateLimited,
            },
        );
    }
    if !status.is_success() {
        return Err(ResolutionReadError::HttpStatus(status.as_u16()));
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RESPONSE_BYTES as u64)
    {
        return Err(ResolutionReadError::ResponseTooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ResolutionReadError::ResponseUnreadable)?
    {
        if chunk.len() > MAX_RESPONSE_BYTES - body.len() {
            return Err(ResolutionReadError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    let page: ResolutionsPage =
        serde_json::from_slice(&body).map_err(|_| ResolutionReadError::InvalidEnvelope)?;
    Ok(page.data.unwrap_or_default())
}

#[derive(Debug, Deserialize)]
struct ResolutionsPage {
    #[serde(default)]
    data: Option<Vec<Value>>,
}
