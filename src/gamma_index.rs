//! Paper-first, async-hydrated outcome-token index backed by Polymarket's
//! Gamma `/markets` endpoint.
//!
//! This module closes the enrichment boundary left open by the v2
//! market-resolution adapter and resolved by
//! `docs/15-outcome-token-index-research.md`: it turns a **condition-grain**
//! Gamma market row into the **token-grain** mapping that contract v1 needs.
//! It is read-only (public HTTP `GET`s only: no orders, no credentials, no
//! account state, no mutation of any kind).
//!
//! # The join (docs 15 §1)
//!
//! The token ↔ outcome-index join lives in Gamma `GET /markets`:
//!
//! ```text
//! GET {base}/markets?condition_ids=<id>&condition_ids=<id2>&closed=true
//! ```
//!
//! Each returned market object carries `conditionId`, `outcomes`, and
//! `clobTokenIds` — the latter two being **JSON-encoded strings** of parallel
//! arrays correlated strictly **by index** (their JSON type is `string` on the
//! live API). A real JSON array is also accepted for backward compatibility.
//! `clobTokenIds[i]` is the CLOB
//! `token_id` for outcome index `i`, and the Data API v2 `payouts[i]` uses the
//! same outcome-index space (docs 15 §1.1). The mapping keys strictly on
//! position, never on the outcome *label*.
//!
//! Two load-bearing quirks (docs 15 §2.1) are handled here:
//!
//! - **`condition_ids` is repeatable, never comma-joined.** `reqwest`'s
//!   `.query(&[(..)])` with one tuple per id produces the repeatable form
//!   automatically; a comma-joined list would silently return `[]`.
//! - **`closed=true` is mandatory.** `closed` defaults to `false`, so a
//!   resolved/historical market is **absent** unless this flag is sent. Every
//!   hydration request therefore sends `closed=true`.
//!
//! # Fail-closed semantics
//!
//! This index never invents data. In every case where a token cannot be
//! derived with certainty, the mapping for that condition is cached as
//! *missing* and [`GammaOutcomeTokenIndex::token_id_for_outcome`] returns `None`,
//! which lets the host v2 resolution adapter fail closed on an unmapped
//! outcome.
//!
//! | vendor condition                                 | result                              |
//! |---------------------------------------------------|-------------------------------------|
//! | `clobTokenIds` absent / `null` / empty string     | cached missing → `None` (fail closed) |
//! | unknown condition id, HTTP 200 `[]` (documented miss) | cached missing → `None`         |
//! | outcome index out of range                        | `None` (fail closed)                |
//! | malformed `outcomes`/`clobTokenIds` (neither a JSON array nor a valid JSON-encoded array string) | explicit [`GammaIndexError`] |
//! | `outcomes`/`clobTokenIds` length mismatch         | explicit error                     |
//! | conflicting duplicate rows for one condition      | explicit error                     |
//! | malformed envelope, HTTP non-2xx/`429`, transport | explicit error                     |
//!
//! # Immutability
//!
//! The condition → token mapping is immutable once a market is minted (docs 15
//! §6.5), so a cached mapping must never silently change. Re-hydrating a
//! condition whose mapping would change — tokens differ, or a previously
//! present market vanishes — is an explicit
//! [`GammaIndexError::ImmutableConflict`] and commits **no** change to the
//! cache for that whole hydration batch. Re-hydrating with the identical
//! mapping is a harmless idempotent no-op, and a missing → present transition
//! (a condition that has since resolved/closed) is a legitimate new insert.
//!
//! # Bounded cache
//!
//! The cache is keyed only by the condition ids the caller explicitly hydrates;
//! a market row whose `conditionId` was not requested is ignored. The cache
//! therefore cannot grow beyond the caller-supplied condition set.
//!
//! # Composition
//!
//! The host can implement its synchronous outcome-token trait by delegating
//! to `token_id_for_outcome`. Hydration is separate: an un-hydrated lookup
//! returns `None` (fail closed) rather than inventing data.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use futures_util::{StreamExt, TryStreamExt, stream};
use serde_json::{Map, Value};

use crate::resolutions::MAX_CONDITION_SELECTORS;

const MAX_GAMMA_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// The Gamma markets path, relative to [`GAMMA_DEFAULT_BASE_URL`].
pub const GAMMA_MARKETS_PATH: &str = "/markets";

/// The production base URL of Polymarket's Gamma API.
pub const GAMMA_DEFAULT_BASE_URL: &str = "https://gamma-api.polymarket.com";

/// Gamma `/markets` dedicated rate limit (docs 15 §5.1): requests per 10 s.
pub const GAMMA_MARKETS_RATE_LIMIT_PER_10S: u32 = 300;

/// Maximum number of independent Gamma hydration batches in flight.
pub const GAMMA_HYDRATE_CONCURRENCY: usize = 8;

/// A hydration (or mapping-parse) failure.
///
/// Every failure is explicit: a fail-closed miss returns `None` from
/// [`GammaOutcomeTokenIndex::token_id_for_outcome`], never this error. This error
/// is reserved for the cases where the index cannot even decide what to cache
/// (transport/HTTP, malformed envelope or row, a conflicting duplicate, or a
/// mapping that would silently change).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GammaIndexError {
    /// The HTTP request could not be sent (transport / connection / timeout).
    #[error("gamma markets request failed")]
    RequestFailed(String),
    /// `429` rate limited, with any `Retry-After` hint surfaced.
    #[error("gamma markets request was rate limited (http 429{retry_hint})")]
    RateLimited { retry_hint: String },
    /// Any other non-2xx status.
    #[error("gamma markets request returned http {status}")]
    HttpStatus { status: u16 },
    /// The response body could not be read.
    #[error("gamma markets response could not be read")]
    ReadBody(String),
    /// The body was not the expected JSON array of market objects.
    #[error("gamma markets response was not a valid envelope")]
    MalformedEnvelope(String),
    /// Response body exceeded the bounded Gamma read limit.
    #[error("gamma markets response exceeded the size limit")]
    ResponseTooLarge,
    /// A market row was not a JSON object.
    #[error("gamma markets row is not a JSON object")]
    NotAnObject,
    /// A required, non-blank string field was missing/blank/wrong-typed.
    #[error("gamma markets row field `{field}` is missing, blank, or of the wrong type")]
    InvalidField { field: &'static str },
    /// `outcomes`/`clobTokenIds` was not a JSON-encoded array string.
    #[error(
        "gamma markets row field `{field}` for condition `{condition_id}` is not a \
         JSON-encoded array"
    )]
    MalformedArray {
        condition_id: String,
        field: &'static str,
        raw: String,
    },
    /// `outcomes` and `clobTokenIds` have different lengths; the index is
    /// strictly positional, so this cannot be mapped.
    #[error(
        "gamma markets row for condition `{condition_id}` has a length mismatch: \
         outcomes={outcomes}, clobTokenIds={clob_token_ids}"
    )]
    LengthMismatch {
        condition_id: String,
        outcomes: usize,
        clob_token_ids: usize,
    },
    /// A parsed `clobTokenIds` entry was blank, so no token can be derived.
    #[error(
        "gamma markets row for condition `{condition_id}` has a blank outcome token at index {index}"
    )]
    BlankToken { condition_id: String, index: usize },
    /// Two market rows for one condition disagreed on the mapping.
    #[error(
        "gamma markets returned duplicate rows for condition `{condition_id}` with conflicting mappings"
    )]
    DuplicateConflict { condition_id: String },
    /// A re-hydration would silently change a cached (immutable) mapping.
    #[error(
        "re-hydration would change the immutable mapping for condition `{condition_id}` \
         (before={before:?}, after={after:?})"
    )]
    ImmutableConflict {
        condition_id: String,
        before: Vec<String>,
        after: Vec<String>,
    },
}

/// The positional outcome → token mapping for one condition.
#[derive(Clone, Debug, PartialEq, Eq)]
struct OutcomeMap {
    /// `tokens[i]` is the CLOB `token_id` for outcome index `i`. Empty means
    /// the market has no CLOB order book → every lookup fails closed to `None`.
    tokens: Vec<String>,
}

/// Internal, shared, thread-safe state of a [`GammaOutcomeTokenIndex`].
struct GammaState {
    client: reqwest::Client,
    base_url: String,
    /// condition_id → `Some(OutcomeMap)` when mapped, `None` when the condition
    /// is known to be unmappable (documented miss, or no CLOB book).
    cache: RwLock<HashMap<String, Option<OutcomeMap>>>,
}

/// An async-hydrated, fail-closed outcome-token index over Gamma `/markets`.
///
/// Create one (optionally with an injected HTTP client/base URL), call
/// [`hydrate`](Self::hydrate) with the condition ids to resolve, then hand it
/// to a v2 resolutions feed as its `enrichment`. It is `Send + Sync` and cheap
/// to clone, so it can be shared across threads.
#[derive(Clone)]
pub struct GammaOutcomeTokenIndex {
    inner: std::sync::Arc<GammaState>,
}

impl GammaOutcomeTokenIndex {
    /// Build an index against the default Gamma base URL, using a default HTTP
    /// client.
    #[must_use]
    pub fn new() -> Self {
        Self::with_client(
            crate::http_client::default_http_client(),
            GAMMA_DEFAULT_BASE_URL,
        )
    }

    /// Build an index against `base_url`, using a default HTTP client.
    ///
    /// A narrow seam for callers (for example the read-only wallet
    /// qualification tooling) that must point Gamma at a scripted endpoint.
    #[must_use]
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self::with_client(crate::http_client::default_http_client(), base_url)
    }

    /// Build an index with an injected HTTP client and base URL, for tests and
    /// callers that need their own timeouts or proxies.
    #[must_use]
    pub fn with_client(client: reqwest::Client, base_url: impl Into<String>) -> Self {
        Self {
            inner: std::sync::Arc::new(GammaState {
                client,
                base_url: base_url.into(),
                cache: RwLock::new(HashMap::new()),
            }),
        }
    }

    /// The configured base URL, without a trailing slash.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.inner.base_url
    }

    /// The number of condition ids currently in the cache (present or missing).
    ///
    /// The cache is bounded by the caller-supplied hydrate set, so this never
    /// exceeds the number of distinct conditions hydrated.
    #[must_use]
    pub fn cache_len(&self) -> usize {
        self.inner
            .cache
            .read()
            .expect("gamma cache read lock")
            .len()
    }

    /// Hydrate the mapping for `conditions`, fetching Gamma `/markets` in
    /// batches of at most [`MAX_CONDITION_SELECTORS`] ids.
    ///
    /// Each batch sends one `GET /markets?condition_ids=<id>…&closed=true`
    /// with **repeatable** `condition_ids` and the mandatory `closed=true`.
    /// Every requested condition ends up cached — mapped, or missing (which
    /// makes the host's lookup fail closed to `None`).
    ///
    /// # Fail-closed mapping
    ///
    /// A condition with no CLOB book (absent/`null`/empty `clobTokenIds`) or
    /// no matching row (HTTP 200 `[]`) is cached as *missing*, so a later
    /// lookup returns `None` — never invented data. A malformed row, a
    /// conflicting duplicate, a malformed envelope, or any HTTP/transport
    /// failure is an explicit [`GammaIndexError`].
    ///
    /// # Immutability
    ///
    /// A cached mapping is immutable. Re-hydrating with the identical mapping
    /// is an idempotent no-op; re-hydrating with a *different* mapping — or a
    /// previously present condition that has vanished — is
    /// [`GammaIndexError::ImmutableConflict`], and the whole batch commits no
    /// change.
    pub async fn hydrate(&self, conditions: &[String]) -> Result<(), GammaIndexError> {
        let batches: Vec<Vec<String>> = conditions
            .chunks(MAX_CONDITION_SELECTORS)
            .map(<[String]>::to_vec)
            .collect();
        stream::iter(batches)
            .map(|batch| async move { self.hydrate_batch(&batch).await })
            .buffer_unordered(GAMMA_HYDRATE_CONCURRENCY)
            .try_collect()
            .await
    }

    async fn hydrate_batch(&self, batch: &[String]) -> Result<(), GammaIndexError> {
        // Local validation: a blank condition id cannot be queried and a
        // blank-keyed cache entry would be nonsense.
        if let Some(_blank) = batch.iter().find(|c| c.trim().is_empty()) {
            return Err(GammaIndexError::InvalidField {
                field: "condition_id",
            });
        }
        // An empty batch (only possible when conditions is empty) is a no-op.
        if batch.is_empty() {
            return Ok(());
        }

        let requested: HashSet<&str> = batch.iter().map(String::as_str).collect();
        let url = format!(
            "{}{}",
            self.inner.base_url.trim_end_matches('/'),
            GAMMA_MARKETS_PATH
        );

        // Repeatable `condition_ids`, one tuple per id — never comma-joined —
        // plus the mandatory `closed=true`.
        let mut query: Vec<(&str, &str)> = batch
            .iter()
            .map(|id| ("condition_ids", id.as_str()))
            .collect();
        query.push(("closed", "true"));

        let response = self
            .inner
            .client
            .get(url)
            .query(&query)
            .send()
            .await
            .map_err(|_| GammaIndexError::RequestFailed("request failed".to_owned()))?;

        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let hint = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|delay| delay.parse::<u64>().ok())
                .map(|delay| format!(", retry after {delay}"))
                .unwrap_or_default();
            return Err(GammaIndexError::RateLimited { retry_hint: hint });
        }
        if !status.is_success() {
            return Err(GammaIndexError::HttpStatus {
                status: status.as_u16(),
            });
        }

        let body = read_bounded_gamma_response(response).await?;
        let markets: Vec<Value> = serde_json::from_slice(&body)
            .map_err(|_| GammaIndexError::MalformedEnvelope("invalid JSON".to_owned()))?;

        // First pass: build the per-condition mappings for this batch and
        // detect conflicting duplicates, without touching the shared cache.
        let mut mapped: HashMap<String, OutcomeMap> = HashMap::new();
        for market in markets {
            let object = market.as_object().ok_or(GammaIndexError::NotAnObject)?;
            let condition_id = match object.get("conditionId").and_then(Value::as_str) {
                Some(value) if !value.trim().is_empty() => value.to_owned(),
                _ => {
                    return Err(GammaIndexError::InvalidField {
                        field: "conditionId",
                    });
                }
            };
            // Only a requested condition may enter the cache (bounded growth).
            if !requested.contains(condition_id.as_str()) {
                continue;
            }
            let map = build_outcome_map(&condition_id, object)?;
            match mapped.get(&condition_id) {
                // An identical duplicate is harmless; a conflicting one is not.
                Some(existing) if existing == &map => {}
                Some(_) => {
                    return Err(GammaIndexError::DuplicateConflict { condition_id });
                }
                None => {
                    mapped.insert(condition_id, map);
                }
            }
        }

        // Second pass: detect any immutable conflict against the existing
        // cache across the whole batch before committing anything.
        let mut pending: Vec<(String, Option<OutcomeMap>)> = Vec::with_capacity(batch.len());
        {
            let cache = self.inner.cache.read().expect("gamma cache read lock");
            for condition_id in &requested {
                let new_state = mapped.get(*condition_id).cloned();
                match cache.get(*condition_id) {
                    // Not cached yet: any state is a fresh insert.
                    None => {}
                    // Previously mapped: the new state must be identical, or
                    // the immutable mapping would silently change.
                    Some(Some(old)) => {
                        let after = match &new_state {
                            Some(new_map) if new_map == old => continue,
                            Some(new_map) => new_map.tokens.clone(),
                            None => Vec::new(),
                        };
                        return Err(GammaIndexError::ImmutableConflict {
                            condition_id: (*condition_id).to_owned(),
                            before: old.tokens.clone(),
                            after,
                        });
                    }
                    // Previously missing: a new mapping is a legitimate insert,
                    // and staying missing is idempotent.
                    Some(None) => {}
                }
                pending.push(((*condition_id).to_owned(), new_state));
            }
        }

        // Commit only now, so a conflicting batch mutates nothing.
        {
            let mut cache = self.inner.cache.write().expect("gamma cache write lock");
            for (condition_id, state) in pending {
                cache.insert(condition_id, state);
            }
        }
        Ok(())
    }
}

impl Default for GammaOutcomeTokenIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Read-only Gamma lookup for a market's immutable negRisk group.
#[derive(Clone)]
pub struct GammaNegRiskGroupLookup {
    client: reqwest::Client,
    base_url: String,
}

impl GammaNegRiskGroupLookup {
    #[must_use]
    pub fn new() -> Self {
        Self::with_client(
            crate::http_client::default_http_client(),
            GAMMA_DEFAULT_BASE_URL,
        )
    }

    /// Build against a scripted Gamma endpoint using the bounded default client.
    #[must_use]
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self::with_client(crate::http_client::default_http_client(), base_url)
    }

    #[must_use]
    pub fn with_client(client: reqwest::Client, base_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: base_url.into(),
        }
    }

    /// Fetch the exact Gamma `negRiskMarketID` for `condition_id`. A missing
    /// row, `negRisk: false`, or absent/blank id is a normal ungrouped `None`.
    pub async fn lookup(&self, condition_id: &str) -> Result<Option<String>, GammaIndexError> {
        if condition_id.trim().is_empty() {
            return Err(GammaIndexError::InvalidField {
                field: "condition_id",
            });
        }
        let url = format!(
            "{}{}",
            self.base_url.trim_end_matches('/'),
            GAMMA_MARKETS_PATH
        );
        let response = self
            .client
            .get(url)
            .query(&[("condition_ids", condition_id)])
            .send()
            .await
            .map_err(|_| GammaIndexError::RequestFailed("request failed".to_owned()))?;
        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(GammaIndexError::RateLimited {
                retry_hint: String::new(),
            });
        }
        if !status.is_success() {
            return Err(GammaIndexError::HttpStatus {
                status: status.as_u16(),
            });
        }
        let body = read_bounded_gamma_response(response).await?;
        let markets: Vec<Value> = serde_json::from_slice(&body)
            .map_err(|_| GammaIndexError::MalformedEnvelope("invalid JSON".to_owned()))?;
        let mut group = None;
        for market in markets {
            let object = market.as_object().ok_or(GammaIndexError::NotAnObject)?;
            if object.get("conditionId").and_then(Value::as_str) != Some(condition_id) {
                continue;
            }
            let found = if object.get("negRisk").and_then(Value::as_bool) == Some(true) {
                object
                    .get("negRiskMarketID")
                    .and_then(Value::as_str)
                    .filter(|id| !id.trim().is_empty())
                    .map(str::to_owned)
            } else {
                None
            };
            if let Some(previous) = &group {
                if group != Some(found.clone()) {
                    return Err(GammaIndexError::DuplicateConflict {
                        condition_id: condition_id.to_owned(),
                    });
                }
                let _ = previous;
            } else {
                group = Some(found);
            }
        }
        Ok(group.flatten())
    }
}

impl Default for GammaNegRiskGroupLookup {
    fn default() -> Self {
        Self::new()
    }
}

impl GammaOutcomeTokenIndex {
    /// Resolve one outcome position after explicit hydration. Unknown and
    /// missing mappings fail closed to `None`.
    #[must_use]
    pub fn token_id_for_outcome(&self, condition_id: &str, outcome_index: u32) -> Option<String> {
        let cache = self.inner.cache.read().expect("gamma cache read lock");
        match cache.get(condition_id) {
            Some(Some(map)) => map
                .tokens
                .get(outcome_index as usize)
                .cloned()
                .filter(|token| !token.trim().is_empty()),
            // Not hydrated yet, a documented miss, or no CLOB book: fail closed.
            _ => None,
        }
    }
}

async fn read_bounded_gamma_response(
    mut response: reqwest::Response,
) -> Result<Vec<u8>, GammaIndexError> {
    if response
        .content_length()
        .is_some_and(|size| size > MAX_GAMMA_RESPONSE_BYTES as u64)
    {
        return Err(GammaIndexError::ResponseTooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| GammaIndexError::ReadBody("body read failed".to_owned()))?
    {
        if chunk.len() > MAX_GAMMA_RESPONSE_BYTES - body.len() {
            return Err(GammaIndexError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Build a positional outcome map from a single Gamma market object.
///
/// `outcomes` and `clobTokenIds` are **JSON-encoded array strings** on the
/// live Gamma API (their JSON type is `string`), but a real JSON array is
/// accepted too for backward compatibility with older fixtures and any
/// future API change. `outcomes` is read for its length only (labels are
/// opaque and never used as keys); `clobTokenIds` supplies the token per
/// index. The two must be equal length, or the row cannot be mapped.
fn build_outcome_map(
    condition_id: &str,
    object: &Map<String, Value>,
) -> Result<OutcomeMap, GammaIndexError> {
    let outcomes = decode_array_field(condition_id, object, "outcomes")?;

    // A market with no CLOB order book (AMM/fpmm era) has absent/`null`/empty
    // `clobTokenIds` (docs 15 §4.4). It cannot be enriched: cache as missing
    // (empty map) so lookups fail closed to `None` — this is not an error.
    let tokens = match object.get("clobTokenIds") {
        None | Some(Value::Null) => return Ok(OutcomeMap { tokens: Vec::new() }),
        Some(Value::String(raw)) if raw.trim().is_empty() => {
            return Ok(OutcomeMap { tokens: Vec::new() });
        }
        Some(_) => {
            let parsed = decode_array_field(condition_id, object, "clobTokenIds")?;
            parsed
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let token = value.as_str().filter(|t| !t.trim().is_empty()).ok_or(
                        GammaIndexError::BlankToken {
                            condition_id: condition_id.to_owned(),
                            index,
                        },
                    )?;
                    Ok(token.to_owned())
                })
                .collect::<Result<Vec<String>, GammaIndexError>>()?
        }
    };

    if tokens.len() != outcomes.len() {
        return Err(GammaIndexError::LengthMismatch {
            condition_id: condition_id.to_owned(),
            outcomes: outcomes.len(),
            clob_token_ids: tokens.len(),
        });
    }

    Ok(OutcomeMap { tokens })
}

/// Decode a Gamma market field that is either a real JSON array or a
/// JSON-encoded string whose contents are a JSON array.
///
/// The live Gamma API serializes `outcomes`/`clobTokenIds`/`outcomePrices` as
/// JSON-encoded **strings** (their JSON type is `string`), so the string form
/// is the primary wire shape. A real JSON array is accepted as a
/// backward-compatible alternative. Anything else — a non-array string, a
/// non-string scalar, a `null`, or a blank string — is an explicit
/// [`GammaIndexError`], never a silent miss. This is the only coercion the
/// index performs: the decoded value must be a JSON array, and every element
/// is still validated strictly downstream (token type/length, blank tokens,
/// length parity).
fn decode_array_field(
    condition_id: &str,
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Vec<Value>, GammaIndexError> {
    let value = object
        .get(field)
        .ok_or(GammaIndexError::InvalidField { field })?;
    match value {
        // A real JSON array on the wire.
        Value::Array(items) => Ok(items.clone()),
        // A JSON-encoded array string (the live Gamma wire shape).
        Value::String(raw) if !raw.trim().is_empty() => {
            serde_json::from_str(raw).map_err(|_| GammaIndexError::MalformedArray {
                condition_id: condition_id.to_owned(),
                field,
                raw: "<redacted>".to_owned(),
            })
        }
        // `null` or a blank string is not a usable array.
        Value::Null | Value::String(_) => Err(GammaIndexError::InvalidField { field }),
        // Any other scalar (number, bool, object) is not an array.
        _ => Err(GammaIndexError::InvalidField { field }),
    }
}
