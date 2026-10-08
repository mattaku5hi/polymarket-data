//! Bounded Data API v2 activity hints and optional receipt-only observations.
//!
//! Activity rows are acquisition hints, not complete wallet history, balance
//! evidence, canonical identity, ROI, or qualification evidence.

use std::{collections::HashSet, time::Duration};

use reqwest::{Client, Response, Url};
use serde_json::Value;
use thiserror::Error;
use tokio::time::{Instant, sleep_until};

use crate::{
    DEFAULT_BASE_URL,
    chain_log_audit::{
        ChainLogAuditError, ChainLogVerifier, ChainTransactionReceiptEvidence,
        TransactionRequestBudget,
    },
};

pub const V2_ACTIVITY_PATH: &str = "/v2/activity";
pub const ACTIVITY_HINT_POLICY_VERSION: &str = "data-api-v2-activity-default-plus-tip/1";
pub const MAX_ACTIVITY_PAGE_SIZE: usize = 1_000;

/// Shared execution budget/deadline supplied by a larger candidate workflow.
#[derive(Clone, Copy)]
pub struct ActivityObservationContext<'a> {
    request_budget: &'a TransactionRequestBudget,
    deadline: Instant,
}

impl<'a> ActivityObservationContext<'a> {
    #[must_use]
    pub const fn new(request_budget: &'a TransactionRequestBudget, deadline: Instant) -> Self {
        Self {
            request_budget,
            deadline,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivityHintPass {
    DefaultTypes,
    Tip,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivityHintPassStatus {
    NotStarted,
    Complete,
    Incomplete(ActivityHintIncompleteReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivityHintIncompleteReason {
    ActivityRequestLimit,
    ActivityPageLimit,
    ActivityRowLimit,
    ResponseByteLimit,
    CursorCycle,
    ProviderUnavailable,
    ProviderRefused(u16),
    InvalidPageEnvelope,
    InvalidActivityRow,
    DeadlineExceeded,
}

impl ActivityHintIncompleteReason {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ActivityRequestLimit => "activity_request_limit",
            Self::ActivityPageLimit => "activity_page_limit",
            Self::ActivityRowLimit => "activity_row_limit",
            Self::ResponseByteLimit => "activity_response_byte_limit",
            Self::CursorCycle => "activity_cursor_cycle",
            Self::ProviderUnavailable => "activity_provider_unavailable",
            Self::ProviderRefused(_) => "activity_provider_refused",
            Self::InvalidPageEnvelope => "activity_page_invalid",
            Self::InvalidActivityRow => "activity_row_invalid",
            Self::DeadlineExceeded => "activity_deadline_exceeded",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ActivityHintOccurrence {
    pub pass: ActivityHintPass,
    /// One-based page ordinal within this independent pass.
    pub page: usize,
    /// Zero-based row ordinal within its page.
    pub ordinal: usize,
    pub timestamp: i64,
    pub activity_type: String,
    /// Lowercase worklist key. The original row remains unchanged in `raw`.
    pub transaction_hash: String,
    pub raw: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivityHintPassSummary {
    pub pages_requested: usize,
    pub rows_retained: usize,
    pub status: ActivityHintPassStatus,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ActivityHintAcquisition {
    wallet: String,
    start: i64,
    end: i64,
    policy_version: &'static str,
    default_pass: ActivityHintPassSummary,
    tip_pass: ActivityHintPassSummary,
    total_requests: usize,
    total_response_bytes: usize,
    occurrences: Vec<ActivityHintOccurrence>,
    distinct_transaction_hashes: Vec<String>,
    seen_transaction_hashes: HashSet<String>,
    incomplete_reason: Option<ActivityHintIncompleteReason>,
}

impl ActivityHintAcquisition {
    #[must_use]
    pub fn wallet(&self) -> &str {
        &self.wallet
    }
    #[must_use]
    pub fn start(&self) -> i64 {
        self.start
    }
    #[must_use]
    pub fn end(&self) -> i64 {
        self.end
    }
    #[must_use]
    pub fn policy_version(&self) -> &str {
        self.policy_version
    }
    #[must_use]
    pub fn default_pass(&self) -> ActivityHintPassSummary {
        self.default_pass
    }
    #[must_use]
    pub fn tip_pass(&self) -> ActivityHintPassSummary {
        self.tip_pass
    }
    #[must_use]
    pub fn total_requests(&self) -> usize {
        self.total_requests
    }
    #[must_use]
    pub fn total_response_bytes(&self) -> usize {
        self.total_response_bytes
    }
    #[must_use]
    pub fn occurrences(&self) -> &[ActivityHintOccurrence] {
        &self.occurrences
    }
    #[must_use]
    pub fn distinct_transaction_hashes(&self) -> &[String] {
        &self.distinct_transaction_hashes
    }
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.incomplete_reason.is_none()
    }
    #[must_use]
    pub fn incomplete_reason(&self) -> Option<ActivityHintIncompleteReason> {
        self.incomplete_reason
    }
    /// Even two exhausted API filters are not complete wallet history.
    #[must_use]
    pub const fn history_coverage_unproven(&self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalletActivityObservationLimits {
    pub max_pages: usize,
    pub max_rows: usize,
    pub page_size: usize,
    pub max_activity_requests: usize,
    pub max_response_bytes: usize,
    pub max_rpc_requests: usize,
    pub deadline: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptObservationStatus {
    NotStartedActivityIncomplete(ActivityHintIncompleteReason),
    Complete,
    Incomplete(ReceiptObservationIncompleteReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptObservationIncompleteReason {
    DeadlineExceeded,
    RpcRequestLimit,
    VerificationFailed,
}

impl ReceiptObservationIncompleteReason {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DeadlineExceeded => "receipt_deadline_exceeded",
            Self::RpcRequestLimit => "receipt_rpc_request_limit",
            Self::VerificationFailed => "receipt_verification_failed",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct WalletActivityObservation {
    activity: ActivityHintAcquisition,
    receipt_observations: Vec<ChainTransactionReceiptEvidence>,
    receipt_status: ReceiptObservationStatus,
    receipt_policy_version: &'static str,
    rpc_requests: usize,
}

impl WalletActivityObservation {
    #[must_use]
    pub fn activity(&self) -> &ActivityHintAcquisition {
        &self.activity
    }
    #[must_use]
    pub fn receipt_observations(&self) -> &[ChainTransactionReceiptEvidence] {
        &self.receipt_observations
    }
    #[must_use]
    pub fn receipt_status(&self) -> ReceiptObservationStatus {
        self.receipt_status
    }
    #[must_use]
    pub fn receipt_policy_version(&self) -> &str {
        self.receipt_policy_version
    }
    #[must_use]
    pub fn rpc_requests(&self) -> usize {
        self.rpc_requests
    }
    #[must_use]
    pub const fn history_coverage_unproven(&self) -> bool {
        true
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ActivityHintInputError {
    #[error("invalid activity request or limits")]
    InvalidRequest,
    #[error("invalid activity API endpoint configuration")]
    InvalidEndpoint,
}

/// Read-only adapter for `/v2/activity`; no credentials, account state, writes,
/// retries, or redirects. `base_url` is intended for production constant or
/// isolated loopback fixtures only.
pub struct PolymarketActivityHintClient {
    base_url: Url,
    client: Client,
}

impl PolymarketActivityHintClient {
    pub fn new(base_url: &str) -> Result<Self, ActivityHintInputError> {
        let base_url = validate_base_url(base_url)?;
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ActivityHintInputError::InvalidEndpoint)?;
        Ok(Self { base_url, client })
    }

    pub fn production() -> Self {
        Self::new(DEFAULT_BASE_URL).expect("static Data API endpoint is valid")
    }

    /// Walk default (type omitted) and explicit TIP independently, retaining raw
    /// row occurrences and per-pass/page/ordinal provenance. Once both walks
    /// exhaust their filters, verify only distinct transaction hashes through
    /// the separate receipt-only verifier under one shared RPC budget and the
    /// same overall deadline. No API result establishes completeness or ROI.
    pub async fn observe_wallet_activity(
        &self,
        wallet: &str,
        start: i64,
        end: i64,
        limits: WalletActivityObservationLimits,
        verifier: &ChainLogVerifier,
    ) -> Result<WalletActivityObservation, ActivityHintInputError> {
        let (wallet, deadline) = validate_request(wallet, start, end, limits)?;
        let budget = TransactionRequestBudget::new(limits.max_rpc_requests);
        self.observe_wallet_activity_with_context(
            &wallet,
            start,
            end,
            limits,
            verifier,
            ActivityObservationContext::new(&budget, deadline),
        )
        .await
    }

    /// Candidate integration variant. The caller owns the absolute deadline and
    /// shared actual-send budget so earlier history/fill work is not reset.
    pub async fn observe_wallet_activity_with_context(
        &self,
        wallet: &str,
        start: i64,
        end: i64,
        limits: WalletActivityObservationLimits,
        verifier: &ChainLogVerifier,
        context: ActivityObservationContext<'_>,
    ) -> Result<WalletActivityObservation, ActivityHintInputError> {
        let wallet = validate_activity_request(wallet, start, end, limits)?;
        let budget = context.request_budget;
        let deadline = context.deadline;
        let rpc_request_start = budget.reserved_requests();
        let activity = self
            .acquire_hints_until(wallet, start, end, limits, deadline)
            .await;

        if let Some(reason) = activity.incomplete_reason {
            return Ok(WalletActivityObservation {
                activity,
                receipt_observations: Vec::new(),
                receipt_status: ReceiptObservationStatus::NotStartedActivityIncomplete(reason),
                receipt_policy_version: crate::chain_log_audit::RECEIPT_OBSERVER_POLICY_VERSION,
                rpc_requests: budget.reserved_requests().saturating_sub(rpc_request_start),
            });
        }

        let mut receipt_observations =
            Vec::with_capacity(activity.distinct_transaction_hashes.len());
        let mut receipt_status = ReceiptObservationStatus::Complete;
        for transaction_hash in &activity.distinct_transaction_hashes {
            if Instant::now() >= deadline {
                receipt_status = ReceiptObservationStatus::Incomplete(
                    ReceiptObservationIncompleteReason::DeadlineExceeded,
                );
                break;
            }
            let verification = verifier
                .verify_transaction_receipt_observation_with_budget(transaction_hash, budget);
            match tokio::time::timeout_at(deadline, verification).await {
                Err(_) => {
                    receipt_status = ReceiptObservationStatus::Incomplete(
                        ReceiptObservationIncompleteReason::DeadlineExceeded,
                    );
                    break;
                }
                Ok(Ok(evidence)) => receipt_observations.push(evidence),
                Ok(Err(ChainLogAuditError::Unavailable)) if budget.is_exhausted() => {
                    receipt_status = ReceiptObservationStatus::Incomplete(
                        ReceiptObservationIncompleteReason::RpcRequestLimit,
                    );
                    break;
                }
                Ok(Err(_)) => {
                    receipt_status = ReceiptObservationStatus::Incomplete(
                        ReceiptObservationIncompleteReason::VerificationFailed,
                    );
                    break;
                }
            }
        }

        Ok(WalletActivityObservation {
            activity,
            receipt_observations,
            receipt_status,
            receipt_policy_version: crate::chain_log_audit::RECEIPT_OBSERVER_POLICY_VERSION,
            rpc_requests: budget.reserved_requests().saturating_sub(rpc_request_start),
        })
    }

    async fn acquire_hints_until(
        &self,
        wallet: String,
        start: i64,
        end: i64,
        limits: WalletActivityObservationLimits,
        deadline: Instant,
    ) -> ActivityHintAcquisition {
        let mut activity = ActivityHintAcquisition {
            wallet,
            start,
            end,
            policy_version: ACTIVITY_HINT_POLICY_VERSION,
            default_pass: empty_pass(),
            tip_pass: empty_pass(),
            total_requests: 0,
            total_response_bytes: 0,
            occurrences: Vec::new(),
            distinct_transaction_hashes: Vec::new(),
            seen_transaction_hashes: HashSet::new(),
            incomplete_reason: None,
        };
        for (pass_index, pass) in [ActivityHintPass::DefaultTypes, ActivityHintPass::Tip]
            .into_iter()
            .enumerate()
        {
            if pass_index > 0 {
                if let Some(reason) = exhausted_limit(&activity, limits) {
                    set_pass_status(
                        &mut activity,
                        pass,
                        ActivityHintPassStatus::Incomplete(reason),
                    );
                    activity.incomplete_reason = Some(reason);
                    break;
                }
            }
            match self.walk_pass(&mut activity, pass, limits, deadline).await {
                Ok(()) => set_pass_status(&mut activity, pass, ActivityHintPassStatus::Complete),
                Err(reason) => {
                    set_pass_status(
                        &mut activity,
                        pass,
                        ActivityHintPassStatus::Incomplete(reason),
                    );
                    activity.incomplete_reason = Some(reason);
                    break;
                }
            }
        }
        activity
    }

    async fn walk_pass(
        &self,
        acquisition: &mut ActivityHintAcquisition,
        pass: ActivityHintPass,
        limits: WalletActivityObservationLimits,
        deadline: Instant,
    ) -> Result<(), ActivityHintIncompleteReason> {
        let mut cursor: Option<String> = None;
        let mut used_cursors = HashSet::new();
        let mut expected_offset = 0_i64;
        loop {
            if acquisition.total_requests >= limits.max_activity_requests {
                return Err(ActivityHintIncompleteReason::ActivityRequestLimit);
            }
            if total_pages(acquisition) >= limits.max_pages {
                return Err(ActivityHintIncompleteReason::ActivityPageLimit);
            }
            if acquisition.occurrences.len() >= limits.max_rows {
                return Err(ActivityHintIncompleteReason::ActivityRowLimit);
            }
            if acquisition.total_response_bytes >= limits.max_response_bytes {
                return Err(ActivityHintIncompleteReason::ResponseByteLimit);
            }
            let page = page_number(acquisition, pass) + 1;
            let url = self.page_url(acquisition, pass, limits.page_size, cursor.as_deref());
            let response_result = tokio::select! {
                biased;
                () = sleep_until(deadline) => return Err(ActivityHintIncompleteReason::DeadlineExceeded),
                result = async {
                    acquisition.total_requests += 1;
                    increment_pages(acquisition, pass);
                    self.client.get(url).send().await
                } => result,
            };
            let response =
                response_result.map_err(|_| ActivityHintIncompleteReason::ProviderUnavailable)?;
            if !response.status().is_success() {
                return Err(ActivityHintIncompleteReason::ProviderRefused(
                    response.status().as_u16(),
                ));
            }
            let remaining_bytes = limits.max_response_bytes - acquisition.total_response_bytes;
            if response
                .content_length()
                .is_some_and(|length| length > remaining_bytes as u64)
            {
                return Err(ActivityHintIncompleteReason::ResponseByteLimit);
            }
            let body = read_bounded_body(
                response,
                remaining_bytes,
                deadline,
                &mut acquisition.total_response_bytes,
            )
            .await?;
            let envelope: Value = serde_json::from_slice(&body)
                .map_err(|_| ActivityHintIncompleteReason::InvalidPageEnvelope)?;
            let page_data = parse_page(&envelope, limits.page_size, expected_offset)?;
            let remaining_rows = limits.max_rows - acquisition.occurrences.len();
            if page_data.rows.len() > remaining_rows {
                for (ordinal, row) in page_data.rows.iter().take(remaining_rows).enumerate() {
                    let occurrence = parse_activity_row(
                        row,
                        &acquisition.wallet,
                        acquisition.start,
                        acquisition.end,
                        pass,
                        page,
                        ordinal,
                    )?;
                    add_occurrence(acquisition, occurrence);
                }
                return Err(ActivityHintIncompleteReason::ActivityRowLimit);
            }
            for (ordinal, row) in page_data.rows.iter().enumerate() {
                let occurrence = parse_activity_row(
                    row,
                    &acquisition.wallet,
                    acquisition.start,
                    acquisition.end,
                    pass,
                    page,
                    ordinal,
                )?;
                add_occurrence(acquisition, occurrence);
            }
            expected_offset = expected_offset
                .checked_add(
                    i64::try_from(page_data.rows.len())
                        .map_err(|_| ActivityHintIncompleteReason::InvalidPageEnvelope)?,
                )
                .filter(|offset| *offset <= i64::from(i32::MAX))
                .ok_or(ActivityHintIncompleteReason::InvalidPageEnvelope)?;
            let Some(next_cursor) = page_data.next_cursor else {
                return Ok(());
            };
            if !used_cursors.insert(next_cursor.clone()) {
                return Err(ActivityHintIncompleteReason::CursorCycle);
            }
            cursor = Some(next_cursor);
        }
    }

    fn page_url(
        &self,
        acquisition: &ActivityHintAcquisition,
        pass: ActivityHintPass,
        page_size: usize,
        cursor: Option<&str>,
    ) -> Url {
        let mut url = self.base_url.clone();
        url.set_path(V2_ACTIVITY_PATH);
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("user", &acquisition.wallet);
            query.append_pair("start", &acquisition.start.to_string());
            query.append_pair("end", &acquisition.end.to_string());
            query.append_pair("sort_by", "TIMESTAMP");
            query.append_pair("sort_direction", "DESC");
            query.append_pair("exclude_deposits_withdrawals", "false");
            query.append_pair("limit", &page_size.to_string());
            if pass == ActivityHintPass::Tip {
                query.append_pair("type", "TIP");
            }
            if let Some(cursor) = cursor {
                query.append_pair("cursor", cursor);
            }
        }
        url
    }
}

fn validate_base_url(value: &str) -> Result<Url, ActivityHintInputError> {
    let url = Url::parse(value).map_err(|_| ActivityHintInputError::InvalidEndpoint)?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(ActivityHintInputError::InvalidEndpoint);
    }
    Ok(url)
}

fn validate_request(
    wallet: &str,
    start: i64,
    end: i64,
    limits: WalletActivityObservationLimits,
) -> Result<(String, Instant), ActivityHintInputError> {
    validate_activity_request(wallet, start, end, limits).and_then(|wallet| {
        let deadline = Instant::now()
            .checked_add(limits.deadline)
            .ok_or(ActivityHintInputError::InvalidRequest)?;
        Ok((wallet, deadline))
    })
}

fn validate_activity_request(
    wallet: &str,
    start: i64,
    end: i64,
    limits: WalletActivityObservationLimits,
) -> Result<String, ActivityHintInputError> {
    let wallet = validate_address(wallet).ok_or(ActivityHintInputError::InvalidRequest)?;
    if start < 1
        || end < start
        || limits.max_pages == 0
        || limits.max_rows == 0
        || limits.page_size == 0
        || limits.page_size > MAX_ACTIVITY_PAGE_SIZE
        || limits.max_activity_requests == 0
        || limits.max_response_bytes == 0
        || limits.max_rpc_requests == 0
        || limits.deadline.is_zero()
    {
        return Err(ActivityHintInputError::InvalidRequest);
    }
    Ok(wallet)
}

fn validate_address(value: &str) -> Option<String> {
    (value.len() == 42
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit()))
    .then(|| value.to_ascii_lowercase())
}

fn empty_pass() -> ActivityHintPassSummary {
    ActivityHintPassSummary {
        pages_requested: 0,
        rows_retained: 0,
        status: ActivityHintPassStatus::NotStarted,
    }
}

fn set_pass_status(
    acquisition: &mut ActivityHintAcquisition,
    pass: ActivityHintPass,
    status: ActivityHintPassStatus,
) {
    match pass {
        ActivityHintPass::DefaultTypes => acquisition.default_pass.status = status,
        ActivityHintPass::Tip => acquisition.tip_pass.status = status,
    }
}

fn increment_pages(acquisition: &mut ActivityHintAcquisition, pass: ActivityHintPass) {
    match pass {
        ActivityHintPass::DefaultTypes => acquisition.default_pass.pages_requested += 1,
        ActivityHintPass::Tip => acquisition.tip_pass.pages_requested += 1,
    }
}

fn page_number(acquisition: &ActivityHintAcquisition, pass: ActivityHintPass) -> usize {
    match pass {
        ActivityHintPass::DefaultTypes => acquisition.default_pass.pages_requested,
        ActivityHintPass::Tip => acquisition.tip_pass.pages_requested,
    }
}

fn total_pages(acquisition: &ActivityHintAcquisition) -> usize {
    acquisition.default_pass.pages_requested + acquisition.tip_pass.pages_requested
}

fn exhausted_limit(
    acquisition: &ActivityHintAcquisition,
    limits: WalletActivityObservationLimits,
) -> Option<ActivityHintIncompleteReason> {
    if acquisition.total_requests >= limits.max_activity_requests {
        Some(ActivityHintIncompleteReason::ActivityRequestLimit)
    } else if total_pages(acquisition) >= limits.max_pages {
        Some(ActivityHintIncompleteReason::ActivityPageLimit)
    } else if acquisition.occurrences.len() >= limits.max_rows {
        Some(ActivityHintIncompleteReason::ActivityRowLimit)
    } else if acquisition.total_response_bytes >= limits.max_response_bytes {
        Some(ActivityHintIncompleteReason::ResponseByteLimit)
    } else {
        None
    }
}

#[derive(Debug)]
struct ParsedActivityPage {
    rows: Vec<Value>,
    next_cursor: Option<String>,
}

fn parse_page(
    value: &Value,
    page_size: usize,
    expected_offset: i64,
) -> Result<ParsedActivityPage, ActivityHintIncompleteReason> {
    let data = value
        .get("data")
        .and_then(Value::as_array)
        .ok_or(ActivityHintIncompleteReason::InvalidPageEnvelope)?;
    let pagination = value
        .get("pagination")
        .and_then(Value::as_object)
        .ok_or(ActivityHintIncompleteReason::InvalidPageEnvelope)?;
    let limit = pagination
        .get("limit")
        .and_then(Value::as_u64)
        .ok_or(ActivityHintIncompleteReason::InvalidPageEnvelope)?;
    let offset = pagination
        .get("offset")
        .and_then(Value::as_i64)
        .ok_or(ActivityHintIncompleteReason::InvalidPageEnvelope)?;
    let has_more = pagination
        .get("has_more")
        .and_then(Value::as_bool)
        .ok_or(ActivityHintIncompleteReason::InvalidPageEnvelope)?;
    let next_cursor_value = pagination.get("next_cursor");
    let next_cursor = match (has_more, next_cursor_value) {
        (false, None | Some(Value::Null)) => None,
        (true, Some(Value::String(cursor))) if !cursor.is_empty() => Some(cursor.clone()),
        _ => return Err(ActivityHintIncompleteReason::InvalidPageEnvelope),
    };
    if limit != page_size as u64
        || offset != expected_offset
        || offset < 0
        || offset > i64::from(i32::MAX)
        || data.len() > page_size
    {
        return Err(ActivityHintIncompleteReason::InvalidPageEnvelope);
    }
    Ok(ParsedActivityPage {
        rows: data.clone(),
        next_cursor,
    })
}

fn parse_activity_row(
    raw: &Value,
    wallet: &str,
    start: i64,
    end: i64,
    pass: ActivityHintPass,
    page: usize,
    ordinal: usize,
) -> Result<ActivityHintOccurrence, ActivityHintIncompleteReason> {
    let row_wallet = raw
        .get("proxy_wallet")
        .and_then(Value::as_str)
        .and_then(validate_address)
        .ok_or(ActivityHintIncompleteReason::InvalidActivityRow)?;
    let timestamp = raw
        .get("timestamp")
        .and_then(Value::as_i64)
        .filter(|timestamp| (start..=end).contains(timestamp))
        .ok_or(ActivityHintIncompleteReason::InvalidActivityRow)?;
    let activity_type = raw
        .get("type")
        .and_then(Value::as_str)
        .filter(|activity_type| !activity_type.trim().is_empty())
        .ok_or(ActivityHintIncompleteReason::InvalidActivityRow)?
        .to_owned();
    let transaction_hash = raw
        .get("transaction_hash")
        .and_then(Value::as_str)
        .filter(|hash| {
            hash.len() == 66
                && hash.starts_with("0x")
                && hash[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .ok_or(ActivityHintIncompleteReason::InvalidActivityRow)?
        .to_ascii_lowercase();
    if row_wallet != wallet {
        return Err(ActivityHintIncompleteReason::InvalidActivityRow);
    }
    Ok(ActivityHintOccurrence {
        pass,
        page,
        ordinal,
        timestamp,
        activity_type,
        transaction_hash,
        raw: raw.clone(),
    })
}

fn add_occurrence(acquisition: &mut ActivityHintAcquisition, occurrence: ActivityHintOccurrence) {
    if acquisition
        .seen_transaction_hashes
        .insert(occurrence.transaction_hash.clone())
    {
        acquisition
            .distinct_transaction_hashes
            .push(occurrence.transaction_hash.clone());
    }
    match occurrence.pass {
        ActivityHintPass::DefaultTypes => acquisition.default_pass.rows_retained += 1,
        ActivityHintPass::Tip => acquisition.tip_pass.rows_retained += 1,
    }
    acquisition.occurrences.push(occurrence);
}

async fn read_bounded_body(
    mut response: Response,
    remaining_bytes: usize,
    deadline: Instant,
    total_bytes: &mut usize,
) -> Result<Vec<u8>, ActivityHintIncompleteReason> {
    let mut body = Vec::new();
    loop {
        let chunk = tokio::select! {
            biased;
            () = sleep_until(deadline) => return Err(ActivityHintIncompleteReason::DeadlineExceeded),
            chunk = response.chunk() => chunk.map_err(|_| ActivityHintIncompleteReason::ProviderUnavailable)?,
        };
        let Some(chunk) = chunk else { break };
        if chunk.len() > remaining_bytes.saturating_sub(body.len()) {
            return Err(ActivityHintIncompleteReason::ResponseByteLimit);
        }
        *total_bytes = total_bytes
            .checked_add(chunk.len())
            .ok_or(ActivityHintIncompleteReason::ResponseByteLimit)?;
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        body::Body,
        extract::{Query, State},
        http::{Response, StatusCode},
        response::IntoResponse,
        routing::get,
    };
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::Duration,
    };

    #[test]
    fn endpoint_rejects_credentials_queries_and_non_loopback_http() {
        for endpoint in [
            "http://example.com",
            "http://user:secret@127.0.0.1:1234",
            "https://example.com/?token=secret",
            "https://example.com/path",
        ] {
            assert_eq!(
                validate_base_url(endpoint),
                Err(ActivityHintInputError::InvalidEndpoint)
            );
        }
        assert!(validate_base_url("http://127.0.0.1:1234").is_ok());
        assert!(validate_base_url("https://data-api.example").is_ok());
    }

    #[test]
    fn activity_page_requires_cursor_and_has_more_to_agree() {
        for pagination in [
            serde_json::json!({"limit":2,"offset":0,"has_more":true}),
            serde_json::json!({"limit":2,"offset":0,"has_more":false,"next_cursor":"x"}),
            serde_json::json!({"limit":2,"offset":0,"has_more":true,"next_cursor":null}),
        ] {
            assert_eq!(
                parse_page(
                    &serde_json::json!({"data":[],"pagination":pagination}),
                    2,
                    0
                )
                .unwrap_err(),
                ActivityHintIncompleteReason::InvalidPageEnvelope
            );
        }
        assert!(parse_page(
            &serde_json::json!({"data":[],"pagination":{"limit":2,"offset":0,"has_more":false}}),
            2,
            0,
        ).is_ok());
        assert!(parse_page(
            &serde_json::json!({"data":[],"pagination":{"limit":2,"offset":0,"has_more":false,"next_cursor":null}}),
            2,
            0,
        ).is_ok());
    }

    #[derive(Clone)]
    struct FixtureState {
        requests: Arc<Mutex<Vec<HashMap<String, String>>>>,
        cycle: bool,
        delay: Duration,
        oversized_body: Option<usize>,
    }

    async fn fixture_page(
        State(state): State<FixtureState>,
        Query(query): Query<HashMap<String, String>>,
    ) -> Response<Body> {
        state.requests.lock().unwrap().push(query.clone());
        if let Some(size) = state.oversized_body {
            return Response::builder()
                .header("content-type", "application/json")
                .body(Body::from(vec![b' '; size]))
                .unwrap();
        }
        if !state.delay.is_zero() {
            tokio::time::sleep(state.delay).await;
        }
        let tip = query.get("type").is_some_and(|value| value == "TIP");
        let cursor = query.get("cursor").map(String::as_str);
        let (rows, has_more, next_cursor, offset) = match (tip, cursor) {
            (false, None) => (
                vec![row(1, "TRADE", 7), row(2, "FUTURE_EVENT", 8)],
                true,
                Some("shared"),
                0,
            ),
            (false, Some("shared")) if state.cycle => (vec![], true, Some("shared"), 2),
            (false, Some("shared")) => (vec![row(1, "CONVERSION", 5)], false, None, 2),
            (true, None) => (vec![row(1, "TIP", 6)], true, Some("shared"), 0),
            (true, Some("shared")) => (vec![row(2, "TIP", 4)], false, None, 1),
            _ => panic!("unexpected cursor"),
        };
        let mut pagination = serde_json::json!({"limit":2,"offset":offset,"has_more":has_more});
        if let Some(cursor) = next_cursor {
            pagination["next_cursor"] = serde_json::json!(cursor);
        }
        Json(serde_json::json!({"data":rows,"pagination":pagination})).into_response()
    }

    fn row(tx: u8, kind: &str, timestamp: i64) -> Value {
        serde_json::json!({
            "proxy_wallet": format!("0x{}", "aa".repeat(20)),
            "timestamp": timestamp,
            "type": kind,
            "transaction_hash": format!("0x{}", format!("{tx:02x}").repeat(32)),
            "price": 0
        })
    }

    async fn fixture_client(
        cycle: bool,
        delay: Duration,
        oversized_body: Option<usize>,
    ) -> (
        PolymarketActivityHintClient,
        Arc<Mutex<Vec<HashMap<String, String>>>>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let state = FixtureState {
            requests: requests.clone(),
            cycle,
            delay,
            oversized_body,
        };
        tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route(V2_ACTIVITY_PATH, get(fixture_page))
                    .with_state(state),
            )
            .await
            .unwrap();
        });
        (PolymarketActivityHintClient::new(&base).unwrap(), requests)
    }

    async fn acquire_fixture(
        client: &PolymarketActivityHintClient,
        limits: WalletActivityObservationLimits,
    ) -> ActivityHintAcquisition {
        let (wallet, deadline) = validate_request(&format!("0x{}", "aa".repeat(20)), 1, 10, limits)
            .expect("valid fixture request");
        client
            .acquire_hints_until(wallet, 1, 10, limits, deadline)
            .await
    }

    #[tokio::test]
    async fn independent_default_and_tip_walks_preserve_occurrences_and_pin_filters() {
        let (client, requests) = fixture_client(false, Duration::ZERO, None).await;
        let acquisition = acquire_fixture(&client, limits()).await;
        assert!(acquisition.is_complete());
        assert_eq!(acquisition.occurrences().len(), 5);
        assert_eq!(acquisition.distinct_transaction_hashes().len(), 2);
        assert_eq!(
            acquisition
                .occurrences()
                .iter()
                .filter(|hint| hint.transaction_hash.ends_with(&"01".repeat(32)))
                .count(),
            3
        );
        assert_eq!(acquisition.occurrences()[1].activity_type, "FUTURE_EVENT");
        assert_eq!(acquisition.occurrences()[1].raw["price"], 0);
        assert_eq!(
            acquisition.occurrences()[0].pass,
            ActivityHintPass::DefaultTypes
        );
        assert_eq!(acquisition.occurrences()[0].page, 1);
        assert_eq!(acquisition.occurrences()[0].ordinal, 0);
        assert_eq!(acquisition.occurrences()[3].pass, ActivityHintPass::Tip);
        assert_eq!(
            acquisition.default_pass().status,
            ActivityHintPassStatus::Complete
        );
        assert_eq!(
            acquisition.tip_pass().status,
            ActivityHintPassStatus::Complete
        );
        assert_eq!(acquisition.total_requests(), 4);
        assert_eq!(acquisition.default_pass().pages_requested, 2);
        assert_eq!(acquisition.tip_pass().pages_requested, 2);
        assert!(acquisition.history_coverage_unproven());

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 4);
        let expected_wallet = format!("0x{}", "aa".repeat(20));
        for (index, query) in requests.iter().enumerate() {
            assert_eq!(
                query.get("user").map(String::as_str),
                Some(expected_wallet.as_str())
            );
            assert_eq!(query.get("start").map(String::as_str), Some("1"));
            assert_eq!(query.get("end").map(String::as_str), Some("10"));
            assert_eq!(query.get("sort_by").map(String::as_str), Some("TIMESTAMP"));
            assert_eq!(
                query.get("sort_direction").map(String::as_str),
                Some("DESC")
            );
            assert_eq!(
                query
                    .get("exclude_deposits_withdrawals")
                    .map(String::as_str),
                Some("false")
            );
            assert_eq!(query.get("limit").map(String::as_str), Some("2"));
            if index == 0 || index == 1 {
                assert!(!query.contains_key("type"));
            } else {
                assert_eq!(query.get("type").map(String::as_str), Some("TIP"));
            }
            if index == 1 || index == 3 {
                assert_eq!(query.get("cursor").map(String::as_str), Some("shared"));
            }
        }
    }

    #[tokio::test]
    async fn repeated_cursor_within_one_pass_is_incomplete_but_not_shared_across_passes() {
        let (client, requests) = fixture_client(true, Duration::ZERO, None).await;
        let acquisition = acquire_fixture(&client, limits()).await;
        assert_eq!(
            acquisition.incomplete_reason(),
            Some(ActivityHintIncompleteReason::CursorCycle)
        );
        assert_eq!(acquisition.occurrences().len(), 2);
        assert_eq!(
            acquisition.tip_pass().status,
            ActivityHintPassStatus::NotStarted
        );
        assert_eq!(requests.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn exact_terminal_page_row_and_request_caps_are_complete_but_nonterminal_caps_are_not() {
        let (client, _) = fixture_client(false, Duration::ZERO, None).await;
        let complete = acquire_fixture(&client, limits()).await;
        assert!(complete.is_complete());
        let mut exact_bytes = limits();
        exact_bytes.max_response_bytes = complete.total_response_bytes();
        let (client, _) = fixture_client(false, Duration::ZERO, None).await;
        assert!(acquire_fixture(&client, exact_bytes).await.is_complete());

        for (field, reason) in [
            ("max_pages", ActivityHintIncompleteReason::ActivityPageLimit),
            ("max_rows", ActivityHintIncompleteReason::ActivityRowLimit),
            (
                "max_activity_requests",
                ActivityHintIncompleteReason::ActivityRequestLimit,
            ),
        ] {
            let mut capped = limits();
            match field {
                "max_pages" => capped.max_pages = 1,
                "max_rows" => capped.max_rows = 1,
                _ => capped.max_activity_requests = 1,
            }
            let (client, _) = fixture_client(false, Duration::ZERO, None).await;
            let acquisition = acquire_fixture(&client, capped).await;
            assert_eq!(acquisition.incomplete_reason(), Some(reason), "{field}");
            assert!(acquisition.occurrences().len() <= capped.max_rows);
        }
    }

    #[tokio::test]
    async fn oversized_response_and_deadline_are_explicit_incomplete_results() {
        let mut capped = limits();
        capped.max_response_bytes = 32;
        let (client, _) = fixture_client(false, Duration::ZERO, Some(100_000)).await;
        assert_eq!(
            acquire_fixture(&client, capped).await.incomplete_reason(),
            Some(ActivityHintIncompleteReason::ResponseByteLimit)
        );

        let (client, _) = fixture_client(false, Duration::from_millis(100), None).await;
        let mut timed = limits();
        timed.deadline = Duration::from_millis(5);
        assert_eq!(
            acquire_fixture(&client, timed).await.incomplete_reason(),
            Some(ActivityHintIncompleteReason::DeadlineExceeded)
        );
    }

    #[tokio::test]
    async fn missing_locator_wallet_mismatch_and_out_of_window_rows_are_not_dropped() {
        let valid = row(1, "CONVERSION", 5);
        for invalid in [
            serde_json::json!({"proxy_wallet":format!("0x{}", "aa".repeat(20)),"timestamp":5,"type":"CONVERSION"}),
            serde_json::json!({"proxy_wallet":format!("0x{}", "bb".repeat(20)),"timestamp":5,"type":"CONVERSION","transaction_hash":format!("0x{}", "11".repeat(32))}),
            serde_json::json!({"proxy_wallet":format!("0x{}", "aa".repeat(20)),"timestamp":99,"type":"CONVERSION","transaction_hash":format!("0x{}", "11".repeat(32))}),
        ] {
            assert_eq!(
                parse_activity_row(
                    &invalid,
                    &format!("0x{}", "aa".repeat(20)),
                    1,
                    10,
                    ActivityHintPass::Tip,
                    1,
                    0
                ),
                Err(ActivityHintIncompleteReason::InvalidActivityRow)
            );
        }
        assert!(
            parse_activity_row(
                &valid,
                &format!("0x{}", "aa".repeat(20)),
                1,
                10,
                ActivityHintPass::DefaultTypes,
                1,
                0
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn provider_refusal_is_an_explicit_redacted_incomplete_result() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    V2_ACTIVITY_PATH,
                    get(|| async { StatusCode::TOO_MANY_REQUESTS }),
                ),
            )
            .await
            .unwrap();
        });
        let client = PolymarketActivityHintClient::new(&base).unwrap();
        let acquisition = acquire_fixture(&client, limits()).await;
        assert_eq!(
            acquisition.incomplete_reason(),
            Some(ActivityHintIncompleteReason::ProviderRefused(429))
        );
        assert_eq!(acquisition.total_requests(), 1);
        assert_eq!(acquisition.total_response_bytes(), 0);
    }

    #[tokio::test]
    async fn caller_cancellation_stops_activity_pagination() {
        let (client, requests) = fixture_client(false, Duration::from_millis(250), None).await;
        let caller = tokio::spawn(async move { acquire_fixture(&client, limits()).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while requests.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("first request reached loopback server");
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    fn limits() -> WalletActivityObservationLimits {
        WalletActivityObservationLimits {
            max_pages: 4,
            max_rows: 5,
            page_size: 2,
            max_activity_requests: 4,
            max_response_bytes: 20_000,
            max_rpc_requests: 64,
            deadline: Duration::from_secs(5),
        }
    }
}
