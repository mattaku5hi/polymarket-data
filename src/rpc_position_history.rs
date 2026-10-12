//! Bounded, read-only JSON-RPC observation of raw position-transfer history.
//!
//! This records a provider response and caller anchor comparison. It is not a
//! consensus proof, complete inventory, rooted balance, basis or P&L result.

use std::{collections::BTreeMap, net::IpAddr, time::Duration};

use chrono::{DateTime, Utc};
use reqwest::{Client, ClientBuilder, Url};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::position_history::{
    CTF_EMITTER, MAX_HISTORY_REQUESTS, MAX_HISTORY_RESPONSE_BYTES, MAX_HISTORY_TOTAL_BYTES,
    POSITION_MANAGER_EMITTER, PositionHistoryDirection, PositionHistoryError, PositionTransferLog,
    RecordedSqdPositionHistorySegmentObservation, SqdPositionHistoryObservation,
    TRANSFER_BATCH_TOPIC, TRANSFER_SINGLE_TOPIC, normalize_address, normalize_hash, normalize_log,
};

const RPC_CHAIN_ID: u64 = 137;
const RPC_CONTEXT_CALLS: u128 = 4;
const RPC_SEGMENT_CONTEXT_CALLS: u128 = 5;
const MAX_RECORDED_REQUEST_BYTES: usize = 4096;

/// Structural source capture with an extra start-header observation; no ancestry proof.
pub const RPC_POSITION_HISTORY_SEGMENT_POLICY_VERSION: &str =
    "rpc-position-history-start-boundary-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RpcPositionHistoryError {
    #[error("RPC position-history input is invalid")]
    InvalidInput,
    #[error("RPC position-history HTTP client could not be built")]
    ClientBuild,
    #[error("RPC position-history call budget exceeded")]
    RequestBudgetExceeded,
    #[error("RPC position-history timed out")]
    Timeout,
    #[error("RPC position-history request failed")]
    RequestFailed,
    #[error(
        "RPC position-history returned HTTP {status} (retry after {retry_after_seconds:?} seconds)"
    )]
    HttpStatus {
        status: u16,
        retry_after_seconds: Option<u64>,
    },
    #[error("RPC position-history returned JSON-RPC error code {code}")]
    RpcError { code: i64 },
    #[error("RPC position-history response exceeded a byte limit")]
    BodyBudgetExceeded,
    #[error("RPC position-history response could not be read")]
    ResponseUnreadable,
    #[error("RPC position-history response was malformed")]
    MalformedResponse,
    #[error("RPC position-history chain id was not Polygon")]
    WrongChain,
    #[error("RPC position-history finalized head is below the requested block")]
    NotFinalized,
    #[error("RPC position-history terminal anchor did not match")]
    AnchorMismatch,
    #[error("RPC position-history returned conflicting block headers")]
    ConflictingHeader,
    #[error("RPC position-history returned conflicting log locators")]
    ConflictingLocator,
}

/// Fixed whitelist of JSON-RPC methods issued by this reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcPositionHistoryRequestMethod {
    ChainId,
    GetBlockByNumber,
    GetLogs,
}

/// Fixed reader phase for a planned JSON-RPC call; contains no raw request values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcPositionHistoryRequestPhase {
    Chain,
    Finalized,
    TerminalBefore,
    StartHeader,
    Logs {
        direction: PositionHistoryDirection,
        from_block: u64,
        through_block: u64,
    },
    TerminalAfter,
}

/// Per-read locator for a failed network call; this is not a consensus proof.
///
/// The ordinal identifies this reader's planned dispatch order. It does not prove the provider
/// received the request; for example, request pacing may time out before an HTTP send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcPositionHistoryRequestLocator {
    request_ordinal: u64,
    method: RpcPositionHistoryRequestMethod,
    phase: RpcPositionHistoryRequestPhase,
}

impl RpcPositionHistoryRequestLocator {
    #[must_use]
    pub const fn request_ordinal(&self) -> u64 {
        self.request_ordinal
    }

    #[must_use]
    pub const fn method(&self) -> RpcPositionHistoryRequestMethod {
        self.method
    }

    #[must_use]
    pub const fn phase(&self) -> RpcPositionHistoryRequestPhase {
        self.phase
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("RPC position-history request failed during {request:?}: {error}")]
pub struct RpcPositionHistoryFailure {
    error: RpcPositionHistoryError,
    request: Option<RpcPositionHistoryRequestLocator>,
}

impl RpcPositionHistoryFailure {
    #[must_use]
    pub const fn error(&self) -> RpcPositionHistoryError {
        self.error
    }

    #[must_use]
    pub const fn request(&self) -> Option<RpcPositionHistoryRequestLocator> {
        self.request
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcPositionHistoryRequest {
    pub holder_address: String,
    pub from_block: u64,
    pub through_block: u64,
    /// Caller comparison value, not a consensus-proven anchor.
    pub expected_through_hash: String,
    pub max_requests: usize,
    pub max_total_response_bytes: usize,
    pub total_timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcPositionHistoryPage {
    method: String,
    request_json: String,
    response_json: String,
}

/// Untrusted raw JSON-RPC frames retained by the host capture journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedRpcPositionHistoryPage {
    pub request_json: String,
    pub response_json: String,
}

impl RpcPositionHistoryPage {
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }
    #[must_use]
    pub fn request_json(&self) -> &str {
        &self.request_json
    }
    #[must_use]
    pub fn response_json(&self) -> &str {
        &self.response_json
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RpcBlockHeader {
    number: u64,
    hash: String,
    parent_hash: String,
    state_root: String,
    transactions_root: String,
    receipts_root: String,
    logs_bloom: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcPositionHistoryObservation {
    content: RpcPositionHistoryContent,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    elapsed: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RpcPositionHistoryContent {
    holder_address: String,
    from_block: u64,
    through_block: u64,
    expected_through_hash: String,
    terminal_header: RpcBlockHeader,
    logs: Vec<PositionTransferLog>,
    pages: Vec<RpcPositionHistoryPage>,
    request_count: usize,
    response_bytes: usize,
}

impl RpcPositionHistoryObservation {
    #[must_use]
    pub fn holder_address(&self) -> &str {
        &self.content.holder_address
    }
    #[must_use]
    pub const fn from_block(&self) -> u64 {
        self.content.from_block
    }
    #[must_use]
    pub const fn through_block(&self) -> u64 {
        self.content.through_block
    }
    #[must_use]
    pub fn expected_through_hash(&self) -> &str {
        &self.content.expected_through_hash
    }
    #[must_use]
    pub const fn terminal_number(&self) -> u64 {
        self.content.terminal_header.number
    }
    #[must_use]
    pub fn terminal_hash(&self) -> &str {
        &self.content.terminal_header.hash
    }
    #[must_use]
    pub fn terminal_state_root(&self) -> &str {
        &self.content.terminal_header.state_root
    }
    #[must_use]
    pub fn terminal_transactions_root(&self) -> &str {
        &self.content.terminal_header.transactions_root
    }
    #[must_use]
    pub fn terminal_receipts_root(&self) -> &str {
        &self.content.terminal_header.receipts_root
    }
    #[must_use]
    pub fn logs(&self) -> &[PositionTransferLog] {
        &self.content.logs
    }
    #[must_use]
    pub fn pages(&self) -> &[RpcPositionHistoryPage] {
        &self.content.pages
    }
    #[must_use]
    pub const fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }
    #[must_use]
    pub const fn completed_at(&self) -> DateTime<Utc> {
        self.completed_at
    }
    #[must_use]
    pub const fn elapsed(&self) -> Duration {
        self.elapsed
    }
    #[must_use]
    pub const fn request_count(&self) -> usize {
        self.content.request_count
    }
    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.content.response_bytes
    }
}

/// A bounded history observation with the provider-reported header at its start block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcPositionHistorySegmentObservation {
    history: RpcPositionHistoryObservation,
    start_header: RpcBlockHeader,
}

/// Offline-reverified content from a bounded ordered RPC transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedRpcPositionHistorySegmentObservation {
    content: RpcPositionHistoryContent,
    start_header: RpcBlockHeader,
}

impl RpcPositionHistorySegmentObservation {
    #[must_use]
    pub const fn history(&self) -> &RpcPositionHistoryObservation {
        &self.history
    }

    #[must_use]
    pub const fn start_block_number(&self) -> u64 {
        self.start_header.number
    }

    #[must_use]
    pub fn start_block_hash(&self) -> &str {
        &self.start_header.hash
    }

    #[must_use]
    pub fn start_parent_hash(&self) -> &str {
        &self.start_header.parent_hash
    }
}

impl RecordedRpcPositionHistorySegmentObservation {
    #[must_use]
    pub fn holder_address(&self) -> &str {
        &self.content.holder_address
    }
    #[must_use]
    pub const fn from_block(&self) -> u64 {
        self.content.from_block
    }
    #[must_use]
    pub const fn through_block(&self) -> u64 {
        self.content.through_block
    }
    #[must_use]
    pub fn expected_through_hash(&self) -> &str {
        &self.content.expected_through_hash
    }
    #[must_use]
    pub const fn start_block_number(&self) -> u64 {
        self.start_header.number
    }
    #[must_use]
    pub fn start_block_hash(&self) -> &str {
        &self.start_header.hash
    }
    #[must_use]
    pub fn start_parent_hash(&self) -> &str {
        &self.start_header.parent_hash
    }
    #[must_use]
    pub const fn terminal_number(&self) -> u64 {
        self.content.terminal_header.number
    }
    #[must_use]
    pub fn terminal_hash(&self) -> &str {
        &self.content.terminal_header.hash
    }
    #[must_use]
    pub fn terminal_state_root(&self) -> &str {
        &self.content.terminal_header.state_root
    }
    #[must_use]
    pub fn terminal_transactions_root(&self) -> &str {
        &self.content.terminal_header.transactions_root
    }
    #[must_use]
    pub fn terminal_receipts_root(&self) -> &str {
        &self.content.terminal_header.receipts_root
    }
    #[must_use]
    pub fn logs(&self) -> &[PositionTransferLog] {
        &self.content.logs
    }
    #[must_use]
    pub fn pages(&self) -> &[RpcPositionHistoryPage] {
        &self.content.pages
    }
    #[must_use]
    pub const fn request_count(&self) -> usize {
        self.content.request_count
    }
    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.content.response_bytes
    }
}

/// Validates matching source events and complete provider-reported start headers.
#[cfg(feature = "chain-audit")]
pub fn validate_position_history_segment_source_agreement(
    source_a: &RpcPositionHistorySegmentObservation,
    source_b: &RpcPositionHistorySegmentObservation,
) -> Result<(), crate::position_history_receipts::PositionHistoryReceiptJoinError> {
    crate::position_history_receipts::validate_position_history_source_agreement(
        source_a.history(),
        source_b.history(),
    )?;
    if source_a.start_header != source_b.start_header {
        return Err(
            crate::position_history_receipts::PositionHistoryReceiptJoinError::SourceMismatch,
        );
    }
    Ok(())
}

/// Validates matching content and complete start headers from two stored transcripts.
#[cfg(feature = "chain-audit")]
pub fn validate_recorded_position_history_segment_source_agreement(
    source_a: &RecordedRpcPositionHistorySegmentObservation,
    source_b: &RecordedRpcPositionHistorySegmentObservation,
) -> Result<(), crate::position_history_receipts::PositionHistoryReceiptJoinError> {
    let a = &source_a.content;
    let b = &source_b.content;
    if a.from_block > a.through_block
        || a.holder_address != b.holder_address
        || a.from_block != b.from_block
        || a.through_block != b.through_block
        || a.expected_through_hash != b.expected_through_hash
        || a.terminal_header.number != a.through_block
        || b.terminal_header.number != b.through_block
        || a.terminal_header.hash != a.expected_through_hash
        || b.terminal_header.hash != b.expected_through_hash
        || a.terminal_header.hash != b.terminal_header.hash
        || a.terminal_header.state_root != b.terminal_header.state_root
        || a.terminal_header.transactions_root != b.terminal_header.transactions_root
        || a.terminal_header.receipts_root != b.terminal_header.receipts_root
    {
        return Err(
            crate::position_history_receipts::PositionHistoryReceiptJoinError::InvalidInput,
        );
    }
    if a.logs != b.logs {
        return Err(
            crate::position_history_receipts::PositionHistoryReceiptJoinError::SourceMismatch,
        );
    }
    if source_a.start_header != source_b.start_header {
        return Err(
            crate::position_history_receipts::PositionHistoryReceiptJoinError::SourceMismatch,
        );
    }
    Ok(())
}

/// Compares one live RPC and one live SQD bounded segment as provider-reported observations.
/// Agreement does not prove either provider complete or establish canonical chain truth.
#[cfg(feature = "chain-audit")]
pub fn validate_rpc_sqd_position_history_segment_source_agreement(
    rpc: &RpcPositionHistorySegmentObservation,
    sqd: &SqdPositionHistoryObservation,
) -> Result<(), crate::position_history_receipts::PositionHistoryReceiptJoinError> {
    validate_rpc_sqd_content(
        &rpc.history.content,
        &rpc.start_header,
        SqdComparison {
            holder: sqd.holder_address(),
            from_block: sqd.from_block(),
            through_block: sqd.through_block(),
            expected_through_hash: sqd.expected_through_hash(),
            start_header: sqd.start_header(),
            from_terminal: sqd.from_terminal(),
            to_terminal: sqd.to_terminal(),
            logs: sqd.logs(),
        },
    )
}

/// Compares endpoint-free RPC and SQD transcripts after each SDK parser revalidates its pages.
#[cfg(feature = "chain-audit")]
pub fn validate_recorded_rpc_sqd_position_history_segment_source_agreement(
    rpc: &RecordedRpcPositionHistorySegmentObservation,
    sqd: &RecordedSqdPositionHistorySegmentObservation,
) -> Result<(), crate::position_history_receipts::PositionHistoryReceiptJoinError> {
    validate_rpc_sqd_content(
        &rpc.content,
        &rpc.start_header,
        SqdComparison {
            holder: sqd.holder_address(),
            from_block: sqd.from_block(),
            through_block: sqd.through_block(),
            expected_through_hash: sqd.expected_through_hash(),
            start_header: sqd.start_header(),
            from_terminal: sqd.from_terminal(),
            to_terminal: sqd.to_terminal(),
            logs: sqd.logs(),
        },
    )
}

#[cfg(feature = "chain-audit")]
struct SqdComparison<'a> {
    holder: &'a str,
    from_block: u64,
    through_block: u64,
    expected_through_hash: &'a str,
    start_header: &'a crate::position_history::SqdBlockHeader,
    from_terminal: &'a crate::position_history::SqdBlockHeader,
    to_terminal: &'a crate::position_history::SqdBlockHeader,
    logs: &'a [PositionTransferLog],
}

#[cfg(feature = "chain-audit")]
fn validate_rpc_sqd_content(
    rpc: &RpcPositionHistoryContent,
    rpc_start: &RpcBlockHeader,
    sqd: SqdComparison<'_>,
) -> Result<(), crate::position_history_receipts::PositionHistoryReceiptJoinError> {
    use crate::position_history_receipts::PositionHistoryReceiptJoinError as Error;
    if rpc.holder_address != sqd.holder
        || rpc.from_block != sqd.from_block
        || rpc.through_block != sqd.through_block
        || rpc.expected_through_hash != sqd.expected_through_hash
        || rpc.from_block > rpc.through_block
        || rpc.terminal_header.number != rpc.through_block
        || rpc.terminal_header.hash != rpc.expected_through_hash
        || sqd.from_terminal.number() != sqd.through_block
        || sqd.to_terminal.number() != sqd.through_block
        || sqd.to_terminal.hash() != sqd.expected_through_hash
        || sqd.from_terminal != sqd.to_terminal
        || !rpc_header_matches_sqd(&rpc.terminal_header, sqd.to_terminal)
        || !rpc_header_matches_sqd(rpc_start, sqd.start_header)
    {
        return Err(Error::InvalidInput);
    }
    if rpc.logs != sqd.logs {
        return Err(Error::SourceMismatch);
    }
    Ok(())
}

#[cfg(feature = "chain-audit")]
fn rpc_header_matches_sqd(
    rpc: &RpcBlockHeader,
    sqd: &crate::position_history::SqdBlockHeader,
) -> bool {
    rpc.number == sqd.number()
        && rpc.hash == sqd.hash()
        && rpc.parent_hash == sqd.parent_hash()
        && rpc.state_root == sqd.state_root()
        && rpc.transactions_root == sqd.transactions_root()
        && rpc.receipts_root == sqd.receipts_root()
        && rpc.logs_bloom == sqd.logs_bloom()
}

/// Caller-configured JSON-RPC endpoint. No provider URL or credential is selected here.
pub struct RpcPositionHistoryReader {
    client: Client,
    endpoint: Url,
    pacing: Option<RpcRequestPacing>,
}

struct RpcRequestPacing {
    minimum_interval: Duration,
    next_start: Mutex<Option<tokio::time::Instant>>,
}

impl RpcPositionHistoryReader {
    /// HTTPS is required except for loopback HTTP used by local test servers.
    pub fn new(builder: ClientBuilder, endpoint: &str) -> Result<Self, RpcPositionHistoryError> {
        Self::new_with_request_interval(builder, endpoint, Duration::ZERO)
    }

    /// Builds a reader with an optional minimum delay between actual request starts.
    pub fn new_with_request_interval(
        builder: ClientBuilder,
        endpoint: &str,
        minimum_request_interval: Duration,
    ) -> Result<Self, RpcPositionHistoryError> {
        if tokio::time::Instant::now()
            .checked_add(minimum_request_interval)
            .is_none()
        {
            return Err(RpcPositionHistoryError::InvalidInput);
        }
        let endpoint = Url::parse(endpoint).map_err(|_| RpcPositionHistoryError::InvalidInput)?;
        let host = endpoint
            .host_str()
            .ok_or(RpcPositionHistoryError::InvalidInput)?;
        let loopback = host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
            || host.eq_ignore_ascii_case("localhost");
        if (endpoint.scheme() != "https" && !(endpoint.scheme() == "http" && loopback))
            || endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(RpcPositionHistoryError::InvalidInput);
        }
        let client = builder
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .map_err(|_| RpcPositionHistoryError::ClientBuild)?;
        let pacing = (!minimum_request_interval.is_zero()).then(|| RpcRequestPacing {
            minimum_interval: minimum_request_interval,
            next_start: Mutex::new(None),
        });
        Ok(Self {
            client,
            endpoint,
            pacing,
        })
    }

    /// Reads chain/finality, a before anchor, both full-range filters, and an after anchor.
    pub async fn read_history(
        &self,
        request: &RpcPositionHistoryRequest,
    ) -> Result<RpcPositionHistoryObservation, RpcPositionHistoryError> {
        let mut source = RpcCallSource::network(self, false);
        Self::read_history_inner(request, None, false, &mut source)
            .await?
            .into_network_observation()
    }

    /// Reads one finite interval using caller-sized inclusive `eth_getLogs` ranges.
    ///
    /// The chunk width is required and provider-neutral. This returns an observation only if
    /// every chunk and both directions succeed under the request's shared budgets.
    pub async fn read_history_paginated(
        &self,
        request: &RpcPositionHistoryRequest,
        max_blocks_per_log_query: u64,
    ) -> Result<RpcPositionHistoryObservation, RpcPositionHistoryError> {
        if max_blocks_per_log_query == 0 {
            return Err(RpcPositionHistoryError::InvalidInput);
        }
        let mut source = RpcCallSource::network(self, false);
        Self::read_history_inner(request, Some(max_blocks_per_log_query), false, &mut source)
            .await?
            .into_network_observation()
    }

    /// Reads a bounded interval and captures its provider-reported start header under the same
    /// request deadline and response-byte budget.
    pub async fn read_history_segment_paginated(
        &self,
        request: &RpcPositionHistoryRequest,
        max_blocks_per_log_query: u64,
    ) -> Result<RpcPositionHistorySegmentObservation, RpcPositionHistoryError> {
        if max_blocks_per_log_query == 0 {
            return Err(RpcPositionHistoryError::InvalidInput);
        }
        let mut source = RpcCallSource::network(self, false);
        let output =
            Self::read_history_inner(request, Some(max_blocks_per_log_query), true, &mut source)
                .await?;
        let start_header = output
            .start_header
            .clone()
            .ok_or(RpcPositionHistoryError::MalformedResponse)?;
        Ok(RpcPositionHistorySegmentObservation {
            history: output.into_network_observation()?,
            start_header,
        })
    }

    /// Reads a bounded interval and includes a sanitized locator when an RPC call fails.
    ///
    /// The locator reports the planned call phase and ordinal only. It does not establish that
    /// the provider received the request or that any partial history is valid.
    pub async fn read_history_segment_paginated_with_failure_context(
        &self,
        request: &RpcPositionHistoryRequest,
        max_blocks_per_log_query: u64,
    ) -> Result<RpcPositionHistorySegmentObservation, RpcPositionHistoryFailure> {
        if max_blocks_per_log_query == 0 {
            return Err(RpcPositionHistoryFailure {
                error: RpcPositionHistoryError::InvalidInput,
                request: None,
            });
        }
        let mut source = RpcCallSource::network(self, true);
        let result = async {
            let output = Self::read_history_inner(
                request,
                Some(max_blocks_per_log_query),
                true,
                &mut source,
            )
            .await?;
            let start_header = output
                .start_header
                .clone()
                .ok_or(RpcPositionHistoryError::MalformedResponse)?;
            Ok(RpcPositionHistorySegmentObservation {
                history: output.into_network_observation()?,
                start_header,
            })
        }
        .await;
        result.map_err(|error| RpcPositionHistoryFailure {
            error,
            request: source.last_failure(),
        })
    }

    async fn read_history_inner(
        request: &RpcPositionHistoryRequest,
        max_blocks_per_log_query: Option<u64>,
        include_start_header: bool,
        source: &mut RpcCallSource<'_>,
    ) -> Result<ReadOutput, RpcPositionHistoryError> {
        let holder = normalize_address(&request.holder_address)
            .ok_or(RpcPositionHistoryError::InvalidInput)?;
        if holder == format!("0x{}", "00".repeat(20)) {
            return Err(RpcPositionHistoryError::InvalidInput);
        }
        let expected_hash = normalize_hash(&request.expected_through_hash)
            .ok_or(RpcPositionHistoryError::InvalidInput)?;
        if request.from_block > request.through_block
            || request.max_requests == 0
            || request.max_requests > MAX_HISTORY_REQUESTS
            || request.max_total_response_bytes == 0
            || request.max_total_response_bytes > MAX_HISTORY_TOTAL_BYTES
            || request.total_timeout.is_zero()
        {
            return Err(RpcPositionHistoryError::InvalidInput);
        }
        let chunk_count = match max_blocks_per_log_query {
            Some(width) => {
                let inclusive_blocks =
                    u128::from(request.through_block) - u128::from(request.from_block) + 1;
                inclusive_blocks.div_ceil(u128::from(width))
            }
            None => 1,
        };
        let context_calls = if include_start_header {
            RPC_SEGMENT_CONTEXT_CALLS
        } else {
            RPC_CONTEXT_CALLS
        };
        let planned_calls = context_calls + 2 * chunk_count;
        if planned_calls > request.max_requests as u128 {
            return Err(RpcPositionHistoryError::RequestBudgetExceeded);
        }
        source.validate_count(planned_calls)?;

        let started_at = source.is_network().then(Utc::now);
        let start = tokio::time::Instant::now();
        let deadline = start
            .checked_add(request.total_timeout)
            .ok_or(RpcPositionHistoryError::InvalidInput)?;
        let mut state = ReadState {
            pages: Vec::new(),
            response_bytes: 0,
            next_id: 1,
        };
        let chain = source
            .call(
                "eth_chainId",
                json!([]),
                RpcPositionHistoryRequestPhase::Chain,
                deadline,
                request,
                &mut state,
            )
            .await?;
        if parse_quantity(&chain) != Some(RPC_CHAIN_ID) {
            return Err(RpcPositionHistoryError::WrongChain);
        }
        let finalized = source
            .call(
                "eth_getBlockByNumber",
                json!(["finalized", false]),
                RpcPositionHistoryRequestPhase::Finalized,
                deadline,
                request,
                &mut state,
            )
            .await?;
        let finalized_number = parse_header(&finalized)?.number;
        if finalized_number < request.through_block {
            return Err(RpcPositionHistoryError::NotFinalized);
        }
        let through_tag = quantity(request.through_block);
        let before = parse_header(
            &source
                .call(
                    "eth_getBlockByNumber",
                    json!([through_tag, false]),
                    RpcPositionHistoryRequestPhase::TerminalBefore,
                    deadline,
                    request,
                    &mut state,
                )
                .await?,
        )?;
        if before.number != request.through_block {
            return Err(RpcPositionHistoryError::ConflictingHeader);
        }
        if before.hash != expected_hash {
            return Err(RpcPositionHistoryError::AnchorMismatch);
        }
        let start_header = if include_start_header {
            let header = parse_header(
                &source
                    .call(
                        "eth_getBlockByNumber",
                        json!([quantity(request.from_block), false]),
                        RpcPositionHistoryRequestPhase::StartHeader,
                        deadline,
                        request,
                        &mut state,
                    )
                    .await?,
            )?;
            if header.number != request.from_block {
                return Err(RpcPositionHistoryError::ConflictingHeader);
            }
            if request.from_block == request.through_block && header != before {
                return Err(RpcPositionHistoryError::ConflictingHeader);
            }
            Some(header)
        } else {
            None
        };

        let holder_topic = format!("0x{:0>64}", &holder[2..]);
        let mut logs = BTreeMap::<(String, u64), PositionTransferLog>::new();
        let mut block_hashes = BTreeMap::<u64, String>::new();
        let mut transaction_hashes = BTreeMap::<(String, u64), String>::new();
        let mut chunk_start = request.from_block;
        loop {
            let chunk_end = match max_blocks_per_log_query {
                Some(width) => chunk_start
                    .saturating_add(width - 1)
                    .min(request.through_block),
                None => request.through_block,
            };
            for direction in [PositionHistoryDirection::From, PositionHistoryDirection::To] {
                let topics = match direction {
                    PositionHistoryDirection::From => json!([
                        [TRANSFER_SINGLE_TOPIC, TRANSFER_BATCH_TOPIC],
                        null,
                        holder_topic,
                        null
                    ]),
                    PositionHistoryDirection::To => json!([
                        [TRANSFER_SINGLE_TOPIC, TRANSFER_BATCH_TOPIC],
                        null,
                        null,
                        holder_topic
                    ]),
                };
                let filter = json!({"fromBlock": quantity(chunk_start), "toBlock": quantity(chunk_end),
                    "address": [CTF_EMITTER, POSITION_MANAGER_EMITTER], "topics": topics});
                let result = source
                    .call(
                        "eth_getLogs",
                        json!([filter]),
                        RpcPositionHistoryRequestPhase::Logs {
                            direction,
                            from_block: chunk_start,
                            through_block: chunk_end,
                        },
                        deadline,
                        request,
                        &mut state,
                    )
                    .await?;
                let entries = result
                    .as_array()
                    .ok_or(RpcPositionHistoryError::MalformedResponse)?;
                for entry in entries {
                    if entry.is_null()
                        || entry.get("removed").and_then(Value::as_bool) != Some(false)
                    {
                        return Err(RpcPositionHistoryError::MalformedResponse);
                    }
                    let block_number = entry
                        .get("blockNumber")
                        .and_then(parse_quantity)
                        .ok_or(RpcPositionHistoryError::MalformedResponse)?;
                    if block_number < chunk_start || block_number > chunk_end {
                        return Err(RpcPositionHistoryError::MalformedResponse);
                    }
                    let block_hash = entry
                        .get("blockHash")
                        .and_then(Value::as_str)
                        .and_then(normalize_hash)
                        .ok_or(RpcPositionHistoryError::MalformedResponse)?;
                    if include_start_header
                        && ((block_number == request.from_block
                            && start_header
                                .as_ref()
                                .is_some_and(|header| block_hash != header.hash))
                            || (block_number == request.through_block && block_hash != before.hash))
                    {
                        return Err(RpcPositionHistoryError::ConflictingHeader);
                    }
                    let log = normalize_log(entry, block_number, &block_hash, &holder, direction)
                        .map_err(map_log_error)?;
                    let locator = (block_hash, log.log_index());
                    if block_hashes
                        .insert(block_number, locator.0.clone())
                        .is_some_and(|previous| previous != locator.0)
                    {
                        return Err(RpcPositionHistoryError::ConflictingHeader);
                    }
                    if transaction_hashes
                        .insert(
                            (locator.0.clone(), log.transaction_index()),
                            log.transaction_hash().to_owned(),
                        )
                        .is_some_and(|previous| previous != log.transaction_hash())
                    {
                        return Err(RpcPositionHistoryError::ConflictingLocator);
                    }
                    if let Some(previous) = logs.get(&locator) {
                        if previous != &log {
                            return Err(RpcPositionHistoryError::ConflictingLocator);
                        }
                    } else {
                        logs.insert(locator, log);
                    }
                }
            }
            if chunk_end == request.through_block {
                break;
            }
            chunk_start = chunk_end + 1;
        }
        let after = parse_header(
            &source
                .call(
                    "eth_getBlockByNumber",
                    json!([through_tag, false]),
                    RpcPositionHistoryRequestPhase::TerminalAfter,
                    deadline,
                    request,
                    &mut state,
                )
                .await?,
        )?;
        if before != after || before.hash != expected_hash {
            return Err(RpcPositionHistoryError::AnchorMismatch);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(RpcPositionHistoryError::Timeout);
        }
        let mut ordered_logs: Vec<_> = logs.into_values().collect();
        ordered_logs
            .sort_by_key(|log| (log.block_number(), log.transaction_index(), log.log_index()));
        Ok(ReadOutput {
            content: RpcPositionHistoryContent {
                holder_address: holder,
                from_block: request.from_block,
                through_block: request.through_block,
                expected_through_hash: expected_hash,
                terminal_header: before,
                logs: ordered_logs,
                pages: state.pages,
                request_count: state.next_id.saturating_sub(1) as usize,
                response_bytes: state.response_bytes,
            },
            start_header,
            network_timing: started_at.map(|started_at| NetworkTiming {
                started_at,
                completed_at: Utc::now(),
                elapsed: start.elapsed(),
            }),
        })
    }

    async fn call_network(
        &self,
        method: &str,
        params: Value,
        deadline: tokio::time::Instant,
        request: &RpcPositionHistoryRequest,
        state: &mut ReadState,
    ) -> Result<Value, RpcPositionHistoryError> {
        if tokio::time::Instant::now() >= deadline {
            return Err(RpcPositionHistoryError::Timeout);
        }
        if state.next_id.saturating_sub(1) as usize >= request.max_requests {
            return Err(RpcPositionHistoryError::RequestBudgetExceeded);
        }
        let id = state.next_id;
        state.next_id += 1;
        let request_json =
            json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}).to_string();
        self.wait_for_request_start(deadline).await?;
        let response = tokio::time::timeout_at(
            deadline,
            self.client
                .post(self.endpoint.clone())
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header(reqwest::header::ACCEPT_ENCODING, "identity")
                .body(request_json.clone())
                .send(),
        )
        .await
        .map_err(|_| RpcPositionHistoryError::Timeout)?
        .map_err(|_| RpcPositionHistoryError::RequestFailed)?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let retry_after_seconds = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok());
            return Err(RpcPositionHistoryError::HttpStatus {
                status,
                retry_after_seconds,
            });
        }
        if response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| !v.eq_ignore_ascii_case("identity"))
        {
            return Err(RpcPositionHistoryError::MalformedResponse);
        }
        if response.content_length().is_some_and(|n| {
            n > MAX_HISTORY_RESPONSE_BYTES as u64
                || n > request
                    .max_total_response_bytes
                    .saturating_sub(state.response_bytes) as u64
        }) {
            return Err(RpcPositionHistoryError::BodyBudgetExceeded);
        }
        let mut response = response;
        let mut body = Vec::new();
        loop {
            let chunk = tokio::time::timeout_at(deadline, response.chunk())
                .await
                .map_err(|_| RpcPositionHistoryError::Timeout)?
                .map_err(|_| RpcPositionHistoryError::ResponseUnreadable)?;
            let Some(chunk) = chunk else { break };
            if body.len().saturating_add(chunk.len()) > MAX_HISTORY_RESPONSE_BYTES
                || state
                    .response_bytes
                    .saturating_add(body.len())
                    .saturating_add(chunk.len())
                    > request.max_total_response_bytes
            {
                return Err(RpcPositionHistoryError::BodyBudgetExceeded);
            }
            body.extend_from_slice(&chunk);
        }
        state.response_bytes += body.len();
        let response_json =
            String::from_utf8(body).map_err(|_| RpcPositionHistoryError::MalformedResponse)?;
        let result = parse_rpc_response(&response_json, id)?;
        state.pages.push(RpcPositionHistoryPage {
            method: method.to_owned(),
            request_json,
            response_json,
        });
        Ok(result)
    }

    async fn wait_for_request_start(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), RpcPositionHistoryError> {
        let Some(pacing) = &self.pacing else {
            return Ok(());
        };
        let mut next_start = tokio::time::timeout_at(deadline, pacing.next_start.lock())
            .await
            .map_err(|_| RpcPositionHistoryError::Timeout)?;
        if let Some(next_start) = *next_start {
            tokio::time::timeout_at(deadline, tokio::time::sleep_until(next_start))
                .await
                .map_err(|_| RpcPositionHistoryError::Timeout)?;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(RpcPositionHistoryError::Timeout);
        }
        *next_start = Some(
            tokio::time::Instant::now()
                .checked_add(pacing.minimum_interval)
                .ok_or(RpcPositionHistoryError::InvalidInput)?,
        );
        Ok(())
    }
}

/// Re-verifies a saved ordered transcript without constructing a network client.
pub async fn reverify_recorded_rpc_position_history_segment(
    request: &RpcPositionHistoryRequest,
    max_blocks_per_log_query: u64,
    pages: &[RecordedRpcPositionHistoryPage],
) -> Result<RecordedRpcPositionHistorySegmentObservation, RpcPositionHistoryError> {
    if max_blocks_per_log_query == 0 {
        return Err(RpcPositionHistoryError::InvalidInput);
    }
    let mut source = RpcCallSource::Recorded {
        pages,
        next_page: 0,
    };
    let output = RpcPositionHistoryReader::read_history_inner(
        request,
        Some(max_blocks_per_log_query),
        true,
        &mut source,
    )
    .await?;
    source.finish()?;
    let start_header = output
        .start_header
        .ok_or(RpcPositionHistoryError::MalformedResponse)?;
    Ok(RecordedRpcPositionHistorySegmentObservation {
        content: output.content,
        start_header,
    })
}

fn recorded_call(
    pages: &[RecordedRpcPositionHistoryPage],
    next_page: &mut usize,
    method: &str,
    params: Value,
    deadline: tokio::time::Instant,
    request: &RpcPositionHistoryRequest,
    state: &mut ReadState,
) -> Result<Value, RpcPositionHistoryError> {
    if tokio::time::Instant::now() >= deadline {
        return Err(RpcPositionHistoryError::Timeout);
    }
    if state.next_id.saturating_sub(1) as usize >= request.max_requests {
        return Err(RpcPositionHistoryError::RequestBudgetExceeded);
    }
    let page = pages
        .get(*next_page)
        .ok_or(RpcPositionHistoryError::MalformedResponse)?;
    if page.request_json.len() > MAX_RECORDED_REQUEST_BYTES {
        return Err(RpcPositionHistoryError::BodyBudgetExceeded);
    }
    let expected_id = state.next_id;
    let expected_request = json!({
        "jsonrpc":"2.0",
        "id":expected_id,
        "method":method,
        "params":params,
    });
    let expected_request_json = expected_request.to_string();
    if page.request_json != expected_request_json {
        return Err(RpcPositionHistoryError::MalformedResponse);
    }
    let response_bytes = page.response_json.len();
    if response_bytes > MAX_HISTORY_RESPONSE_BYTES
        || response_bytes
            > request
                .max_total_response_bytes
                .saturating_sub(state.response_bytes)
    {
        return Err(RpcPositionHistoryError::BodyBudgetExceeded);
    }
    let result = parse_rpc_response(&page.response_json, expected_id)?;
    state.next_id += 1;
    *next_page += 1;
    state.response_bytes += response_bytes;
    state.pages.push(RpcPositionHistoryPage {
        method: method.to_owned(),
        request_json: page.request_json.clone(),
        response_json: page.response_json.clone(),
    });
    Ok(result)
}

fn parse_rpc_response(response_json: &str, id: u64) -> Result<Value, RpcPositionHistoryError> {
    let envelope: Value = serde_json::from_str(response_json)
        .map_err(|_| RpcPositionHistoryError::MalformedResponse)?;
    if envelope.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || envelope.get("id").and_then(Value::as_u64) != Some(id)
    {
        return Err(RpcPositionHistoryError::MalformedResponse);
    }
    if let Some(error) = envelope.get("error") {
        if envelope.get("result").is_some() {
            return Err(RpcPositionHistoryError::MalformedResponse);
        }
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .ok_or(RpcPositionHistoryError::MalformedResponse)?;
        return Err(RpcPositionHistoryError::RpcError { code });
    }
    if envelope.get("result").is_none_or(Value::is_null) {
        return Err(RpcPositionHistoryError::MalformedResponse);
    }
    envelope
        .get("result")
        .cloned()
        .ok_or(RpcPositionHistoryError::MalformedResponse)
}

struct ReadState {
    pages: Vec<RpcPositionHistoryPage>,
    response_bytes: usize,
    next_id: u64,
}

struct ReadOutput {
    content: RpcPositionHistoryContent,
    start_header: Option<RpcBlockHeader>,
    network_timing: Option<NetworkTiming>,
}

struct NetworkTiming {
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    elapsed: Duration,
}

impl ReadOutput {
    fn into_network_observation(
        self,
    ) -> Result<RpcPositionHistoryObservation, RpcPositionHistoryError> {
        let timing = self
            .network_timing
            .ok_or(RpcPositionHistoryError::MalformedResponse)?;
        Ok(RpcPositionHistoryObservation {
            content: self.content,
            started_at: timing.started_at,
            completed_at: timing.completed_at,
            elapsed: timing.elapsed,
        })
    }
}

enum RpcCallSource<'a> {
    Network {
        reader: &'a RpcPositionHistoryReader,
        capture_failure_context: bool,
        last_failure: Option<RpcPositionHistoryRequestLocator>,
    },
    Recorded {
        pages: &'a [RecordedRpcPositionHistoryPage],
        next_page: usize,
    },
}

impl RpcCallSource<'_> {
    fn network(
        reader: &RpcPositionHistoryReader,
        capture_failure_context: bool,
    ) -> RpcCallSource<'_> {
        RpcCallSource::Network {
            reader,
            capture_failure_context,
            last_failure: None,
        }
    }

    fn is_network(&self) -> bool {
        matches!(self, Self::Network { .. })
    }

    fn last_failure(&self) -> Option<RpcPositionHistoryRequestLocator> {
        match self {
            Self::Network { last_failure, .. } => *last_failure,
            Self::Recorded { .. } => None,
        }
    }

    async fn call(
        &mut self,
        method: &str,
        params: Value,
        phase: RpcPositionHistoryRequestPhase,
        deadline: tokio::time::Instant,
        request: &RpcPositionHistoryRequest,
        state: &mut ReadState,
    ) -> Result<Value, RpcPositionHistoryError> {
        match self {
            Self::Network {
                reader,
                capture_failure_context,
                last_failure,
            } => {
                let locator = RpcPositionHistoryRequestLocator {
                    request_ordinal: state.next_id,
                    method: match method {
                        "eth_chainId" => RpcPositionHistoryRequestMethod::ChainId,
                        "eth_getBlockByNumber" => RpcPositionHistoryRequestMethod::GetBlockByNumber,
                        "eth_getLogs" => RpcPositionHistoryRequestMethod::GetLogs,
                        _ => unreachable!("only fixed position-history methods are dispatched"),
                    },
                    phase,
                };
                let result = reader
                    .call_network(method, params, deadline, request, state)
                    .await;
                *last_failure = if *capture_failure_context && result.is_err() {
                    Some(locator)
                } else {
                    None
                };
                result
            }
            Self::Recorded { pages, next_page } => {
                recorded_call(pages, next_page, method, params, deadline, request, state)
            }
        }
    }

    fn finish(&self) -> Result<(), RpcPositionHistoryError> {
        match self {
            Self::Network { .. } => Ok(()),
            Self::Recorded { pages, next_page } if *next_page == pages.len() => Ok(()),
            Self::Recorded { .. } => Err(RpcPositionHistoryError::MalformedResponse),
        }
    }

    fn validate_count(&self, planned_calls: u128) -> Result<(), RpcPositionHistoryError> {
        match self {
            Self::Network { .. } => Ok(()),
            Self::Recorded { pages, .. } => {
                if pages.len() > MAX_HISTORY_REQUESTS {
                    return Err(RpcPositionHistoryError::RequestBudgetExceeded);
                }
                if pages.len() as u128 != planned_calls {
                    return Err(RpcPositionHistoryError::MalformedResponse);
                }
                Ok(())
            }
        }
    }
}

fn parse_header(value: &Value) -> Result<RpcBlockHeader, RpcPositionHistoryError> {
    let hash = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .and_then(normalize_hash)
            .ok_or(RpcPositionHistoryError::MalformedResponse)
    };
    let number = value
        .get("number")
        .and_then(parse_quantity)
        .ok_or(RpcPositionHistoryError::MalformedResponse)?;
    let logs_bloom = value
        .get("logsBloom")
        .and_then(Value::as_str)
        .and_then(|s| {
            let digits = s.strip_prefix("0x")?;
            (digits.len() == 512 && digits.bytes().all(|b| b.is_ascii_hexdigit()))
                .then(|| format!("0x{}", digits.to_ascii_lowercase()))
        })
        .ok_or(RpcPositionHistoryError::MalformedResponse)?;
    Ok(RpcBlockHeader {
        number,
        hash: hash("hash")?,
        parent_hash: hash("parentHash")?,
        state_root: hash("stateRoot")?,
        transactions_root: hash("transactionsRoot")?,
        receipts_root: hash("receiptsRoot")?,
        logs_bloom,
    })
}

fn parse_quantity(value: &Value) -> Option<u64> {
    let text = value.as_str()?;
    let digits = text.strip_prefix("0x")?;
    if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

fn quantity(value: u64) -> String {
    format!("0x{value:x}")
}

fn map_log_error(error: PositionHistoryError) -> RpcPositionHistoryError {
    match error {
        PositionHistoryError::ConflictingLocator => RpcPositionHistoryError::ConflictingLocator,
        _ => RpcPositionHistoryError::MalformedResponse,
    }
}
