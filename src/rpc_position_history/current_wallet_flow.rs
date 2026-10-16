//! Bounded, provider-reported source-wallet flow capture and offline replay.
//!
//! This module owns orchestration for Activity, current transfer/fill census,
//! transaction/receipt and optional fifth/V2 settlement contexts. Its artifact
//! is an endpoint-free transcript, not proof of complete wallet history or NAV.

use std::{collections::BTreeSet, time::Duration};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::time::{Instant, timeout};

use crate::{
    activity_hints::{
        ACTIVITY_HINT_POLICY_VERSION, ActivityHintAcquisition, ActivityHintIncompleteReason,
        ActivityHintOccurrence, ActivityHintPass, ActivityHintPassStatus, ActivityHintPassSummary,
        MAX_ACTIVITY_PAGE_SIZE, PolymarketActivityHintClient, WalletActivityHintLimits,
    },
    chain_log_audit::{
        ProviderReportedCtfV2Settlement, ProviderReportedFifthSettlement,
        decode_provider_reported_ctf_v2_complementary_settlement,
        decode_provider_reported_fifth_binary_settlement,
        provider_reported_ctf_v2_settlement_context_candidate,
        provider_reported_fifth_settlement_context_candidate,
    },
    rpc_position_history::{
        RecordedRpcPositionHistoryPage, RpcPositionHistoryError, RpcPositionHistoryPage,
        RpcPositionHistoryReader,
        ctf_v2_context::{
            RpcCurrentCtfV2Context, RpcCurrentCtfV2ContextRequest,
            reverify_recorded_current_ctf_v2_context,
        },
        current_interval_census::{
            RpcCurrentIntervalCensus, RpcCurrentIntervalCensusRequest,
            RpcCurrentIntervalOwnerFillCensus,
            reverify_recorded_current_interval_owner_fills_chunked,
        },
        current_interval_transactions::{
            RpcCurrentIntervalTransactions, RpcCurrentIntervalTransactionsCaptureWindow,
            RpcCurrentIntervalTransactionsRequest, reverify_recorded_current_interval_transactions,
        },
        fifth_binary_context::{
            RpcCurrentFifthBinaryContext, RpcCurrentFifthBinaryContextRequest,
            reverify_recorded_current_fifth_binary_context,
        },
    },
};

use super::current_interval_census::portfolio_flow::{
    SourceWalletActivityWindow, SourceWalletFlowReduction,
    reduce_source_wallet_flows_with_fifth_settlements,
    reduce_source_wallet_flows_with_provider_settlements,
};

pub const CURRENT_WALLET_FLOW_ARTIFACT_VERSION: u32 = 2;
const LEGACY_CURRENT_WALLET_FLOW_ARTIFACT_VERSION: u32 = 1;
pub const CURRENT_WALLET_FLOW_DEFAULT_ACTIVITY_REQUESTS: usize = 8;
pub const CURRENT_WALLET_FLOW_DEFAULT_RPC_REQUESTS: usize = 256;
pub const CURRENT_WALLET_FLOW_DEFAULT_RAW_BYTES: usize = 32 * 1024 * 1024;
pub const CURRENT_WALLET_FLOW_DEFAULT_CANDIDATE_TRANSACTIONS: usize = 32;
pub const CURRENT_WALLET_FLOW_LOG_CHUNK_BLOCKS: u64 = 32;
const MAX_FLOW_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_ACTIVITY_ROWS: usize = 20_000;
const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

/// Aggregate bounds shared by the network phases of one wallet capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurrentWalletFlowLimits {
    pub max_activity_requests: usize,
    pub max_rpc_requests: usize,
    pub max_raw_response_bytes: usize,
    pub max_candidate_transactions: usize,
    pub total_timeout: Duration,
}

impl Default for CurrentWalletFlowLimits {
    fn default() -> Self {
        Self {
            max_activity_requests: CURRENT_WALLET_FLOW_DEFAULT_ACTIVITY_REQUESTS,
            max_rpc_requests: CURRENT_WALLET_FLOW_DEFAULT_RPC_REQUESTS,
            max_raw_response_bytes: CURRENT_WALLET_FLOW_DEFAULT_RAW_BYTES,
            max_candidate_transactions: CURRENT_WALLET_FLOW_DEFAULT_CANDIDATE_TRANSACTIONS,
            total_timeout: MAX_FLOW_TIMEOUT,
        }
    }
}

/// One wallet and the cash-block anchors for two source windows. Activity
/// query bounds are derived from the replayed census headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentWalletFlowRequest {
    pub wallet: String,
    pub start_block: u64,
    pub expected_start_hash: String,
    pub through_block: u64,
    pub expected_through_hash: String,
    pub limits: CurrentWalletFlowLimits,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CurrentWalletFlowError {
    #[error("current wallet flow input or capture window is invalid")]
    InvalidInput,
    #[error("current wallet flow capture failed within its configured budget")]
    CaptureFailed,
    #[error("current wallet flow artifact is malformed, oversized or inconsistent")]
    InvalidArtifact,
    #[error("current wallet flow artifact digest does not match")]
    Tampered,
    #[error("unsupported current wallet flow artifact version")]
    UnsupportedVersion,
}

impl From<RpcPositionHistoryError> for CurrentWalletFlowError {
    fn from(_: RpcPositionHistoryError) -> Self {
        Self::CaptureFailed
    }
}

/// Opaque, owned capture with a replayed provider-reported flow reduction.
#[derive(Clone, PartialEq, Eq)]
pub struct CurrentWalletFlowObservation {
    packet: CurrentWalletFlowPacket,
    reduction: SourceWalletFlowReduction,
}

impl CurrentWalletFlowObservation {
    /// Returns the wallet and caller-provided NAV block anchors bound into
    /// this capture. Activity bounds are derived from the replayed headers.
    #[must_use]
    pub fn request(&self) -> CurrentWalletFlowRequest {
        self.packet.request.to_request()
    }

    #[must_use]
    pub const fn reduction(&self) -> &SourceWalletFlowReduction {
        &self.reduction
    }

    #[must_use]
    pub const fn capture_started_at(&self) -> DateTime<Utc> {
        self.packet.capture_started_at
    }

    #[must_use]
    pub const fn capture_completed_at(&self) -> DateTime<Utc> {
        self.packet.capture_completed_at
    }

    #[must_use]
    pub fn activity_occurrence_count(&self) -> usize {
        self.packet.activity.occurrences.len()
    }

    #[must_use]
    pub const fn census_log_count(&self) -> usize {
        self.packet.census.log_count
    }

    #[must_use]
    pub const fn owner_fill_count(&self) -> usize {
        self.packet.census.owner_fill_count
    }

    #[must_use]
    pub const fn activity_start(&self) -> i64 {
        self.packet.activity.start
    }

    #[must_use]
    pub const fn activity_end(&self) -> i64 {
        self.packet.activity.end
    }

    #[must_use]
    pub const fn activity_request_count(&self) -> usize {
        self.packet.activity.total_requests
    }

    #[must_use]
    pub fn transaction_count(&self) -> usize {
        self.packet.transactions.request.transaction_hashes.len()
    }

    #[must_use]
    pub fn fifth_context_count(&self) -> usize {
        self.packet.contexts.len()
    }

    #[must_use]
    pub fn ctf_v2_context_count(&self) -> usize {
        self.packet.ctf_v2_contexts.len()
    }

    #[must_use]
    pub fn total_rpc_request_count(&self) -> usize {
        self.packet
            .census
            .request_count
            .saturating_add(self.packet.transactions.request_count)
            .saturating_add(saturating_sum(
                self.packet.contexts.iter().map(|item| item.request_count),
            ))
            .saturating_add(saturating_sum(
                self.packet
                    .ctf_v2_contexts
                    .iter()
                    .map(|item| item.request_count),
            ))
    }

    #[must_use]
    pub fn total_raw_response_bytes(&self) -> usize {
        self.packet
            .census
            .response_bytes
            .saturating_add(self.packet.activity.total_response_bytes)
            .saturating_add(self.packet.transactions.response_bytes)
            .saturating_add(saturating_sum(
                self.packet.contexts.iter().map(|item| item.response_bytes),
            ))
            .saturating_add(saturating_sum(
                self.packet
                    .ctf_v2_contexts
                    .iter()
                    .map(|item| item.response_bytes),
            ))
    }

    /// Returns the complete endpoint-free transcript plus the derived report.
    pub fn to_artifact(&self) -> Result<Vec<u8>, CurrentWalletFlowError> {
        let mut packet = self.packet.clone();
        packet.reduction = FlowPacket::from_reduction(&self.reduction);
        packet.content_sha256.clear();
        packet.content_sha256 = packet.calculate_sha256()?;
        let bytes =
            serde_json::to_vec(&packet).map_err(|_| CurrentWalletFlowError::InvalidArtifact)?;
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(CurrentWalletFlowError::InvalidArtifact);
        }
        Ok(bytes)
    }

    /// Parses an owned artifact and replays every recorded SDK component before
    /// comparing the derived flow projection. Replay performs no network I/O.
    pub async fn from_artifact(bytes: &[u8]) -> Result<Self, CurrentWalletFlowError> {
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(CurrentWalletFlowError::InvalidArtifact);
        }
        let packet: CurrentWalletFlowPacket =
            serde_json::from_slice(bytes).map_err(|_| CurrentWalletFlowError::InvalidArtifact)?;
        if packet.version != LEGACY_CURRENT_WALLET_FLOW_ARTIFACT_VERSION
            && packet.version != CURRENT_WALLET_FLOW_ARTIFACT_VERSION
        {
            return Err(CurrentWalletFlowError::UnsupportedVersion);
        }
        packet.verify_sha256()?;
        let reduction = packet.recompute_reduction().await?;
        if FlowPacket::from_reduction(&reduction) != packet.reduction {
            return Err(CurrentWalletFlowError::InvalidArtifact);
        }
        Ok(Self { packet, reduction })
    }
}

/// Captures one bounded activity interval and one Polygon census. All later
/// RPC phases consume the remaining shared call, byte and time budgets.
pub async fn capture_current_wallet_flow_observation(
    activity_client: &PolymarketActivityHintClient,
    rpc_reader: &RpcPositionHistoryReader,
    request: &CurrentWalletFlowRequest,
) -> Result<CurrentWalletFlowObservation, CurrentWalletFlowError> {
    validate_request(request)?;
    let deadline = Instant::now()
        .checked_add(request.limits.total_timeout)
        .ok_or(CurrentWalletFlowError::InvalidInput)?;
    let capture_started_at = Utc::now();

    // Reserve one quarter of the aggregate body cap for the two Activity
    // passes; each later phase receives only the unused remainder.
    let activity_reserve = (request.limits.max_raw_response_bytes / 4).max(1);
    let census_byte_cap = request.limits.max_raw_response_bytes - activity_reserve;
    let census_request = RpcCurrentIntervalCensusRequest {
        wallets: vec![request.wallet.clone()],
        start_block: request.start_block,
        expected_start_hash: request.expected_start_hash.clone(),
        through_block: request.through_block,
        expected_through_hash: request.expected_through_hash.clone(),
        max_requests: request.limits.max_rpc_requests,
        max_total_response_bytes: census_byte_cap,
        total_timeout: remaining(deadline)?,
    };
    let census = timeout(
        remaining(deadline)?,
        rpc_reader.read_current_interval_owner_fills_chunked(
            &census_request,
            CURRENT_WALLET_FLOW_LOG_CHUNK_BLOCKS,
        ),
    )
    .await
    .map_err(|_| CurrentWalletFlowError::CaptureFailed)??;

    let activity_start = i64::try_from(census.census.start_header.timestamp)
        .ok()
        .and_then(|timestamp| timestamp.checked_add(1))
        .ok_or(CurrentWalletFlowError::InvalidInput)?;
    let activity_end = i64::try_from(census.census.end_header.timestamp)
        .map_err(|_| CurrentWalletFlowError::InvalidInput)?;
    if activity_end > Utc::now().timestamp() {
        return Err(CurrentWalletFlowError::InvalidInput);
    }
    let activity_started_at = Utc::now();
    let activity = if activity_start > activity_end {
        None
    } else {
        let activity_limits = WalletActivityHintLimits {
            max_pages: request.limits.max_activity_requests,
            max_rows: MAX_ACTIVITY_ROWS,
            page_size: MAX_ACTIVITY_PAGE_SIZE,
            max_activity_requests: request.limits.max_activity_requests,
            max_response_bytes: (request.limits.max_raw_response_bytes
                - census.census.response_bytes)
                .min(8 * 1024 * 1024),
            deadline: remaining(deadline)?,
        };
        Some(
            timeout(
                remaining(deadline)?,
                activity_client.acquire_wallet_activity_hints(
                    &request.wallet,
                    activity_start,
                    activity_end,
                    activity_limits,
                ),
            )
            .await
            .map_err(|_| CurrentWalletFlowError::CaptureFailed)?
            .map_err(|_| CurrentWalletFlowError::CaptureFailed)?,
        )
    };
    let activity_completed_at = Utc::now();
    let activity_packet = activity.as_ref().map_or_else(
        || {
            ActivityPacket::empty_unavailable(
                &request.wallet,
                activity_start,
                activity_end,
                activity_started_at,
                activity_completed_at,
            )
        },
        |activity| {
            ActivityPacket::from_acquisition(activity, activity_started_at, activity_completed_at)
        },
    );

    let remaining_bytes = request
        .limits
        .max_raw_response_bytes
        .checked_sub(census.census.response_bytes)
        .and_then(|bytes| {
            bytes.checked_sub(
                activity
                    .as_ref()
                    .map_or(0, ActivityHintAcquisition::total_response_bytes),
            )
        })
        .ok_or(CurrentWalletFlowError::CaptureFailed)?;

    let mut remaining_rpc = request
        .limits
        .max_rpc_requests
        .checked_sub(census.census.request_count)
        .ok_or(CurrentWalletFlowError::CaptureFailed)?;
    let mut remaining_bytes = remaining_bytes;
    let tx_hashes =
        candidate_transaction_hashes(&census.census, request.limits.max_candidate_transactions);
    let skipped_candidate_transactions = tx_hashes.skipped;
    let transactions_request = RpcCurrentIntervalTransactionsRequest {
        transaction_hashes: tx_hashes.selected,
        max_requests: remaining_rpc.min(64),
        max_total_response_bytes: remaining_bytes.min(16 * 1024 * 1024),
        total_timeout: remaining(deadline)?,
    };
    let tx_started_at = Utc::now();
    let transactions = if transactions_request.transaction_hashes.is_empty() {
        None
    } else if transactions_request.max_requests
        >= transactions_request
            .transaction_hashes
            .len()
            .saturating_mul(2)
        && transactions_request.max_total_response_bytes > 0
    {
        Some(
            timeout(
                remaining(deadline)?,
                rpc_reader
                    .read_current_interval_transactions(&census.census, &transactions_request),
            )
            .await
            .map_err(|_| CurrentWalletFlowError::CaptureFailed)??,
        )
    } else {
        None
    };
    let tx_completed_at = Utc::now();
    let (transactions_packet, tx_capture_window) = match &transactions {
        Some(capture) => {
            remaining_rpc = remaining_rpc
                .checked_sub(capture.request_count)
                .ok_or(CurrentWalletFlowError::CaptureFailed)?;
            remaining_bytes = remaining_bytes
                .checked_sub(capture.response_bytes)
                .ok_or(CurrentWalletFlowError::CaptureFailed)?;
            (
                TransactionPacket::from_capture(capture, &transactions_request),
                RpcCurrentIntervalTransactionsCaptureWindow {
                    started_at: capture.started_at,
                    completed_at: capture.completed_at,
                },
            )
        }
        None => (
            TransactionPacket::empty(),
            RpcCurrentIntervalTransactionsCaptureWindow {
                started_at: tx_started_at,
                completed_at: tx_completed_at,
            },
        ),
    };
    let skipped_candidate_transactions = skipped_candidate_transactions.saturating_add(
        transactions
            .as_ref()
            .map_or(transactions_request.transaction_hashes.len(), |_| 0),
    );

    let mut context_packets = Vec::new();
    let mut skipped_context_blocks = 0usize;
    let mut ctf_v2_context_packets = Vec::new();
    let mut skipped_ctf_v2_context_blocks = 0usize;
    if let Some(capture) = &transactions {
        let mut candidates = BTreeSet::new();
        for tx in &capture.transactions {
            if let Some(anchor) =
                provider_reported_fifth_settlement_context_candidate(&tx.transaction)
            {
                candidates.insert(anchor);
            }
        }
        for (block_number, expected_hash) in candidates {
            if remaining_rpc < 4 || remaining_bytes == 0 {
                skipped_context_blocks += 1;
                continue;
            }
            let context_request = RpcCurrentFifthBinaryContextRequest {
                block_number,
                expected_hash,
                max_requests: remaining_rpc.min(256),
                max_total_response_bytes: remaining_bytes.min(256 * 1024),
                total_timeout: remaining(deadline)?.min(Duration::from_secs(30)),
            };
            let context = timeout(
                remaining(deadline)?,
                rpc_reader.read_current_fifth_binary_context(&census.census, &context_request),
            )
            .await
            .map_err(|_| CurrentWalletFlowError::CaptureFailed)??;
            remaining_rpc = remaining_rpc
                .checked_sub(context.request_count())
                .ok_or(CurrentWalletFlowError::CaptureFailed)?;
            remaining_bytes = remaining_bytes
                .checked_sub(context.response_bytes())
                .ok_or(CurrentWalletFlowError::CaptureFailed)?;
            context_packets.push(ContextPacket::from_capture(&context, context_request));
        }

        let mut ctf_v2_candidates = BTreeSet::new();
        for tx in &capture.transactions {
            if let Some(anchor) =
                provider_reported_ctf_v2_settlement_context_candidate(&tx.transaction)
            {
                ctf_v2_candidates.insert(anchor);
            }
        }
        for (block_number, expected_hash) in ctf_v2_candidates {
            if remaining_rpc < 5 || remaining_bytes == 0 {
                skipped_ctf_v2_context_blocks += 1;
                continue;
            }
            let context_request = RpcCurrentCtfV2ContextRequest {
                block_number,
                expected_hash,
                max_requests: remaining_rpc.min(256),
                max_total_response_bytes: remaining_bytes.min(256 * 1024),
                total_timeout: remaining(deadline)?.min(Duration::from_secs(30)),
            };
            let context = timeout(
                remaining(deadline)?,
                rpc_reader.read_current_ctf_v2_context(&census.census, &context_request),
            )
            .await
            .map_err(|_| CurrentWalletFlowError::CaptureFailed)??;
            remaining_rpc = remaining_rpc
                .checked_sub(context.request_count())
                .ok_or(CurrentWalletFlowError::CaptureFailed)?;
            remaining_bytes = remaining_bytes
                .checked_sub(context.response_bytes())
                .ok_or(CurrentWalletFlowError::CaptureFailed)?;
            ctf_v2_context_packets
                .push(CtfV2ContextPacket::from_capture(&context, context_request));
        }
    }
    let mut packet = CurrentWalletFlowPacket {
        version: if ctf_v2_context_packets.is_empty() && skipped_ctf_v2_context_blocks == 0 {
            LEGACY_CURRENT_WALLET_FLOW_ARTIFACT_VERSION
        } else {
            CURRENT_WALLET_FLOW_ARTIFACT_VERSION
        },
        source: "provider_reported".to_owned(),
        capture_started_at,
        capture_completed_at: Utc::now(),
        request: RequestPacket::from_request(request),
        activity: activity_packet,
        census: CensusPacket::from_capture(&census, &census_request),
        transactions: transactions_packet.with_window(tx_capture_window),
        contexts: context_packets,
        skipped_candidate_transactions,
        skipped_context_blocks,
        ctf_v2_contexts: ctf_v2_context_packets,
        skipped_ctf_v2_context_blocks,
        reduction: FlowPacket::empty(),
        content_sha256: String::new(),
    };
    let reduction = packet.recompute_reduction().await?;
    packet.reduction = FlowPacket::from_reduction(&reduction);
    packet.content_sha256 = packet.calculate_sha256()?;
    Ok(CurrentWalletFlowObservation { packet, reduction })
}

fn validate_request(request: &CurrentWalletFlowRequest) -> Result<(), CurrentWalletFlowError> {
    let limits = request.limits;
    let wallet = normalize_address(&request.wallet);
    let start_hash = crate::position_history::normalize_hash(&request.expected_start_hash);
    let through_hash = crate::position_history::normalize_hash(&request.expected_through_hash);
    if wallet.as_deref() != Some(request.wallet.as_str())
        || request.wallet == format!("0x{}", "00".repeat(20))
        || start_hash.as_deref() != Some(request.expected_start_hash.as_str())
        || through_hash.as_deref() != Some(request.expected_through_hash.as_str())
        || request.expected_start_hash == format!("0x{}", "00".repeat(32))
        || request.expected_through_hash == format!("0x{}", "00".repeat(32))
        || request.start_block >= request.through_block
        || request.through_block - request.start_block > 2_048
        || !(1..=CURRENT_WALLET_FLOW_DEFAULT_ACTIVITY_REQUESTS)
            .contains(&limits.max_activity_requests)
        || !(1..=CURRENT_WALLET_FLOW_DEFAULT_RPC_REQUESTS).contains(&limits.max_rpc_requests)
        || !(2..=CURRENT_WALLET_FLOW_DEFAULT_RAW_BYTES).contains(&limits.max_raw_response_bytes)
        || !(1..=CURRENT_WALLET_FLOW_DEFAULT_CANDIDATE_TRANSACTIONS)
            .contains(&limits.max_candidate_transactions)
        || limits.total_timeout.is_zero()
        || limits.total_timeout > MAX_FLOW_TIMEOUT
    {
        return Err(CurrentWalletFlowError::InvalidInput);
    }
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration, CurrentWalletFlowError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(CurrentWalletFlowError::CaptureFailed)
    } else {
        Ok(remaining)
    }
}

fn candidate_transaction_hashes(
    census: &RpcCurrentIntervalCensus,
    maximum: usize,
) -> CandidateHashes {
    let all = census
        .logs
        .iter()
        .map(|log| log.transaction_hash.clone())
        .collect::<BTreeSet<_>>();
    CandidateHashes {
        selected: all.iter().take(maximum).cloned().collect(),
        skipped: all.len().saturating_sub(maximum),
    }
}

struct CandidateHashes {
    selected: Vec<String>,
    skipped: usize,
}

fn decode_fifth_settlements(
    wallet: &str,
    transactions: Option<&RpcCurrentIntervalTransactions>,
    contexts: &[RpcCurrentFifthBinaryContext],
) -> Vec<ProviderReportedFifthSettlement> {
    let Some(transactions) = transactions else {
        return Vec::new();
    };
    transactions
        .transactions
        .iter()
        .filter_map(|tx| {
            let context = contexts.iter().find(|context| {
                provider_reported_fifth_settlement_context_candidate(&tx.transaction).is_some_and(
                    |(block, hash)| block == context.block_number() && hash == context.block_hash(),
                )
            })?;
            decode_provider_reported_fifth_binary_settlement(
                &tx.transaction,
                &tx.receipt,
                wallet,
                context,
            )
            .ok()
        })
        .collect()
}

fn decode_ctf_v2_settlements(
    wallet: &str,
    transactions: Option<&RpcCurrentIntervalTransactions>,
    contexts: &[RpcCurrentCtfV2Context],
) -> Vec<ProviderReportedCtfV2Settlement> {
    let Some(transactions) = transactions else {
        return Vec::new();
    };
    transactions
        .transactions
        .iter()
        .filter_map(|tx| {
            let context = contexts.iter().find(|context| {
                provider_reported_ctf_v2_settlement_context_candidate(&tx.transaction).is_some_and(
                    |(block, hash)| {
                        block == context.block_number()
                            && hash.eq_ignore_ascii_case(context.block_hash())
                    },
                )
            })?;
            decode_provider_reported_ctf_v2_complementary_settlement(
                &tx.transaction,
                &tx.receipt,
                wallet,
                context,
            )
            .ok()
        })
        .collect()
}

fn mark_unknown_for_limits(reduction: &mut SourceWalletFlowReduction) {
    use super::current_interval_census::portfolio_flow::{
        SourceFlowCoverage, SourceFlowReason, UnresolvedSourceMovement,
    };
    reduction.coverage = SourceFlowCoverage::Unknown;
    reduction.unresolved.push(UnresolvedSourceMovement {
        movement_locator: None,
        activity_occurrence: None,
        reason: SourceFlowReason::InputLimitExceeded,
    });
}

fn saturating_sum(values: impl Iterator<Item = usize>) -> usize {
    values.fold(0, usize::saturating_add)
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn elapsed_exceeds(start: DateTime<Utc>, end: DateTime<Utc>, maximum: Duration) -> bool {
    end.signed_duration_since(start)
        .to_std()
        .map_or(true, |elapsed| elapsed > maximum)
}

fn normalize_address(value: &str) -> Option<String> {
    crate::position_history::normalize_address(value)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CurrentWalletFlowPacket {
    version: u32,
    source: String,
    capture_started_at: DateTime<Utc>,
    capture_completed_at: DateTime<Utc>,
    request: RequestPacket,
    activity: ActivityPacket,
    census: CensusPacket,
    transactions: TransactionPacket,
    contexts: Vec<ContextPacket>,
    skipped_candidate_transactions: usize,
    skipped_context_blocks: usize,
    reduction: FlowPacket,
    content_sha256: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ctf_v2_contexts: Vec<CtfV2ContextPacket>,
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    skipped_ctf_v2_context_blocks: usize,
}

fn is_zero_usize(value: &usize) -> bool {
    *value == 0
}

impl CurrentWalletFlowPacket {
    fn calculate_sha256(&self) -> Result<String, CurrentWalletFlowError> {
        let mut content = self.clone();
        content.content_sha256.clear();
        let encoded =
            serde_json::to_vec(&content).map_err(|_| CurrentWalletFlowError::InvalidArtifact)?;
        Ok(format!("{:x}", Sha256::digest(encoded)))
    }

    fn verify_sha256(&self) -> Result<(), CurrentWalletFlowError> {
        if self.source != "provider_reported"
            || self.capture_started_at > self.capture_completed_at
            || self.calculate_sha256()? != self.content_sha256
        {
            return Err(CurrentWalletFlowError::Tampered);
        }
        Ok(())
    }

    async fn recompute_reduction(
        &self,
    ) -> Result<SourceWalletFlowReduction, CurrentWalletFlowError> {
        self.validate_capture_windows()?;
        let (owner_census, transactions, contexts, ctf_v2_contexts) =
            self.replay_components().await?;
        self.activity
            .validate(&self.request, &owner_census.census)?;
        if self.capture_completed_at < self.capture_started_at
            || self
                .capture_completed_at
                .signed_duration_since(self.capture_started_at)
                .to_std()
                .map_err(|_| CurrentWalletFlowError::InvalidArtifact)?
                > self.request.limits.to_limits()?.total_timeout
            || self
                .census
                .request_count
                .saturating_add(self.transactions.request_count)
                .saturating_add(saturating_sum(
                    self.contexts.iter().map(|context| context.request_count),
                ))
                .saturating_add(saturating_sum(
                    self.ctf_v2_contexts
                        .iter()
                        .map(|context| context.request_count),
                ))
                > self.request.limits.max_rpc_requests
            || self
                .census
                .response_bytes
                .saturating_add(self.transactions.response_bytes)
                .saturating_add(saturating_sum(
                    self.contexts.iter().map(|context| context.response_bytes),
                ))
                .saturating_add(saturating_sum(
                    self.ctf_v2_contexts
                        .iter()
                        .map(|context| context.response_bytes),
                ))
                .saturating_add(self.activity.total_response_bytes)
                > self.request.limits.max_raw_response_bytes
            || self
                .contexts
                .len()
                .saturating_add(self.ctf_v2_contexts.len())
                > self.request.limits.max_candidate_transactions
            || self.skipped_candidate_transactions > 20_000
            || self.skipped_context_blocks > self.request.limits.max_candidate_transactions
            || self.skipped_ctf_v2_context_blocks > self.request.limits.max_candidate_transactions
            || (self.version == LEGACY_CURRENT_WALLET_FLOW_ARTIFACT_VERSION
                && (!self.ctf_v2_contexts.is_empty() || self.skipped_ctf_v2_context_blocks > 0))
            || (self.version == CURRENT_WALLET_FLOW_ARTIFACT_VERSION
                && self.ctf_v2_contexts.is_empty()
                && self.skipped_ctf_v2_context_blocks == 0)
        {
            return Err(CurrentWalletFlowError::InvalidArtifact);
        }
        let occurrences = self.activity.to_occurrences();
        let activity = SourceWalletActivityWindow {
            wallet: &self.activity.wallet,
            policy_version: &self.activity.policy_version,
            start: self.activity.start,
            end: self.activity.end,
            default_pass: self.activity.default_pass.to_summary(),
            tip_pass: self.activity.tip_pass.to_summary(),
            occurrences: &occurrences,
        };
        let fifth_settlements =
            decode_fifth_settlements(&self.request.wallet, transactions.as_ref(), &contexts);
        let ctf_v2_settlements = decode_ctf_v2_settlements(
            &self.request.wallet,
            transactions.as_ref(),
            &ctf_v2_contexts,
        );
        let mut reduction = if self.version == LEGACY_CURRENT_WALLET_FLOW_ARTIFACT_VERSION {
            reduce_source_wallet_flows_with_fifth_settlements(
                activity,
                &owner_census,
                &fifth_settlements,
            )
        } else {
            reduce_source_wallet_flows_with_provider_settlements(
                activity,
                &owner_census,
                &fifth_settlements,
                &ctf_v2_settlements,
            )
        };
        if self.skipped_candidate_transactions > 0
            || self.skipped_context_blocks > 0
            || self.skipped_ctf_v2_context_blocks > 0
        {
            mark_unknown_for_limits(&mut reduction);
        }
        Ok(reduction)
    }

    fn validate_capture_windows(&self) -> Result<(), CurrentWalletFlowError> {
        let limits = self.request.limits.to_limits()?;
        let census = &self.census;
        let activity = &self.activity;
        let transactions = &self.transactions;
        let now = Utc::now();
        let expected_census_bytes = limits
            .max_raw_response_bytes
            .saturating_sub((limits.max_raw_response_bytes / 4).max(1));
        if self.capture_completed_at > now
            || census.started_at < self.capture_started_at
            || census.started_at > census.completed_at
            || census.completed_at > activity.started_at
            || activity.started_at > activity.completed_at
            || activity.completed_at > transactions.started_at
            || transactions.started_at > transactions.completed_at
            || transactions.completed_at > self.capture_completed_at
            || census.started_at > now
            || activity.started_at > now
            || activity.completed_at > now
            || transactions.started_at > now
            || transactions.completed_at > now
            || elapsed_exceeds(census.started_at, census.completed_at, limits.total_timeout)
            || elapsed_exceeds(
                activity.started_at,
                activity.completed_at,
                limits.total_timeout,
            )
            || elapsed_exceeds(
                transactions.started_at,
                transactions.completed_at,
                limits.total_timeout,
            )
            || census.request.wallet != self.request.wallet
            || census.request.start_block != self.request.start_block
            || census.request.expected_start_hash != self.request.expected_start_hash
            || census.request.through_block != self.request.through_block
            || census.request.expected_through_hash != self.request.expected_through_hash
            || census.request.max_requests != limits.max_rpc_requests
            || census.request.max_total_response_bytes != expected_census_bytes
            || census.request.timeout_millis == 0
            || census.request.timeout_millis > duration_millis(limits.total_timeout)
            || census.chunk_blocks != CURRENT_WALLET_FLOW_LOG_CHUNK_BLOCKS
            || (transactions.captured
                && (transactions.request.timeout_millis == 0
                    || transactions.request.timeout_millis > duration_millis(limits.total_timeout)
                    || transactions.request.max_requests == 0
                    || transactions.request.max_requests > 64
                    || transactions.request.max_total_response_bytes == 0
                    || transactions.request.max_total_response_bytes > 16 * 1024 * 1024))
        {
            return Err(CurrentWalletFlowError::InvalidArtifact);
        }
        let mut previous_completed = transactions.completed_at;
        for context in &self.contexts {
            if context.started_at < previous_completed
                || context.started_at > context.completed_at
                || context.completed_at > self.capture_completed_at
                || context.completed_at > now
                || elapsed_exceeds(
                    context.started_at,
                    context.completed_at,
                    Duration::from_secs(30),
                )
                || context.request.timeout_millis == 0
                || context.request.timeout_millis > duration_millis(limits.total_timeout)
            {
                return Err(CurrentWalletFlowError::InvalidArtifact);
            }
            previous_completed = context.completed_at;
        }
        for context in &self.ctf_v2_contexts {
            if context.started_at < previous_completed
                || context.started_at > context.completed_at
                || context.completed_at > self.capture_completed_at
                || context.completed_at > now
                || elapsed_exceeds(
                    context.started_at,
                    context.completed_at,
                    Duration::from_secs(30),
                )
                || context.request.timeout_millis == 0
                || context.request.timeout_millis > duration_millis(limits.total_timeout)
            {
                return Err(CurrentWalletFlowError::InvalidArtifact);
            }
            previous_completed = context.completed_at;
        }
        Ok(())
    }

    async fn replay_components(
        &self,
    ) -> Result<
        (
            RpcCurrentIntervalOwnerFillCensus,
            Option<RpcCurrentIntervalTransactions>,
            Vec<RpcCurrentFifthBinaryContext>,
            Vec<RpcCurrentCtfV2Context>,
        ),
        CurrentWalletFlowError,
    > {
        self.request.validate()?;
        let census_request = self.census.to_sdk_request()?;
        let owner_census = reverify_recorded_current_interval_owner_fills_chunked(
            &census_request,
            &self.census.pages.to_sdk(),
            self.census.chunk_blocks,
        )
        .await?;
        if owner_census.census.request_count != self.census.request_count
            || owner_census.census.response_bytes != self.census.response_bytes
            || owner_census.census.logs.len() != self.census.log_count
            || owner_census.owner_fills.len() != self.census.owner_fill_count
            || self.census.started_at > self.census.completed_at
            || self
                .census
                .completed_at
                .signed_duration_since(self.census.started_at)
                .num_seconds()
                > 120
        {
            return Err(CurrentWalletFlowError::InvalidArtifact);
        }
        let candidates = candidate_transaction_hashes(
            &owner_census.census,
            self.request.limits.max_candidate_transactions,
        );
        let expected_skipped = if self.transactions.captured {
            if self.transactions.request.transaction_hashes != candidates.selected {
                return Err(CurrentWalletFlowError::InvalidArtifact);
            }
            candidates.skipped
        } else {
            if !self.transactions.request.transaction_hashes.is_empty() {
                return Err(CurrentWalletFlowError::InvalidArtifact);
            }
            candidates.skipped.saturating_add(candidates.selected.len())
        };
        if self.skipped_candidate_transactions != expected_skipped {
            return Err(CurrentWalletFlowError::InvalidArtifact);
        }
        let transactions = if self.transactions.captured {
            let transactions_request = self.transactions.to_sdk_request()?;
            let capture = reverify_recorded_current_interval_transactions(
                &owner_census.census,
                &transactions_request,
                RpcCurrentIntervalTransactionsCaptureWindow {
                    started_at: self.transactions.started_at,
                    completed_at: self.transactions.completed_at,
                },
                &self.transactions.pages.to_sdk(),
            )
            .await?;
            if capture.request_count != self.transactions.request_count
                || capture.response_bytes != self.transactions.response_bytes
            {
                return Err(CurrentWalletFlowError::InvalidArtifact);
            }
            Some(capture)
        } else {
            if !self.transactions.pages.0.is_empty()
                || self.transactions.request_count != 0
                || self.transactions.response_bytes != 0
                || !self.transactions.request.transaction_hashes.is_empty()
            {
                return Err(CurrentWalletFlowError::InvalidArtifact);
            }
            None
        };
        let mut contexts = Vec::with_capacity(self.contexts.len());
        let mut context_anchors = BTreeSet::new();
        for packet in &self.contexts {
            let request = packet.request.to_sdk_request()?;
            if !context_anchors.insert((request.block_number, request.expected_hash.clone())) {
                return Err(CurrentWalletFlowError::InvalidArtifact);
            }
            let context = reverify_recorded_current_fifth_binary_context(
                &owner_census.census,
                &request,
                &packet.pages.to_sdk(),
            )
            .await?;
            if context.request_count() != packet.request_count
                || context.response_bytes() != packet.response_bytes
                || packet.started_at > packet.completed_at
                || packet
                    .completed_at
                    .signed_duration_since(packet.started_at)
                    .num_seconds()
                    > 30
            {
                return Err(CurrentWalletFlowError::InvalidArtifact);
            }
            contexts.push(context);
        }
        let mut ctf_v2_contexts = Vec::with_capacity(self.ctf_v2_contexts.len());
        let mut ctf_v2_context_anchors = BTreeSet::new();
        for packet in &self.ctf_v2_contexts {
            let request = packet.request.to_sdk_request()?;
            if !ctf_v2_context_anchors.insert((request.block_number, request.expected_hash.clone()))
            {
                return Err(CurrentWalletFlowError::InvalidArtifact);
            }
            let context = reverify_recorded_current_ctf_v2_context(
                &owner_census.census,
                &request,
                &packet.pages.to_sdk(),
            )
            .await?;
            if context.request_count() != packet.request_count
                || context.response_bytes() != packet.response_bytes
                || context.source()
                    != crate::rpc_position_history::ctf_v2_context::RpcCurrentCtfV2ContextSource::ProviderReported
                || context.implementation_version()
                    != crate::rpc_position_history::ctf_v2_context::RpcCurrentCtfV2ImplementationVersion::Unbound
            {
                return Err(CurrentWalletFlowError::InvalidArtifact);
            }
            ctf_v2_contexts.push(context);
        }
        let required_context_anchors = transactions
            .as_ref()
            .into_iter()
            .flat_map(|capture| capture.transactions.iter())
            .filter_map(|tx| provider_reported_fifth_settlement_context_candidate(&tx.transaction))
            .collect::<BTreeSet<_>>();
        if context_anchors
            .iter()
            .any(|anchor| !required_context_anchors.contains(anchor))
            || required_context_anchors
                .len()
                .saturating_sub(context_anchors.len())
                != self.skipped_context_blocks
        {
            return Err(CurrentWalletFlowError::InvalidArtifact);
        }
        let required_ctf_v2_context_anchors = transactions
            .as_ref()
            .into_iter()
            .flat_map(|capture| capture.transactions.iter())
            .filter_map(|tx| provider_reported_ctf_v2_settlement_context_candidate(&tx.transaction))
            .collect::<BTreeSet<_>>();
        if ctf_v2_context_anchors
            .iter()
            .any(|anchor| !required_ctf_v2_context_anchors.contains(anchor))
            || required_ctf_v2_context_anchors
                .len()
                .saturating_sub(ctf_v2_context_anchors.len())
                != self.skipped_ctf_v2_context_blocks
        {
            return Err(CurrentWalletFlowError::InvalidArtifact);
        }
        self.activity
            .validate(&self.request, &owner_census.census)?;
        Ok((owner_census, transactions, contexts, ctf_v2_contexts))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RequestPacket {
    wallet: String,
    start_block: u64,
    expected_start_hash: String,
    through_block: u64,
    expected_through_hash: String,
    limits: LimitsPacket,
}

impl RequestPacket {
    fn from_request(request: &CurrentWalletFlowRequest) -> Self {
        Self {
            wallet: request.wallet.clone(),
            start_block: request.start_block,
            expected_start_hash: request.expected_start_hash.clone(),
            through_block: request.through_block,
            expected_through_hash: request.expected_through_hash.clone(),
            limits: LimitsPacket::from_limits(request.limits),
        }
    }

    fn validate(&self) -> Result<(), CurrentWalletFlowError> {
        let request = CurrentWalletFlowRequest {
            wallet: self.wallet.clone(),
            start_block: self.start_block,
            expected_start_hash: self.expected_start_hash.clone(),
            through_block: self.through_block,
            expected_through_hash: self.expected_through_hash.clone(),
            limits: self.limits.to_limits()?,
        };
        validate_request(&request)
    }

    fn to_request(&self) -> CurrentWalletFlowRequest {
        CurrentWalletFlowRequest {
            wallet: self.wallet.clone(),
            start_block: self.start_block,
            expected_start_hash: self.expected_start_hash.clone(),
            through_block: self.through_block,
            expected_through_hash: self.expected_through_hash.clone(),
            limits: CurrentWalletFlowLimits {
                max_activity_requests: self.limits.max_activity_requests,
                max_rpc_requests: self.limits.max_rpc_requests,
                max_raw_response_bytes: self.limits.max_raw_response_bytes,
                max_candidate_transactions: self.limits.max_candidate_transactions,
                total_timeout: Duration::from_millis(self.limits.total_timeout_millis),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LimitsPacket {
    max_activity_requests: usize,
    max_rpc_requests: usize,
    max_raw_response_bytes: usize,
    max_candidate_transactions: usize,
    total_timeout_millis: u64,
}

impl LimitsPacket {
    fn from_limits(limits: CurrentWalletFlowLimits) -> Self {
        Self {
            max_activity_requests: limits.max_activity_requests,
            max_rpc_requests: limits.max_rpc_requests,
            max_raw_response_bytes: limits.max_raw_response_bytes,
            max_candidate_transactions: limits.max_candidate_transactions,
            total_timeout_millis: u64::try_from(limits.total_timeout.as_millis())
                .unwrap_or(u64::MAX),
        }
    }

    fn to_limits(self) -> Result<CurrentWalletFlowLimits, CurrentWalletFlowError> {
        let total_timeout = Duration::from_millis(self.total_timeout_millis);
        let limits = CurrentWalletFlowLimits {
            max_activity_requests: self.max_activity_requests,
            max_rpc_requests: self.max_rpc_requests,
            max_raw_response_bytes: self.max_raw_response_bytes,
            max_candidate_transactions: self.max_candidate_transactions,
            total_timeout,
        };
        if total_timeout.as_millis() != u128::from(self.total_timeout_millis) {
            return Err(CurrentWalletFlowError::InvalidArtifact);
        }
        Ok(limits)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ActivityPacket {
    wallet: String,
    policy_version: String,
    start: i64,
    end: i64,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    total_requests: usize,
    total_response_bytes: usize,
    default_pass: PassPacket,
    tip_pass: PassPacket,
    occurrences: Vec<ActivityOccurrencePacket>,
}

impl ActivityPacket {
    fn empty_unavailable(
        wallet: &str,
        start: i64,
        end: i64,
        started_at: DateTime<Utc>,
        completed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            wallet: wallet.to_owned(),
            policy_version: ACTIVITY_HINT_POLICY_VERSION.to_owned(),
            start,
            end,
            started_at,
            completed_at,
            total_requests: 0,
            total_response_bytes: 0,
            default_pass: PassPacket::unavailable("activity_window_has_no_integer_second"),
            tip_pass: PassPacket::unavailable("activity_window_has_no_integer_second"),
            occurrences: Vec::new(),
        }
    }

    fn from_acquisition(
        acquisition: &ActivityHintAcquisition,
        started_at: DateTime<Utc>,
        completed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            wallet: acquisition.wallet().to_owned(),
            policy_version: acquisition.policy_version().to_owned(),
            start: acquisition.start(),
            end: acquisition.end(),
            started_at,
            completed_at,
            total_requests: acquisition.total_requests(),
            total_response_bytes: acquisition.total_response_bytes(),
            default_pass: PassPacket::from_summary(acquisition.default_pass()),
            tip_pass: PassPacket::from_summary(acquisition.tip_pass()),
            occurrences: acquisition
                .occurrences()
                .iter()
                .map(ActivityOccurrencePacket::from_occurrence)
                .collect(),
        }
    }

    fn validate(
        &self,
        request: &RequestPacket,
        census: &RpcCurrentIntervalCensus,
    ) -> Result<(), CurrentWalletFlowError> {
        let expected_start = i64::try_from(census.start_header.timestamp)
            .ok()
            .and_then(|timestamp| timestamp.checked_add(1))
            .ok_or(CurrentWalletFlowError::InvalidArtifact)?;
        let expected_end = i64::try_from(census.end_header.timestamp)
            .map_err(|_| CurrentWalletFlowError::InvalidArtifact)?;
        if self.wallet != request.wallet
            || self.start != expected_start
            || self.end != expected_end
            || self.started_at > self.completed_at
            || self.end > self.started_at.timestamp()
            || self
                .completed_at
                .signed_duration_since(self.started_at)
                .num_seconds()
                > 120
            || self.total_requests > request.limits.max_activity_requests
            || self.total_response_bytes > request.limits.max_raw_response_bytes
            || self.occurrences.len() > MAX_ACTIVITY_ROWS
            || self.policy_version.is_empty()
            || (self.default_pass.complete && self.default_pass.incomplete_reason.is_some())
            || (self.tip_pass.complete && self.tip_pass.incomplete_reason.is_some())
            || (!self.default_pass.complete
                && self.default_pass.pages_requested > 0
                && self.default_pass.incomplete_reason.is_none())
            || (!self.tip_pass.complete
                && self.tip_pass.pages_requested > 0
                && self.tip_pass.incomplete_reason.is_none())
            || self
                .default_pass
                .pages_requested
                .saturating_add(self.tip_pass.pages_requested)
                > self.total_requests
            || self.default_pass.rows_retained
                != self
                    .occurrences
                    .iter()
                    .filter(|row| row.pass == ActivityPassPacketKind::DefaultTypes)
                    .count()
            || self.tip_pass.rows_retained
                != self
                    .occurrences
                    .iter()
                    .filter(|row| row.pass == ActivityPassPacketKind::Tip)
                    .count()
        {
            return Err(CurrentWalletFlowError::InvalidArtifact);
        }
        Ok(())
    }

    fn to_occurrences(&self) -> Vec<ActivityHintOccurrence> {
        self.occurrences
            .iter()
            .map(ActivityOccurrencePacket::to_occurrence)
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ActivityPassPacketKind {
    DefaultTypes,
    Tip,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PassPacket {
    pages_requested: usize,
    rows_retained: usize,
    complete: bool,
    incomplete_reason: Option<String>,
}

impl PassPacket {
    fn unavailable(reason: &str) -> Self {
        Self {
            pages_requested: 0,
            rows_retained: 0,
            complete: false,
            incomplete_reason: Some(reason.to_owned()),
        }
    }

    fn from_summary(summary: ActivityHintPassSummary) -> Self {
        Self {
            pages_requested: summary.pages_requested,
            rows_retained: summary.rows_retained,
            complete: summary.status == ActivityHintPassStatus::Complete,
            incomplete_reason: match summary.status {
                ActivityHintPassStatus::Complete | ActivityHintPassStatus::NotStarted => None,
                ActivityHintPassStatus::Incomplete(reason) => Some(reason.label().to_owned()),
            },
        }
    }

    fn to_summary(&self) -> ActivityHintPassSummary {
        ActivityHintPassSummary {
            pages_requested: self.pages_requested,
            rows_retained: self.rows_retained,
            status: if self.complete {
                ActivityHintPassStatus::Complete
            } else if self.pages_requested == 0 && self.rows_retained == 0 {
                ActivityHintPassStatus::NotStarted
            } else {
                ActivityHintPassStatus::Incomplete(
                    ActivityHintIncompleteReason::ProviderUnavailable,
                )
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ActivityOccurrencePacket {
    pass: ActivityPassPacketKind,
    page: usize,
    ordinal: usize,
    timestamp: i64,
    activity_type: String,
    transaction_hash: String,
    raw: Value,
}

impl ActivityOccurrencePacket {
    fn from_occurrence(row: &ActivityHintOccurrence) -> Self {
        Self {
            pass: match row.pass {
                ActivityHintPass::DefaultTypes => ActivityPassPacketKind::DefaultTypes,
                ActivityHintPass::Tip => ActivityPassPacketKind::Tip,
            },
            page: row.page,
            ordinal: row.ordinal,
            timestamp: row.timestamp,
            activity_type: row.activity_type.clone(),
            transaction_hash: row.transaction_hash.clone(),
            raw: row.raw.clone(),
        }
    }

    fn to_occurrence(&self) -> ActivityHintOccurrence {
        ActivityHintOccurrence {
            pass: match self.pass {
                ActivityPassPacketKind::DefaultTypes => ActivityHintPass::DefaultTypes,
                ActivityPassPacketKind::Tip => ActivityHintPass::Tip,
            },
            page: self.page,
            ordinal: self.ordinal,
            timestamp: self.timestamp,
            activity_type: self.activity_type.clone(),
            transaction_hash: self.transaction_hash.clone(),
            raw: self.raw.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RpcPagePacket {
    request_json: String,
    response_json: String,
}

impl RpcPagePacket {
    fn from_pages(pages: &[RpcPositionHistoryPage]) -> Vec<Self> {
        pages
            .iter()
            .map(|page| Self {
                request_json: page.request_json().to_owned(),
                response_json: page.response_json().to_owned(),
            })
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
struct RpcPages(Vec<RpcPagePacket>);

impl RpcPages {
    fn from_pages(pages: &[RpcPositionHistoryPage]) -> Self {
        Self(RpcPagePacket::from_pages(pages))
    }
    fn to_sdk(&self) -> Vec<RecordedRpcPositionHistoryPage> {
        self.0
            .iter()
            .map(|page| RecordedRpcPositionHistoryPage {
                request_json: page.request_json.clone(),
                response_json: page.response_json.clone(),
            })
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CensusPacket {
    request: CensusRequestPacket,
    chunk_blocks: u64,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    request_count: usize,
    response_bytes: usize,
    log_count: usize,
    owner_fill_count: usize,
    pages: RpcPages,
}

impl CensusPacket {
    fn from_capture(
        capture: &RpcCurrentIntervalOwnerFillCensus,
        request: &RpcCurrentIntervalCensusRequest,
    ) -> Self {
        Self {
            request: CensusRequestPacket::from_request(request),
            chunk_blocks: CURRENT_WALLET_FLOW_LOG_CHUNK_BLOCKS,
            started_at: capture.census.started_at,
            completed_at: capture.census.completed_at,
            request_count: capture.census.request_count,
            response_bytes: capture.census.response_bytes,
            log_count: capture.census.logs.len(),
            owner_fill_count: capture.owner_fills.len(),
            pages: RpcPages::from_pages(&capture.census.requests),
        }
    }
    fn to_sdk_request(&self) -> Result<RpcCurrentIntervalCensusRequest, CurrentWalletFlowError> {
        self.request.to_sdk_request()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CensusRequestPacket {
    wallet: String,
    start_block: u64,
    expected_start_hash: String,
    through_block: u64,
    expected_through_hash: String,
    max_requests: usize,
    max_total_response_bytes: usize,
    timeout_millis: u64,
}

impl CensusRequestPacket {
    fn from_request(request: &RpcCurrentIntervalCensusRequest) -> Self {
        Self {
            wallet: request.wallets[0].clone(),
            start_block: request.start_block,
            expected_start_hash: request.expected_start_hash.clone(),
            through_block: request.through_block,
            expected_through_hash: request.expected_through_hash.clone(),
            max_requests: request.max_requests,
            max_total_response_bytes: request.max_total_response_bytes,
            timeout_millis: request
                .total_timeout
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        }
    }
    fn to_sdk_request(&self) -> Result<RpcCurrentIntervalCensusRequest, CurrentWalletFlowError> {
        if self.timeout_millis == 0 {
            return Err(CurrentWalletFlowError::InvalidArtifact);
        }
        Ok(RpcCurrentIntervalCensusRequest {
            wallets: vec![self.wallet.clone()],
            start_block: self.start_block,
            expected_start_hash: self.expected_start_hash.clone(),
            through_block: self.through_block,
            expected_through_hash: self.expected_through_hash.clone(),
            max_requests: self.max_requests,
            max_total_response_bytes: self.max_total_response_bytes,
            total_timeout: Duration::from_millis(self.timeout_millis),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TransactionPacket {
    captured: bool,
    request: TransactionRequestPacket,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    request_count: usize,
    response_bytes: usize,
    pages: RpcPages,
}

impl TransactionPacket {
    fn empty() -> Self {
        Self {
            captured: false,
            request: TransactionRequestPacket {
                transaction_hashes: Vec::new(),
                max_requests: 0,
                max_total_response_bytes: 0,
                timeout_millis: 1,
            },
            started_at: Utc::now(),
            completed_at: Utc::now(),
            request_count: 0,
            response_bytes: 0,
            pages: RpcPages(Vec::new()),
        }
    }
    fn from_capture(
        capture: &RpcCurrentIntervalTransactions,
        request: &RpcCurrentIntervalTransactionsRequest,
    ) -> Self {
        Self {
            captured: true,
            request: TransactionRequestPacket {
                transaction_hashes: request.transaction_hashes.clone(),
                max_requests: request.max_requests,
                max_total_response_bytes: request.max_total_response_bytes,
                timeout_millis: request.total_timeout.as_millis().try_into().unwrap_or(1),
            },
            started_at: capture.started_at,
            completed_at: capture.completed_at,
            request_count: capture.request_count,
            response_bytes: capture.response_bytes,
            pages: RpcPages::from_pages(&capture.requests),
        }
    }
    fn with_window(mut self, window: RpcCurrentIntervalTransactionsCaptureWindow) -> Self {
        self.started_at = window.started_at;
        self.completed_at = window.completed_at;
        self
    }
    fn to_sdk_request(
        &self,
    ) -> Result<RpcCurrentIntervalTransactionsRequest, CurrentWalletFlowError> {
        self.request.to_sdk_request()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TransactionRequestPacket {
    transaction_hashes: Vec<String>,
    max_requests: usize,
    max_total_response_bytes: usize,
    timeout_millis: u64,
}

impl TransactionRequestPacket {
    fn to_sdk_request(
        &self,
    ) -> Result<RpcCurrentIntervalTransactionsRequest, CurrentWalletFlowError> {
        if self.timeout_millis == 0 {
            return Err(CurrentWalletFlowError::InvalidArtifact);
        }
        Ok(RpcCurrentIntervalTransactionsRequest {
            transaction_hashes: self.transaction_hashes.clone(),
            max_requests: self.max_requests,
            max_total_response_bytes: self.max_total_response_bytes,
            total_timeout: Duration::from_millis(self.timeout_millis),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ContextPacket {
    request: ContextRequestPacket,
    pages: RpcPages,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    request_count: usize,
    response_bytes: usize,
}

impl ContextPacket {
    fn from_capture(
        context: &RpcCurrentFifthBinaryContext,
        request: RpcCurrentFifthBinaryContextRequest,
    ) -> Self {
        Self {
            request: ContextRequestPacket::from_request(&request),
            pages: RpcPages::from_pages(context.requests()),
            started_at: context.started_at(),
            completed_at: context.completed_at(),
            request_count: context.request_count(),
            response_bytes: context.response_bytes(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ContextRequestPacket {
    block_number: u64,
    expected_hash: String,
    max_requests: usize,
    max_total_response_bytes: usize,
    timeout_millis: u64,
}

impl ContextRequestPacket {
    fn from_request(request: &RpcCurrentFifthBinaryContextRequest) -> Self {
        Self {
            block_number: request.block_number,
            expected_hash: request.expected_hash.clone(),
            max_requests: request.max_requests,
            max_total_response_bytes: request.max_total_response_bytes,
            timeout_millis: request.total_timeout.as_millis().try_into().unwrap_or(1),
        }
    }
    fn to_sdk_request(
        &self,
    ) -> Result<RpcCurrentFifthBinaryContextRequest, CurrentWalletFlowError> {
        if self.timeout_millis == 0 {
            return Err(CurrentWalletFlowError::InvalidArtifact);
        }
        Ok(RpcCurrentFifthBinaryContextRequest {
            block_number: self.block_number,
            expected_hash: self.expected_hash.clone(),
            max_requests: self.max_requests,
            max_total_response_bytes: self.max_total_response_bytes,
            total_timeout: Duration::from_millis(self.timeout_millis),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CtfV2ContextPacket {
    request: CtfV2ContextRequestPacket,
    pages: RpcPages,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    request_count: usize,
    response_bytes: usize,
}

impl CtfV2ContextPacket {
    fn from_capture(
        context: &RpcCurrentCtfV2Context,
        request: RpcCurrentCtfV2ContextRequest,
    ) -> Self {
        Self {
            request: CtfV2ContextRequestPacket::from_request(&request),
            pages: RpcPages::from_pages(context.requests()),
            started_at: context.started_at(),
            completed_at: context.completed_at(),
            request_count: context.request_count(),
            response_bytes: context.response_bytes(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CtfV2ContextRequestPacket {
    block_number: u64,
    expected_hash: String,
    max_requests: usize,
    max_total_response_bytes: usize,
    timeout_millis: u64,
}

impl CtfV2ContextRequestPacket {
    fn from_request(request: &RpcCurrentCtfV2ContextRequest) -> Self {
        Self {
            block_number: request.block_number,
            expected_hash: request.expected_hash.clone(),
            max_requests: request.max_requests,
            max_total_response_bytes: request.max_total_response_bytes,
            timeout_millis: request.total_timeout.as_millis().try_into().unwrap_or(1),
        }
    }

    fn to_sdk_request(&self) -> Result<RpcCurrentCtfV2ContextRequest, CurrentWalletFlowError> {
        if self.timeout_millis == 0 {
            return Err(CurrentWalletFlowError::InvalidArtifact);
        }
        Ok(RpcCurrentCtfV2ContextRequest {
            block_number: self.block_number,
            expected_hash: self.expected_hash.clone(),
            max_requests: self.max_requests,
            max_total_response_bytes: self.max_total_response_bytes,
            total_timeout: Duration::from_millis(self.timeout_millis),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FlowPacket {
    wallet: String,
    start_block: u64,
    through_block: u64,
    known: bool,
    capital_flows: Vec<FlowMovementPacket>,
    unresolved: Vec<UnresolvedPacket>,
}

impl FlowPacket {
    fn empty() -> Self {
        Self {
            wallet: String::new(),
            start_block: 0,
            through_block: 0,
            known: false,
            capital_flows: Vec::new(),
            unresolved: Vec::new(),
        }
    }
    fn from_reduction(reduction: &SourceWalletFlowReduction) -> Self {
        Self {
            wallet: reduction.wallet.clone(),
            start_block: reduction.start_block,
            through_block: reduction.through_block,
            known: format!("{:?}", reduction.coverage) == "KnownForDeclaredScope",
            capital_flows: reduction
                .capital_flows
                .iter()
                .map(|flow| FlowMovementPacket {
                    locator: flow.locator.clone(),
                    timestamp: flow.timestamp,
                    asset: format!("{:?}", flow.asset),
                    signed_amount_microunits: flow.signed_amount_microunits,
                })
                .collect(),
            unresolved: reduction
                .unresolved
                .iter()
                .map(|item| UnresolvedPacket {
                    movement_locator: item.movement_locator.clone(),
                    activity_occurrence: item.activity_occurrence.clone(),
                    reason: format!("{:?}", item.reason),
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FlowMovementPacket {
    locator: String,
    timestamp: u64,
    asset: String,
    signed_amount_microunits: i128,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct UnresolvedPacket {
    movement_locator: Option<String>,
    activity_occurrence: Option<String>,
    reason: String,
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use axum::{
        Json, Router,
        body::Bytes,
        extract::{Query, State},
        routing::{get, post},
    };
    use serde_json::{Value, json};

    use super::*;
    use crate::collateral_cash::{PUSD_ADDRESS, USDCE_ADDRESS};
    use crate::rpc_position_history::current_interval_census::{
        RpcCurrentIntervalAsset, RpcCurrentIntervalHeader, RpcCurrentIntervalLog,
        RpcCurrentIntervalSource,
    };

    fn request(limits: CurrentWalletFlowLimits) -> CurrentWalletFlowRequest {
        CurrentWalletFlowRequest {
            wallet: format!("0x{}", "11".repeat(20)),
            start_block: 10,
            expected_start_hash: format!("0x{}", "22".repeat(32)),
            through_block: 20,
            expected_through_hash: format!("0x{}", "33".repeat(32)),
            limits,
        }
    }

    #[tokio::test]
    async fn invalid_budget_is_rejected_before_either_endpoint_is_called() {
        let activity = PolymarketActivityHintClient::new("http://127.0.0.1:9").unwrap();
        let rpc = RpcPositionHistoryReader::new(reqwest::Client::builder(), "http://127.0.0.1:9")
            .unwrap();
        let limits = CurrentWalletFlowLimits {
            max_rpc_requests: 0,
            ..CurrentWalletFlowLimits::default()
        };
        assert!(matches!(
            capture_current_wallet_flow_observation(&activity, &rpc, &request(limits)).await,
            Err(CurrentWalletFlowError::InvalidInput)
        ));
    }

    #[test]
    fn transaction_cap_reports_omitted_candidates_instead_of_dropping_them_silently() {
        let wallet = format!("0x{}", "11".repeat(20));
        let logs = (0..33)
            .map(|index| {
                let hash = format!("0x{:064x}", index + 1);
                RpcCurrentIntervalLog {
                    locator: format!("137:{hash}:{index}"),
                    block_hash: format!("0x{}", "44".repeat(32)),
                    transaction_hash: hash,
                    block_number: 15,
                    transaction_index: index,
                    log_index: index,
                    asset: RpcCurrentIntervalAsset::Pusd,
                    from: wallet.clone(),
                    to: format!("0x{}", "55".repeat(20)),
                    amount_word: Some(format!("0x{:064x}", 1)),
                    position_log: None,
                }
            })
            .collect();
        let census = RpcCurrentIntervalCensus {
            wallets: vec![wallet],
            start_block: 10,
            through_block: 20,
            start_header: RpcCurrentIntervalHeader {
                number: 10,
                hash: format!("0x{}", "22".repeat(32)),
                timestamp: 100,
            },
            end_header: RpcCurrentIntervalHeader {
                number: 20,
                hash: format!("0x{}", "33".repeat(32)),
                timestamp: 200,
            },
            event_headers: vec![RpcCurrentIntervalHeader {
                number: 15,
                hash: format!("0x{}", "44".repeat(32)),
                timestamp: 150,
            }],
            logs,
            source: RpcCurrentIntervalSource::ProviderReported,
            started_at: Utc::now(),
            completed_at: Utc::now(),
            elapsed: Duration::ZERO,
            request_count: 0,
            response_bytes: 0,
            requests: Vec::new(),
        };
        let candidates = candidate_transaction_hashes(&census, 32);
        assert_eq!(candidates.selected.len(), 32);
        assert_eq!(candidates.skipped, 1);
        let mut known = SourceWalletFlowReduction {
            wallet: census.wallets[0].clone(),
            source: super::super::current_interval_census::portfolio_flow::SourceFlowSource::ProviderReported,
            start_block: 10,
            through_block: 20,
            coverage: super::super::current_interval_census::portfolio_flow::SourceFlowCoverage::KnownForDeclaredScope,
            capital_flows: Vec::new(),
            unresolved: Vec::new(),
        };
        mark_unknown_for_limits(&mut known);
        assert_eq!(
            known.coverage,
            super::super::current_interval_census::portfolio_flow::SourceFlowCoverage::Unknown
        );
    }

    #[test]
    fn unknown_reduction_is_not_projected_as_zero_known() {
        let reduction = SourceWalletFlowReduction {
            wallet: format!("0x{}", "11".repeat(20)),
            source: super::super::current_interval_census::portfolio_flow::SourceFlowSource::ProviderReported,
            start_block: 10,
            through_block: 20,
            coverage: super::super::current_interval_census::portfolio_flow::SourceFlowCoverage::Unknown,
            capital_flows: Vec::new(),
            unresolved: Vec::new(),
        };
        let projection = FlowPacket::from_reduction(&reduction);
        assert!(!projection.known);
        assert!(projection.capital_flows.is_empty());
    }

    #[derive(Clone)]
    struct FlowRpcState {
        requests: Arc<Mutex<Vec<Value>>>,
        emit_transfer: bool,
    }

    async fn flow_rpc(State(state): State<FlowRpcState>, body: Bytes) -> Json<Value> {
        let request: Value = serde_json::from_slice(&body).unwrap();
        state.requests.lock().unwrap().push(request.clone());
        let params = &request["params"];
        let result = match request["method"].as_str().unwrap() {
            "eth_chainId" => json!("0x89"),
            "eth_getBlockByNumber" => {
                let tag = params[0].as_str().unwrap();
                let number = if tag == "finalized" {
                    11
                } else {
                    u64::from_str_radix(tag.trim_start_matches("0x"), 16).unwrap()
                };
                flow_header(number)
            }
            "eth_getLogs"
                if state.emit_transfer
                    && params[0]["address"] == json!([PUSD_ADDRESS, USDCE_ADDRESS])
                    && params[0]["topics"][1].as_array().is_some_and(|topics| {
                        topics.iter().any(|topic| topic == &flow_wallet_topic())
                    }) =>
            {
                json!([flow_cash_log()])
            }
            "eth_getLogs" => json!([]),
            method => panic!("unexpected RPC method: {method}"),
        };
        Json(json!({"jsonrpc":"2.0", "id":request["id"], "result":result}))
    }

    async fn activity_page(Query(_query): Query<HashMap<String, String>>) -> Json<Value> {
        Json(json!({
            "data":[],
            "pagination":{"limit":MAX_ACTIVITY_PAGE_SIZE,"offset":0,"has_more":false}
        }))
    }

    fn flow_header(number: u64) -> Value {
        json!({
            "number":format!("0x{number:x}"),
            "hash":format!("0x{:064x}", number + 1),
            "parentHash":format!("0x{:064x}", number),
            "stateRoot":format!("0x{:064x}", number + 2),
            "transactionsRoot":format!("0x{:064x}", number + 3),
            "receiptsRoot":format!("0x{:064x}", number + 4),
            "logsBloom":format!("0x{}", "00".repeat(256)),
            "timestamp":format!("0x{:x}", 1_700_000_000 + number),
        })
    }

    fn flow_wallet_topic() -> Value {
        json!(format!("0x{:0>64}", "11".repeat(20)))
    }

    fn flow_cash_log() -> Value {
        json!({
            "removed":false,
            "blockNumber":"0xb",
            "blockHash":flow_header(11)["hash"],
            "transactionHash":format!("0x{}", "44".repeat(32)),
            "transactionIndex":"0x1",
            "logIndex":"0x2",
            "address":PUSD_ADDRESS,
            "topics":[
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                flow_wallet_topic(),
                format!("0x{:0>64}", "22".repeat(20))
            ],
            "data":format!("0x{:064x}", 1_000_000_u64)
        })
    }

    fn packet_bytes(packet: &mut CurrentWalletFlowPacket) -> Vec<u8> {
        packet.content_sha256 = packet.calculate_sha256().unwrap();
        serde_json::to_vec(packet).unwrap()
    }

    #[tokio::test]
    async fn empty_capture_replays_and_rejects_tampering_without_losing_unknown() {
        let rpc_requests = Arc::new(Mutex::new(Vec::new()));
        let rpc_app = Router::new()
            .route("/", post(flow_rpc))
            .with_state(FlowRpcState {
                requests: rpc_requests,
                emit_transfer: false,
            });
        let rpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_address = rpc_listener.local_addr().unwrap();
        let rpc_server = tokio::spawn(async move {
            axum::serve(rpc_listener, rpc_app).await.unwrap();
        });
        let rpc = RpcPositionHistoryReader::new(
            reqwest::Client::builder(),
            &format!("http://{rpc_address}/"),
        )
        .unwrap();

        let activity_app = Router::new().route("/v2/activity", get(activity_page));
        let activity_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let activity_address = activity_listener.local_addr().unwrap();
        let activity_server = tokio::spawn(async move {
            axum::serve(activity_listener, activity_app).await.unwrap();
        });
        let activity =
            PolymarketActivityHintClient::new(&format!("http://{activity_address}/")).unwrap();
        let request = CurrentWalletFlowRequest {
            wallet: format!("0x{}", "11".repeat(20)),
            start_block: 10,
            expected_start_hash: flow_header(10)["hash"].as_str().unwrap().to_owned(),
            through_block: 11,
            expected_through_hash: flow_header(11)["hash"].as_str().unwrap().to_owned(),
            limits: CurrentWalletFlowLimits::default(),
        };
        let captured = capture_current_wallet_flow_observation(&activity, &rpc, &request)
            .await
            .unwrap();
        let artifact = captured.to_artifact().unwrap();
        let legacy_packet: Value = serde_json::from_slice(&artifact).unwrap();
        assert_eq!(
            legacy_packet["version"],
            LEGACY_CURRENT_WALLET_FLOW_ARTIFACT_VERSION
        );
        assert!(legacy_packet.get("ctf_v2_contexts").is_none());
        assert!(legacy_packet.get("skipped_ctf_v2_context_blocks").is_none());
        let replayed = CurrentWalletFlowObservation::from_artifact(&artifact)
            .await
            .unwrap();
        assert_eq!(replayed.reduction().coverage, super::super::current_interval_census::portfolio_flow::SourceFlowCoverage::KnownForDeclaredScope);
        assert_eq!(replayed.request(), request);
        assert_eq!(replayed.capture_started_at(), captured.capture_started_at());
        assert_eq!(
            replayed.capture_completed_at(),
            captured.capture_completed_at()
        );
        assert_eq!(
            replayed.activity_occurrence_count(),
            captured.activity_occurrence_count()
        );
        assert_eq!(replayed.census_log_count(), captured.census_log_count());
        assert_eq!(replayed.owner_fill_count(), captured.owner_fill_count());
        assert_eq!(replayed.to_artifact().unwrap(), artifact);
        assert_eq!(
            replayed.total_rpc_request_count(),
            captured.total_rpc_request_count()
        );
        assert_eq!(
            replayed.total_raw_response_bytes(),
            captured.total_raw_response_bytes()
        );

        let mut report_tamper: CurrentWalletFlowPacket = serde_json::from_slice(&artifact).unwrap();
        report_tamper.reduction.known = false;
        assert!(matches!(
            CurrentWalletFlowObservation::from_artifact(&packet_bytes(&mut report_tamper)).await,
            Err(CurrentWalletFlowError::InvalidArtifact)
        ));

        let mut scope_tamper: CurrentWalletFlowPacket = serde_json::from_slice(&artifact).unwrap();
        scope_tamper.request.expected_through_hash = format!("0x{}", "77".repeat(32));
        assert!(
            CurrentWalletFlowObservation::from_artifact(&packet_bytes(&mut scope_tamper))
                .await
                .is_err()
        );

        let mut raw_tamper: CurrentWalletFlowPacket = serde_json::from_slice(&artifact).unwrap();
        let chain_id_page = raw_tamper
            .census
            .pages
            .0
            .iter_mut()
            .find(|page| page.request_json.contains("eth_chainId"))
            .unwrap();
        let mut response: Value = serde_json::from_str(&chain_id_page.response_json).unwrap();
        response["result"] = json!("0x1");
        chain_id_page.response_json = serde_json::to_string(&response).unwrap();
        assert!(
            CurrentWalletFlowObservation::from_artifact(&packet_bytes(&mut raw_tamper))
                .await
                .is_err()
        );

        let mut unknown: CurrentWalletFlowPacket = serde_json::from_slice(&artifact).unwrap();
        unknown.activity.default_pass.complete = false;
        unknown.activity.default_pass.incomplete_reason = Some("fixture_incomplete".to_owned());
        let reduction = unknown.recompute_reduction().await.unwrap();
        unknown.reduction = FlowPacket::from_reduction(&reduction);
        let unknown = CurrentWalletFlowObservation::from_artifact(&packet_bytes(&mut unknown))
            .await
            .unwrap();
        assert_eq!(
            unknown.reduction().coverage,
            super::super::current_interval_census::portfolio_flow::SourceFlowCoverage::Unknown
        );

        let transfer_app = Router::new()
            .route("/", post(flow_rpc))
            .with_state(FlowRpcState {
                requests: Arc::new(Mutex::new(Vec::new())),
                emit_transfer: true,
            });
        let transfer_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let transfer_address = transfer_listener.local_addr().unwrap();
        let transfer_server = tokio::spawn(async move {
            axum::serve(transfer_listener, transfer_app).await.unwrap();
        });
        let transfer_rpc = RpcPositionHistoryReader::new(
            reqwest::Client::builder(),
            &format!("http://{transfer_address}/"),
        )
        .unwrap();
        let limited_request = CurrentWalletFlowRequest {
            limits: CurrentWalletFlowLimits {
                max_rpc_requests: 11,
                ..CurrentWalletFlowLimits::default()
            },
            ..request
        };
        let skipped =
            capture_current_wallet_flow_observation(&activity, &transfer_rpc, &limited_request)
                .await
                .unwrap();
        let mut skipped_packet: CurrentWalletFlowPacket =
            serde_json::from_slice(&skipped.to_artifact().unwrap()).unwrap();
        assert_eq!(skipped_packet.skipped_candidate_transactions, 1);
        skipped_packet.skipped_candidate_transactions = 0;
        assert!(
            CurrentWalletFlowObservation::from_artifact(&packet_bytes(&mut skipped_packet))
                .await
                .is_err()
        );

        rpc_server.abort();
        activity_server.abort();
        transfer_server.abort();
    }
}
