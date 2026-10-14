//! Bounded, provider-reported finalized watch window for a selected CTF V2
//! maker cohort. This remains source attestation, not receipt-root evidence.

use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::Mutex;

use super::{
    ChainLogAuditError, ChainLogVerifier, MAX_BLOCKS, MAX_RECORDED_RECEIPT_REQUEST_BYTES,
    MAX_RECORDED_RECEIPT_RESPONSE_BYTES, MAX_RECORDED_RECEIPT_TIMEOUT, RpcCaptureState,
    RpcExecution, TransactionRequestBudget, V2_ORDER_FILLED,
    header_binding::bind_header,
    selected_owner_watch::{SelectedCtfV2OwnerLogIdentity, normalize_provider_logs},
};

pub const SELECTED_CTF_V2_OWNER_WATCH_WINDOW_POLICY_VERSION: &str =
    "ctf-v2-selected-maker-finalized-watch-window/1";
const MAX_SELECTED_MAKERS: usize = 1_024;

/// One provider's locally content-bound finalized-head response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SelectedCtfV2OwnerWatchFinalizedHead {
    block_number: u64,
    block_hash: String,
    parent_hash: String,
}

impl SelectedCtfV2OwnerWatchFinalizedHead {
    #[must_use]
    pub const fn block_number(&self) -> u64 {
        self.block_number
    }

    #[must_use]
    pub fn block_hash(&self) -> &str {
        &self.block_hash
    }

    #[must_use]
    pub fn parent_hash(&self) -> &str {
        &self.parent_hash
    }
}

/// Canonical selected-maker declaration. Its digest binds the sorted cohort,
/// not a provider's completeness or a wallet's identity beyond this input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SelectedCtfV2OwnerWatchWindowCohort {
    selected_makers: Vec<String>,
    sha256: String,
}

impl SelectedCtfV2OwnerWatchWindowCohort {
    #[must_use]
    pub fn selected_makers(&self) -> &[String] {
        &self.selected_makers
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Lagging providers yield their content-bound heads without an `eth_getLogs`
/// request. This is a wait condition, not a negative-activity assertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedCtfV2OwnerWatchWindowWaiting {
    from_block: u64,
    cohort: SelectedCtfV2OwnerWatchWindowCohort,
    primary_finalized: SelectedCtfV2OwnerWatchFinalizedHead,
    secondary_finalized: SelectedCtfV2OwnerWatchFinalizedHead,
    request_count: usize,
    response_bytes: usize,
}

impl SelectedCtfV2OwnerWatchWindowWaiting {
    #[must_use]
    pub const fn from_block(&self) -> u64 {
        self.from_block
    }

    #[must_use]
    pub fn cohort(&self) -> &SelectedCtfV2OwnerWatchWindowCohort {
        &self.cohort
    }

    #[must_use]
    pub fn primary_finalized(&self) -> &SelectedCtfV2OwnerWatchFinalizedHead {
        &self.primary_finalized
    }

    #[must_use]
    pub fn secondary_finalized(&self) -> &SelectedCtfV2OwnerWatchFinalizedHead {
        &self.secondary_finalized
    }

    #[must_use]
    pub const fn request_count(&self) -> usize {
        self.request_count
    }

    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.response_bytes
    }
}

/// Equal fully normalized selected-maker logs within a range pinned to both
/// providers' current finalized-head observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceAttestedSelectedCtfV2OwnerWatchWindow {
    from_block: u64,
    through_block: u64,
    cohort: SelectedCtfV2OwnerWatchWindowCohort,
    primary_finalized: SelectedCtfV2OwnerWatchFinalizedHead,
    secondary_finalized: SelectedCtfV2OwnerWatchFinalizedHead,
    logs: Vec<SelectedCtfV2OwnerLogIdentity>,
    partition_count: usize,
    request_count: usize,
    response_bytes: usize,
}

impl SourceAttestedSelectedCtfV2OwnerWatchWindow {
    #[must_use]
    pub const fn from_block(&self) -> u64 {
        self.from_block
    }

    #[must_use]
    pub const fn through_block(&self) -> u64 {
        self.through_block
    }

    #[must_use]
    pub fn cohort(&self) -> &SelectedCtfV2OwnerWatchWindowCohort {
        &self.cohort
    }

    #[must_use]
    pub fn primary_finalized(&self) -> &SelectedCtfV2OwnerWatchFinalizedHead {
        &self.primary_finalized
    }

    #[must_use]
    pub fn secondary_finalized(&self) -> &SelectedCtfV2OwnerWatchFinalizedHead {
        &self.secondary_finalized
    }

    #[must_use]
    pub fn logs(&self) -> &[SelectedCtfV2OwnerLogIdentity] {
        &self.logs
    }

    #[must_use]
    pub const fn partition_count(&self) -> usize {
        self.partition_count
    }

    #[must_use]
    pub const fn request_count(&self) -> usize {
        self.request_count
    }

    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.response_bytes
    }

    #[must_use]
    pub const fn policy_version(&self) -> &'static str {
        SELECTED_CTF_V2_OWNER_WATCH_WINDOW_POLICY_VERSION
    }
}

/// A bounded current-head observation either waits for the starting block or
/// reports provider-agreed candidate logs over the bounded finalized interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectedCtfV2OwnerWatchWindow {
    Waiting(SelectedCtfV2OwnerWatchWindowWaiting),
    SourceAttested(SourceAttestedSelectedCtfV2OwnerWatchWindow),
}

impl SelectedCtfV2OwnerWatchWindow {
    #[must_use]
    pub const fn policy_version(&self) -> &'static str {
        SELECTED_CTF_V2_OWNER_WATCH_WINDOW_POLICY_VERSION
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedSelectedCtfV2OwnerWindowError {
    #[error("selected owner finalized watch request budget exhausted")]
    RequestBudgetExceeded,
    #[error("selected owner finalized watch exceeded its total deadline")]
    Timeout,
    #[error("providers reported conflicting hashes for the same finalized height")]
    FinalizedFork,
    #[error(transparent)]
    Verification(ChainLogAuditError),
}

struct WindowResult {
    window: SelectedCtfV2OwnerWatchWindow,
    response_bytes: usize,
}

enum WindowError {
    RequestBudgetExceeded,
    FinalizedFork,
    Verification(ChainLogAuditError),
}

impl From<ChainLogAuditError> for WindowError {
    fn from(error: ChainLogAuditError) -> Self {
        Self::Verification(error)
    }
}

impl ChainLogVerifier {
    /// Observe a fixed selected-maker cohort over the common provider-reported
    /// finalized interval beginning at `from_block`, capped at 16 inclusive
    /// blocks. A waiting result contains only the two content-bound heads and
    /// does not issue log queries. Neither result proves log completeness or
    /// EVM receipt inclusion.
    pub async fn observe_selected_ctf_v2_owner_window_bounded(
        &self,
        from_block: u64,
        selected_makers: &[String],
        budget: &TransactionRequestBudget,
        max_total_response_bytes: usize,
        total_timeout: Duration,
    ) -> Result<SelectedCtfV2OwnerWatchWindow, BoundedSelectedCtfV2OwnerWindowError> {
        if from_block == 0
            || max_total_response_bytes == 0
            || max_total_response_bytes > MAX_RECORDED_RECEIPT_RESPONSE_BYTES
            || total_timeout.is_zero()
            || total_timeout > MAX_RECORDED_RECEIPT_TIMEOUT
        {
            return Err(BoundedSelectedCtfV2OwnerWindowError::Verification(
                ChainLogAuditError::InvalidInput,
            ));
        }
        let cohort = canonical_cohort(selected_makers)
            .map_err(BoundedSelectedCtfV2OwnerWindowError::Verification)?;
        let topics = cohort_topics(&cohort.selected_makers)
            .map_err(BoundedSelectedCtfV2OwnerWindowError::Verification)?;
        let widest_through = from_block.checked_add(MAX_BLOCKS - 1).ok_or(
            BoundedSelectedCtfV2OwnerWindowError::Verification(ChainLogAuditError::InvalidInput),
        )?;
        // Plan every actual serialized filter before any RPC send. Using the
        // widest allowed endpoint cannot underestimate a later wire body.
        let partitions = partition_topics(from_block, widest_through, &topics)
            .map_err(BoundedSelectedCtfV2OwnerWindowError::Verification)?;
        if budget.remaining_requests() < 2 {
            return Err(BoundedSelectedCtfV2OwnerWindowError::RequestBudgetExceeded);
        }

        let deadline_at = tokio::time::Instant::now()
            .checked_add(total_timeout)
            .ok_or(BoundedSelectedCtfV2OwnerWindowError::Verification(
                ChainLogAuditError::InvalidInput,
            ))?;
        let requests_before = budget.reserved_requests();
        let mut scoped = self.with_request_budget(budget.inner());
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let operation = async {
            observe_window_inner(
                &mut scoped,
                from_block,
                widest_through,
                cohort,
                partitions,
                budget,
                max_total_response_bytes,
            )
            .await
        };
        tokio::pin!(operation);
        let result = tokio::select! {
            biased;
            _ = exhaustion.wait_for(|is_exhausted| *is_exhausted) => {
                return Err(BoundedSelectedCtfV2OwnerWindowError::RequestBudgetExceeded);
            }
            () = tokio::time::sleep_until(deadline_at) => {
                return if budget.is_exhausted() {
                    Err(BoundedSelectedCtfV2OwnerWindowError::RequestBudgetExceeded)
                } else {
                    Err(BoundedSelectedCtfV2OwnerWindowError::Timeout)
                };
            }
            result = &mut operation => {
                if budget.is_exhausted() {
                    return Err(BoundedSelectedCtfV2OwnerWindowError::RequestBudgetExceeded);
                }
                match result {
                    Ok(result) => result,
                    Err(WindowError::RequestBudgetExceeded) => {
                        return Err(BoundedSelectedCtfV2OwnerWindowError::RequestBudgetExceeded);
                    }
                    Err(WindowError::FinalizedFork) => {
                        return Err(BoundedSelectedCtfV2OwnerWindowError::FinalizedFork);
                    }
                    Err(WindowError::Verification(error)) => {
                        return Err(BoundedSelectedCtfV2OwnerWindowError::Verification(error));
                    }
                }
            }
        };
        if tokio::time::Instant::now() >= deadline_at {
            return Err(BoundedSelectedCtfV2OwnerWindowError::Timeout);
        }
        let actual_requests = budget.reserved_requests().saturating_sub(requests_before);
        match result.window {
            SelectedCtfV2OwnerWatchWindow::Waiting(mut waiting) => {
                waiting.request_count = actual_requests;
                waiting.response_bytes = result.response_bytes;
                Ok(SelectedCtfV2OwnerWatchWindow::Waiting(waiting))
            }
            SelectedCtfV2OwnerWatchWindow::SourceAttested(mut observation) => {
                observation.request_count = actual_requests;
                observation.response_bytes = result.response_bytes;
                Ok(SelectedCtfV2OwnerWatchWindow::SourceAttested(observation))
            }
        }
    }
}

async fn observe_window_inner(
    verifier: &mut ChainLogVerifier,
    from_block: u64,
    widest_through: u64,
    cohort: SelectedCtfV2OwnerWatchWindowCohort,
    partitions: Vec<Vec<String>>,
    budget: &TransactionRequestBudget,
    max_total_response_bytes: usize,
) -> Result<WindowResult, WindowError> {
    let (primary_value, secondary_value, header_bytes) = captured_rpc_pair(
        verifier,
        max_total_response_bytes,
        "eth_getBlockByNumber",
        json!(["finalized", false]),
    )
    .await?;
    let primary_finalized = finalized_head(&primary_value)?;
    let secondary_finalized = finalized_head(&secondary_value)?;
    if primary_finalized.block_number == secondary_finalized.block_number
        && primary_finalized.block_hash != secondary_finalized.block_hash
    {
        return Err(WindowError::FinalizedFork);
    }
    let through_block = primary_finalized
        .block_number
        .min(secondary_finalized.block_number)
        .min(widest_through);
    if through_block < from_block {
        return Ok(WindowResult {
            window: SelectedCtfV2OwnerWatchWindow::Waiting(SelectedCtfV2OwnerWatchWindowWaiting {
                from_block,
                cohort,
                primary_finalized,
                secondary_finalized,
                request_count: 2,
                response_bytes: header_bytes,
            }),
            response_bytes: header_bytes,
        });
    }

    let remaining_requests = budget.remaining_requests();
    let required_log_requests = partitions
        .len()
        .checked_mul(2)
        .ok_or(ChainLogAuditError::InvalidInput)?;
    if remaining_requests < required_log_requests {
        return Err(WindowError::RequestBudgetExceeded);
    }

    let mut response_bytes = header_bytes;
    let mut merged = BTreeMap::new();
    for partition in &partitions {
        let params = watch_filter(from_block, through_block, partition);
        let (primary_value, secondary_value, partition_bytes) = captured_rpc_pair(
            verifier,
            max_total_response_bytes - response_bytes,
            "eth_getLogs",
            params,
        )
        .await?;
        response_bytes = response_bytes
            .checked_add(partition_bytes)
            .ok_or(ChainLogAuditError::Unverified)?;
        let primary = normalize_provider_logs(primary_value, from_block, through_block, partition)?;
        let secondary =
            normalize_provider_logs(secondary_value, from_block, through_block, partition)?;
        if primary != secondary {
            return Err(ChainLogAuditError::Divergent.into());
        }
        for (key, normalized) in primary {
            if merged.insert(key, normalized).is_some() {
                return Err(ChainLogAuditError::Unverified.into());
            }
        }
    }
    let logs = merged
        .into_values()
        .map(|(identity, _canonical)| identity)
        .collect();
    Ok(WindowResult {
        window: SelectedCtfV2OwnerWatchWindow::SourceAttested(
            SourceAttestedSelectedCtfV2OwnerWatchWindow {
                from_block,
                through_block,
                cohort,
                primary_finalized,
                secondary_finalized,
                logs,
                partition_count: partitions.len(),
                request_count: 0,
                response_bytes,
            },
        ),
        response_bytes,
    })
}

async fn captured_rpc_pair(
    verifier: &mut ChainLogVerifier,
    remaining_bytes: usize,
    method: &str,
    params: Value,
) -> Result<(Value, Value, usize), ChainLogAuditError> {
    if remaining_bytes == 0 {
        return Err(ChainLogAuditError::Unverified);
    }
    let capture = Arc::new(Mutex::new(RpcCaptureState {
        max_response_bytes: remaining_bytes,
        response_bytes: 0,
        pages: Vec::new(),
    }));
    verifier.rpc_execution = RpcExecution::Capture(Arc::clone(&capture));
    let (primary, secondary) = tokio::try_join!(
        verifier.rpc(&verifier.primary, method, params.clone()),
        verifier.rpc(&verifier.secondary, method, params),
    )?;
    let bytes = capture.lock().await.response_bytes;
    Ok((primary, secondary, bytes))
}

fn finalized_head(
    value: &Value,
) -> Result<SelectedCtfV2OwnerWatchFinalizedHead, ChainLogAuditError> {
    let header = bind_header(value)?;
    Ok(SelectedCtfV2OwnerWatchFinalizedHead {
        block_number: header.number,
        block_hash: header.hash,
        parent_hash: header.parent_hash,
    })
}

fn canonical_cohort(
    selected_makers: &[String],
) -> Result<SelectedCtfV2OwnerWatchWindowCohort, ChainLogAuditError> {
    if selected_makers.is_empty() || selected_makers.len() > MAX_SELECTED_MAKERS {
        return Err(ChainLogAuditError::InvalidInput);
    }
    let mut canonical = BTreeSet::new();
    for maker in selected_makers {
        let address = Address::from_str(maker).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let normalized = format!("0x{}", hex::encode(address.as_slice()));
        if maker != &normalized || !canonical.insert(normalized) {
            return Err(ChainLogAuditError::InvalidInput);
        }
    }
    let selected_makers = canonical.into_iter().collect::<Vec<_>>();
    let bytes =
        serde_json::to_vec(&selected_makers).map_err(|_| ChainLogAuditError::InvalidInput)?;
    let sha256 = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
    Ok(SelectedCtfV2OwnerWatchWindowCohort {
        selected_makers,
        sha256,
    })
}

fn cohort_topics(selected_makers: &[String]) -> Result<Vec<String>, ChainLogAuditError> {
    selected_makers
        .iter()
        .map(|maker| {
            let address = Address::from_str(maker).map_err(|_| ChainLogAuditError::InvalidInput)?;
            Ok(format!(
                "0x{}{}",
                "00".repeat(12),
                hex::encode(address.as_slice())
            ))
        })
        .collect()
}

fn partition_topics(
    from_block: u64,
    widest_through: u64,
    topics: &[String],
) -> Result<Vec<Vec<String>>, ChainLogAuditError> {
    let mut partitions = Vec::new();
    let mut current = Vec::new();
    for topic in topics {
        current.push(topic.clone());
        if serialized_request_len(from_block, widest_through, &current)?
            <= MAX_RECORDED_RECEIPT_REQUEST_BYTES
        {
            continue;
        }
        let last = current.pop().ok_or(ChainLogAuditError::InvalidInput)?;
        if current.is_empty() {
            return Err(ChainLogAuditError::InvalidInput);
        }
        partitions.push(std::mem::take(&mut current));
        current.push(last);
        if serialized_request_len(from_block, widest_through, &current)?
            > MAX_RECORDED_RECEIPT_REQUEST_BYTES
        {
            return Err(ChainLogAuditError::InvalidInput);
        }
    }
    if !current.is_empty() {
        partitions.push(current);
    }
    Ok(partitions)
}

fn serialized_request_len(
    from_block: u64,
    through_block: u64,
    topics: &[String],
) -> Result<usize, ChainLogAuditError> {
    serde_json::to_vec(&json!({
        "jsonrpc":"2.0",
        "id":1,
        "method":"eth_getLogs",
        "params":watch_filter(from_block, through_block, topics),
    }))
    .map(|body| body.len())
    .map_err(|_| ChainLogAuditError::InvalidInput)
}

fn watch_filter(from_block: u64, through_block: u64, topics: &[String]) -> Value {
    json!([{
        "fromBlock": format!("{from_block:#x}"),
        "toBlock": format!("{through_block:#x}"),
        "address": [
            super::EXCHANGES[2].to_ascii_lowercase(),
            super::EXCHANGES[3].to_ascii_lowercase(),
        ],
        "topics": [V2_ORDER_FILLED, Value::Null, topics],
    }])
}
