//! Bounded selected-maker CTF V2 log watch.
//!
//! Agreement is only source-attested provider output. It is not receipt-root
//! verification, a finality proof, or evidence that a quiet range is complete.

use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use alloy_primitives::Address;
use serde::Deserialize;
use serde_json::{Value, json};
use thiserror::Error;
use tokio::sync::Mutex;

use super::{
    ChainLogAuditError, ChainLogVerifier, MAX_BLOCKS, MAX_RECORDED_RECEIPT_REQUEST_BYTES,
    MAX_RECORDED_RECEIPT_RESPONSE_BYTES, MAX_RECORDED_RECEIPT_TIMEOUT, RpcCaptureState,
    RpcExecution, TransactionRequestBudget, V2_ORDER_FILLED, decode_maker_fill, validate_hex,
    validate_hex_data,
};

pub const SELECTED_CTF_V2_OWNER_WATCH_POLICY_VERSION: &str =
    "ctf-v2-selected-maker-two-provider-source-attested-watch/1";

/// A candidate owner log reported by both configured providers.
///
/// These fields identify provider-reported logs only. They do not establish
/// inclusion in a verified receipt root or prove that the queried range is
/// complete.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SelectedCtfV2OwnerLogIdentity {
    block_number: u64,
    block_hash: String,
    transaction_hash: String,
    log_index: u64,
    exchange: String,
    maker: String,
    order_hash: String,
}

impl SelectedCtfV2OwnerLogIdentity {
    #[must_use]
    pub const fn block_number(&self) -> u64 {
        self.block_number
    }

    #[must_use]
    pub fn block_hash(&self) -> &str {
        &self.block_hash
    }

    #[must_use]
    pub fn transaction_hash(&self) -> &str {
        &self.transaction_hash
    }

    #[must_use]
    pub const fn log_index(&self) -> u64 {
        self.log_index
    }

    #[must_use]
    pub fn exchange(&self) -> &str {
        &self.exchange
    }

    #[must_use]
    pub fn maker(&self) -> &str {
        &self.maker
    }

    #[must_use]
    pub fn order_hash(&self) -> &str {
        &self.order_hash
    }
}

/// Equal, fully normalized selected-maker logs returned by both RPC providers.
/// An empty list means both providers returned no matching logs; it does not
/// prove absence, finality, receipt completeness, or all-chain coverage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceAttestedSelectedCtfV2OwnerWatchObservation {
    from_block: u64,
    through_block: u64,
    logs: Vec<SelectedCtfV2OwnerLogIdentity>,
    request_count: usize,
    response_bytes: usize,
}

impl SourceAttestedSelectedCtfV2OwnerWatchObservation {
    #[must_use]
    pub const fn from_block(&self) -> u64 {
        self.from_block
    }

    #[must_use]
    pub const fn through_block(&self) -> u64 {
        self.through_block
    }

    #[must_use]
    pub fn logs(&self) -> &[SelectedCtfV2OwnerLogIdentity] {
        &self.logs
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
        SELECTED_CTF_V2_OWNER_WATCH_POLICY_VERSION
    }
}

/// Caller bounds or provider responses could not be verified.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedSelectedCtfV2OwnerWatchError {
    #[error("selected owner watch RPC request budget exhausted")]
    RequestBudgetExceeded,
    #[error("selected owner watch exceeded its total deadline")]
    Timeout,
    #[error(transparent)]
    Verification(ChainLogAuditError),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SelectedOwnerRpcLog {
    address: String,
    block_number: String,
    block_hash: String,
    transaction_hash: String,
    log_index: String,
    topics: Vec<String>,
    data: String,
    removed: bool,
}

type NormalizedOwnerLogs =
    BTreeMap<(u64, u64), (SelectedCtfV2OwnerLogIdentity, super::CanonicalLog)>;

impl ChainLogVerifier {
    /// Compare selected CTF V2 maker logs from both providers over an explicit
    /// bounded range. The caller is responsible for choosing a range believed
    /// finalized. This method does not query block headers or establish
    /// finality; only the existing rooted capture can verify a candidate.
    pub async fn observe_selected_ctf_v2_owner_logs_bounded(
        &self,
        from_block: u64,
        through_block: u64,
        selected_makers: &[String],
        budget: &TransactionRequestBudget,
        max_total_response_bytes: usize,
        total_timeout: Duration,
    ) -> Result<SourceAttestedSelectedCtfV2OwnerWatchObservation, BoundedSelectedCtfV2OwnerWatchError>
    {
        if from_block == 0
            || from_block > through_block
            || through_block - from_block >= MAX_BLOCKS
            || max_total_response_bytes == 0
            || max_total_response_bytes > MAX_RECORDED_RECEIPT_RESPONSE_BYTES
            || total_timeout.is_zero()
            || total_timeout > MAX_RECORDED_RECEIPT_TIMEOUT
        {
            return Err(BoundedSelectedCtfV2OwnerWatchError::Verification(
                ChainLogAuditError::InvalidInput,
            ));
        }
        let maker_topics = selected_maker_topics(selected_makers)
            .map_err(BoundedSelectedCtfV2OwnerWatchError::Verification)?;
        let params = json!([{
            "fromBlock": format!("{from_block:#x}"),
            "toBlock": format!("{through_block:#x}"),
            "address": [
                super::EXCHANGES[2].to_ascii_lowercase(),
                super::EXCHANGES[3].to_ascii_lowercase(),
            ],
            "topics": [V2_ORDER_FILLED, Value::Null, maker_topics],
        }]);
        let request_body =
            json!({"jsonrpc":"2.0", "id":1, "method":"eth_getLogs", "params":params});
        if serde_json::to_vec(&request_body)
            .map_err(|_| {
                BoundedSelectedCtfV2OwnerWatchError::Verification(ChainLogAuditError::InvalidInput)
            })?
            .len()
            > MAX_RECORDED_RECEIPT_REQUEST_BYTES
        {
            return Err(BoundedSelectedCtfV2OwnerWatchError::Verification(
                ChainLogAuditError::InvalidInput,
            ));
        }

        let deadline_at = tokio::time::Instant::now()
            .checked_add(total_timeout)
            .ok_or(BoundedSelectedCtfV2OwnerWatchError::Verification(
                ChainLogAuditError::InvalidInput,
            ))?;
        let capture = Arc::new(Mutex::new(RpcCaptureState {
            max_response_bytes: max_total_response_bytes,
            response_bytes: 0,
            pages: Vec::new(),
        }));
        let mut scoped = self.with_request_budget(budget.inner());
        scoped.rpc_execution = RpcExecution::Capture(Arc::clone(&capture));
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let query = async {
            let (primary_response, secondary_response) = tokio::try_join!(
                scoped.rpc(&scoped.primary, "eth_getLogs", params.clone()),
                scoped.rpc(&scoped.secondary, "eth_getLogs", params),
            )?;
            let primary = normalize_provider_logs(
                primary_response,
                from_block,
                through_block,
                &maker_topics,
            )?;
            let secondary = normalize_provider_logs(
                secondary_response,
                from_block,
                through_block,
                &maker_topics,
            )?;
            if primary != secondary {
                return Err(ChainLogAuditError::Divergent);
            }
            Ok(primary
                .into_values()
                .map(|(identity, _canonical)| identity)
                .collect::<Vec<_>>())
        };
        tokio::pin!(query);
        let logs = tokio::select! {
            biased;
            _ = exhaustion.wait_for(|is_exhausted| *is_exhausted) => {
                return Err(BoundedSelectedCtfV2OwnerWatchError::RequestBudgetExceeded);
            }
            () = tokio::time::sleep_until(deadline_at) => {
                return if budget.is_exhausted() {
                    Err(BoundedSelectedCtfV2OwnerWatchError::RequestBudgetExceeded)
                } else {
                    Err(BoundedSelectedCtfV2OwnerWatchError::Timeout)
                };
            }
            result = &mut query => {
                if budget.is_exhausted() {
                    return Err(BoundedSelectedCtfV2OwnerWatchError::RequestBudgetExceeded);
                }
                result.map_err(BoundedSelectedCtfV2OwnerWatchError::Verification)?
            }
        };
        let response_bytes = capture.lock().await.response_bytes;
        if tokio::time::Instant::now() >= deadline_at {
            return Err(BoundedSelectedCtfV2OwnerWatchError::Timeout);
        }
        Ok(SourceAttestedSelectedCtfV2OwnerWatchObservation {
            from_block,
            through_block,
            logs,
            request_count: 2,
            response_bytes,
        })
    }
}

fn selected_maker_topics(selected_makers: &[String]) -> Result<Vec<String>, ChainLogAuditError> {
    if selected_makers.is_empty() || selected_makers.len() > MAX_RECORDED_RECEIPT_REQUEST_BYTES / 68
    {
        return Err(ChainLogAuditError::InvalidInput);
    }
    let mut topics = BTreeSet::new();
    for maker in selected_makers {
        let address = Address::from_str(maker).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let canonical = format!("0x{}", hex::encode(address.as_slice()));
        if maker != &canonical
            || !topics.insert(format!("0x{}{}", "00".repeat(12), &canonical[2..]))
        {
            return Err(ChainLogAuditError::InvalidInput);
        }
    }
    Ok(topics.into_iter().collect())
}

fn normalize_provider_logs(
    value: Value,
    from_block: u64,
    through_block: u64,
    selected_maker_topics: &[String],
) -> Result<NormalizedOwnerLogs, ChainLogAuditError> {
    let raw: Vec<SelectedOwnerRpcLog> =
        serde_json::from_value(value).map_err(|_| ChainLogAuditError::Unverified)?;
    let mut logs = BTreeMap::new();
    for row in raw {
        let block_number = super::parse_hex_u64(&row.block_number)?;
        let log_index = super::parse_hex_u64(&row.log_index)?;
        let address = validate_hex(&row.address, 20)?;
        let block_hash = validate_hex(&row.block_hash, 32)?;
        let transaction_hash = validate_hex(&row.transaction_hash, 32)?;
        let topics: Vec<String> = row
            .topics
            .iter()
            .map(|topic| validate_hex(topic, 32))
            .collect::<Result<_, _>>()?;
        let data = validate_hex_data(&row.data)?;
        if row.removed
            || !(from_block..=through_block).contains(&block_number)
            || !super::EXCHANGES[2..4]
                .iter()
                .any(|exchange| exchange.eq_ignore_ascii_case(&address))
            || topics.first().map(String::as_str) != Some(V2_ORDER_FILLED)
            || topics.len() != 4
            || !topics
                .get(2)
                .is_some_and(|topic| selected_maker_topics.contains(topic))
        {
            return Err(ChainLogAuditError::Unverified);
        }
        let canonical = super::CanonicalLog {
            address: address.clone(),
            block_number,
            block_hash: block_hash.clone(),
            transaction_hash: transaction_hash.clone(),
            log_index,
            topics: topics.clone(),
            data,
        };
        let fill = decode_maker_fill(&canonical)?;
        if fill.decoder_version != super::CtfDecoderVersion::V2 {
            return Err(ChainLogAuditError::Unverified);
        }
        let order_hash = topics
            .get(1)
            .cloned()
            .ok_or(ChainLogAuditError::Unverified)?;
        let identity = SelectedCtfV2OwnerLogIdentity {
            block_number,
            block_hash,
            transaction_hash,
            log_index,
            exchange: address,
            maker: fill.wallet,
            order_hash,
        };
        if logs
            .insert((block_number, log_index), (identity, canonical))
            .is_some()
        {
            return Err(ChainLogAuditError::Unverified);
        }
    }
    Ok(logs)
}
