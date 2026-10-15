//! Bounded provider-reported transactions and receipts for selected current movement logs.
//!
//! This reader reuses the position-history RPC transport and current interval census. It records
//! raw provider responses only; it does not authenticate transactions/receipts or classify flows.

use std::{collections::BTreeMap, time::Duration};

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tokio::time::Instant;

use super::current_interval_census::{
    RpcCurrentIntervalAsset, RpcCurrentIntervalCensus, RpcCurrentIntervalLog,
    RpcCurrentIntervalSource,
};
use super::{
    MAX_HISTORY_REQUESTS, MAX_HISTORY_TOTAL_BYTES, ReadState, RecordedRpcPositionHistoryPage,
    RpcPositionHistoryError, RpcPositionHistoryPage, RpcPositionHistoryReader,
    RpcPositionHistoryRequest, RpcPositionHistoryRequestPhase, normalize_hash, parse_quantity,
    request_byte_limit,
};
use crate::position_history::{
    PositionHistoryDirection, PositionLedger, normalize_address, normalize_log,
};

const MAX_CURRENT_TRANSACTIONS: usize = 32;
const MAX_CURRENT_TRANSACTION_REQUESTS: usize = 64;
const MAX_CURRENT_TRANSACTION_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CURRENT_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_CENSUS_LOGS: usize = 20_000;
const MAX_CENSUS_EVENT_BLOCKS: usize = 384;
const MAX_CENSUS_BLOCK_SPAN: u64 = 2_048;
const ERC20_TRANSFER_TOPIC: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

pub(super) enum CurrentIntervalRpcCallSource<'a> {
    Network(&'a RpcPositionHistoryReader),
    Recorded {
        pages: &'a [RecordedRpcPositionHistoryPage],
        next_page: usize,
    },
}

impl CurrentIntervalRpcCallSource<'_> {
    pub(super) async fn call(
        &mut self,
        method: &str,
        params: Value,
        deadline: Instant,
        request: &RpcPositionHistoryRequest,
        state: &mut ReadState,
    ) -> Result<Value, RpcPositionHistoryError> {
        // This existing phase is used only for the shared 4 KiB JSON-RPC request cap here.
        // Transaction/receipt calls do not have anchor/finality semantics.
        let phase = RpcPositionHistoryRequestPhase::CurrentIntervalEndBefore;
        match self {
            Self::Network(reader) => {
                reader
                    .call_network(
                        method,
                        params,
                        request_byte_limit(phase),
                        deadline,
                        request,
                        state,
                    )
                    .await
            }
            Self::Recorded { pages, next_page } => super::recorded_call(
                pages,
                next_page,
                (method, params),
                phase,
                deadline,
                request,
                state,
            ),
        }
    }

    pub(super) fn validate_count(
        &self,
        planned_calls: usize,
    ) -> Result<(), RpcPositionHistoryError> {
        if let Self::Recorded { pages, .. } = self {
            if pages.len() > MAX_HISTORY_REQUESTS {
                return Err(RpcPositionHistoryError::RequestBudgetExceeded);
            }
            if pages.len() != planned_calls {
                return Err(RpcPositionHistoryError::MalformedResponse);
            }
        }
        Ok(())
    }

    pub(super) fn finish(&self) -> Result<(), RpcPositionHistoryError> {
        match self {
            Self::Network(_) => Ok(()),
            Self::Recorded { pages, next_page } if *next_page == pages.len() => Ok(()),
            Self::Recorded { .. } => Err(RpcPositionHistoryError::MalformedResponse),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcCurrentIntervalTransactionsRequest {
    /// Canonical lower-case transaction hashes, each present in `census.logs`.
    pub transaction_hashes: Vec<String>,
    pub max_requests: usize,
    pub max_total_response_bytes: usize,
    pub total_timeout: Duration,
}

/// Caller-preserved wall-clock bounds for an offline transcript replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcCurrentIntervalTransactionsCaptureWindow {
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcCurrentIntervalTransactionsSource {
    ProviderReported,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcCurrentIntervalTransaction {
    pub transaction_hash: String,
    pub block_number: u64,
    pub block_hash: String,
    pub transaction_index: u64,
    /// Original `eth_getTransactionByHash` result value.
    pub transaction: Value,
    /// Original `eth_getTransactionReceipt` result value.
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcCurrentIntervalTransactions {
    pub wallets: Vec<String>,
    pub start_block: u64,
    pub start_hash: String,
    pub through_block: u64,
    pub through_hash: String,
    pub transactions: Vec<RpcCurrentIntervalTransaction>,
    pub source: RpcCurrentIntervalTransactionsSource,
    /// Network capture times, or caller-preserved times for recorded replay.
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub elapsed: Duration,
    pub request_count: usize,
    pub response_bytes: usize,
    /// Ordered raw JSON-RPC request/response evidence; endpoint is omitted.
    pub requests: Vec<RpcPositionHistoryPage>,
}

impl RpcPositionHistoryReader {
    /// Capture each selected transaction and receipt after a current movement census.
    ///
    /// Exactly two sequential calls are made per distinct transaction hash. The raw receipt must
    /// bind to the census block locator and contain every selected movement log exactly once.
    /// These provider responses do not establish signature validity, receipt inclusion, successful
    /// settlement, or activity completeness.
    pub async fn read_current_interval_transactions(
        &self,
        census: &RpcCurrentIntervalCensus,
        request: &RpcCurrentIntervalTransactionsRequest,
    ) -> Result<RpcCurrentIntervalTransactions, RpcPositionHistoryError> {
        let timer = Instant::now();
        let started_at = Utc::now();
        let mut source = CurrentIntervalRpcCallSource::Network(self);
        read_current_transactions_inner(census, request, &mut source, None, timer, started_at).await
    }
}

/// Revalidates raw transaction/receipt frames captured by `read_current_interval_transactions`.
/// The supplied time window remains caller-reported and is not authenticated by the transcript.
pub async fn reverify_recorded_current_interval_transactions(
    census: &RpcCurrentIntervalCensus,
    request: &RpcCurrentIntervalTransactionsRequest,
    capture_window: RpcCurrentIntervalTransactionsCaptureWindow,
    pages: &[RecordedRpcPositionHistoryPage],
) -> Result<RpcCurrentIntervalTransactions, RpcPositionHistoryError> {
    let timer = Instant::now();
    let mut source = CurrentIntervalRpcCallSource::Recorded {
        pages,
        next_page: 0,
    };
    read_current_transactions_inner(
        census,
        request,
        &mut source,
        Some(capture_window),
        timer,
        Utc::now(),
    )
    .await
}

async fn read_current_transactions_inner(
    census: &RpcCurrentIntervalCensus,
    request: &RpcCurrentIntervalTransactionsRequest,
    source: &mut CurrentIntervalRpcCallSource<'_>,
    replay_window: Option<RpcCurrentIntervalTransactionsCaptureWindow>,
    timer: Instant,
    network_started_at: DateTime<Utc>,
) -> Result<RpcCurrentIntervalTransactions, RpcPositionHistoryError> {
    let groups = validate_inputs(census, request)?;
    let planned_calls = groups
        .len()
        .checked_mul(2)
        .ok_or(RpcPositionHistoryError::InvalidInput)?;
    if planned_calls > request.max_requests || planned_calls > MAX_CURRENT_TRANSACTION_REQUESTS {
        return Err(RpcPositionHistoryError::RequestBudgetExceeded);
    }
    source.validate_count(planned_calls)?;

    if let Some(window) = replay_window {
        let duration = window
            .completed_at
            .signed_duration_since(window.started_at)
            .to_std()
            .map_err(|_| RpcPositionHistoryError::InvalidInput)?;
        if duration > MAX_CURRENT_TRANSACTION_TIMEOUT || duration > request.total_timeout {
            return Err(RpcPositionHistoryError::InvalidInput);
        }
    }

    let transport = RpcPositionHistoryRequest {
        holder_address: census.wallets[0].clone(),
        from_block: census.start_block,
        through_block: census.through_block,
        expected_through_hash: census.end_header.hash.clone(),
        max_requests: request.max_requests,
        max_total_response_bytes: request.max_total_response_bytes,
        total_timeout: request.total_timeout,
    };
    let deadline = timer
        .checked_add(request.total_timeout)
        .ok_or(RpcPositionHistoryError::InvalidInput)?;
    let mut state = ReadState {
        pages: Vec::with_capacity(planned_calls),
        response_bytes: 0,
        next_id: 1,
    };
    let mut transactions = Vec::with_capacity(groups.len());
    for (hash, anchor) in groups {
        let transaction = source
            .call(
                "eth_getTransactionByHash",
                json!([hash]),
                deadline,
                &transport,
                &mut state,
            )
            .await?;
        validate_transaction(&transaction, &hash, &anchor)?;
        let receipt = source
            .call(
                "eth_getTransactionReceipt",
                json!([hash]),
                deadline,
                &transport,
                &mut state,
            )
            .await?;
        validate_receipt(&receipt, &hash, &anchor, census)?;
        transactions.push(RpcCurrentIntervalTransaction {
            transaction_hash: hash,
            block_number: anchor.block_number,
            block_hash: anchor.block_hash,
            transaction_index: anchor.transaction_index,
            transaction,
            receipt,
        });
    }
    if state.next_id.saturating_sub(1) as usize != planned_calls
        || state.response_bytes > request.max_total_response_bytes
        || tokio::time::Instant::now() >= deadline
    {
        return Err(if tokio::time::Instant::now() >= deadline {
            RpcPositionHistoryError::Timeout
        } else {
            RpcPositionHistoryError::MalformedResponse
        });
    }
    source.finish()?;
    let (started_at, completed_at, elapsed) = match replay_window {
        Some(window) => (
            window.started_at,
            window.completed_at,
            window
                .completed_at
                .signed_duration_since(window.started_at)
                .to_std()
                .map_err(|_| RpcPositionHistoryError::InvalidInput)?,
        ),
        None => (network_started_at, Utc::now(), timer.elapsed()),
    };
    Ok(RpcCurrentIntervalTransactions {
        wallets: census.wallets.clone(),
        start_block: census.start_block,
        start_hash: census.start_header.hash.clone(),
        through_block: census.through_block,
        through_hash: census.end_header.hash.clone(),
        transactions,
        source: RpcCurrentIntervalTransactionsSource::ProviderReported,
        started_at,
        completed_at,
        elapsed,
        request_count: state.next_id.saturating_sub(1) as usize,
        response_bytes: state.response_bytes,
        requests: state.pages,
    })
}

#[derive(Clone)]
struct TransactionAnchor {
    block_number: u64,
    block_hash: String,
    transaction_index: u64,
    logs: Vec<RpcCurrentIntervalLog>,
}

fn validate_inputs(
    census: &RpcCurrentIntervalCensus,
    request: &RpcCurrentIntervalTransactionsRequest,
) -> Result<Vec<(String, TransactionAnchor)>, RpcPositionHistoryError> {
    if census.source != RpcCurrentIntervalSource::ProviderReported
        || census.logs.len() > MAX_CENSUS_LOGS
        || census.event_headers.len() > MAX_CENSUS_EVENT_BLOCKS
        || census.wallets.is_empty()
        || census.wallets.len() > 100
        || census.start_header.number != census.start_block
        || census.end_header.number != census.through_block
        || census.start_block >= census.through_block
        || census
            .through_block
            .checked_sub(census.start_block)
            .is_none_or(|span| span > MAX_CENSUS_BLOCK_SPAN)
        || normalize_hash(&census.start_header.hash).as_deref()
            != Some(census.start_header.hash.as_str())
        || normalize_hash(&census.end_header.hash).as_deref()
            != Some(census.end_header.hash.as_str())
        || census.start_header.timestamp > census.end_header.timestamp
        || request.transaction_hashes.is_empty()
        || request.transaction_hashes.len() > MAX_CURRENT_TRANSACTIONS
        || request.max_requests == 0
        || request.max_requests > MAX_CURRENT_TRANSACTION_REQUESTS
        || request.max_total_response_bytes == 0
        || request.max_total_response_bytes > MAX_CURRENT_TRANSACTION_RESPONSE_BYTES
        || request.max_total_response_bytes > MAX_HISTORY_TOTAL_BYTES
        || request.total_timeout.is_zero()
        || request.total_timeout > MAX_CURRENT_TRANSACTION_TIMEOUT
    {
        return Err(RpcPositionHistoryError::InvalidInput);
    }
    let mut wallets = census.wallets.clone();
    wallets.sort();
    if wallets.windows(2).any(|pair| pair[0] == pair[1])
        || wallets != census.wallets
        || census.wallets.iter().any(|wallet| {
            normalize_address(wallet).as_deref() != Some(wallet.as_str())
                || wallet == &format!("0x{}", "00".repeat(20))
        })
    {
        return Err(RpcPositionHistoryError::InvalidInput);
    }
    if census.event_headers.iter().any(|header| {
        normalize_hash(&header.hash).as_deref() != Some(header.hash.as_str())
            || header.number < census.start_block
            || header.number > census.through_block
    }) || census
        .event_headers
        .windows(2)
        .any(|pair| pair[0].number >= pair[1].number)
    {
        return Err(RpcPositionHistoryError::MalformedResponse);
    }

    let mut requested = Vec::with_capacity(request.transaction_hashes.len());
    let mut seen = std::collections::BTreeSet::new();
    for hash in &request.transaction_hashes {
        if normalize_hash(hash).as_deref() != Some(hash.as_str()) || !seen.insert(hash.clone()) {
            return Err(RpcPositionHistoryError::InvalidInput);
        }
        requested.push(hash.clone());
    }

    let mut groups = BTreeMap::<String, TransactionAnchor>::new();
    let mut global_indices = BTreeMap::<(String, u64), String>::new();
    for log in &census.logs {
        if log.block_number <= census.start_block || log.block_number > census.through_block {
            return Err(RpcPositionHistoryError::MalformedResponse);
        }
        if normalize_hash(&log.transaction_hash).as_deref() != Some(log.transaction_hash.as_str())
            || log.locator != format!("137:{}:{}", log.transaction_hash, log.log_index)
            || normalize_address(&log.from).as_deref() != Some(log.from.as_str())
            || normalize_address(&log.to).as_deref() != Some(log.to.as_str())
            || (!census.wallets.contains(&log.from) && !census.wallets.contains(&log.to))
        {
            return Err(RpcPositionHistoryError::MalformedResponse);
        }
        let Some(header) = census
            .event_headers
            .iter()
            .find(|header| header.number == log.block_number)
        else {
            return Err(RpcPositionHistoryError::MalformedResponse);
        };
        if header.hash != log.block_hash
            || header.timestamp < census.start_header.timestamp
            || header.timestamp > census.end_header.timestamp
        {
            return Err(RpcPositionHistoryError::ConflictingHeader);
        }
        if !requested.contains(&log.transaction_hash) {
            continue;
        }
        if global_indices
            .insert(
                (log.block_hash.clone(), log.log_index),
                log.transaction_hash.clone(),
            )
            .is_some_and(|previous| previous != log.transaction_hash)
        {
            return Err(RpcPositionHistoryError::ConflictingLocator);
        }
        let anchor = groups
            .entry(log.transaction_hash.clone())
            .or_insert_with(|| TransactionAnchor {
                block_number: log.block_number,
                block_hash: log.block_hash.clone(),
                transaction_index: log.transaction_index,
                logs: Vec::new(),
            });
        if anchor.block_number != log.block_number
            || anchor.block_hash != log.block_hash
            || anchor.transaction_index != log.transaction_index
            || anchor
                .logs
                .iter()
                .any(|previous| previous.log_index == log.log_index)
        {
            return Err(RpcPositionHistoryError::ConflictingLocator);
        }
        anchor.logs.push(log.clone());
    }
    if requested.iter().any(|hash| !groups.contains_key(hash)) {
        return Err(RpcPositionHistoryError::InvalidInput);
    }
    for anchor in groups.values_mut() {
        anchor.logs.sort_by_key(|log| log.log_index);
    }
    requested
        .into_iter()
        .map(|hash| {
            let anchor = groups
                .remove(&hash)
                .ok_or(RpcPositionHistoryError::InvalidInput)?;
            Ok((hash, anchor))
        })
        .collect()
}

fn validate_transaction(
    transaction: &Value,
    requested_hash: &str,
    anchor: &TransactionAnchor,
) -> Result<(), RpcPositionHistoryError> {
    if transaction.is_null()
        || normalized_field(transaction, "hash")? != requested_hash
        || quantity_field(transaction, "blockNumber")? != anchor.block_number
        || normalized_field(transaction, "blockHash")? != anchor.block_hash
        || quantity_field(transaction, "transactionIndex")? != anchor.transaction_index
    {
        return Err(RpcPositionHistoryError::ConflictingLocator);
    }
    Ok(())
}

fn validate_receipt(
    receipt: &Value,
    requested_hash: &str,
    anchor: &TransactionAnchor,
    census: &RpcCurrentIntervalCensus,
) -> Result<(), RpcPositionHistoryError> {
    if receipt.is_null()
        || normalized_field(receipt, "transactionHash")? != requested_hash
        || quantity_field(receipt, "blockNumber")? != anchor.block_number
        || normalized_field(receipt, "blockHash")? != anchor.block_hash
        || quantity_field(receipt, "transactionIndex")? != anchor.transaction_index
    {
        return Err(RpcPositionHistoryError::ConflictingLocator);
    }
    let entries = receipt
        .get("logs")
        .and_then(Value::as_array)
        .ok_or(RpcPositionHistoryError::MalformedResponse)?;
    let mut by_index = BTreeMap::<u64, &Value>::new();
    let mut previous_index = None;
    for entry in entries {
        if entry.get("removed").and_then(Value::as_bool) != Some(false)
            || quantity_field(entry, "blockNumber")? != anchor.block_number
            || normalized_field(entry, "blockHash")? != anchor.block_hash
            || normalized_field(entry, "transactionHash")? != requested_hash
            || quantity_field(entry, "transactionIndex")? != anchor.transaction_index
        {
            return Err(RpcPositionHistoryError::ConflictingLocator);
        }
        let index = quantity_field(entry, "logIndex")?;
        if previous_index.is_some_and(|previous| index <= previous)
            || normalize_address(entry.get("address").and_then(Value::as_str).unwrap_or(""))
                .is_none()
            || !valid_topics_and_data(entry)
            || by_index.insert(index, entry).is_some()
        {
            return Err(RpcPositionHistoryError::MalformedResponse);
        }
        previous_index = Some(index);
    }
    for movement in &anchor.logs {
        let raw = by_index
            .get(&movement.log_index)
            .ok_or(RpcPositionHistoryError::ConflictingLocator)?;
        validate_movement_receipt_match(raw, movement, census)?;
    }
    Ok(())
}

fn validate_movement_receipt_match(
    raw: &Value,
    movement: &RpcCurrentIntervalLog,
    census: &RpcCurrentIntervalCensus,
) -> Result<(), RpcPositionHistoryError> {
    let fail = || RpcPositionHistoryError::ConflictingLocator;
    let emitter = raw
        .get("address")
        .and_then(Value::as_str)
        .and_then(normalize_address)
        .ok_or_else(fail)?;
    let raw_topics = normalized_topics(raw)?;
    let raw_data = normalized_data(raw)?;
    if raw.get("logIndex").and_then(parse_quantity) != Some(movement.log_index) {
        return Err(fail());
    }
    match movement.asset {
        RpcCurrentIntervalAsset::Pusd | RpcCurrentIntervalAsset::UsdcE => {
            let expected_emitter = match movement.asset {
                RpcCurrentIntervalAsset::Pusd => crate::collateral_cash::PUSD_ADDRESS,
                RpcCurrentIntervalAsset::UsdcE => crate::collateral_cash::USDCE_ADDRESS,
                _ => unreachable!(),
            };
            let amount = movement.amount_word.as_deref().ok_or_else(fail)?;
            if emitter != expected_emitter
                || raw_topics.len() != 3
                || raw_topics[0] != ERC20_TRANSFER_TOPIC
                || topic_address(&raw_topics[1]).as_deref() != Some(movement.from.as_str())
                || topic_address(&raw_topics[2]).as_deref() != Some(movement.to.as_str())
                || raw_data != amount
            {
                return Err(fail());
            }
        }
        RpcCurrentIntervalAsset::Ctf | RpcCurrentIntervalAsset::PositionManager => {
            let position = movement
                .position_log
                .as_ref()
                .ok_or(RpcPositionHistoryError::MalformedResponse)?;
            let expected_ledger = match movement.asset {
                RpcCurrentIntervalAsset::Ctf => PositionLedger::Ctf,
                RpcCurrentIntervalAsset::PositionManager => PositionLedger::PositionManager,
                _ => unreachable!(),
            };
            if emitter != position.emitter()
                || position.ledger() != expected_ledger
                || raw_topics != position.topics()
                || raw_data != position.data()
            {
                return Err(fail());
            }
            let mut parsed_match = false;
            for wallet in &census.wallets {
                for direction in [PositionHistoryDirection::From, PositionHistoryDirection::To] {
                    if (direction == PositionHistoryDirection::From && movement.from != *wallet)
                        || (direction == PositionHistoryDirection::To && movement.to != *wallet)
                    {
                        continue;
                    }
                    let Ok(parsed) = normalize_log(
                        raw,
                        movement.block_number,
                        &movement.block_hash,
                        wallet,
                        direction,
                    ) else {
                        continue;
                    };
                    if &parsed == position {
                        parsed_match = true;
                    }
                }
            }
            if !parsed_match {
                return Err(fail());
            }
        }
    }
    Ok(())
}

fn quantity_field(value: &Value, name: &str) -> Result<u64, RpcPositionHistoryError> {
    value
        .get(name)
        .and_then(parse_quantity)
        .ok_or(RpcPositionHistoryError::MalformedResponse)
}

fn normalized_field(value: &Value, name: &str) -> Result<String, RpcPositionHistoryError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .and_then(normalize_hash)
        .ok_or(RpcPositionHistoryError::MalformedResponse)
}

fn valid_topics_and_data(value: &Value) -> bool {
    normalized_topics(value).is_ok_and(|topics| !topics.is_empty() && topics.len() <= 4)
        && normalized_data(value).is_ok()
}

fn normalized_topics(value: &Value) -> Result<Vec<String>, RpcPositionHistoryError> {
    value
        .get("topics")
        .and_then(Value::as_array)
        .ok_or(RpcPositionHistoryError::MalformedResponse)?
        .iter()
        .map(|topic| {
            topic
                .as_str()
                .and_then(normalize_hash)
                .ok_or(RpcPositionHistoryError::MalformedResponse)
        })
        .collect()
}

fn normalized_data(value: &Value) -> Result<String, RpcPositionHistoryError> {
    let data = value
        .get("data")
        .and_then(Value::as_str)
        .ok_or(RpcPositionHistoryError::MalformedResponse)?;
    if !data.starts_with("0x")
        || data.len() % 2 != 0
        || !data[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(RpcPositionHistoryError::MalformedResponse);
    }
    Ok(data.to_ascii_lowercase())
}

fn topic_address(topic: &str) -> Option<String> {
    let digits = topic.strip_prefix("0x")?;
    if digits.len() != 64 || !digits[..24].bytes().all(|byte| byte == b'0') {
        return None;
    }
    normalize_address(&format!("0x{}", &digits[24..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, body::Bytes, extract::State, routing::post};
    use chrono::TimeZone;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    const WALLET: &str = "0x1111111111111111111111111111111111111111";
    const OTHER: &str = "0x2222222222222222222222222222222222222222";
    const TX_HASH: &str = "0x3333333333333333333333333333333333333333333333333333333333333333";
    const BLOCK_HASH: &str = "0x4444444444444444444444444444444444444444444444444444444444444444";

    #[derive(Clone)]
    struct MockState {
        requests: Arc<Mutex<Vec<Value>>>,
        transaction: Value,
        receipt: Value,
    }

    async fn mock_rpc(State(state): State<MockState>, body: Bytes) -> Json<Value> {
        let request: Value = serde_json::from_slice(&body).unwrap();
        state.requests.lock().unwrap().push(request.clone());
        let result = match request["method"].as_str().unwrap() {
            "eth_getTransactionByHash" => state.transaction.clone(),
            "eth_getTransactionReceipt" => state.receipt.clone(),
            _ => panic!("unexpected RPC method"),
        };
        Json(json!({"jsonrpc":"2.0", "id":request["id"], "result":result}))
    }

    fn word(value: u64) -> String {
        format!("0x{value:064x}")
    }

    fn topic_address(address: &str) -> String {
        format!("0x{:0>64}", &address[2..])
    }

    fn fixture() -> (
        RpcCurrentIntervalCensus,
        RpcCurrentIntervalTransactionsRequest,
        Value,
        Value,
    ) {
        let transaction = json!({
            "hash":TX_HASH,
            "blockNumber":"0xf",
            "blockHash":BLOCK_HASH,
            "transactionIndex":"0x2",
        });
        let receipt_log = json!({
            "removed":false,
            "address":crate::collateral_cash::PUSD_ADDRESS,
            "topics":[ERC20_TRANSFER_TOPIC, topic_address(WALLET), topic_address(OTHER)],
            "data":word(7),
            "blockNumber":"0xf",
            "blockHash":BLOCK_HASH,
            "transactionHash":TX_HASH,
            "transactionIndex":"0x2",
            "logIndex":"0x4",
        });
        let receipt = json!({
            "transactionHash":TX_HASH,
            "blockNumber":"0xf",
            "blockHash":BLOCK_HASH,
            "transactionIndex":"0x2",
            "status":"0x1",
            "logs":[receipt_log],
        });
        let start_hash = word(10);
        let end_hash = word(20);
        let census = RpcCurrentIntervalCensus {
            wallets: vec![WALLET.to_owned()],
            start_block: 10,
            through_block: 20,
            start_header: super::super::current_interval_census::RpcCurrentIntervalHeader {
                number: 10,
                hash: start_hash,
                timestamp: 100,
            },
            end_header: super::super::current_interval_census::RpcCurrentIntervalHeader {
                number: 20,
                hash: end_hash,
                timestamp: 200,
            },
            event_headers: vec![
                super::super::current_interval_census::RpcCurrentIntervalHeader {
                    number: 15,
                    hash: BLOCK_HASH.to_owned(),
                    timestamp: 150,
                },
            ],
            logs: vec![RpcCurrentIntervalLog {
                locator: format!("137:{TX_HASH}:4"),
                block_hash: BLOCK_HASH.to_owned(),
                transaction_hash: TX_HASH.to_owned(),
                block_number: 15,
                transaction_index: 2,
                log_index: 4,
                asset: RpcCurrentIntervalAsset::Pusd,
                from: WALLET.to_owned(),
                to: OTHER.to_owned(),
                amount_word: Some(word(7)),
                position_log: None,
            }],
            source: RpcCurrentIntervalSource::ProviderReported,
            started_at: Utc.timestamp_opt(100, 0).unwrap(),
            completed_at: Utc.timestamp_opt(200, 0).unwrap(),
            elapsed: Duration::from_secs(100),
            request_count: 5,
            response_bytes: 100,
            requests: Vec::new(),
        };
        let request = RpcCurrentIntervalTransactionsRequest {
            transaction_hashes: vec![TX_HASH.to_owned()],
            max_requests: 2,
            max_total_response_bytes: 1024 * 1024,
            total_timeout: Duration::from_secs(10),
        };
        (census, request, transaction, receipt)
    }

    fn recorded_pages(transaction: &Value, receipt: &Value) -> Vec<RecordedRpcPositionHistoryPage> {
        [
            ("eth_getTransactionByHash", transaction),
            ("eth_getTransactionReceipt", receipt),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, (method, result))| RecordedRpcPositionHistoryPage {
            request_json: json!({
                "jsonrpc":"2.0", "id":index + 1, "method":method, "params":[TX_HASH]
            })
            .to_string(),
            response_json: json!({
                "jsonrpc":"2.0", "id":index + 1, "result":result
            })
            .to_string(),
        })
        .collect()
    }

    #[tokio::test]
    async fn captures_exact_transaction_receipt_pair_and_raw_evidence() {
        let (census, request, transaction, receipt) = fixture();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let state = MockState {
            requests: Arc::clone(&requests),
            transaction: transaction.clone(),
            receipt: receipt.clone(),
        };
        let app = Router::new().route("/", post(mock_rpc)).with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let reader = RpcPositionHistoryReader::new(reqwest::Client::builder(), &endpoint).unwrap();
        let result = reader
            .read_current_interval_transactions(&census, &request)
            .await
            .unwrap();
        let mut insufficient_budget = request.clone();
        insufficient_budget.max_requests = 1;
        assert_eq!(
            reader
                .read_current_interval_transactions(&census, &insufficient_budget)
                .await,
            Err(RpcPositionHistoryError::RequestBudgetExceeded)
        );
        server.abort();

        let seen = requests.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0]["method"], "eth_getTransactionByHash");
        assert_eq!(seen[1]["method"], "eth_getTransactionReceipt");
        assert_eq!(result.request_count, 2);
        assert_eq!(result.transactions[0].transaction, transaction);
        assert_eq!(result.transactions[0].receipt, receipt);
        assert_eq!(result.requests.len(), 2);
        assert!(result.response_bytes > 0);
        assert!(
            result
                .requests
                .iter()
                .all(|page| !page.request_json().contains(&endpoint))
        );
        assert_eq!(
            result.source,
            RpcCurrentIntervalTransactionsSource::ProviderReported
        );
    }

    #[tokio::test]
    async fn recorded_replay_rechecks_movement_binding_and_limits_before_io() {
        let (census, request, transaction, receipt) = fixture();
        let now = Utc::now();
        let window = RpcCurrentIntervalTransactionsCaptureWindow {
            started_at: now,
            completed_at: now + chrono::TimeDelta::seconds(1),
        };
        let pages = recorded_pages(&transaction, &receipt);
        let replay =
            reverify_recorded_current_interval_transactions(&census, &request, window, &pages)
                .await
                .unwrap();
        assert_eq!(replay.requests[1].response_json(), pages[1].response_json);
        assert_eq!(replay.transactions[0].transaction_hash, TX_HASH);

        for invalid_pages in [
            pages[..1].to_vec(),
            vec![pages[0].clone(), pages[1].clone(), pages[1].clone()],
        ] {
            assert_eq!(
                reverify_recorded_current_interval_transactions(
                    &census,
                    &request,
                    window,
                    &invalid_pages,
                )
                .await,
                Err(RpcPositionHistoryError::MalformedResponse)
            );
        }
        let mut reordered_pages = pages.clone();
        reordered_pages.swap(0, 1);
        assert_eq!(
            reverify_recorded_current_interval_transactions(
                &census,
                &request,
                window,
                &reordered_pages,
            )
            .await,
            Err(RpcPositionHistoryError::MalformedResponse)
        );

        let mut changed_receipt = receipt;
        changed_receipt["logs"][0]["data"] = json!(word(8));
        let bad_pages = recorded_pages(&transaction, &changed_receipt);
        assert_eq!(
            reverify_recorded_current_interval_transactions(&census, &request, window, &bad_pages,)
                .await,
            Err(RpcPositionHistoryError::ConflictingLocator)
        );

        let mut duplicate_request = request;
        duplicate_request
            .transaction_hashes
            .push(TX_HASH.to_owned());
        assert!(matches!(
            validate_inputs(&census, &duplicate_request),
            Err(RpcPositionHistoryError::InvalidInput)
        ));
    }
}
