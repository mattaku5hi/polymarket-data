//! Bounded, read-only JSON-RPC observation of raw position-transfer history.
//!
//! This records a provider response and caller anchor comparison. It is not a
//! consensus proof, complete inventory, rooted balance, basis or P&L result.

use std::{collections::BTreeMap, net::IpAddr, time::Duration};

use chrono::{DateTime, Utc};
use reqwest::{Client, ClientBuilder, Url};
use serde_json::{Value, json};

use crate::position_history::{
    CTF_EMITTER, MAX_HISTORY_REQUESTS, MAX_HISTORY_RESPONSE_BYTES, MAX_HISTORY_TOTAL_BYTES,
    POSITION_MANAGER_EMITTER, PositionHistoryDirection, PositionHistoryError, PositionTransferLog,
    TRANSFER_BATCH_TOPIC, TRANSFER_SINGLE_TOPIC, normalize_address, normalize_hash, normalize_log,
};

const RPC_CHAIN_ID: u64 = 137;
const RPC_CALLS: usize = 6;

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
    holder_address: String,
    from_block: u64,
    through_block: u64,
    expected_through_hash: String,
    terminal_header: RpcBlockHeader,
    logs: Vec<PositionTransferLog>,
    pages: Vec<RpcPositionHistoryPage>,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    elapsed: Duration,
    request_count: usize,
    response_bytes: usize,
}

impl RpcPositionHistoryObservation {
    #[must_use]
    pub fn holder_address(&self) -> &str {
        &self.holder_address
    }
    #[must_use]
    pub const fn from_block(&self) -> u64 {
        self.from_block
    }
    #[must_use]
    pub const fn through_block(&self) -> u64 {
        self.through_block
    }
    #[must_use]
    pub fn expected_through_hash(&self) -> &str {
        &self.expected_through_hash
    }
    #[must_use]
    pub const fn terminal_number(&self) -> u64 {
        self.terminal_header.number
    }
    #[must_use]
    pub fn terminal_hash(&self) -> &str {
        &self.terminal_header.hash
    }
    #[must_use]
    pub fn terminal_state_root(&self) -> &str {
        &self.terminal_header.state_root
    }
    #[must_use]
    pub fn terminal_transactions_root(&self) -> &str {
        &self.terminal_header.transactions_root
    }
    #[must_use]
    pub fn terminal_receipts_root(&self) -> &str {
        &self.terminal_header.receipts_root
    }
    #[must_use]
    pub fn logs(&self) -> &[PositionTransferLog] {
        &self.logs
    }
    #[must_use]
    pub fn pages(&self) -> &[RpcPositionHistoryPage] {
        &self.pages
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
        self.request_count
    }
    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.response_bytes
    }
}

/// Caller-configured JSON-RPC endpoint. No provider URL or credential is selected here.
pub struct RpcPositionHistoryReader {
    client: Client,
    endpoint: Url,
}

impl RpcPositionHistoryReader {
    /// HTTPS is required except for loopback HTTP used by local test servers.
    pub fn new(builder: ClientBuilder, endpoint: &str) -> Result<Self, RpcPositionHistoryError> {
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
        Ok(Self { client, endpoint })
    }

    /// Reads chain/finality, a before anchor, both full-range filters, and an after anchor.
    pub async fn read_history(
        &self,
        request: &RpcPositionHistoryRequest,
    ) -> Result<RpcPositionHistoryObservation, RpcPositionHistoryError> {
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
        if request.max_requests < RPC_CALLS {
            return Err(RpcPositionHistoryError::RequestBudgetExceeded);
        }

        let started_at = Utc::now();
        let start = tokio::time::Instant::now();
        let deadline = start
            .checked_add(request.total_timeout)
            .ok_or(RpcPositionHistoryError::InvalidInput)?;
        let mut state = ReadState {
            pages: Vec::new(),
            response_bytes: 0,
            next_id: 1,
        };
        let chain = self
            .call("eth_chainId", json!([]), deadline, request, &mut state)
            .await?;
        if parse_quantity(&chain) != Some(RPC_CHAIN_ID) {
            return Err(RpcPositionHistoryError::WrongChain);
        }
        let finalized = self
            .call(
                "eth_getBlockByNumber",
                json!(["finalized", false]),
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
            &self
                .call(
                    "eth_getBlockByNumber",
                    json!([through_tag, false]),
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

        let holder_topic = format!("0x{:0>64}", &holder[2..]);
        let mut logs = BTreeMap::<(String, u64), PositionTransferLog>::new();
        let mut block_hashes = BTreeMap::<u64, String>::new();
        let mut transaction_hashes = BTreeMap::<(String, u64), String>::new();
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
            let filter = json!({"fromBlock": quantity(request.from_block), "toBlock": quantity(request.through_block),
                "address": [CTF_EMITTER, POSITION_MANAGER_EMITTER], "topics": topics});
            let result = self
                .call(
                    "eth_getLogs",
                    json!([filter]),
                    deadline,
                    request,
                    &mut state,
                )
                .await?;
            let entries = result
                .as_array()
                .ok_or(RpcPositionHistoryError::MalformedResponse)?;
            for entry in entries {
                if entry.is_null() || entry.get("removed").and_then(Value::as_bool) != Some(false) {
                    return Err(RpcPositionHistoryError::MalformedResponse);
                }
                let block_number = entry
                    .get("blockNumber")
                    .and_then(parse_quantity)
                    .ok_or(RpcPositionHistoryError::MalformedResponse)?;
                if block_number < request.from_block || block_number > request.through_block {
                    return Err(RpcPositionHistoryError::MalformedResponse);
                }
                let block_hash = entry
                    .get("blockHash")
                    .and_then(Value::as_str)
                    .and_then(normalize_hash)
                    .ok_or(RpcPositionHistoryError::MalformedResponse)?;
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
        let after = parse_header(
            &self
                .call(
                    "eth_getBlockByNumber",
                    json!([through_tag, false]),
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
        Ok(RpcPositionHistoryObservation {
            holder_address: holder,
            from_block: request.from_block,
            through_block: request.through_block,
            expected_through_hash: expected_hash,
            terminal_header: before,
            logs: ordered_logs,
            pages: state.pages,
            started_at,
            completed_at: Utc::now(),
            elapsed: start.elapsed(),
            request_count: state.next_id.saturating_sub(1) as usize,
            response_bytes: state.response_bytes,
        })
    }

    async fn call(
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
        let envelope: Value = serde_json::from_str(&response_json)
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
        let result = envelope
            .get("result")
            .cloned()
            .ok_or(RpcPositionHistoryError::MalformedResponse)?;
        state.pages.push(RpcPositionHistoryPage {
            method: method.to_owned(),
            request_json,
            response_json,
        });
        Ok(result)
    }
}

struct ReadState {
    pages: Vec<RpcPositionHistoryPage>,
    response_bytes: usize,
    next_id: u64,
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
