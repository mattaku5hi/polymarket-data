//! Bounded SQD acquisition of raw ERC-1155 position-transfer history.
//!
//! This is a source observation only. It does not establish canonicality,
//! receipt inclusion, complete inventory, balances, cost basis, or P&L.

use std::{collections::BTreeMap, net::IpAddr, time::Duration};

use chrono::{DateTime, Utc};
use reqwest::{Client, ClientBuilder, StatusCode, Url};
use serde_json::{Value, json};

pub const SQD_POLYGON_DATASET_URL: &str = "https://portal.sqd.dev/datasets/polygon-mainnet";
pub const CTF_EMITTER: &str = "0x4d97dcd97ec945f40cf65f87097ace5ea0476045";
pub const POSITION_MANAGER_EMITTER: &str = "0x006f54f7f9a22e0000cc2ab60031000000ae9fef";
pub const TRANSFER_SINGLE_TOPIC: &str =
    "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62";
pub const TRANSFER_BATCH_TOPIC: &str =
    "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb";
pub const MAX_HISTORY_REQUESTS: usize = 512;
pub const MAX_HISTORY_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_HISTORY_TOTAL_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PositionHistoryDirection {
    From,
    To,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PositionLedger {
    Ctf,
    PositionManager,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PositionHistoryError {
    #[error("SQD position-history input is invalid")]
    InvalidInput,
    #[error("SQD position-history HTTP client could not be built")]
    ClientBuild,
    #[error("SQD position-history request budget exhausted")]
    RequestBudgetExceeded,
    #[error("SQD position-history timed out at {0:?}")]
    Timeout(PositionHistoryDirection),
    #[error("SQD position-history request failed at {0:?}")]
    RequestFailed(PositionHistoryDirection),
    #[error(
        "SQD position-history returned HTTP {status} at {direction:?} (retry after {retry_after_seconds:?} seconds)"
    )]
    RateLimited {
        direction: PositionHistoryDirection,
        status: u16,
        retry_after_seconds: Option<u64>,
    },
    #[error("SQD position-history returned HTTP {status} at {direction:?}")]
    HttpStatus {
        direction: PositionHistoryDirection,
        status: u16,
        retry_after_seconds: Option<u64>,
    },
    #[error("SQD position-history response byte budget exceeded")]
    BodyBudgetExceeded,
    #[error("SQD position-history response could not be read at {0:?}")]
    ResponseUnreadable(PositionHistoryDirection),
    #[error("SQD position-history response was malformed at {0:?}")]
    MalformedResponse(PositionHistoryDirection),
    #[error("SQD position-history log did not match its query at {0:?}")]
    FilterMismatch(PositionHistoryDirection),
    #[error("SQD position-history page cursor was invalid at {0:?}")]
    InvalidPageCursor(PositionHistoryDirection),
    #[error("SQD position-history did not reach its requested terminal block at {0:?}")]
    Incomplete(PositionHistoryDirection),
    #[error("SQD position-history terminal hash disagreed with the caller anchor")]
    AnchorMismatch,
    #[error("SQD position-history returned conflicting data for a log locator")]
    ConflictingLocator,
    #[error("SQD position-history returned inconsistent block headers")]
    ConflictingHeader,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqdPositionHistoryRequest {
    pub holder_address: String,
    pub from_block: u64,
    pub through_block: u64,
    /// Caller-supplied anchor; the reader only compares both source terminals to it.
    pub expected_through_hash: String,
    pub max_requests: usize,
    pub max_total_response_bytes: usize,
    pub total_timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqdBlockHeader {
    number: u64,
    hash: String,
    parent_hash: String,
    state_root: String,
    transactions_root: String,
    receipts_root: String,
    logs_bloom: String,
}

impl SqdBlockHeader {
    #[must_use]
    pub const fn number(&self) -> u64 {
        self.number
    }
    #[must_use]
    pub fn hash(&self) -> &str {
        &self.hash
    }
    #[must_use]
    pub fn parent_hash(&self) -> &str {
        &self.parent_hash
    }
    #[must_use]
    pub fn state_root(&self) -> &str {
        &self.state_root
    }
    #[must_use]
    pub fn transactions_root(&self) -> &str {
        &self.transactions_root
    }
    #[must_use]
    pub fn receipts_root(&self) -> &str {
        &self.receipts_root
    }
    #[must_use]
    pub fn logs_bloom(&self) -> &str {
        &self.logs_bloom
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PositionTransferLog {
    ledger: PositionLedger,
    block_number: u64,
    block_hash: String,
    transaction_hash: String,
    transaction_index: u64,
    log_index: u64,
    emitter: String,
    topics: Vec<String>,
    data: String,
}

impl PositionTransferLog {
    #[must_use]
    pub const fn ledger(&self) -> PositionLedger {
        self.ledger
    }
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
    pub const fn transaction_index(&self) -> u64 {
        self.transaction_index
    }
    #[must_use]
    pub const fn log_index(&self) -> u64 {
        self.log_index
    }
    #[must_use]
    pub fn emitter(&self) -> &str {
        &self.emitter
    }
    #[must_use]
    pub fn topics(&self) -> &[String] {
        &self.topics
    }
    #[must_use]
    pub fn data(&self) -> &str {
        &self.data
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqdPositionHistoryPage {
    direction: PositionHistoryDirection,
    cursor: u64,
    last_block: u64,
    request_body: String,
    response_body: String,
}

impl SqdPositionHistoryPage {
    #[must_use]
    pub const fn direction(&self) -> PositionHistoryDirection {
        self.direction
    }
    #[must_use]
    pub const fn cursor(&self) -> u64 {
        self.cursor
    }
    #[must_use]
    pub const fn last_block(&self) -> u64 {
        self.last_block
    }
    #[must_use]
    pub fn request_body(&self) -> &str {
        &self.request_body
    }
    #[must_use]
    pub fn response_body(&self) -> &str {
        &self.response_body
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqdPositionHistoryObservation {
    holder_address: String,
    from_block: u64,
    through_block: u64,
    expected_through_hash: String,
    from_terminal: SqdBlockHeader,
    to_terminal: SqdBlockHeader,
    /// Deduplicated logs sorted by (block number, transaction index, log index).
    logs: Vec<PositionTransferLog>,
    pages: Vec<SqdPositionHistoryPage>,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    elapsed: Duration,
    request_count: usize,
    response_bytes: usize,
}

impl SqdPositionHistoryObservation {
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
    pub fn from_terminal(&self) -> &SqdBlockHeader {
        &self.from_terminal
    }
    #[must_use]
    pub fn to_terminal(&self) -> &SqdBlockHeader {
        &self.to_terminal
    }
    #[must_use]
    pub fn logs(&self) -> &[PositionTransferLog] {
        &self.logs
    }
    #[must_use]
    pub fn pages(&self) -> &[SqdPositionHistoryPage] {
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

/// Caller-configured, read-only access to SQD's Polygon finalized stream.
pub struct SqdPositionHistoryReader {
    client: Client,
    endpoint: Url,
}

impl SqdPositionHistoryReader {
    /// Builds a reader from a base URL ending at the dataset, without credentials.
    /// HTTPS is required except for loopback HTTP used by local test servers.
    pub fn new(
        builder: ClientBuilder,
        dataset_base_url: &str,
    ) -> Result<Self, PositionHistoryError> {
        let mut endpoint =
            Url::parse(dataset_base_url).map_err(|_| PositionHistoryError::InvalidInput)?;
        let host = endpoint
            .host_str()
            .ok_or(PositionHistoryError::InvalidInput)?;
        let loopback = host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
            || host.eq_ignore_ascii_case("localhost");
        if (endpoint.scheme() != "https" && !(endpoint.scheme() == "http" && loopback))
            || endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(PositionHistoryError::InvalidInput);
        }
        let path = format!("{}/finalized-stream", endpoint.path().trim_end_matches('/'));
        endpoint.set_path(&path);
        let client = builder
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .map_err(|_| PositionHistoryError::ClientBuild)?;
        Ok(Self { client, endpoint })
    }

    /// Reads both holder directions to the fixed inclusive terminal block.
    pub async fn read_history(
        &self,
        request: &SqdPositionHistoryRequest,
    ) -> Result<SqdPositionHistoryObservation, PositionHistoryError> {
        let holder =
            normalize_address(&request.holder_address).ok_or(PositionHistoryError::InvalidInput)?;
        if holder == "0x0000000000000000000000000000000000000000" {
            return Err(PositionHistoryError::InvalidInput);
        }
        let expected_hash = normalize_hash(&request.expected_through_hash)
            .ok_or(PositionHistoryError::InvalidInput)?;
        if request.from_block > request.through_block
            || request.max_requests == 0
            || request.max_requests > MAX_HISTORY_REQUESTS
            || request.max_total_response_bytes == 0
            || request.max_total_response_bytes > MAX_HISTORY_TOTAL_BYTES
            || request.total_timeout.is_zero()
        {
            return Err(PositionHistoryError::InvalidInput);
        }
        if request.max_requests < 2 {
            return Err(PositionHistoryError::RequestBudgetExceeded);
        }
        let started_at = Utc::now();
        let start = tokio::time::Instant::now();
        let deadline = start
            .checked_add(request.total_timeout)
            .ok_or(PositionHistoryError::InvalidInput)?;
        let mut state = ReadState {
            request_count: 0,
            response_bytes: 0,
            pages: Vec::new(),
            logs: BTreeMap::new(),
            headers: BTreeMap::new(),
        };
        let from_terminal = self
            .read_direction(
                request,
                &holder,
                PositionHistoryDirection::From,
                deadline,
                &mut state,
            )
            .await?;
        let to_terminal = self
            .read_direction(
                request,
                &holder,
                PositionHistoryDirection::To,
                deadline,
                &mut state,
            )
            .await?;
        if from_terminal != to_terminal
            || from_terminal.hash != expected_hash
            || to_terminal.hash != expected_hash
        {
            return Err(PositionHistoryError::AnchorMismatch);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(PositionHistoryError::Timeout(PositionHistoryDirection::To));
        }
        Ok(SqdPositionHistoryObservation {
            holder_address: holder,
            from_block: request.from_block,
            through_block: request.through_block,
            expected_through_hash: expected_hash,
            from_terminal,
            to_terminal,
            logs: {
                let mut logs: Vec<_> = state.logs.into_values().collect();
                logs.sort_by_key(|log| (log.block_number, log.transaction_index, log.log_index));
                logs
            },
            pages: state.pages,
            started_at,
            completed_at: Utc::now(),
            elapsed: start.elapsed(),
            request_count: state.request_count,
            response_bytes: state.response_bytes,
        })
    }

    async fn read_direction(
        &self,
        request: &SqdPositionHistoryRequest,
        holder: &str,
        direction: PositionHistoryDirection,
        deadline: tokio::time::Instant,
        state: &mut ReadState,
    ) -> Result<SqdBlockHeader, PositionHistoryError> {
        let mut cursor = request.from_block;
        let terminal = loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(PositionHistoryError::Timeout(direction));
            }
            if state.request_count >= request.max_requests {
                return Err(PositionHistoryError::RequestBudgetExceeded);
            }
            state.request_count += 1;
            let body_value = query_body(cursor, request.through_block, holder, direction);
            let request_body = serde_json::to_string(&body_value)
                .map_err(|_| PositionHistoryError::InvalidInput)?;
            let response = tokio::time::timeout_at(
                deadline,
                self.client
                    .post(self.endpoint.clone())
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .header(reqwest::header::ACCEPT, "application/x-ndjson")
                    .header(reqwest::header::ACCEPT_ENCODING, "identity")
                    .body(request_body.clone())
                    .send(),
            )
            .await
            .map_err(|_| PositionHistoryError::Timeout(direction))?
            .map_err(|_| PositionHistoryError::RequestFailed(direction))?;
            let status = response.status();
            if status == StatusCode::TOO_MANY_REQUESTS {
                let retry = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse().ok());
                return Err(PositionHistoryError::RateLimited {
                    direction,
                    status: status.as_u16(),
                    retry_after_seconds: retry,
                });
            }
            if status.as_u16() == 529 {
                let retry = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse().ok());
                return Err(PositionHistoryError::RateLimited {
                    direction,
                    status: status.as_u16(),
                    retry_after_seconds: retry,
                });
            }
            if !status.is_success() {
                let retry = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse().ok());
                return Err(PositionHistoryError::HttpStatus {
                    direction,
                    status: status.as_u16(),
                    retry_after_seconds: retry,
                });
            }
            if response
                .headers()
                .get(reqwest::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| !v.eq_ignore_ascii_case("identity"))
            {
                return Err(PositionHistoryError::MalformedResponse(direction));
            }
            if response.content_length().is_some_and(|n| {
                n > MAX_HISTORY_RESPONSE_BYTES as u64
                    || n > (request.max_total_response_bytes - state.response_bytes) as u64
            }) {
                return Err(PositionHistoryError::BodyBudgetExceeded);
            }
            let mut response = response;
            let mut body = Vec::new();
            loop {
                let chunk = tokio::time::timeout_at(deadline, response.chunk())
                    .await
                    .map_err(|_| PositionHistoryError::Timeout(direction))?
                    .map_err(|_| PositionHistoryError::ResponseUnreadable(direction))?;
                let Some(chunk) = chunk else { break };
                if body.len().saturating_add(chunk.len()) > MAX_HISTORY_RESPONSE_BYTES
                    || state
                        .response_bytes
                        .saturating_add(body.len())
                        .saturating_add(chunk.len())
                        > request.max_total_response_bytes
                {
                    return Err(PositionHistoryError::BodyBudgetExceeded);
                }
                body.extend_from_slice(&chunk);
            }
            state.response_bytes += body.len();
            let raw_body = String::from_utf8(body.clone())
                .map_err(|_| PositionHistoryError::MalformedResponse(direction))?;
            if raw_body.trim().is_empty() {
                return Err(PositionHistoryError::Incomplete(direction));
            }
            let headers_and_logs = parse_page(
                &body,
                request.from_block,
                request.through_block,
                cursor,
                holder,
                direction,
            )?;
            let (headers, logs) = headers_and_logs;
            let first = headers
                .first()
                .ok_or(PositionHistoryError::Incomplete(direction))?
                .number;
            let last = headers
                .last()
                .cloned()
                .ok_or(PositionHistoryError::Incomplete(direction))?;
            if first != cursor || last.number < cursor || last.number > request.through_block {
                return Err(PositionHistoryError::InvalidPageCursor(direction));
            }
            for header in headers {
                register_header(&mut state.headers, header)?;
            }
            for log in logs {
                let locator = (log.block_hash.clone(), log.log_index);
                if let Some(previous) = state.logs.get(&locator) {
                    if previous != &log {
                        return Err(PositionHistoryError::ConflictingLocator);
                    }
                } else {
                    state.logs.insert(locator, log);
                }
            }
            state.pages.push(SqdPositionHistoryPage {
                direction,
                cursor,
                last_block: last.number,
                request_body,
                response_body: raw_body,
            });
            if last.number == request.through_block {
                break last;
            }
            let next = last
                .number
                .checked_add(1)
                .ok_or(PositionHistoryError::InvalidPageCursor(direction))?;
            if next <= cursor {
                return Err(PositionHistoryError::InvalidPageCursor(direction));
            }
            cursor = next;
        };
        Ok(terminal)
    }
}

struct ReadState {
    request_count: usize,
    response_bytes: usize,
    pages: Vec<SqdPositionHistoryPage>,
    logs: BTreeMap<(String, u64), PositionTransferLog>,
    headers: BTreeMap<u64, SqdBlockHeader>,
}

fn register_header(
    known: &mut BTreeMap<u64, SqdBlockHeader>,
    header: SqdBlockHeader,
) -> Result<(), PositionHistoryError> {
    if known
        .get(&header.number)
        .is_some_and(|previous| previous != &header)
    {
        return Err(PositionHistoryError::ConflictingHeader);
    }
    if let Some(previous) = header.number.checked_sub(1).and_then(|n| known.get(&n)) {
        if header.parent_hash != previous.hash {
            return Err(PositionHistoryError::ConflictingHeader);
        }
    }
    if let Some(next) = header.number.checked_add(1).and_then(|n| known.get(&n)) {
        if next.parent_hash != header.hash {
            return Err(PositionHistoryError::ConflictingHeader);
        }
    }
    known.insert(header.number, header);
    Ok(())
}

fn query_body(from: u64, to: u64, holder: &str, direction: PositionHistoryDirection) -> Value {
    let holder_topic = format!("0x{:0>64}", &holder[2..]);
    let indexed_topic = match direction {
        PositionHistoryDirection::From => "topic2",
        PositionHistoryDirection::To => "topic3",
    };
    let mut single = json!({
        "address": [CTF_EMITTER, POSITION_MANAGER_EMITTER],
        "topic0": [TRANSFER_SINGLE_TOPIC]
    });
    let mut batch = json!({
        "address": [CTF_EMITTER, POSITION_MANAGER_EMITTER],
        "topic0": [TRANSFER_BATCH_TOPIC]
    });
    single[indexed_topic] = json!([holder_topic]);
    batch[indexed_topic] = json!([holder_topic]);
    json!({
        "type": "evm", "fromBlock": from, "toBlock": to,
        "fields": {
            "block": {"number": true, "hash": true, "parentHash": true, "stateRoot": true,
                "transactionsRoot": true, "receiptsRoot": true, "logsBloom": true},
            "log": {"address": true, "topics": true, "data": true,
                "transactionHash": true, "transactionIndex": true, "logIndex": true}
        },
        "logs": [single, batch]
    })
}

fn parse_page(
    body: &[u8],
    range_start: u64,
    range_end: u64,
    cursor: u64,
    holder: &str,
    direction: PositionHistoryDirection,
) -> Result<(Vec<SqdBlockHeader>, Vec<PositionTransferLog>), PositionHistoryError> {
    let fail = || PositionHistoryError::MalformedResponse(direction);
    let mut first = None;
    let mut previous_number = None;
    let mut headers = Vec::new();
    let mut logs = Vec::new();
    for line in body
        .split(|b| *b == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
    {
        let block: Value = serde_json::from_slice(line).map_err(|_| fail())?;
        let header_v = block.get("header").ok_or_else(fail)?;
        let number = header_v
            .get("number")
            .and_then(Value::as_u64)
            .ok_or_else(fail)?;
        if first.is_none() {
            first = Some(number);
        }
        if previous_number.is_some_and(|p| number <= p)
            || number < range_start
            || number > range_end
        {
            return Err(PositionHistoryError::InvalidPageCursor(direction));
        }
        previous_number = Some(number);
        let header = SqdBlockHeader {
            number,
            hash: field_hash(header_v, "hash").ok_or_else(fail)?,
            parent_hash: field_hash(header_v, "parentHash").ok_or_else(fail)?,
            state_root: field_hash(header_v, "stateRoot").ok_or_else(fail)?,
            transactions_root: field_hash(header_v, "transactionsRoot").ok_or_else(fail)?,
            receipts_root: field_hash(header_v, "receiptsRoot").ok_or_else(fail)?,
            logs_bloom: field_fixed_hex(header_v, "logsBloom", 256).ok_or_else(fail)?,
        };
        let block_hash = header.hash.clone();
        if let Some(block_logs) = block.get("logs") {
            let entries = block_logs.as_array().ok_or_else(fail)?;
            for entry in entries {
                let log = normalize_log(entry, number, &block_hash, holder, direction)?;
                logs.push(log);
            }
        }
        headers.push(header);
    }
    let first = first.ok_or(PositionHistoryError::Incomplete(direction))?;
    if first != cursor {
        return Err(PositionHistoryError::InvalidPageCursor(direction));
    }
    Ok((headers, logs))
}

pub(crate) fn normalize_log(
    v: &Value,
    block_number: u64,
    block_hash: &str,
    holder: &str,
    direction: PositionHistoryDirection,
) -> Result<PositionTransferLog, PositionHistoryError> {
    let mismatch = || PositionHistoryError::FilterMismatch(direction);
    let emitter = v
        .get("address")
        .and_then(Value::as_str)
        .and_then(normalize_address)
        .ok_or_else(mismatch)?;
    let ledger = match emitter.as_str() {
        CTF_EMITTER => PositionLedger::Ctf,
        POSITION_MANAGER_EMITTER => PositionLedger::PositionManager,
        _ => return Err(mismatch()),
    };
    let topics_v = v
        .get("topics")
        .and_then(Value::as_array)
        .ok_or_else(mismatch)?;
    if topics_v.len() != 4 {
        return Err(mismatch());
    }
    let mut topics = Vec::with_capacity(4);
    for topic in topics_v {
        topics.push(
            topic
                .as_str()
                .and_then(normalize_hash)
                .ok_or_else(mismatch)?,
        );
    }
    if topics[0] != TRANSFER_SINGLE_TOPIC && topics[0] != TRANSFER_BATCH_TOPIC {
        return Err(mismatch());
    }
    let holder_topic = format!("0x{:0>64}", &holder[2..]);
    let indexed_holder = match direction {
        PositionHistoryDirection::From => &topics[2],
        PositionHistoryDirection::To => &topics[3],
    };
    if indexed_holder != &holder_topic {
        return Err(mismatch());
    }
    let transaction_hash = v
        .get("transactionHash")
        .and_then(Value::as_str)
        .and_then(normalize_hash)
        .ok_or_else(mismatch)?;
    let transaction_index = v
        .get("transactionIndex")
        .and_then(parse_index)
        .ok_or_else(mismatch)?;
    let log_index = v
        .get("logIndex")
        .and_then(parse_index)
        .ok_or_else(mismatch)?;
    let data = v
        .get("data")
        .and_then(Value::as_str)
        .and_then(normalize_hex_bytes)
        .ok_or_else(mismatch)?;
    Ok(PositionTransferLog {
        ledger,
        block_number,
        block_hash: block_hash.to_owned(),
        transaction_hash,
        transaction_index,
        log_index,
        emitter,
        topics,
        data,
    })
}

pub(crate) fn parse_index(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| {
        v.as_str().and_then(|s| {
            s.strip_prefix("0x")
                .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        })
    })
}
fn field_hash(v: &Value, field: &str) -> Option<String> {
    v.get(field)
        .and_then(Value::as_str)
        .and_then(normalize_hash)
}
fn field_fixed_hex(v: &Value, field: &str, bytes: usize) -> Option<String> {
    let s = v.get(field)?.as_str()?;
    let n = s.strip_prefix("0x")?;
    if n.len() != bytes * 2 || !n.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("0x{}", n.to_ascii_lowercase()))
}
pub(crate) fn normalize_hash(s: &str) -> Option<String> {
    field_hex(s, 32)
}
pub(crate) fn normalize_address(s: &str) -> Option<String> {
    field_hex(s, 20)
}
fn field_hex(s: &str, bytes: usize) -> Option<String> {
    let n = s.strip_prefix("0x")?;
    if n.len() != bytes * 2 || !n.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("0x{}", n.to_ascii_lowercase()))
}
fn normalize_hex_bytes(s: &str) -> Option<String> {
    let n = s.strip_prefix("0x")?;
    if n.len() % 2 != 0 || !n.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("0x{}", n.to_ascii_lowercase()))
}
