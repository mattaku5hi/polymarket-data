//! Bounded provider-reported fifth binary module lookup at a current census block.
//!
//! The registry getter result is ordinary RPC context tied to a caller-selected
//! block hash. It is not code identity, a state proof, or execution authority.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tokio::time::Instant;

use super::current_interval_census::{RpcCurrentIntervalCensus, RpcCurrentIntervalSource};
use super::current_interval_transactions::CurrentIntervalRpcCallSource;
use super::{
    MAX_HISTORY_REQUESTS, ReadState, RecordedRpcPositionHistoryPage, RpcPositionHistoryError,
    RpcPositionHistoryPage, RpcPositionHistoryReader, RpcPositionHistoryRequest, normalize_address,
    normalize_hash, parse_header, parse_quantity, quantity,
};
use crate::collateral_cash::PUSD_ADDRESS;
use crate::position_history::POSITION_MANAGER_EMITTER;

const MODULE_ID: u64 = 1;
const REGISTRY_GETTER_SELECTOR: &str = "0x4d51cdf1";
const EXCHANGE_ADDRESS: &str = "0xe3333700ca9d93003f00f0f71f8515005f6c00aa";
const MAX_CONTEXT_CALLS: usize = 4;
const MAX_CONTEXT_TOTAL_BYTES: usize = 256 * 1024;
const MAX_CONTEXT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcCurrentFifthBinaryContextRequest {
    pub block_number: u64,
    /// Expected provider-reported block hash, compared with the census header.
    pub expected_hash: String,
    pub max_requests: usize,
    pub max_total_response_bytes: usize,
    pub total_timeout: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcCurrentFifthBinaryContextSource {
    ProviderReported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcCurrentFifthBinaryImplementationVersion {
    Unbound,
}

/// Unrooted module registry context. Its implementation version is always unbound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcCurrentFifthBinaryContext {
    block_number: u64,
    block_hash: String,
    module_id: u64,
    module_address: String,
    source: RpcCurrentFifthBinaryContextSource,
    implementation_version: RpcCurrentFifthBinaryImplementationVersion,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    elapsed: Duration,
    request_count: usize,
    response_bytes: usize,
    requests: Vec<RpcPositionHistoryPage>,
}

impl RpcCurrentFifthBinaryContext {
    #[must_use]
    pub const fn block_number(&self) -> u64 {
        self.block_number
    }

    #[must_use]
    pub fn block_hash(&self) -> &str {
        &self.block_hash
    }

    #[must_use]
    pub const fn module_id(&self) -> u64 {
        self.module_id
    }

    #[must_use]
    pub fn module_address(&self) -> &str {
        &self.module_address
    }

    #[must_use]
    pub const fn source(&self) -> RpcCurrentFifthBinaryContextSource {
        self.source
    }

    #[must_use]
    pub const fn implementation_version(&self) -> RpcCurrentFifthBinaryImplementationVersion {
        self.implementation_version
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

    #[must_use]
    pub fn requests(&self) -> &[RpcPositionHistoryPage] {
        &self.requests
    }
}

impl RpcPositionHistoryReader {
    /// Resolve PositionManager `moduleById(1)` at an event header from the census.
    ///
    /// Four ordinary JSON-RPC requests are made: chain id, block header, getter,
    /// and the same header again. This does not read code or establish proofs.
    pub async fn read_current_fifth_binary_context(
        &self,
        census: &RpcCurrentIntervalCensus,
        request: &RpcCurrentFifthBinaryContextRequest,
    ) -> Result<RpcCurrentFifthBinaryContext, RpcPositionHistoryError> {
        let timer = Instant::now();
        let started_at = Utc::now();
        let mut source = CurrentIntervalRpcCallSource::Network(self);
        read_current_fifth_binary_context_inner(census, request, &mut source, timer, started_at)
            .await
    }
}

/// Revalidates the four raw frames from a context read without making RPC calls.
/// Timing fields describe this local replay; original capture times belong with the frames.
pub async fn reverify_recorded_current_fifth_binary_context(
    census: &RpcCurrentIntervalCensus,
    request: &RpcCurrentFifthBinaryContextRequest,
    pages: &[RecordedRpcPositionHistoryPage],
) -> Result<RpcCurrentFifthBinaryContext, RpcPositionHistoryError> {
    let timer = Instant::now();
    let started_at = Utc::now();
    let mut source = CurrentIntervalRpcCallSource::Recorded {
        pages,
        next_page: 0,
    };
    read_current_fifth_binary_context_inner(census, request, &mut source, timer, started_at).await
}

async fn read_current_fifth_binary_context_inner(
    census: &RpcCurrentIntervalCensus,
    request: &RpcCurrentFifthBinaryContextRequest,
    source: &mut CurrentIntervalRpcCallSource<'_>,
    timer: Instant,
    started_at: DateTime<Utc>,
) -> Result<RpcCurrentFifthBinaryContext, RpcPositionHistoryError> {
    let census_header = validate_context_inputs(census, request)?;
    if request.max_requests < MAX_CONTEXT_CALLS {
        return Err(RpcPositionHistoryError::RequestBudgetExceeded);
    }
    source.validate_count(MAX_CONTEXT_CALLS)?;

    let transport = RpcPositionHistoryRequest {
        holder_address: census.wallets[0].clone(),
        from_block: request.block_number,
        through_block: request.block_number,
        expected_through_hash: census_header.hash.clone(),
        max_requests: request.max_requests,
        max_total_response_bytes: request.max_total_response_bytes,
        total_timeout: request.total_timeout,
    };
    let deadline = timer
        .checked_add(request.total_timeout)
        .ok_or(RpcPositionHistoryError::InvalidInput)?;
    let mut state = ReadState {
        pages: Vec::with_capacity(MAX_CONTEXT_CALLS),
        response_bytes: 0,
        next_id: 1,
    };

    let chain = source
        .call("eth_chainId", json!([]), deadline, &transport, &mut state)
        .await?;
    if parse_quantity(&chain) != Some(137) {
        return Err(RpcPositionHistoryError::WrongChain);
    }

    let block_tag = quantity(request.block_number);
    let before_value = source
        .call(
            "eth_getBlockByNumber",
            json!([block_tag, false]),
            deadline,
            &transport,
            &mut state,
        )
        .await?;
    let before = parse_header(&before_value)?;
    if before.number != request.block_number || before.hash != census_header.hash {
        return Err(RpcPositionHistoryError::AnchorMismatch);
    }

    let getter_call = format!("{REGISTRY_GETTER_SELECTOR}{:0>64x}", MODULE_ID);
    let result = source
        .call(
            "eth_call",
            json!([
                {"to": POSITION_MANAGER_EMITTER, "data": getter_call},
                block_tag
            ]),
            deadline,
            &transport,
            &mut state,
        )
        .await?;
    let module_address = decode_registry_address(&result)?;

    let after_value = source
        .call(
            "eth_getBlockByNumber",
            json!([quantity(request.block_number), false]),
            deadline,
            &transport,
            &mut state,
        )
        .await?;
    let after = parse_header(&after_value)?;
    if before != after {
        return Err(RpcPositionHistoryError::AnchorMismatch);
    }
    if state.next_id.saturating_sub(1) as usize != MAX_CONTEXT_CALLS
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

    Ok(RpcCurrentFifthBinaryContext {
        block_number: request.block_number,
        block_hash: census_header.hash,
        module_id: MODULE_ID,
        module_address,
        source: RpcCurrentFifthBinaryContextSource::ProviderReported,
        implementation_version: RpcCurrentFifthBinaryImplementationVersion::Unbound,
        started_at,
        completed_at: Utc::now(),
        elapsed: timer.elapsed(),
        request_count: state.next_id.saturating_sub(1) as usize,
        response_bytes: state.response_bytes,
        requests: state.pages,
    })
}

fn validate_context_inputs(
    census: &RpcCurrentIntervalCensus,
    request: &RpcCurrentFifthBinaryContextRequest,
) -> Result<super::current_interval_census::RpcCurrentIntervalHeader, RpcPositionHistoryError> {
    if census.source != RpcCurrentIntervalSource::ProviderReported
        || census.wallets.is_empty()
        || census.wallets.len() > 100
        || census.start_block >= census.through_block
        || census.start_header.number != census.start_block
        || census.end_header.number != census.through_block
        || census
            .through_block
            .checked_sub(census.start_block)
            .is_none_or(|span| span > 2_048)
        || census.event_headers.len() > 384
        || request.block_number <= census.start_block
        || request.block_number > census.through_block
        || request.max_requests == 0
        || request.max_requests > MAX_HISTORY_REQUESTS
        || request.max_total_response_bytes == 0
        || request.max_total_response_bytes > MAX_CONTEXT_TOTAL_BYTES
        || request.total_timeout.is_zero()
        || request.total_timeout > MAX_CONTEXT_TIMEOUT
    {
        return Err(RpcPositionHistoryError::InvalidInput);
    }
    let mut wallets = census.wallets.clone();
    wallets.sort();
    if wallets != census.wallets
        || wallets.windows(2).any(|pair| pair[0] == pair[1])
        || wallets.iter().any(|wallet| {
            normalize_address(wallet).as_deref() != Some(wallet.as_str())
                || wallet == &format!("0x{}", "00".repeat(20))
        })
        || normalize_hash(&census.start_header.hash).as_deref()
            != Some(census.start_header.hash.as_str())
        || normalize_hash(&census.end_header.hash).as_deref()
            != Some(census.end_header.hash.as_str())
        || normalize_hash(&request.expected_hash).as_deref() != Some(request.expected_hash.as_str())
    {
        return Err(RpcPositionHistoryError::InvalidInput);
    }
    if census.event_headers.iter().any(|header| {
        normalize_hash(&header.hash).as_deref() != Some(header.hash.as_str())
            || header.number <= census.start_block
            || header.number > census.through_block
    }) || census
        .event_headers
        .windows(2)
        .any(|pair| pair[0].number >= pair[1].number)
    {
        return Err(RpcPositionHistoryError::MalformedResponse);
    }
    let mut matched_header = None;
    for header in &census.event_headers {
        if header.number == request.block_number {
            if matched_header.is_some() {
                return Err(RpcPositionHistoryError::MalformedResponse);
            }
            matched_header = Some(header);
        }
    }
    let header = matched_header.ok_or(RpcPositionHistoryError::InvalidInput)?;
    if header.hash != request.expected_hash {
        return Err(RpcPositionHistoryError::AnchorMismatch);
    }
    Ok((*header).clone())
}

fn decode_registry_address(result: &Value) -> Result<String, RpcPositionHistoryError> {
    let text = result
        .as_str()
        .and_then(|text| text.strip_prefix("0x"))
        .ok_or(RpcPositionHistoryError::MalformedResponse)?;
    let word = hex::decode(text).map_err(|_| RpcPositionHistoryError::MalformedResponse)?;
    if word.len() != 32 || word[..12].iter().any(|byte| *byte != 0) {
        return Err(RpcPositionHistoryError::MalformedResponse);
    }
    let address = format!("0x{}", hex::encode(&word[12..]));
    let address = normalize_address(&address).ok_or(RpcPositionHistoryError::MalformedResponse)?;
    if address == format!("0x{}", "00".repeat(20))
        || address == POSITION_MANAGER_EMITTER
        || address == PUSD_ADDRESS
        || address == EXCHANGE_ADDRESS
    {
        return Err(RpcPositionHistoryError::MalformedResponse);
    }
    Ok(address)
}

#[cfg(test)]
pub(crate) fn test_context(
    block_number: u64,
    block_hash: &str,
    module_address: &str,
) -> RpcCurrentFifthBinaryContext {
    RpcCurrentFifthBinaryContext {
        block_number,
        block_hash: block_hash.to_owned(),
        module_id: MODULE_ID,
        module_address: module_address.to_owned(),
        source: RpcCurrentFifthBinaryContextSource::ProviderReported,
        implementation_version: RpcCurrentFifthBinaryImplementationVersion::Unbound,
        started_at: Utc::now(),
        completed_at: Utc::now(),
        elapsed: Duration::ZERO,
        request_count: MAX_CONTEXT_CALLS,
        response_bytes: 0,
        requests: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc_position_history::current_interval_census::RpcCurrentIntervalHeader;
    use axum::{Json, Router, body::Bytes, extract::State, routing::post};
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    const MODULE: &str = "0x2222222222222222222222222222222222222222";

    #[derive(Clone)]
    struct MockState {
        requests: Arc<Mutex<Vec<Value>>>,
        headers: BTreeMap<String, Value>,
        result: Value,
    }

    async fn mock_rpc(State(state): State<MockState>, body: Bytes) -> Json<Value> {
        let request: Value = serde_json::from_slice(&body).unwrap();
        let params = &request["params"];
        state.requests.lock().unwrap().push(request.clone());
        let result = match request["method"].as_str().unwrap() {
            "eth_chainId" => json!("0x89"),
            "eth_getBlockByNumber" => {
                let tag = params[0].as_str().unwrap();
                state
                    .headers
                    .get(tag)
                    .cloned()
                    .unwrap_or_else(|| mock_header(100))
            }
            "eth_call" => state.result.clone(),
            other => panic!("unexpected method {other}"),
        };
        Json(json!({"jsonrpc":"2.0", "id":request["id"], "result":result}))
    }

    fn mock_header(number: u64) -> Value {
        let hash = format!("0x{:064x}", number + 1);
        json!({
            "number":format!("0x{number:x}"), "hash":hash,
            "parentHash":format!("0x{:064x}", number),
            "stateRoot":format!("0x{:064x}", number + 2),
            "transactionsRoot":format!("0x{:064x}", number + 3),
            "receiptsRoot":format!("0x{:064x}", number + 4),
            "logsBloom":format!("0x{}", "00".repeat(256)),
        })
    }

    fn module_word(address: &str) -> Value {
        json!(format!("0x{}{}", "00".repeat(12), &address[2..]))
    }

    fn census(block_number: u64) -> RpcCurrentIntervalCensus {
        let header = mock_header(block_number);
        let parsed = parse_header(&header).unwrap();
        RpcCurrentIntervalCensus {
            wallets: vec!["0x1111111111111111111111111111111111111111".to_owned()],
            start_block: block_number - 1,
            through_block: block_number,
            start_header: RpcCurrentIntervalHeader {
                number: block_number - 1,
                hash: mock_header(block_number - 1)["hash"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                timestamp: 1_800_000_000 + block_number - 1,
            },
            end_header: RpcCurrentIntervalHeader {
                number: block_number,
                hash: mock_header(block_number)["hash"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                timestamp: 1_800_000_000 + block_number,
            },
            event_headers: vec![RpcCurrentIntervalHeader {
                number: parsed.number,
                hash: parsed.hash,
                timestamp: 1_800_000_000 + block_number,
            }],
            logs: Vec::new(),
            source: RpcCurrentIntervalSource::ProviderReported,
            started_at: Utc::now(),
            completed_at: Utc::now(),
            elapsed: Duration::ZERO,
            request_count: 0,
            response_bytes: 0,
            requests: Vec::new(),
        }
    }

    fn request(block_number: u64) -> RpcCurrentFifthBinaryContextRequest {
        RpcCurrentFifthBinaryContextRequest {
            block_number,
            expected_hash: mock_header(block_number)["hash"]
                .as_str()
                .unwrap()
                .to_owned(),
            max_requests: MAX_CONTEXT_CALLS,
            max_total_response_bytes: MAX_CONTEXT_TOTAL_BYTES,
            total_timeout: Duration::from_secs(5),
        }
    }

    async fn mock_reader(
        result: Value,
        headers: BTreeMap<String, Value>,
    ) -> (
        RpcPositionHistoryReader,
        Arc<Mutex<Vec<Value>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/", post(mock_rpc))
            .with_state(MockState {
                requests: requests.clone(),
                headers,
                result,
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let reader = RpcPositionHistoryReader::new(
            reqwest::Client::builder(),
            &format!("http://{address}/"),
        )
        .unwrap();
        (reader, requests, server)
    }

    #[tokio::test]
    async fn context_reads_exact_module_getter_and_replays_identically() {
        let (reader, requests, server) = mock_reader(module_word(MODULE), BTreeMap::new()).await;
        let observation = reader
            .read_current_fifth_binary_context(&census(100), &request(100))
            .await
            .unwrap();
        assert_eq!(observation.request_count(), MAX_CONTEXT_CALLS);
        assert_eq!(observation.module_id(), 1);
        assert_eq!(observation.module_address(), MODULE);
        assert_eq!(
            observation.implementation_version(),
            RpcCurrentFifthBinaryImplementationVersion::Unbound
        );
        {
            let calls = requests.lock().unwrap();
            assert_eq!(calls.len(), 4);
            assert_eq!(calls[2]["method"], "eth_call");
            assert_eq!(calls[2]["params"][0]["to"], POSITION_MANAGER_EMITTER);
            assert_eq!(
                calls[2]["params"][0]["data"],
                format!("{REGISTRY_GETTER_SELECTOR}{:0>64x}", 1)
            );
            assert_eq!(calls[2]["params"][1], "0x64");
        }
        let pages = observation
            .requests()
            .iter()
            .map(|page| RecordedRpcPositionHistoryPage {
                request_json: page.request_json().to_owned(),
                response_json: page.response_json().to_owned(),
            })
            .collect::<Vec<_>>();
        let replayed =
            reverify_recorded_current_fifth_binary_context(&census(100), &request(100), &pages)
                .await
                .unwrap();
        assert_eq!(replayed.module_address(), observation.module_address());
        assert_eq!(replayed.block_hash(), observation.block_hash());
        assert_eq!(replayed.request_count(), observation.request_count());
        assert_eq!(
            replayed
                .requests()
                .iter()
                .map(|page| page.request_json())
                .collect::<Vec<_>>(),
            observation
                .requests()
                .iter()
                .map(|page| page.request_json())
                .collect::<Vec<_>>()
        );
        server.abort();
    }

    #[tokio::test]
    async fn context_rejects_unanchored_block_bad_getters_and_budget_before_io() {
        let (reader, requests, server) = mock_reader(module_word(MODULE), BTreeMap::new()).await;
        let mut wrong_hash = request(100);
        wrong_hash.expected_hash = format!("0x{}", "ff".repeat(32));
        assert_eq!(
            reader
                .read_current_fifth_binary_context(&census(100), &wrong_hash)
                .await
                .unwrap_err(),
            RpcPositionHistoryError::AnchorMismatch
        );
        let mut insufficient = request(100);
        insufficient.max_requests = 3;
        assert_eq!(
            reader
                .read_current_fifth_binary_context(&census(100), &insufficient)
                .await
                .unwrap_err(),
            RpcPositionHistoryError::RequestBudgetExceeded
        );
        assert!(requests.lock().unwrap().is_empty());
        server.abort();

        for result in [
            json!("0x01"),
            module_word(PUSD_ADDRESS),
            module_word(POSITION_MANAGER_EMITTER),
            module_word(EXCHANGE_ADDRESS),
        ] {
            let (reader, _requests, server) = mock_reader(result, BTreeMap::new()).await;
            assert_eq!(
                reader
                    .read_current_fifth_binary_context(&census(100), &request(100))
                    .await
                    .unwrap_err(),
                RpcPositionHistoryError::MalformedResponse
            );
            server.abort();
        }
    }

    #[tokio::test]
    async fn context_rejects_rpc_header_that_disagrees_with_census_before_getter() {
        let mut wrong_header = mock_header(100);
        wrong_header["hash"] = json!(format!("0x{}", "ff".repeat(32)));
        let (reader, requests, server) = mock_reader(
            module_word(MODULE),
            BTreeMap::from([("0x64".to_owned(), wrong_header)]),
        )
        .await;
        assert_eq!(
            reader
                .read_current_fifth_binary_context(&census(100), &request(100))
                .await
                .unwrap_err(),
            RpcPositionHistoryError::AnchorMismatch
        );
        let calls = requests.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["method"], "eth_chainId");
        assert_eq!(calls[1]["method"], "eth_getBlockByNumber");
        server.abort();
    }
}
