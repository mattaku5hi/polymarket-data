//! Bounded provider-reported standard CTF V2 asset getters at a census block.
//!
//! The returned addresses are ordinary provider observations at a caller-bound
//! block hash. They do not prove deployment code or historical execution.

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
use crate::position_history::CTF_EMITTER;

const EXCHANGE_ADDRESS: &str = "0xe111180000d2663c0091e4f400237545b87b996b";
const MAX_CONTEXT_CALLS: usize = 5;
const MAX_CONTEXT_TOTAL_BYTES: usize = 256 * 1024;
const MAX_CONTEXT_TIMEOUT: Duration = Duration::from_secs(30);
const COLLATERAL_SELECTOR: &str = "0x5c1548fb";
const CTF_SELECTOR: &str = "0x3b521d78";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcCurrentCtfV2ContextRequest {
    pub block_number: u64,
    pub expected_hash: String,
    pub max_requests: usize,
    pub max_total_response_bytes: usize,
    pub total_timeout: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcCurrentCtfV2ContextSource {
    ProviderReported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcCurrentCtfV2ImplementationVersion {
    Unbound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcCurrentCtfV2Context {
    block_number: u64,
    block_hash: String,
    collateral_address: String,
    ctf_address: String,
    source: RpcCurrentCtfV2ContextSource,
    implementation_version: RpcCurrentCtfV2ImplementationVersion,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    elapsed: Duration,
    request_count: usize,
    response_bytes: usize,
    requests: Vec<RpcPositionHistoryPage>,
}

impl RpcCurrentCtfV2Context {
    #[must_use]
    pub const fn block_number(&self) -> u64 {
        self.block_number
    }
    #[must_use]
    pub fn block_hash(&self) -> &str {
        &self.block_hash
    }
    #[must_use]
    pub fn collateral_address(&self) -> &str {
        &self.collateral_address
    }
    #[must_use]
    pub fn ctf_address(&self) -> &str {
        &self.ctf_address
    }
    #[must_use]
    pub const fn source(&self) -> RpcCurrentCtfV2ContextSource {
        self.source
    }
    #[must_use]
    pub const fn implementation_version(&self) -> RpcCurrentCtfV2ImplementationVersion {
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
    /// Read chain ID, a before header, both source-defined getters and an after
    /// header. Getter values are accepted only when they match the SDK's known
    /// PUSD and CTF emitter scope.
    pub async fn read_current_ctf_v2_context(
        &self,
        census: &RpcCurrentIntervalCensus,
        request: &RpcCurrentCtfV2ContextRequest,
    ) -> Result<RpcCurrentCtfV2Context, RpcPositionHistoryError> {
        let timer = Instant::now();
        let started_at = Utc::now();
        let mut source = CurrentIntervalRpcCallSource::Network(self);
        read_context_inner(census, request, &mut source, timer, started_at).await
    }
}

/// Revalidates the five captured frames without issuing RPC calls. Timing
/// values describe local replay; the original captured frames retain provenance.
pub async fn reverify_recorded_current_ctf_v2_context(
    census: &RpcCurrentIntervalCensus,
    request: &RpcCurrentCtfV2ContextRequest,
    pages: &[RecordedRpcPositionHistoryPage],
) -> Result<RpcCurrentCtfV2Context, RpcPositionHistoryError> {
    let timer = Instant::now();
    let started_at = Utc::now();
    let mut source = CurrentIntervalRpcCallSource::Recorded {
        pages,
        next_page: 0,
    };
    read_context_inner(census, request, &mut source, timer, started_at).await
}

async fn read_context_inner(
    census: &RpcCurrentIntervalCensus,
    request: &RpcCurrentCtfV2ContextRequest,
    source: &mut CurrentIntervalRpcCallSource<'_>,
    timer: Instant,
    started_at: DateTime<Utc>,
) -> Result<RpcCurrentCtfV2Context, RpcPositionHistoryError> {
    let census_header = validate_inputs(census, request)?;
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
    let collateral = read_address(
        source,
        COLLATERAL_SELECTOR,
        &block_tag,
        deadline,
        &transport,
        &mut state,
    )
    .await?;
    let ctf = read_address(
        source,
        CTF_SELECTOR,
        &block_tag,
        deadline,
        &transport,
        &mut state,
    )
    .await?;
    if collateral != PUSD_ADDRESS || ctf != CTF_EMITTER {
        return Err(RpcPositionHistoryError::MalformedResponse);
    }
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
    Ok(RpcCurrentCtfV2Context {
        block_number: request.block_number,
        block_hash: census_header.hash,
        collateral_address: collateral,
        ctf_address: ctf,
        source: RpcCurrentCtfV2ContextSource::ProviderReported,
        implementation_version: RpcCurrentCtfV2ImplementationVersion::Unbound,
        started_at,
        completed_at: Utc::now(),
        elapsed: timer.elapsed(),
        request_count: state.next_id.saturating_sub(1) as usize,
        response_bytes: state.response_bytes,
        requests: state.pages,
    })
}

async fn read_address(
    source: &mut CurrentIntervalRpcCallSource<'_>,
    selector: &str,
    block_tag: &str,
    deadline: Instant,
    transport: &RpcPositionHistoryRequest,
    state: &mut ReadState,
) -> Result<String, RpcPositionHistoryError> {
    let result = source
        .call(
            "eth_call",
            json!([{"to":EXCHANGE_ADDRESS,"data":selector}, block_tag]),
            deadline,
            transport,
            state,
        )
        .await?;
    decode_canonical_address(&result)
}

fn validate_inputs(
    census: &RpcCurrentIntervalCensus,
    request: &RpcCurrentCtfV2ContextRequest,
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
    let header = census
        .event_headers
        .iter()
        .find(|header| header.number == request.block_number)
        .ok_or(RpcPositionHistoryError::InvalidInput)?;
    if header.hash != request.expected_hash {
        return Err(RpcPositionHistoryError::AnchorMismatch);
    }
    Ok(header.clone())
}

fn decode_canonical_address(result: &Value) -> Result<String, RpcPositionHistoryError> {
    let text = result
        .as_str()
        .and_then(|text| text.strip_prefix("0x"))
        .ok_or(RpcPositionHistoryError::MalformedResponse)?;
    let word = hex::decode(text).map_err(|_| RpcPositionHistoryError::MalformedResponse)?;
    if word.len() != 32 || word[..12].iter().any(|byte| *byte != 0) {
        return Err(RpcPositionHistoryError::MalformedResponse);
    }
    normalize_address(&format!("0x{}", hex::encode(&word[12..])))
        .ok_or(RpcPositionHistoryError::MalformedResponse)
}

#[cfg(test)]
pub(crate) fn test_ctf_v2_context(block_number: u64, block_hash: &str) -> RpcCurrentCtfV2Context {
    RpcCurrentCtfV2Context {
        block_number,
        block_hash: block_hash.to_owned(),
        collateral_address: PUSD_ADDRESS.to_owned(),
        ctf_address: CTF_EMITTER.to_owned(),
        source: RpcCurrentCtfV2ContextSource::ProviderReported,
        implementation_version: RpcCurrentCtfV2ImplementationVersion::Unbound,
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
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use axum::{Router, body::Bytes, extract::State, routing::post};
    use serde_json::{Value, json};

    use super::*;
    use crate::rpc_position_history::current_interval_census::{
        RpcCurrentIntervalHeader, RpcCurrentIntervalSource,
    };

    #[derive(Clone)]
    struct MockState {
        calls: Arc<Mutex<Vec<Value>>>,
        headers: BTreeMap<String, Value>,
        collateral_result: Value,
        ctf_result: Value,
    }

    async fn mock_rpc(State(state): State<MockState>, body: Bytes) -> axum::Json<Value> {
        let request: Value = serde_json::from_slice(&body).unwrap();
        let result = match request["method"].as_str().unwrap() {
            "eth_chainId" => json!("0x89"),
            "eth_getBlockByNumber" => state
                .headers
                .get(request["params"][0].as_str().unwrap())
                .cloned()
                .unwrap_or_else(|| header(100)),
            "eth_call" => match request["params"][0]["data"].as_str().unwrap() {
                COLLATERAL_SELECTOR => state.collateral_result.clone(),
                CTF_SELECTOR => state.ctf_result.clone(),
                selector => panic!("unexpected getter selector {selector}"),
            },
            method => panic!("unexpected RPC method {method}"),
        };
        state.calls.lock().unwrap().push(request.clone());
        axum::Json(json!({"jsonrpc":"2.0", "id":request["id"], "result":result}))
    }

    fn header(number: u64) -> Value {
        json!({
            "number":format!("0x{number:x}"),
            "hash":format!("0x{:064x}", number + 1),
            "parentHash":format!("0x{:064x}", number),
            "stateRoot":format!("0x{:064x}", number + 2),
            "transactionsRoot":format!("0x{:064x}", number + 3),
            "receiptsRoot":format!("0x{:064x}", number + 4),
            "logsBloom":format!("0x{}", "00".repeat(256)),
        })
    }

    fn address_word(address: &str) -> Value {
        json!(format!("0x{}{}", "00".repeat(12), &address[2..]))
    }

    fn census(block: u64) -> RpcCurrentIntervalCensus {
        let end = parse_header(&header(block)).unwrap();
        RpcCurrentIntervalCensus {
            wallets: vec!["0x1111111111111111111111111111111111111111".to_owned()],
            start_block: block - 1,
            through_block: block,
            start_header: RpcCurrentIntervalHeader {
                number: block - 1,
                hash: header(block - 1)["hash"].as_str().unwrap().to_owned(),
                timestamp: 1_800_000_000 + block - 1,
            },
            end_header: RpcCurrentIntervalHeader {
                number: block,
                hash: end.hash.clone(),
                timestamp: 1_800_000_000 + block,
            },
            event_headers: vec![RpcCurrentIntervalHeader {
                number: block,
                hash: end.hash,
                timestamp: 1_800_000_000 + block,
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

    fn request(block: u64) -> RpcCurrentCtfV2ContextRequest {
        RpcCurrentCtfV2ContextRequest {
            block_number: block,
            expected_hash: header(block)["hash"].as_str().unwrap().to_owned(),
            max_requests: MAX_CONTEXT_CALLS,
            max_total_response_bytes: MAX_CONTEXT_TOTAL_BYTES,
            total_timeout: Duration::from_secs(5),
        }
    }

    async fn mock_reader(
        collateral_result: Value,
        ctf_result: Value,
        headers: BTreeMap<String, Value>,
    ) -> (
        RpcPositionHistoryReader,
        Arc<Mutex<Vec<Value>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/", post(mock_rpc))
            .with_state(MockState {
                calls: calls.clone(),
                headers,
                collateral_result,
                ctf_result,
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let reader = RpcPositionHistoryReader::new(
            reqwest::Client::builder(),
            &format!("http://{address}/"),
        )
        .unwrap();
        (reader, calls, server)
    }

    #[tokio::test]
    async fn reads_exact_two_getters_and_replays_the_five_frames() {
        let (reader, calls, server) = mock_reader(
            address_word(PUSD_ADDRESS),
            address_word(CTF_EMITTER),
            BTreeMap::new(),
        )
        .await;
        let observed = reader
            .read_current_ctf_v2_context(&census(100), &request(100))
            .await
            .unwrap();
        assert_eq!(observed.request_count(), MAX_CONTEXT_CALLS);
        assert_eq!(observed.collateral_address(), PUSD_ADDRESS);
        assert_eq!(observed.ctf_address(), CTF_EMITTER);
        assert_eq!(
            observed.implementation_version(),
            RpcCurrentCtfV2ImplementationVersion::Unbound
        );
        {
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 5);
            assert_eq!(calls[0]["method"], "eth_chainId");
            assert_eq!(calls[2]["params"][0]["data"], COLLATERAL_SELECTOR);
            assert_eq!(calls[3]["params"][0]["data"], CTF_SELECTOR);
            assert_eq!(calls[2]["params"][0]["to"], EXCHANGE_ADDRESS);
            assert_eq!(calls[3]["params"][1], "0x64");
        }
        let pages = observed
            .requests()
            .iter()
            .map(|page| RecordedRpcPositionHistoryPage {
                request_json: page.request_json().to_owned(),
                response_json: page.response_json().to_owned(),
            })
            .collect::<Vec<_>>();
        let replayed =
            reverify_recorded_current_ctf_v2_context(&census(100), &request(100), &pages)
                .await
                .unwrap();
        assert_eq!(replayed.collateral_address(), observed.collateral_address());
        assert_eq!(replayed.ctf_address(), observed.ctf_address());
        assert_eq!(replayed.block_hash(), observed.block_hash());
        assert_eq!(replayed.request_count(), observed.request_count());
        server.abort();
    }

    #[tokio::test]
    async fn rejects_bad_getters_changed_header_and_insufficient_budget_before_io() {
        let (reader, calls, server) = mock_reader(
            address_word(PUSD_ADDRESS),
            address_word(CTF_EMITTER),
            BTreeMap::new(),
        )
        .await;
        let mut too_few = request(100);
        too_few.max_requests = 4;
        assert_eq!(
            reader
                .read_current_ctf_v2_context(&census(100), &too_few)
                .await
                .unwrap_err(),
            RpcPositionHistoryError::RequestBudgetExceeded
        );
        assert!(calls.lock().unwrap().is_empty());
        server.abort();

        for (collateral, ctf) in [
            (address_word(CTF_EMITTER), address_word(CTF_EMITTER)),
            (json!("0x01"), address_word(CTF_EMITTER)),
            (address_word(PUSD_ADDRESS), address_word(PUSD_ADDRESS)),
        ] {
            let (reader, _, server) = mock_reader(collateral, ctf, BTreeMap::new()).await;
            assert!(
                reader
                    .read_current_ctf_v2_context(&census(100), &request(100))
                    .await
                    .is_err()
            );
            server.abort();
        }

        let (reader, calls, server) = mock_reader(
            address_word(PUSD_ADDRESS),
            address_word(CTF_EMITTER),
            BTreeMap::new(),
        )
        .await;
        let observed = reader
            .read_current_ctf_v2_context(&census(100), &request(100))
            .await
            .unwrap();
        let mut pages = observed
            .requests()
            .iter()
            .map(|page| RecordedRpcPositionHistoryPage {
                request_json: page.request_json().to_owned(),
                response_json: page.response_json().to_owned(),
            })
            .collect::<Vec<_>>();
        let mut response: Value = serde_json::from_str(&pages[4].response_json).unwrap();
        response["result"]["hash"] = json!(format!("0x{}", "ff".repeat(32)));
        pages[4].response_json = response.to_string();
        assert_eq!(
            reverify_recorded_current_ctf_v2_context(&census(100), &request(100), &pages)
                .await
                .unwrap_err(),
            RpcPositionHistoryError::AnchorMismatch
        );
        assert_eq!(calls.lock().unwrap().len(), 5);
        server.abort();
    }
}
