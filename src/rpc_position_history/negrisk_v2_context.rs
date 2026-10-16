//! Bounded provider-reported E222 NegRisk asset/factory context at a census block.
//!
//! Getter observations are bound to the caller-selected block hash. They do not
//! establish contract code identity, historical execution, or a state proof.

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
use crate::collateral_cash::{PUSD_ADDRESS, USDCE_ADDRESS};
use crate::position_history::CTF_EMITTER;

pub const MAX_NEG_RISK_V2_CONTEXT_CALLS: usize = 15;
pub const MAX_NEG_RISK_V2_CONTEXT_TOTAL_BYTES: usize = 256 * 1024;
pub const MAX_NEG_RISK_V2_CONTEXT_TIMEOUT: Duration = Duration::from_secs(30);

const EXCHANGE_ADDRESS: &str = "0xe2222d279d744050d28e00520010520000310f59";
const OUTCOME_TOKEN_FACTORY_ADDRESS: &str = "0xada200001000ef00d07553cee7006808f895c6f1";
const NEG_RISK_ADAPTER_ADDRESS: &str = "0xd91e80cf2e7be2e162c6513ced06f1dd0da35296";
const MAX_COHORT_WALLETS: usize = 100;
const MAX_CENSUS_SPAN: u64 = 2_048;
const MAX_EVENT_HEADERS: usize = 384;

const GET_COLLATERAL_SELECTOR: &str = "0x5c1548fb";
const GET_CTF_SELECTOR: &str = "0x3b521d78";
const GET_OUTCOME_TOKEN_FACTORY_SELECTOR: &str = "0x29cf67f2";
const GET_NEG_RISK_ADAPTER_SELECTOR: &str = "0xf6f88a8d";
const GET_WRAPPED_COLLATERAL_SELECTOR: &str = "0x2d277260";
const GET_CONDITIONAL_TOKENS_SELECTOR: &str = "0x165d1f36";
const GET_COLLATERAL_TOKEN_SELECTOR: &str = "0xf5f1f1a7";
const GET_USDCE_SELECTOR: &str = "0x195187e1";
const GET_VAULT_SELECTOR: &str = "0x411557d1";
const GET_LEGACY_CTF_SELECTOR: &str = "0x22a9339f";
const GET_LEGACY_COLLATERAL_SELECTOR: &str = "0xa78695b0";
const GET_LEGACY_WRAPPED_COLLATERAL_SELECTOR: &str = "0x7e3b74c3";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcCurrentNegRiskV2ContextRequest {
    pub block_number: u64,
    /// Expected provider-reported block hash, compared with the census header.
    pub expected_hash: String,
    pub max_requests: usize,
    pub max_total_response_bytes: usize,
    pub total_timeout: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcCurrentNegRiskV2ContextSource {
    ProviderReported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcCurrentNegRiskV2ImplementationVersion {
    Unbound,
}

/// Getter relationships observed at one selected Polygon block.
///
/// The WCOL address is provider-reported and dynamically returned by the
/// configured factory; it is not pinned to a receipt emitter address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcCurrentNegRiskV2Context {
    block_number: u64,
    block_hash: String,
    exchange_address: String,
    collateral_address: String,
    ctf_address: String,
    outcome_token_factory_address: String,
    neg_risk_adapter_address: String,
    wrapped_collateral_address: String,
    underlying_collateral_address: String,
    vault_address: String,
    source: RpcCurrentNegRiskV2ContextSource,
    implementation_version: RpcCurrentNegRiskV2ImplementationVersion,
    captured_started_at: DateTime<Utc>,
    captured_completed_at: DateTime<Utc>,
    elapsed: Duration,
    request_count: usize,
    response_bytes: usize,
    pages: Vec<RpcPositionHistoryPage>,
}

impl RpcCurrentNegRiskV2Context {
    #[must_use]
    pub const fn block_number(&self) -> u64 {
        self.block_number
    }

    #[must_use]
    pub fn block_hash(&self) -> &str {
        &self.block_hash
    }

    #[must_use]
    pub fn exchange_address(&self) -> &str {
        &self.exchange_address
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
    pub fn outcome_token_factory_address(&self) -> &str {
        &self.outcome_token_factory_address
    }

    #[must_use]
    pub fn neg_risk_adapter_address(&self) -> &str {
        &self.neg_risk_adapter_address
    }

    #[must_use]
    pub fn wrapped_collateral_address(&self) -> &str {
        &self.wrapped_collateral_address
    }

    #[must_use]
    pub fn underlying_collateral_address(&self) -> &str {
        &self.underlying_collateral_address
    }

    #[must_use]
    pub fn vault_address(&self) -> &str {
        &self.vault_address
    }

    #[must_use]
    pub const fn source(&self) -> RpcCurrentNegRiskV2ContextSource {
        self.source
    }

    #[must_use]
    pub const fn implementation_version(&self) -> RpcCurrentNegRiskV2ImplementationVersion {
        self.implementation_version
    }

    #[must_use]
    pub const fn captured_started_at(&self) -> DateTime<Utc> {
        self.captured_started_at
    }

    #[must_use]
    pub const fn captured_completed_at(&self) -> DateTime<Utc> {
        self.captured_completed_at
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
    pub fn pages(&self) -> &[RpcPositionHistoryPage] {
        &self.pages
    }
}

impl RpcPositionHistoryReader {
    /// Read the E222 exchange, factory, and legacy adapter getter chain at a
    /// block already represented by the current interval census.
    pub async fn read_current_neg_risk_v2_context(
        &self,
        census: &RpcCurrentIntervalCensus,
        request: &RpcCurrentNegRiskV2ContextRequest,
    ) -> Result<RpcCurrentNegRiskV2Context, RpcPositionHistoryError> {
        let timer = Instant::now();
        let captured_started_at = Utc::now();
        let mut source = CurrentIntervalRpcCallSource::Network(self);
        read_context_inner(census, request, &mut source, timer, captured_started_at).await
    }
}

/// Revalidate the exact fifteen recorded frames without issuing RPC calls.
/// Timing fields describe this local replay, not the original capture window.
pub async fn reverify_recorded_current_neg_risk_v2_context(
    census: &RpcCurrentIntervalCensus,
    request: &RpcCurrentNegRiskV2ContextRequest,
    pages: &[RecordedRpcPositionHistoryPage],
) -> Result<RpcCurrentNegRiskV2Context, RpcPositionHistoryError> {
    let timer = Instant::now();
    let captured_started_at = Utc::now();
    let mut source = CurrentIntervalRpcCallSource::Recorded {
        pages,
        next_page: 0,
    };
    read_context_inner(census, request, &mut source, timer, captured_started_at).await
}

async fn read_context_inner(
    census: &RpcCurrentIntervalCensus,
    request: &RpcCurrentNegRiskV2ContextRequest,
    source: &mut CurrentIntervalRpcCallSource<'_>,
    timer: Instant,
    captured_started_at: DateTime<Utc>,
) -> Result<RpcCurrentNegRiskV2Context, RpcPositionHistoryError> {
    let census_header = validate_inputs(census, request)?;
    if request.max_requests < MAX_NEG_RISK_V2_CONTEXT_CALLS {
        return Err(RpcPositionHistoryError::RequestBudgetExceeded);
    }
    source.validate_count(MAX_NEG_RISK_V2_CONTEXT_CALLS)?;

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
        pages: Vec::with_capacity(MAX_NEG_RISK_V2_CONTEXT_CALLS),
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

    let collateral = read_getter(
        source,
        EXCHANGE_ADDRESS,
        GET_COLLATERAL_SELECTOR,
        &block_tag,
        deadline,
        &transport,
        &mut state,
    )
    .await?;
    let ctf = read_getter(
        source,
        EXCHANGE_ADDRESS,
        GET_CTF_SELECTOR,
        &block_tag,
        deadline,
        &transport,
        &mut state,
    )
    .await?;
    let factory = read_getter(
        source,
        EXCHANGE_ADDRESS,
        GET_OUTCOME_TOKEN_FACTORY_SELECTOR,
        &block_tag,
        deadline,
        &transport,
        &mut state,
    )
    .await?;
    ensure_distinct(&[
        EXCHANGE_ADDRESS,
        PUSD_ADDRESS,
        CTF_EMITTER,
        OUTCOME_TOKEN_FACTORY_ADDRESS,
        NEG_RISK_ADAPTER_ADDRESS,
        USDCE_ADDRESS,
    ])?;
    if collateral != PUSD_ADDRESS || ctf != CTF_EMITTER || factory != OUTCOME_TOKEN_FACTORY_ADDRESS
    {
        return Err(RpcPositionHistoryError::MalformedResponse);
    }

    let neg_risk_adapter = read_getter(
        source,
        &factory,
        GET_NEG_RISK_ADAPTER_SELECTOR,
        &block_tag,
        deadline,
        &transport,
        &mut state,
    )
    .await?;
    let wrapped_collateral = read_getter(
        source,
        &factory,
        GET_WRAPPED_COLLATERAL_SELECTOR,
        &block_tag,
        deadline,
        &transport,
        &mut state,
    )
    .await?;
    let factory_ctf = read_getter(
        source,
        &factory,
        GET_CONDITIONAL_TOKENS_SELECTOR,
        &block_tag,
        deadline,
        &transport,
        &mut state,
    )
    .await?;
    let factory_collateral = read_getter(
        source,
        &factory,
        GET_COLLATERAL_TOKEN_SELECTOR,
        &block_tag,
        deadline,
        &transport,
        &mut state,
    )
    .await?;
    let underlying_collateral = read_getter(
        source,
        &factory,
        GET_USDCE_SELECTOR,
        &block_tag,
        deadline,
        &transport,
        &mut state,
    )
    .await?;
    let vault = read_getter(
        source,
        PUSD_ADDRESS,
        GET_VAULT_SELECTOR,
        &block_tag,
        deadline,
        &transport,
        &mut state,
    )
    .await?;
    ensure_distinct(&[
        EXCHANGE_ADDRESS,
        PUSD_ADDRESS,
        CTF_EMITTER,
        OUTCOME_TOKEN_FACTORY_ADDRESS,
        NEG_RISK_ADAPTER_ADDRESS,
        USDCE_ADDRESS,
        &wrapped_collateral,
        &vault,
    ])?;
    if neg_risk_adapter != NEG_RISK_ADAPTER_ADDRESS
        || factory_ctf != CTF_EMITTER
        || factory_collateral != PUSD_ADDRESS
        || underlying_collateral != USDCE_ADDRESS
    {
        return Err(RpcPositionHistoryError::MalformedResponse);
    }

    let legacy_ctf = read_getter(
        source,
        &neg_risk_adapter,
        GET_LEGACY_CTF_SELECTOR,
        &block_tag,
        deadline,
        &transport,
        &mut state,
    )
    .await?;
    let legacy_collateral = read_getter(
        source,
        &neg_risk_adapter,
        GET_LEGACY_COLLATERAL_SELECTOR,
        &block_tag,
        deadline,
        &transport,
        &mut state,
    )
    .await?;
    let legacy_wrapped_collateral = read_getter(
        source,
        &neg_risk_adapter,
        GET_LEGACY_WRAPPED_COLLATERAL_SELECTOR,
        &block_tag,
        deadline,
        &transport,
        &mut state,
    )
    .await?;
    if legacy_ctf != CTF_EMITTER
        || legacy_collateral != underlying_collateral
        || legacy_wrapped_collateral != wrapped_collateral
    {
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
    if state.next_id.saturating_sub(1) as usize != MAX_NEG_RISK_V2_CONTEXT_CALLS
        || state.response_bytes > request.max_total_response_bytes
        || Instant::now() >= deadline
    {
        return Err(if Instant::now() >= deadline {
            RpcPositionHistoryError::Timeout
        } else {
            RpcPositionHistoryError::MalformedResponse
        });
    }
    source.finish()?;

    Ok(RpcCurrentNegRiskV2Context {
        block_number: request.block_number,
        block_hash: census_header.hash,
        exchange_address: EXCHANGE_ADDRESS.to_owned(),
        collateral_address: collateral,
        ctf_address: ctf,
        outcome_token_factory_address: factory,
        neg_risk_adapter_address: neg_risk_adapter,
        wrapped_collateral_address: wrapped_collateral,
        underlying_collateral_address: underlying_collateral,
        vault_address: vault,
        source: RpcCurrentNegRiskV2ContextSource::ProviderReported,
        implementation_version: RpcCurrentNegRiskV2ImplementationVersion::Unbound,
        captured_started_at,
        captured_completed_at: Utc::now(),
        elapsed: timer.elapsed(),
        request_count: state.next_id.saturating_sub(1) as usize,
        response_bytes: state.response_bytes,
        pages: state.pages,
    })
}

async fn read_getter(
    source: &mut CurrentIntervalRpcCallSource<'_>,
    target: &str,
    selector: &str,
    block_tag: &str,
    deadline: Instant,
    transport: &RpcPositionHistoryRequest,
    state: &mut ReadState,
) -> Result<String, RpcPositionHistoryError> {
    let result = source
        .call(
            "eth_call",
            json!([{"to":target,"data":selector}, block_tag]),
            deadline,
            transport,
            state,
        )
        .await?;
    decode_nonzero_canonical_address(&result)
}

fn decode_nonzero_canonical_address(result: &Value) -> Result<String, RpcPositionHistoryError> {
    let text = result
        .as_str()
        .and_then(|text| text.strip_prefix("0x"))
        .ok_or(RpcPositionHistoryError::MalformedResponse)?;
    let word = hex::decode(text).map_err(|_| RpcPositionHistoryError::MalformedResponse)?;
    if word.len() != 32 || word[..12].iter().any(|byte| *byte != 0) {
        return Err(RpcPositionHistoryError::MalformedResponse);
    }
    let address = normalize_address(&format!("0x{}", hex::encode(&word[12..])))
        .ok_or(RpcPositionHistoryError::MalformedResponse)?;
    if address == format!("0x{}", "00".repeat(20)) {
        return Err(RpcPositionHistoryError::MalformedResponse);
    }
    Ok(address)
}

fn ensure_distinct(addresses: &[&str]) -> Result<(), RpcPositionHistoryError> {
    for (index, address) in addresses.iter().enumerate() {
        if addresses[..index].contains(address) {
            return Err(RpcPositionHistoryError::MalformedResponse);
        }
    }
    Ok(())
}

fn validate_inputs(
    census: &RpcCurrentIntervalCensus,
    request: &RpcCurrentNegRiskV2ContextRequest,
) -> Result<super::current_interval_census::RpcCurrentIntervalHeader, RpcPositionHistoryError> {
    if census.source != RpcCurrentIntervalSource::ProviderReported
        || census.wallets.is_empty()
        || census.wallets.len() > MAX_COHORT_WALLETS
        || census.start_block >= census.through_block
        || census.start_header.number != census.start_block
        || census.end_header.number != census.through_block
        || census
            .through_block
            .checked_sub(census.start_block)
            .is_none_or(|span| span > MAX_CENSUS_SPAN)
        || census.event_headers.len() > MAX_EVENT_HEADERS
        || request.block_number <= census.start_block
        || request.block_number > census.through_block
        || request.max_requests == 0
        || request.max_requests > MAX_HISTORY_REQUESTS
        || request.max_total_response_bytes == 0
        || request.max_total_response_bytes > MAX_NEG_RISK_V2_CONTEXT_TOTAL_BYTES
        || request.total_timeout.is_zero()
        || request.total_timeout > MAX_NEG_RISK_V2_CONTEXT_TIMEOUT
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
    let mut matched = None;
    for header in &census.event_headers {
        if header.number == request.block_number {
            if matched.is_some() {
                return Err(RpcPositionHistoryError::MalformedResponse);
            }
            matched = Some(header);
        }
    }
    let header = matched.ok_or(RpcPositionHistoryError::InvalidInput)?;
    if header.hash != request.expected_hash {
        return Err(RpcPositionHistoryError::AnchorMismatch);
    }
    Ok((*header).clone())
}

#[cfg(test)]
pub(crate) fn test_negrisk_v2_context(
    block_number: u64,
    block_hash: &str,
) -> RpcCurrentNegRiskV2Context {
    RpcCurrentNegRiskV2Context {
        block_number,
        block_hash: block_hash.to_owned(),
        exchange_address: EXCHANGE_ADDRESS.to_owned(),
        collateral_address: PUSD_ADDRESS.to_owned(),
        ctf_address: CTF_EMITTER.to_owned(),
        outcome_token_factory_address: OUTCOME_TOKEN_FACTORY_ADDRESS.to_owned(),
        neg_risk_adapter_address: NEG_RISK_ADAPTER_ADDRESS.to_owned(),
        // Receipt emitter used only for core fixtures. Live capture accepts and
        // returns the observed distinct factory/legacy getter agreement.
        wrapped_collateral_address: "0x3a3bd7bb9528e159577f7c2e685cc81a765002e2".to_owned(),
        underlying_collateral_address: USDCE_ADDRESS.to_owned(),
        vault_address: "0x4444444444444444444444444444444444444444".to_owned(),
        source: RpcCurrentNegRiskV2ContextSource::ProviderReported,
        implementation_version: RpcCurrentNegRiskV2ImplementationVersion::Unbound,
        captured_started_at: Utc::now(),
        captured_completed_at: Utc::now(),
        elapsed: Duration::ZERO,
        request_count: MAX_NEG_RISK_V2_CONTEXT_CALLS,
        response_bytes: 0,
        pages: Vec::new(),
    }
}

#[cfg(test)]
pub(crate) fn test_negrisk_v2_context_recorded_pages(
    context: &RpcCurrentNegRiskV2Context,
) -> Vec<RecordedRpcPositionHistoryPage> {
    context
        .pages()
        .iter()
        .map(|page| RecordedRpcPositionHistoryPage {
            request_json: page.request_json().to_owned(),
            response_json: page.response_json().to_owned(),
        })
        .collect()
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
    use tokio::task::JoinHandle;

    const WRAPPED_COLLATERAL: &str = "0x3a3bd7bb9528e159577f7c2e685cc81a765002e2";

    #[derive(Clone)]
    struct MockState {
        calls: Arc<Mutex<Vec<Value>>>,
        headers: BTreeMap<String, Value>,
        override_results: BTreeMap<String, Value>,
        wrong_after_hash: bool,
        header_calls: Arc<Mutex<usize>>,
    }

    async fn mock_rpc(State(state): State<MockState>, body: Bytes) -> Json<Value> {
        let request: Value = serde_json::from_slice(&body).unwrap();
        let method = request["method"].as_str().unwrap();
        let result = match method {
            "eth_chainId" => json!("0x89"),
            "eth_getBlockByNumber" => {
                let mut calls = state.header_calls.lock().unwrap();
                *calls += 1;
                let tag = request["params"][0].as_str().unwrap();
                if state.wrong_after_hash && *calls == 2 {
                    let mut changed = header(100);
                    changed["hash"] = json!(format!("0x{}", "ff".repeat(32)));
                    changed
                } else {
                    state
                        .headers
                        .get(tag)
                        .cloned()
                        .unwrap_or_else(|| header(100))
                }
            }
            "eth_call" => {
                let data = request["params"][0]["data"].as_str().unwrap();
                state
                    .override_results
                    .get(data)
                    .cloned()
                    .unwrap_or_else(|| result_for(data))
            }
            other => panic!("unexpected RPC method {other}"),
        };
        state.calls.lock().unwrap().push(request.clone());
        Json(json!({"jsonrpc":"2.0", "id":request["id"], "result":result}))
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

    fn result_for(selector: &str) -> Value {
        address_word(match selector {
            GET_COLLATERAL_SELECTOR | GET_COLLATERAL_TOKEN_SELECTOR => PUSD_ADDRESS,
            GET_CTF_SELECTOR | GET_CONDITIONAL_TOKENS_SELECTOR | GET_LEGACY_CTF_SELECTOR => {
                CTF_EMITTER
            }
            GET_OUTCOME_TOKEN_FACTORY_SELECTOR => OUTCOME_TOKEN_FACTORY_ADDRESS,
            GET_NEG_RISK_ADAPTER_SELECTOR => NEG_RISK_ADAPTER_ADDRESS,
            GET_WRAPPED_COLLATERAL_SELECTOR | GET_LEGACY_WRAPPED_COLLATERAL_SELECTOR => {
                WRAPPED_COLLATERAL
            }
            GET_VAULT_SELECTOR => "0x4444444444444444444444444444444444444444",
            GET_USDCE_SELECTOR | GET_LEGACY_COLLATERAL_SELECTOR => USDCE_ADDRESS,
            other => panic!("unexpected getter selector {other}"),
        })
    }

    fn census(block_number: u64) -> RpcCurrentIntervalCensus {
        let end = parse_header(&header(block_number)).unwrap();
        RpcCurrentIntervalCensus {
            wallets: vec!["0x1111111111111111111111111111111111111111".to_owned()],
            start_block: block_number - 1,
            through_block: block_number,
            start_header: RpcCurrentIntervalHeader {
                number: block_number - 1,
                hash: header(block_number - 1)["hash"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                timestamp: 1_800_000_000 + block_number - 1,
            },
            end_header: RpcCurrentIntervalHeader {
                number: block_number,
                hash: end.hash.clone(),
                timestamp: 1_800_000_000 + block_number,
            },
            event_headers: vec![RpcCurrentIntervalHeader {
                number: block_number,
                hash: end.hash,
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

    fn request(block_number: u64) -> RpcCurrentNegRiskV2ContextRequest {
        RpcCurrentNegRiskV2ContextRequest {
            block_number,
            expected_hash: header(block_number)["hash"].as_str().unwrap().to_owned(),
            max_requests: MAX_NEG_RISK_V2_CONTEXT_CALLS,
            max_total_response_bytes: MAX_NEG_RISK_V2_CONTEXT_TOTAL_BYTES,
            total_timeout: Duration::from_secs(5),
        }
    }

    async fn mock_reader(
        override_results: BTreeMap<String, Value>,
        wrong_after_hash: bool,
    ) -> (
        RpcPositionHistoryReader,
        Arc<Mutex<Vec<Value>>>,
        JoinHandle<()>,
    ) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/", post(mock_rpc))
            .with_state(MockState {
                calls: calls.clone(),
                headers: BTreeMap::new(),
                override_results,
                wrong_after_hash,
                header_calls: Arc::new(Mutex::new(0)),
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
    async fn reads_getter_chain_and_replays_exact_fifteen_frames() {
        let (reader, calls, server) = mock_reader(BTreeMap::new(), false).await;
        let observed = reader
            .read_current_neg_risk_v2_context(&census(100), &request(100))
            .await
            .unwrap();
        assert_eq!(observed.request_count(), MAX_NEG_RISK_V2_CONTEXT_CALLS);
        assert_eq!(observed.pages().len(), MAX_NEG_RISK_V2_CONTEXT_CALLS);
        assert_eq!(observed.exchange_address(), EXCHANGE_ADDRESS);
        assert_eq!(observed.collateral_address(), PUSD_ADDRESS);
        assert_eq!(observed.ctf_address(), CTF_EMITTER);
        assert_eq!(
            observed.outcome_token_factory_address(),
            OUTCOME_TOKEN_FACTORY_ADDRESS
        );
        assert_eq!(
            observed.neg_risk_adapter_address(),
            NEG_RISK_ADAPTER_ADDRESS
        );
        assert_eq!(observed.wrapped_collateral_address(), WRAPPED_COLLATERAL);
        assert_eq!(observed.underlying_collateral_address(), USDCE_ADDRESS);
        assert_eq!(
            observed.vault_address(),
            "0x4444444444444444444444444444444444444444"
        );
        assert_eq!(
            observed.source(),
            RpcCurrentNegRiskV2ContextSource::ProviderReported
        );
        assert_eq!(
            observed.implementation_version(),
            RpcCurrentNegRiskV2ImplementationVersion::Unbound
        );
        let requests = calls.lock().unwrap().clone();
        assert_eq!(requests.len(), MAX_NEG_RISK_V2_CONTEXT_CALLS);
        let expected = [
            ("eth_chainId", None, None),
            ("eth_getBlockByNumber", None, None),
            (
                "eth_call",
                Some(EXCHANGE_ADDRESS),
                Some(GET_COLLATERAL_SELECTOR),
            ),
            ("eth_call", Some(EXCHANGE_ADDRESS), Some(GET_CTF_SELECTOR)),
            (
                "eth_call",
                Some(EXCHANGE_ADDRESS),
                Some(GET_OUTCOME_TOKEN_FACTORY_SELECTOR),
            ),
            (
                "eth_call",
                Some(OUTCOME_TOKEN_FACTORY_ADDRESS),
                Some(GET_NEG_RISK_ADAPTER_SELECTOR),
            ),
            (
                "eth_call",
                Some(OUTCOME_TOKEN_FACTORY_ADDRESS),
                Some(GET_WRAPPED_COLLATERAL_SELECTOR),
            ),
            (
                "eth_call",
                Some(OUTCOME_TOKEN_FACTORY_ADDRESS),
                Some(GET_CONDITIONAL_TOKENS_SELECTOR),
            ),
            (
                "eth_call",
                Some(OUTCOME_TOKEN_FACTORY_ADDRESS),
                Some(GET_COLLATERAL_TOKEN_SELECTOR),
            ),
            (
                "eth_call",
                Some(OUTCOME_TOKEN_FACTORY_ADDRESS),
                Some(GET_USDCE_SELECTOR),
            ),
            ("eth_call", Some(PUSD_ADDRESS), Some(GET_VAULT_SELECTOR)),
            (
                "eth_call",
                Some(NEG_RISK_ADAPTER_ADDRESS),
                Some(GET_LEGACY_CTF_SELECTOR),
            ),
            (
                "eth_call",
                Some(NEG_RISK_ADAPTER_ADDRESS),
                Some(GET_LEGACY_COLLATERAL_SELECTOR),
            ),
            (
                "eth_call",
                Some(NEG_RISK_ADAPTER_ADDRESS),
                Some(GET_LEGACY_WRAPPED_COLLATERAL_SELECTOR),
            ),
            ("eth_getBlockByNumber", None, None),
        ];
        for (request, (method, target, selector)) in requests.iter().zip(expected) {
            assert_eq!(request["method"], method);
            if let Some(target) = target {
                assert_eq!(request["params"][0]["to"], target);
                assert_eq!(request["params"][0]["data"], selector.unwrap());
                assert_eq!(request["params"][1], "0x64");
            }
        }

        let replay = reverify_recorded_current_neg_risk_v2_context(
            &census(100),
            &request(100),
            &test_negrisk_v2_context_recorded_pages(&observed),
        )
        .await
        .unwrap();
        assert_eq!(replay.block_hash(), observed.block_hash());
        assert_eq!(replay.wrapped_collateral_address(), WRAPPED_COLLATERAL);
        assert_eq!(replay.request_count(), 15);
        server.abort();
    }

    #[tokio::test]
    async fn rejects_conflicting_getters_noncanonical_words_and_moved_after_header() {
        let cases = [
            (GET_NEG_RISK_ADAPTER_SELECTOR, address_word(CTF_EMITTER)),
            (GET_WRAPPED_COLLATERAL_SELECTOR, address_word(USDCE_ADDRESS)),
            (GET_LEGACY_COLLATERAL_SELECTOR, address_word(PUSD_ADDRESS)),
            (GET_VAULT_SELECTOR, address_word(USDCE_ADDRESS)),
            (
                GET_COLLATERAL_SELECTOR,
                json!(format!("0x{}{}", "01".repeat(12), &PUSD_ADDRESS[2..])),
            ),
            (
                GET_COLLATERAL_SELECTOR,
                address_word("0x0000000000000000000000000000000000000000"),
            ),
        ];
        for (selector, bad_result) in cases {
            let (reader, _, server) =
                mock_reader(BTreeMap::from([(selector.to_owned(), bad_result)]), false).await;
            assert_eq!(
                reader
                    .read_current_neg_risk_v2_context(&census(100), &request(100))
                    .await
                    .unwrap_err(),
                RpcPositionHistoryError::MalformedResponse,
                "selector {selector}"
            );
            server.abort();
        }

        let (reader, _, server) = mock_reader(BTreeMap::new(), true).await;
        assert_eq!(
            reader
                .read_current_neg_risk_v2_context(&census(100), &request(100))
                .await
                .unwrap_err(),
            RpcPositionHistoryError::AnchorMismatch
        );
        server.abort();
    }

    #[tokio::test]
    async fn rejects_insufficient_budget_before_network_io_and_invalid_census() {
        let (reader, calls, server) = mock_reader(BTreeMap::new(), false).await;
        let mut insufficient = request(100);
        insufficient.max_requests = MAX_NEG_RISK_V2_CONTEXT_CALLS - 1;
        assert_eq!(
            reader
                .read_current_neg_risk_v2_context(&census(100), &insufficient)
                .await
                .unwrap_err(),
            RpcPositionHistoryError::RequestBudgetExceeded
        );
        assert!(calls.lock().unwrap().is_empty());

        let mut oversized_bytes = request(100);
        oversized_bytes.max_total_response_bytes = MAX_NEG_RISK_V2_CONTEXT_TOTAL_BYTES + 1;
        assert_eq!(
            reader
                .read_current_neg_risk_v2_context(&census(100), &oversized_bytes)
                .await
                .unwrap_err(),
            RpcPositionHistoryError::InvalidInput
        );
        let mut excessive_timeout = request(100);
        excessive_timeout.total_timeout = MAX_NEG_RISK_V2_CONTEXT_TIMEOUT + Duration::from_secs(1);
        assert_eq!(
            reader
                .read_current_neg_risk_v2_context(&census(100), &excessive_timeout)
                .await
                .unwrap_err(),
            RpcPositionHistoryError::InvalidInput
        );
        assert!(calls.lock().unwrap().is_empty());

        let mut wrong_hash = census(100);
        wrong_hash.event_headers[0].hash = format!("0x{}", "ff".repeat(32));
        assert_eq!(
            reader
                .read_current_neg_risk_v2_context(&wrong_hash, &request(100))
                .await
                .unwrap_err(),
            RpcPositionHistoryError::AnchorMismatch
        );
        assert!(calls.lock().unwrap().is_empty());
        server.abort();
    }

    #[tokio::test]
    async fn replay_rejects_wrong_frame_count_and_mutated_getter_frame() {
        let (reader, _, server) = mock_reader(BTreeMap::new(), false).await;
        let observed = reader
            .read_current_neg_risk_v2_context(&census(100), &request(100))
            .await
            .unwrap();
        let pages = test_negrisk_v2_context_recorded_pages(&observed);
        assert_eq!(
            reverify_recorded_current_neg_risk_v2_context(
                &census(100),
                &request(100),
                &pages[..14]
            )
            .await
            .unwrap_err(),
            RpcPositionHistoryError::MalformedResponse
        );
        let mut mutated = pages;
        let response: Value = serde_json::from_str(&mutated[5].response_json).unwrap();
        let mut response = response;
        response["result"] = address_word(CTF_EMITTER);
        mutated[5].response_json = response.to_string();
        assert_eq!(
            reverify_recorded_current_neg_risk_v2_context(&census(100), &request(100), &mutated)
                .await
                .unwrap_err(),
            RpcPositionHistoryError::MalformedResponse
        );
        server.abort();
    }
}
