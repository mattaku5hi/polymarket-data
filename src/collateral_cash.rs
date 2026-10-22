//! Bounded provider observations of Polygon pUSD and USDC.e balances, plus
//! pure composition with current venue-reported position values.
//!
//! Live reads batch balances through chunked Multicall3 `aggregate3` calls at
//! one pinned finalized block (artifact version 2). Version 1 artifacts that
//! used one `eth_call` per balance still replay.
//!
//! Cash is a same-block provider attestation. It does not verify state roots
//! or establish portfolio NAV. The composition API uses exact Decimal sums
//! over mixed capture windows and does not establish completeness or peg value.

use std::{collections::HashSet, net::IpAddr, time::Duration};

use chrono::{DateTime, Utc};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::time::timeout;

mod mark_composition;
pub use mark_composition::{
    CurrentPortfolioEstimateSet, CurrentWalletEstimate, CurrentWalletEstimateWithCashEvidence,
    MarkCompositionError, compose_current_portfolio_estimates, compose_current_wallet_estimate,
};

pub const POLYGON_CHAIN_ID: u64 = 137;
pub const MAX_COLLATERAL_WALLETS: usize = 100;
pub const MAX_COLLATERAL_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;
pub const PUSD_ADDRESS: &str = "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb";
pub const USDCE_ADDRESS: &str = "0x2791bca1f2de4661ed88a30c99a7a9449aa84174";
/// Canonical Multicall3 deployment (identical address on Polygon).
pub const MULTICALL3_ADDRESS: &str = "0xca11bde05977b3631167028862be2a173976ca11";
/// Wallets per `aggregate3` call; each wallet adds two `balanceOf` sub-calls.
/// Keeps every JSON-RPC response far below the per-frame byte cap.
pub const MULTICALL_WALLETS_PER_CHUNK: usize = 50;
/// Minimum spacing between the starts of consecutive JSON-RPC requests of one
/// read, keeping a provider's credits-per-second budget safe.
pub const MIN_RPC_REQUEST_INTERVAL: Duration = Duration::from_millis(200);
const TOKEN_DECIMALS: u8 = 6;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RPC_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_TOTAL_RESPONSE_BYTES: usize = 1024 * 1024;
const BALANCE_OF_SELECTOR: &str = "70a08231";
const DECIMALS_SELECTOR: &str = "313ce567";
const AGGREGATE3_SELECTOR: [u8; 4] = [0x82, 0xad, 0x56, 0xcb];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollateralCashSource {
    ProviderReported,
}

impl CollateralCashSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        "PROVIDER_REPORTED"
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralAsset {
    Pusd,
    UsdcE,
}

impl CollateralAsset {
    #[must_use]
    pub const fn address(self) -> &'static str {
        match self {
            Self::Pusd => PUSD_ADDRESS,
            Self::UsdcE => USDCE_ADDRESS,
        }
    }

    #[must_use]
    pub const fn decimals(self) -> u8 {
        TOKEN_DECIMALS
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollateralCashBlock {
    pub chain_id: u64,
    pub number: u64,
    pub hash: String,
    /// Unix seconds as reported by the provider's finalized header.
    pub timestamp: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollateralBalance {
    pub wallet: String,
    pub asset: CollateralAsset,
    /// ABI-encoded uint256. Kept raw so callers choose their own arithmetic.
    pub balance_word: [u8; 32],
    pub decimals: u8,
}

#[derive(Clone, PartialEq, Eq)]
pub struct CollateralRpcEvidence {
    method: String,
    request_id: u64,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    request_body: Vec<u8>,
    response_body: Vec<u8>,
}

impl std::fmt::Debug for CollateralRpcEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CollateralRpcEvidence")
            .field("method", &self.method)
            .field("request_id", &self.request_id)
            .field("started_at", &self.started_at)
            .field("completed_at", &self.completed_at)
            .field("request_body_bytes", &self.request_body.len())
            .field("response_body_bytes", &self.response_body.len())
            .finish()
    }
}

impl CollateralRpcEvidence {
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    #[must_use]
    pub const fn started_at(&self) -> &DateTime<Utc> {
        &self.started_at
    }

    #[must_use]
    pub const fn completed_at(&self) -> &DateTime<Utc> {
        &self.completed_at
    }

    /// Exact JSON-RPC request bytes. The RPC endpoint and its credentials are
    /// never part of this capture.
    #[must_use]
    pub fn request_body(&self) -> &[u8] {
        &self.request_body
    }

    /// Exact successful HTTP response bytes from the provider.
    #[must_use]
    pub fn response_body(&self) -> &[u8] {
        &self.response_body
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollateralCashSnapshot {
    pub source: CollateralCashSource,
    pub block: CollateralCashBlock,
    pub wallets: Vec<String>,
    pub balances: Vec<CollateralBalance>,
    pub requests: Vec<CollateralRpcEvidence>,
}

impl CollateralCashSnapshot {
    /// Serialize this snapshot as a bounded, versioned, endpoint-free artifact.
    /// The artifact stores each raw JSON-RPC frame as a string to preserve its
    /// exact bytes and validates all derived fields before writing.
    pub fn to_artifact(&self) -> Result<Vec<u8>, CollateralCashError> {
        let layout = validate_snapshot(self)?;
        let artifact = CollateralCashArtifact {
            version: layout.artifact_version(),
            source: self.source.as_str().to_owned(),
            block: ArtifactBlock {
                chain_id: self.block.chain_id,
                number: self.block.number,
                hash: self.block.hash.clone(),
                timestamp: self.block.timestamp,
            },
            wallets: self.wallets.clone(),
            balances: self
                .balances
                .iter()
                .map(|balance| ArtifactBalance {
                    wallet: balance.wallet.clone(),
                    asset: balance.asset,
                    balance_word: format!("0x{}", encode_hex(&balance.balance_word)),
                    decimals: balance.decimals,
                })
                .collect(),
            requests: self
                .requests
                .iter()
                .map(|request| {
                    Ok(ArtifactRequest {
                        method: request.method.clone(),
                        request_id: request.request_id,
                        started_at: request.started_at,
                        completed_at: request.completed_at,
                        request_body: String::from_utf8(request.request_body.clone())
                            .map_err(|_| CollateralCashError::InvalidArtifact)?,
                        response_body: String::from_utf8(request.response_body.clone())
                            .map_err(|_| CollateralCashError::InvalidArtifact)?,
                    })
                })
                .collect::<Result<Vec<_>, CollateralCashError>>()?,
        };
        let bytes =
            serde_json::to_vec(&artifact).map_err(|_| CollateralCashError::InvalidArtifact)?;
        if bytes.len() > MAX_COLLATERAL_ARTIFACT_BYTES {
            return Err(CollateralCashError::ArtifactTooLarge);
        }
        Ok(bytes)
    }

    /// Parse and offline-validate a bounded collateral cash artifact.
    /// Returned balances and block metadata are reconstructed from the raw
    /// frames and compared with the artifact's stored projections.
    pub fn from_artifact(bytes: &[u8]) -> Result<Self, CollateralCashError> {
        if bytes.len() > MAX_COLLATERAL_ARTIFACT_BYTES {
            return Err(CollateralCashError::ArtifactTooLarge);
        }
        let artifact: CollateralCashArtifact =
            serde_json::from_slice(bytes).map_err(|_| CollateralCashError::InvalidArtifact)?;
        if !matches!(
            artifact.version,
            COLLATERAL_CASH_ARTIFACT_VERSION_SINGLE_CALLS
                | COLLATERAL_CASH_ARTIFACT_VERSION_MULTICALL
        ) || artifact.source != CollateralCashSource::ProviderReported.as_str()
        {
            return Err(CollateralCashError::InvalidArtifact);
        }
        let version = artifact.version;
        let snapshot = Self {
            source: CollateralCashSource::ProviderReported,
            block: CollateralCashBlock {
                chain_id: artifact.block.chain_id,
                number: artifact.block.number,
                hash: artifact.block.hash,
                timestamp: artifact.block.timestamp,
            },
            wallets: artifact.wallets,
            balances: artifact
                .balances
                .into_iter()
                .map(|balance| {
                    Ok(CollateralBalance {
                        wallet: balance.wallet,
                        asset: balance.asset,
                        balance_word: parse_word(&balance.balance_word)
                            .map_err(|_| CollateralCashError::InvalidArtifact)?,
                        decimals: balance.decimals,
                    })
                })
                .collect::<Result<Vec<_>, CollateralCashError>>()?,
            requests: artifact
                .requests
                .into_iter()
                .map(|request| CollateralRpcEvidence {
                    method: request.method,
                    request_id: request.request_id,
                    started_at: request.started_at,
                    completed_at: request.completed_at,
                    request_body: request.request_body.into_bytes(),
                    response_body: request.response_body.into_bytes(),
                })
                .collect(),
        };
        if validate_snapshot(&snapshot)?.artifact_version() != version {
            return Err(CollateralCashError::InvalidArtifact);
        }
        Ok(snapshot)
    }
}

/// Version 1: one `eth_call` per decimals/balance. Replay only.
const COLLATERAL_CASH_ARTIFACT_VERSION_SINGLE_CALLS: u8 = 1;
/// Version 2: chunked Multicall3 `aggregate3` reads.
const COLLATERAL_CASH_ARTIFACT_VERSION_MULTICALL: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadLayout {
    SingleCalls,
    Multicall,
}

impl ReadLayout {
    const fn artifact_version(self) -> u8 {
        match self {
            Self::SingleCalls => COLLATERAL_CASH_ARTIFACT_VERSION_SINGLE_CALLS,
            Self::Multicall => COLLATERAL_CASH_ARTIFACT_VERSION_MULTICALL,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CollateralCashArtifact {
    version: u8,
    source: String,
    block: ArtifactBlock,
    wallets: Vec<String>,
    balances: Vec<ArtifactBalance>,
    requests: Vec<ArtifactRequest>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactBlock {
    chain_id: u64,
    number: u64,
    hash: String,
    timestamp: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactBalance {
    wallet: String,
    asset: CollateralAsset,
    balance_word: String,
    decimals: u8,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactRequest {
    method: String,
    request_id: u64,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    /// Raw JSON kept as a string so artifact parsing cannot normalize bytes.
    request_body: String,
    response_body: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CollateralCashError {
    #[error("collateral cash input is invalid")]
    InvalidInput,
    #[error("collateral cash RPC endpoint must use HTTPS or loopback HTTP")]
    InvalidEndpoint,
    #[error("collateral cash RPC request failed")]
    RequestFailed,
    #[error("collateral cash RPC returned HTTP {0}")]
    HttpStatus(u16),
    #[error("collateral cash RPC request timed out")]
    Timeout,
    #[error("collateral cash RPC response exceeded a byte limit")]
    ResponseTooLarge,
    #[error("collateral cash RPC response could not be read")]
    ResponseUnreadable,
    #[error("collateral cash RPC response was malformed")]
    MalformedResponse,
    #[error("collateral cash RPC returned JSON-RPC error code {0}")]
    RpcError(i64),
    #[error("collateral cash RPC endpoint is not Polygon")]
    WrongChain,
    #[error("collateral cash token decimals did not match the pinned value")]
    WrongDecimals,
    #[error("collateral cash block changed during the read")]
    BlockChanged,
    #[error("collateral cash Multicall3 sub-call failed")]
    MulticallCallFailed,
    #[error("collateral cash artifact is invalid or internally inconsistent")]
    InvalidArtifact,
    #[error("collateral cash artifact exceeded its byte limit")]
    ArtifactTooLarge,
}

/// Read pUSD and USDC.e balances at one provider-reported finalized block.
/// Wallets are normalized to lowercase before duplicate checks and requests.
/// Balances are batched through Multicall3 `aggregate3`, at most
/// [`MULTICALL_WALLETS_PER_CHUNK`] wallets per call, so one read uses exactly
/// `3 + ceil(wallets / 50)` sequential JSON-RPC calls (chain id, finalized
/// header, one call per chunk, header recheck) whose starts are at least
/// [`MIN_RPC_REQUEST_INTERVAL`] apart. The first chunk also carries both token
/// `decimals()` sub-calls. Every sub-call must succeed.
///
/// # Errors
///
/// Rejects invalid inputs, endpoint policy violations, transport/RPC failures,
/// malformed ABI data, failed Multicall3 sub-calls, non-Polygon endpoints,
/// unexpected token decimals, or a changed block header. Errors never include
/// the RPC URL.
pub async fn fetch_collateral_cash_snapshot(
    client: &Client,
    rpc_url: &str,
    wallets: &[impl AsRef<str>],
) -> Result<CollateralCashSnapshot, CollateralCashError> {
    fetch_collateral_cash_snapshot_paced(client, rpc_url, wallets, MIN_RPC_REQUEST_INTERVAL).await
}

async fn fetch_collateral_cash_snapshot_paced(
    client: &Client,
    rpc_url: &str,
    wallets: &[impl AsRef<str>],
    request_interval: Duration,
) -> Result<CollateralCashSnapshot, CollateralCashError> {
    let wallets = canonical_wallets(wallets)?;
    validate_rpc_url(rpc_url)?;

    timeout(TOTAL_TIMEOUT, async {
        let mut rpc = RpcRead::new(client, rpc_url, request_interval);
        let chain_id = rpc.call("eth_chainId", json!([])).await?;
        if parse_quantity(
            chain_id
                .as_str()
                .ok_or(CollateralCashError::MalformedResponse)?,
        )? != POLYGON_CHAIN_ID
        {
            return Err(CollateralCashError::WrongChain);
        }

        let header_value = rpc
            .call("eth_getBlockByNumber", json!(["finalized", false]))
            .await?;
        let block = parse_block(&header_value)?;
        let block_tag = format!("0x{:x}", block.number);

        let mut balances = Vec::with_capacity(wallets.len() * 2);
        for (index, chunk) in wallets.chunks(MULTICALL_WALLETS_PER_CHUNK).enumerate() {
            let calls = multicall_chunk_calls(chunk, index == 0)?;
            let request = encode_aggregate3_request(&calls);
            let result = rpc
                .call(
                    "eth_call",
                    json!([{"to": MULTICALL3_ADDRESS, "data": request}, block_tag.as_str()]),
                )
                .await?;
            let mut words = decode_aggregate3_words(
                result
                    .as_str()
                    .ok_or(CollateralCashError::MalformedResponse)?,
                calls.len(),
            )?
            .into_iter();
            if index == 0 {
                for _ in 0..2 {
                    let word = words.next().ok_or(CollateralCashError::MalformedResponse)?;
                    parse_decimals_word(&word)?;
                }
            }
            for wallet in chunk {
                for asset in [CollateralAsset::Pusd, CollateralAsset::UsdcE] {
                    balances.push(CollateralBalance {
                        wallet: wallet.clone(),
                        asset,
                        balance_word: words.next().ok_or(CollateralCashError::MalformedResponse)?,
                        decimals: TOKEN_DECIMALS,
                    });
                }
            }
        }

        let after_value = rpc
            .call("eth_getBlockByNumber", json!([block_tag.as_str(), false]))
            .await?;
        let after = parse_block(&after_value)?;
        if after != block {
            return Err(CollateralCashError::BlockChanged);
        }

        Ok(CollateralCashSnapshot {
            source: CollateralCashSource::ProviderReported,
            block,
            wallets,
            balances,
            requests: rpc.evidence,
        })
    })
    .await
    .map_err(|_| CollateralCashError::Timeout)?
}

/// One Multicall3 sub-call: target token address and ABI calldata.
struct MulticallCall {
    target: &'static str,
    calldata: Vec<u8>,
}

/// Sub-calls of one chunk: optionally both `decimals()` reads first, then
/// pUSD and USDC.e `balanceOf` for every wallet in order.
fn multicall_chunk_calls(
    wallets: &[String],
    with_decimals: bool,
) -> Result<Vec<MulticallCall>, CollateralCashError> {
    let mut calls = Vec::with_capacity(wallets.len() * 2 + 2);
    if with_decimals {
        for target in [PUSD_ADDRESS, USDCE_ADDRESS] {
            calls.push(MulticallCall {
                target,
                calldata: parse_hex_bytes(&format!("0x{DECIMALS_SELECTOR}"))?,
            });
        }
    }
    for wallet in wallets {
        let calldata = parse_hex_bytes(&balance_of_calldata(wallet)?)?;
        for asset in [CollateralAsset::Pusd, CollateralAsset::UsdcE] {
            calls.push(MulticallCall {
                target: asset.address(),
                calldata: calldata.clone(),
            });
        }
    }
    Ok(calls)
}

fn usize_word(value: usize) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&(value as u64).to_be_bytes());
    word
}

fn padded_len(length: usize) -> usize {
    length.div_ceil(32) * 32
}

/// Canonical ABI encoding of
/// `aggregate3((address target, bool allowFailure, bytes callData)[])` with
/// `allowFailure = true` so each sub-call's success flag is checked.
fn encode_aggregate3_request(calls: &[MulticallCall]) -> String {
    let mut data = Vec::new();
    data.extend_from_slice(&AGGREGATE3_SELECTOR);
    data.extend_from_slice(&usize_word(32));
    data.extend_from_slice(&usize_word(calls.len()));
    let mut offset = calls.len() * 32;
    for call in calls {
        data.extend_from_slice(&usize_word(offset));
        offset += 32 * 4 + padded_len(call.calldata.len());
    }
    for call in calls {
        let mut address_word = [0u8; 32];
        if let Ok(address) = parse_hex_bytes(call.target) {
            address_word[12..].copy_from_slice(&address);
        }
        data.extend_from_slice(&address_word);
        data.extend_from_slice(&usize_word(1));
        data.extend_from_slice(&usize_word(96));
        data.extend_from_slice(&usize_word(call.calldata.len()));
        data.extend_from_slice(&call.calldata);
        let padding = padded_len(call.calldata.len()) - call.calldata.len();
        data.resize(data.len() + padding, 0);
    }
    format!("0x{}", encode_hex(&data))
}

/// Strictly decode the canonical `Result[]` returned by `aggregate3` when
/// every sub-call returned exactly one 32-byte word. A cleared success flag is
/// a failed sub-call; any other deviation from the canonical layout is
/// malformed.
fn decode_aggregate3_words(
    result: &str,
    expected: usize,
) -> Result<Vec<[u8; 32]>, CollateralCashError> {
    let bytes = parse_hex_bytes(result)?;
    let word_at = |position: usize| -> Result<&[u8], CollateralCashError> {
        bytes
            .get(position..position + 32)
            .ok_or(CollateralCashError::MalformedResponse)
    };
    let is_word = |position: usize, value: usize| -> Result<bool, CollateralCashError> {
        Ok(word_at(position)? == usize_word(value))
    };
    let element_size = 32 * 4;
    if expected == 0
        || bytes.len() != 64 + expected * 32 + expected * element_size
        || !is_word(0, 32)?
        || !is_word(32, expected)?
    {
        return Err(CollateralCashError::MalformedResponse);
    }
    let mut words = Vec::with_capacity(expected);
    for index in 0..expected {
        if !is_word(64 + index * 32, expected * 32 + index * element_size)? {
            return Err(CollateralCashError::MalformedResponse);
        }
        let element = 64 + expected * 32 + index * element_size;
        if is_word(element, 0)? {
            return Err(CollateralCashError::MulticallCallFailed);
        }
        if !is_word(element, 1)? || !is_word(element + 32, 64)? || !is_word(element + 64, 32)? {
            return Err(CollateralCashError::MalformedResponse);
        }
        words.push(
            word_at(element + 96)?
                .try_into()
                .map_err(|_| CollateralCashError::MalformedResponse)?,
        );
    }
    Ok(words)
}

struct RpcRead<'a> {
    client: &'a Client,
    rpc_url: &'a str,
    response_bytes: usize,
    evidence: Vec<CollateralRpcEvidence>,
    request_interval: Duration,
    last_started: Option<tokio::time::Instant>,
}

impl<'a> RpcRead<'a> {
    fn new(client: &'a Client, rpc_url: &'a str, request_interval: Duration) -> Self {
        Self {
            client,
            rpc_url,
            response_bytes: 0,
            evidence: Vec::new(),
            request_interval,
            last_started: None,
        }
    }

    async fn call(&mut self, method: &str, params: Value) -> Result<Value, CollateralCashError> {
        if let Some(previous) = self.last_started {
            tokio::time::sleep_until(previous + self.request_interval).await;
        }
        self.last_started = Some(tokio::time::Instant::now());
        let request_id = u64::try_from(self.evidence.len() + 1)
            .map_err(|_| CollateralCashError::InvalidInput)?;
        let request_body = encode_rpc_request(request_id, method, &params)?;
        let started_at = Utc::now();
        let work = async {
            let mut response = self
                .client
                .post(self.rpc_url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(request_body.clone())
                .send()
                .await
                .map_err(|_| CollateralCashError::RequestFailed)?;
            let status = response.status();
            if !status.is_success() {
                return Err(CollateralCashError::HttpStatus(status.as_u16()));
            }
            let mut response_body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| CollateralCashError::ResponseUnreadable)?
            {
                if chunk.len() > MAX_RPC_RESPONSE_BYTES - response_body.len()
                    || chunk.len() > MAX_TOTAL_RESPONSE_BYTES - self.response_bytes
                {
                    return Err(CollateralCashError::ResponseTooLarge);
                }
                response_body.extend_from_slice(&chunk);
                self.response_bytes += chunk.len();
            }
            let completed_at = Utc::now();
            let result = parse_rpc_result(&response_body, request_id)?;
            self.evidence.push(CollateralRpcEvidence {
                method: method.to_owned(),
                request_id,
                started_at,
                completed_at,
                request_body,
                response_body,
            });
            Ok(result)
        };
        timeout(REQUEST_TIMEOUT, work)
            .await
            .map_err(|_| CollateralCashError::Timeout)?
    }
}

fn encode_rpc_request(
    request_id: u64,
    method: &str,
    params: &Value,
) -> Result<Vec<u8>, CollateralCashError> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params,
    }))
    .map_err(|_| CollateralCashError::MalformedResponse)
}

fn parse_rpc_result(body: &[u8], request_id: u64) -> Result<Value, CollateralCashError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| CollateralCashError::MalformedResponse)?;
    let object = value
        .as_object()
        .ok_or(CollateralCashError::MalformedResponse)?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || object.get("id").and_then(Value::as_u64) != Some(request_id)
    {
        return Err(CollateralCashError::MalformedResponse);
    }
    if let Some(error) = object.get("error") {
        if object.contains_key("result") {
            return Err(CollateralCashError::MalformedResponse);
        }
        let code = error
            .as_object()
            .and_then(|error| error.get("code"))
            .and_then(Value::as_i64)
            .ok_or(CollateralCashError::MalformedResponse)?;
        return Err(CollateralCashError::RpcError(code));
    }
    object
        .get("result")
        .cloned()
        .ok_or(CollateralCashError::MalformedResponse)
}

fn parse_decimals_result(result: &Value) -> Result<u8, CollateralCashError> {
    let word = parse_word(
        result
            .as_str()
            .ok_or(CollateralCashError::MalformedResponse)?,
    )?;
    parse_decimals_word(&word)
}

fn parse_decimals_word(word: &[u8; 32]) -> Result<u8, CollateralCashError> {
    if word[..31].iter().any(|byte| *byte != 0) {
        return Err(CollateralCashError::WrongDecimals);
    }
    let decimals = word[31];
    if decimals != TOKEN_DECIMALS {
        return Err(CollateralCashError::WrongDecimals);
    }
    Ok(decimals)
}

fn validate_snapshot(snapshot: &CollateralCashSnapshot) -> Result<ReadLayout, CollateralCashError> {
    let wallets =
        canonical_wallets(&snapshot.wallets).map_err(|_| CollateralCashError::InvalidArtifact)?;
    if wallets != snapshot.wallets || snapshot.block.chain_id != POLYGON_CHAIN_ID {
        return Err(CollateralCashError::InvalidArtifact);
    }
    // The two layouts never share a request count (`2 + 2N` is never a chunk
    // count), so the count selects the layout unambiguously.
    let layout = if snapshot.requests.len() == 5 + 2 * wallets.len() {
        ReadLayout::SingleCalls
    } else if snapshot.requests.len() == 3 + wallets.len().div_ceil(MULTICALL_WALLETS_PER_CHUNK) {
        ReadLayout::Multicall
    } else {
        return Err(CollateralCashError::InvalidArtifact);
    };

    let mut total_response_bytes = 0usize;
    for (index, request) in snapshot.requests.iter().enumerate() {
        if request.started_at > request.completed_at
            || (index > 0 && snapshot.requests[index - 1].completed_at > request.started_at)
            || request.response_body.len() > MAX_RPC_RESPONSE_BYTES
        {
            return Err(CollateralCashError::InvalidArtifact);
        }
        total_response_bytes = total_response_bytes
            .checked_add(request.response_body.len())
            .ok_or(CollateralCashError::InvalidArtifact)?;
        if total_response_bytes > MAX_TOTAL_RESPONSE_BYTES {
            return Err(CollateralCashError::InvalidArtifact);
        }
    }

    match layout {
        ReadLayout::SingleCalls => validate_single_call_layout(snapshot, &wallets)?,
        ReadLayout::Multicall => validate_multicall_layout(snapshot, &wallets)?,
    }
    Ok(layout)
}

fn validate_multicall_layout(
    snapshot: &CollateralCashSnapshot,
    wallets: &[String],
) -> Result<(), CollateralCashError> {
    let invalid = |_| CollateralCashError::InvalidArtifact;
    let chain_id = expected_result(snapshot, 0, "eth_chainId", json!([]))?;
    if parse_quantity(
        chain_id
            .as_str()
            .ok_or(CollateralCashError::InvalidArtifact)?,
    )
    .map_err(invalid)?
        != POLYGON_CHAIN_ID
    {
        return Err(CollateralCashError::InvalidArtifact);
    }
    let header = expected_result(
        snapshot,
        1,
        "eth_getBlockByNumber",
        json!(["finalized", false]),
    )?;
    let block = parse_block(&header).map_err(invalid)?;
    if block != snapshot.block {
        return Err(CollateralCashError::InvalidArtifact);
    }
    let block_tag = format!("0x{:x}", block.number);

    let mut balances = Vec::with_capacity(wallets.len() * 2);
    let mut index = 2;
    for (chunk_index, chunk) in wallets.chunks(MULTICALL_WALLETS_PER_CHUNK).enumerate() {
        let calls = multicall_chunk_calls(chunk, chunk_index == 0).map_err(invalid)?;
        let result = expected_result(
            snapshot,
            index,
            "eth_call",
            json!([{"to": MULTICALL3_ADDRESS, "data": encode_aggregate3_request(&calls)}, block_tag.as_str()]),
        )?;
        index += 1;
        let mut words = decode_aggregate3_words(
            result
                .as_str()
                .ok_or(CollateralCashError::InvalidArtifact)?,
            calls.len(),
        )
        .map_err(invalid)?
        .into_iter();
        if chunk_index == 0 {
            for _ in 0..2 {
                let word = words.next().ok_or(CollateralCashError::InvalidArtifact)?;
                parse_decimals_word(&word).map_err(invalid)?;
            }
        }
        for wallet in chunk {
            for asset in [CollateralAsset::Pusd, CollateralAsset::UsdcE] {
                balances.push(CollateralBalance {
                    wallet: wallet.clone(),
                    asset,
                    balance_word: words.next().ok_or(CollateralCashError::InvalidArtifact)?,
                    decimals: TOKEN_DECIMALS,
                });
            }
        }
    }

    let final_header = expected_result(
        snapshot,
        index,
        "eth_getBlockByNumber",
        json!([block_tag.as_str(), false]),
    )?;
    let final_block = parse_block(&final_header).map_err(invalid)?;
    if final_block != block || balances != snapshot.balances {
        return Err(CollateralCashError::InvalidArtifact);
    }
    Ok(())
}

fn validate_single_call_layout(
    snapshot: &CollateralCashSnapshot,
    wallets: &[String],
) -> Result<(), CollateralCashError> {
    let mut index = 0;
    let chain_id = expected_result(snapshot, index, "eth_chainId", json!([]))?;
    index += 1;
    if parse_quantity(
        chain_id
            .as_str()
            .ok_or(CollateralCashError::InvalidArtifact)?,
    )
    .map_err(|_| CollateralCashError::InvalidArtifact)?
        != POLYGON_CHAIN_ID
    {
        return Err(CollateralCashError::InvalidArtifact);
    }

    let header = expected_result(
        snapshot,
        index,
        "eth_getBlockByNumber",
        json!(["finalized", false]),
    )?;
    index += 1;
    let block = parse_block(&header).map_err(|_| CollateralCashError::InvalidArtifact)?;
    if block != snapshot.block {
        return Err(CollateralCashError::InvalidArtifact);
    }
    let block_tag = format!("0x{:x}", block.number);

    for token in [PUSD_ADDRESS, USDCE_ADDRESS] {
        let result = expected_result(
            snapshot,
            index,
            "eth_call",
            json!([{"to": token, "data": format!("0x{DECIMALS_SELECTOR}")}, block_tag.as_str()]),
        )?;
        index += 1;
        parse_decimals_result(&result).map_err(|_| CollateralCashError::InvalidArtifact)?;
    }

    let mut balances = Vec::with_capacity(wallets.len() * 2);
    for wallet in wallets {
        for asset in [CollateralAsset::Pusd, CollateralAsset::UsdcE] {
            let calldata =
                balance_of_calldata(wallet).map_err(|_| CollateralCashError::InvalidArtifact)?;
            let result = expected_result(
                snapshot,
                index,
                "eth_call",
                json!([{"to": asset.address(), "data": calldata}, block_tag.as_str()]),
            )?;
            index += 1;
            let balance_word = parse_word(
                result
                    .as_str()
                    .ok_or(CollateralCashError::InvalidArtifact)?,
            )
            .map_err(|_| CollateralCashError::InvalidArtifact)?;
            balances.push(CollateralBalance {
                wallet: wallet.clone(),
                asset,
                balance_word,
                decimals: TOKEN_DECIMALS,
            });
        }
    }

    let final_header = expected_result(
        snapshot,
        index,
        "eth_getBlockByNumber",
        json!([block_tag.as_str(), false]),
    )?;
    let final_block =
        parse_block(&final_header).map_err(|_| CollateralCashError::InvalidArtifact)?;
    if final_block != block || balances != snapshot.balances {
        return Err(CollateralCashError::InvalidArtifact);
    }
    Ok(())
}

fn expected_result(
    snapshot: &CollateralCashSnapshot,
    index: usize,
    method: &str,
    params: Value,
) -> Result<Value, CollateralCashError> {
    let request_id = u64::try_from(index + 1).map_err(|_| CollateralCashError::InvalidArtifact)?;
    let evidence = snapshot
        .requests
        .get(index)
        .ok_or(CollateralCashError::InvalidArtifact)?;
    if evidence.method != method || evidence.request_id != request_id {
        return Err(CollateralCashError::InvalidArtifact);
    }
    let expected_body = encode_rpc_request(request_id, method, &params)
        .map_err(|_| CollateralCashError::InvalidArtifact)?;
    if evidence.request_body != expected_body {
        return Err(CollateralCashError::InvalidArtifact);
    }
    parse_rpc_result(&evidence.response_body, request_id)
        .map_err(|_| CollateralCashError::InvalidArtifact)
}

fn canonical_wallets(wallets: &[impl AsRef<str>]) -> Result<Vec<String>, CollateralCashError> {
    if !(1..=MAX_COLLATERAL_WALLETS).contains(&wallets.len()) {
        return Err(CollateralCashError::InvalidInput);
    }
    let mut canonical = Vec::with_capacity(wallets.len());
    let mut seen = HashSet::with_capacity(wallets.len());
    for wallet in wallets {
        let wallet = wallet.as_ref();
        let Some(address) = wallet.strip_prefix("0x") else {
            return Err(CollateralCashError::InvalidInput);
        };
        if address.len() != 40 || !address.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(CollateralCashError::InvalidInput);
        }
        let wallet = format!("0x{}", address.to_ascii_lowercase());
        if !seen.insert(wallet.clone()) {
            return Err(CollateralCashError::InvalidInput);
        }
        canonical.push(wallet);
    }
    Ok(canonical)
}

fn validate_rpc_url(rpc_url: &str) -> Result<(), CollateralCashError> {
    let url = Url::parse(rpc_url).map_err(|_| CollateralCashError::InvalidEndpoint)?;
    let loopback_host = url.host_str().is_some_and(|host| {
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    let allowed = url.scheme() == "https" || (url.scheme() == "http" && loopback_host);
    if allowed && url.fragment().is_none() {
        Ok(())
    } else {
        Err(CollateralCashError::InvalidEndpoint)
    }
}

fn parse_block(value: &Value) -> Result<CollateralCashBlock, CollateralCashError> {
    let object = value
        .as_object()
        .ok_or(CollateralCashError::MalformedResponse)?;
    let number = parse_quantity(
        object
            .get("number")
            .and_then(Value::as_str)
            .ok_or(CollateralCashError::MalformedResponse)?,
    )?;
    let hash = object
        .get("hash")
        .and_then(Value::as_str)
        .ok_or(CollateralCashError::MalformedResponse)?;
    let hash_bytes = parse_hex_bytes(hash)?;
    if hash_bytes.len() != 32 {
        return Err(CollateralCashError::MalformedResponse);
    }
    let timestamp = parse_quantity(
        object
            .get("timestamp")
            .and_then(Value::as_str)
            .ok_or(CollateralCashError::MalformedResponse)?,
    )?;
    Ok(CollateralCashBlock {
        chain_id: POLYGON_CHAIN_ID,
        number,
        hash: format!("0x{}", encode_hex(&hash_bytes)),
        timestamp,
    })
}

fn parse_quantity(value: &str) -> Result<u64, CollateralCashError> {
    let digits = value
        .strip_prefix("0x")
        .ok_or(CollateralCashError::MalformedResponse)?;
    if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
        return Err(CollateralCashError::MalformedResponse);
    }
    u64::from_str_radix(digits, 16).map_err(|_| CollateralCashError::MalformedResponse)
}

fn parse_word(value: &str) -> Result<[u8; 32], CollateralCashError> {
    let bytes = parse_hex_bytes(value)?;
    bytes
        .try_into()
        .map_err(|_| CollateralCashError::MalformedResponse)
}

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>, CollateralCashError> {
    let digits = value
        .strip_prefix("0x")
        .ok_or(CollateralCashError::MalformedResponse)?;
    if digits.len() % 2 != 0 {
        return Err(CollateralCashError::MalformedResponse);
    }
    digits
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(CollateralCashError::MalformedResponse)?;
            let low = hex_nibble(pair[1]).ok_or(CollateralCashError::MalformedResponse)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn balance_of_calldata(wallet: &str) -> Result<String, CollateralCashError> {
    let address = wallet
        .strip_prefix("0x")
        .ok_or(CollateralCashError::InvalidInput)?;
    Ok(format!(
        "0x{BALANCE_OF_SELECTOR}{}{}",
        "0".repeat(24),
        address
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{Json, Router, extract::State, routing::post};
    use serde_json::{Value, json};
    use tokio::net::TcpListener;

    use super::*;

    #[derive(Clone, Default)]
    struct Fixture(Arc<Mutex<FixtureState>>);

    #[derive(Default)]
    struct FixtureState {
        requests: Vec<Value>,
        wrong_chain: bool,
        wrong_decimals: bool,
        malformed_abi: bool,
        failed_subcall: bool,
        wrong_id: bool,
        reorg: bool,
        rpc_error: bool,
        padding_bytes: usize,
    }

    /// Fixed balance returned for every `balanceOf` sub-call.
    const BALANCE: u8 = 0x2a;

    /// Decode a canonical `aggregate3` request into `(target, calldata)` pairs.
    fn decode_calls(data: &str) -> Vec<(String, Vec<u8>)> {
        let bytes = parse_hex_bytes(data).unwrap();
        assert_eq!(bytes[..4], AGGREGATE3_SELECTOR);
        let body = &bytes[4..];
        let word = |position: usize| -> usize {
            let slice = &body[position..position + 32];
            assert!(slice[..24].iter().all(|byte| *byte == 0));
            u64::from_be_bytes(slice[24..].try_into().unwrap()) as usize
        };
        assert_eq!(word(0), 32);
        let count = word(32);
        (0..count)
            .map(|index| {
                let element = 64 + word(64 + index * 32);
                assert_eq!(word(element + 32), 1, "allowFailure must be true");
                assert_eq!(word(element + 64), 96);
                let length = word(element + 96);
                let target = format!("0x{}", encode_hex(&body[element + 12..element + 32]));
                (target, body[element + 128..element + 128 + length].to_vec())
            })
            .collect()
    }

    fn multicall_result(calls: &[(String, Vec<u8>)], state: &FixtureState) -> String {
        let mut data = Vec::new();
        data.extend_from_slice(&usize_word(32));
        data.extend_from_slice(&usize_word(calls.len()));
        for index in 0..calls.len() {
            data.extend_from_slice(&usize_word(calls.len() * 32 + index * 128));
        }
        for (index, (_, calldata)) in calls.iter().enumerate() {
            let is_decimals =
                calldata == &parse_hex_bytes(&format!("0x{DECIMALS_SELECTOR}")).unwrap();
            let success = !(state.failed_subcall && index == 1);
            data.extend_from_slice(&usize_word(usize::from(success)));
            data.extend_from_slice(&usize_word(64));
            data.extend_from_slice(&usize_word(32));
            let mut value = [0u8; 32];
            value[31] = if is_decimals {
                if state.wrong_decimals { 18 } else { 6 }
            } else {
                BALANCE
            };
            data.extend_from_slice(&value);
        }
        if state.malformed_abi {
            data.truncate(data.len() - 1);
        }
        format!("0x{}", encode_hex(&data))
    }

    async fn rpc_route(State(fixture): State<Fixture>, Json(request): Json<Value>) -> Json<Value> {
        let mut state = fixture.0.lock().unwrap();
        state.requests.push(request.clone());
        let id = request["id"].as_u64().unwrap();
        let method = request["method"].as_str().unwrap();
        let result = match method {
            "eth_chainId" => json!(if state.wrong_chain { "0x1" } else { "0x89" }),
            "eth_getBlockByNumber" => {
                let is_recheck = request["params"][0] != "finalized";
                let hash = if is_recheck && state.reorg {
                    format!("0x{}", "22".repeat(32))
                } else {
                    format!("0x{}", "11".repeat(32))
                };
                json!({"number":"0x1234","hash":hash,"timestamp":"0x6789"})
            }
            "eth_call" => {
                assert_eq!(request["params"][0]["to"], MULTICALL3_ADDRESS);
                let calls = decode_calls(request["params"][0]["data"].as_str().unwrap());
                Value::String(multicall_result(&calls, &state))
            }
            _ => panic!("unexpected JSON-RPC method"),
        };
        let response_id = if state.wrong_id { id + 1 } else { id };
        let mut response = if state.rpc_error {
            json!({"jsonrpc":"2.0","id":response_id,"error":{"code":-32000,"message":"hidden provider detail"}})
        } else {
            json!({"jsonrpc":"2.0","id":response_id,"result":result})
        };
        if state.padding_bytes > 0 {
            response["fixture_padding"] = json!("x".repeat(state.padding_bytes));
        }
        Json(response)
    }

    async fn server(fixture: Fixture) -> String {
        let app = Router::new()
            .route("/", post(rpc_route))
            .with_state(fixture);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{address}/")
    }

    fn wallet(byte: &str) -> String {
        format!("0x{}", byte.repeat(20))
    }

    /// Unpaced read so ordinary tests stay fast; pacing has its own test.
    async fn fast(
        client: &Client,
        url: &str,
        wallets: &[impl AsRef<str>],
    ) -> Result<CollateralCashSnapshot, CollateralCashError> {
        fetch_collateral_cash_snapshot_paced(client, url, wallets, Duration::ZERO).await
    }

    #[tokio::test]
    async fn reads_both_assets_at_one_finalized_block_in_one_multicall() {
        let fixture = Fixture::default();
        let url = server(fixture.clone()).await;
        let snapshot = fast(&Client::new(), &url, &[wallet("aa"), wallet("bb")])
            .await
            .unwrap();

        assert_eq!(snapshot.source, CollateralCashSource::ProviderReported);
        assert_eq!(snapshot.source.as_str(), "PROVIDER_REPORTED");
        assert_eq!(snapshot.block.number, 0x1234);
        assert_eq!(snapshot.block.hash, format!("0x{}", "11".repeat(32)));
        assert_eq!(snapshot.block.timestamp, 0x6789);
        assert_eq!(snapshot.balances.len(), 4);
        assert!(
            snapshot
                .balances
                .iter()
                .all(|balance| balance.decimals == 6)
        );
        assert!(
            snapshot
                .balances
                .iter()
                .all(|balance| balance.balance_word[31] == BALANCE)
        );
        let order = snapshot
            .balances
            .iter()
            .map(|balance| (balance.wallet.clone(), balance.asset))
            .collect::<Vec<_>>();
        assert_eq!(
            order,
            vec![
                (wallet("aa"), CollateralAsset::Pusd),
                (wallet("aa"), CollateralAsset::UsdcE),
                (wallet("bb"), CollateralAsset::Pusd),
                (wallet("bb"), CollateralAsset::UsdcE),
            ]
        );
        // chain id, finalized header, one aggregate3 chunk, header recheck.
        assert_eq!(snapshot.requests.len(), 4);
        assert!(
            snapshot
                .requests
                .iter()
                .all(|request| request.started_at <= request.completed_at)
        );
        assert_eq!(snapshot.requests[0].method(), "eth_chainId");
        assert_eq!(snapshot.requests[1].method(), "eth_getBlockByNumber");
        assert_eq!(snapshot.requests[2].method(), "eth_call");
        assert_eq!(snapshot.requests[3].request_id(), 4);
        let observed = fixture.0.lock().unwrap();
        assert_eq!(observed.requests.len(), 4);
        assert_eq!(observed.requests[1]["params"], json!(["finalized", false]));
        assert_eq!(observed.requests[2]["params"][1], "0x1234");
        assert_eq!(observed.requests[3]["params"], json!(["0x1234", false]));
        let calls = decode_calls(observed.requests[2]["params"][0]["data"].as_str().unwrap());
        assert_eq!(calls.len(), 6);
        assert_eq!(calls[0].0, PUSD_ADDRESS);
        assert_eq!(calls[1].0, USDCE_ADDRESS);
        assert_eq!(calls[0].1, parse_hex_bytes("0x313ce567").unwrap());
        assert_eq!(calls[2].0, PUSD_ADDRESS);
        assert_eq!(calls[3].0, USDCE_ADDRESS);
        assert_eq!(
            calls[2].1,
            parse_hex_bytes(&format!(
                "0x{BALANCE_OF_SELECTOR}{}{}",
                "0".repeat(24),
                "aa".repeat(20)
            ))
            .unwrap()
        );
        assert!(
            snapshot.requests[0]
                .request_body()
                .windows(11)
                .any(|w| w == b"eth_chainId")
        );
        assert_eq!(
            serde_json::from_slice::<Value>(snapshot.requests[0].response_body()).unwrap(),
            json!({"jsonrpc":"2.0","id":1,"result":"0x89"})
        );
        assert!(!format!("{snapshot:?}").contains(&url));
    }

    #[test]
    fn aggregate3_encoding_matches_the_canonical_abi_layout() {
        let calls = vec![MulticallCall {
            target: PUSD_ADDRESS,
            calldata: parse_hex_bytes(&format!("0x{DECIMALS_SELECTOR}")).unwrap(),
        }];
        let expected = [
            "0x82ad56cb".to_owned(),
            format!("{:064x}", 0x20),
            format!("{:064x}", 1),
            format!("{:064x}", 0x20),
            format!("{:0>64}", &PUSD_ADDRESS[2..]),
            format!("{:064x}", 1),
            format!("{:064x}", 0x60),
            format!("{:064x}", 4),
            format!("{:0<64}", DECIMALS_SELECTOR),
        ]
        .concat();
        assert_eq!(encode_aggregate3_request(&calls), expected);
    }

    #[test]
    fn decoder_rejects_every_noncanonical_or_failed_result() {
        let calls = vec![(PUSD_ADDRESS.to_owned(), vec![0u8; 4]); 2];
        let good = multicall_result(&calls, &FixtureState::default());
        assert_eq!(decode_aggregate3_words(&good, 2).unwrap().len(), 2);
        assert_eq!(
            decode_aggregate3_words(&good, 3),
            Err(CollateralCashError::MalformedResponse)
        );
        let failed = multicall_result(
            &calls,
            &FixtureState {
                failed_subcall: true,
                ..FixtureState::default()
            },
        );
        assert_eq!(
            decode_aggregate3_words(&failed, 2),
            Err(CollateralCashError::MulticallCallFailed)
        );
        let truncated = &good[..good.len() - 2];
        assert_eq!(
            decode_aggregate3_words(truncated, 2),
            Err(CollateralCashError::MalformedResponse)
        );
        // Wrong array offset, array length, element offset, success flag of 2
        // and bytes offset; each is one changed low byte.
        for position in [31usize, 63, 95, 159, 191] {
            let mut bytes = parse_hex_bytes(&good).unwrap();
            bytes[position] = bytes[position].wrapping_add(2);
            assert!(
                decode_aggregate3_words(&format!("0x{}", encode_hex(&bytes)), 2).is_err(),
                "mutation at {position}"
            );
        }
        assert_eq!(
            decode_aggregate3_words("0x", 1),
            Err(CollateralCashError::MalformedResponse)
        );
    }

    #[tokio::test]
    async fn chunks_one_hundred_wallets_into_two_calls_under_the_frame_cap() {
        let fixture = Fixture::default();
        let url = server(fixture.clone()).await;
        let wallets = (0..MAX_COLLATERAL_WALLETS)
            .map(|number| wallet(&format!("{number:02x}")))
            .collect::<Vec<_>>();
        let snapshot = fast(&Client::new(), &url, &wallets).await.unwrap();
        assert_eq!(snapshot.balances.len(), 200);
        assert_eq!(snapshot.requests.len(), 5);
        assert_eq!(snapshot.requests[2].method(), "eth_call");
        assert_eq!(snapshot.requests[3].method(), "eth_call");
        assert!(
            snapshot
                .requests
                .iter()
                .all(|request| request.response_body().len() < MAX_RPC_RESPONSE_BYTES * 3 / 4)
        );
        let observed = fixture.0.lock().unwrap();
        let first = decode_calls(observed.requests[2]["params"][0]["data"].as_str().unwrap());
        let second = decode_calls(observed.requests[3]["params"][0]["data"].as_str().unwrap());
        // First chunk: 2 decimals + 50 wallets x 2; second chunk: 50 wallets x 2.
        assert_eq!(first.len(), 102);
        assert_eq!(second.len(), 100);
        let artifact = snapshot.to_artifact().unwrap();
        assert_eq!(
            CollateralCashSnapshot::from_artifact(&artifact).unwrap(),
            snapshot
        );
    }

    #[tokio::test]
    async fn spaces_rpc_request_starts_by_the_minimum_interval() {
        let fixture = Fixture::default();
        let url = server(fixture).await;
        let started = std::time::Instant::now();
        let snapshot = fetch_collateral_cash_snapshot(&Client::new(), &url, &[wallet("aa")])
            .await
            .unwrap();
        assert!(started.elapsed() >= MIN_RPC_REQUEST_INTERVAL * 3);
        assert_eq!(snapshot.requests.len(), 4);
        for pair in snapshot.requests.windows(2) {
            let gap = (*pair[1].started_at() - *pair[0].started_at())
                .to_std()
                .unwrap();
            assert!(gap >= MIN_RPC_REQUEST_INTERVAL - Duration::from_millis(5));
        }
    }

    #[tokio::test]
    async fn rejects_invalid_wallet_sets_before_network_io() {
        let fixture = Fixture::default();
        let url = server(fixture.clone()).await;
        for wallets in [
            Vec::<String>::new(),
            vec!["bad".to_owned()],
            vec![wallet("aa"), format!("0x{}", "AA".repeat(20))],
        ] {
            assert_eq!(
                fast(&Client::new(), &url, &wallets).await,
                Err(CollateralCashError::InvalidInput)
            );
        }
        let too_many = vec![wallet("ab"); MAX_COLLATERAL_WALLETS + 1];
        assert_eq!(
            fast(&Client::new(), &url, &too_many).await,
            Err(CollateralCashError::InvalidInput)
        );
        assert!(fixture.0.lock().unwrap().requests.is_empty());
    }

    #[tokio::test]
    async fn rejects_wrong_chain_decimals_abi_subcall_id_rpc_errors_and_block_changes() {
        for (field, expected) in [
            ("wrong_chain", CollateralCashError::WrongChain),
            ("wrong_decimals", CollateralCashError::WrongDecimals),
            ("malformed_abi", CollateralCashError::MalformedResponse),
            ("failed_subcall", CollateralCashError::MulticallCallFailed),
            ("wrong_id", CollateralCashError::MalformedResponse),
            ("rpc_error", CollateralCashError::RpcError(-32000)),
            ("reorg", CollateralCashError::BlockChanged),
        ] {
            let fixture = Fixture::default();
            match field {
                "wrong_chain" => fixture.0.lock().unwrap().wrong_chain = true,
                "wrong_decimals" => fixture.0.lock().unwrap().wrong_decimals = true,
                "malformed_abi" => fixture.0.lock().unwrap().malformed_abi = true,
                "failed_subcall" => fixture.0.lock().unwrap().failed_subcall = true,
                "wrong_id" => fixture.0.lock().unwrap().wrong_id = true,
                "rpc_error" => fixture.0.lock().unwrap().rpc_error = true,
                "reorg" => fixture.0.lock().unwrap().reorg = true,
                _ => unreachable!(),
            }
            let url = server(fixture).await;
            let error = fast(&Client::new(), &url, &[wallet("aa")])
                .await
                .unwrap_err();
            assert_eq!(error, expected, "{field}");
            assert!(!error.to_string().contains("hidden provider detail"));
            assert!(!format!("{error:?}").contains(&url));
        }
    }

    #[tokio::test]
    async fn rejects_bad_endpoints_without_echoing_credentials() {
        let secret_url = "http://user:supersecret@rpc.example.invalid/path";
        let error = fast(&Client::new(), secret_url, &[wallet("aa")])
            .await
            .unwrap_err();
        assert_eq!(error, CollateralCashError::InvalidEndpoint);
        assert!(!error.to_string().contains("supersecret"));
        assert!(!format!("{error:?}").contains("supersecret"));
    }

    #[test]
    fn accepts_ipv6_loopback_and_rejects_nonloopback_ipv6() {
        assert!(validate_rpc_url("http://[::1]:8545/").is_ok());
        assert_eq!(
            validate_rpc_url("http://[2001:db8::1]:8545/"),
            Err(CollateralCashError::InvalidEndpoint)
        );
    }

    #[tokio::test]
    async fn enforces_single_response_byte_cap() {
        let oversized = Fixture::default();
        oversized.0.lock().unwrap().padding_bytes = MAX_RPC_RESPONSE_BYTES;
        let url = server(oversized.clone()).await;
        assert_eq!(
            fast(&Client::new(), &url, &[wallet("aa")]).await,
            Err(CollateralCashError::ResponseTooLarge)
        );
        assert_eq!(oversized.0.lock().unwrap().requests.len(), 1);
    }

    #[tokio::test]
    async fn artifact_round_trip_preserves_frames_without_endpoint_credentials() {
        let fixture = Fixture::default();
        let local_url = server(fixture).await;
        let secret_url = local_url.replacen("http://", "http://user-secret:password-secret@", 1);
        let snapshot = fast(&Client::new(), &secret_url, &[wallet("aa"), wallet("bb")])
            .await
            .unwrap();

        let artifact = snapshot.to_artifact().unwrap();
        assert!(artifact.len() <= MAX_COLLATERAL_ARTIFACT_BYTES);
        let artifact_text = std::str::from_utf8(&artifact).unwrap();
        assert!(!artifact_text.contains(&secret_url));
        assert!(!artifact_text.contains("user-secret"));
        assert!(!artifact_text.contains("password-secret"));
        assert_eq!(
            serde_json::from_slice::<Value>(&artifact).unwrap()["version"],
            2
        );
        let restored = CollateralCashSnapshot::from_artifact(&artifact).unwrap();
        assert_eq!(restored, snapshot);
        assert_eq!(restored.block.chain_id, POLYGON_CHAIN_ID);
        assert_eq!(
            restored.balances[0].balance_word,
            snapshot.balances[0].balance_word
        );
    }

    /// Build a version-1 (one `eth_call` per balance) snapshot by hand.
    fn single_call_snapshot(wallets: &[String]) -> CollateralCashSnapshot {
        let block =
            json!({"number":"0x1234","hash":format!("0x{}", "11".repeat(32)),"timestamp":"0x6789"});
        let mut frames: Vec<(&str, Value, Value)> = vec![
            ("eth_chainId", json!([]), json!("0x89")),
            (
                "eth_getBlockByNumber",
                json!(["finalized", false]),
                block.clone(),
            ),
        ];
        let six = format!("0x{}06", "00".repeat(31));
        for token in [PUSD_ADDRESS, USDCE_ADDRESS] {
            frames.push((
                "eth_call",
                json!([{"to": token, "data": format!("0x{DECIMALS_SELECTOR}")}, "0x1234"]),
                json!(six),
            ));
        }
        let mut balances = Vec::new();
        for wallet in wallets {
            for asset in [CollateralAsset::Pusd, CollateralAsset::UsdcE] {
                frames.push((
                    "eth_call",
                    json!([{"to": asset.address(), "data": balance_of_calldata(wallet).unwrap()}, "0x1234"]),
                    json!(format!("0x{}2a", "00".repeat(31))),
                ));
                let mut balance_word = [0u8; 32];
                balance_word[31] = BALANCE;
                balances.push(CollateralBalance {
                    wallet: wallet.clone(),
                    asset,
                    balance_word,
                    decimals: 6,
                });
            }
        }
        frames.push(("eth_getBlockByNumber", json!(["0x1234", false]), block));
        let base = Utc::now();
        let requests = frames
            .into_iter()
            .enumerate()
            .map(|(index, (method, params, result))| {
                let request_id = index as u64 + 1;
                CollateralRpcEvidence {
                    method: method.to_owned(),
                    request_id,
                    started_at: base + chrono::Duration::milliseconds(index as i64 * 10),
                    completed_at: base + chrono::Duration::milliseconds(index as i64 * 10 + 5),
                    request_body: encode_rpc_request(request_id, method, &params).unwrap(),
                    response_body: serde_json::to_vec(
                        &json!({"jsonrpc":"2.0","id":request_id,"result":result}),
                    )
                    .unwrap(),
                }
            })
            .collect();
        CollateralCashSnapshot {
            source: CollateralCashSource::ProviderReported,
            block: CollateralCashBlock {
                chain_id: POLYGON_CHAIN_ID,
                number: 0x1234,
                hash: format!("0x{}", "11".repeat(32)),
                timestamp: 0x6789,
            },
            wallets: wallets.to_vec(),
            balances,
            requests,
        }
    }

    #[test]
    fn version_one_single_call_artifacts_still_replay_and_keep_their_version() {
        let snapshot = single_call_snapshot(&[wallet("aa"), wallet("bb")]);
        assert_eq!(snapshot.requests.len(), 9);
        let bytes = snapshot.to_artifact().unwrap();
        let artifact: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(artifact["version"], 1);
        assert_eq!(
            CollateralCashSnapshot::from_artifact(&bytes).unwrap(),
            snapshot
        );
        // A version label that disagrees with the frame layout is refused.
        for version in [2, 3] {
            let mut relabelled = artifact.clone();
            relabelled["version"] = json!(version);
            assert_eq!(
                CollateralCashSnapshot::from_artifact(&serde_json::to_vec(&relabelled).unwrap()),
                Err(CollateralCashError::InvalidArtifact)
            );
        }
    }

    #[tokio::test]
    async fn artifact_replay_rejects_projection_and_raw_frame_mismatches() {
        let fixture = Fixture::default();
        let url = server(fixture).await;
        let snapshot = fast(&Client::new(), &url, &[wallet("aa"), wallet("bb")])
            .await
            .unwrap();
        let bytes = snapshot.to_artifact().unwrap();
        let artifact: Value = serde_json::from_slice(&bytes).unwrap();

        let mut mutations = Vec::new();
        let mut changed_wallet = artifact.clone();
        changed_wallet["wallets"][0] = json!(wallet("cc"));
        mutations.push(changed_wallet);

        let mut changed_asset = artifact.clone();
        changed_asset["balances"][0]["asset"] = json!("usdc_e");
        mutations.push(changed_asset);

        let mut changed_amount = artifact.clone();
        changed_amount["balances"][0]["balance_word"] = json!(format!("0x{}2b", "00".repeat(31)));
        mutations.push(changed_amount);

        let mut changed_block = artifact.clone();
        changed_block["block"]["timestamp"] = json!(0x678a);
        mutations.push(changed_block);

        let mut changed_request = artifact.clone();
        let request_body = changed_request["requests"][0]["request_body"]
            .as_str()
            .unwrap()
            .replace("eth_chainId", "eth_blockNumber");
        changed_request["requests"][0]["request_body"] = json!(request_body);
        mutations.push(changed_request);

        // The Multicall3 target and the allowFailure flag are bound by the
        // exact request bytes.
        let mut changed_target = artifact.clone();
        let request_body = changed_target["requests"][2]["request_body"]
            .as_str()
            .unwrap()
            .replace(&MULTICALL3_ADDRESS[2..], &"11".repeat(20));
        changed_target["requests"][2]["request_body"] = json!(request_body);
        mutations.push(changed_target);

        let mut changed_id = artifact.clone();
        changed_id["requests"][0]["request_id"] = json!(2);
        mutations.push(changed_id);

        let mut changed_time = artifact.clone();
        changed_time["requests"][0]["completed_at"] = json!("1970-01-01T00:00:00Z");
        mutations.push(changed_time);

        // Change one balance inside the raw aggregate3 response frame.
        let mut changed_response = artifact.clone();
        let response_body: &str = changed_response["requests"][2]["response_body"]
            .as_str()
            .unwrap();
        let mut response: Value = serde_json::from_str(response_body).unwrap();
        let mut result = response["result"].as_str().unwrap().to_owned();
        result.replace_range(result.len() - 2.., "2b");
        response["result"] = json!(result);
        changed_response["requests"][2]["response_body"] = json!(response.to_string());
        mutations.push(changed_response);

        // A cleared success flag in the raw frame is a failed sub-call.
        let mut failed_subcall = artifact.clone();
        let response_body: &str = failed_subcall["requests"][2]["response_body"]
            .as_str()
            .unwrap();
        let mut response: Value = serde_json::from_str(response_body).unwrap();
        let mut bytes = parse_hex_bytes(response["result"].as_str().unwrap()).unwrap();
        let first_element = 64 + 6 * 32;
        bytes[first_element + 31] = 0;
        response["result"] = json!(format!("0x{}", encode_hex(&bytes)));
        failed_subcall["requests"][2]["response_body"] = json!(response.to_string());
        mutations.push(failed_subcall);

        for mutation in mutations {
            let bytes = serde_json::to_vec(&mutation).unwrap();
            assert_eq!(
                CollateralCashSnapshot::from_artifact(&bytes),
                Err(CollateralCashError::InvalidArtifact)
            );
        }
    }

    #[tokio::test]
    async fn artifact_replay_enforces_raw_frame_and_outer_byte_limits() {
        let fixture = Fixture::default();
        let url = server(fixture).await;
        let snapshot = fast(&Client::new(), &url, &[wallet("aa")]).await.unwrap();
        let mut artifact: Value = serde_json::from_slice(&snapshot.to_artifact().unwrap()).unwrap();
        artifact["requests"][0]["response_body"] = json!("x".repeat(MAX_RPC_RESPONSE_BYTES + 1));
        let oversized_frame = serde_json::to_vec(&artifact).unwrap();
        assert_eq!(
            CollateralCashSnapshot::from_artifact(&oversized_frame),
            Err(CollateralCashError::InvalidArtifact)
        );
        assert_eq!(
            CollateralCashSnapshot::from_artifact(&vec![b'x'; MAX_COLLATERAL_ARTIFACT_BYTES + 1]),
            Err(CollateralCashError::ArtifactTooLarge)
        );
        let error = CollateralCashSnapshot::from_artifact(b"password-secret").unwrap_err();
        assert!(!error.to_string().contains("password-secret"));
    }
}
