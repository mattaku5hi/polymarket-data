//! Bounded provider observations of Polygon pUSD and USDC.e balances, plus
//! pure composition with current venue-reported position values.
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
const TOKEN_DECIMALS: u8 = 6;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RPC_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_TOTAL_RESPONSE_BYTES: usize = 1024 * 1024;
const BALANCE_OF_SELECTOR: &str = "70a08231";
const DECIMALS_SELECTOR: &str = "313ce567";

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
        validate_snapshot(self)?;
        let artifact = CollateralCashArtifact {
            version: COLLATERAL_CASH_ARTIFACT_VERSION,
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
        if artifact.version != COLLATERAL_CASH_ARTIFACT_VERSION
            || artifact.source != CollateralCashSource::ProviderReported.as_str()
        {
            return Err(CollateralCashError::InvalidArtifact);
        }
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
        validate_snapshot(&snapshot)?;
        Ok(snapshot)
    }
}

const COLLATERAL_CASH_ARTIFACT_VERSION: u8 = 1;

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
    #[error("collateral cash artifact is invalid or internally inconsistent")]
    InvalidArtifact,
    #[error("collateral cash artifact exceeded its byte limit")]
    ArtifactTooLarge,
}

/// Read pUSD and USDC.e balances at one provider-reported finalized block.
/// Wallets are normalized to lowercase before duplicate checks and requests.
/// The request uses exactly `5 + 2 * wallets.len()` sequential JSON-RPC calls.
///
/// # Errors
///
/// Rejects invalid inputs, endpoint policy violations, transport/RPC failures,
/// malformed ABI data, non-Polygon endpoints, unexpected token decimals, or
/// a changed block header. Errors never include the RPC URL.
pub async fn fetch_collateral_cash_snapshot(
    client: &Client,
    rpc_url: &str,
    wallets: &[impl AsRef<str>],
) -> Result<CollateralCashSnapshot, CollateralCashError> {
    let wallets = canonical_wallets(wallets)?;
    validate_rpc_url(rpc_url)?;

    timeout(TOTAL_TIMEOUT, async {
        let mut rpc = RpcRead::new(client, rpc_url);
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

        let pusd_decimals = fetch_decimals(&mut rpc, PUSD_ADDRESS, &block_tag).await?;
        let usdce_decimals = fetch_decimals(&mut rpc, USDCE_ADDRESS, &block_tag).await?;
        let mut balances = Vec::with_capacity(wallets.len() * 2);
        for wallet in &wallets {
            for (asset, decimals) in [
                (CollateralAsset::Pusd, pusd_decimals),
                (CollateralAsset::UsdcE, usdce_decimals),
            ] {
                let calldata = balance_of_calldata(wallet)?;
                let result = rpc
                    .call(
                        "eth_call",
                        json!([{"to": asset.address(), "data": calldata}, block_tag.as_str()]),
                    )
                    .await?;
                balances.push(CollateralBalance {
                    wallet: wallet.clone(),
                    asset,
                    balance_word: parse_word(
                        result
                            .as_str()
                            .ok_or(CollateralCashError::MalformedResponse)?,
                    )?,
                    decimals,
                });
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

struct RpcRead<'a> {
    client: &'a Client,
    rpc_url: &'a str,
    response_bytes: usize,
    evidence: Vec<CollateralRpcEvidence>,
}

impl<'a> RpcRead<'a> {
    fn new(client: &'a Client, rpc_url: &'a str) -> Self {
        Self {
            client,
            rpc_url,
            response_bytes: 0,
            evidence: Vec::new(),
        }
    }

    async fn call(&mut self, method: &str, params: Value) -> Result<Value, CollateralCashError> {
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

async fn fetch_decimals(
    rpc: &mut RpcRead<'_>,
    token: &str,
    block_tag: &str,
) -> Result<u8, CollateralCashError> {
    let result = rpc
        .call(
            "eth_call",
            json!([{"to": token, "data": format!("0x{DECIMALS_SELECTOR}")}, block_tag]),
        )
        .await?;
    parse_decimals_result(&result)
}

fn parse_decimals_result(result: &Value) -> Result<u8, CollateralCashError> {
    let word = parse_word(
        result
            .as_str()
            .ok_or(CollateralCashError::MalformedResponse)?,
    )?;
    if word[..31].iter().any(|byte| *byte != 0) {
        return Err(CollateralCashError::WrongDecimals);
    }
    let decimals = word[31];
    if decimals != TOKEN_DECIMALS {
        return Err(CollateralCashError::WrongDecimals);
    }
    Ok(decimals)
}

fn validate_snapshot(snapshot: &CollateralCashSnapshot) -> Result<(), CollateralCashError> {
    let wallets =
        canonical_wallets(&snapshot.wallets).map_err(|_| CollateralCashError::InvalidArtifact)?;
    if wallets != snapshot.wallets || snapshot.block.chain_id != POLYGON_CHAIN_ID {
        return Err(CollateralCashError::InvalidArtifact);
    }
    let expected_requests = 5 + 2 * wallets.len();
    if snapshot.requests.len() != expected_requests {
        return Err(CollateralCashError::InvalidArtifact);
    }

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
    for wallet in &wallets {
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
        wrong_id: bool,
        reorg: bool,
        rpc_error: bool,
        padding_bytes: usize,
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
                let data = request["params"][0]["data"].as_str().unwrap();
                Value::String(if data == format!("0x{DECIMALS_SELECTOR}") {
                    let decimals = if state.wrong_decimals { 18 } else { 6 };
                    format!("0x{}{:02x}", "00".repeat(31), decimals)
                } else if state.malformed_abi {
                    "0x1234".to_owned()
                } else {
                    format!("0x{}", "00".repeat(31) + "2a")
                })
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

    #[tokio::test]
    async fn reads_both_assets_at_one_finalized_block_and_captures_exact_calls() {
        let fixture = Fixture::default();
        let url = server(fixture.clone()).await;
        let snapshot =
            fetch_collateral_cash_snapshot(&Client::new(), &url, &[wallet("aa"), wallet("bb")])
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
                .all(|balance| balance.balance_word[31] == 0x2a)
        );
        assert_eq!(snapshot.requests.len(), 9);
        assert!(
            snapshot
                .requests
                .iter()
                .all(|request| request.started_at <= request.completed_at)
        );
        assert_eq!(snapshot.requests[0].method(), "eth_chainId");
        assert_eq!(snapshot.requests[1].method(), "eth_getBlockByNumber");
        assert_eq!(snapshot.requests[8].request_id(), 9);
        let observed = fixture.0.lock().unwrap();
        assert_eq!(observed.requests.len(), 9);
        assert_eq!(observed.requests[1]["params"], json!(["finalized", false]));
        assert_eq!(observed.requests[2]["params"][1], "0x1234");
        assert_eq!(observed.requests[3]["params"][1], "0x1234");
        assert_eq!(observed.requests[8]["params"], json!(["0x1234", false]));
        for request in observed.requests.iter().skip(4).take(4) {
            assert_eq!(request["params"][1], "0x1234");
        }
        assert_eq!(observed.requests[4]["params"][0]["to"], PUSD_ADDRESS);
        assert_eq!(observed.requests[5]["params"][0]["to"], USDCE_ADDRESS);
        assert_eq!(
            observed.requests[4]["params"][0]["data"],
            format!(
                "0x{BALANCE_OF_SELECTOR}{}{}",
                "0".repeat(24),
                "aa".repeat(20)
            )
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
                fetch_collateral_cash_snapshot(&Client::new(), &url, &wallets).await,
                Err(CollateralCashError::InvalidInput)
            );
        }
        let too_many = vec![wallet("ab"); MAX_COLLATERAL_WALLETS + 1];
        assert_eq!(
            fetch_collateral_cash_snapshot(&Client::new(), &url, &too_many).await,
            Err(CollateralCashError::InvalidInput)
        );
        assert!(fixture.0.lock().unwrap().requests.is_empty());
    }

    #[tokio::test]
    async fn rejects_wrong_chain_decimals_abi_id_rpc_errors_and_block_changes() {
        for (field, expected) in [
            ("wrong_chain", CollateralCashError::WrongChain),
            ("wrong_decimals", CollateralCashError::WrongDecimals),
            ("malformed_abi", CollateralCashError::MalformedResponse),
            ("wrong_id", CollateralCashError::MalformedResponse),
            ("rpc_error", CollateralCashError::RpcError(-32000)),
            ("reorg", CollateralCashError::BlockChanged),
        ] {
            let fixture = Fixture::default();
            match field {
                "wrong_chain" => fixture.0.lock().unwrap().wrong_chain = true,
                "wrong_decimals" => fixture.0.lock().unwrap().wrong_decimals = true,
                "malformed_abi" => fixture.0.lock().unwrap().malformed_abi = true,
                "wrong_id" => fixture.0.lock().unwrap().wrong_id = true,
                "rpc_error" => fixture.0.lock().unwrap().rpc_error = true,
                "reorg" => fixture.0.lock().unwrap().reorg = true,
                _ => unreachable!(),
            }
            let url = server(fixture).await;
            let error = fetch_collateral_cash_snapshot(&Client::new(), &url, &[wallet("aa")])
                .await
                .unwrap_err();
            assert_eq!(error, expected);
            assert!(!error.to_string().contains("hidden provider detail"));
            assert!(!format!("{error:?}").contains(&url));
        }
    }

    #[tokio::test]
    async fn rejects_bad_endpoints_without_echoing_credentials() {
        let secret_url = "http://user:supersecret@rpc.example.invalid/path";
        let error = fetch_collateral_cash_snapshot(&Client::new(), secret_url, &[wallet("aa")])
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
    async fn enforces_single_response_and_aggregate_byte_caps() {
        let oversized = Fixture::default();
        oversized.0.lock().unwrap().padding_bytes = MAX_RPC_RESPONSE_BYTES;
        let url = server(oversized.clone()).await;
        assert_eq!(
            fetch_collateral_cash_snapshot(&Client::new(), &url, &[wallet("aa")]).await,
            Err(CollateralCashError::ResponseTooLarge)
        );
        assert_eq!(oversized.0.lock().unwrap().requests.len(), 1);

        let aggregate = Fixture::default();
        aggregate.0.lock().unwrap().padding_bytes = 55_500;
        let url = server(aggregate.clone()).await;
        let wallets = (1..=7)
            .map(|number| wallet(&format!("{number:02x}")))
            .collect::<Vec<_>>();
        assert_eq!(
            fetch_collateral_cash_snapshot(&Client::new(), &url, &wallets).await,
            Err(CollateralCashError::ResponseTooLarge)
        );
        assert_eq!(aggregate.0.lock().unwrap().requests.len(), 19);
    }

    #[tokio::test]
    async fn artifact_round_trip_preserves_frames_without_endpoint_credentials() {
        let fixture = Fixture::default();
        let local_url = server(fixture).await;
        let secret_url = local_url.replacen("http://", "http://user-secret:password-secret@", 1);
        let snapshot = fetch_collateral_cash_snapshot(
            &Client::new(),
            &secret_url,
            &[wallet("aa"), wallet("bb")],
        )
        .await
        .unwrap();

        let artifact = snapshot.to_artifact().unwrap();
        assert!(artifact.len() <= MAX_COLLATERAL_ARTIFACT_BYTES);
        let artifact_text = std::str::from_utf8(&artifact).unwrap();
        assert!(!artifact_text.contains(&secret_url));
        assert!(!artifact_text.contains("user-secret"));
        assert!(!artifact_text.contains("password-secret"));
        let restored = CollateralCashSnapshot::from_artifact(&artifact).unwrap();
        assert_eq!(restored, snapshot);
        assert_eq!(restored.block.chain_id, POLYGON_CHAIN_ID);
        assert_eq!(
            restored.balances[0].balance_word,
            snapshot.balances[0].balance_word
        );
    }

    #[tokio::test]
    async fn artifact_replay_rejects_projection_and_raw_frame_mismatches() {
        let fixture = Fixture::default();
        let url = server(fixture).await;
        let snapshot =
            fetch_collateral_cash_snapshot(&Client::new(), &url, &[wallet("aa"), wallet("bb")])
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

        let mut changed_id = artifact.clone();
        changed_id["requests"][0]["request_id"] = json!(2);
        mutations.push(changed_id);

        let mut changed_time = artifact.clone();
        changed_time["requests"][0]["completed_at"] = json!("1970-01-01T00:00:00Z");
        mutations.push(changed_time);

        let mut changed_response = artifact.clone();
        let response_body: &str = changed_response["requests"][4]["response_body"]
            .as_str()
            .unwrap();
        let mut response: Value = serde_json::from_str(response_body).unwrap();
        response["result"] = json!(format!("0x{}2b", "00".repeat(31)));
        changed_response["requests"][4]["response_body"] = json!(response.to_string());
        mutations.push(changed_response);

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
        let snapshot = fetch_collateral_cash_snapshot(&Client::new(), &url, &[wallet("aa")])
            .await
            .unwrap();
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
