//! Bounded provider-reported wallet movement logs for one current interval.
//!
//! This child module shares `rpc_position_history`'s private transport, limits,
//! JSON-RPC validation and endpoint redaction. It does not classify flows,
//! verify state, or claim cash-inclusive NAV.

use std::{collections::BTreeMap, time::Duration};

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tokio::time::Instant;

#[cfg(feature = "chain-audit")]
use crate::chain_log_audit::{
    ChainMakerFill, EXCHANGES, V1_ORDER_FILLED, V2_ORDER_FILLED,
    decode_provider_reported_maker_fill,
};

use super::{
    CurrentIntervalLogFamily, MAX_HISTORY_REQUESTS, MAX_HISTORY_TOTAL_BYTES, RPC_CHAIN_ID,
    ReadState, RecordedRpcPositionHistoryPage, RpcCallSource, RpcPositionHistoryError,
    RpcPositionHistoryPage, RpcPositionHistoryReader, RpcPositionHistoryRequest,
    RpcPositionHistoryRequestPhase, parse_header, parse_quantity, quantity,
};
use crate::{
    collateral_cash::{PUSD_ADDRESS, USDCE_ADDRESS},
    position_history::{
        CTF_EMITTER, POSITION_MANAGER_EMITTER, PositionHistoryDirection, PositionTransferLog,
        TRANSFER_BATCH_TOPIC, TRANSFER_SINGLE_TOPIC, normalize_address, normalize_hash,
        normalize_log,
    },
};

#[cfg(feature = "chain-audit")]
pub mod portfolio_flow;

const ERC20_TRANSFER_TOPIC: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const MAX_BLOCK_SPAN: u64 = 2_048;
const LOG_CHUNK_BLOCKS: u64 = 128;
const MAX_EVENT_BLOCKS: usize = 384;
const MAX_UNIQUE_LOGS: usize = 20_000;
const MAX_TOTAL_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_WALLETS: usize = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcCurrentIntervalCensusRequest {
    pub wallets: Vec<String>,
    /// Previous cash snapshot block, whose hash is checked before the log range.
    pub start_block: u64,
    pub expected_start_hash: String,
    /// New cash snapshot's finalized block and expected hash.
    pub through_block: u64,
    pub expected_through_hash: String,
    pub max_requests: usize,
    pub max_total_response_bytes: usize,
    pub total_timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcCurrentIntervalHeader {
    pub number: u64,
    pub hash: String,
    pub timestamp: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcCurrentIntervalLog {
    /// `chain_id:transaction_hash:log_index`, stable across the two direction filters.
    pub locator: String,
    /// Kept separate from the stable event identity so reorg conflicts are detectable.
    pub block_hash: String,
    pub transaction_hash: String,
    pub block_number: u64,
    pub transaction_index: u64,
    pub log_index: u64,
    pub asset: RpcCurrentIntervalAsset,
    pub from: String,
    pub to: String,
    /// ERC-20 amount as the original 32-byte ABI word, not converted money.
    pub amount_word: Option<String>,
    /// Present for ERC-1155 logs; retains the existing strict decoder's raw topics/data.
    pub position_log: Option<PositionTransferLog>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcCurrentIntervalAsset {
    Pusd,
    UsdcE,
    Ctf,
    PositionManager,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcCurrentIntervalSource {
    ProviderReported,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcCurrentIntervalCensus {
    pub wallets: Vec<String>,
    /// Logs are in `(start_block, through_block]`.
    pub start_block: u64,
    pub through_block: u64,
    pub start_header: RpcCurrentIntervalHeader,
    pub end_header: RpcCurrentIntervalHeader,
    /// Timestamp-bearing headers for every block containing a returned log.
    pub event_headers: Vec<RpcCurrentIntervalHeader>,
    pub logs: Vec<RpcCurrentIntervalLog>,
    pub source: RpcCurrentIntervalSource,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub elapsed: Duration,
    pub request_count: usize,
    pub response_bytes: usize,
    /// Ordered raw JSON-RPC request/response evidence; endpoint is omitted.
    pub requests: Vec<RpcPositionHistoryPage>,
}

/// Provider-reported owner fill from the current interval's single grouped
/// maker-topic query. The enclosing census retains the raw response frame.
#[cfg(feature = "chain-audit")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcCurrentIntervalOwnerFill {
    pub fill: ChainMakerFill,
    pub transaction_index: u64,
    pub block_timestamp: u64,
}

/// Opt-in transfer census plus first-four-exchange CTF owner fills.
/// Request/byte totals and raw request frames in `census` cover both parts.
/// This remains provider-reported event data, not receipt, flow, or NAV proof.
#[cfg(feature = "chain-audit")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcCurrentIntervalOwnerFillCensus {
    pub census: RpcCurrentIntervalCensus,
    pub owner_fills: Vec<RpcCurrentIntervalOwnerFill>,
}

#[cfg(feature = "chain-audit")]
type OwnerFillResult = Vec<RpcCurrentIntervalOwnerFill>;
#[cfg(not(feature = "chain-audit"))]
type OwnerFillResult = ();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    From,
    To,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Locator {
    chain_id: u64,
    transaction_hash: String,
    log_index: u64,
}

impl RpcPositionHistoryReader {
    /// Read pUSD, USDC.e, CTF and Position Manager transfers through one
    /// provider, using the existing bounded RPC transport. This is a raw event
    /// census, not external-flow classification, a state proof or NAV.
    pub async fn read_current_interval_census(
        &self,
        request: &RpcCurrentIntervalCensusRequest,
    ) -> Result<RpcCurrentIntervalCensus, RpcPositionHistoryError> {
        self.read_current_interval_census_chunked(request, LOG_CHUNK_BLOCKS)
            .await
    }

    /// Read a current interval using bounded log queries no wider than the
    /// requested number of blocks. The transport and total request limits
    /// still apply to the complete census.
    pub async fn read_current_interval_census_chunked(
        &self,
        request: &RpcCurrentIntervalCensusRequest,
        max_blocks_per_log_query: u64,
    ) -> Result<RpcCurrentIntervalCensus, RpcPositionHistoryError> {
        let mut source = RpcCallSource::network(self, false);
        Self::read_current_interval_inner(request, false, max_blocks_per_log_query, &mut source)
            .await
            .map(|(census, _)| census)
    }

    /// Opt in to one grouped OrderFilled maker-topic query per block chunk.
    /// The selected wallets are ORed at topic 2, so one query covers indexed
    /// maker ownership without adding a redundant taker-topic query.
    #[cfg(feature = "chain-audit")]
    pub async fn read_current_interval_owner_fills(
        &self,
        request: &RpcCurrentIntervalCensusRequest,
    ) -> Result<RpcCurrentIntervalOwnerFillCensus, RpcPositionHistoryError> {
        self.read_current_interval_owner_fills_chunked(request, LOG_CHUNK_BLOCKS)
            .await
    }

    /// Read owner fills with the same bounded chunk width used by the transfer
    /// census. Every chunk uses identical filters in live and recorded reads.
    #[cfg(feature = "chain-audit")]
    pub async fn read_current_interval_owner_fills_chunked(
        &self,
        request: &RpcCurrentIntervalCensusRequest,
        max_blocks_per_log_query: u64,
    ) -> Result<RpcCurrentIntervalOwnerFillCensus, RpcPositionHistoryError> {
        let mut source = RpcCallSource::network(self, false);
        let (census, owner_fills) =
            Self::read_current_interval_inner(request, true, max_blocks_per_log_query, &mut source)
                .await?;
        Ok(RpcCurrentIntervalOwnerFillCensus {
            census,
            owner_fills,
        })
    }

    async fn read_current_interval_inner(
        request: &RpcCurrentIntervalCensusRequest,
        include_owner_fills: bool,
        max_blocks_per_log_query: u64,
        source: &mut RpcCallSource<'_>,
    ) -> Result<(RpcCurrentIntervalCensus, OwnerFillResult), RpcPositionHistoryError> {
        if !(1..=LOG_CHUNK_BLOCKS).contains(&max_blocks_per_log_query) {
            return Err(RpcPositionHistoryError::InvalidInput);
        }
        if request.wallets.is_empty() || request.wallets.len() > MAX_WALLETS {
            return Err(RpcPositionHistoryError::InvalidInput);
        }
        let mut wallets = Vec::with_capacity(request.wallets.len());
        for wallet in &request.wallets {
            wallets.push(normalize_address(wallet).ok_or(RpcPositionHistoryError::InvalidInput)?);
        }
        wallets.sort();
        if wallets.windows(2).any(|pair| pair[0] == pair[1])
            || wallets
                .iter()
                .any(|wallet| wallet == &format!("0x{}", "00".repeat(20)))
        {
            return Err(RpcPositionHistoryError::InvalidInput);
        }
        let expected_start_hash = normalize_hash(&request.expected_start_hash)
            .ok_or(RpcPositionHistoryError::InvalidInput)?;
        let expected_end_hash = normalize_hash(&request.expected_through_hash)
            .ok_or(RpcPositionHistoryError::InvalidInput)?;
        let span = request
            .through_block
            .checked_sub(request.start_block)
            .filter(|span| *span > 0)
            .ok_or(RpcPositionHistoryError::InvalidInput)?;
        if span > MAX_BLOCK_SPAN
            || request.max_requests == 0
            || request.max_requests > MAX_HISTORY_REQUESTS
            || request.max_total_response_bytes == 0
            || request.max_total_response_bytes > MAX_HISTORY_TOTAL_BYTES
            || request.total_timeout.is_zero()
            || request.total_timeout > MAX_TOTAL_TIMEOUT
        {
            return Err(RpcPositionHistoryError::InvalidInput);
        }
        let chunks = span.div_ceil(max_blocks_per_log_query);
        // Five chain/finality/anchor calls, four filters per chunk, and at
        // most one timestamp header per distinct event block.
        let filters_per_chunk = if include_owner_fills { 5 } else { 4 };
        let minimum_calls = 5_u128 + filters_per_chunk * u128::from(chunks);
        if minimum_calls > request.max_requests as u128 {
            return Err(RpcPositionHistoryError::RequestBudgetExceeded);
        }

        let log_from_block = request
            .start_block
            .checked_add(1)
            .ok_or(RpcPositionHistoryError::InvalidInput)?;
        let transport = RpcPositionHistoryRequest {
            holder_address: wallets[0].clone(),
            from_block: log_from_block,
            through_block: request.through_block,
            expected_through_hash: expected_end_hash.clone(),
            max_requests: request.max_requests,
            max_total_response_bytes: request.max_total_response_bytes,
            total_timeout: request.total_timeout,
        };
        let timer = Instant::now();
        let started_at = Utc::now();
        let deadline = timer
            .checked_add(request.total_timeout)
            .ok_or(RpcPositionHistoryError::InvalidInput)?;
        let mut state = ReadState {
            pages: Vec::new(),
            response_bytes: 0,
            next_id: 1,
        };
        let chain = source
            .call(
                "eth_chainId",
                json!([]),
                RpcPositionHistoryRequestPhase::Chain,
                deadline,
                &transport,
                &mut state,
            )
            .await?;
        if parse_quantity(&chain) != Some(RPC_CHAIN_ID) {
            return Err(RpcPositionHistoryError::WrongChain);
        }
        let finalized = source
            .call(
                "eth_getBlockByNumber",
                json!(["finalized", false]),
                RpcPositionHistoryRequestPhase::Finalized,
                deadline,
                &transport,
                &mut state,
            )
            .await?;
        let finalized_header = parse_header(&finalized)?;
        if finalized_header.number < request.through_block {
            return Err(RpcPositionHistoryError::NotFinalized);
        }
        if finalized_header.number == request.through_block
            && finalized_header.hash != expected_end_hash
        {
            return Err(RpcPositionHistoryError::ConflictingHeader);
        }
        let start_value = source
            .call(
                "eth_getBlockByNumber",
                json!([quantity(request.start_block), false]),
                RpcPositionHistoryRequestPhase::CurrentIntervalStartAnchor,
                deadline,
                &transport,
                &mut state,
            )
            .await?;
        let start_header = read_header(&start_value, request.start_block)?;
        if start_header.hash != expected_start_hash {
            return Err(RpcPositionHistoryError::AnchorMismatch);
        }
        let end_value = source
            .call(
                "eth_getBlockByNumber",
                json!([quantity(request.through_block), false]),
                RpcPositionHistoryRequestPhase::CurrentIntervalEndBefore,
                deadline,
                &transport,
                &mut state,
            )
            .await?;
        let end_header = read_header(&end_value, request.through_block)?;
        if end_header.hash != expected_end_hash {
            return Err(RpcPositionHistoryError::AnchorMismatch);
        }

        if end_header.timestamp < start_header.timestamp {
            return Err(RpcPositionHistoryError::ConflictingHeader);
        }

        let base_filters = filters(&wallets, log_from_block, request.through_block)
            .ok_or(RpcPositionHistoryError::InvalidInput)?;
        let mut movements = BTreeMap::<Locator, RpcCurrentIntervalLog>::new();
        #[cfg(feature = "chain-audit")]
        let mut owner_fills = BTreeMap::<Locator, RpcCurrentIntervalOwnerFill>::new();
        let mut event_blocks = BTreeMap::<u64, String>::new();
        let mut chunk_start = log_from_block;
        while chunk_start <= request.through_block {
            let chunk_end = chunk_start
                .saturating_add(max_blocks_per_log_query - 1)
                .min(request.through_block);
            for (index, base_filter) in base_filters.iter().enumerate() {
                let direction = if index % 2 == 0 {
                    Direction::From
                } else {
                    Direction::To
                };
                let family = if index < 2 {
                    CurrentIntervalLogFamily::Collateral
                } else {
                    CurrentIntervalLogFamily::Position
                };
                let mut filter = base_filter.clone();
                filter["fromBlock"] = json!(quantity(chunk_start));
                filter["toBlock"] = json!(quantity(chunk_end));
                let phase_direction = match direction {
                    Direction::From => PositionHistoryDirection::From,
                    Direction::To => PositionHistoryDirection::To,
                };
                let response = source
                    .call(
                        "eth_getLogs",
                        json!([filter]),
                        RpcPositionHistoryRequestPhase::CurrentIntervalLogs {
                            family,
                            direction: phase_direction,
                            from_block: chunk_start,
                            through_block: chunk_end,
                        },
                        deadline,
                        &transport,
                        &mut state,
                    )
                    .await?;
                let rows = response
                    .as_array()
                    .ok_or(RpcPositionHistoryError::MalformedResponse)?;
                for row in rows {
                    let movement =
                        decode_log(row, &wallets, chunk_start, chunk_end, direction, family)?;
                    let block_number = movement.block_number;
                    let block_hash = movement_block_hash(&movement)
                        .ok_or(RpcPositionHistoryError::MalformedResponse)?
                        .to_owned();
                    if event_blocks
                        .get(&block_number)
                        .is_some_and(|previous| previous != &block_hash)
                    {
                        return Err(RpcPositionHistoryError::ConflictingHeader);
                    }
                    event_blocks.insert(block_number, block_hash);
                    #[cfg(feature = "chain-audit")]
                    if owner_fills.contains_key(&movement_key(&movement)?) {
                        return Err(RpcPositionHistoryError::ConflictingLocator);
                    }
                    insert_unique_log(&mut movements, movement)?;
                    #[cfg(feature = "chain-audit")]
                    if include_owner_fills
                        && movements.len().saturating_add(owner_fills.len()) > MAX_UNIQUE_LOGS
                    {
                        return Err(RpcPositionHistoryError::BodyBudgetExceeded);
                    }
                }
            }
            #[cfg(feature = "chain-audit")]
            if include_owner_fills {
                let mut filter = owner_fill_filter(&wallets, chunk_start, chunk_end)
                    .ok_or(RpcPositionHistoryError::InvalidInput)?;
                filter["fromBlock"] = json!(quantity(chunk_start));
                filter["toBlock"] = json!(quantity(chunk_end));
                let response = source
                    .call(
                        "eth_getLogs",
                        json!([filter]),
                        RpcPositionHistoryRequestPhase::CurrentIntervalOwnerFills {
                            from_block: chunk_start,
                            through_block: chunk_end,
                        },
                        deadline,
                        &transport,
                        &mut state,
                    )
                    .await?;
                let rows = response
                    .as_array()
                    .ok_or(RpcPositionHistoryError::MalformedResponse)?;
                for row in rows {
                    let fill = decode_owner_fill(row, &wallets, chunk_start, chunk_end)?;
                    let key = owner_fill_key(&fill);
                    if movements.contains_key(&key) {
                        return Err(RpcPositionHistoryError::ConflictingLocator);
                    }
                    let block_number = fill.fill.block_number;
                    if event_blocks
                        .get(&block_number)
                        .is_some_and(|previous| previous != &fill.fill.block_hash)
                    {
                        return Err(RpcPositionHistoryError::ConflictingHeader);
                    }
                    event_blocks.insert(block_number, fill.fill.block_hash.clone());
                    insert_unique_owner_fill(&mut owner_fills, fill)?;
                    if movements.len().saturating_add(owner_fills.len()) > MAX_UNIQUE_LOGS {
                        return Err(RpcPositionHistoryError::BodyBudgetExceeded);
                    }
                }
            }
            if chunk_end == request.through_block {
                break;
            }
            chunk_start = chunk_end
                .checked_add(1)
                .ok_or(RpcPositionHistoryError::InvalidInput)?;
        }
        validate_block_log_indices(&movements)?;
        #[cfg(feature = "chain-audit")]
        validate_owner_fill_block_log_indices(&movements, &owner_fills)?;
        if event_blocks.len() > MAX_EVENT_BLOCKS {
            return Err(RpcPositionHistoryError::RequestBudgetExceeded);
        }

        let mut event_headers = Vec::with_capacity(event_blocks.len());
        for (number, expected_hash) in event_blocks {
            let header = if number == start_header.number {
                start_header.clone()
            } else if number == end_header.number {
                end_header.clone()
            } else {
                let value = source
                    .call(
                        "eth_getBlockByNumber",
                        json!([quantity(number), false]),
                        RpcPositionHistoryRequestPhase::CurrentIntervalBlockTimestamp { number },
                        deadline,
                        &transport,
                        &mut state,
                    )
                    .await?;
                read_header(&value, number)?
            };
            if header.hash != expected_hash {
                return Err(RpcPositionHistoryError::ConflictingHeader);
            }
            if header.timestamp < start_header.timestamp || header.timestamp > end_header.timestamp
            {
                return Err(RpcPositionHistoryError::ConflictingHeader);
            }
            event_headers.push(header);
        }
        #[cfg(feature = "chain-audit")]
        for fill in owner_fills.values_mut() {
            fill.block_timestamp = event_headers
                .iter()
                .find(|header| header.number == fill.fill.block_number)
                .ok_or(RpcPositionHistoryError::MalformedResponse)?
                .timestamp;
        }
        let end_after = source
            .call(
                "eth_getBlockByNumber",
                json!([quantity(request.through_block), false]),
                RpcPositionHistoryRequestPhase::CurrentIntervalEndAfter,
                deadline,
                &transport,
                &mut state,
            )
            .await?;
        if parse_header(&end_after)? != parse_header(&end_value)?
            || read_header(&end_after, request.through_block)? != end_header
        {
            return Err(RpcPositionHistoryError::AnchorMismatch);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(RpcPositionHistoryError::Timeout);
        }
        source.finish()?;
        let mut logs: Vec<_> = movements.into_values().collect();
        logs.sort_by_key(|log| (log.block_number, log.transaction_index, log.log_index));
        let census = RpcCurrentIntervalCensus {
            wallets,
            start_block: request.start_block,
            through_block: request.through_block,
            start_header,
            end_header,
            event_headers,
            logs,
            source: RpcCurrentIntervalSource::ProviderReported,
            started_at,
            completed_at: Utc::now(),
            elapsed: timer.elapsed(),
            request_count: state.next_id.saturating_sub(1) as usize,
            response_bytes: state.response_bytes,
            requests: state.pages,
        };
        #[cfg(feature = "chain-audit")]
        let mut fills: Vec<_> = owner_fills.into_values().collect();
        #[cfg(feature = "chain-audit")]
        fills.sort_by_key(|fill| {
            (
                fill.fill.block_number,
                fill.transaction_index,
                fill.fill.log_index,
            )
        });
        #[cfg(not(feature = "chain-audit"))]
        let fills = ();
        Ok((census, fills))
    }
}

/// Replays captured four-filter RPC frames without creating a network client.
/// Timing fields report this local replay, not the original capture window.
pub async fn reverify_recorded_current_interval_census(
    request: &RpcCurrentIntervalCensusRequest,
    pages: &[RecordedRpcPositionHistoryPage],
) -> Result<RpcCurrentIntervalCensus, RpcPositionHistoryError> {
    reverify_recorded_current_interval_census_chunked(request, pages, LOG_CHUNK_BLOCKS).await
}

/// Replays captured census frames using the chunk width expected by the
/// capture. A transcript recorded with another width fails request validation.
pub async fn reverify_recorded_current_interval_census_chunked(
    request: &RpcCurrentIntervalCensusRequest,
    pages: &[RecordedRpcPositionHistoryPage],
    max_blocks_per_log_query: u64,
) -> Result<RpcCurrentIntervalCensus, RpcPositionHistoryError> {
    let mut source = RpcCallSource::Recorded {
        pages,
        next_page: 0,
    };
    let (census, _) = RpcPositionHistoryReader::read_current_interval_inner(
        request,
        false,
        max_blocks_per_log_query,
        &mut source,
    )
    .await?;
    source.finish()?;
    Ok(census)
}

/// Replays captured RPC frames without creating a reader or network client.
/// The census timing fields report this local replay, not the original capture window;
/// callers should retain original capture times alongside the recorded frames.
#[cfg(feature = "chain-audit")]
pub async fn reverify_recorded_current_interval_owner_fills(
    request: &RpcCurrentIntervalCensusRequest,
    pages: &[RecordedRpcPositionHistoryPage],
) -> Result<RpcCurrentIntervalOwnerFillCensus, RpcPositionHistoryError> {
    reverify_recorded_current_interval_owner_fills_chunked(request, pages, LOG_CHUNK_BLOCKS).await
}

/// Replays owner-fill frames using the chunk width expected by the capture.
/// A transcript recorded with another width fails request validation.
#[cfg(feature = "chain-audit")]
pub async fn reverify_recorded_current_interval_owner_fills_chunked(
    request: &RpcCurrentIntervalCensusRequest,
    pages: &[RecordedRpcPositionHistoryPage],
    max_blocks_per_log_query: u64,
) -> Result<RpcCurrentIntervalOwnerFillCensus, RpcPositionHistoryError> {
    let mut source = RpcCallSource::Recorded {
        pages,
        next_page: 0,
    };
    let (census, owner_fills) = RpcPositionHistoryReader::read_current_interval_inner(
        request,
        true,
        max_blocks_per_log_query,
        &mut source,
    )
    .await?;
    source.finish()?;
    Ok(RpcCurrentIntervalOwnerFillCensus {
        census,
        owner_fills,
    })
}

fn read_header(
    value: &Value,
    number: u64,
) -> Result<RpcCurrentIntervalHeader, RpcPositionHistoryError> {
    let parsed = parse_header(value)?;
    let timestamp = value
        .get("timestamp")
        .and_then(parse_quantity)
        .ok_or(RpcPositionHistoryError::MalformedResponse)?;
    if parsed.number != number {
        return Err(RpcPositionHistoryError::ConflictingHeader);
    }
    Ok(RpcCurrentIntervalHeader {
        number,
        hash: parsed.hash,
        timestamp,
    })
}

fn filters(wallets: &[String], from: u64, through: u64) -> Option<[Value; 4]> {
    if wallets.is_empty() || wallets.len() > MAX_WALLETS {
        return None;
    }
    let span = through.checked_sub(from)?.checked_add(1)?;
    if span > MAX_BLOCK_SPAN {
        return None;
    }
    let topics: Vec<_> = wallets
        .iter()
        .map(|wallet| normalize_address(wallet).map(|wallet| format!("0x{:0>64}", &wallet[2..])))
        .collect::<Option<_>>()?;
    let mut cash_from =
        json!({"address":[PUSD_ADDRESS, USDCE_ADDRESS], "topics":[ERC20_TRANSFER_TOPIC, topics]});
    let mut cash_to = json!({"address":[PUSD_ADDRESS, USDCE_ADDRESS], "topics":[ERC20_TRANSFER_TOPIC, null, topics]});
    let mut position_from = json!({"address":[CTF_EMITTER, POSITION_MANAGER_EMITTER], "topics":[[TRANSFER_SINGLE_TOPIC, TRANSFER_BATCH_TOPIC], null, topics]});
    let mut position_to = json!({"address":[CTF_EMITTER, POSITION_MANAGER_EMITTER], "topics":[[TRANSFER_SINGLE_TOPIC, TRANSFER_BATCH_TOPIC], null, null, topics]});
    for filter in [
        &mut cash_from,
        &mut cash_to,
        &mut position_from,
        &mut position_to,
    ] {
        filter["fromBlock"] = json!(quantity(from));
        filter["toBlock"] = json!(quantity(through));
    }
    Some([cash_from, cash_to, position_from, position_to])
}

#[cfg(feature = "chain-audit")]
fn owner_fill_filter(wallets: &[String], from: u64, through: u64) -> Option<Value> {
    if wallets.is_empty() || wallets.len() > MAX_WALLETS {
        return None;
    }
    let span = through.checked_sub(from)?.checked_add(1)?;
    if span > MAX_BLOCK_SPAN {
        return None;
    }
    let maker_topics: Vec<_> = wallets
        .iter()
        .map(|wallet| normalize_address(wallet).map(|wallet| format!("0x{:0>64}", &wallet[2..])))
        .collect::<Option<_>>()?;
    Some(json!({
        "address": &EXCHANGES[..4],
        "topics": [[V1_ORDER_FILLED, V2_ORDER_FILLED], null, maker_topics],
        "fromBlock": quantity(from),
        "toBlock": quantity(through),
    }))
}

#[cfg(feature = "chain-audit")]
fn decode_owner_fill(
    raw: &Value,
    wallets: &[String],
    from_block: u64,
    through_block: u64,
) -> Result<RpcCurrentIntervalOwnerFill, RpcPositionHistoryError> {
    let decoded = decode_provider_reported_maker_fill(raw)
        .map_err(|_| RpcPositionHistoryError::MalformedResponse)?;
    if decoded.chain_id != RPC_CHAIN_ID
        || !(from_block..=through_block).contains(&decoded.block_number)
        || !wallets.iter().any(|wallet| wallet == &decoded.wallet)
    {
        return Err(RpcPositionHistoryError::MalformedResponse);
    }
    let transaction_index = raw
        .get("transactionIndex")
        .and_then(parse_quantity)
        .ok_or(RpcPositionHistoryError::MalformedResponse)?;
    Ok(RpcCurrentIntervalOwnerFill {
        block_timestamp: 0,
        fill: decoded,
        transaction_index,
    })
}

fn decode_log(
    raw: &Value,
    wallets: &[String],
    from_block: u64,
    through_block: u64,
    direction: Direction,
    family: CurrentIntervalLogFamily,
) -> Result<RpcCurrentIntervalLog, RpcPositionHistoryError> {
    let fail = || RpcPositionHistoryError::MalformedResponse;
    if raw.get("removed").and_then(Value::as_bool) != Some(false) {
        return Err(fail());
    }
    let block_number = raw
        .get("blockNumber")
        .and_then(parse_quantity)
        .ok_or_else(fail)?;
    if !(from_block..=through_block).contains(&block_number) {
        return Err(fail());
    }
    let block_hash = raw
        .get("blockHash")
        .and_then(Value::as_str)
        .and_then(normalize_hash)
        .ok_or_else(fail)?;
    let transaction_hash = raw
        .get("transactionHash")
        .and_then(Value::as_str)
        .and_then(normalize_hash)
        .ok_or_else(fail)?;
    let transaction_index = raw
        .get("transactionIndex")
        .and_then(parse_quantity)
        .ok_or_else(fail)?;
    let log_index = raw
        .get("logIndex")
        .and_then(parse_quantity)
        .ok_or_else(fail)?;
    let emitter = raw
        .get("address")
        .and_then(Value::as_str)
        .and_then(normalize_address)
        .ok_or_else(fail)?;
    let locator = format!("{RPC_CHAIN_ID}:{transaction_hash}:{log_index}");
    if emitter == PUSD_ADDRESS || emitter == USDCE_ADDRESS {
        if family != CurrentIntervalLogFamily::Collateral {
            return Err(fail());
        }
        let topics = raw
            .get("topics")
            .and_then(Value::as_array)
            .ok_or_else(fail)?;
        let topic0 = topics
            .first()
            .and_then(Value::as_str)
            .and_then(normalize_hash)
            .ok_or_else(fail)?;
        if topics.len() != 3 || topic0 != ERC20_TRANSFER_TOPIC {
            return Err(fail());
        }
        let from = indexed_address(topics.get(1).and_then(Value::as_str).ok_or_else(fail)?)
            .ok_or_else(fail)?;
        let to = indexed_address(topics.get(2).and_then(Value::as_str).ok_or_else(fail)?)
            .ok_or_else(fail)?;
        let expected = if direction == Direction::From {
            &from
        } else {
            &to
        };
        if !wallets.iter().any(|wallet| wallet == expected) {
            return Err(fail());
        }
        let data = raw
            .get("data")
            .and_then(Value::as_str)
            .and_then(|v| v.strip_prefix("0x"))
            .ok_or_else(fail)?;
        let bytes = decode_hex(data).ok_or_else(fail)?;
        if bytes.len() != 32 {
            return Err(fail());
        }
        return Ok(RpcCurrentIntervalLog {
            locator,
            block_hash,
            transaction_hash,
            block_number,
            transaction_index,
            log_index,
            asset: if emitter == PUSD_ADDRESS {
                RpcCurrentIntervalAsset::Pusd
            } else {
                RpcCurrentIntervalAsset::UsdcE
            },
            from,
            to,
            amount_word: Some(format!("0x{}", encode_hex(&bytes))),
            position_log: None,
        });
    }
    if family != CurrentIntervalLogFamily::Position {
        return Err(fail());
    }
    let position_direction = if direction == Direction::From {
        PositionHistoryDirection::From
    } else {
        PositionHistoryDirection::To
    };
    let log = wallets
        .iter()
        .find_map(|wallet| {
            normalize_log(raw, block_number, &block_hash, wallet, position_direction).ok()
        })
        .ok_or_else(fail)?;
    crate::position_history::erc1155_abi::decode_fields(log.topics(), log.data())
        .map_err(|_| fail())?;
    let asset = match log.ledger() {
        crate::position_history::PositionLedger::Ctf => RpcCurrentIntervalAsset::Ctf,
        crate::position_history::PositionLedger::PositionManager => {
            RpcCurrentIntervalAsset::PositionManager
        }
    };
    let topics = log.topics();
    let from = indexed_address(topics.get(2).ok_or_else(fail)?).ok_or_else(fail)?;
    let to = indexed_address(topics.get(3).ok_or_else(fail)?).ok_or_else(fail)?;
    Ok(RpcCurrentIntervalLog {
        locator,
        block_hash,
        transaction_hash,
        block_number,
        transaction_index,
        log_index,
        asset,
        from,
        to,
        amount_word: None,
        position_log: Some(log),
    })
}

fn movement_key(log: &RpcCurrentIntervalLog) -> Result<Locator, RpcPositionHistoryError> {
    Ok(Locator {
        chain_id: RPC_CHAIN_ID,
        transaction_hash: log.transaction_hash.clone(),
        log_index: log.log_index,
    })
}

fn insert_unique_log(
    movements: &mut BTreeMap<Locator, RpcCurrentIntervalLog>,
    movement: RpcCurrentIntervalLog,
) -> Result<(), RpcPositionHistoryError> {
    let key = movement_key(&movement)?;
    if let Some(previous) = movements.get(&key) {
        if previous != &movement {
            return Err(RpcPositionHistoryError::ConflictingLocator);
        }
    } else {
        movements.insert(key, movement);
        if movements.len() > MAX_UNIQUE_LOGS {
            return Err(RpcPositionHistoryError::BodyBudgetExceeded);
        }
    }
    Ok(())
}

#[cfg(feature = "chain-audit")]
fn owner_fill_key(fill: &RpcCurrentIntervalOwnerFill) -> Locator {
    Locator {
        chain_id: fill.fill.chain_id,
        transaction_hash: fill.fill.transaction_hash.clone(),
        log_index: fill.fill.log_index,
    }
}

#[cfg(feature = "chain-audit")]
fn insert_unique_owner_fill(
    fills: &mut BTreeMap<Locator, RpcCurrentIntervalOwnerFill>,
    fill: RpcCurrentIntervalOwnerFill,
) -> Result<(), RpcPositionHistoryError> {
    let key = owner_fill_key(&fill);
    if let Some(previous) = fills.get(&key) {
        if previous != &fill {
            return Err(RpcPositionHistoryError::ConflictingLocator);
        }
    } else {
        fills.insert(key, fill);
    }
    Ok(())
}

#[cfg(feature = "chain-audit")]
fn validate_owner_fill_block_log_indices(
    movements: &BTreeMap<Locator, RpcCurrentIntervalLog>,
    fills: &BTreeMap<Locator, RpcCurrentIntervalOwnerFill>,
) -> Result<(), RpcPositionHistoryError> {
    let mut indices = BTreeMap::new();
    for (block_hash, log_index, transaction_hash) in movements
        .values()
        .map(|log| {
            (
                log.block_hash.as_str(),
                log.log_index,
                log.transaction_hash.as_str(),
            )
        })
        .chain(fills.values().map(|fill| {
            (
                fill.fill.block_hash.as_str(),
                fill.fill.log_index,
                fill.fill.transaction_hash.as_str(),
            )
        }))
    {
        if indices
            .insert((block_hash, log_index), transaction_hash)
            .is_some_and(|previous| previous != transaction_hash)
        {
            return Err(RpcPositionHistoryError::ConflictingLocator);
        }
    }
    Ok(())
}

fn validate_block_log_indices(
    movements: &BTreeMap<Locator, RpcCurrentIntervalLog>,
) -> Result<(), RpcPositionHistoryError> {
    let mut indices = BTreeMap::new();
    for log in movements.values() {
        if indices
            .insert(
                (log.block_hash.as_str(), log.log_index),
                log.transaction_hash.as_str(),
            )
            .is_some_and(|previous| previous != log.transaction_hash)
        {
            return Err(RpcPositionHistoryError::ConflictingLocator);
        }
    }
    Ok(())
}

fn movement_block_hash(log: &RpcCurrentIntervalLog) -> Option<&str> {
    Some(&log.block_hash)
}

fn indexed_address(topic: &str) -> Option<String> {
    let bytes = decode_hex(topic.strip_prefix("0x")?)?;
    if bytes.len() != 32 || bytes[..12].iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(format!("0x{}", encode_hex(&bytes[12..])))
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    if input.len() % 2 != 0 {
        return None;
    }
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            Some((digit(pair[0])? << 4) | digit(pair[1])?)
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, body::Bytes, extract::State, routing::post};
    use std::sync::{Arc, Mutex};

    const WALLET: &str = "0x1111111111111111111111111111111111111111";
    const TEST_OWNER_FILL_EXCHANGES: [&str; 4] = [
        "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E",
        "0xC5d563A36AE78145C45a50134d48A1215220f80a",
        "0xE111180000d2663C0091e4f400237545B87B996B",
        "0xe2222d279d744050d28e00520010520000310F59",
    ];
    const TEST_V1_ORDER_FILLED_TOPIC: &str =
        "0xd0a08e8c493f9c94f29311604c9de1b4e8c8d4c06bd0c789af57f2d65bfec0f6";
    const TEST_V2_ORDER_FILLED_TOPIC: &str =
        "0xd543adfd945773f1a62f74f0ee55a5e3b9b1a28262980ba90b1a89f2ea84d8ee";
    fn topic(address: &str) -> String {
        format!("0x{:0>64}", &address[2..])
    }

    #[test]
    fn builds_four_fixed_address_direction_filters() {
        let other = "0x2222222222222222222222222222222222222222";
        let wallets = vec![WALLET.to_owned(), other.to_owned()];
        let filters = filters(&wallets, 11, 20).unwrap();
        assert_eq!(filters[0]["address"], json!([PUSD_ADDRESS, USDCE_ADDRESS]));
        assert_eq!(
            filters[0]["topics"],
            json!([ERC20_TRANSFER_TOPIC, [topic(WALLET), topic(other)]])
        );
        assert_eq!(
            filters[1]["topics"],
            json!([ERC20_TRANSFER_TOPIC, null, [topic(WALLET), topic(other)]])
        );
        assert_eq!(
            filters[2]["address"],
            json!([CTF_EMITTER, POSITION_MANAGER_EMITTER])
        );
        assert_eq!(
            filters[2]["topics"][2],
            json!([topic(WALLET), topic(other)])
        );
        assert_eq!(
            filters[3]["topics"][3],
            json!([topic(WALLET), topic(other)])
        );
        assert!(super::filters(&wallets, 1, MAX_BLOCK_SPAN + 1).is_none());
    }

    #[cfg(feature = "chain-audit")]
    #[test]
    fn owner_fill_filter_is_one_grouped_topic_two_query_for_known_exchanges() {
        let other = "0x2222222222222222222222222222222222222222";
        let wallets = vec![WALLET.to_owned(), other.to_owned()];
        let filter = owner_fill_filter(&wallets, 11, 20).unwrap();
        assert_eq!(filter["address"], json!(&EXCHANGES[..4]));
        assert_eq!(
            filter["topics"],
            json!([
                [V1_ORDER_FILLED, V2_ORDER_FILLED],
                null,
                [topic(WALLET), topic(other)]
            ])
        );
        assert_eq!(filter["fromBlock"], "0xb");
        assert_eq!(filter["toBlock"], "0x14");
        assert!(owner_fill_filter(&wallets, 1, MAX_BLOCK_SPAN + 1).is_none());
    }

    #[cfg(feature = "chain-audit")]
    #[test]
    fn recorded_calls_allow_capped_grouped_wallet_filters_only_in_current_interval_phase() {
        let wallets: Vec<_> = (1_u128..=MAX_WALLETS as u128)
            .map(|index| format!("0x{index:040x}"))
            .collect();
        let filter = owner_fill_filter(&wallets, 11, 20).unwrap();
        let params = json!([filter]);
        let expected_request = json!({
            "jsonrpc":"2.0", "id":1, "method":"eth_getLogs", "params":params,
        })
        .to_string();
        assert!(expected_request.len() > super::super::MAX_RECORDED_REQUEST_BYTES);
        assert!(expected_request.len() <= super::super::MAX_CURRENT_INTERVAL_LOG_REQUEST_BYTES);
        let response = json!({"jsonrpc":"2.0", "id":1, "result":[]}).to_string();
        let pages = [super::super::RecordedRpcPositionHistoryPage {
            request_json: expected_request.clone(),
            response_json: response.clone(),
        }];
        let request = RpcPositionHistoryRequest {
            holder_address: wallets[0].clone(),
            from_block: 11,
            through_block: 20,
            expected_through_hash: mock_header(20)["hash"].as_str().unwrap().to_owned(),
            max_requests: 1,
            max_total_response_bytes: MAX_HISTORY_TOTAL_BYTES,
            total_timeout: Duration::from_secs(5),
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let phase = RpcPositionHistoryRequestPhase::CurrentIntervalOwnerFills {
            from_block: 11,
            through_block: 20,
        };
        let mut next_page = 0;
        let mut state = super::super::ReadState {
            pages: Vec::new(),
            response_bytes: 0,
            next_id: 1,
        };
        assert!(
            super::super::recorded_call(
                &pages,
                &mut next_page,
                (
                    "eth_getLogs",
                    json!([owner_fill_filter(&wallets, 11, 20).unwrap()])
                ),
                phase,
                deadline,
                &request,
                &mut state,
            )
            .is_ok()
        );

        let mut next_page = 0;
        let mut state = super::super::ReadState {
            pages: vec![],
            response_bytes: 0,
            next_id: 1,
        };
        let legacy_phase = RpcPositionHistoryRequestPhase::Logs {
            direction: PositionHistoryDirection::From,
            from_block: 11,
            through_block: 20,
        };
        assert_eq!(
            super::super::recorded_call(
                &pages,
                &mut next_page,
                (
                    "eth_getLogs",
                    json!([owner_fill_filter(&wallets, 11, 20).unwrap()])
                ),
                legacy_phase,
                deadline,
                &request,
                &mut state,
            ),
            Err(RpcPositionHistoryError::BodyBudgetExceeded)
        );

        let oversized_filter = json!({"padding":"x".repeat(17_000)});
        let oversized_request = json!({
            "jsonrpc":"2.0", "id":1, "method":"eth_getLogs", "params":[oversized_filter],
        })
        .to_string();
        let oversized = [super::super::RecordedRpcPositionHistoryPage {
            request_json: oversized_request,
            response_json: response,
        }];
        let mut next_page = 0;
        let mut state = super::super::ReadState {
            pages: vec![],
            response_bytes: 0,
            next_id: 1,
        };
        assert_eq!(
            super::super::recorded_call(
                &oversized,
                &mut next_page,
                ("eth_getLogs", json!([{"padding":"x".repeat(17_000)}])),
                phase,
                deadline,
                &request,
                &mut state,
            ),
            Err(RpcPositionHistoryError::BodyBudgetExceeded)
        );
    }

    #[test]
    fn strict_cash_log_validation_binds_range_wallet_and_locator() {
        let raw = json!({
            "removed":false,"blockNumber":"0x1e","blockHash":format!("0x{}", "22".repeat(32)),
            "transactionHash":format!("0x{}", "33".repeat(32)),"transactionIndex":"0x2","logIndex":"0x4",
            "address":PUSD_ADDRESS,"topics":[ERC20_TRANSFER_TOPIC,topic(WALLET),topic("0x2222222222222222222222222222222222222222")],
            "data":format!("0x{}", format!("{:064x}", 2_000_000_u64))
        });
        let parsed = decode_log(
            &raw,
            &[WALLET.to_owned()],
            21,
            30,
            Direction::From,
            CurrentIntervalLogFamily::Collateral,
        )
        .unwrap();
        assert_eq!(
            parsed.amount_word.as_deref(),
            Some(format!("0x{:064x}", 2_000_000_u64).as_str())
        );
        assert_eq!(parsed.locator, format!("137:0x{}:4", "33".repeat(32)));
        assert_eq!(parsed.block_hash, format!("0x{}", "22".repeat(32)));
        assert_eq!(parsed.transaction_hash, format!("0x{}", "33".repeat(32)));
        assert!(
            decode_log(
                &raw,
                &[WALLET.to_owned()],
                12,
                20,
                Direction::From,
                CurrentIntervalLogFamily::Collateral
            )
            .is_err()
        );
        assert!(
            decode_log(
                &raw,
                &[WALLET.to_owned()],
                21,
                30,
                Direction::To,
                CurrentIntervalLogFamily::Collateral
            )
            .is_err()
        );
    }

    #[test]
    fn refuses_removed_and_malformed_abi_rows() {
        let mut raw = json!({
            "removed":false,"blockNumber":"0x14","blockHash":format!("0x{}", "22".repeat(32)),
            "transactionHash":format!("0x{}", "33".repeat(32)),"transactionIndex":"0x2","logIndex":"0x4",
            "address":USDCE_ADDRESS,"topics":[ERC20_TRANSFER_TOPIC,topic(WALLET),topic("0x2222222222222222222222222222222222222222")],"data":"0x01"
        });
        assert!(
            decode_log(
                &raw,
                &[WALLET.to_owned()],
                12,
                20,
                Direction::From,
                CurrentIntervalLogFamily::Collateral
            )
            .is_err()
        );
        raw["removed"] = json!(true);
        assert!(
            decode_log(
                &raw,
                &[WALLET.to_owned()],
                12,
                20,
                Direction::From,
                CurrentIntervalLogFamily::Collateral
            )
            .is_err()
        );
    }

    #[test]
    fn identical_direction_overlap_deduplicates_but_locator_collision_fails() {
        let base = json!({
            "removed":false,"blockNumber":"0x14","blockHash":format!("0x{}", "22".repeat(32)),
            "transactionHash":format!("0x{}", "33".repeat(32)),"transactionIndex":"0x2","logIndex":"0x4",
            "address":PUSD_ADDRESS,"topics":[ERC20_TRANSFER_TOPIC,topic(WALLET),topic("0x2222222222222222222222222222222222222222")],
            "data":format!("0x{}", format!("{:064x}", 9_u64))
        });
        let first = decode_log(
            &base,
            &[WALLET.to_owned()],
            12,
            20,
            Direction::From,
            CurrentIntervalLogFamily::Collateral,
        )
        .unwrap();
        let same = decode_log(
            &base,
            &[WALLET.to_owned()],
            12,
            20,
            Direction::From,
            CurrentIntervalLogFamily::Collateral,
        )
        .unwrap();
        let mut unique = BTreeMap::new();
        insert_unique_log(&mut unique, first.clone()).unwrap();
        insert_unique_log(&mut unique, same).unwrap();
        assert_eq!(unique.len(), 1);

        for (field, value) in [
            ("data", json!(format!("0x{}", format!("{:064x}", 10_u64)))),
            ("blockHash", json!(format!("0x{}", "55".repeat(32)))),
            ("transactionIndex", json!("0x3")),
            ("address", json!(USDCE_ADDRESS)),
        ] {
            let mut conflict = base.clone();
            conflict[field] = value;
            let changed = decode_log(
                &conflict,
                &[WALLET.to_owned()],
                12,
                20,
                Direction::From,
                CurrentIntervalLogFamily::Collateral,
            )
            .unwrap();
            assert_eq!(
                insert_unique_log(&mut unique, changed),
                Err(RpcPositionHistoryError::ConflictingLocator),
                "changed {field} under the same event identity must conflict"
            );
        }
    }

    #[test]
    fn block_global_index_cannot_identify_two_different_transactions() {
        let raw = mock_cash_log();
        let first = decode_log(
            &raw,
            &[WALLET.to_owned()],
            10,
            20,
            Direction::From,
            CurrentIntervalLogFamily::Collateral,
        )
        .unwrap();
        let mut another = first.clone();
        another.transaction_hash = format!("0x{}", "55".repeat(32));
        another.locator = format!("137:{}:{}", another.transaction_hash, another.log_index);
        let mut movements = BTreeMap::new();
        insert_unique_log(&mut movements, first).unwrap();
        insert_unique_log(&mut movements, another.clone()).unwrap();
        assert_eq!(
            validate_block_log_indices(&movements),
            Err(RpcPositionHistoryError::ConflictingLocator)
        );
        movements.remove(&movement_key(&another).unwrap());
        another.log_index += 1;
        another.locator = format!("137:{}:{}", another.transaction_hash, another.log_index);
        insert_unique_log(&mut movements, another).unwrap();
        assert!(validate_block_log_indices(&movements).is_ok());
    }

    #[test]
    fn decoder_rejects_log_from_the_wrong_requested_filter_family() {
        let cash = mock_cash_log();
        assert!(
            decode_log(
                &cash,
                &[WALLET.to_owned()],
                10,
                20,
                Direction::From,
                CurrentIntervalLogFamily::Position,
            )
            .is_err()
        );

        let position = json!({
            "removed":false,"blockNumber":"0xf","blockHash":mock_header(15)["hash"],
            "transactionHash":format!("0x{}", "66".repeat(32)),"transactionIndex":"0x1","logIndex":"0x2",
            "address":CTF_EMITTER,"topics":[TRANSFER_SINGLE_TOPIC,topic("0x2222222222222222222222222222222222222222"),topic(WALLET),topic("0x3333333333333333333333333333333333333333")],
            "data":format!("0x{}{}", format!("{:064x}", 1_u64), format!("{:064x}", 1_u64))
        });
        assert!(
            decode_log(
                &position,
                &[WALLET.to_owned()],
                10,
                20,
                Direction::From,
                CurrentIntervalLogFamily::Collateral,
            )
            .is_err()
        );
    }

    #[test]
    fn position_log_is_checked_by_existing_strict_abi_decoder() {
        let operator = "0x2222222222222222222222222222222222222222";
        let recipient = "0x3333333333333333333333333333333333333333";
        let raw = json!({
            "removed":false,"blockNumber":"0x14","blockHash":format!("0x{}", "22".repeat(32)),
            "transactionHash":format!("0x{}", "33".repeat(32)),"transactionIndex":"0x2","logIndex":"0x4",
            "address":CTF_EMITTER,"topics":[TRANSFER_SINGLE_TOPIC,topic(operator),topic(WALLET),topic(recipient)],
            "data":format!("0x{}{}", format!("{:064x}", 17_u64), format!("{:064x}", 4_u64))
        });
        let parsed = decode_log(
            &raw,
            &[WALLET.to_owned()],
            12,
            20,
            Direction::From,
            CurrentIntervalLogFamily::Position,
        )
        .unwrap();
        assert_eq!(parsed.asset, RpcCurrentIntervalAsset::Ctf);
        assert!(parsed.position_log.is_some());
        let mut malformed = raw;
        malformed["data"] = json!("0x00");
        assert!(
            decode_log(
                &malformed,
                &[WALLET.to_owned()],
                12,
                20,
                Direction::From,
                CurrentIntervalLogFamily::Position
            )
            .is_err()
        );
    }

    #[test]
    fn position_decoder_rejects_bad_operator_padding_and_batch_layout_or_size() {
        let operator = "0x2222222222222222222222222222222222222222";
        let single_topics = vec![
            TRANSFER_SINGLE_TOPIC.to_owned(),
            topic(operator),
            topic(WALLET),
            topic("0x3333333333333333333333333333333333333333"),
        ];
        let single_data = format!("0x{:064x}{:064x}", 1_u64, 2_u64);
        let mut bad_operator = single_topics.clone();
        bad_operator[1] = format!("0x{}{}", "01".repeat(12), "22".repeat(20));
        assert!(
            crate::position_history::erc1155_abi::decode_fields(&bad_operator, &single_data,)
                .is_err()
        );

        let batch_topics = vec![
            TRANSFER_BATCH_TOPIC.to_owned(),
            topic(operator),
            topic(WALLET),
            topic("0x3333333333333333333333333333333333333333"),
        ];
        let valid_one_item = format!(
            "0x{:064x}{:064x}{:064x}{:064x}{:064x}{:064x}",
            64_u64, 128_u64, 1_u64, 17_u64, 1_u64, 2_u64
        );
        assert!(
            crate::position_history::erc1155_abi::decode_fields(&batch_topics, &valid_one_item,)
                .is_ok()
        );
        let bad_layout = valid_one_item.replacen(
            &format!("{:064x}", 128_u64),
            &format!("{:064x}", 160_u64),
            1,
        );
        assert!(
            crate::position_history::erc1155_abi::decode_fields(&batch_topics, &bad_layout,)
                .is_err()
        );
        let too_many = format!(
            "0x{:064x}{:064x}{:064x}",
            64_u64,
            96_u64 + 129 * 32,
            129_u64
        );
        assert!(
            crate::position_history::erc1155_abi::decode_fields(&batch_topics, &too_many,).is_err()
        );
    }

    #[derive(Clone)]
    struct MockRpcState {
        requests: Arc<Mutex<Vec<Value>>>,
        headers: BTreeMap<String, Value>,
    }

    async fn mock_rpc(State(state): State<MockRpcState>, body: Bytes) -> Json<Value> {
        let request: Value = serde_json::from_slice(&body).unwrap();
        let method = request["method"].as_str().unwrap();
        let params = &request["params"];
        state.requests.lock().unwrap().push(request.clone());
        let result = match method {
            "eth_chainId" => json!("0x89"),
            "eth_getBlockByNumber" => {
                let tag = params[0].as_str().unwrap();
                let number = if tag == "finalized" {
                    20
                } else {
                    u64::from_str_radix(tag.strip_prefix("0x").unwrap(), 16).unwrap()
                };
                state
                    .headers
                    .get(tag)
                    .cloned()
                    .unwrap_or_else(|| mock_header(number))
            }
            "eth_getLogs" => {
                let filter = &params[0];
                if filter["address"] == json!([PUSD_ADDRESS, USDCE_ADDRESS])
                    && filter["topics"][0] == ERC20_TRANSFER_TOPIC
                    && filter_contains_block(filter, 15)
                    && filter["topics"][1].as_array().is_some_and(|topics| {
                        topics
                            .iter()
                            .any(|entry| entry.as_str() == Some(&topic(WALLET)))
                    })
                {
                    json!([mock_cash_log()])
                } else if filter["address"] == json!(TEST_OWNER_FILL_EXCHANGES)
                    && filter["topics"][0]
                        == json!([TEST_V1_ORDER_FILLED_TOPIC, TEST_V2_ORDER_FILLED_TOPIC])
                    && filter_contains_block(filter, 15)
                {
                    json!([mock_owner_fill()])
                } else {
                    json!([])
                }
            }
            _ => panic!("unexpected method"),
        };
        Json(json!({"jsonrpc":"2.0", "id":request["id"], "result":result}))
    }

    fn filter_contains_block(filter: &Value, block: u64) -> bool {
        parse_quantity(&filter["fromBlock"]).is_some_and(|from| from <= block)
            && parse_quantity(&filter["toBlock"]).is_some_and(|through| block <= through)
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
            "timestamp":format!("0x{:x}", 1_800_000_000 + number),
        })
    }

    fn mock_cash_log() -> Value {
        json!({
            "removed":false, "blockNumber":"0xf", "blockHash":mock_header(15)["hash"],
            "transactionHash":format!("0x{}", "44".repeat(32)),
            "transactionIndex":"0x1", "logIndex":"0x2", "address":PUSD_ADDRESS,
            "topics":[ERC20_TRANSFER_TOPIC, topic(WALLET), topic("0x2222222222222222222222222222222222222222")],
            "data":format!("0x{}", format!("{:064x}", 123_u64)),
        })
    }

    fn mock_owner_fill() -> Value {
        let words = [0_u128, 123, 5_000_000, 7_000_000, 9]
            .into_iter()
            .map(|word| format!("{word:064x}"))
            .collect::<String>();
        json!({
            "removed":false,
            "blockNumber":"0xf",
            "blockHash":mock_header(15)["hash"],
            "transactionHash":format!("0x{}", "77".repeat(32)),
            "transactionIndex":"0x3",
            "logIndex":"0x5",
            "address":TEST_OWNER_FILL_EXCHANGES[0],
            "topics":[
                TEST_V1_ORDER_FILLED_TOPIC,
                format!("0x{}", "88".repeat(32)),
                topic(WALLET),
                topic("0x2222222222222222222222222222222222222222")
            ],
            "data":format!("0x{words}"),
        })
    }

    async fn mock_reader() -> (
        RpcPositionHistoryReader,
        Arc<Mutex<Vec<Value>>>,
        tokio::task::JoinHandle<()>,
    ) {
        mock_reader_with_headers(BTreeMap::new()).await
    }

    async fn mock_reader_with_headers(
        headers: BTreeMap<String, Value>,
    ) -> (
        RpcPositionHistoryReader,
        Arc<Mutex<Vec<Value>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/", post(mock_rpc))
            .with_state(MockRpcState {
                requests: requests.clone(),
                headers,
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
    async fn loopback_census_reuses_bounded_rpc_transport_and_timestamps_event_header() {
        let (reader, requests, server) = mock_reader().await;
        let request = RpcCurrentIntervalCensusRequest {
            wallets: vec![
                WALLET.to_owned(),
                "0x2222222222222222222222222222222222222222".to_owned(),
            ],
            start_block: 10,
            expected_start_hash: mock_header(10)["hash"].as_str().unwrap().to_owned(),
            through_block: 20,
            expected_through_hash: mock_header(20)["hash"].as_str().unwrap().to_owned(),
            max_requests: 5 + 4 + MAX_EVENT_BLOCKS,
            max_total_response_bytes: MAX_HISTORY_TOTAL_BYTES,
            total_timeout: Duration::from_secs(5),
        };
        let observation = reader.read_current_interval_census(&request).await.unwrap();
        assert_eq!(
            observation.source,
            RpcCurrentIntervalSource::ProviderReported
        );
        assert_eq!(observation.request_count, 10);
        assert_eq!(requests.lock().unwrap().len(), 10);
        assert_eq!(observation.start_header.timestamp, 1_800_000_010);
        assert_eq!(observation.end_header.timestamp, 1_800_000_020);
        assert_eq!(observation.event_headers[0].timestamp, 1_800_000_015);
        assert_eq!(observation.logs.len(), 1);
        assert_eq!(observation.wallets.len(), 2);
        assert!(
            observation
                .requests
                .iter()
                .all(|page| !page.request_json().contains("127.0.0.1"))
        );
        assert_eq!(
            observation
                .requests
                .iter()
                .filter(|page| page.method() == "eth_getLogs")
                .count(),
            4
        );
        let recorded_pages = observation
            .requests
            .iter()
            .map(|page| RecordedRpcPositionHistoryPage {
                request_json: page.request_json().to_owned(),
                response_json: page.response_json().to_owned(),
            })
            .collect::<Vec<_>>();
        let replayed = reverify_recorded_current_interval_census(&request, &recorded_pages)
            .await
            .unwrap();
        assert_eq!(replayed.wallets, observation.wallets);
        assert_eq!(replayed.start_header, observation.start_header);
        assert_eq!(replayed.end_header, observation.end_header);
        assert_eq!(replayed.event_headers, observation.event_headers);
        assert_eq!(replayed.logs, observation.logs);
        assert_eq!(replayed.request_count, observation.request_count);
        assert_eq!(replayed.response_bytes, observation.response_bytes);
        assert_eq!(replayed.requests.len(), observation.requests.len());
        for (replayed_page, captured_page) in replayed.requests.iter().zip(&observation.requests) {
            assert_eq!(replayed_page.method(), captured_page.method());
            assert_eq!(replayed_page.request_json(), captured_page.request_json());
            assert_eq!(replayed_page.response_json(), captured_page.response_json());
        }
        server.abort();
    }

    #[tokio::test]
    async fn selectable_chunk_width_covers_ranges_and_recorded_replay_requires_same_width() {
        let headers = BTreeMap::from([("finalized".to_owned(), mock_header(150))]);
        let (reader, requests, server) = mock_reader_with_headers(headers).await;
        let request = RpcCurrentIntervalCensusRequest {
            wallets: vec![WALLET.to_owned()],
            start_block: 10,
            expected_start_hash: mock_header(10)["hash"].as_str().unwrap().to_owned(),
            through_block: 150,
            expected_through_hash: mock_header(150)["hash"].as_str().unwrap().to_owned(),
            max_requests: 5 + 4 * 5 + MAX_EVENT_BLOCKS,
            max_total_response_bytes: MAX_HISTORY_TOTAL_BYTES,
            total_timeout: Duration::from_secs(5),
        };

        let chunked = reader
            .read_current_interval_census_chunked(&request, 32)
            .await
            .unwrap();
        let expected_ranges = [(11, 42), (43, 74), (75, 106), (107, 138), (139, 150)];
        {
            let calls = requests.lock().unwrap();
            let log_ranges: Vec<_> = calls
                .iter()
                .filter(|call| call["method"] == "eth_getLogs")
                .map(|call| {
                    let filter = &call["params"][0];
                    (
                        parse_quantity(&filter["fromBlock"]).unwrap(),
                        parse_quantity(&filter["toBlock"]).unwrap(),
                    )
                })
                .collect();
            let expected_log_ranges: Vec<_> = expected_ranges
                .iter()
                .flat_map(|range| [*range; 4])
                .collect();
            assert_eq!(log_ranges, expected_log_ranges);
        }
        assert_eq!(chunked.request_count, 26);
        assert_eq!(chunked.logs.len(), 1);

        let recorded_pages = chunked
            .requests
            .iter()
            .map(|page| RecordedRpcPositionHistoryPage {
                request_json: page.request_json().to_owned(),
                response_json: page.response_json().to_owned(),
            })
            .collect::<Vec<_>>();
        let replayed =
            reverify_recorded_current_interval_census_chunked(&request, &recorded_pages, 32)
                .await
                .unwrap();
        assert_eq!(replayed.logs, chunked.logs);
        assert_eq!(replayed.event_headers, chunked.event_headers);
        assert_eq!(replayed.request_count, chunked.request_count);
        assert_eq!(
            reverify_recorded_current_interval_census_chunked(&request, &recorded_pages, 16)
                .await
                .unwrap_err(),
            RpcPositionHistoryError::MalformedResponse
        );
        server.abort();
    }

    #[tokio::test]
    async fn chunk_width_validation_and_request_budget_fail_before_io() {
        let (reader, requests, server) = mock_reader().await;
        let mut request = RpcCurrentIntervalCensusRequest {
            wallets: vec![WALLET.to_owned()],
            start_block: 10,
            expected_start_hash: mock_header(10)["hash"].as_str().unwrap().to_owned(),
            through_block: 150,
            expected_through_hash: mock_header(150)["hash"].as_str().unwrap().to_owned(),
            max_requests: 24,
            max_total_response_bytes: MAX_HISTORY_TOTAL_BYTES,
            total_timeout: Duration::from_secs(5),
        };
        assert_eq!(
            reader
                .read_current_interval_census_chunked(&request, 32)
                .await
                .unwrap_err(),
            RpcPositionHistoryError::RequestBudgetExceeded
        );
        assert!(requests.lock().unwrap().is_empty());

        request.max_requests = 5 + 4 * 5 + MAX_EVENT_BLOCKS;
        for width in [0, LOG_CHUNK_BLOCKS + 1] {
            assert_eq!(
                reader
                    .read_current_interval_census_chunked(&request, width)
                    .await
                    .unwrap_err(),
                RpcPositionHistoryError::InvalidInput
            );
        }
        assert!(requests.lock().unwrap().is_empty());
        server.abort();
    }

    #[tokio::test]
    async fn default_entry_point_is_equivalent_to_explicit_128_block_width() {
        let (reader, _requests, server) = mock_reader().await;
        let request = RpcCurrentIntervalCensusRequest {
            wallets: vec![WALLET.to_owned()],
            start_block: 10,
            expected_start_hash: mock_header(10)["hash"].as_str().unwrap().to_owned(),
            through_block: 20,
            expected_through_hash: mock_header(20)["hash"].as_str().unwrap().to_owned(),
            max_requests: 5 + 4 + MAX_EVENT_BLOCKS,
            max_total_response_bytes: MAX_HISTORY_TOTAL_BYTES,
            total_timeout: Duration::from_secs(5),
        };
        let default = reader.read_current_interval_census(&request).await.unwrap();
        let explicit = reader
            .read_current_interval_census_chunked(&request, LOG_CHUNK_BLOCKS)
            .await
            .unwrap();
        assert_eq!(default.logs, explicit.logs);
        assert_eq!(default.event_headers, explicit.event_headers);
        assert_eq!(default.request_count, explicit.request_count);
        assert_eq!(default.response_bytes, explicit.response_bytes);
        assert_eq!(
            default
                .requests
                .iter()
                .map(|page| page.request_json())
                .collect::<Vec<_>>(),
            explicit
                .requests
                .iter()
                .map(|page| page.request_json())
                .collect::<Vec<_>>()
        );
        server.abort();
    }

    #[cfg(feature = "chain-audit")]
    #[tokio::test]
    async fn owner_fill_chunked_api_and_recorded_replay_share_the_width() {
        let headers = BTreeMap::from([("finalized".to_owned(), mock_header(150))]);
        let (reader, requests, server) = mock_reader_with_headers(headers).await;
        let request = RpcCurrentIntervalCensusRequest {
            wallets: vec![WALLET.to_owned()],
            start_block: 10,
            expected_start_hash: mock_header(10)["hash"].as_str().unwrap().to_owned(),
            through_block: 150,
            expected_through_hash: mock_header(150)["hash"].as_str().unwrap().to_owned(),
            max_requests: 5 + 5 * 5 + MAX_EVENT_BLOCKS,
            max_total_response_bytes: MAX_HISTORY_TOTAL_BYTES,
            total_timeout: Duration::from_secs(5),
        };
        let captured = reader
            .read_current_interval_owner_fills_chunked(&request, 32)
            .await
            .unwrap();
        assert_eq!(captured.owner_fills.len(), 1);
        assert_eq!(captured.census.request_count, 31);
        let ranges: Vec<_> = {
            let calls = requests.lock().unwrap();
            calls
                .iter()
                .filter(|call| call["method"] == "eth_getLogs")
                .map(|call| {
                    let filter = &call["params"][0];
                    (
                        parse_quantity(&filter["fromBlock"]).unwrap(),
                        parse_quantity(&filter["toBlock"]).unwrap(),
                    )
                })
                .collect()
        };
        let expected_ranges = [(11, 42), (43, 74), (75, 106), (107, 138), (139, 150)];
        assert_eq!(
            ranges,
            expected_ranges
                .iter()
                .flat_map(|range| [*range; 5])
                .collect::<Vec<_>>()
        );
        let recorded_pages = captured
            .census
            .requests
            .iter()
            .map(|page| RecordedRpcPositionHistoryPage {
                request_json: page.request_json().to_owned(),
                response_json: page.response_json().to_owned(),
            })
            .collect::<Vec<_>>();
        let replayed =
            reverify_recorded_current_interval_owner_fills_chunked(&request, &recorded_pages, 32)
                .await
                .unwrap();
        assert_eq!(replayed.owner_fills, captured.owner_fills);
        assert_eq!(replayed.census.logs, captured.census.logs);
        assert_eq!(
            reverify_recorded_current_interval_owner_fills(&request, &recorded_pages)
                .await
                .unwrap_err(),
            RpcPositionHistoryError::MalformedResponse
        );
        server.abort();
    }

    #[cfg(feature = "chain-audit")]
    #[tokio::test]
    async fn opt_in_owner_fill_census_shares_caps_frames_and_event_headers() {
        let (reader, requests, server) = mock_reader().await;
        let mut wallets = vec![WALLET.to_owned()];
        wallets.extend((2_u128..=MAX_WALLETS as u128).map(|index| format!("0x{index:040x}")));
        let request = RpcCurrentIntervalCensusRequest {
            wallets,
            start_block: 10,
            expected_start_hash: mock_header(10)["hash"].as_str().unwrap().to_owned(),
            through_block: 20,
            expected_through_hash: mock_header(20)["hash"].as_str().unwrap().to_owned(),
            max_requests: 5 + 5 + MAX_EVENT_BLOCKS,
            max_total_response_bytes: MAX_HISTORY_TOTAL_BYTES,
            total_timeout: Duration::from_secs(5),
        };
        let observation = reader
            .read_current_interval_owner_fills(&request)
            .await
            .unwrap();
        assert_eq!(observation.census.logs.len(), 1);
        assert_eq!(observation.owner_fills.len(), 1);
        let fill = &observation.owner_fills[0];
        assert_eq!(fill.fill.block_number, 15);
        assert_eq!(fill.fill.log_index, 5);
        assert_eq!(fill.fill.wallet, WALLET);
        assert_eq!(fill.transaction_index, 3);
        assert_eq!(fill.block_timestamp, 1_800_000_015);
        assert_eq!(observation.census.event_headers.len(), 1);
        assert_eq!(observation.census.wallets.len(), MAX_WALLETS);
        assert_eq!(observation.census.request_count, 11);
        assert_eq!(observation.census.requests.len(), 11);
        {
            let calls = requests.lock().unwrap();
            assert_eq!(calls.len(), 11);
            let log_filters: Vec<_> = calls
                .iter()
                .filter(|call| call["method"] == "eth_getLogs")
                .collect();
            assert_eq!(log_filters.len(), 5);
            assert_eq!(
                log_filters[4]["params"][0]["topics"][2]
                    .as_array()
                    .unwrap()
                    .len(),
                MAX_WALLETS
            );
        }

        let recorded_pages = observation
            .census
            .requests
            .iter()
            .map(|page| RecordedRpcPositionHistoryPage {
                request_json: page.request_json().to_owned(),
                response_json: page.response_json().to_owned(),
            })
            .collect::<Vec<_>>();
        let grouped_fill_page = recorded_pages
            .iter()
            .find(|page| {
                let request: Value = serde_json::from_str(&page.request_json).unwrap();
                request["method"] == "eth_getLogs"
                    && request["params"][0]["address"] == json!(TEST_OWNER_FILL_EXCHANGES)
            })
            .unwrap();
        assert!(grouped_fill_page.request_json.len() > 4 * 1024);
        assert!(grouped_fill_page.request_json.len() <= 16 * 1024);

        let replayed = reverify_recorded_current_interval_owner_fills(&request, &recorded_pages)
            .await
            .unwrap();
        assert_eq!(replayed.census.wallets, observation.census.wallets);
        assert_eq!(
            replayed.census.start_header,
            observation.census.start_header
        );
        assert_eq!(replayed.census.end_header, observation.census.end_header);
        assert_eq!(
            replayed.census.event_headers,
            observation.census.event_headers
        );
        assert_eq!(replayed.census.logs, observation.census.logs);
        assert_eq!(replayed.owner_fills, observation.owner_fills);
        assert_eq!(
            replayed.census.request_count,
            observation.census.request_count
        );
        assert_eq!(
            replayed.census.response_bytes,
            observation.census.response_bytes
        );
        assert_eq!(
            replayed.census.requests.len(),
            observation.census.requests.len()
        );
        for (replayed_page, captured_page) in replayed
            .census
            .requests
            .iter()
            .zip(&observation.census.requests)
        {
            assert_eq!(replayed_page.method(), captured_page.method());
            assert_eq!(replayed_page.request_json(), captured_page.request_json());
            assert_eq!(replayed_page.response_json(), captured_page.response_json());
        }

        assert_eq!(
            reverify_recorded_current_interval_owner_fills(
                &request,
                &recorded_pages[..recorded_pages.len() - 1]
            )
            .await
            .unwrap_err(),
            RpcPositionHistoryError::MalformedResponse
        );
        let mut reordered = recorded_pages.clone();
        reordered.swap(0, 1);
        assert_eq!(
            reverify_recorded_current_interval_owner_fills(&request, &reordered)
                .await
                .unwrap_err(),
            RpcPositionHistoryError::MalformedResponse
        );
        let mut extra = recorded_pages.clone();
        extra.push(recorded_pages[0].clone());
        assert_eq!(
            reverify_recorded_current_interval_owner_fills(&request, &extra)
                .await
                .unwrap_err(),
            RpcPositionHistoryError::MalformedResponse
        );
        let mut changed_filter = recorded_pages.clone();
        let grouped_fill_index = changed_filter
            .iter()
            .position(|page| {
                let rpc_request: Value = serde_json::from_str(&page.request_json).unwrap();
                rpc_request["method"] == "eth_getLogs"
                    && rpc_request["params"][0]["address"] == json!(TEST_OWNER_FILL_EXCHANGES)
            })
            .unwrap();
        let mut altered_request: Value =
            serde_json::from_str(&changed_filter[grouped_fill_index].request_json).unwrap();
        altered_request["params"][0]["fromBlock"] = json!("0x10");
        changed_filter[grouped_fill_index].request_json = altered_request.to_string();
        assert_eq!(
            reverify_recorded_current_interval_owner_fills(&request, &changed_filter)
                .await
                .unwrap_err(),
            RpcPositionHistoryError::MalformedResponse
        );
        server.abort();
    }

    #[cfg(feature = "chain-audit")]
    #[tokio::test]
    async fn owner_fill_event_header_request_counts_against_shared_request_budget() {
        let (reader, requests, server) = mock_reader().await;
        let request = RpcCurrentIntervalCensusRequest {
            wallets: vec![WALLET.to_owned()],
            start_block: 10,
            expected_start_hash: mock_header(10)["hash"].as_str().unwrap().to_owned(),
            through_block: 20,
            expected_through_hash: mock_header(20)["hash"].as_str().unwrap().to_owned(),
            max_requests: 10,
            max_total_response_bytes: MAX_HISTORY_TOTAL_BYTES,
            total_timeout: Duration::from_secs(5),
        };
        assert_eq!(
            reader.read_current_interval_owner_fills(&request).await,
            Err(RpcPositionHistoryError::RequestBudgetExceeded)
        );
        let calls = requests.lock().unwrap();
        assert_eq!(calls.len(), 10);
        assert_eq!(
            calls
                .iter()
                .filter(|call| call["method"] == "eth_getLogs")
                .count(),
            5
        );
        server.abort();
    }

    #[cfg(feature = "chain-audit")]
    #[tokio::test]
    async fn owner_fill_response_uses_existing_shared_byte_budget() {
        let (reader, _, server) = mock_reader().await;
        let request = RpcCurrentIntervalCensusRequest {
            wallets: vec![
                WALLET.to_owned(),
                "0x2222222222222222222222222222222222222222".to_owned(),
            ],
            start_block: 10,
            expected_start_hash: mock_header(10)["hash"].as_str().unwrap().to_owned(),
            through_block: 20,
            expected_through_hash: mock_header(20)["hash"].as_str().unwrap().to_owned(),
            max_requests: 5 + 5 + MAX_EVENT_BLOCKS,
            max_total_response_bytes: MAX_HISTORY_TOTAL_BYTES,
            total_timeout: Duration::from_secs(5),
        };
        let baseline = reader.read_current_interval_census(&request).await.unwrap();
        let bounded = RpcCurrentIntervalCensusRequest {
            max_total_response_bytes: baseline.response_bytes,
            ..request
        };
        assert_eq!(
            reader.read_current_interval_owner_fills(&bounded).await,
            Err(RpcPositionHistoryError::BodyBudgetExceeded)
        );
        server.abort();
    }

    #[cfg(feature = "chain-audit")]
    #[test]
    fn owner_fill_rows_bind_wallet_range_and_conflict_at_the_shared_locator() {
        let wallets = vec![WALLET.to_owned()];
        let raw = mock_owner_fill();
        let fill = decode_owner_fill(&raw, &wallets, 11, 20).unwrap();
        assert_eq!(fill.fill.wallet, WALLET);
        assert_eq!(fill.transaction_index, 3);
        assert!(decode_owner_fill(&raw, &wallets, 16, 20).is_err());

        let mut wrong_wallet = raw.clone();
        wrong_wallet["topics"][2] = json!(topic("0x2222222222222222222222222222222222222222"));
        assert!(decode_owner_fill(&wrong_wallet, &wallets, 11, 20).is_err());

        let mut fills = BTreeMap::new();
        insert_unique_owner_fill(&mut fills, fill.clone()).unwrap();
        insert_unique_owner_fill(&mut fills, fill.clone()).unwrap();
        assert_eq!(fills.len(), 1);
        let mut changed = fill;
        changed.transaction_index += 1;
        assert_eq!(
            insert_unique_owner_fill(&mut fills, changed),
            Err(RpcPositionHistoryError::ConflictingLocator)
        );
    }

    #[tokio::test]
    async fn loopback_wrong_previous_anchor_stops_before_any_log_query() {
        let (reader, requests, server) = mock_reader().await;
        let request = RpcCurrentIntervalCensusRequest {
            wallets: vec![WALLET.to_owned()],
            start_block: 10,
            expected_start_hash: format!("0x{}", "ff".repeat(32)),
            through_block: 20,
            expected_through_hash: mock_header(20)["hash"].as_str().unwrap().to_owned(),
            max_requests: 5 + 4 + MAX_EVENT_BLOCKS,
            max_total_response_bytes: MAX_HISTORY_TOTAL_BYTES,
            total_timeout: Duration::from_secs(5),
        };
        assert_eq!(
            reader.read_current_interval_census(&request).await,
            Err(RpcPositionHistoryError::AnchorMismatch)
        );
        assert_eq!(requests.lock().unwrap().len(), 3);
        server.abort();
    }

    #[tokio::test]
    async fn conflicting_finalized_hash_and_reversed_interval_time_stop_before_log_queries() {
        let mut wrong_finalized = mock_header(20);
        wrong_finalized["hash"] = json!(format!("0x{}", "ff".repeat(32)));
        let mut reversed_end = mock_header(20);
        reversed_end["timestamp"] = mock_header(9)["timestamp"].clone();
        for (tag, header, expected_calls) in
            [("finalized", wrong_finalized, 2), ("0x14", reversed_end, 4)]
        {
            let (reader, requests, server) =
                mock_reader_with_headers(BTreeMap::from([(tag.to_owned(), header)])).await;
            let request = RpcCurrentIntervalCensusRequest {
                wallets: vec![WALLET.to_owned()],
                start_block: 10,
                expected_start_hash: mock_header(10)["hash"].as_str().unwrap().to_owned(),
                through_block: 20,
                expected_through_hash: mock_header(20)["hash"].as_str().unwrap().to_owned(),
                max_requests: 5 + 4 + MAX_EVENT_BLOCKS,
                max_total_response_bytes: MAX_HISTORY_TOTAL_BYTES,
                total_timeout: Duration::from_secs(5),
            };
            assert_eq!(
                reader.read_current_interval_census(&request).await,
                Err(RpcPositionHistoryError::ConflictingHeader)
            );
            let calls = requests.lock().unwrap();
            assert_eq!(calls.len(), expected_calls);
            assert!(
                calls
                    .iter()
                    .all(|request| request["method"] != "eth_getLogs")
            );
            server.abort();
        }
    }

    #[tokio::test]
    async fn oversized_total_timeout_is_rejected_before_rpc() {
        let (reader, requests, server) = mock_reader().await;
        let request = RpcCurrentIntervalCensusRequest {
            wallets: vec![WALLET.to_owned()],
            start_block: 10,
            expected_start_hash: mock_header(10)["hash"].as_str().unwrap().to_owned(),
            through_block: 20,
            expected_through_hash: mock_header(20)["hash"].as_str().unwrap().to_owned(),
            max_requests: 5 + 4 + MAX_EVENT_BLOCKS,
            max_total_response_bytes: MAX_HISTORY_TOTAL_BYTES,
            total_timeout: Duration::from_secs(121),
        };
        assert_eq!(
            reader.read_current_interval_census(&request).await,
            Err(RpcPositionHistoryError::InvalidInput)
        );
        let duplicate_wallets = RpcCurrentIntervalCensusRequest {
            wallets: vec![WALLET.to_owned(), WALLET.to_owned()],
            total_timeout: Duration::from_secs(5),
            ..request
        };
        assert_eq!(
            reader
                .read_current_interval_census(&duplicate_wallets)
                .await,
            Err(RpcPositionHistoryError::InvalidInput)
        );
        assert!(requests.lock().unwrap().is_empty());
        server.abort();
    }
}
