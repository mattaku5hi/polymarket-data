//! Conservative provider-reported flow classification for one wallet and one
//! bounded current interval. This is not proof of complete wallet history.

use std::{
    collections::{HashMap, HashSet},
    io::{self, Write},
};

use crate::{
    TradeSide,
    activity_hints::{
        ActivityHintAcquisition, ActivityHintOccurrence, ActivityHintPass, ActivityHintPassStatus,
        ActivityHintPassSummary,
    },
    chain_log_audit::{
        FifthEventImplementationVersion, FifthEventObservationSource, ProviderReportedFifthAsset,
        ProviderReportedFifthDirection, ProviderReportedFifthSettlement,
    },
    collateral_cash::CollateralAsset,
    position_history::erc1155_abi::{DecodedTransfer, decode_fields},
    rpc_position_history::current_interval_census::{
        RpcCurrentIntervalAsset, RpcCurrentIntervalCensus, RpcCurrentIntervalLog,
        RpcCurrentIntervalOwnerFill, RpcCurrentIntervalOwnerFillCensus,
    },
};

#[cfg(test)]
const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
const MAX_FLOW_ACTIVITY_OCCURRENCES: usize = 20_000;
const MAX_FLOW_ACTIVITY_ROW_BYTES: usize = 64 * 1024;
const MAX_FLOW_ACTIVITY_BYTES: usize = 8 * 1024 * 1024;
const MAX_FLOW_POSITION_ITEMS: usize = 20_000;
const MAX_FLOW_UNRESOLVED: usize = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceFlowCoverage {
    KnownForDeclaredScope,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceFlowSource {
    ProviderReported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceFlowReason {
    ActivityPassIncomplete,
    UnsupportedActivityPolicy,
    ActivityRangeDoesNotContainCensus,
    InvalidActivityAmount,
    InvalidActivityOccurrence,
    UnsupportedActivityType,
    MissingOrAmbiguousActivityMatch,
    UnsupportedFeeBearingTrade,
    UnsupportedTradeAttribution,
    UnsupportedConversionBoundary,
    UnmatchedCashMovement,
    UnmatchedPositionMovement,
    InvalidPositionMovement,
    InputLimitExceeded,
    InvalidCensusEntry,
    UnsupportedTradeVenueOrAssets,
    UnsupportedFifthSettlement,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SourceWalletCapitalFlow {
    /// Stable raw event locator: chain:transaction:log-index.
    pub locator: String,
    pub timestamp: u64,
    pub asset: CollateralAsset,
    /// Exact six-decimal token units, signed from the source wallet's view.
    pub signed_amount_microunits: i128,
}

#[derive(Clone, PartialEq, Eq)]
pub struct UnresolvedSourceMovement {
    pub movement_locator: Option<String>,
    pub activity_occurrence: Option<String>,
    pub reason: SourceFlowReason,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SourceWalletFlowReduction {
    pub wallet: String,
    pub source: SourceFlowSource,
    pub start_block: u64,
    pub through_block: u64,
    pub coverage: SourceFlowCoverage,
    pub capital_flows: Vec<SourceWalletCapitalFlow>,
    pub unresolved: Vec<UnresolvedSourceMovement>,
}

/// Borrowed offline-replay view of a bounded Activity capture. Complete means
/// the two API passes completed, not complete wallet history.
#[derive(Clone, Copy)]
pub struct SourceWalletActivityWindow<'a> {
    pub wallet: &'a str,
    pub policy_version: &'a str,
    pub start: i64,
    pub end: i64,
    pub default_pass: ActivityHintPassSummary,
    pub tip_pass: ActivityHintPassSummary,
    pub occurrences: &'a [ActivityHintOccurrence],
}

impl<'a> From<&'a ActivityHintAcquisition> for SourceWalletActivityWindow<'a> {
    fn from(activity: &'a ActivityHintAcquisition) -> Self {
        Self {
            wallet: activity.wallet(),
            policy_version: activity.policy_version(),
            start: activity.start(),
            end: activity.end(),
            default_pass: activity.default_pass(),
            tip_pass: activity.tip_pass(),
            occurrences: activity.occurrences(),
        }
    }
}

#[derive(Clone)]
struct CashMovement<'a> {
    log: &'a RpcCurrentIntervalLog,
    amount: u128,
    asset: CollateralAsset,
    incoming: bool,
}

#[derive(Clone)]
struct PositionMovement<'a> {
    log: &'a RpcCurrentIntervalLog,
    token_id: String,
    amount: u128,
    incoming: bool,
}

type ActivityCashKey = (String, bool, u128, u64);
type TradeCashKey = (String, u64, String, u64, bool, u128, u8);
type TradePositionKey = (String, u64, String, u64, bool, u128, String, u8);
type TradeFillKey = (String, String, u128, String, u8, u64);

#[derive(Clone, Copy, PartialEq, Eq)]
enum ActivityKind {
    Deposit,
    Withdrawal,
    TipIn,
    TipOut,
    Return,
    Trade,
    Unsupported,
}

/// Classify only movements that have a unique, exact Activity/fill match.
/// Any unresolved movement makes this interval's flow coverage Unknown.
pub fn reduce_source_wallet_flows(
    activity: SourceWalletActivityWindow<'_>,
    census: &RpcCurrentIntervalOwnerFillCensus,
) -> SourceWalletFlowReduction {
    reduce_source_wallet_flows_with_fifth_settlements(activity, census, &[])
}

/// Add exact provider-reported fifth settlement legs to the bounded flow view.
/// Each DTO remains unbound and caller-scoped; its legs must still match this
/// wallet's census entries and current block headers exactly.
pub fn reduce_source_wallet_flows_with_fifth_settlements(
    activity: SourceWalletActivityWindow<'_>,
    census: &RpcCurrentIntervalOwnerFillCensus,
    settlements: &[ProviderReportedFifthSettlement],
) -> SourceWalletFlowReduction {
    reduce_source_wallet_flow_parts_with_fifth(activity, census, settlements)
}

fn reduce_source_wallet_flow_parts_with_fifth(
    activity: SourceWalletActivityWindow<'_>,
    owner_census: &RpcCurrentIntervalOwnerFillCensus,
    fifth_settlements: &[ProviderReportedFifthSettlement],
) -> SourceWalletFlowReduction {
    let SourceWalletActivityWindow {
        wallet: raw_wallet,
        policy_version,
        start: activity_start,
        end: activity_end,
        default_pass,
        tip_pass,
        occurrences,
    } = activity;
    let census = &owner_census.census;
    let wallet = crate::position_history::normalize_address(raw_wallet)
        .unwrap_or_else(|| raw_wallet.to_ascii_lowercase());
    let mut result = SourceWalletFlowReduction {
        wallet: wallet.clone(),
        source: SourceFlowSource::ProviderReported,
        start_block: census.start_block,
        through_block: census.through_block,
        coverage: SourceFlowCoverage::KnownForDeclaredScope,
        capital_flows: Vec::new(),
        unresolved: Vec::new(),
    };
    let settlement_items = fifth_settlements
        .iter()
        .try_fold(0_usize, |total, settlement| {
            total
                .checked_add(settlement.wallet_legs().len())?
                .checked_add(settlement.owner_fills().len())
        });
    if fifth_settlements.len() > 32
        || settlement_items.is_none_or(|items| items > MAX_FLOW_POSITION_ITEMS)
    {
        result.coverage = SourceFlowCoverage::Unknown;
        result.unresolved.push(UnresolvedSourceMovement {
            movement_locator: None,
            activity_occurrence: None,
            reason: SourceFlowReason::InputLimitExceeded,
        });
        return result;
    }
    macro_rules! unknown {
        ($movement_locator:expr, $activity_occurrence:expr, $reason:expr) => {{
            if result.unresolved.len() < MAX_FLOW_UNRESOLVED - 1 {
                result.unresolved.push(UnresolvedSourceMovement {
                    movement_locator: $movement_locator,
                    activity_occurrence: $activity_occurrence,
                    reason: $reason,
                });
            } else if result.unresolved.len() == MAX_FLOW_UNRESOLVED - 1 {
                result.unresolved.push(UnresolvedSourceMovement {
                    movement_locator: None,
                    activity_occurrence: None,
                    reason: SourceFlowReason::InputLimitExceeded,
                });
            }
            result.coverage = SourceFlowCoverage::Unknown;
        }};
    }

    let Some(start_ts) = i64::try_from(census.start_header.timestamp).ok() else {
        unknown!(
            None,
            None,
            SourceFlowReason::ActivityRangeDoesNotContainCensus
        );
        return result;
    };
    let Some(end_ts) = i64::try_from(census.end_header.timestamp).ok() else {
        unknown!(
            None,
            None,
            SourceFlowReason::ActivityRangeDoesNotContainCensus
        );
        return result;
    };
    if !census.wallets.iter().any(|candidate| {
        crate::position_history::normalize_address(candidate).as_deref() == Some(&wallet)
    }) || activity_start > start_ts.saturating_add(1)
        || activity_end < end_ts
        || activity_start > activity_end
    {
        unknown!(
            None,
            None,
            SourceFlowReason::ActivityRangeDoesNotContainCensus
        );
    }
    let mut occurrence_keys = HashSet::new();
    let activity_bytes = occurrences.iter().try_fold(0_usize, |sum, row| {
        sum.checked_add(json_size_bounded(&row.raw, MAX_FLOW_ACTIVITY_ROW_BYTES)?)
    });
    if census.logs.len() > super::MAX_UNIQUE_LOGS
        || census.event_headers.len() > super::MAX_EVENT_BLOCKS
        || census.request_count > super::MAX_HISTORY_REQUESTS
        || census.response_bytes > super::MAX_HISTORY_TOTAL_BYTES
        || owner_census.owner_fills.len() > super::MAX_UNIQUE_LOGS
        || occurrences.len() > MAX_FLOW_ACTIVITY_OCCURRENCES
        || activity_bytes.is_none_or(|bytes| bytes > MAX_FLOW_ACTIVITY_BYTES)
    {
        unknown!(None, None, SourceFlowReason::InputLimitExceeded);
        return result;
    }
    if census.wallets.is_empty()
        || census.wallets.len() > super::MAX_WALLETS
        || census
            .wallets
            .iter()
            .any(|candidate| crate::position_history::normalize_address(candidate).is_none())
        || census.wallets.iter().enumerate().any(|(index, candidate)| {
            census.wallets[..index].iter().any(|previous| {
                crate::position_history::normalize_address(previous)
                    == crate::position_history::normalize_address(candidate)
            })
        })
    {
        unknown!(None, None, SourceFlowReason::InvalidCensusEntry);
        return result;
    }
    if census.start_header.number != census.start_block
        || census.end_header.number != census.through_block
        || census.start_block >= census.through_block
        || crate::position_history::normalize_hash(&census.start_header.hash).is_none()
        || crate::position_history::normalize_hash(&census.end_header.hash).is_none()
    {
        unknown!(None, None, SourceFlowReason::InvalidCensusEntry);
    }
    let mut transaction_bindings = HashMap::new();
    let mut block_log_bindings = HashMap::new();
    for log in &census.logs {
        let Some(tx) = crate::position_history::normalize_hash(&log.transaction_hash) else {
            unknown!(
                Some(log.locator.clone()),
                None,
                SourceFlowReason::InvalidCensusEntry
            );
            continue;
        };
        let binding = (
            log.block_number,
            log.block_hash.clone(),
            log.transaction_index,
        );
        if transaction_bindings
            .insert(tx.clone(), binding.clone())
            .is_some_and(|previous| previous != binding)
        {
            unknown!(
                Some(log.locator.clone()),
                None,
                SourceFlowReason::InvalidCensusEntry
            );
        }
        let log_binding = (tx, log.transaction_index);
        if block_log_bindings
            .insert((log.block_number, log.log_index), log_binding.clone())
            .is_some_and(|previous| previous != log_binding)
        {
            unknown!(
                Some(log.locator.clone()),
                None,
                SourceFlowReason::InvalidCensusEntry
            );
        }
    }
    if policy_version != crate::activity_hints::ACTIVITY_HINT_POLICY_VERSION {
        unknown!(None, None, SourceFlowReason::UnsupportedActivityPolicy);
    }
    if default_pass.status != ActivityHintPassStatus::Complete
        || tip_pass.status != ActivityHintPassStatus::Complete
        || default_pass.pages_requested == 0
        || tip_pass.pages_requested == 0
        || occurrences
            .iter()
            .filter(|row| row.pass == ActivityHintPass::DefaultTypes)
            .count()
            != default_pass.rows_retained
        || occurrences
            .iter()
            .filter(|row| row.pass == ActivityHintPass::Tip)
            .count()
            != tip_pass.rows_retained
    {
        unknown!(None, None, SourceFlowReason::ActivityPassIncomplete);
    }
    if occurrences.iter().any(|row| {
        !activity_occurrence_consistent(row, &wallet, activity_start, activity_end)
            || row.page == 0
            || row.page
                > match row.pass {
                    ActivityHintPass::DefaultTypes => default_pass.pages_requested,
                    ActivityHintPass::Tip => tip_pass.pages_requested,
                }
            || row.ordinal >= 1_000
    }) || occurrences.iter().any(|row| {
        let pass_key = match row.pass {
            ActivityHintPass::DefaultTypes => 0_u8,
            ActivityHintPass::Tip => 1_u8,
        };
        !occurrence_keys.insert((pass_key, row.page, row.ordinal))
    }) {
        unknown!(None, None, SourceFlowReason::InvalidActivityOccurrence);
    }

    let mut cash = Vec::new();
    let mut positions = Vec::new();
    let mut seen_locators = HashSet::new();
    let mut seen_event_blocks = HashSet::new();
    for header in &census.event_headers {
        if header.number <= census.start_block
            || header.number > census.through_block
            || crate::position_history::normalize_hash(&header.hash).is_none()
            || (header.number == census.end_header.number
                && (header.hash != census.end_header.hash
                    || header.timestamp != census.end_header.timestamp))
            || !seen_event_blocks.insert(header.number)
        {
            unknown!(None, None, SourceFlowReason::InvalidCensusEntry);
        }
    }
    for log in &census.logs {
        if !seen_locators.insert(log.locator.as_str()) {
            unknown!(
                Some(log.locator.clone()),
                None,
                SourceFlowReason::UnmatchedCashMovement
            );
            continue;
        }
        let normalized_tx = crate::position_history::normalize_hash(&log.transaction_hash);
        let expected_locator = normalized_tx
            .as_ref()
            .map(|tx| format!("137:{tx}:{}", log.log_index));
        let event_header = census
            .event_headers
            .iter()
            .find(|header| header.number == log.block_number);
        if log.block_number <= census.start_block
            || log.block_number > census.through_block
            || normalized_tx.is_none()
            || crate::position_history::normalize_hash(&log.block_hash).is_none()
            || expected_locator.as_deref() != Some(log.locator.as_str())
            || event_header.is_none_or(|header| {
                header.hash != log.block_hash
                    || header.timestamp <= census.start_header.timestamp
                    || header.timestamp > census.end_header.timestamp
            })
        {
            unknown!(
                Some(log.locator.clone()),
                None,
                SourceFlowReason::InvalidCensusEntry
            );
            continue;
        }
        let from = crate::position_history::normalize_address(&log.from);
        let to = crate::position_history::normalize_address(&log.to);
        let incoming = to.as_deref() == Some(&wallet);
        let outgoing = from.as_deref() == Some(&wallet);
        if !incoming && !outgoing {
            continue;
        }
        if incoming && outgoing {
            continue; // A true self-transfer has zero net wallet effect.
        }
        let timestamp = census
            .event_headers
            .iter()
            .find(|header| header.number == log.block_number)
            .map(|header| header.timestamp);
        if timestamp.is_none_or(|ts| {
            ts <= census.start_header.timestamp || ts > census.end_header.timestamp
        }) {
            unknown!(
                Some(log.locator.clone()),
                None,
                SourceFlowReason::ActivityRangeDoesNotContainCensus
            );
            continue;
        }
        match log.asset {
            RpcCurrentIntervalAsset::Pusd | RpcCurrentIntervalAsset::UsdcE => {
                if log.position_log.is_some() {
                    unknown!(
                        Some(log.locator.clone()),
                        None,
                        SourceFlowReason::InvalidCensusEntry
                    );
                    continue;
                }
                let Some(amount) = log.amount_word.as_deref().and_then(parse_uint256_u128) else {
                    unknown!(
                        Some(log.locator.clone()),
                        None,
                        SourceFlowReason::UnmatchedCashMovement
                    );
                    continue;
                };
                if amount == 0 {
                    continue;
                }
                cash.push(CashMovement {
                    log,
                    amount,
                    asset: if log.asset == RpcCurrentIntervalAsset::Pusd {
                        CollateralAsset::Pusd
                    } else {
                        CollateralAsset::UsdcE
                    },
                    incoming,
                });
            }
            RpcCurrentIntervalAsset::Ctf | RpcCurrentIntervalAsset::PositionManager => {
                if log.amount_word.is_some() {
                    unknown!(
                        Some(log.locator.clone()),
                        None,
                        SourceFlowReason::InvalidCensusEntry
                    );
                    continue;
                }
                let Some(raw) = log.position_log.as_ref() else {
                    unknown!(
                        Some(log.locator.clone()),
                        None,
                        SourceFlowReason::InvalidPositionMovement
                    );
                    continue;
                };
                if raw.topics().len() != 4
                    || raw.topics().iter().any(|topic| topic.len() > 66)
                    || raw.data().len() > 16 * 1024
                    || !position_log_binding_valid(raw, log)
                {
                    unknown!(
                        Some(log.locator.clone()),
                        None,
                        SourceFlowReason::InputLimitExceeded
                    );
                    continue;
                }
                match decode_fields(raw.topics(), raw.data()) {
                    Ok(DecodedTransfer::Single {
                        from,
                        to,
                        id,
                        amount,
                        ..
                    }) => {
                        if decoded_endpoints_match(&from, &to, log)
                            && position_asset_matches(log.asset, raw.ledger())
                            && let Some((token_id, amount)) = words_to_position(&id, &amount)
                        {
                            if amount > 0 {
                                positions.push(PositionMovement {
                                    log,
                                    token_id,
                                    amount,
                                    incoming,
                                });
                            }
                        } else {
                            unknown!(
                                Some(log.locator.clone()),
                                None,
                                SourceFlowReason::InvalidPositionMovement
                            );
                        }
                    }
                    Ok(DecodedTransfer::Batch {
                        from,
                        to,
                        ids,
                        amounts,
                        ..
                    }) if ids.len() == amounts.len() => {
                        if !decoded_endpoints_match(&from, &to, log)
                            || !position_asset_matches(log.asset, raw.ledger())
                            || positions.len().saturating_add(ids.len()) > MAX_FLOW_POSITION_ITEMS
                        {
                            unknown!(
                                Some(log.locator.clone()),
                                None,
                                SourceFlowReason::InvalidPositionMovement
                            );
                            continue;
                        }
                        for (id, amount) in ids.iter().zip(&amounts) {
                            if let Some((token_id, amount)) = words_to_position(id, amount) {
                                if amount > 0 {
                                    positions.push(PositionMovement {
                                        log,
                                        token_id,
                                        amount,
                                        incoming,
                                    });
                                }
                            } else {
                                unknown!(
                                    Some(log.locator.clone()),
                                    None,
                                    SourceFlowReason::InvalidPositionMovement
                                );
                            }
                        }
                    }
                    _ => unknown!(
                        Some(log.locator.clone()),
                        None,
                        SourceFlowReason::InvalidPositionMovement
                    ),
                }
            }
        }
    }

    let mut consumed_cash = vec![false; cash.len()];
    let mut consumed_positions = vec![false; positions.len()];
    let mut consumed_activity = vec![false; occurrences.len()];
    let mut conversion_candidate = vec![false; cash.len()];
    let mut conversion_candidates: HashMap<(String, u8, bool, u128), Vec<usize>> = HashMap::new();
    for (index, movement) in cash.iter().enumerate() {
        let asset = collateral_key(movement.asset);
        conversion_candidates
            .entry((
                movement.log.transaction_hash.to_ascii_lowercase(),
                asset,
                movement.incoming,
                movement.amount,
            ))
            .or_default()
            .push(index);
    }
    let mut conversion_activity_keys = HashSet::new();
    for (index, movement) in cash.iter().enumerate() {
        let other_asset = match movement.asset {
            CollateralAsset::Pusd => 1,
            CollateralAsset::UsdcE => 0,
        };
        if conversion_candidates.contains_key(&(
            movement.log.transaction_hash.to_ascii_lowercase(),
            other_asset,
            !movement.incoming,
            movement.amount,
        )) {
            conversion_candidate[index] = true;
            conversion_activity_keys.insert((
                movement.log.transaction_hash.to_ascii_lowercase(),
                movement.amount,
                movement.incoming,
            ));
        }
    }

    let mut activity_cash_index: HashMap<ActivityCashKey, Vec<usize>> = HashMap::new();
    let mut trade_cash_index: HashMap<TradeCashKey, Vec<usize>> = HashMap::new();
    for (index, movement) in cash.iter().enumerate() {
        let Some(timestamp) = census
            .event_headers
            .iter()
            .find(|header| header.number == movement.log.block_number)
            .map(|header| header.timestamp)
        else {
            continue;
        };
        let tx = movement.log.transaction_hash.to_ascii_lowercase();
        activity_cash_index
            .entry((tx.clone(), movement.incoming, movement.amount, timestamp))
            .or_default()
            .push(index);
        trade_cash_index
            .entry((
                tx,
                movement.log.block_number,
                movement.log.block_hash.clone(),
                movement.log.transaction_index,
                movement.incoming,
                movement.amount,
                collateral_key(movement.asset),
            ))
            .or_default()
            .push(index);
    }
    let mut trade_position_index: HashMap<TradePositionKey, Vec<usize>> = HashMap::new();
    for (index, movement) in positions.iter().enumerate() {
        trade_position_index
            .entry((
                movement.log.transaction_hash.to_ascii_lowercase(),
                movement.log.block_number,
                movement.log.block_hash.clone(),
                movement.log.transaction_index,
                movement.incoming,
                movement.amount,
                movement.token_id.clone(),
                position_asset_key(movement.log.asset),
            ))
            .or_default()
            .push(index);
    }
    let mut trade_fill_index: HashMap<TradeFillKey, Vec<usize>> = HashMap::new();
    for (index, wrapped_fill) in owner_census.owner_fills.iter().enumerate() {
        let fill = &wrapped_fill.fill;
        if !owner_fill_binding_valid(fill, wrapped_fill, census) {
            continue;
        }
        trade_fill_index
            .entry((
                fill.wallet.to_ascii_lowercase(),
                fill.transaction_hash.to_ascii_lowercase(),
                fill.share_base_units,
                fill.token_id.clone(),
                trade_side_key(fill.side),
                wrapped_fill.block_timestamp,
            ))
            .or_default()
            .push(index);
    }

    let mut consumed_fills = vec![false; owner_census.owner_fills.len()];
    let mut fifth_transactions = HashSet::new();
    for settlement in fifth_settlements {
        let transaction_hash = settlement.transaction_hash().to_ascii_lowercase();
        let matching_activity: Vec<_> = occurrences
            .iter()
            .enumerate()
            .filter(|(_, occurrence)| {
                occurrence
                    .transaction_hash
                    .eq_ignore_ascii_case(&transaction_hash)
                    && classify_kind(occurrence) == ActivityKind::Trade
            })
            .map(|(index, _)| index)
            .collect();
        for index in &matching_activity {
            consumed_activity[*index] = true;
        }
        if !fifth_transactions.insert(transaction_hash.clone())
            || !fifth_settlement_scope_valid(settlement, &wallet, census)
            || !fifth_activity_fills_match(settlement, &matching_activity, occurrences, census)
        {
            unknown!(
                None,
                matching_activity
                    .first()
                    .map(|index| activity_locator(&occurrences[*index])),
                SourceFlowReason::UnsupportedFifthSettlement
            );
            continue;
        }
        let Some((cash_indexes, position_indexes)) = fifth_settlement_census_matches(
            settlement,
            &cash,
            &positions,
            &consumed_cash,
            &consumed_positions,
        ) else {
            unknown!(
                None,
                matching_activity
                    .first()
                    .map(|index| activity_locator(&occurrences[*index])),
                SourceFlowReason::UnsupportedFifthSettlement
            );
            continue;
        };
        for index in cash_indexes {
            consumed_cash[index] = true;
        }
        for index in position_indexes {
            consumed_positions[index] = true;
        }
    }

    // CTF V1 trades are internal only when zero-fee fill, cash leg and
    // position leg each have a unique exact match.
    for (activity_index, occurrence) in occurrences.iter().enumerate() {
        if consumed_activity[activity_index] || classify_kind(occurrence) != ActivityKind::Trade {
            continue;
        }
        let Some(trade_size) = occurrence
            .raw
            .get("size")
            .and_then(parse_decimal_microunits)
        else {
            unknown!(
                None,
                Some(activity_locator(occurrence)),
                SourceFlowReason::InvalidActivityAmount
            );
            consumed_activity[activity_index] = true;
            continue;
        };
        let Some(token_id) = occurrence.raw.get("asset").and_then(value_string) else {
            unknown!(
                None,
                Some(activity_locator(occurrence)),
                SourceFlowReason::UnsupportedTradeAttribution
            );
            consumed_activity[activity_index] = true;
            continue;
        };
        let side = occurrence
            .raw
            .get("side")
            .and_then(value_string)
            .map(|v| v.to_ascii_uppercase());
        let tx = occurrence.transaction_hash.to_ascii_lowercase();
        let side_key = if side.as_deref() == Some("BUY") {
            0
        } else if side.as_deref() == Some("SELL") {
            1
        } else {
            unknown!(
                None,
                Some(activity_locator(occurrence)),
                SourceFlowReason::UnsupportedTradeAttribution
            );
            consumed_activity[activity_index] = true;
            continue;
        };
        let fill_key = (
            wallet.clone(),
            tx.clone(),
            trade_size,
            token_id,
            side_key,
            u64::try_from(occurrence.timestamp).unwrap_or_default(),
        );
        let fills: Vec<_> = trade_fill_index
            .get(&fill_key)
            .into_iter()
            .flatten()
            .filter(|index| !consumed_fills[**index])
            .map(|index| (*index, &owner_census.owner_fills[*index]))
            .collect();
        if trade_size == 0 || fills.len() != 1 {
            unknown!(
                None,
                Some(activity_locator(occurrence)),
                SourceFlowReason::UnsupportedTradeAttribution
            );
            consumed_activity[activity_index] = true;
            continue;
        }
        let (fill_index, wrapped_fill) = fills[0];
        consumed_fills[fill_index] = true;
        let fill = &wrapped_fill.fill;
        let v1_supported = fill.decoder_version == crate::chain_log_audit::CtfDecoderVersion::V1
            && crate::chain_log_audit::EXCHANGES[..2]
                .iter()
                .any(|exchange| exchange.eq_ignore_ascii_case(&fill.exchange));
        if !v1_supported {
            unknown!(
                None,
                Some(activity_locator(occurrence)),
                SourceFlowReason::UnsupportedTradeVenueOrAssets
            );
            consumed_activity[activity_index] = true;
            continue;
        }
        if fill.fee_base_units != 0 {
            unknown!(
                None,
                Some(activity_locator(occurrence)),
                SourceFlowReason::UnsupportedFeeBearingTrade
            );
            consumed_activity[activity_index] = true;
            continue;
        }
        let incoming = fill.side == TradeSide::Buy;
        let cash_key = (
            tx.clone(),
            fill.block_number,
            fill.block_hash.clone(),
            wrapped_fill.transaction_index,
            !incoming,
            fill.collateral_base_units,
            collateral_key(CollateralAsset::UsdcE),
        );
        let cash_matches: Vec<_> = trade_cash_index
            .get(&cash_key)
            .into_iter()
            .flatten()
            .filter(|index| !consumed_cash[**index] && !conversion_candidate[**index])
            .map(|index| (*index, &cash[*index]))
            .collect();
        let position_key = (
            tx.clone(),
            fill.block_number,
            fill.block_hash.clone(),
            wrapped_fill.transaction_index,
            incoming,
            fill.share_base_units,
            fill.token_id.clone(),
            position_asset_key(RpcCurrentIntervalAsset::Ctf),
        );
        let position_matches: Vec<_> = trade_position_index
            .get(&position_key)
            .into_iter()
            .flatten()
            .filter(|index| !consumed_positions[**index])
            .map(|index| (*index, &positions[*index]))
            .collect();
        if cash_matches.len() != 1 || position_matches.len() != 1 {
            unknown!(
                None,
                Some(activity_locator(occurrence)),
                SourceFlowReason::UnsupportedTradeAttribution
            );
            consumed_activity[activity_index] = true;
            continue;
        }
        consumed_cash[cash_matches[0].0] = true;
        consumed_positions[position_matches[0].0] = true;
        consumed_activity[activity_index] = true;
    }

    // D/W, TIP and documented income rows corroborate a single actual cash
    // movement; API amounts never become the source amount.
    for (activity_index, occurrence) in occurrences.iter().enumerate() {
        if consumed_activity[activity_index] {
            continue;
        }
        let kind = classify_kind(occurrence);
        if kind == ActivityKind::Trade {
            continue;
        }
        if kind == ActivityKind::Unsupported {
            unknown!(
                None,
                Some(activity_locator(occurrence)),
                SourceFlowReason::UnsupportedActivityType
            );
            consumed_activity[activity_index] = true;
            continue;
        }
        let amount = if kind == ActivityKind::TipIn || kind == ActivityKind::TipOut {
            let a = occurrence
                .raw
                .get("size")
                .and_then(parse_decimal_microunits);
            let b = occurrence
                .raw
                .get("usdc_size")
                .and_then(parse_decimal_microunits);
            if a.is_none() || a != b {
                unknown!(
                    None,
                    Some(activity_locator(occurrence)),
                    SourceFlowReason::InvalidActivityAmount
                );
                consumed_activity[activity_index] = true;
                continue;
            }
            a.unwrap_or_default()
        } else {
            let Some(amount) = occurrence
                .raw
                .get("usdc_size")
                .and_then(parse_decimal_microunits)
            else {
                unknown!(
                    None,
                    Some(activity_locator(occurrence)),
                    SourceFlowReason::InvalidActivityAmount
                );
                consumed_activity[activity_index] = true;
                continue;
            };
            amount
        };
        if amount == 0 {
            unknown!(
                None,
                Some(activity_locator(occurrence)),
                SourceFlowReason::InvalidActivityAmount
            );
            consumed_activity[activity_index] = true;
            continue;
        }
        let incoming = matches!(
            kind,
            ActivityKind::Deposit | ActivityKind::TipIn | ActivityKind::Return
        );
        let tx = occurrence.transaction_hash.to_ascii_lowercase();
        let activity_key = (
            tx.clone(),
            incoming,
            amount,
            u64::try_from(occurrence.timestamp).unwrap_or_default(),
        );
        let matches: Vec<_> = activity_cash_index
            .get(&activity_key)
            .into_iter()
            .flatten()
            .filter(|index| !consumed_cash[**index] && !conversion_candidate[**index])
            .map(|index| (*index, &cash[*index]))
            .collect();
        if matches.len() != 1 {
            let reason = if conversion_activity_keys.contains(&(tx.clone(), amount, incoming)) {
                SourceFlowReason::UnsupportedConversionBoundary
            } else {
                SourceFlowReason::MissingOrAmbiguousActivityMatch
            };
            unknown!(None, Some(activity_locator(occurrence)), reason);
            consumed_activity[activity_index] = true;
            continue;
        }
        let (cash_index, movement) = matches[0];
        consumed_cash[cash_index] = true;
        consumed_activity[activity_index] = true;
        if !matches!(kind, ActivityKind::Return) {
            let timestamp = census
                .event_headers
                .iter()
                .find(|header| header.number == movement.log.block_number)
                .map_or(0, |header| header.timestamp);
            let Some(signed_amount) = i128::try_from(movement.amount).ok() else {
                unknown!(
                    Some(movement.log.locator.clone()),
                    None,
                    SourceFlowReason::UnmatchedCashMovement
                );
                continue;
            };
            result.capital_flows.push(SourceWalletCapitalFlow {
                locator: movement.log.locator.clone(),
                timestamp,
                asset: movement.asset,
                signed_amount_microunits: if incoming {
                    signed_amount
                } else {
                    -signed_amount
                },
            });
        }
    }

    for (index, movement) in cash.iter().enumerate() {
        if !consumed_cash[index] {
            let reason = if conversion_candidate[index] {
                SourceFlowReason::UnsupportedConversionBoundary
            } else {
                SourceFlowReason::UnmatchedCashMovement
            };
            unknown!(Some(movement.log.locator.clone()), None, reason);
        }
    }
    for (index, movement) in positions.iter().enumerate() {
        if !consumed_positions[index] {
            unknown!(
                Some(movement.log.locator.clone()),
                None,
                SourceFlowReason::UnmatchedPositionMovement
            );
        }
    }
    for (index, wrapped_fill) in owner_census.owner_fills.iter().enumerate() {
        if !consumed_fills[index] && wrapped_fill.fill.wallet.eq_ignore_ascii_case(&wallet) {
            unknown!(None, None, SourceFlowReason::UnsupportedTradeAttribution);
        }
    }
    result
        .capital_flows
        .sort_by(|a, b| (a.timestamp, &a.locator).cmp(&(b.timestamp, &b.locator)));
    result
}

fn fifth_settlement_scope_valid(
    settlement: &ProviderReportedFifthSettlement,
    wallet: &str,
    census: &RpcCurrentIntervalCensus,
) -> bool {
    let Some(owner) = crate::position_history::normalize_address(settlement.owner()) else {
        return false;
    };
    let Some(transaction_hash) =
        crate::position_history::normalize_hash(settlement.transaction_hash())
    else {
        return false;
    };
    let Some(block_hash) = crate::position_history::normalize_hash(settlement.block_hash()) else {
        return false;
    };
    settlement.chain_id() == 137
        && settlement.source() == FifthEventObservationSource::ProviderReported
        && settlement.implementation_version() == FifthEventImplementationVersion::Unbound
        && owner == wallet
        && settlement.block_number() > census.start_block
        && settlement.block_number() <= census.through_block
        && !settlement.wallet_legs().is_empty()
        && !settlement.owner_fills().is_empty()
        && census.event_headers.iter().any(|header| {
            header.number == settlement.block_number()
                && header.hash.eq_ignore_ascii_case(&block_hash)
                && header.timestamp > census.start_header.timestamp
                && header.timestamp <= census.end_header.timestamp
        })
        && settlement
            .owner_fills()
            .iter()
            .all(|fill| fill.token_id() != alloy_primitives::U256::ZERO)
        && transaction_hash == settlement.transaction_hash().to_ascii_lowercase()
}

fn fifth_activity_fills_match(
    settlement: &ProviderReportedFifthSettlement,
    activity_indexes: &[usize],
    occurrences: &[ActivityHintOccurrence],
    census: &RpcCurrentIntervalCensus,
) -> bool {
    if activity_indexes.is_empty() {
        return true;
    }
    if activity_indexes.len() != settlement.owner_fills().len() {
        return false;
    }
    let Some(timestamp) = census
        .event_headers
        .iter()
        .find(|header| {
            header.number == settlement.block_number()
                && header.hash.eq_ignore_ascii_case(settlement.block_hash())
        })
        .map(|header| header.timestamp)
    else {
        return false;
    };
    let mut expected = HashMap::<(String, u8, u128), usize>::new();
    for fill in settlement.owner_fills() {
        let token_id = fill.token_id().to_string();
        let share_amount = if fill.side() == TradeSide::Buy {
            fill.gross_taking()
        } else {
            fill.gross_making()
        };
        let Ok(share_amount) = share_amount.to_string().parse::<u128>() else {
            return false;
        };
        let side = trade_side_key(fill.side());
        *expected.entry((token_id, side, share_amount)).or_default() += 1;
    }
    let mut observed = HashMap::<(String, u8, u128), usize>::new();
    for index in activity_indexes {
        let occurrence = &occurrences[*index];
        if occurrence.timestamp != i64::try_from(timestamp).unwrap_or_default() {
            return false;
        }
        let Some(token_id) = occurrence.raw.get("asset").and_then(value_string) else {
            return false;
        };
        let Some(side) = occurrence
            .raw
            .get("side")
            .and_then(value_string)
            .map(|value| value.to_ascii_uppercase())
        else {
            return false;
        };
        let side = match side.as_str() {
            "BUY" => 0,
            "SELL" => 1,
            _ => return false,
        };
        let Some(size) = occurrence
            .raw
            .get("size")
            .and_then(parse_decimal_microunits)
        else {
            return false;
        };
        *observed.entry((token_id, side, size)).or_default() += 1;
    }
    observed == expected
}

fn fifth_settlement_census_matches(
    settlement: &ProviderReportedFifthSettlement,
    cash: &[CashMovement<'_>],
    positions: &[PositionMovement<'_>],
    consumed_cash: &[bool],
    consumed_positions: &[bool],
) -> Option<(Vec<usize>, Vec<usize>)> {
    let transaction_hash = settlement.transaction_hash().to_ascii_lowercase();
    let block_hash = settlement.block_hash().to_ascii_lowercase();
    let position_ids = settlement
        .position_ids()
        .map(|id| alloy_primitives::U256::from_be_bytes(id.0));
    let mut cash_indexes = Vec::new();
    let mut position_indexes = Vec::new();
    for leg in settlement.wallet_legs() {
        let amount = leg.amount().to_string().parse::<u128>().ok()?;
        let locator = format!(
            "{}:{}:{}",
            settlement.chain_id(),
            transaction_hash,
            leg.log_index()
        );
        match leg.asset() {
            ProviderReportedFifthAsset::Pusd => {
                let incoming = leg.direction() == ProviderReportedFifthDirection::Inflow;
                let matches: Vec<_> = cash
                    .iter()
                    .enumerate()
                    .filter(|(index, movement)| {
                        !consumed_cash[*index]
                            && movement.log.locator.eq_ignore_ascii_case(&locator)
                            && movement
                                .log
                                .transaction_hash
                                .eq_ignore_ascii_case(&transaction_hash)
                            && movement.log.block_number == settlement.block_number()
                            && movement.log.block_hash.eq_ignore_ascii_case(&block_hash)
                            && movement.log.transaction_index == settlement.transaction_index()
                            && movement.log.asset == RpcCurrentIntervalAsset::Pusd
                            && movement.incoming == incoming
                            && movement.amount == amount
                            && movement
                                .log
                                .from
                                .eq_ignore_ascii_case(&format!("{:#x}", leg.from()))
                            && movement
                                .log
                                .to
                                .eq_ignore_ascii_case(&format!("{:#x}", leg.to()))
                    })
                    .map(|(index, _)| index)
                    .collect();
                if matches.len() != 1 {
                    return None;
                }
                cash_indexes.push(matches[0]);
            }
            ProviderReportedFifthAsset::Position { token_id } => {
                if !position_ids.contains(&token_id) {
                    return None;
                }
                let incoming = leg.direction() == ProviderReportedFifthDirection::Inflow;
                let token_id = token_id.to_string();
                let matches: Vec<_> = positions
                    .iter()
                    .enumerate()
                    .filter(|(index, movement)| {
                        !consumed_positions[*index]
                            && movement.log.locator.eq_ignore_ascii_case(&locator)
                            && movement
                                .log
                                .transaction_hash
                                .eq_ignore_ascii_case(&transaction_hash)
                            && movement.log.block_number == settlement.block_number()
                            && movement.log.block_hash.eq_ignore_ascii_case(&block_hash)
                            && movement.log.transaction_index == settlement.transaction_index()
                            && movement.log.asset == RpcCurrentIntervalAsset::PositionManager
                            && movement.incoming == incoming
                            && movement.token_id == token_id
                            && movement.amount == amount
                            && movement
                                .log
                                .from
                                .eq_ignore_ascii_case(&format!("{:#x}", leg.from()))
                            && movement
                                .log
                                .to
                                .eq_ignore_ascii_case(&format!("{:#x}", leg.to()))
                    })
                    .map(|(index, _)| index)
                    .collect();
                if matches.len() != 1 {
                    return None;
                }
                position_indexes.push(matches[0]);
            }
        }
    }
    let mut unique_cash = HashSet::new();
    let mut unique_positions = HashSet::new();
    if !cash_indexes.iter().all(|index| unique_cash.insert(*index))
        || !position_indexes
            .iter()
            .all(|index| unique_positions.insert(*index))
    {
        return None;
    }
    Some((cash_indexes, position_indexes))
}

fn activity_occurrence_consistent(
    row: &ActivityHintOccurrence,
    wallet: &str,
    start: i64,
    end: i64,
) -> bool {
    let raw_wallet = row
        .raw
        .get("proxy_wallet")
        .and_then(serde_json::Value::as_str)
        .and_then(crate::position_history::normalize_address);
    let raw_timestamp = row.raw.get("timestamp").and_then(serde_json::Value::as_i64);
    let raw_type = row.raw.get("type").and_then(serde_json::Value::as_str);
    let raw_transaction = row
        .raw
        .get("transaction_hash")
        .and_then(serde_json::Value::as_str);
    raw_wallet.as_deref() == Some(wallet)
        && raw_timestamp == Some(row.timestamp)
        && (start..=end).contains(&row.timestamp)
        && raw_type == Some(row.activity_type.as_str())
        && raw_transaction.is_some_and(|transaction| {
            transaction.len() == 66
                && transaction.starts_with("0x")
                && transaction[2..]
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                && transaction.eq_ignore_ascii_case(&row.transaction_hash)
        })
}

fn json_size_bounded(value: &serde_json::Value, maximum: usize) -> Option<usize> {
    struct LimitedCounter {
        bytes: usize,
        maximum: usize,
    }

    impl Write for LimitedCounter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let Some(total) = self.bytes.checked_add(bytes.len()) else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "size overflow"));
            };
            if total > self.maximum {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "size limit"));
            }
            self.bytes = total;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut counter = LimitedCounter { bytes: 0, maximum };
    serde_json::to_writer(&mut counter, value).ok()?;
    Some(counter.bytes)
}

fn owner_fill_binding_valid(
    fill: &crate::chain_log_audit::ChainMakerFill,
    wrapped_fill: &RpcCurrentIntervalOwnerFill,
    census: &RpcCurrentIntervalCensus,
) -> bool {
    let exchange_version_matches = match fill.decoder_version {
        crate::chain_log_audit::CtfDecoderVersion::V1 => crate::chain_log_audit::EXCHANGES[..2]
            .iter()
            .any(|exchange| exchange.eq_ignore_ascii_case(&fill.exchange)),
        crate::chain_log_audit::CtfDecoderVersion::V2 => crate::chain_log_audit::EXCHANGES[2..4]
            .iter()
            .any(|exchange| exchange.eq_ignore_ascii_case(&fill.exchange)),
    };
    fill.chain_id == 137
        && fill.block_number > census.start_block
        && fill.block_number <= census.through_block
        && fill.token_id.len() <= 78
        && !fill.token_id.is_empty()
        && fill.token_id.bytes().all(|byte| byte.is_ascii_digit())
        && crate::position_history::normalize_address(&fill.wallet).is_some()
        && crate::position_history::normalize_address(&fill.exchange).is_some()
        && fill.exchange.len() == 42
        && fill.wallet.len() == 42
        && fill.transaction_hash.len() == 66
        && fill.block_hash.len() == 66
        && exchange_version_matches
        && crate::position_history::normalize_hash(&fill.transaction_hash).is_some()
        && crate::position_history::normalize_hash(&fill.block_hash).is_some()
        && census.event_headers.iter().any(|header| {
            header.number == fill.block_number
                && header.hash == fill.block_hash
                && header.timestamp == wrapped_fill.block_timestamp
        })
}

fn decoded_endpoints_match(from: &str, to: &str, log: &RpcCurrentIntervalLog) -> bool {
    crate::position_history::normalize_address(from)
        == crate::position_history::normalize_address(&log.from)
        && crate::position_history::normalize_address(to)
            == crate::position_history::normalize_address(&log.to)
}

fn position_log_binding_valid(
    position_log: &crate::position_history::PositionTransferLog,
    log: &RpcCurrentIntervalLog,
) -> bool {
    position_log.block_number() == log.block_number
        && position_log.block_hash() == log.block_hash
        && position_log.transaction_hash() == log.transaction_hash
        && position_log.transaction_index() == log.transaction_index
        && position_log.log_index() == log.log_index
}

fn position_asset_matches(
    asset: RpcCurrentIntervalAsset,
    ledger: crate::position_history::PositionLedger,
) -> bool {
    matches!(
        (asset, ledger),
        (
            RpcCurrentIntervalAsset::Ctf,
            crate::position_history::PositionLedger::Ctf
        ) | (
            RpcCurrentIntervalAsset::PositionManager,
            crate::position_history::PositionLedger::PositionManager
        )
    )
}

fn collateral_key(asset: CollateralAsset) -> u8 {
    match asset {
        CollateralAsset::Pusd => 0,
        CollateralAsset::UsdcE => 1,
    }
}

fn position_asset_key(asset: RpcCurrentIntervalAsset) -> u8 {
    match asset {
        RpcCurrentIntervalAsset::Ctf => 0,
        RpcCurrentIntervalAsset::PositionManager => 1,
        RpcCurrentIntervalAsset::Pusd | RpcCurrentIntervalAsset::UsdcE => u8::MAX,
    }
}

fn trade_side_key(side: TradeSide) -> u8 {
    match side {
        TradeSide::Buy => 0,
        TradeSide::Sell => 1,
    }
}

fn classify_kind(occurrence: &ActivityHintOccurrence) -> ActivityKind {
    match occurrence.activity_type.to_ascii_uppercase().as_str() {
        "DEPOSIT" => ActivityKind::Deposit,
        "WITHDRAWAL" => ActivityKind::Withdrawal,
        "TIP" => match occurrence
            .raw
            .get("side")
            .and_then(value_string)
            .map(|s| s.to_ascii_uppercase())
            .as_deref()
        {
            Some("IN") => ActivityKind::TipIn,
            Some("OUT") => ActivityKind::TipOut,
            _ => ActivityKind::Unsupported,
        },
        "REWARD" | "YIELD" | "MAKER_REBATE" | "TAKER_REBATE" | "REFERRAL_REWARD" => {
            ActivityKind::Return
        }
        "TRADE" => ActivityKind::Trade,
        _ => ActivityKind::Unsupported,
    }
}

fn activity_locator(occurrence: &ActivityHintOccurrence) -> String {
    format!(
        "{:?}:{}:{}:{}",
        occurrence.pass, occurrence.page, occurrence.ordinal, occurrence.transaction_hash
    )
}

fn value_string(value: &serde_json::Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_number().map(ToString::to_string))
}

fn parse_decimal_microunits(value: &serde_json::Value) -> Option<u128> {
    let raw = value_string(value)?;
    if raw.starts_with('-') || raw.starts_with('+') || raw.contains(['e', 'E']) {
        return None;
    }
    let (whole, fraction) = raw.split_once('.').unwrap_or((raw.as_str(), ""));
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 6
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let whole = whole.parse::<u128>().ok()?;
    let fraction_value = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u128>().ok()?
    };
    let scale = 10_u128.checked_pow(u32::try_from(6_usize.checked_sub(fraction.len())?).ok()?)?;
    whole
        .checked_mul(1_000_000)?
        .checked_add(fraction_value.checked_mul(scale)?)
}

fn parse_uint256_u128(raw: &str) -> Option<u128> {
    let digits = raw.strip_prefix("0x")?;
    if digits.len() != 64 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let value = u128::from_str_radix(&digits[32..], 16).ok()?;
    if digits[..32].bytes().any(|b| b != b'0') {
        None
    } else {
        Some(value)
    }
}

fn words_to_position(id: &[u8; 32], amount: &[u8; 32]) -> Option<(String, u128)> {
    let token_id = num_bigint::BigUint::from_bytes_be(id).to_str_radix(10);
    Some((token_id, BigEndianWord(amount).to_u128()?))
}

struct BigEndianWord<'a>(&'a [u8; 32]);

impl BigEndianWord<'_> {
    fn to_u128(&self) -> Option<u128> {
        if self.0[..16].iter().any(|byte| *byte != 0) {
            return None;
        }
        Some(u128::from_be_bytes(self.0[16..].try_into().ok()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activity_hints::ActivityHintPass;
    use crate::chain_log_audit::{CtfDecoderVersion, FeeAsset};
    use crate::rpc_position_history::current_interval_census::{
        RpcCurrentIntervalHeader, RpcCurrentIntervalSource,
    };
    use chrono::Utc;
    use serde_json::json;

    const WALLET: &str = "0x1111111111111111111111111111111111111111";
    const OTHER: &str = "0x2222222222222222222222222222222222222222";

    fn tx_hash(tx: &str) -> String {
        format!("0x{:0>64}", tx.strip_prefix("0x").unwrap_or(tx))
    }

    fn occurrence(
        activity_type: &str,
        mut raw: serde_json::Value,
        tx: &str,
    ) -> ActivityHintOccurrence {
        raw["proxy_wallet"] = json!(WALLET);
        raw["timestamp"] = json!(1_001);
        raw["type"] = json!(activity_type);
        raw["transaction_hash"] = json!(tx_hash(tx));
        ActivityHintOccurrence {
            pass: ActivityHintPass::DefaultTypes,
            page: 1,
            ordinal: 0,
            timestamp: 1_001,
            activity_type: activity_type.to_owned(),
            transaction_hash: tx_hash(tx),
            raw,
        }
    }

    fn cash_log(tx: &str, index: u64, from: &str, to: &str, amount: u128) -> RpcCurrentIntervalLog {
        RpcCurrentIntervalLog {
            locator: format!("137:{}:{index}", tx_hash(tx)),
            block_hash: format!("0x{}", "a".repeat(64)),
            transaction_hash: tx_hash(tx),
            block_number: 101,
            transaction_index: 0,
            log_index: index,
            asset: RpcCurrentIntervalAsset::Pusd,
            from: from.to_owned(),
            to: to.to_owned(),
            amount_word: Some(format!("0x{:064x}", amount)),
            position_log: None,
        }
    }

    fn position_log(
        tx: &str,
        index: u64,
        from: &str,
        to: &str,
        token: &str,
        amount: u128,
        emitter: &str,
    ) -> RpcCurrentIntervalLog {
        let indexed = |address: &str| format!("0x{:0>64}", &address[2..]);
        let token_value = num_bigint::BigUint::parse_bytes(token.as_bytes(), 10)
            .expect("decimal fixture token id");
        let token_bytes = token_value.to_bytes_be();
        assert!(token_bytes.len() <= 32);
        let mut token_word = [0_u8; 32];
        token_word[32 - token_bytes.len()..].copy_from_slice(&token_bytes);
        let raw = json!({
            "address": emitter,
            "removed": false,
            "blockNumber": "0x65",
            "blockHash": format!("0x{}", "a".repeat(64)),
            "transactionHash": tx_hash(tx),
            "transactionIndex": "0x0",
            "logIndex": format!("0x{index:x}"),
            "topics": [
                crate::position_history::TRANSFER_SINGLE_TOPIC,
                indexed(OTHER),
                indexed(from),
                indexed(to),
            ],
            "data": format!("0x{}{:064x}", hex::encode(token_word), amount),
        });
        let direction = if to == WALLET {
            super::super::Direction::To
        } else {
            super::super::Direction::From
        };
        super::super::decode_log(
            &raw,
            &[WALLET.to_owned()],
            100,
            101,
            direction,
            super::super::CurrentIntervalLogFamily::Position,
        )
        .expect("well-formed fixture ERC-1155 transfer")
    }

    fn settlement_position_log(
        settlement: &ProviderReportedFifthSettlement,
        index: u64,
        from: &str,
        to: &str,
        token: &str,
        amount: u128,
        emitter: &str,
    ) -> RpcCurrentIntervalLog {
        let indexed = |address: &str| format!("0x{:0>64}", &address[2..]);
        let token_value = num_bigint::BigUint::parse_bytes(token.as_bytes(), 10)
            .expect("decimal fixture token id");
        let token_bytes = token_value.to_bytes_be();
        assert!(token_bytes.len() <= 32);
        let mut token_word = [0_u8; 32];
        token_word[32 - token_bytes.len()..].copy_from_slice(&token_bytes);
        let transaction_hash = settlement.transaction_hash();
        let block_hash = settlement.block_hash();
        let raw = json!({
            "address": emitter,
            "removed": false,
            "blockNumber": format!("0x{:x}", settlement.block_number()),
            "blockHash": block_hash,
            "transactionHash": transaction_hash,
            "transactionIndex": format!("0x{:x}", settlement.transaction_index()),
            "logIndex": format!("0x{index:x}"),
            "topics": [
                crate::position_history::TRANSFER_SINGLE_TOPIC,
                indexed(OTHER),
                indexed(from),
                indexed(to),
            ],
            "data": format!("0x{}{:064x}", hex::encode(token_word), amount),
        });
        let direction = if to.eq_ignore_ascii_case(settlement.owner()) {
            super::super::Direction::To
        } else {
            super::super::Direction::From
        };
        super::super::decode_log(
            &raw,
            &[settlement.owner().to_owned()],
            settlement.block_number() - 1,
            settlement.block_number(),
            direction,
            super::super::CurrentIntervalLogFamily::Position,
        )
        .expect("well-formed settlement ERC-1155 transfer")
    }

    fn fifth_fixture(
        settlement: &ProviderReportedFifthSettlement,
        extra_cash: bool,
    ) -> RpcCurrentIntervalOwnerFillCensus {
        let mut logs = Vec::new();
        for leg in settlement.wallet_legs() {
            let amount = leg.amount().to_string().parse::<u128>().unwrap();
            let from = format!("{:#x}", leg.from());
            let to = format!("{:#x}", leg.to());
            let mut log = match leg.asset() {
                ProviderReportedFifthAsset::Pusd => cash_log(
                    settlement.transaction_hash(),
                    leg.log_index(),
                    &from,
                    &to,
                    amount,
                ),
                ProviderReportedFifthAsset::Position { token_id } => settlement_position_log(
                    settlement,
                    leg.log_index(),
                    &from,
                    &to,
                    &token_id.to_string(),
                    amount,
                    crate::position_history::POSITION_MANAGER_EMITTER,
                ),
            };
            log.locator = format!(
                "{}:{}:{}",
                settlement.chain_id(),
                settlement.transaction_hash(),
                leg.log_index()
            );
            log.block_number = settlement.block_number();
            log.block_hash = settlement.block_hash().to_owned();
            log.transaction_hash = settlement.transaction_hash().to_owned();
            log.transaction_index = settlement.transaction_index();
            log.asset = match leg.asset() {
                ProviderReportedFifthAsset::Pusd => RpcCurrentIntervalAsset::Pusd,
                ProviderReportedFifthAsset::Position { .. } => {
                    RpcCurrentIntervalAsset::PositionManager
                }
            };
            logs.push(log);
        }
        if extra_cash {
            let mut extra = cash_log(
                settlement.transaction_hash(),
                999,
                settlement.owner(),
                OTHER,
                7,
            );
            extra.locator = format!(
                "{}:{}:999",
                settlement.chain_id(),
                settlement.transaction_hash()
            );
            extra.block_number = settlement.block_number();
            extra.block_hash = settlement.block_hash().to_owned();
            extra.transaction_hash = settlement.transaction_hash().to_owned();
            extra.transaction_index = settlement.transaction_index();
            logs.push(extra);
        }
        let mut wrapped = census(logs);
        wrapped.census.wallets = vec![settlement.owner().to_owned()];
        wrapped.census.start_block = settlement.block_number() - 1;
        wrapped.census.through_block = settlement.block_number();
        wrapped.census.start_header = RpcCurrentIntervalHeader {
            number: settlement.block_number() - 1,
            hash: format!("0x{}", "bb".repeat(32)),
            timestamp: 1_000,
        };
        wrapped.census.end_header = RpcCurrentIntervalHeader {
            number: settlement.block_number(),
            hash: settlement.block_hash().to_owned(),
            timestamp: 1_001,
        };
        wrapped.census.event_headers = vec![wrapped.census.end_header.clone()];
        wrapped
    }

    fn fifth_activity_window<'a>(
        wallet: &'a str,
        occurrences: &'a [ActivityHintOccurrence],
    ) -> SourceWalletActivityWindow<'a> {
        SourceWalletActivityWindow {
            wallet,
            policy_version: crate::activity_hints::ACTIVITY_HINT_POLICY_VERSION,
            start: 999,
            end: 1_003,
            default_pass: ActivityHintPassSummary {
                pages_requested: 1,
                rows_retained: occurrences
                    .iter()
                    .filter(|row| row.pass == ActivityHintPass::DefaultTypes)
                    .count(),
                status: ActivityHintPassStatus::Complete,
            },
            tip_pass: ActivityHintPassSummary {
                pages_requested: 1,
                rows_retained: occurrences
                    .iter()
                    .filter(|row| row.pass == ActivityHintPass::Tip)
                    .count(),
                status: ActivityHintPassStatus::Complete,
            },
            occurrences,
        }
    }

    fn fifth_trade_occurrence(
        settlement: &ProviderReportedFifthSettlement,
    ) -> ActivityHintOccurrence {
        let fill = &settlement.owner_fills()[0];
        let shares = if fill.side() == TradeSide::Buy {
            fill.gross_taking()
        } else {
            fill.gross_making()
        };
        let size = shares.to_string().parse::<u128>().unwrap();
        let mut row = occurrence(
            "TRADE",
            json!({
                "asset": fill.token_id().to_string(),
                "side": if fill.side() == TradeSide::Buy { "BUY" } else { "SELL" },
                "size": format!("{}.{:06}", size / 1_000_000, size % 1_000_000),
                "usdc_size": "provider-gross-net-unspecified",
            }),
            settlement.transaction_hash(),
        );
        row.raw["proxy_wallet"] = json!(settlement.owner());
        row.raw["transaction_hash"] = json!(settlement.transaction_hash());
        row.transaction_hash = settlement.transaction_hash().to_owned();
        row
    }

    fn census(logs: Vec<RpcCurrentIntervalLog>) -> RpcCurrentIntervalOwnerFillCensus {
        RpcCurrentIntervalOwnerFillCensus {
            census: RpcCurrentIntervalCensus {
                wallets: vec![WALLET.to_owned()],
                start_block: 100,
                through_block: 101,
                start_header: RpcCurrentIntervalHeader {
                    number: 100,
                    hash: format!("0x{}", "b".repeat(64)),
                    timestamp: 1_000,
                },
                end_header: RpcCurrentIntervalHeader {
                    number: 101,
                    hash: format!("0x{}", "a".repeat(64)),
                    timestamp: 1_001,
                },
                event_headers: vec![RpcCurrentIntervalHeader {
                    number: 101,
                    hash: format!("0x{}", "a".repeat(64)),
                    timestamp: 1_001,
                }],
                logs,
                source: RpcCurrentIntervalSource::ProviderReported,
                started_at: Utc::now(),
                completed_at: Utc::now(),
                elapsed: std::time::Duration::ZERO,
                request_count: 1,
                response_bytes: 1,
                requests: Vec::new(),
            },
            owner_fills: Vec::new(),
        }
    }

    fn reduce(
        rows: &[ActivityHintOccurrence],
        logs: Vec<RpcCurrentIntervalLog>,
    ) -> SourceWalletFlowReduction {
        let window = SourceWalletActivityWindow {
            wallet: WALLET,
            policy_version: crate::activity_hints::ACTIVITY_HINT_POLICY_VERSION,
            start: 999,
            end: 1_003,
            default_pass: ActivityHintPassSummary {
                pages_requested: 1,
                rows_retained: rows
                    .iter()
                    .filter(|row| row.pass == ActivityHintPass::DefaultTypes)
                    .count(),
                status: ActivityHintPassStatus::Complete,
            },
            tip_pass: ActivityHintPassSummary {
                pages_requested: 1,
                rows_retained: rows
                    .iter()
                    .filter(|row| row.pass == ActivityHintPass::Tip)
                    .count(),
                status: ActivityHintPassStatus::Complete,
            },
            occurrences: rows,
        };
        reduce_source_wallet_flows(window, &census(logs))
    }

    #[test]
    fn fifth_settlement_consumes_exact_legs_and_fee_refund_are_not_extra_flows() {
        let normal = crate::chain_log_audit::provider_normal_buy_settlement();
        assert_eq!(normal.owner_fills()[0].fee(), alloy_primitives::U256::ONE);
        let normal_census = fifth_fixture(&normal, false);
        let normal_result = reduce_source_wallet_flows_with_fifth_settlements(
            fifth_activity_window(normal.owner(), &[]),
            &normal_census,
            std::slice::from_ref(&normal),
        );
        assert_eq!(
            normal_result.coverage,
            SourceFlowCoverage::KnownForDeclaredScope
        );
        assert!(normal_result.capital_flows.is_empty());
        assert!(normal_result.unresolved.is_empty());

        let refunded = crate::chain_log_audit::provider_mint_refund_settlement();
        assert_eq!(
            refunded.owner_refund_amount(),
            alloy_primitives::U256::from(10_u8)
        );
        assert!(refunded.owner_refund_log_index().is_some());
        let refunded_census = fifth_fixture(&refunded, false);
        let refunded_result = reduce_source_wallet_flows_with_fifth_settlements(
            fifth_activity_window(refunded.owner(), &[]),
            &refunded_census,
            std::slice::from_ref(&refunded),
        );
        assert_eq!(
            refunded_result.coverage,
            SourceFlowCoverage::KnownForDeclaredScope
        );
        assert!(refunded_result.capital_flows.is_empty());
        assert!(refunded_result.unresolved.is_empty());
    }

    #[test]
    fn fifth_settlement_api_trade_corroborates_fills_but_ignores_undocumented_cash_size() {
        let settlement = crate::chain_log_audit::provider_normal_buy_settlement();
        let census = fifth_fixture(&settlement, false);
        let row = fifth_trade_occurrence(&settlement);
        let result = reduce_source_wallet_flows_with_fifth_settlements(
            fifth_activity_window(settlement.owner(), std::slice::from_ref(&row)),
            &census,
            std::slice::from_ref(&settlement),
        );
        assert_eq!(result.coverage, SourceFlowCoverage::KnownForDeclaredScope);
        assert!(result.capital_flows.is_empty());
        assert!(result.unresolved.is_empty());

        let legacy = reduce_source_wallet_flows(
            fifth_activity_window(settlement.owner(), std::slice::from_ref(&row)),
            &census,
        );
        let empty_extended = reduce_source_wallet_flows_with_fifth_settlements(
            fifth_activity_window(settlement.owner(), std::slice::from_ref(&row)),
            &census,
            &[],
        );
        assert!(legacy == empty_extended);
        assert_eq!(legacy.coverage, SourceFlowCoverage::Unknown);
    }

    #[test]
    fn fifth_settlement_rejects_mismatched_or_partial_api_occurrences() {
        let settlement = crate::chain_log_audit::provider_normal_buy_settlement();
        let census = fifth_fixture(&settlement, false);
        for field in ["asset", "size"] {
            let mut row = fifth_trade_occurrence(&settlement);
            row.raw[field] = json!(if field == "asset" { "999" } else { "0.0002" });
            let result = reduce_source_wallet_flows_with_fifth_settlements(
                fifth_activity_window(settlement.owner(), std::slice::from_ref(&row)),
                &census,
                std::slice::from_ref(&settlement),
            );
            assert_eq!(result.coverage, SourceFlowCoverage::Unknown);
        }
        let row = fifth_trade_occurrence(&settlement);
        let mut duplicate = row.clone();
        duplicate.ordinal = 1;
        let rows = [row, duplicate];
        let result = reduce_source_wallet_flows_with_fifth_settlements(
            fifth_activity_window(settlement.owner(), &rows),
            &census,
            std::slice::from_ref(&settlement),
        );
        assert_eq!(result.coverage, SourceFlowCoverage::Unknown);
    }

    #[test]
    fn fifth_settlement_leaves_unprojected_or_conflicting_movements_unknown() {
        let settlement = crate::chain_log_audit::provider_normal_buy_settlement();
        let extra = fifth_fixture(&settlement, true);
        let result = reduce_source_wallet_flows_with_fifth_settlements(
            fifth_activity_window(settlement.owner(), &[]),
            &extra,
            std::slice::from_ref(&settlement),
        );
        assert_eq!(result.coverage, SourceFlowCoverage::Unknown);
        assert!(result.unresolved.iter().any(|item| {
            item.movement_locator
                .as_deref()
                .is_some_and(|locator| locator.ends_with(":999"))
        }));

        let mut wrong_locator = fifth_fixture(&settlement, false);
        wrong_locator.census.logs[0].locator = "wrong-locator".to_owned();
        let result = reduce_source_wallet_flows_with_fifth_settlements(
            fifth_activity_window(settlement.owner(), &[]),
            &wrong_locator,
            std::slice::from_ref(&settlement),
        );
        assert_eq!(result.coverage, SourceFlowCoverage::Unknown);

        let mut wrong_ledger = fifth_fixture(&settlement, false);
        let position_index = wrong_ledger
            .census
            .logs
            .iter()
            .position(|log| log.asset == RpcCurrentIntervalAsset::PositionManager)
            .unwrap();
        let projected_leg = settlement
            .wallet_legs()
            .iter()
            .find(|leg| matches!(leg.asset(), ProviderReportedFifthAsset::Position { .. }))
            .unwrap();
        let ProviderReportedFifthAsset::Position { token_id } = projected_leg.asset() else {
            unreachable!()
        };
        let amount = projected_leg.amount().to_string().parse::<u128>().unwrap();
        wrong_ledger.census.logs[position_index] = settlement_position_log(
            &settlement,
            projected_leg.log_index(),
            &format!("{:#x}", projected_leg.from()),
            &format!("{:#x}", projected_leg.to()),
            &token_id.to_string(),
            amount,
            crate::position_history::CTF_EMITTER,
        );
        wrong_ledger.census.logs[position_index].asset = RpcCurrentIntervalAsset::Ctf;
        let result = reduce_source_wallet_flows_with_fifth_settlements(
            fifth_activity_window(settlement.owner(), &[]),
            &wrong_ledger,
            std::slice::from_ref(&settlement),
        );
        assert_eq!(result.coverage, SourceFlowCoverage::Unknown);

        let mut wrong_counterparty = fifth_fixture(&settlement, false);
        let leg = &settlement.wallet_legs()[0];
        let movement = wrong_counterparty
            .census
            .logs
            .iter_mut()
            .find(|log| log.log_index == leg.log_index())
            .unwrap();
        if format!("{:#x}", leg.from()).eq_ignore_ascii_case(settlement.owner()) {
            movement.to = WALLET.to_owned();
        } else {
            movement.from = WALLET.to_owned();
        }
        let result = reduce_source_wallet_flows_with_fifth_settlements(
            fifth_activity_window(settlement.owner(), &[]),
            &wrong_counterparty,
            std::slice::from_ref(&settlement),
        );
        assert_eq!(result.coverage, SourceFlowCoverage::Unknown);

        let mut wrong_position_counterparty = fifth_fixture(&settlement, false);
        let position_leg = settlement
            .wallet_legs()
            .iter()
            .find(|leg| matches!(leg.asset(), ProviderReportedFifthAsset::Position { .. }))
            .unwrap();
        let ProviderReportedFifthAsset::Position { token_id } = position_leg.asset() else {
            unreachable!()
        };
        let position_index = wrong_position_counterparty
            .census
            .logs
            .iter()
            .position(|log| log.log_index == position_leg.log_index())
            .unwrap();
        let position_amount = position_leg.amount().to_string().parse::<u128>().unwrap();
        wrong_position_counterparty.census.logs[position_index] = settlement_position_log(
            &settlement,
            position_leg.log_index(),
            WALLET,
            &format!("{:#x}", position_leg.to()),
            &token_id.to_string(),
            position_amount,
            crate::position_history::POSITION_MANAGER_EMITTER,
        );
        wrong_position_counterparty.census.logs[position_index].asset =
            RpcCurrentIntervalAsset::PositionManager;
        let result = reduce_source_wallet_flows_with_fifth_settlements(
            fifth_activity_window(settlement.owner(), &[]),
            &wrong_position_counterparty,
            std::slice::from_ref(&settlement),
        );
        assert_eq!(result.coverage, SourceFlowCoverage::Unknown);

        let mut wrong_range = fifth_fixture(&settlement, false);
        wrong_range.census.start_block = settlement.block_number();
        let result = reduce_source_wallet_flows_with_fifth_settlements(
            fifth_activity_window(settlement.owner(), &[]),
            &wrong_range,
            std::slice::from_ref(&settlement),
        );
        assert_eq!(result.coverage, SourceFlowCoverage::Unknown);

        let mut wrong_owner_census = fifth_fixture(&settlement, false);
        wrong_owner_census.census.wallets = vec![settlement.owner().to_owned(), WALLET.to_owned()];
        let result = reduce_source_wallet_flows_with_fifth_settlements(
            fifth_activity_window(WALLET, &[]),
            &wrong_owner_census,
            std::slice::from_ref(&settlement),
        );
        assert_eq!(result.coverage, SourceFlowCoverage::Unknown);

        let duplicate = [settlement.clone(), settlement.clone()];
        let census = fifth_fixture(&settlement, false);
        let result = reduce_source_wallet_flows_with_fifth_settlements(
            fifth_activity_window(settlement.owner(), &[]),
            &census,
            &duplicate,
        );
        assert_eq!(result.coverage, SourceFlowCoverage::Unknown);
    }

    #[test]
    fn decimal_amounts_are_exact_and_limited_to_six_places() {
        assert_eq!(
            parse_decimal_microunits(&serde_json::json!("1.000001")),
            Some(1_000_001)
        );
        assert_eq!(
            parse_decimal_microunits(&serde_json::json!("0.1")),
            Some(100_000)
        );
        assert_eq!(
            parse_decimal_microunits(&serde_json::json!("0.0000001")),
            None
        );
        assert_eq!(parse_decimal_microunits(&serde_json::json!("1e-6")), None);
    }

    #[test]
    fn oversized_abi_amounts_are_not_truncated() {
        assert_eq!(
            parse_uint256_u128(&format!("0x{}{}", "1".repeat(32), "0".repeat(32))),
            None
        );
        assert_eq!(parse_uint256_u128(&format!("0x{:064x}", 7)), Some(7));
        assert_eq!(
            parse_uint256_u128(&format!("0x{}é{}", "0".repeat(31), "0".repeat(31))),
            None
        );
    }

    #[test]
    fn deposit_and_withdrawal_use_unique_chain_cash_legs_once() {
        let mut rows = [
            occurrence("DEPOSIT", json!({"usdc_size":"1"}), "0x01"),
            occurrence("WITHDRAWAL", json!({"usdc_size":"0.25"}), "0x02"),
        ];
        rows[1].ordinal = 1;
        let result = reduce(
            &rows,
            vec![
                cash_log("0x01", 1, ZERO_ADDRESS, WALLET, 1_000_000),
                cash_log("0x02", 2, WALLET, OTHER, 250_000),
            ],
        );
        assert_eq!(result.coverage, SourceFlowCoverage::KnownForDeclaredScope);
        assert_eq!(result.capital_flows.len(), 2);
        assert_eq!(result.capital_flows[0].signed_amount_microunits, 1_000_000);
        assert_eq!(result.capital_flows[1].signed_amount_microunits, -250_000);
        assert!(result.unresolved.is_empty());
    }

    #[test]
    fn tip_requires_dual_amount_match_and_income_is_not_capital() {
        let rows = [
            {
                let mut row = occurrence(
                    "TIP",
                    json!({"side":"IN","size":"0.5","usdc_size":"0.5"}),
                    "0x03",
                );
                row.pass = ActivityHintPass::Tip;
                row
            },
            occurrence("YIELD", json!({"usdc_size":"0.1"}), "0x04"),
        ];
        let result = reduce(
            &rows,
            vec![
                cash_log("0x03", 3, OTHER, WALLET, 500_000),
                cash_log("0x04", 4, OTHER, WALLET, 100_000),
            ],
        );
        assert_eq!(result.coverage, SourceFlowCoverage::KnownForDeclaredScope);
        assert_eq!(result.capital_flows.len(), 1);
        assert_eq!(result.capital_flows[0].signed_amount_microunits, 500_000);

        let bad_tip = [{
            let mut row = occurrence(
                "TIP",
                json!({"side":"IN","size":"0.5","usdc_size":"0.4"}),
                "0x05",
            );
            row.pass = ActivityHintPass::Tip;
            row
        }];
        let bad = reduce(&bad_tip, vec![cash_log("0x05", 5, OTHER, WALLET, 500_000)]);
        assert_eq!(bad.coverage, SourceFlowCoverage::Unknown);
        assert!(bad.capital_flows.is_empty());
    }

    #[test]
    fn repeated_activity_claims_and_unrelated_cash_do_not_suppress_movements() {
        let mut rows = [
            occurrence("DEPOSIT", json!({"usdc_size":"1"}), "0x06"),
            occurrence("DEPOSIT", json!({"usdc_size":"1"}), "0x06"),
        ];
        rows[1].ordinal = 1;
        let result = reduce(
            &rows,
            vec![
                cash_log("0x06", 6, OTHER, WALLET, 1_000_000),
                cash_log("0x06", 7, WALLET, OTHER, 2_000_000),
            ],
        );
        assert_eq!(result.coverage, SourceFlowCoverage::Unknown);
        assert_eq!(result.capital_flows.len(), 1);
        assert_eq!(
            result.capital_flows[0].locator,
            format!("137:{}:6", tx_hash("0x06"))
        );
        assert!(
            result
                .unresolved
                .iter()
                .any(|item| item.reason == SourceFlowReason::MissingOrAmbiguousActivityMatch)
        );
        assert!(
            result
                .unresolved
                .iter()
                .any(|item| item.reason == SourceFlowReason::UnmatchedCashMovement)
        );
    }

    #[test]
    fn incomplete_activity_pass_keeps_coverage_unknown() {
        let result = reduce(&[], Vec::new());
        assert_eq!(result.coverage, SourceFlowCoverage::KnownForDeclaredScope);
        let window = SourceWalletActivityWindow {
            wallet: WALLET,
            policy_version: crate::activity_hints::ACTIVITY_HINT_POLICY_VERSION,
            start: 999,
            end: 1_003,
            default_pass: ActivityHintPassSummary {
                pages_requested: 0,
                rows_retained: 0,
                status: ActivityHintPassStatus::Complete,
            },
            tip_pass: ActivityHintPassSummary {
                pages_requested: 0,
                rows_retained: 0,
                status: ActivityHintPassStatus::NotStarted,
            },
            occurrences: &[],
        };
        let result = reduce_source_wallet_flows(window, &census(Vec::new()));
        assert_eq!(result.coverage, SourceFlowCoverage::Unknown);
        assert!(
            result
                .unresolved
                .iter()
                .any(|item| item.reason == SourceFlowReason::ActivityPassIncomplete)
        );
    }

    #[test]
    fn zero_value_transfer_has_no_cash_effect_and_inconsistent_raw_row_is_unknown() {
        let result = reduce(&[], vec![cash_log("0x0a", 9, OTHER, WALLET, 0)]);
        assert_eq!(result.coverage, SourceFlowCoverage::KnownForDeclaredScope);
        assert!(result.capital_flows.is_empty());
        assert!(result.unresolved.is_empty());

        let mut row = occurrence("DEPOSIT", json!({"usdc_size":"1"}), "0x0b");
        row.raw["timestamp"] = json!(1_000);
        let result = reduce(&[row], vec![cash_log("0x0b", 10, OTHER, WALLET, 1_000_000)]);
        assert_eq!(result.coverage, SourceFlowCoverage::Unknown);
        assert!(
            result
                .unresolved
                .iter()
                .any(|item| { item.reason == SourceFlowReason::InvalidActivityOccurrence })
        );
    }

    #[test]
    fn equal_opposite_cross_collateral_pair_stays_unknown_without_boundary_evidence() {
        let mut inbound = cash_log("0x07", 8, OTHER, WALLET, 5_000_000);
        inbound.asset = RpcCurrentIntervalAsset::UsdcE;
        let result = reduce(
            &[],
            vec![cash_log("0x07", 7, WALLET, OTHER, 5_000_000), inbound],
        );
        assert_eq!(result.coverage, SourceFlowCoverage::Unknown);
        assert!(result.capital_flows.is_empty());
        assert_eq!(result.unresolved.len(), 2);
        assert!(
            result
                .unresolved
                .iter()
                .all(|item| item.reason == SourceFlowReason::UnsupportedConversionBoundary)
        );
    }

    #[test]
    fn unrecognized_activity_tag_cannot_turn_a_cash_leg_into_a_flow() {
        let row = occurrence("NEW_VENUE_EVENT", json!({"usdc_size":"1"}), "0x0c");
        let result = reduce(&[row], vec![cash_log("0x0c", 12, OTHER, WALLET, 1_000_000)]);
        assert_eq!(result.coverage, SourceFlowCoverage::Unknown);
        assert!(result.capital_flows.is_empty());
        assert!(
            result
                .unresolved
                .iter()
                .any(|item| { item.reason == SourceFlowReason::UnsupportedActivityType })
        );
    }

    #[test]
    fn zero_fee_v1_and_unsupported_v2_trade_shapes_are_classified_conservatively() {
        for (tx, side, cash_from, cash_to, position_from, position_to, decoder_version, token_id) in [
            (
                "0x08",
                TradeSide::Buy,
                WALLET,
                OTHER,
                OTHER,
                WALLET,
                CtfDecoderVersion::V1,
                "340282366920938463463374607431768211456",
            ),
            (
                "0x09",
                TradeSide::Sell,
                OTHER,
                WALLET,
                WALLET,
                OTHER,
                CtfDecoderVersion::V2,
                "1",
            ),
        ] {
            let occurrence = occurrence(
                "TRADE",
                json!({"asset":token_id,"side":side.as_str().to_ascii_uppercase(),"size":"1"}),
                tx,
            );
            let mut cash = cash_log(tx, 10, cash_from, cash_to, 2_000_000);
            cash.asset = RpcCurrentIntervalAsset::UsdcE;
            let mut wrapped = census(vec![
                cash,
                position_log(
                    tx,
                    11,
                    position_from,
                    position_to,
                    token_id,
                    1_000_000,
                    crate::position_history::CTF_EMITTER,
                ),
            ]);
            wrapped.owner_fills.push(RpcCurrentIntervalOwnerFill {
                fill: crate::chain_log_audit::ChainMakerFill {
                    chain_id: 137,
                    block_number: 101,
                    block_hash: format!("0x{}", "a".repeat(64)),
                    exchange: crate::chain_log_audit::EXCHANGES[if decoder_version
                        == CtfDecoderVersion::V1
                    {
                        0
                    } else {
                        2
                    }]
                    .to_ascii_lowercase(),
                    transaction_hash: tx_hash(tx),
                    log_index: 12,
                    order_hash: format!("0x{}", "c".repeat(64)),
                    wallet: WALLET.to_owned(),
                    raw_counterparty: OTHER.to_owned(),
                    exchange_counterparty_aggregate_shape: false,
                    decoder_version,
                    fee_asset: FeeAsset::Collateral,
                    token_id: token_id.to_owned(),
                    side,
                    share_base_units: 1_000_000,
                    collateral_base_units: 2_000_000,
                    fee_base_units: 0,
                },
                transaction_index: 0,
                block_timestamp: 1_001,
            });
            let window = SourceWalletActivityWindow {
                wallet: WALLET,
                policy_version: crate::activity_hints::ACTIVITY_HINT_POLICY_VERSION,
                start: 999,
                end: 1_003,
                default_pass: ActivityHintPassSummary {
                    pages_requested: 1,
                    rows_retained: 1,
                    status: ActivityHintPassStatus::Complete,
                },
                tip_pass: ActivityHintPassSummary {
                    pages_requested: 1,
                    rows_retained: 0,
                    status: ActivityHintPassStatus::Complete,
                },
                occurrences: std::slice::from_ref(&occurrence),
            };
            let result = reduce_source_wallet_flows(window, &wrapped);
            if decoder_version == CtfDecoderVersion::V1 {
                assert_eq!(result.coverage, SourceFlowCoverage::KnownForDeclaredScope);
                assert!(result.capital_flows.is_empty());
                assert!(result.unresolved.is_empty());

                let no_activity = SourceWalletActivityWindow {
                    default_pass: ActivityHintPassSummary {
                        pages_requested: 1,
                        rows_retained: 0,
                        status: ActivityHintPassStatus::Complete,
                    },
                    occurrences: &[],
                    ..window
                };
                let result = reduce_source_wallet_flows(no_activity, &wrapped);
                assert_eq!(result.coverage, SourceFlowCoverage::Unknown);
                assert!(
                    result.unresolved.iter().any(|item| {
                        item.reason == SourceFlowReason::UnsupportedTradeAttribution
                    })
                );

                wrapped.owner_fills[0].fill.token_id = "not-decimal".to_owned();
                let result = reduce_source_wallet_flows(no_activity, &wrapped);
                assert_eq!(result.coverage, SourceFlowCoverage::Unknown);
                assert!(
                    result.unresolved.iter().any(|item| {
                        item.reason == SourceFlowReason::UnsupportedTradeAttribution
                    })
                );

                wrapped.owner_fills[0].fill.token_id = token_id.to_owned();
                wrapped.owner_fills[0].fill.fee_base_units = 1;
                let result = reduce_source_wallet_flows(window, &wrapped);
                assert_eq!(result.coverage, SourceFlowCoverage::Unknown);
                assert!(
                    result.unresolved.iter().any(|item| {
                        item.reason == SourceFlowReason::UnsupportedFeeBearingTrade
                    })
                );
            } else {
                assert_eq!(result.coverage, SourceFlowCoverage::Unknown);
                assert!(result.unresolved.iter().any(|item| {
                    item.reason == SourceFlowReason::UnsupportedTradeVenueOrAssets
                }));
            }
        }
    }
}
