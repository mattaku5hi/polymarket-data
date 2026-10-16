//! Provider-reported, standard CTF V2 all-complementary settlement projection.
//!
//! This is deliberately separate from the fifth Exchange model and remains
//! unbound to runtime code identity. Only canonical one-family complementary
//! `matchOrders` transactions with an exact complete receipt are supported.

use std::str::FromStr;

use alloy_primitives::{Address, B256, U256};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use thiserror::Error;

use super::fifth_match_orders_call::{
    FIFTH_MATCH_ORDERS_MAX_MAKERS, FIFTH_MATCH_ORDERS_MAX_SIGNATURE_BYTES, FifthMatchOrder,
    FifthOrderSide, decode_order_tuple, fifth_order_struct_hash,
};
use super::provider_reported_transaction::{
    ProviderTransactionBindingError, ProviderTransactionLog, bind_provider_transaction,
    match_ordered_logs,
};
use super::{abi_u256_word, abi_usize, field, parse_hex_u64, validate_hex};
use crate::rpc_position_history::ctf_v2_context::{
    RpcCurrentCtfV2Context, RpcCurrentCtfV2ContextSource, RpcCurrentCtfV2ImplementationVersion,
};

const EXCHANGE: &str = "0xe111180000d2663c0091e4f400237545b87b996b";
const MATCH_SELECTOR: [u8; 4] = [0x3c, 0x2b, 0x43, 0x99];
const ORDER_FILLED_SIGNATURE: &str =
    "OrderFilled(bytes32,address,address,uint8,uint256,uint256,uint256,uint256,bytes32,bytes32)";
const FEE_CHARGED_SIGNATURE: &str = "FeeCharged(address,uint256)";
const ORDERS_MATCHED_SIGNATURE: &str =
    "OrdersMatched(bytes32,address,uint8,uint256,uint256,uint256)";
const TRANSFER_SIGNATURE: &str = "Transfer(address,address,uint256)";
const TRANSFER_SINGLE_SIGNATURE: &str = "TransferSingle(address,address,address,uint256,uint256)";

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProviderReportedCtfV2SettlementError {
    #[error("provider-reported CTF V2 transaction is malformed")]
    MalformedTransaction,
    #[error("provider-reported CTF V2 receipt is malformed")]
    MalformedReceipt,
    #[error("provider-reported CTF V2 settlement does not match the pinned complementary model")]
    SettlementMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderReportedCtfV2Direction {
    Inflow,
    Outflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderReportedCtfV2Side {
    Buy,
    Sell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderReportedCtfV2OrderRole {
    Active,
    Maker,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderReportedCtfV2WalletLeg {
    log_index: u64,
    asset_address: Address,
    from: Address,
    to: Address,
    direction: ProviderReportedCtfV2Direction,
    amount: U256,
    token_id: Option<U256>,
}

impl ProviderReportedCtfV2WalletLeg {
    #[must_use]
    pub const fn log_index(&self) -> u64 {
        self.log_index
    }
    #[must_use]
    pub const fn asset_address(&self) -> Address {
        self.asset_address
    }
    #[must_use]
    pub const fn from(&self) -> Address {
        self.from
    }
    #[must_use]
    pub const fn to(&self) -> Address {
        self.to
    }
    #[must_use]
    pub const fn direction(&self) -> ProviderReportedCtfV2Direction {
        self.direction
    }
    #[must_use]
    pub const fn amount(&self) -> U256 {
        self.amount
    }
    #[must_use]
    pub const fn token_id(&self) -> Option<U256> {
        self.token_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderReportedCtfV2OwnerFill {
    log_index: u64,
    token_id: U256,
    side: ProviderReportedCtfV2Side,
    gross_making: U256,
    gross_taking: U256,
    fee: U256,
    role: ProviderReportedCtfV2OrderRole,
}

impl ProviderReportedCtfV2OwnerFill {
    #[must_use]
    pub const fn log_index(&self) -> u64 {
        self.log_index
    }
    #[must_use]
    pub const fn token_id(&self) -> U256 {
        self.token_id
    }
    #[must_use]
    pub const fn side(&self) -> ProviderReportedCtfV2Side {
        self.side
    }
    #[must_use]
    pub const fn gross_making(&self) -> U256 {
        self.gross_making
    }
    #[must_use]
    pub const fn gross_taking(&self) -> U256 {
        self.gross_taking
    }
    #[must_use]
    pub const fn fee(&self) -> U256 {
        self.fee
    }
    #[must_use]
    pub const fn role(&self) -> ProviderReportedCtfV2OrderRole {
        self.role
    }
}

/// Opaque provider-reported flow projection. It is not a receipt proof or a
/// source/runtime identity claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderReportedCtfV2Settlement {
    chain_id: u64,
    owner: Address,
    block_number: u64,
    block_hash: String,
    transaction_hash: String,
    transaction_index: u64,
    collateral_address: Address,
    ctf_address: Address,
    context_source: RpcCurrentCtfV2ContextSource,
    implementation_version: RpcCurrentCtfV2ImplementationVersion,
    wallet_legs: Vec<ProviderReportedCtfV2WalletLeg>,
    owner_fills: Vec<ProviderReportedCtfV2OwnerFill>,
}

impl ProviderReportedCtfV2Settlement {
    #[must_use]
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }
    #[must_use]
    pub const fn owner(&self) -> Address {
        self.owner
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
    pub const fn collateral_address(&self) -> Address {
        self.collateral_address
    }
    #[must_use]
    pub const fn ctf_address(&self) -> Address {
        self.ctf_address
    }
    #[must_use]
    pub const fn context_source(&self) -> RpcCurrentCtfV2ContextSource {
        self.context_source
    }
    #[must_use]
    pub const fn implementation_version(&self) -> RpcCurrentCtfV2ImplementationVersion {
        self.implementation_version
    }
    #[must_use]
    pub fn wallet_legs(&self) -> &[ProviderReportedCtfV2WalletLeg] {
        &self.wallet_legs
    }
    #[must_use]
    pub fn owner_fills(&self) -> &[ProviderReportedCtfV2OwnerFill] {
        &self.owner_fills
    }
}

#[derive(Debug)]
struct V2MatchOrdersCall {
    condition_id: B256,
    active: FifthMatchOrder,
    makers: Vec<FifthMatchOrder>,
    active_fill: U256,
    maker_fills: Vec<U256>,
    active_fee: U256,
    maker_fees: Vec<U256>,
}

#[derive(Debug)]
struct FillEvent {
    hash: B256,
    maker: Address,
    taker: Address,
    side: ProviderReportedCtfV2Side,
    token_id: U256,
    making: U256,
    taking: U256,
    fee: U256,
    builder: B256,
    metadata: B256,
}

#[derive(Debug)]
enum Expected {
    Position {
        from: Address,
        to: Address,
        id: U256,
        amount: U256,
    },
    Cash {
        from: Address,
        to: Address,
        amount: U256,
    },
    Fee {
        receiver: Address,
        amount: U256,
    },
    Fill(FillEvent),
    Matched {
        hash: B256,
        taker: Address,
        side: ProviderReportedCtfV2Side,
        id: U256,
        making: U256,
        taking: U256,
    },
}

/// Selects only standard e111 V2 matchOrders transactions for bounded current
/// context reads. The complete decoder independently validates every field.
pub fn provider_reported_ctf_v2_settlement_context_candidate(
    transaction: &Value,
) -> Option<(u64, String)> {
    if !field(transaction, "to")
        .ok()?
        .eq_ignore_ascii_case(EXCHANGE)
    {
        return None;
    }
    let input = transaction.get("input")?.as_str()?.strip_prefix("0x")?;
    if input.len() > 2 * 256 * 1024 {
        return None;
    }
    let bytes = hex::decode(input).ok()?;
    if bytes.get(..4)? != MATCH_SELECTOR {
        return None;
    }
    let block_number = parse_hex_u64(field(transaction, "blockNumber").ok()?).ok()?;
    let block_hash = validate_hex(field(transaction, "blockHash").ok()?, 32).ok()?;
    Some((block_number, block_hash))
}

pub fn decode_provider_reported_ctf_v2_complementary_settlement(
    transaction: &Value,
    receipt: &Value,
    owner: &str,
    context: &RpcCurrentCtfV2Context,
) -> Result<ProviderReportedCtfV2Settlement, ProviderReportedCtfV2SettlementError> {
    let owner = validate_hex(owner, 20)
        .map_err(|_| ProviderReportedCtfV2SettlementError::MalformedTransaction)?;
    let owner = Address::from_str(&owner)
        .map_err(|_| ProviderReportedCtfV2SettlementError::MalformedTransaction)?;
    if owner == Address::ZERO
        || owner == Address::from_str(EXCHANGE).unwrap_or(Address::ZERO)
        || context.source() != RpcCurrentCtfV2ContextSource::ProviderReported
        || context.implementation_version() != RpcCurrentCtfV2ImplementationVersion::Unbound
    {
        return Err(ProviderReportedCtfV2SettlementError::SettlementMismatch);
    }
    let bound = bind_provider_transaction(transaction, receipt).map_err(|error| match error {
        ProviderTransactionBindingError::Transaction => {
            ProviderReportedCtfV2SettlementError::MalformedTransaction
        }
        ProviderTransactionBindingError::Receipt => {
            ProviderReportedCtfV2SettlementError::MalformedReceipt
        }
    })?;
    if bound.block_number != context.block_number()
        || bound.block_hash != context.block_hash()
        || bound.to != EXCHANGE
        || !bound.input.starts_with(&MATCH_SELECTOR)
        || !bound.value.is_zero()
    {
        return Err(ProviderReportedCtfV2SettlementError::SettlementMismatch);
    }
    let call = decode_v2_match_orders(&bound.input)
        .ok_or(ProviderReportedCtfV2SettlementError::MalformedTransaction)?;
    let expected = build_complementary_expectations(&call, owner)
        .ok_or(ProviderReportedCtfV2SettlementError::SettlementMismatch)?;
    let expected = bind_fee_receiver(expected, &bound.logs)
        .ok_or(ProviderReportedCtfV2SettlementError::SettlementMismatch)?;
    if !match_ordered_logs(&expected, &bound.logs, |expected, actual| {
        expected_matches(expected, actual, context)
    }) {
        return Err(ProviderReportedCtfV2SettlementError::SettlementMismatch);
    }
    let owner_fills = expected
        .iter()
        .zip(&bound.logs)
        .filter_map(|(expected, log)| match expected {
            Expected::Fill(fill)
                if fill.maker == owner && fill.taker != Address::from_str(EXCHANGE).ok()? =>
            {
                Some(ProviderReportedCtfV2OwnerFill {
                    log_index: log.log_index,
                    token_id: fill.token_id,
                    side: fill.side,
                    gross_making: fill.making,
                    gross_taking: fill.taking,
                    fee: fill.fee,
                    role: ProviderReportedCtfV2OrderRole::Maker,
                })
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let owner_fills = add_active_owner_fill(owner_fills, &expected, &bound.logs, owner);
    if owner_fills.is_empty() {
        return Err(ProviderReportedCtfV2SettlementError::SettlementMismatch);
    }
    let collateral = Address::from_str(context.collateral_address())
        .map_err(|_| ProviderReportedCtfV2SettlementError::SettlementMismatch)?;
    let ctf = Address::from_str(context.ctf_address())
        .map_err(|_| ProviderReportedCtfV2SettlementError::SettlementMismatch)?;
    let wallet_legs = expected
        .iter()
        .zip(&bound.logs)
        .filter_map(|(expected, log)| {
            let (asset, from, to, amount, token_id) = match expected {
                Expected::Cash { from, to, amount } => (collateral, *from, *to, *amount, None),
                Expected::Position {
                    from,
                    to,
                    id,
                    amount,
                } => (ctf, *from, *to, *amount, Some(*id)),
                _ => return None,
            };
            if from != owner && to != owner {
                return None;
            }
            Some(ProviderReportedCtfV2WalletLeg {
                log_index: log.log_index,
                asset_address: asset,
                from,
                to,
                direction: if to == owner {
                    ProviderReportedCtfV2Direction::Inflow
                } else {
                    ProviderReportedCtfV2Direction::Outflow
                },
                amount,
                token_id,
            })
        })
        .collect();
    Ok(ProviderReportedCtfV2Settlement {
        chain_id: 137,
        owner,
        block_number: bound.block_number,
        block_hash: bound.block_hash,
        transaction_hash: bound.transaction_hash,
        transaction_index: bound.transaction_index,
        collateral_address: collateral,
        ctf_address: ctf,
        context_source: context.source(),
        implementation_version: context.implementation_version(),
        wallet_legs,
        owner_fills,
    })
}

fn decode_v2_match_orders(input: &[u8]) -> Option<V2MatchOrdersCall> {
    if input.len() < 4 + 7 * 32 || input.len() > 256 * 1024 || input.get(..4)? != MATCH_SELECTOR {
        return None;
    }
    let args = input.get(4..)?;
    if args.len() % 32 != 0 {
        return None;
    }
    let condition_id = B256::from_slice(args.get(..32)?);
    let active_offset = abi_usize(abi_u256_word(args, 32)?)?;
    let makers_offset = abi_usize(abi_u256_word(args, 64)?)?;
    let active_fill = abi_u256_word(args, 96)?;
    let maker_fills_offset = abi_usize(abi_u256_word(args, 128)?)?;
    let active_fee = abi_u256_word(args, 160)?;
    let maker_fees_offset = abi_usize(abi_u256_word(args, 192)?)?;
    if active_offset != 7 * 32 {
        return None;
    }
    let (active, active_end) = decode_order_tuple(args, active_offset)?;
    if makers_offset != active_end {
        return None;
    }
    let (makers, makers_end) = decode_v2_order_array(args, makers_offset)?;
    if maker_fills_offset != makers_end {
        return None;
    }
    let (maker_fills, fills_end) = decode_u256_array(args, maker_fills_offset, makers.len())?;
    if maker_fees_offset != fills_end {
        return None;
    }
    let (maker_fees, end) = decode_u256_array(args, maker_fees_offset, makers.len())?;
    if end != args.len() {
        return None;
    }
    Some(V2MatchOrdersCall {
        condition_id,
        active,
        makers,
        active_fill,
        maker_fills,
        active_fee,
        maker_fees,
    })
}

fn decode_v2_order_array(args: &[u8], start: usize) -> Option<(Vec<FifthMatchOrder>, usize)> {
    let count = abi_usize(abi_u256_word(args, start)?)?;
    if !(1..=FIFTH_MATCH_ORDERS_MAX_MAKERS).contains(&count) {
        return None;
    }
    let head_start = start.checked_add(32)?;
    let head_end = head_start.checked_add(count.checked_mul(32)?)?;
    if head_end > args.len() {
        return None;
    }
    let mut cursor = head_end;
    let mut orders = Vec::with_capacity(count);
    for index in 0..count {
        let head = head_start.checked_add(index.checked_mul(32)?)?;
        if abi_usize(abi_u256_word(args, head)?)? != cursor.checked_sub(head_start)? {
            return None;
        }
        let (order, end) = decode_order_tuple(args, cursor)?;
        if order.signature.len() > FIFTH_MATCH_ORDERS_MAX_SIGNATURE_BYTES {
            return None;
        }
        orders.push(order);
        cursor = end;
    }
    Some((orders, cursor))
}

fn decode_u256_array(args: &[u8], start: usize, expected: usize) -> Option<(Vec<U256>, usize)> {
    let count = abi_usize(abi_u256_word(args, start)?)?;
    if count != expected || count > FIFTH_MATCH_ORDERS_MAX_MAKERS {
        return None;
    }
    let begin = start.checked_add(32)?;
    let end = begin.checked_add(count.checked_mul(32)?)?;
    if end > args.len() {
        return None;
    }
    let values = (0..count)
        .map(|index| abi_u256_word(args, begin.checked_add(index.checked_mul(32)?)?))
        .collect::<Option<Vec<_>>>()?;
    Some((values, end))
}

fn build_complementary_expectations(
    call: &V2MatchOrdersCall,
    owner: Address,
) -> Option<Vec<Expected>> {
    let active = &call.active;
    if call.condition_id == B256::ZERO
        || active.maker == Address::ZERO
        || active.token_id.is_zero()
        || call.active_fill.is_zero()
        || call.active_fill > active.maker_amount
        || active.maker_amount.is_zero()
        || active.taker_amount.is_zero()
        || call.makers.len() != call.maker_fills.len()
        || call.makers.len() != call.maker_fees.len()
        || call.makers.iter().any(|maker| {
            maker.side == active.side
                || maker.token_id != active.token_id
                || maker.maker == active.maker
        })
        || call.makers.iter().any(|maker| {
            maker.maker == Address::ZERO || maker.maker == owner && active.maker == owner
        })
    {
        return None;
    }
    let exchange = Address::from_str(EXCHANGE).ok()?;
    let active_hash = v2_order_hash(active, exchange);
    let mut expected = Vec::new();
    let mut active_making = U256::ZERO;
    let mut active_taking = U256::ZERO;
    let mut owner_orders = 0;
    let mut total_fees = call.active_fee;
    for ((maker, maker_fill), maker_fee) in call
        .makers
        .iter()
        .zip(&call.maker_fills)
        .zip(&call.maker_fees)
    {
        if maker.maker == exchange
            || maker.maker_amount.is_zero()
            || maker.taker_amount.is_zero()
            || maker_fill.is_zero()
            || *maker_fill > maker.maker_amount
        {
            return None;
        }
        let taking = maker_fill
            .checked_mul(maker.taker_amount)?
            .checked_div(maker.maker_amount)?;
        if taking.is_zero() {
            return None;
        }
        let (maker_making, maker_taking, active_making_part, active_taking_part) =
            (*maker_fill, taking, taking, *maker_fill);
        let maker_cash = if maker.side == FifthOrderSide::Buy {
            maker_making
        } else {
            maker_taking
        };
        if *maker_fee > maker_cash {
            return None;
        }
        total_fees = total_fees.checked_add(*maker_fee)?;
        active_making = active_making.checked_add(active_making_part)?;
        active_taking = active_taking.checked_add(active_taking_part)?;
        let maker_hash = v2_order_hash(maker, exchange);
        if maker.maker == owner {
            owner_orders += 1;
        }
        let (position_from, position_to, cash_from, cash_to) = if active.side == FifthOrderSide::Buy
        {
            (maker.maker, active.maker, active.maker, maker.maker)
        } else {
            (active.maker, maker.maker, maker.maker, exchange)
        };
        expected.push(Expected::Position {
            from: position_from,
            to: position_to,
            id: active.token_id,
            amount: if active.side == FifthOrderSide::Buy {
                maker_making
            } else {
                maker_taking
            },
        });
        let maker_cash_after_fee = maker_cash.checked_sub(*maker_fee)?;
        let cash_amount = if active.side == FifthOrderSide::Buy {
            maker_cash_after_fee
        } else {
            maker_cash.checked_add(*maker_fee)?
        };
        expected.push(Expected::Cash {
            from: cash_from,
            to: cash_to,
            amount: cash_amount,
        });
        if !maker_fee.is_zero() {
            expected.push(Expected::Fee {
                receiver: Address::ZERO,
                amount: *maker_fee,
            });
        }
        expected.push(Expected::Fill(FillEvent {
            hash: maker_hash,
            maker: maker.maker,
            taker: active.maker,
            side: side(maker.side),
            token_id: maker.token_id,
            making: maker_making,
            taking: maker_taking,
            fee: *maker_fee,
            builder: maker.builder,
            metadata: maker.metadata,
        }));
    }
    if owner_orders > 1 || active.maker == owner && owner_orders > 0 {
        return None;
    }
    if active_making > call.active_fill {
        return None;
    }
    let active_minimum_taking = active_making
        .checked_mul(active.taker_amount)?
        .checked_div(active.maker_amount)?;
    if active_taking < active_minimum_taking {
        return None;
    }
    if active_taking > active.taker_amount {
        return None;
    }
    if call.active_fee
        > if active.side == FifthOrderSide::Buy {
            active_making
        } else {
            active_taking
        }
    {
        return None;
    }
    if !call.active_fee.is_zero() {
        expected.push(Expected::Fee {
            receiver: Address::ZERO,
            amount: call.active_fee,
        });
    }
    if active.side == FifthOrderSide::Sell {
        expected.push(Expected::Cash {
            from: exchange,
            to: active.maker,
            amount: active_taking.checked_sub(call.active_fee)?,
        });
    }
    expected.push(Expected::Fill(FillEvent {
        hash: active_hash,
        maker: active.maker,
        taker: exchange,
        side: side(active.side),
        token_id: active.token_id,
        making: active_making,
        taking: active_taking,
        fee: call.active_fee,
        builder: active.builder,
        metadata: active.metadata,
    }));
    expected.push(Expected::Matched {
        hash: active_hash,
        taker: active.maker,
        side: side(active.side),
        id: active.token_id,
        making: active_making,
        taking: active_taking,
    });
    if !total_fees.is_zero() {
        expected.push(Expected::Cash {
            from: if active.side == FifthOrderSide::Buy {
                active.maker
            } else {
                exchange
            },
            to: Address::ZERO,
            amount: total_fees,
        });
    }
    Some(expected)
}

fn bind_fee_receiver(
    mut expected: Vec<Expected>,
    logs: &[ProviderTransactionLog],
) -> Option<Vec<Expected>> {
    let fee_topic = topic_hash(FEE_CHARGED_SIGNATURE);
    let receivers = logs
        .iter()
        .filter(|log| {
            log.address.eq_ignore_ascii_case(EXCHANGE)
                && log
                    .topics
                    .first()
                    .is_some_and(|topic| topic.eq_ignore_ascii_case(&fee_topic))
        })
        .map(|log| topic_address(log.topics.get(1)?))
        .collect::<Option<Vec<_>>>()?;
    let needs_receiver = expected
        .iter()
        .any(|entry| matches!(entry, Expected::Fee { .. }));
    let receiver = if needs_receiver {
        let first = *receivers.first()?;
        if receivers.iter().any(|item| *item != first) {
            return None;
        }
        Some(first)
    } else if !receivers.is_empty() {
        return None;
    } else {
        None
    };
    for entry in &mut expected {
        match entry {
            Expected::Fee {
                receiver: expected_receiver,
                ..
            } => *expected_receiver = receiver?,
            Expected::Cash { to, .. } if *to == Address::ZERO => *to = receiver?,
            _ => {}
        }
    }
    Some(expected)
}

fn expected_matches(
    expected: &Expected,
    actual: &ProviderTransactionLog,
    context: &RpcCurrentCtfV2Context,
) -> bool {
    let topic = actual
        .topics
        .first()
        .map(String::as_str)
        .unwrap_or_default();
    match expected {
        Expected::Cash { from, to, amount } => {
            actual
                .address
                .eq_ignore_ascii_case(context.collateral_address())
                && topic.eq_ignore_ascii_case(&topic_hash(TRANSFER_SIGNATURE))
                && actual.topics.len() == 3
                && topic_address(&actual.topics[1]) == Some(*from)
                && topic_address(&actual.topics[2]) == Some(*to)
                && data_word(&actual.data, 0) == Some(*amount)
                && actual.data.len() == 66
        }
        Expected::Position {
            from,
            to,
            id,
            amount,
        } => {
            actual.address.eq_ignore_ascii_case(context.ctf_address())
                && topic.eq_ignore_ascii_case(&topic_hash(TRANSFER_SINGLE_SIGNATURE))
                && actual.topics.len() == 4
                && topic_address(&actual.topics[1]) == Address::from_str(EXCHANGE).ok()
                && topic_address(&actual.topics[2]) == Some(*from)
                && topic_address(&actual.topics[3]) == Some(*to)
                && data_word(&actual.data, 0) == Some(*id)
                && data_word(&actual.data, 32) == Some(*amount)
                && actual.data.len() == 130
        }
        Expected::Fee { receiver, amount } => {
            actual.address.eq_ignore_ascii_case(EXCHANGE)
                && topic.eq_ignore_ascii_case(&topic_hash(FEE_CHARGED_SIGNATURE))
                && actual.topics.len() == 2
                && actual.data.len() == 66
                && topic_address(&actual.topics[1]) == Some(*receiver)
                && data_word(&actual.data, 0) == Some(*amount)
        }
        Expected::Fill(fill) => {
            actual.address.eq_ignore_ascii_case(EXCHANGE)
                && topic.eq_ignore_ascii_case(&topic_hash(ORDER_FILLED_SIGNATURE))
                && actual.topics.len() == 4
                && actual.topics[1].eq_ignore_ascii_case(&format!("{:#x}", fill.hash))
                && topic_address(&actual.topics[2]) == Some(fill.maker)
                && topic_address(&actual.topics[3]) == Some(fill.taker)
                && actual.data.len() == 450
                && data_word(&actual.data, 0) == Some(U256::from(side_word(fill.side)))
                && data_word(&actual.data, 32) == Some(fill.token_id)
                && data_word(&actual.data, 64) == Some(fill.making)
                && data_word(&actual.data, 96) == Some(fill.taking)
                && data_word(&actual.data, 128) == Some(fill.fee)
                && data_word(&actual.data, 160) == Some(U256::from_be_bytes(fill.builder.0))
                && data_word(&actual.data, 192) == Some(U256::from_be_bytes(fill.metadata.0))
        }
        Expected::Matched {
            hash,
            taker,
            side,
            id,
            making,
            taking,
        } => {
            actual.address.eq_ignore_ascii_case(EXCHANGE)
                && topic.eq_ignore_ascii_case(&topic_hash(ORDERS_MATCHED_SIGNATURE))
                && actual.topics.len() == 3
                && actual.data.len() == 258
                && actual.topics[1].eq_ignore_ascii_case(&format!("{hash:#x}"))
                && topic_address(&actual.topics[2]) == Some(*taker)
                && data_word(&actual.data, 0) == Some(U256::from(side_word(*side)))
                && data_word(&actual.data, 32) == Some(*id)
                && data_word(&actual.data, 64) == Some(*making)
                && data_word(&actual.data, 96) == Some(*taking)
        }
    }
}

fn add_active_owner_fill(
    mut fills: Vec<ProviderReportedCtfV2OwnerFill>,
    expected: &[Expected],
    logs: &[ProviderTransactionLog],
    owner: Address,
) -> Vec<ProviderReportedCtfV2OwnerFill> {
    for (expected, log) in expected.iter().zip(logs) {
        if let Expected::Fill(fill) = expected {
            if fill.taker == Address::from_str(EXCHANGE).unwrap_or(Address::ZERO)
                && fill.maker == owner
            {
                fills.push(ProviderReportedCtfV2OwnerFill {
                    log_index: log.log_index,
                    token_id: fill.token_id,
                    side: fill.side,
                    gross_making: fill.making,
                    gross_taking: fill.taking,
                    fee: fill.fee,
                    role: ProviderReportedCtfV2OrderRole::Active,
                });
            }
        }
    }
    fills
}

fn v2_order_hash(order: &FifthMatchOrder, exchange: Address) -> B256 {
    let domain_typehash = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let name_hash = keccak256(b"Polymarket CTF Exchange");
    let version_hash = keccak256(b"2");
    let mut domain = Vec::with_capacity(160);
    domain.extend_from_slice(domain_typehash.as_slice());
    domain.extend_from_slice(name_hash.as_slice());
    domain.extend_from_slice(version_hash.as_slice());
    domain.extend_from_slice(&U256::from(137).to_be_bytes::<32>());
    domain.extend_from_slice(&[0; 12]);
    domain.extend_from_slice(exchange.as_slice());
    let separator = keccak256(&domain);
    let struct_hash = fifth_order_struct_hash(order);
    let mut typed = Vec::with_capacity(66);
    typed.extend_from_slice(&[0x19, 0x01]);
    typed.extend_from_slice(separator.as_slice());
    typed.extend_from_slice(struct_hash.as_slice());
    keccak256(&typed)
}

fn side(side: FifthOrderSide) -> ProviderReportedCtfV2Side {
    match side {
        FifthOrderSide::Buy => ProviderReportedCtfV2Side::Buy,
        FifthOrderSide::Sell => ProviderReportedCtfV2Side::Sell,
    }
}
fn side_word(side: ProviderReportedCtfV2Side) -> u8 {
    match side {
        ProviderReportedCtfV2Side::Buy => 0,
        ProviderReportedCtfV2Side::Sell => 1,
    }
}
fn topic_hash(signature: &str) -> String {
    format!("0x{}", hex::encode(Keccak256::digest(signature.as_bytes())))
}
fn topic_address(topic: &str) -> Option<Address> {
    let bytes = hex::decode(topic.strip_prefix("0x")?).ok()?;
    if bytes.len() != 32 || bytes[..12].iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(Address::from_slice(&bytes[12..]))
}
fn data_word(data: &str, offset: usize) -> Option<U256> {
    let raw = hex::decode(data.strip_prefix("0x")?).ok()?;
    let word = raw.get(offset..offset.checked_add(32)?)?;
    Some(U256::from_be_slice(word))
}
fn keccak256(bytes: &[u8]) -> B256 {
    B256::from_slice(&Keccak256::digest(bytes))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        collateral_cash::PUSD_ADDRESS, position_history::CTF_EMITTER,
        rpc_position_history::ctf_v2_context::test_ctf_v2_context,
    };
    use serde_json::json;

    fn fixture() -> (Value, Value, String, RpcCurrentCtfV2Context) {
        let owner = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let maker_a = Address::from_str("0x2222222222222222222222222222222222222222").unwrap();
        let maker_b = Address::from_str("0x3333333333333333333333333333333333333333").unwrap();
        let fee_receiver = Address::from_str("0x4444444444444444444444444444444444444444").unwrap();
        let id = U256::from(42);
        let active = order(
            owner,
            id,
            U256::from(1_000),
            U256::from(500),
            FifthOrderSide::Buy,
            0xaa,
            0xbb,
        );
        let maker_order_a = order(
            maker_a,
            id,
            U256::from(500),
            U256::from(1_000),
            FifthOrderSide::Sell,
            0xcc,
            0xdd,
        );
        let maker_order_b = order(
            maker_b,
            id,
            U256::from(500),
            U256::from(1_000),
            FifthOrderSide::Sell,
            0xee,
            0xff,
        );
        let input = encode_v2_call(
            &active,
            &[maker_order_a.clone(), maker_order_b.clone()],
            U256::from(200),
            &[U256::from(50), U256::from(50)],
            U256::from(3),
            &[U256::from(5), U256::from(7)],
        );
        let (mut transaction, _) = super::super::receipt_tests::signed_polygon_transaction_with_key(
            EXCHANGE, &input, 0x43,
        );
        let encoded =
            super::super::encode_signed_transaction_with_sender_recovery(&transaction, true)
                .unwrap();
        let hash = format!("{:#x}", encoded.hash);
        let block_hash = format!("0x{}", "aa".repeat(32));
        transaction["hash"] = json!(hash);
        transaction["blockNumber"] = json!("0x64");
        transaction["blockHash"] = json!(block_hash);
        transaction["transactionIndex"] = json!("0x3");

        let exchange = Address::from_str(EXCHANGE).unwrap();
        let maker_hash_a = v2_order_hash(&maker_order_a, exchange);
        let maker_hash_b = v2_order_hash(&maker_order_b, exchange);
        let active_hash = v2_order_hash(&active, exchange);
        let logs = vec![
            log(
                CTF_EMITTER,
                vec![
                    topic_hash(TRANSFER_SINGLE_SIGNATURE),
                    topic_address(exchange),
                    topic_address(maker_a),
                    topic_address(owner),
                ],
                data(&[id, U256::from(50)]),
            ),
            log(
                PUSD_ADDRESS,
                vec![
                    topic_hash(TRANSFER_SIGNATURE),
                    topic_address(owner),
                    topic_address(maker_a),
                ],
                data(&[U256::from(95)]),
            ),
            log(
                EXCHANGE,
                vec![
                    topic_hash(FEE_CHARGED_SIGNATURE),
                    topic_address(fee_receiver),
                ],
                data(&[U256::from(5)]),
            ),
            log(
                EXCHANGE,
                fill_topics(maker_hash_a, maker_a, owner),
                data(&[
                    U256::ONE,
                    id,
                    U256::from(50),
                    U256::from(100),
                    U256::from(5),
                    U256::from_be_bytes(maker_order_a.builder.0),
                    U256::from_be_bytes(maker_order_a.metadata.0),
                ]),
            ),
            log(
                CTF_EMITTER,
                vec![
                    topic_hash(TRANSFER_SINGLE_SIGNATURE),
                    topic_address(exchange),
                    topic_address(maker_b),
                    topic_address(owner),
                ],
                data(&[id, U256::from(50)]),
            ),
            log(
                PUSD_ADDRESS,
                vec![
                    topic_hash(TRANSFER_SIGNATURE),
                    topic_address(owner),
                    topic_address(maker_b),
                ],
                data(&[U256::from(93)]),
            ),
            log(
                EXCHANGE,
                vec![
                    topic_hash(FEE_CHARGED_SIGNATURE),
                    topic_address(fee_receiver),
                ],
                data(&[U256::from(7)]),
            ),
            log(
                EXCHANGE,
                fill_topics(maker_hash_b, maker_b, owner),
                data(&[
                    U256::ONE,
                    id,
                    U256::from(50),
                    U256::from(100),
                    U256::from(7),
                    U256::from_be_bytes(maker_order_b.builder.0),
                    U256::from_be_bytes(maker_order_b.metadata.0),
                ]),
            ),
            log(
                EXCHANGE,
                vec![
                    topic_hash(FEE_CHARGED_SIGNATURE),
                    topic_address(fee_receiver),
                ],
                data(&[U256::from(3)]),
            ),
            log(
                EXCHANGE,
                fill_topics(active_hash, owner, exchange),
                data(&[
                    U256::ZERO,
                    id,
                    U256::from(200),
                    U256::from(100),
                    U256::from(3),
                    U256::from_be_bytes(active.builder.0),
                    U256::from_be_bytes(active.metadata.0),
                ]),
            ),
            log(
                EXCHANGE,
                vec![
                    topic_hash(ORDERS_MATCHED_SIGNATURE),
                    format!("{active_hash:#x}"),
                    topic_address(owner),
                ],
                data(&[U256::ZERO, id, U256::from(200), U256::from(100)]),
            ),
            log(
                PUSD_ADDRESS,
                vec![
                    topic_hash(TRANSFER_SIGNATURE),
                    topic_address(owner),
                    topic_address(fee_receiver),
                ],
                data(&[U256::from(15)]),
            ),
        ];
        let receipt_logs = logs
            .iter()
            .enumerate()
            .map(|(index, log)| {
                json!({
                    "address":log["address"], "topics":log["topics"], "data":log["data"],
                    "blockNumber":"0x64", "blockHash":block_hash, "transactionHash":hash,
                    "transactionIndex":"0x3", "logIndex":format!("0x{index:x}"), "removed":false,
                })
            })
            .collect::<Vec<_>>();
        let receipt = json!({"transactionHash":hash,"blockNumber":"0x64","blockHash":block_hash,"transactionIndex":"0x3","status":"0x1","type":"0x0","logs":receipt_logs});
        let context = test_ctf_v2_context(100, &block_hash);
        (transaction, receipt, format!("{owner:#x}"), context)
    }

    fn sell_fixture() -> (Value, Value, String, RpcCurrentCtfV2Context) {
        let owner = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let maker_a = Address::from_str("0x2222222222222222222222222222222222222222").unwrap();
        let maker_b = Address::from_str("0x3333333333333333333333333333333333333333").unwrap();
        let receiver = Address::from_str("0x4444444444444444444444444444444444444444").unwrap();
        let id = U256::from(42);
        let active = order(
            owner,
            id,
            U256::from(200),
            U256::from(200),
            FifthOrderSide::Sell,
            0xaa,
            0xbb,
        );
        let maker_a_order = order(
            maker_a,
            id,
            U256::from(1_000),
            U256::from(1_000),
            FifthOrderSide::Buy,
            0xcc,
            0xdd,
        );
        let maker_b_order = order(
            maker_b,
            id,
            U256::from(1_000),
            U256::from(1_000),
            FifthOrderSide::Buy,
            0xee,
            0xff,
        );
        let input = encode_v2_call(
            &active,
            &[maker_a_order.clone(), maker_b_order.clone()],
            U256::from(200),
            &[U256::from(100), U256::from(100)],
            U256::from(3),
            &[U256::from(5), U256::from(7)],
        );
        let (mut transaction, _) = super::super::receipt_tests::signed_polygon_transaction_with_key(
            EXCHANGE, &input, 0x43,
        );
        let encoded =
            super::super::encode_signed_transaction_with_sender_recovery(&transaction, true)
                .unwrap();
        let hash = format!("{:#x}", encoded.hash);
        let block_hash = format!("0x{}", "aa".repeat(32));
        transaction["hash"] = json!(hash);
        transaction["blockNumber"] = json!("0x64");
        transaction["blockHash"] = json!(block_hash);
        transaction["transactionIndex"] = json!("0x3");
        let exchange = Address::from_str(EXCHANGE).unwrap();
        let active_hash = v2_order_hash(&active, exchange);
        let maker_a_hash = v2_order_hash(&maker_a_order, exchange);
        let maker_b_hash = v2_order_hash(&maker_b_order, exchange);
        let logs = vec![
            log(
                CTF_EMITTER,
                vec![
                    topic_hash(TRANSFER_SINGLE_SIGNATURE),
                    topic_address(exchange),
                    topic_address(owner),
                    topic_address(maker_a),
                ],
                data(&[id, U256::from(100)]),
            ),
            log(
                PUSD_ADDRESS,
                vec![
                    topic_hash(TRANSFER_SIGNATURE),
                    topic_address(maker_a),
                    topic_address(exchange),
                ],
                data(&[U256::from(105)]),
            ),
            log(
                EXCHANGE,
                vec![topic_hash(FEE_CHARGED_SIGNATURE), topic_address(receiver)],
                data(&[U256::from(5)]),
            ),
            log(
                EXCHANGE,
                fill_topics(maker_a_hash, maker_a, owner),
                data(&[
                    U256::ZERO,
                    id,
                    U256::from(100),
                    U256::from(100),
                    U256::from(5),
                    U256::from_be_bytes(maker_a_order.builder.0),
                    U256::from_be_bytes(maker_a_order.metadata.0),
                ]),
            ),
            log(
                CTF_EMITTER,
                vec![
                    topic_hash(TRANSFER_SINGLE_SIGNATURE),
                    topic_address(exchange),
                    topic_address(owner),
                    topic_address(maker_b),
                ],
                data(&[id, U256::from(100)]),
            ),
            log(
                PUSD_ADDRESS,
                vec![
                    topic_hash(TRANSFER_SIGNATURE),
                    topic_address(maker_b),
                    topic_address(exchange),
                ],
                data(&[U256::from(107)]),
            ),
            log(
                EXCHANGE,
                vec![topic_hash(FEE_CHARGED_SIGNATURE), topic_address(receiver)],
                data(&[U256::from(7)]),
            ),
            log(
                EXCHANGE,
                fill_topics(maker_b_hash, maker_b, owner),
                data(&[
                    U256::ZERO,
                    id,
                    U256::from(100),
                    U256::from(100),
                    U256::from(7),
                    U256::from_be_bytes(maker_b_order.builder.0),
                    U256::from_be_bytes(maker_b_order.metadata.0),
                ]),
            ),
            log(
                EXCHANGE,
                vec![topic_hash(FEE_CHARGED_SIGNATURE), topic_address(receiver)],
                data(&[U256::from(3)]),
            ),
            log(
                PUSD_ADDRESS,
                vec![
                    topic_hash(TRANSFER_SIGNATURE),
                    topic_address(exchange),
                    topic_address(owner),
                ],
                data(&[U256::from(197)]),
            ),
            log(
                EXCHANGE,
                fill_topics(active_hash, owner, exchange),
                data(&[
                    U256::ONE,
                    id,
                    U256::from(200),
                    U256::from(200),
                    U256::from(3),
                    U256::from_be_bytes(active.builder.0),
                    U256::from_be_bytes(active.metadata.0),
                ]),
            ),
            log(
                EXCHANGE,
                vec![
                    topic_hash(ORDERS_MATCHED_SIGNATURE),
                    format!("{active_hash:#x}"),
                    topic_address(owner),
                ],
                data(&[U256::ONE, id, U256::from(200), U256::from(200)]),
            ),
            log(
                PUSD_ADDRESS,
                vec![
                    topic_hash(TRANSFER_SIGNATURE),
                    topic_address(exchange),
                    topic_address(receiver),
                ],
                data(&[U256::from(15)]),
            ),
        ];
        let receipt_logs = logs
            .iter()
            .enumerate()
            .map(|(index, log)| {
                json!({
                    "address":log["address"], "topics":log["topics"], "data":log["data"],
                    "blockNumber":"0x64", "blockHash":block_hash, "transactionHash":hash,
                    "transactionIndex":"0x3", "logIndex":format!("0x{index:x}"), "removed":false,
                })
            })
            .collect::<Vec<_>>();
        let receipt = json!({"transactionHash":hash,"blockNumber":"0x64","blockHash":block_hash,"transactionIndex":"0x3","status":"0x1","type":"0x0","logs":receipt_logs});
        let context = test_ctf_v2_context(100, &block_hash);
        (transaction, receipt, format!("{owner:#x}"), context)
    }

    fn order(
        maker: Address,
        token_id: U256,
        maker_amount: U256,
        taker_amount: U256,
        side: FifthOrderSide,
        metadata: u8,
        builder: u8,
    ) -> FifthMatchOrder {
        FifthMatchOrder {
            salt: U256::from(metadata),
            maker,
            signer: maker,
            token_id,
            maker_amount,
            taker_amount,
            side,
            signature_type: super::super::fifth_match_orders_call::FifthOrderSignatureType::Eoa,
            timestamp: U256::ONE,
            metadata: B256::repeat_byte(metadata),
            builder: B256::repeat_byte(builder),
            signature: vec![1],
        }
    }

    fn encode_v2_call(
        active: &FifthMatchOrder,
        makers: &[FifthMatchOrder],
        active_fill: U256,
        maker_fills: &[U256],
        active_fee: U256,
        maker_fees: &[U256],
    ) -> Vec<u8> {
        let active_tail = encode_order(active);
        let maker_tails = makers.iter().map(encode_order).collect::<Vec<_>>();
        let mut maker_array = word(U256::from(maker_tails.len())).to_vec();
        let mut relative = maker_tails.len() * 32;
        for tail in &maker_tails {
            maker_array.extend_from_slice(&word(U256::from(relative)));
            relative += tail.len();
        }
        for tail in maker_tails {
            maker_array.extend_from_slice(&tail);
        }
        let fills = encode_u256_array(maker_fills);
        let fees = encode_u256_array(maker_fees);
        let active_offset = 7 * 32;
        let makers_offset = active_offset + active_tail.len();
        let fills_offset = makers_offset + maker_array.len();
        let fees_offset = fills_offset + fills.len();
        // Canonical V2 head order is condition, active, makers, taker fill,
        // maker fills, taker fee, maker fees.
        let mut head = Vec::new();
        head.extend_from_slice(B256::repeat_byte(0x77).as_slice());
        for value in [active_offset, makers_offset] {
            head.extend_from_slice(&word(U256::from(value)));
        }
        head.extend_from_slice(&word(active_fill));
        head.extend_from_slice(&word(U256::from(fills_offset)));
        head.extend_from_slice(&word(active_fee));
        head.extend_from_slice(&word(U256::from(fees_offset)));
        let mut input = MATCH_SELECTOR.to_vec();
        input.extend_from_slice(&head);
        input.extend_from_slice(&active_tail);
        input.extend_from_slice(&maker_array);
        input.extend_from_slice(&fills);
        input.extend_from_slice(&fees);
        input
    }

    fn encode_order(order: &FifthMatchOrder) -> Vec<u8> {
        let mut encoded = Vec::new();
        for word_value in [
            order.salt,
            U256::from_be_slice(&[0; 32]),
            U256::from_be_slice(&[0; 32]),
            order.token_id,
            order.maker_amount,
            order.taker_amount,
            U256::from(match order.side {
                FifthOrderSide::Buy => 0,
                FifthOrderSide::Sell => 1,
            }),
            U256::ZERO,
            order.timestamp,
            U256::from_be_bytes(order.metadata.0),
            U256::from_be_bytes(order.builder.0),
            U256::from(12 * 32),
        ] {
            encoded.extend_from_slice(&word(word_value));
        }
        // Replace the canonical address words after encoding the static head.
        encoded[32 + 12..32 + 32].copy_from_slice(order.maker.as_slice());
        encoded[64 + 12..96].copy_from_slice(order.signer.as_slice());
        encoded.extend_from_slice(&word(U256::from(order.signature.len())));
        encoded.extend_from_slice(&order.signature);
        encoded.resize(encoded.len().div_ceil(32) * 32, 0);
        encoded
    }

    fn encode_u256_array(values: &[U256]) -> Vec<u8> {
        let mut out = word(U256::from(values.len())).to_vec();
        for value in values {
            out.extend_from_slice(&word(*value));
        }
        out
    }
    fn word(value: U256) -> [u8; 32] {
        value.to_be_bytes::<32>()
    }
    fn data(values: &[U256]) -> String {
        let bytes = values
            .iter()
            .flat_map(|value| value.to_be_bytes::<32>())
            .collect::<Vec<_>>();
        format!("0x{}", hex::encode(bytes))
    }
    fn topic_address(address: Address) -> String {
        format!("0x{}{}", "00".repeat(12), hex::encode(address.as_slice()))
    }
    fn fill_topics(hash: B256, maker: Address, taker: Address) -> Vec<String> {
        vec![
            topic_hash(ORDER_FILLED_SIGNATURE),
            format!("{hash:#x}"),
            topic_address(maker),
            topic_address(taker),
        ]
    }
    fn log(address: &str, topics: Vec<String>, data: String) -> serde_json::Value {
        json!({"address":address,"topics":topics,"data":data})
    }

    #[test]
    fn exact_provider_reported_complementary_buy_is_decoded_and_bound() {
        let (transaction, receipt, owner, context) = fixture();
        assert_eq!(
            provider_reported_ctf_v2_settlement_context_candidate(&transaction),
            Some((100, context.block_hash().to_owned()))
        );
        let settlement = decode_provider_reported_ctf_v2_complementary_settlement(
            &transaction,
            &receipt,
            &owner,
            &context,
        )
        .unwrap();
        assert_eq!(settlement.chain_id(), 137);
        assert_eq!(settlement.wallet_legs().len(), 5);
        assert_eq!(settlement.owner_fills().len(), 1);
        assert_eq!(
            settlement.owner_fills()[0].role(),
            ProviderReportedCtfV2OrderRole::Active
        );
        assert_eq!(
            settlement.owner_fills()[0].side(),
            ProviderReportedCtfV2Side::Buy
        );
        assert_eq!(settlement.owner_fills()[0].gross_making(), U256::from(200));
        assert_eq!(settlement.owner_fills()[0].gross_taking(), U256::from(100));
        assert_eq!(settlement.owner_fills()[0].fee(), U256::from(3));
        assert_eq!(
            settlement.wallet_legs()[0].asset_address(),
            Address::from_str(CTF_EMITTER).unwrap()
        );
        assert_eq!(
            settlement.wallet_legs()[1].asset_address(),
            Address::from_str(PUSD_ADDRESS).unwrap()
        );

        let maker_a = Address::from_str("0x2222222222222222222222222222222222222222").unwrap();
        let maker_a_settlement = decode_provider_reported_ctf_v2_complementary_settlement(
            &transaction,
            &receipt,
            &format!("{maker_a:#x}"),
            &context,
        )
        .unwrap();
        assert_eq!(maker_a_settlement.owner_fills().len(), 1);
        assert_eq!(
            maker_a_settlement.owner_fills()[0].role(),
            ProviderReportedCtfV2OrderRole::Maker
        );
        assert_eq!(
            maker_a_settlement.owner_fills()[0].side(),
            ProviderReportedCtfV2Side::Sell
        );
        assert_eq!(
            maker_a_settlement.owner_fills()[0].gross_making(),
            U256::from(50)
        );
        assert_eq!(
            maker_a_settlement.owner_fills()[0].gross_taking(),
            U256::from(100)
        );
        assert_eq!(maker_a_settlement.owner_fills()[0].fee(), U256::from(5));
        assert_eq!(maker_a_settlement.wallet_legs().len(), 2);
        assert_eq!(maker_a_settlement.wallet_legs()[0].amount(), U256::from(50));
        assert_eq!(maker_a_settlement.wallet_legs()[1].amount(), U256::from(95));
        assert_eq!(
            maker_a_settlement.wallet_legs()[1].direction(),
            ProviderReportedCtfV2Direction::Inflow
        );

        let maker_b = Address::from_str("0x3333333333333333333333333333333333333333").unwrap();
        let maker_b_settlement = decode_provider_reported_ctf_v2_complementary_settlement(
            &transaction,
            &receipt,
            &format!("{maker_b:#x}"),
            &context,
        )
        .unwrap();
        assert_eq!(maker_b_settlement.owner_fills().len(), 1);
        assert_eq!(
            maker_b_settlement.owner_fills()[0].role(),
            ProviderReportedCtfV2OrderRole::Maker
        );
        assert_eq!(
            maker_b_settlement.owner_fills()[0].side(),
            ProviderReportedCtfV2Side::Sell
        );
        assert_eq!(
            maker_b_settlement.owner_fills()[0].gross_making(),
            U256::from(50)
        );
        assert_eq!(
            maker_b_settlement.owner_fills()[0].gross_taking(),
            U256::from(100)
        );
        assert_eq!(maker_b_settlement.owner_fills()[0].fee(), U256::from(7));
        assert_eq!(maker_b_settlement.wallet_legs().len(), 2);
        assert_eq!(maker_b_settlement.wallet_legs()[0].amount(), U256::from(50));
        assert_eq!(maker_b_settlement.wallet_legs()[1].amount(), U256::from(93));
        assert_eq!(
            maker_b_settlement.wallet_legs()[1].direction(),
            ProviderReportedCtfV2Direction::Inflow
        );
    }

    #[test]
    fn complementary_sell_independently_checks_active_and_each_maker_fill() {
        let (transaction, receipt, owner, context) = sell_fixture();
        let active = decode_provider_reported_ctf_v2_complementary_settlement(
            &transaction,
            &receipt,
            &owner,
            &context,
        )
        .unwrap();
        assert_eq!(active.owner_fills().len(), 1);
        assert_eq!(
            active.owner_fills()[0].role(),
            ProviderReportedCtfV2OrderRole::Active
        );
        assert_eq!(
            active.owner_fills()[0].side(),
            ProviderReportedCtfV2Side::Sell
        );
        assert_eq!(active.owner_fills()[0].gross_making(), U256::from(200));
        assert_eq!(active.owner_fills()[0].gross_taking(), U256::from(200));
        assert_eq!(active.owner_fills()[0].fee(), U256::from(3));
        assert_eq!(active.wallet_legs().len(), 3);
        assert_eq!(active.wallet_legs()[0].amount(), U256::from(100));
        assert_eq!(active.wallet_legs()[1].amount(), U256::from(100));
        assert_eq!(active.wallet_legs()[2].amount(), U256::from(197));
        assert_eq!(
            active.wallet_legs()[2].direction(),
            ProviderReportedCtfV2Direction::Inflow
        );

        for (maker, fee, cash) in [
            ("0x2222222222222222222222222222222222222222", 5_u64, 105_u64),
            ("0x3333333333333333333333333333333333333333", 7_u64, 107_u64),
        ] {
            let settlement = decode_provider_reported_ctf_v2_complementary_settlement(
                &transaction,
                &receipt,
                maker,
                &context,
            )
            .unwrap();
            assert_eq!(settlement.owner_fills().len(), 1);
            assert_eq!(
                settlement.owner_fills()[0].role(),
                ProviderReportedCtfV2OrderRole::Maker
            );
            assert_eq!(
                settlement.owner_fills()[0].side(),
                ProviderReportedCtfV2Side::Buy
            );
            assert_eq!(settlement.owner_fills()[0].gross_making(), U256::from(100));
            assert_eq!(settlement.owner_fills()[0].gross_taking(), U256::from(100));
            assert_eq!(settlement.owner_fills()[0].fee(), U256::from(fee));
            assert_eq!(settlement.wallet_legs().len(), 2);
            assert_eq!(settlement.wallet_legs()[0].amount(), U256::from(100));
            assert_eq!(settlement.wallet_legs()[1].amount(), U256::from(cash));
            assert_eq!(
                settlement.wallet_legs()[1].direction(),
                ProviderReportedCtfV2Direction::Outflow
            );
        }
    }

    #[test]
    fn v2_binding_rejects_bad_sender_hash_locator_selector_domain_and_order_hash() {
        let (transaction, receipt, owner, context) = fixture();
        let mut bad_sender = transaction.clone();
        bad_sender["from"] = json!("0x9999999999999999999999999999999999999999");
        assert!(
            decode_provider_reported_ctf_v2_complementary_settlement(
                &bad_sender,
                &receipt,
                &owner,
                &context
            )
            .is_err()
        );
        let mut bad_hash = transaction.clone();
        bad_hash["hash"] = json!(format!("0x{}", "ff".repeat(32)));
        assert!(
            decode_provider_reported_ctf_v2_complementary_settlement(
                &bad_hash, &receipt, &owner, &context
            )
            .is_err()
        );
        let mut bad_locator = receipt.clone();
        bad_locator["transactionIndex"] = json!("0x4");
        assert!(
            decode_provider_reported_ctf_v2_complementary_settlement(
                &transaction,
                &bad_locator,
                &owner,
                &context
            )
            .is_err()
        );

        let mut bad_selector = transaction.clone();
        let input = bad_selector["input"].as_str().unwrap();
        bad_selector["input"] = json!(format!("0x00000000{}", &input[10..]));
        assert!(
            decode_provider_reported_ctf_v2_complementary_settlement(
                &bad_selector,
                &receipt,
                &owner,
                &context
            )
            .is_err()
        );

        let decoded = decode_v2_match_orders(
            &hex::decode(
                transaction["input"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("0x")
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let wrong_domain_hash = super::super::fifth_match_orders_call::fifth_order_eip712_hash(
            &decoded.makers[0],
            Address::from_str(EXCHANGE).unwrap(),
        );
        let mut bad_domain = receipt.clone();
        bad_domain["logs"][3]["topics"][1] = json!(format!("{wrong_domain_hash:#x}"));
        assert!(
            decode_provider_reported_ctf_v2_complementary_settlement(
                &transaction,
                &bad_domain,
                &owner,
                &context
            )
            .is_err()
        );

        let mut bad_order_hash = receipt;
        bad_order_hash["logs"][3]["topics"][1] = json!(format!("0x{}", "ff".repeat(32)));
        assert!(
            decode_provider_reported_ctf_v2_complementary_settlement(
                &transaction,
                &bad_order_hash,
                &owner,
                &context
            )
            .is_err()
        );
    }

    #[test]
    fn v2_call_decoder_rejects_truncation_and_trailing_alias_bytes() {
        let (transaction, _, _, _) = fixture();
        let input = hex::decode(
            transaction["input"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
        )
        .unwrap();
        assert!(decode_v2_match_orders(&input).is_some());
        assert!(decode_v2_match_orders(&input[..input.len() - 32]).is_none());
        let mut trailing = input.clone();
        trailing.extend_from_slice(&[0_u8; 32]);
        assert!(decode_v2_match_orders(&trailing).is_none());
        let mut bad_offset = input;
        bad_offset[4 + 32 + 31] = 1;
        assert!(decode_v2_match_orders(&bad_offset).is_none());
    }

    #[test]
    fn mismatched_context_or_extra_receipt_log_is_rejected() {
        let (transaction, receipt, owner, context) = fixture();
        let wrong_context = test_ctf_v2_context(101, context.block_hash());
        assert_eq!(
            decode_provider_reported_ctf_v2_complementary_settlement(
                &transaction,
                &receipt,
                &owner,
                &wrong_context
            ),
            Err(ProviderReportedCtfV2SettlementError::SettlementMismatch)
        );
        let mut extra = receipt;
        extra["logs"].as_array_mut().unwrap().push(json!({"address":PUSD_ADDRESS,"topics":[topic_hash(TRANSFER_SIGNATURE),topic_address(Address::ZERO),topic_address(Address::ZERO)],"data":data(&[U256::ONE]),"blockNumber":"0x64","blockHash":transaction["blockHash"],"transactionHash":transaction["hash"],"transactionIndex":"0x3","logIndex":"0xc","removed":false}));
        assert_eq!(
            decode_provider_reported_ctf_v2_complementary_settlement(
                &transaction,
                &extra,
                &owner,
                &context
            ),
            Err(ProviderReportedCtfV2SettlementError::SettlementMismatch)
        );
    }

    #[test]
    fn fee_and_ordered_event_values_must_match_calldata() {
        let (transaction, receipt, owner, context) = fixture();
        let mut changed_fee = receipt.clone();
        changed_fee["logs"][2]["data"] = json!(data(&[U256::from(6)]));
        assert_eq!(
            decode_provider_reported_ctf_v2_complementary_settlement(
                &transaction,
                &changed_fee,
                &owner,
                &context,
            ),
            Err(ProviderReportedCtfV2SettlementError::SettlementMismatch)
        );

        let mut reordered = receipt;
        reordered["logs"].as_array_mut().unwrap().swap(0, 1);
        reordered["logs"][0]["logIndex"] = json!("0x0");
        reordered["logs"][1]["logIndex"] = json!("0x1");
        assert_eq!(
            decode_provider_reported_ctf_v2_complementary_settlement(
                &transaction,
                &reordered,
                &owner,
                &context,
            ),
            Err(ProviderReportedCtfV2SettlementError::SettlementMismatch)
        );
    }

    #[cfg(test)]
    pub(crate) fn provider_ctf_v2_normal_complementary_settlement()
    -> ProviderReportedCtfV2Settlement {
        let (transaction, receipt, owner, context) = fixture();
        decode_provider_reported_ctf_v2_complementary_settlement(
            &transaction,
            &receipt,
            &owner,
            &context,
        )
        .unwrap()
    }
}
