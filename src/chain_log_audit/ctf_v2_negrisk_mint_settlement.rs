//! Source-bounded provider-reported E222 one-maker complementary mint model.
//!
//! This accepts only a complete standard CTF V2 both-BUY match whose single
//! maker requires a NegRisk split. It remains provider-reported and unbound to
//! deployed implementation identity.

use std::str::FromStr;

use alloy_primitives::{Address, B256, U256};
use serde_json::Value;
use thiserror::Error;
use tokio::time::{Duration, Instant};

#[cfg(test)]
use super::super::fifth_match_orders_call::FifthOrderSignatureType;
use super::super::provider_reported_transaction::{
    ProviderTransactionBindingError, ProviderTransactionLog, bind_provider_transaction,
    match_ordered_logs,
};
use super::*;
use crate::collateral_cash::{PUSD_ADDRESS, USDCE_ADDRESS};
use crate::position_history::CTF_EMITTER;
use crate::rpc_position_history::ctf_v2_context::{
    RpcCurrentCtfV2ContextSource, RpcCurrentCtfV2ImplementationVersion,
};
use crate::rpc_position_history::negrisk_v2_context::{
    RpcCurrentNegRiskV2Context, RpcCurrentNegRiskV2ContextSource,
    RpcCurrentNegRiskV2ImplementationVersion,
};

const EXCHANGE: &str = "0xe2222d279d744050d28e00520010520000310f59";
const OUTCOME_FACTORY: &str = "0xada200001000ef00d07553cee7006808f895c6f1";
const NEG_RISK_ADAPTER: &str = "0xd91e80cf2e7be2e162c6513ced06f1dd0da35296";
const MATCH_SELECTOR: [u8; 4] = [0x3c, 0x2b, 0x43, 0x99];
const TRANSFER_SIGNATURE: &str = "Transfer(address,address,uint256)";
const APPROVAL_SIGNATURE: &str = "Approval(address,address,uint256)";
const UNWRAPPED_SIGNATURE: &str = "Unwrapped(address,address,address,uint256)";
const TRANSFER_SINGLE_SIGNATURE: &str = "TransferSingle(address,address,address,uint256,uint256)";
const TRANSFER_BATCH_SIGNATURE: &str = "TransferBatch(address,address,address,uint256[],uint256[])";
const CTF_POSITION_SPLIT_SIGNATURE: &str =
    "PositionSplit(address,address,bytes32,bytes32,uint256[],uint256)";
const LEGACY_POSITION_SPLIT_SIGNATURE: &str = "PositionSplit(address,bytes32,uint256)";
const ORDER_FILLED_SIGNATURE: &str =
    "OrderFilled(bytes32,address,address,uint8,uint256,uint256,uint256,uint256,bytes32,bytes32)";
const FEE_CHARGED_SIGNATURE: &str = "FeeCharged(address,uint256)";
const ORDERS_MATCHED_SIGNATURE: &str =
    "OrdersMatched(bytes32,address,uint8,uint256,uint256,uint256)";

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProviderReportedCtfV2NegRiskMintSettlementError {
    #[error("provider-reported E222 transaction is malformed")]
    MalformedTransaction,
    #[error("provider-reported E222 receipt is malformed")]
    MalformedReceipt,
    #[error("provider-reported E222 transaction does not match the bounded NegRisk mint model")]
    SettlementMismatch,
}

/// Opaque provider-reported E222 mint projection; this is not proof of
/// execution or deployed implementation identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderReportedCtfV2NegRiskMintSettlement {
    chain_id: u64,
    owner: Address,
    block_number: u64,
    block_hash: String,
    transaction_hash: String,
    transaction_index: u64,
    exchange_address: Address,
    collateral_address: Address,
    ctf_address: Address,
    outcome_token_factory_address: Address,
    neg_risk_adapter_address: Address,
    wrapped_collateral_address: Address,
    underlying_collateral_address: Address,
    context_source: RpcCurrentCtfV2ContextSource,
    implementation_version: RpcCurrentCtfV2ImplementationVersion,
    wallet_legs: Vec<ProviderReportedCtfV2WalletLeg>,
    owner_fills: Vec<ProviderReportedCtfV2OwnerFill>,
}

impl ProviderReportedCtfV2NegRiskMintSettlement {
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
    pub const fn exchange_address(&self) -> Address {
        self.exchange_address
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
    pub const fn outcome_token_factory_address(&self) -> Address {
        self.outcome_token_factory_address
    }
    #[must_use]
    pub const fn neg_risk_adapter_address(&self) -> Address {
        self.neg_risk_adapter_address
    }
    #[must_use]
    pub const fn wrapped_collateral_address(&self) -> Address {
        self.wrapped_collateral_address
    }
    #[must_use]
    pub const fn underlying_collateral_address(&self) -> Address {
        self.underlying_collateral_address
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
enum MintExpected {
    Transfer {
        asset: Address,
        from: Address,
        to: Address,
        amount: U256,
    },
    Approval {
        owner: Address,
        spender: Address,
    },
    Unwrapped {
        caller: Address,
        asset: Address,
        to: Address,
        amount: U256,
    },
    TransferBatch {
        operator: Address,
        from: Address,
        to: Address,
        ids: [U256; 2],
        amounts: [U256; 2],
    },
    CtfSplit {
        stakeholder: Address,
        collateral: Address,
        condition_id: B256,
        amount: U256,
    },
    LegacySplit {
        stakeholder: Address,
        condition_id: B256,
        amount: U256,
    },
    TransferSingle {
        operator: Address,
        from: Address,
        to: Address,
        id: U256,
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
        token_id: U256,
        making: U256,
        taking: U256,
    },
}

/// Candidate selector used before bounded context reads. The decoder still
/// verifies the signed transaction, complete receipt and selected-block getters.
pub fn provider_reported_ctf_v2_negrisk_mint_settlement_candidate(
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
    let call = decode_v2_match_orders(&bytes)?;
    if !is_one_maker_both_buy_mint_shape(&call) {
        return None;
    }
    Some((
        parse_hex_u64(field(transaction, "blockNumber").ok()?).ok()?,
        validate_hex(field(transaction, "blockHash").ok()?, 32).ok()?,
    ))
}

/// Decode the entire signed transaction and receipt for the source-pinned E222
/// one-maker both-BUY mint route. Position IDs are derived with the selected
/// block's WCOL getter and the canonical bounded CTF root-collection helper.
pub async fn decode_provider_reported_ctf_v2_negrisk_mint_settlement(
    transaction: &Value,
    receipt: &Value,
    owner: Address,
    context: &RpcCurrentNegRiskV2Context,
) -> Result<
    ProviderReportedCtfV2NegRiskMintSettlement,
    ProviderReportedCtfV2NegRiskMintSettlementError,
> {
    if owner == Address::ZERO
        || context.source() != RpcCurrentNegRiskV2ContextSource::ProviderReported
        || context.implementation_version() != RpcCurrentNegRiskV2ImplementationVersion::Unbound
        || !context.exchange_address().eq_ignore_ascii_case(EXCHANGE)
        || !context
            .collateral_address()
            .eq_ignore_ascii_case(PUSD_ADDRESS)
        || !context.ctf_address().eq_ignore_ascii_case(CTF_EMITTER)
        || !context
            .outcome_token_factory_address()
            .eq_ignore_ascii_case(OUTCOME_FACTORY)
        || !context
            .neg_risk_adapter_address()
            .eq_ignore_ascii_case(NEG_RISK_ADAPTER)
        || !context
            .underlying_collateral_address()
            .eq_ignore_ascii_case(USDCE_ADDRESS)
    {
        return Err(ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch);
    }
    let bound = bind_provider_transaction(transaction, receipt).map_err(|error| match error {
        ProviderTransactionBindingError::Transaction => {
            ProviderReportedCtfV2NegRiskMintSettlementError::MalformedTransaction
        }
        ProviderTransactionBindingError::Receipt => {
            ProviderReportedCtfV2NegRiskMintSettlementError::MalformedReceipt
        }
    })?;
    if bound.block_number != context.block_number()
        || bound.block_hash != context.block_hash()
        || !bound.to.eq_ignore_ascii_case(EXCHANGE)
        || !bound.input.starts_with(&MATCH_SELECTOR)
        || !bound.value.is_zero()
    {
        return Err(ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch);
    }
    let call = decode_v2_match_orders(&bound.input)
        .ok_or(ProviderReportedCtfV2NegRiskMintSettlementError::MalformedTransaction)?;
    if !is_one_maker_both_buy_mint_shape(&call)
        || (call.active.maker != owner && call.makers[0].maker != owner)
    {
        return Err(ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch);
    }
    let wrapped = parse_context_address(context.wrapped_collateral_address())?;
    if wrapped == Address::ZERO
        || [
            parse_context_address(PUSD_ADDRESS)?,
            parse_context_address(USDCE_ADDRESS)?,
            parse_context_address(CTF_EMITTER)?,
            parse_context_address(EXCHANGE)?,
            parse_context_address(OUTCOME_FACTORY)?,
            parse_context_address(NEG_RISK_ADAPTER)?,
        ]
        .contains(&wrapped)
    {
        return Err(ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch);
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    let collection_yes = super::super::ctf_position_identity::get_root_collection_id_bounded(
        call.condition_id,
        1,
        128,
        deadline,
    )
    .await
    .map_err(|_| ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch)?;
    let collection_no = super::super::ctf_position_identity::get_root_collection_id_bounded(
        call.condition_id,
        2,
        128,
        deadline,
    )
    .await
    .map_err(|_| ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch)?;
    let id_yes = U256::from_be_bytes(
        super::super::ctf_position_identity::position_id(wrapped, collection_yes).0,
    );
    let id_no = U256::from_be_bytes(
        super::super::ctf_position_identity::position_id(wrapped, collection_no).0,
    );
    if call.active.token_id == call.makers[0].token_id
        || [call.active.token_id, call.makers[0].token_id] != [id_yes, id_no]
            && [call.active.token_id, call.makers[0].token_id] != [id_no, id_yes]
    {
        return Err(ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch);
    }
    let vault = parse_context_address(context.vault_address())?;
    let fee_receiver = observed_fee_receiver(&call, &bound.logs)?;
    let expected = build_mint_expectations(&call, wrapped, vault, [id_yes, id_no], fee_receiver)?;
    if !match_ordered_logs(&expected, &bound.logs, |expected, actual| {
        mint_expected_matches(expected, actual, context)
    }) {
        return Err(ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch);
    }
    let ctf = parse_context_address(context.ctf_address())?;
    let collateral = parse_context_address(context.collateral_address())?;
    let exchange = parse_context_address(context.exchange_address())?;
    let factory = parse_context_address(context.outcome_token_factory_address())?;
    let legacy = parse_context_address(context.neg_risk_adapter_address())?;
    let owner_fills = expected
        .iter()
        .zip(&bound.logs)
        .filter_map(|(expected, log)| match expected {
            MintExpected::Fill(fill) if fill.maker == owner => {
                Some(ProviderReportedCtfV2OwnerFill {
                    log_index: log.log_index,
                    order_hash: fill.hash,
                    raw_counterparty: fill.taker,
                    token_id: fill.token_id,
                    side: fill.side,
                    gross_making: fill.making,
                    gross_taking: fill.taking,
                    fee: fill.fee,
                    role: if fill.taker == exchange {
                        ProviderReportedCtfV2OrderRole::Active
                    } else {
                        ProviderReportedCtfV2OrderRole::Maker
                    },
                })
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if owner_fills.len() != 1 {
        return Err(ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch);
    }
    let wallet_legs = expected
        .iter()
        .zip(&bound.logs)
        .filter_map(|(expected, log)| {
            let (asset, from, to, amount, token_id) = match expected {
                MintExpected::Transfer {
                    asset,
                    from,
                    to,
                    amount,
                } if *asset == collateral => (*asset, *from, *to, *amount, None),
                MintExpected::TransferSingle {
                    from,
                    to,
                    id,
                    amount,
                    ..
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
        .collect::<Vec<_>>();
    if wallet_legs.is_empty() {
        return Err(ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch);
    }
    Ok(ProviderReportedCtfV2NegRiskMintSettlement {
        chain_id: 137,
        owner,
        block_number: bound.block_number,
        block_hash: bound.block_hash,
        transaction_hash: bound.transaction_hash,
        transaction_index: bound.transaction_index,
        exchange_address: exchange,
        collateral_address: collateral,
        ctf_address: ctf,
        outcome_token_factory_address: factory,
        neg_risk_adapter_address: legacy,
        wrapped_collateral_address: wrapped,
        underlying_collateral_address: parse_context_address(
            context.underlying_collateral_address(),
        )?,
        context_source: RpcCurrentCtfV2ContextSource::ProviderReported,
        implementation_version: RpcCurrentCtfV2ImplementationVersion::Unbound,
        wallet_legs,
        owner_fills,
    })
}

fn is_one_maker_both_buy_mint_shape(call: &V2MatchOrdersCall) -> bool {
    call.condition_id != B256::ZERO
        && call.makers.len() == 1
        && call.maker_fills.len() == 1
        && call.maker_fees.len() == 1
        && call.active.side == FifthOrderSide::Buy
        && call.makers[0].side == FifthOrderSide::Buy
        && call.active.token_id != call.makers[0].token_id
        && !call.active.token_id.is_zero()
        && !call.makers[0].token_id.is_zero()
}

fn build_mint_expectations(
    call: &V2MatchOrdersCall,
    wrapped: Address,
    vault: Address,
    position_ids: [U256; 2],
    fee_receiver: Address,
) -> Result<Vec<MintExpected>, ProviderReportedCtfV2NegRiskMintSettlementError> {
    let active = &call.active;
    let maker = &call.makers[0];
    let maker_fill = call.maker_fills[0];
    let maker_fee = call.maker_fees[0];
    let exchange = parse_context_address(EXCHANGE)?;
    let factory = parse_context_address(OUTCOME_FACTORY)?;
    let legacy = parse_context_address(NEG_RISK_ADAPTER)?;
    let collateral = parse_context_address(PUSD_ADDRESS)?;
    let usdce = parse_context_address(USDCE_ADDRESS)?;
    let zero = Address::ZERO;
    if active.maker == zero
        || maker.maker == zero
        || active.maker == maker.maker
        || active.maker == exchange
        || maker.maker == exchange
        || active.maker_amount.is_zero()
        || active.taker_amount.is_zero()
        || maker.maker_amount.is_zero()
        || maker.taker_amount.is_zero()
        || call.active_fill.is_zero()
        || call.active_fill > active.maker_amount
        || maker_fill.is_zero()
        || maker_fill > maker.maker_amount
        || call.active_fee > call.active_fill
        || maker_fee > maker_fill
    {
        return Err(ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch);
    }
    let mint_amount = maker_fill
        .checked_mul(maker.taker_amount)
        .and_then(|amount| amount.checked_div(maker.maker_amount))
        .filter(|amount| !amount.is_zero())
        .ok_or(ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch)?;
    let active_minimum = call
        .active_fill
        .checked_mul(active.taker_amount)
        .and_then(|amount| amount.checked_div(active.maker_amount))
        .ok_or(ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch)?;
    if mint_amount < active_minimum {
        return Err(ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch);
    }
    // This narrow mint profile accepts only the zero-refund principal case.
    if call.active_fill.checked_add(maker_fill) != Some(mint_amount) {
        return Err(ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch);
    }
    let fees = call
        .active_fee
        .checked_add(maker_fee)
        .ok_or(ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch)?;
    let active_cash = call
        .active_fill
        .checked_add(call.active_fee)
        .ok_or(ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch)?;
    let maker_cash = maker_fill
        .checked_add(maker_fee)
        .ok_or(ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch)?;
    let maker_hash = v2_order_hash(maker, exchange);
    let active_hash = v2_order_hash(active, exchange);
    let mut expected = vec![
        MintExpected::Transfer {
            asset: collateral,
            from: active.maker,
            to: exchange,
            amount: active_cash,
        },
        MintExpected::Transfer {
            asset: collateral,
            from: maker.maker,
            to: exchange,
            amount: maker_cash,
        },
        // CtfCollateralAdapter transfers pUSD into the pUSD token contract
        // before unwrapping it to the underlying collateral.
        MintExpected::Transfer {
            asset: collateral,
            from: exchange,
            to: collateral,
            amount: mint_amount,
        },
    ];
    expected.extend([
        // The observed source sequence puts each USDC.e Transfer before its
        // corresponding Approval. Approval value is allowance metadata.
        MintExpected::Transfer {
            asset: usdce,
            from: vault,
            to: factory,
            amount: mint_amount,
        },
        MintExpected::Approval {
            owner: vault,
            spender: collateral,
        },
        MintExpected::Transfer {
            asset: collateral,
            from: collateral,
            to: Address::ZERO,
            amount: mint_amount,
        },
        MintExpected::Unwrapped {
            caller: factory,
            asset: usdce,
            to: factory,
            amount: mint_amount,
        },
        MintExpected::Transfer {
            asset: usdce,
            from: factory,
            to: legacy,
            amount: mint_amount,
        },
        MintExpected::Approval {
            owner: factory,
            spender: legacy,
        },
        MintExpected::Transfer {
            asset: usdce,
            from: legacy,
            to: wrapped,
            amount: mint_amount,
        },
        MintExpected::Approval {
            owner: legacy,
            spender: wrapped,
        },
        MintExpected::Transfer {
            asset: wrapped,
            from: zero,
            to: legacy,
            amount: mint_amount,
        },
        MintExpected::Transfer {
            asset: wrapped,
            from: legacy,
            to: parse_context_address(CTF_EMITTER)?,
            amount: mint_amount,
        },
    ]);
    let ids = position_ids;
    let amounts = [mint_amount, mint_amount];
    expected.extend([
        MintExpected::TransferBatch {
            operator: legacy,
            from: zero,
            to: legacy,
            ids,
            amounts,
        },
        MintExpected::CtfSplit {
            stakeholder: legacy,
            collateral: wrapped,
            condition_id: call.condition_id,
            amount: mint_amount,
        },
        MintExpected::TransferBatch {
            operator: legacy,
            from: legacy,
            to: factory,
            ids,
            amounts,
        },
        MintExpected::LegacySplit {
            stakeholder: factory,
            condition_id: call.condition_id,
            amount: mint_amount,
        },
        MintExpected::TransferBatch {
            operator: factory,
            from: factory,
            to: exchange,
            ids,
            amounts,
        },
        MintExpected::TransferSingle {
            operator: exchange,
            from: exchange,
            to: maker.maker,
            id: maker.token_id,
            amount: mint_amount,
        },
    ]);
    if !maker_fee.is_zero() {
        expected.push(MintExpected::Fee {
            receiver: fee_receiver,
            amount: maker_fee,
        });
    }
    expected.push(MintExpected::Fill(FillEvent {
        hash: maker_hash,
        maker: maker.maker,
        taker: active.maker,
        side: ProviderReportedCtfV2Side::Buy,
        token_id: maker.token_id,
        making: maker_fill,
        taking: mint_amount,
        fee: maker_fee,
        builder: maker.builder,
        metadata: maker.metadata,
    }));
    if !call.active_fee.is_zero() {
        expected.push(MintExpected::Fee {
            receiver: fee_receiver,
            amount: call.active_fee,
        });
    }
    if !fees.is_zero() {
        expected.push(MintExpected::Transfer {
            asset: collateral,
            from: exchange,
            to: fee_receiver,
            amount: fees,
        });
    }
    expected.extend([
        MintExpected::TransferSingle {
            operator: exchange,
            from: exchange,
            to: active.maker,
            id: active.token_id,
            amount: mint_amount,
        },
        MintExpected::Fill(FillEvent {
            hash: active_hash,
            maker: active.maker,
            taker: exchange,
            side: ProviderReportedCtfV2Side::Buy,
            token_id: active.token_id,
            making: call.active_fill,
            taking: mint_amount,
            fee: call.active_fee,
            builder: active.builder,
            metadata: active.metadata,
        }),
        MintExpected::Matched {
            hash: active_hash,
            taker: active.maker,
            token_id: active.token_id,
            making: call.active_fill,
            taking: mint_amount,
        },
    ]);
    Ok(expected)
}

fn observed_fee_receiver(
    call: &V2MatchOrdersCall,
    logs: &[ProviderTransactionLog],
) -> Result<Address, ProviderReportedCtfV2NegRiskMintSettlementError> {
    let expected_count =
        usize::from(!call.active_fee.is_zero()) + usize::from(!call.maker_fees[0].is_zero());
    let fee_topic = topic_hash(FEE_CHARGED_SIGNATURE);
    let events = logs
        .iter()
        .filter(|log| {
            log.address.eq_ignore_ascii_case(EXCHANGE)
                && log
                    .topics
                    .first()
                    .is_some_and(|topic| topic.eq_ignore_ascii_case(&fee_topic))
        })
        .collect::<Vec<_>>();
    if events.len() != expected_count {
        return Err(ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch);
    }
    if expected_count == 0 {
        return Ok(Address::ZERO);
    }
    let receiver = events[0]
        .topics
        .get(1)
        .and_then(|topic| topic_address(topic))
        .filter(|address| *address != Address::ZERO)
        .ok_or(ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch)?;
    if events.iter().any(|event| {
        event.topics.len() != 2
            || event.topics.get(1).and_then(|topic| topic_address(topic)) != Some(receiver)
            || event.data.len() != 66
    }) {
        return Err(ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch);
    }
    Ok(receiver)
}

fn mint_expected_matches(
    expected: &MintExpected,
    actual: &ProviderTransactionLog,
    context: &RpcCurrentNegRiskV2Context,
) -> bool {
    let topic = actual
        .topics
        .first()
        .map(String::as_str)
        .unwrap_or_default();
    match expected {
        MintExpected::Transfer {
            asset,
            from,
            to,
            amount,
        } => {
            actual.address.eq_ignore_ascii_case(&format!("{asset:#x}"))
                && topic.eq_ignore_ascii_case(&topic_hash(TRANSFER_SIGNATURE))
                && actual.topics.len() == 3
                && topic_address(&actual.topics[1]) == Some(*from)
                && topic_address(&actual.topics[2]) == Some(*to)
                && data_word(&actual.data, 0) == Some(*amount)
                && actual.data.len() == 66
        }
        MintExpected::Approval { owner, spender } => {
            let observed_owner = actual.topics.get(1).and_then(|value| topic_address(value));
            let owner_matches = if *owner == Address::ZERO {
                observed_owner.is_some_and(|address| address != Address::ZERO)
            } else {
                observed_owner == Some(*owner)
            };
            actual.address.eq_ignore_ascii_case(USDCE_ADDRESS)
                && topic.eq_ignore_ascii_case(&topic_hash(APPROVAL_SIGNATURE))
                && actual.topics.len() == 3
                && owner_matches
                && topic_address(&actual.topics[2]) == Some(*spender)
                && data_word(&actual.data, 0).is_some()
                && actual.data.len() == 66
        }
        MintExpected::Unwrapped {
            caller,
            asset,
            to,
            amount,
        } => {
            actual
                .address
                .eq_ignore_ascii_case(context.collateral_address())
                && topic.eq_ignore_ascii_case(&topic_hash(UNWRAPPED_SIGNATURE))
                && actual.topics.len() == 4
                && topic_address(&actual.topics[1]) == Some(*caller)
                && topic_address(&actual.topics[2]) == Some(*asset)
                && topic_address(&actual.topics[3]) == Some(*to)
                && data_word(&actual.data, 0) == Some(*amount)
                && actual.data.len() == 66
        }
        MintExpected::TransferBatch {
            operator,
            from,
            to,
            ids,
            amounts,
        } => {
            actual.address.eq_ignore_ascii_case(context.ctf_address())
                && topic.eq_ignore_ascii_case(&topic_hash(TRANSFER_BATCH_SIGNATURE))
                && actual.topics.len() == 4
                && topic_address(&actual.topics[1]) == Some(*operator)
                && topic_address(&actual.topics[2]) == Some(*from)
                && topic_address(&actual.topics[3]) == Some(*to)
                && decode_two_u256_arrays(&actual.data) == Some((*ids, *amounts))
        }
        MintExpected::CtfSplit {
            stakeholder,
            collateral,
            condition_id,
            amount,
        } => {
            actual.address.eq_ignore_ascii_case(context.ctf_address())
                && topic.eq_ignore_ascii_case(&topic_hash(CTF_POSITION_SPLIT_SIGNATURE))
                && actual.topics.len() == 4
                && topic_address(&actual.topics[1]) == Some(*stakeholder)
                && actual.topics[2].eq_ignore_ascii_case(&format!("{:#x}", B256::ZERO))
                && actual.topics[3].eq_ignore_ascii_case(&format!("{condition_id:#x}"))
                && actual.data.len() == 386
                && data_word(&actual.data, 0) == Some(address_as_u256(*collateral))
                && data_word(&actual.data, 32) == Some(U256::from(96))
                && data_word(&actual.data, 64) == Some(*amount)
                && data_word(&actual.data, 96) == Some(U256::from(2))
                && data_word(&actual.data, 128) == Some(U256::ONE)
                && data_word(&actual.data, 160) == Some(U256::from(2))
        }
        MintExpected::LegacySplit {
            stakeholder,
            condition_id,
            amount,
        } => {
            actual
                .address
                .eq_ignore_ascii_case(context.neg_risk_adapter_address())
                && topic.eq_ignore_ascii_case(&topic_hash(LEGACY_POSITION_SPLIT_SIGNATURE))
                && actual.topics.len() == 3
                && topic_address(&actual.topics[1]) == Some(*stakeholder)
                && actual.topics[2].eq_ignore_ascii_case(&format!("{condition_id:#x}"))
                && actual.data.len() == 66
                && data_word(&actual.data, 0) == Some(*amount)
        }
        MintExpected::TransferSingle {
            operator,
            from,
            to,
            id,
            amount,
        } => {
            actual.address.eq_ignore_ascii_case(context.ctf_address())
                && topic.eq_ignore_ascii_case(&topic_hash(TRANSFER_SINGLE_SIGNATURE))
                && actual.topics.len() == 4
                && topic_address(&actual.topics[1]) == Some(*operator)
                && topic_address(&actual.topics[2]) == Some(*from)
                && topic_address(&actual.topics[3]) == Some(*to)
                && actual.data.len() == 130
                && data_word(&actual.data, 0) == Some(*id)
                && data_word(&actual.data, 32) == Some(*amount)
        }
        MintExpected::Fee { receiver, amount } => {
            actual.address.eq_ignore_ascii_case(EXCHANGE)
                && topic.eq_ignore_ascii_case(&topic_hash(FEE_CHARGED_SIGNATURE))
                && actual.topics.len() == 2
                && topic_address(&actual.topics[1]).is_some_and(|value| {
                    if *receiver == Address::ZERO {
                        value != Address::ZERO
                    } else {
                        value == *receiver
                    }
                })
                && actual.data.len() == 66
                && data_word(&actual.data, 0) == Some(*amount)
        }
        MintExpected::Fill(fill) => {
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
        MintExpected::Matched {
            hash,
            taker,
            token_id,
            making,
            taking,
        } => {
            actual.address.eq_ignore_ascii_case(EXCHANGE)
                && topic.eq_ignore_ascii_case(&topic_hash(ORDERS_MATCHED_SIGNATURE))
                && actual.topics.len() == 3
                && actual.topics[1].eq_ignore_ascii_case(&format!("{hash:#x}"))
                && topic_address(&actual.topics[2]) == Some(*taker)
                && actual.data.len() == 258
                && data_word(&actual.data, 0) == Some(U256::ZERO)
                && data_word(&actual.data, 32) == Some(*token_id)
                && data_word(&actual.data, 64) == Some(*making)
                && data_word(&actual.data, 96) == Some(*taking)
        }
    }
}

fn decode_two_u256_arrays(data: &str) -> Option<([U256; 2], [U256; 2])> {
    let bytes = hex::decode(data.strip_prefix("0x")?).ok()?;
    if bytes.len() != 8 * 32
        || U256::from_be_slice(bytes.get(..32)?) != U256::from(64)
        || U256::from_be_slice(bytes.get(32..64)?) != U256::from(160)
        || U256::from_be_slice(bytes.get(64..96)?) != U256::from(2)
        || U256::from_be_slice(bytes.get(160..192)?) != U256::from(2)
    {
        return None;
    }
    Some((
        [
            U256::from_be_slice(bytes.get(96..128)?),
            U256::from_be_slice(bytes.get(128..160)?),
        ],
        [
            U256::from_be_slice(bytes.get(192..224)?),
            U256::from_be_slice(bytes.get(224..256)?),
        ],
    ))
}

fn parse_context_address(
    value: &str,
) -> Result<Address, ProviderReportedCtfV2NegRiskMintSettlementError> {
    let normalized = validate_hex(value, 20)
        .map_err(|_| ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch)?;
    Address::from_str(&normalized)
        .map_err(|_| ProviderReportedCtfV2NegRiskMintSettlementError::SettlementMismatch)
}

fn address_as_u256(address: Address) -> U256 {
    let mut word = [0_u8; 32];
    word[12..].copy_from_slice(address.as_slice());
    U256::from_be_bytes(word)
}

#[cfg(test)]
pub(crate) async fn provider_ctf_v2_negrisk_mint_settlement()
-> ProviderReportedCtfV2NegRiskMintSettlement {
    tests::provider_ctf_v2_negrisk_mint_settlement().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc_position_history::negrisk_v2_context::test_negrisk_v2_context;
    use serde_json::json;

    const OWNER: &str = "0x1111111111111111111111111111111111111111";
    const MAKER: &str = "0x2222222222222222222222222222222222222222";
    const FEE_RECEIVER: &str = "0x6666666666666666666666666666666666666666";
    const VAULT: &str = "0x4444444444444444444444444444444444444444";
    const CONDITION: &str = "0x7777777777777777777777777777777777777777777777777777777777777777";

    #[tokio::test]
    async fn source_ordered_one_maker_both_buy_mint_is_bound_for_active_and_maker_owners() {
        let fixture = fixture().await;
        assert_eq!(
            provider_reported_ctf_v2_negrisk_mint_settlement_candidate(&fixture.transaction),
            Some((100, fixture.context.block_hash().to_owned()))
        );
        let active = decode_provider_reported_ctf_v2_negrisk_mint_settlement(
            &fixture.transaction,
            &fixture.receipt,
            Address::from_str(OWNER).unwrap(),
            &fixture.context,
        )
        .await
        .unwrap();
        assert_eq!(active.chain_id(), 137);
        assert_eq!(active.owner(), Address::from_str(OWNER).unwrap());
        assert_eq!(active.wallet_legs().len(), 2);
        assert_eq!(active.wallet_legs()[0].amount(), U256::from(43));
        assert_eq!(
            active.wallet_legs()[0].asset_address(),
            Address::from_str(PUSD_ADDRESS).unwrap()
        );
        assert_eq!(active.wallet_legs()[1].amount(), U256::from(100));
        assert_eq!(active.wallet_legs()[1].token_id(), Some(fixture.active_id));
        assert_eq!(active.owner_fills().len(), 1);
        assert_fill_matches_receipt(&active.owner_fills()[0], &fixture.receipt);
        assert_eq!(
            active.owner_fills()[0].role(),
            ProviderReportedCtfV2OrderRole::Active
        );
        assert_eq!(active.owner_fills()[0].gross_making(), U256::from(40));
        assert_eq!(active.owner_fills()[0].gross_taking(), U256::from(100));
        assert_eq!(
            active.context_source(),
            RpcCurrentCtfV2ContextSource::ProviderReported
        );
        assert_eq!(
            active.implementation_version(),
            RpcCurrentCtfV2ImplementationVersion::Unbound
        );

        let maker = decode_provider_reported_ctf_v2_negrisk_mint_settlement(
            &fixture.transaction,
            &fixture.receipt,
            Address::from_str(MAKER).unwrap(),
            &fixture.context,
        )
        .await
        .unwrap();
        assert_eq!(maker.wallet_legs().len(), 2);
        assert_eq!(maker.wallet_legs()[0].amount(), U256::from(60));
        assert_eq!(
            maker.wallet_legs()[0].direction(),
            ProviderReportedCtfV2Direction::Outflow
        );
        assert_eq!(maker.wallet_legs()[1].token_id(), Some(fixture.maker_id));
        assert_eq!(maker.owner_fills().len(), 1);
        assert_fill_matches_receipt(&maker.owner_fills()[0], &fixture.receipt);
        assert_eq!(
            maker.owner_fills()[0].role(),
            ProviderReportedCtfV2OrderRole::Maker
        );
        assert_eq!(maker.owner_fills()[0].gross_making(), U256::from(60));
        assert_eq!(maker.owner_fills()[0].gross_taking(), U256::from(100));
    }

    #[tokio::test]
    async fn mint_profile_rejects_an_unmodeled_active_collateral_refund() {
        let fixture = fixture().await;
        let input = hex::decode(
            fixture.transaction["input"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
        )
        .unwrap();
        let mut call = decode_v2_match_orders(&input).unwrap();
        call.active_fill = U256::from(41);
        assert!(
            build_mint_expectations(
                &call,
                Address::from_str("0x3a3bd7bb9528e159577f7c2e685cc81a765002e2").unwrap(),
                Address::from_str(VAULT).unwrap(),
                [fixture.active_id, fixture.maker_id],
                Address::from_str(FEE_RECEIVER).unwrap(),
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn conversion_order_context_and_complete_receipt_are_enforced() {
        let fixture = fixture().await;
        assert!(
            decode_provider_reported_ctf_v2_negrisk_mint_settlement(
                &fixture.transaction,
                &fixture.receipt,
                Address::from_str(OWNER).unwrap(),
                &fixture.context,
            )
            .await
            .is_ok()
        );
        let mut reordered = fixture.receipt.clone();
        reordered["logs"].as_array_mut().unwrap().swap(3, 4);
        rewrite_locator_indexes(&mut reordered);
        assert!(
            decode_provider_reported_ctf_v2_negrisk_mint_settlement(
                &fixture.transaction,
                &reordered,
                Address::from_str(OWNER).unwrap(),
                &fixture.context,
            )
            .await
            .is_err()
        );

        let mut wrong_batch = fixture.receipt.clone();
        wrong_batch["logs"][13]["topics"][2] =
            json!(topic_address(Address::from_str(OWNER).unwrap()));
        assert!(
            decode_provider_reported_ctf_v2_negrisk_mint_settlement(
                &fixture.transaction,
                &wrong_batch,
                Address::from_str(OWNER).unwrap(),
                &fixture.context,
            )
            .await
            .is_err()
        );

        let wrong_context = test_negrisk_v2_context(101, fixture.context.block_hash());
        assert!(
            decode_provider_reported_ctf_v2_negrisk_mint_settlement(
                &fixture.transaction,
                &fixture.receipt,
                Address::from_str(OWNER).unwrap(),
                &wrong_context,
            )
            .await
            .is_err()
        );

        let mut extra = fixture.receipt.clone();
        let last = extra["logs"].as_array().unwrap().len();
        let mut unknown = log(
            PUSD_ADDRESS,
            vec![topic_hash(TRANSFER_SIGNATURE)],
            data(&[U256::ONE]),
        );
        unknown["blockNumber"] = json!("0x64");
        unknown["blockHash"] = fixture.transaction["blockHash"].clone();
        unknown["transactionHash"] = fixture.transaction["hash"].clone();
        unknown["transactionIndex"] = json!("0x3");
        unknown["logIndex"] = json!(format!("0x{last:x}"));
        unknown["removed"] = json!(false);
        extra["logs"].as_array_mut().unwrap().push(unknown);
        assert!(
            decode_provider_reported_ctf_v2_negrisk_mint_settlement(
                &fixture.transaction,
                &extra,
                Address::from_str(OWNER).unwrap(),
                &fixture.context,
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn wrong_sender_hash_and_unsupported_calldata_are_rejected() {
        let fixture = fixture().await;
        let mut wrong_sender = fixture.transaction.clone();
        wrong_sender["from"] = json!(MAKER);
        assert!(
            decode_provider_reported_ctf_v2_negrisk_mint_settlement(
                &wrong_sender,
                &fixture.receipt,
                Address::from_str(OWNER).unwrap(),
                &fixture.context,
            )
            .await
            .is_err()
        );
        let mut wrong_hash = fixture.receipt.clone();
        wrong_hash["transactionHash"] = json!(format!("0x{}", "ff".repeat(32)));
        assert!(
            decode_provider_reported_ctf_v2_negrisk_mint_settlement(
                &fixture.transaction,
                &wrong_hash,
                Address::from_str(OWNER).unwrap(),
                &fixture.context,
            )
            .await
            .is_err()
        );
        let mut bad_selector = fixture.transaction.clone();
        let input = bad_selector["input"].as_str().unwrap();
        bad_selector["input"] = json!(format!("0x00000000{}", &input[10..]));
        assert!(
            provider_reported_ctf_v2_negrisk_mint_settlement_candidate(&bad_selector).is_none()
        );
    }

    #[tokio::test]
    async fn provider_ctf_v2_negrisk_mint_settlement_fixture_is_decoder_output() {
        let settlement = provider_ctf_v2_negrisk_mint_settlement().await;
        assert_eq!(settlement.owner(), Address::from_str(OWNER).unwrap());
        assert_eq!(settlement.wallet_legs().len(), 2);
        assert_eq!(settlement.owner_fills().len(), 1);
    }

    pub(crate) async fn provider_ctf_v2_negrisk_mint_settlement()
    -> ProviderReportedCtfV2NegRiskMintSettlement {
        let fixture = fixture().await;
        decode_provider_reported_ctf_v2_negrisk_mint_settlement(
            &fixture.transaction,
            &fixture.receipt,
            Address::from_str(OWNER).unwrap(),
            &fixture.context,
        )
        .await
        .unwrap()
    }

    fn assert_fill_matches_receipt(fill: &ProviderReportedCtfV2OwnerFill, receipt: &Value) {
        let log = &receipt["logs"][usize::try_from(fill.log_index()).unwrap()];
        let topics = log["topics"].as_array().unwrap();
        assert_eq!(
            fill.order_hash(),
            B256::from_str(topics[1].as_str().unwrap()).unwrap()
        );
        assert_eq!(
            format!("{:#x}", fill.raw_counterparty()),
            super::super::super::topic_address(topics[3].as_str().unwrap()).unwrap()
        );
    }

    struct Fixture {
        transaction: Value,
        receipt: Value,
        context: RpcCurrentNegRiskV2Context,
        active_id: U256,
        maker_id: U256,
    }

    async fn fixture() -> Fixture {
        let condition = B256::from_str(CONDITION).unwrap();
        let wrapped = Address::from_str("0x3a3bd7bb9528e159577f7c2e685cc81a765002e2").unwrap();
        let yes_collection =
            super::super::super::ctf_position_identity::get_root_collection_id_bounded(
                condition,
                1,
                128,
                Instant::now() + Duration::from_secs(30),
            )
            .await
            .unwrap();
        let no_collection =
            super::super::super::ctf_position_identity::get_root_collection_id_bounded(
                condition,
                2,
                128,
                Instant::now() + Duration::from_secs(30),
            )
            .await
            .unwrap();
        let active_id = U256::from_be_bytes(
            super::super::super::ctf_position_identity::position_id(wrapped, yes_collection).0,
        );
        let maker_id = U256::from_be_bytes(
            super::super::super::ctf_position_identity::position_id(wrapped, no_collection).0,
        );
        let active = order(OWNER, active_id, 1_000, 80, 0xaa, 0xbb);
        let maker = order(MAKER, maker_id, 600, 1_000, 0xcc, 0xdd);
        let input = encode_call(&active, &maker);
        let (mut transaction, _) =
            super::super::super::receipt_tests::signed_polygon_transaction_with_key(
                EXCHANGE, &input, 0x53,
            );
        let encoded =
            super::super::super::encode_signed_transaction_with_sender_recovery(&transaction, true)
                .unwrap();
        let tx_hash = format!("{:#x}", encoded.hash);
        let block_hash = format!("0x{}", "aa".repeat(32));
        transaction["hash"] = json!(tx_hash);
        transaction["blockNumber"] = json!("0x64");
        transaction["blockHash"] = json!(block_hash);
        transaction["transactionIndex"] = json!("0x3");
        let context = test_negrisk_v2_context(100, &block_hash);
        let logs = source_ordered_logs(&active, &maker, condition, active_id, maker_id);
        let receipt_logs = logs
            .iter()
            .enumerate()
            .map(|(index, row)| {
                json!({
                    "address": row["address"],
                    "topics": row["topics"],
                    "data": row["data"],
                    "blockNumber": "0x64",
                    "blockHash": block_hash,
                    "transactionHash": tx_hash,
                    "transactionIndex": "0x3",
                    "logIndex": format!("0x{index:x}"),
                    "removed": false,
                })
            })
            .collect::<Vec<_>>();
        let receipt = json!({
            "transactionHash": tx_hash,
            "blockNumber": "0x64",
            "blockHash": block_hash,
            "transactionIndex": "0x3",
            "status": "0x1",
            "type": "0x0",
            "logs": receipt_logs,
        });
        Fixture {
            transaction,
            receipt,
            context,
            active_id,
            maker_id,
        }
    }

    fn source_ordered_logs(
        active: &FifthMatchOrder,
        maker: &FifthMatchOrder,
        condition: B256,
        active_id: U256,
        maker_id: U256,
    ) -> Vec<Value> {
        let exchange = Address::from_str(EXCHANGE).unwrap();
        let factory = Address::from_str(OUTCOME_FACTORY).unwrap();
        let legacy = Address::from_str(NEG_RISK_ADAPTER).unwrap();
        let collateral = Address::from_str(PUSD_ADDRESS).unwrap();
        let usdce = Address::from_str(USDCE_ADDRESS).unwrap();
        let wrapped = Address::from_str("0x3a3bd7bb9528e159577f7c2e685cc81a765002e2").unwrap();
        let ctf = Address::from_str(CTF_EMITTER).unwrap();
        let vault = Address::from_str(VAULT).unwrap();
        let receiver = Address::from_str(FEE_RECEIVER).unwrap();
        let amount = U256::from(100);
        let total_fee = U256::from(3);
        let maker_hash = v2_order_hash(maker, exchange);
        let active_hash = v2_order_hash(active, exchange);
        let yes_no = [active_id, maker_id];
        let values = [amount, amount];
        let mut logs = vec![
            transfer(
                collateral,
                Address::from_str(OWNER).unwrap(),
                exchange,
                U256::from(43),
            ),
            transfer(
                collateral,
                Address::from_str(MAKER).unwrap(),
                exchange,
                U256::from(60),
            ),
            transfer(collateral, exchange, collateral, amount),
            transfer(usdce, vault, factory, amount),
            approval(usdce, vault, collateral),
            transfer(collateral, collateral, Address::ZERO, amount),
            unwrapped(collateral, factory, usdce, factory, amount),
            transfer(usdce, factory, legacy, amount),
            approval(usdce, factory, legacy),
            transfer(usdce, legacy, wrapped, amount),
            approval(usdce, legacy, wrapped),
            transfer(wrapped, Address::ZERO, legacy, amount),
            transfer(wrapped, legacy, ctf, amount),
            transfer_batch(ctf, legacy, Address::ZERO, legacy, yes_no, values),
            ctf_position_split(ctf, legacy, wrapped, condition, amount),
            transfer_batch(ctf, legacy, legacy, factory, yes_no, values),
            legacy_position_split(legacy, factory, condition, amount),
            transfer_batch(ctf, factory, factory, exchange, yes_no, values),
            transfer_single(
                ctf,
                exchange,
                exchange,
                Address::from_str(MAKER).unwrap(),
                maker_id,
                amount,
            ),
            fill(
                exchange,
                &FillEvent {
                    hash: maker_hash,
                    maker: maker.maker,
                    taker: active.maker,
                    side: ProviderReportedCtfV2Side::Buy,
                    token_id: maker_id,
                    making: U256::from(60),
                    taking: U256::from(100),
                    fee: U256::ZERO,
                    builder: maker.builder,
                    metadata: maker.metadata,
                },
            ),
            fee(exchange, receiver, U256::from(3)),
            transfer(collateral, exchange, receiver, total_fee),
            transfer_single(ctf, exchange, exchange, active.maker, active_id, amount),
            fill(
                exchange,
                &FillEvent {
                    hash: active_hash,
                    maker: active.maker,
                    taker: exchange,
                    side: ProviderReportedCtfV2Side::Buy,
                    token_id: active_id,
                    making: U256::from(40),
                    taking: U256::from(100),
                    fee: U256::from(3),
                    builder: active.builder,
                    metadata: active.metadata,
                },
            ),
        ];
        logs.push(matched(
            exchange,
            active_hash,
            active.maker,
            active_id,
            40,
            100,
        ));
        logs
    }

    fn order(
        maker: &str,
        token_id: U256,
        maker_amount: u64,
        taker_amount: u64,
        meta: u8,
        builder: u8,
    ) -> FifthMatchOrder {
        FifthMatchOrder {
            salt: U256::from(meta),
            maker: Address::from_str(maker).unwrap(),
            signer: Address::from_str(maker).unwrap(),
            token_id,
            maker_amount: U256::from(maker_amount),
            taker_amount: U256::from(taker_amount),
            side: FifthOrderSide::Buy,
            signature_type: FifthOrderSignatureType::Eoa,
            timestamp: U256::ONE,
            metadata: B256::repeat_byte(meta),
            builder: B256::repeat_byte(builder),
            signature: vec![1],
        }
    }

    fn encode_call(active: &FifthMatchOrder, maker: &FifthMatchOrder) -> Vec<u8> {
        let active_tail = encode_order(active);
        let maker_tail = encode_order(maker);
        let mut maker_array = word(U256::ONE).to_vec();
        maker_array.extend_from_slice(&word(U256::ZERO));
        maker_array.extend_from_slice(&maker_tail);
        let active_offset = 7 * 32;
        let makers_offset = active_offset + active_tail.len();
        let fills_offset = makers_offset + maker_array.len();
        let fees_offset = fills_offset + 64;
        let mut args = Vec::new();
        args.extend_from_slice(B256::from_str(CONDITION).unwrap().as_slice());
        for value in [active_offset, makers_offset] {
            args.extend_from_slice(&word(U256::from(value)));
        }
        args.extend_from_slice(&word(U256::from(40)));
        args.extend_from_slice(&word(U256::from(fills_offset)));
        args.extend_from_slice(&word(U256::from(3)));
        args.extend_from_slice(&word(U256::from(fees_offset)));
        args.extend_from_slice(&active_tail);
        // The sole tuple offset is relative to the dynamic-array tuple-head.
        let offset_word = word(U256::from(32));
        maker_array[32..64].copy_from_slice(&offset_word);
        args.extend_from_slice(&maker_array);
        args.extend_from_slice(&word(U256::ONE));
        args.extend_from_slice(&word(U256::from(60)));
        args.extend_from_slice(&word(U256::ONE));
        args.extend_from_slice(&word(U256::ZERO));
        let mut input = MATCH_SELECTOR.to_vec();
        input.extend_from_slice(&args);
        input
    }

    fn encode_order(order: &FifthMatchOrder) -> Vec<u8> {
        let mut encoded = Vec::new();
        for value in [
            order.salt,
            U256::from_be_slice(&[0; 32]),
            U256::from_be_slice(&[0; 32]),
            order.token_id,
            order.maker_amount,
            order.taker_amount,
            U256::ZERO,
            U256::ZERO,
            order.timestamp,
            U256::from_be_bytes(order.metadata.0),
            U256::from_be_bytes(order.builder.0),
            U256::from(12 * 32),
        ] {
            encoded.extend_from_slice(&word(value));
        }
        encoded[44..64].copy_from_slice(order.maker.as_slice());
        encoded[76..96].copy_from_slice(order.signer.as_slice());
        encoded.extend_from_slice(&word(U256::ONE));
        encoded.push(1);
        encoded.resize(encoded.len().div_ceil(32) * 32, 0);
        encoded
    }

    fn transfer(asset: Address, from: Address, to: Address, amount: U256) -> Value {
        log(
            &format!("{asset:#x}"),
            vec![
                topic_hash(TRANSFER_SIGNATURE),
                topic_address(from),
                topic_address(to),
            ],
            data(&[amount]),
        )
    }

    fn approval(asset: Address, owner: Address, spender: Address) -> Value {
        log(
            &format!("{asset:#x}"),
            vec![
                topic_hash(APPROVAL_SIGNATURE),
                topic_address(owner),
                topic_address(spender),
            ],
            data(&[U256::MAX]),
        )
    }

    fn unwrapped(
        asset_address: Address,
        caller: Address,
        underlying: Address,
        to: Address,
        amount: U256,
    ) -> Value {
        log(
            &format!("{asset_address:#x}"),
            vec![
                topic_hash(UNWRAPPED_SIGNATURE),
                topic_address(caller),
                topic_address(underlying),
                topic_address(to),
            ],
            data(&[amount]),
        )
    }

    fn transfer_batch(
        ctf: Address,
        operator: Address,
        from: Address,
        to: Address,
        ids: [U256; 2],
        amounts: [U256; 2],
    ) -> Value {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&word(U256::from(64)));
        bytes.extend_from_slice(&word(U256::from(160)));
        bytes.extend_from_slice(&word(U256::from(2)));
        bytes.extend_from_slice(&word(ids[0]));
        bytes.extend_from_slice(&word(ids[1]));
        bytes.extend_from_slice(&word(U256::from(2)));
        bytes.extend_from_slice(&word(amounts[0]));
        bytes.extend_from_slice(&word(amounts[1]));
        log(
            &format!("{ctf:#x}"),
            vec![
                topic_hash(TRANSFER_BATCH_SIGNATURE),
                topic_address(operator),
                topic_address(from),
                topic_address(to),
            ],
            format!("0x{}", hex::encode(bytes)),
        )
    }

    fn ctf_position_split(
        ctf: Address,
        stakeholder: Address,
        collateral: Address,
        condition: B256,
        amount: U256,
    ) -> Value {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&word(U256::from_be_bytes(collateral.into_word().0)));
        bytes.extend_from_slice(&word(U256::from(96)));
        bytes.extend_from_slice(&word(amount));
        bytes.extend_from_slice(&word(U256::from(2)));
        bytes.extend_from_slice(&word(U256::ONE));
        bytes.extend_from_slice(&word(U256::from(2)));
        log(
            &format!("{ctf:#x}"),
            vec![
                topic_hash(CTF_POSITION_SPLIT_SIGNATURE),
                topic_address(stakeholder),
                format!("{:#x}", B256::ZERO),
                format!("{condition:#x}"),
            ],
            format!("0x{}", hex::encode(bytes)),
        )
    }

    fn legacy_position_split(
        adapter: Address,
        stakeholder: Address,
        condition: B256,
        amount: U256,
    ) -> Value {
        log(
            &format!("{adapter:#x}"),
            vec![
                topic_hash(LEGACY_POSITION_SPLIT_SIGNATURE),
                topic_address(stakeholder),
                format!("{condition:#x}"),
            ],
            data(&[amount]),
        )
    }

    fn transfer_single(
        ctf: Address,
        operator: Address,
        from: Address,
        to: Address,
        id: U256,
        amount: U256,
    ) -> Value {
        log(
            &format!("{ctf:#x}"),
            vec![
                topic_hash(TRANSFER_SINGLE_SIGNATURE),
                topic_address(operator),
                topic_address(from),
                topic_address(to),
            ],
            data(&[id, amount]),
        )
    }

    fn fee(exchange: Address, receiver: Address, amount: U256) -> Value {
        log(
            &format!("{exchange:#x}"),
            vec![topic_hash(FEE_CHARGED_SIGNATURE), topic_address(receiver)],
            data(&[amount]),
        )
    }

    fn fill(exchange: Address, fill: &FillEvent) -> Value {
        log(
            &format!("{exchange:#x}"),
            vec![
                topic_hash(ORDER_FILLED_SIGNATURE),
                format!("{:#x}", fill.hash),
                topic_address(fill.maker),
                topic_address(fill.taker),
            ],
            data(&[
                U256::from(side_word(fill.side)),
                fill.token_id,
                fill.making,
                fill.taking,
                fill.fee,
                U256::from_be_bytes(fill.builder.0),
                U256::from_be_bytes(fill.metadata.0),
            ]),
        )
    }

    fn matched(
        exchange: Address,
        hash: B256,
        taker: Address,
        id: U256,
        making: u64,
        taking: u64,
    ) -> Value {
        log(
            &format!("{exchange:#x}"),
            vec![
                topic_hash(ORDERS_MATCHED_SIGNATURE),
                format!("{hash:#x}"),
                topic_address(taker),
            ],
            data(&[U256::ZERO, id, U256::from(making), U256::from(taking)]),
        )
    }

    fn log(address: &str, topics: Vec<String>, data: String) -> Value {
        json!({"address":address,"topics":topics,"data":data})
    }

    fn topic_address(address: Address) -> String {
        format!("0x{}{}", "00".repeat(12), hex::encode(address.as_slice()))
    }

    fn word(value: U256) -> [u8; 32] {
        value.to_be_bytes()
    }

    fn data(values: &[U256]) -> String {
        format!(
            "0x{}",
            values
                .iter()
                .flat_map(|value| word(*value))
                .collect::<Vec<_>>()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    }

    fn rewrite_locator_indexes(receipt: &mut Value) {
        for (index, row) in receipt["logs"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .enumerate()
        {
            row["logIndex"] = json!(format!("0x{index:x}"));
        }
    }
}
