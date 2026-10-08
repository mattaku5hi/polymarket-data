//! Source-reconciled direct fifth Exchange matches over the docs89 interval.

use super::fifth_code_context::{EXCHANGE_PROXY, FifthExchangeImplementationVersion};
use super::fifth_legacy_binary_inventory::{
    BoundedFifthLegacyBinaryInventoryError, FifthLegacyBinaryInventoryObservation,
    FifthLegacyBinaryInventoryStatus,
};
use super::fifth_match_orders_call::{
    FifthMatchOrder, FifthMatchOrdersCall, FifthOrderSide, decode_fifth_match_orders_calldata,
    fifth_order_eip712_hash,
};
use super::{
    ChainLogAuditError, ChainLogVerifier, ChainReceiptIntervalTransaction,
    TransactionRequestBudget, validate_hex,
};
use crate::TradeSide;
use alloy_primitives::{Address, B256, U256};
use sha3::{Digest, Keccak256};
use std::{str::FromStr, time::Duration};
use thiserror::Error;
use tokio::time::Instant;

pub const FIFTH_LEGACY_BINARY_TRADE_POLICY_VERSION: &str =
    "fifth-legacy-binary-match-orders-source-attribution/1";

const EXCHANGE_ADDRESS: &str = EXCHANGE_PROXY;
const MAX_FEE_RATE_BPS: U256 = U256::from_limbs([1_000, 0, 0, 0]);
const FEE_RECEIVER: &str = "0x115f48dc2a731aa16251c6d6e1befc42f92accc9";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedFifthLegacyBinaryTradeError {
    #[error("fifth binary trade RPC request budget exhausted")]
    RequestBudgetExceeded,
    #[error("fifth binary trade verification exceeded its total deadline")]
    Timeout,
    #[error(transparent)]
    Verification(#[from] ChainLogAuditError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthTradeBranch {
    Normal,
    Mint,
    Merge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthTradeOwnerRole {
    Maker,
    Taker,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthTradeOrderFillFact {
    order_hash: B256,
    log_index: u64,
    maker: Address,
    signer: Address,
    side: TradeSide,
    token_id: U256,
    maker_amount_filled: U256,
    taker_amount_filled: U256,
    fee_amount: U256,
    owner_role: FifthTradeOwnerRole,
}

impl FifthTradeOrderFillFact {
    #[must_use]
    pub const fn log_index(&self) -> u64 {
        self.log_index
    }

    #[must_use]
    pub const fn order_hash(&self) -> B256 {
        self.order_hash
    }
    #[must_use]
    pub const fn maker(&self) -> Address {
        self.maker
    }
    #[must_use]
    pub const fn signer(&self) -> Address {
        self.signer
    }
    #[must_use]
    pub const fn side(&self) -> TradeSide {
        self.side
    }
    #[must_use]
    pub const fn token_id(&self) -> U256 {
        self.token_id
    }
    #[must_use]
    pub const fn maker_amount_filled(&self) -> U256 {
        self.maker_amount_filled
    }
    #[must_use]
    pub const fn taker_amount_filled(&self) -> U256 {
        self.taker_amount_filled
    }
    #[must_use]
    pub const fn fee_amount(&self) -> U256 {
        self.fee_amount
    }
    #[must_use]
    pub const fn owner_role(&self) -> FifthTradeOwnerRole {
        self.owner_role
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthTradeTransactionFact {
    block_number: u64,
    block_hash: String,
    transaction_hash: String,
    transaction_index: u64,
    exchange_version: FifthExchangeImplementationVersion,
    branch: FifthTradeBranch,
    owner_position_inflows: [U256; 2],
    owner_position_outflows: [U256; 2],
    owner_pusd_inflow: U256,
    owner_pusd_outflow: U256,
    owner_fee_amount: U256,
    owner_refund_amount: U256,
    order_fills: Vec<FifthTradeOrderFillFact>,
}

impl FifthTradeTransactionFact {
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
    pub const fn exchange_version(&self) -> FifthExchangeImplementationVersion {
        self.exchange_version
    }
    #[must_use]
    pub const fn branch(&self) -> FifthTradeBranch {
        self.branch
    }
    #[must_use]
    pub const fn owner_position_inflows(&self) -> [U256; 2] {
        self.owner_position_inflows
    }
    #[must_use]
    pub const fn owner_position_outflows(&self) -> [U256; 2] {
        self.owner_position_outflows
    }
    #[must_use]
    pub const fn owner_pusd_inflow(&self) -> U256 {
        self.owner_pusd_inflow
    }
    #[must_use]
    pub const fn owner_pusd_outflow(&self) -> U256 {
        self.owner_pusd_outflow
    }
    #[must_use]
    pub const fn owner_fee_amount(&self) -> U256 {
        self.owner_fee_amount
    }
    #[must_use]
    pub const fn owner_refund_amount(&self) -> U256 {
        self.owner_refund_amount
    }
    #[must_use]
    pub fn order_fills(&self) -> &[FifthTradeOrderFillFact] {
        &self.order_fills
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthLegacyBinaryTradeUnavailableReason {
    InventoryUnreconciled,
    UnsupportedOwnerActivity,
    UnsupportedDirectCall,
    InvalidCalldata,
    SourceSettlementMismatch,
    ArithmeticUnavailable,
    UnsupportedOwnerRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FifthLegacyBinaryTradeStatus {
    Matched,
    Unavailable {
        block_number: Option<u64>,
        transaction_hash: Option<String>,
        reason: FifthLegacyBinaryTradeUnavailableReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthLegacyBinaryTradeObservation {
    inventory: FifthLegacyBinaryInventoryObservation,
    status: FifthLegacyBinaryTradeStatus,
    transactions: Vec<FifthTradeTransactionFact>,
}

impl FifthLegacyBinaryTradeObservation {
    #[must_use]
    pub const fn inventory(&self) -> &FifthLegacyBinaryInventoryObservation {
        &self.inventory
    }
    #[must_use]
    pub const fn status(&self) -> &FifthLegacyBinaryTradeStatus {
        &self.status
    }
    #[must_use]
    pub fn transactions(&self) -> &[FifthTradeTransactionFact] {
        &self.transactions
    }
    #[must_use]
    pub const fn source_policy_version(&self) -> &'static str {
        FIFTH_LEGACY_BINARY_TRADE_POLICY_VERSION
    }
}

impl ChainLogVerifier {
    #[allow(clippy::too_many_arguments)]
    pub async fn verify_fifth_legacy_binary_trade_interval_bounded(
        &self,
        owner: &str,
        legacy_condition_id: &str,
        from_block: u64,
        through_block: u64,
        expected_parent_hash: &str,
        expected_end_hash: &str,
        max_requests: usize,
        total_timeout: Duration,
    ) -> Result<FifthLegacyBinaryTradeObservation, BoundedFifthLegacyBinaryTradeError> {
        let owner = validate_hex(owner, 20).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let owner_bytes = hex::decode(&owner[2..]).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let legacy_condition_id = super::parse_fixed_b256(legacy_condition_id)
            .map_err(|_| ChainLogAuditError::InvalidInput)?;
        let expected_parent_hash =
            validate_hex(expected_parent_hash, 32).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let expected_end_hash =
            validate_hex(expected_end_hash, 32).map_err(|_| ChainLogAuditError::InvalidInput)?;
        if owner_bytes.iter().all(|byte| *byte == 0)
            || from_block == 0
            || from_block > through_block
            || through_block - from_block >= super::MAX_BLOCKS
            || max_requests == 0
            || total_timeout.is_zero()
        {
            return Err(ChainLogAuditError::InvalidInput.into());
        }
        let deadline = Instant::now()
            .checked_add(total_timeout)
            .ok_or(ChainLogAuditError::InvalidInput)?;
        let budget = TransactionRequestBudget::new(max_requests);
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let scoped = self.with_request_budget(budget.inner());
        let owner_address = Address::from_slice(&owner_bytes);
        let verification = scoped.verify_fifth_legacy_binary_inventory_inner(
            owner,
            owner_address,
            legacy_condition_id,
            from_block,
            through_block,
            &expected_parent_hash,
            &expected_end_hash,
            deadline,
        );
        tokio::pin!(verification);
        let deadline_wait = tokio::time::sleep_until(deadline);
        tokio::pin!(deadline_wait);
        tokio::select! {
            biased;
            _ = exhaustion.wait_for(|exhausted| *exhausted) => Err(BoundedFifthLegacyBinaryTradeError::RequestBudgetExceeded),
            () = &mut deadline_wait => if budget.is_exhausted() { Err(BoundedFifthLegacyBinaryTradeError::RequestBudgetExceeded) } else { Err(BoundedFifthLegacyBinaryTradeError::Timeout) },
            result = &mut verification => {
                if budget.is_exhausted() { Err(BoundedFifthLegacyBinaryTradeError::RequestBudgetExceeded) }
                else {
                    let classified = result
                        .map_err(map_inventory_error)
                        .and_then(|inventory| classify_inventory(inventory, owner_address, deadline));
                    if Instant::now() >= deadline {
                        Err(BoundedFifthLegacyBinaryTradeError::Timeout)
                    } else {
                        classified
                    }
                }
            }
        }
    }
}

fn map_inventory_error(
    error: BoundedFifthLegacyBinaryInventoryError,
) -> BoundedFifthLegacyBinaryTradeError {
    match error {
        BoundedFifthLegacyBinaryInventoryError::RequestBudgetExceeded => {
            BoundedFifthLegacyBinaryTradeError::RequestBudgetExceeded
        }
        BoundedFifthLegacyBinaryInventoryError::Timeout => {
            BoundedFifthLegacyBinaryTradeError::Timeout
        }
        BoundedFifthLegacyBinaryInventoryError::Verification(error) => {
            BoundedFifthLegacyBinaryTradeError::Verification(error)
        }
    }
}

fn classify_inventory(
    inventory: FifthLegacyBinaryInventoryObservation,
    owner: Address,
    deadline: Instant,
) -> Result<FifthLegacyBinaryTradeObservation, BoundedFifthLegacyBinaryTradeError> {
    if Instant::now() >= deadline {
        return Err(BoundedFifthLegacyBinaryTradeError::Timeout);
    }
    if inventory.status() != &FifthLegacyBinaryInventoryStatus::Matched {
        return Ok(unavailable(
            inventory,
            None,
            None,
            FifthLegacyBinaryTradeUnavailableReason::InventoryUnreconciled,
        ));
    }
    let mut facts = Vec::new();
    let mut refusal = None;
    for block in inventory.evidence().blocks() {
        if Instant::now() >= deadline {
            return Err(BoundedFifthLegacyBinaryTradeError::Timeout);
        }
        let point = inventory
            .block_observations()
            .iter()
            .find(|point| point.selected_balances().block_number() == block.block_number())
            .ok_or(ChainLogAuditError::Unverified)?;
        let exchange_version = point
            .selected_balances()
            .code_context()
            .exchange_implementation_version();
        for transaction in block.transactions() {
            match classify_transaction(
                transaction,
                block.block_number(),
                block.block_hash(),
                owner,
                point.v2_position_ids(),
                inventory.opening().module_proxy(),
                exchange_version,
            ) {
                TransactionClassification::Quiet => {}
                TransactionClassification::Fact(fact) => facts.push(*fact),
                TransactionClassification::Unavailable(reason) => {
                    refusal = Some((
                        block.block_number(),
                        transaction.transaction_hash().to_owned(),
                        reason,
                    ));
                    break;
                }
            }
        }
        if refusal.is_some() {
            break;
        }
    }
    if let Some((block_number, transaction_hash, reason)) = refusal {
        return Ok(unavailable(
            inventory,
            Some(block_number),
            Some(transaction_hash),
            reason,
        ));
    }
    if Instant::now() >= deadline {
        return Err(BoundedFifthLegacyBinaryTradeError::Timeout);
    }
    Ok(FifthLegacyBinaryTradeObservation {
        inventory,
        status: FifthLegacyBinaryTradeStatus::Matched,
        transactions: facts,
    })
}

fn unavailable(
    inventory: FifthLegacyBinaryInventoryObservation,
    block_number: Option<u64>,
    transaction_hash: Option<String>,
    reason: FifthLegacyBinaryTradeUnavailableReason,
) -> FifthLegacyBinaryTradeObservation {
    FifthLegacyBinaryTradeObservation {
        inventory,
        status: FifthLegacyBinaryTradeStatus::Unavailable {
            block_number,
            transaction_hash,
            reason,
        },
        transactions: Vec::new(),
    }
}

pub(super) enum TransactionClassification {
    Quiet,
    Fact(Box<FifthTradeTransactionFact>),
    Unavailable(FifthLegacyBinaryTradeUnavailableReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExpectedLog {
    Pusd {
        from: Address,
        to: Address,
        amount: U256,
    },
    Position {
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
    Filled {
        hash: B256,
        maker: Address,
        taker: Address,
        side: TradeSide,
        id: U256,
        making: U256,
        taking: U256,
        fee: U256,
        builder: B256,
        metadata: B256,
    },
    Matched {
        hash: B256,
        taker: Address,
        side: TradeSide,
        id: U256,
        making: U256,
        taking: U256,
    },
    Split {
        module: Address,
        condition: B256,
        recipient_a: Address,
        recipient_b: Address,
        amount: U256,
    },
    Merge {
        module: Address,
        condition: B256,
        recipient: Address,
        amount: U256,
    },
}

struct Settlement {
    branch: FifthTradeBranch,
    expected_logs: Vec<ExpectedLog>,
    owner_position_inflows: [U256; 2],
    owner_position_outflows: [U256; 2],
    owner_pusd_inflow: U256,
    owner_pusd_outflow: U256,
    owner_fee_amount: U256,
    owner_refund_amount: U256,
    order_fills: Vec<FifthTradeOrderFillFact>,
    owner_participates: bool,
}

pub(super) fn classify_transaction(
    transaction: &ChainReceiptIntervalTransaction,
    block_number: u64,
    block_hash: &str,
    owner: Address,
    position_ids: [B256; 2],
    module_address: Address,
    exchange_version: FifthExchangeImplementationVersion,
) -> TransactionClassification {
    let exchange_call = transaction
        .to
        .as_deref()
        .is_some_and(|to| to.eq_ignore_ascii_case(EXCHANGE_ADDRESS));
    let has_owner_activity = transaction
        .movement_observations()
        .iter()
        .any(|observation| movement_observation_mentions_owner(observation, owner, position_ids));
    let has_owner_exchange_event = transaction
        .logs()
        .iter()
        .any(|log| exchange_log_mentions_owner(log, owner));
    if transaction.status != 1 {
        return if has_owner_activity || has_owner_exchange_event {
            TransactionClassification::Unavailable(
                FifthLegacyBinaryTradeUnavailableReason::SourceSettlementMismatch,
            )
        } else {
            TransactionClassification::Quiet
        };
    }
    if !exchange_call {
        return if has_owner_activity || has_owner_exchange_event {
            TransactionClassification::Unavailable(
                FifthLegacyBinaryTradeUnavailableReason::UnsupportedOwnerActivity,
            )
        } else {
            TransactionClassification::Quiet
        };
    }
    let Some(input) = transaction.input.as_deref() else {
        return if has_owner_activity || has_owner_exchange_event {
            TransactionClassification::Unavailable(
                FifthLegacyBinaryTradeUnavailableReason::UnsupportedDirectCall,
            )
        } else {
            TransactionClassification::Quiet
        };
    };
    if !input.starts_with(&super::fifth_match_orders_call::FIFTH_MATCH_ORDERS_SELECTOR) {
        return if has_owner_activity || has_owner_exchange_event {
            TransactionClassification::Unavailable(
                FifthLegacyBinaryTradeUnavailableReason::UnsupportedDirectCall,
            )
        } else {
            TransactionClassification::Quiet
        };
    }
    if !transaction.replay_protected_sender
        || !transaction.value.is_zero()
        || transaction.recovered_from.is_none()
    {
        return TransactionClassification::Unavailable(
            FifthLegacyBinaryTradeUnavailableReason::UnsupportedDirectCall,
        );
    }
    let Some(call) = decode_fifth_match_orders_calldata(input) else {
        return TransactionClassification::Unavailable(
            FifthLegacyBinaryTradeUnavailableReason::InvalidCalldata,
        );
    };
    let Some(mut settlement) = build_settlement(&call, owner, position_ids, module_address) else {
        return TransactionClassification::Unavailable(
            FifthLegacyBinaryTradeUnavailableReason::ArithmeticUnavailable,
        );
    };
    if settlement.owner_participates && unsupported_owner_role(owner, module_address) {
        return TransactionClassification::Unavailable(
            FifthLegacyBinaryTradeUnavailableReason::UnsupportedOwnerRole,
        );
    }
    if transaction.logs().len() != settlement.expected_logs.len()
        || transaction
            .logs()
            .iter()
            .zip(&settlement.expected_logs)
            .any(|(actual, expected)| !expected.matches(actual, module_address))
    {
        return TransactionClassification::Unavailable(
            FifthLegacyBinaryTradeUnavailableReason::SourceSettlementMismatch,
        );
    }
    if !settlement.owner_participates && has_owner_activity {
        return TransactionClassification::Unavailable(
            FifthLegacyBinaryTradeUnavailableReason::UnsupportedOwnerRole,
        );
    }
    if !settlement.owner_participates {
        return TransactionClassification::Quiet;
    }
    let mut used = std::collections::BTreeSet::new();
    for fill in &mut settlement.order_fills {
        let expected_taker = match fill.owner_role {
            FifthTradeOwnerRole::Taker => Address::from_str(EXCHANGE_ADDRESS).unwrap(),
            FifthTradeOwnerRole::Maker => call.taker_order.maker,
        };
        let Some((index, _)) = settlement
            .expected_logs
            .iter()
            .enumerate()
            .find(|(index, log)| {
                !used.contains(index)
                    && matches!(log, ExpectedLog::Filled {
                    hash, maker, taker, side, id, making, taking, fee, ..
                } if *hash == fill.order_hash
                    && *maker == fill.maker
                    && *taker == expected_taker
                    && *side == fill.side
                    && *id == fill.token_id
                    && *making == fill.maker_amount_filled
                    && *taking == fill.taker_amount_filled
                    && *fee == fill.fee_amount)
            })
        else {
            return TransactionClassification::Unavailable(
                FifthLegacyBinaryTradeUnavailableReason::SourceSettlementMismatch,
            );
        };
        used.insert(index);
        fill.log_index = transaction.logs()[index].block_log_index();
    }
    TransactionClassification::Fact(Box::new(FifthTradeTransactionFact {
        block_number,
        block_hash: block_hash.to_owned(),
        transaction_hash: transaction.transaction_hash().to_owned(),
        transaction_index: transaction.transaction_index(),
        exchange_version,
        branch: settlement.branch,
        owner_position_inflows: settlement.owner_position_inflows,
        owner_position_outflows: settlement.owner_position_outflows,
        owner_pusd_inflow: settlement.owner_pusd_inflow,
        owner_pusd_outflow: settlement.owner_pusd_outflow,
        owner_fee_amount: settlement.owner_fee_amount,
        owner_refund_amount: settlement.owner_refund_amount,
        order_fills: settlement.order_fills,
    }))
}

fn unsupported_owner_role(owner: Address, module: Address) -> bool {
    owner == Address::from_str(FEE_RECEIVER).unwrap_or_default()
        || owner == module
        || owner == Address::from_str(EXCHANGE_ADDRESS).unwrap_or_default()
        || owner
            == Address::from_str(super::fifth_code_context::POSITION_MANAGER_PROXY)
                .unwrap_or_default()
        || owner
            == Address::from_str("0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb").unwrap_or_default()
}

fn movement_observation_mentions_owner(
    observation: &super::RawMovementObservation,
    owner: Address,
    position_ids: [B256; 2],
) -> bool {
    let is_pusd = observation
        .emitter()
        .eq_ignore_ascii_case("0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb");
    let is_pm = observation
        .emitter()
        .eq_ignore_ascii_case(super::fifth_code_context::POSITION_MANAGER_PROXY);
    match observation.status() {
        super::MovementObservationStatus::Unsupported(_) => is_pusd || is_pm,
        super::MovementObservationStatus::Decoded(movement) => match movement {
            super::ObservedAssetMovement::Erc20Transfer { from, to, .. } => {
                is_pusd && (address_is(from, owner) || address_is(to, owner))
            }
            super::ObservedAssetMovement::Erc1155TransferSingle { from, to, id, .. } => {
                is_pm
                    && (address_is(from, owner) || address_is(to, owner))
                    && position_ids.iter().any(|p| U256::from_be_bytes(p.0) == *id)
            }
            super::ObservedAssetMovement::Erc1155TransferBatch { from, to, ids, .. } => {
                is_pm
                    && (address_is(from, owner) || address_is(to, owner))
                    && ids
                        .iter()
                        .any(|id| position_ids.iter().any(|p| U256::from_be_bytes(p.0) == *id))
            }
        },
    }
}

fn exchange_log_mentions_owner(log: &super::ChainReceiptLog, owner: Address) -> bool {
    if !log.address().eq_ignore_ascii_case(EXCHANGE_ADDRESS) {
        return false;
    }
    let owner = format!("{owner:#x}");
    let topic = log.topics().first().map(String::as_str).unwrap_or_default();
    (topic.eq_ignore_ascii_case(&event_topic("OrderFilled(bytes32,address,address,uint8,uint256,uint256,uint256,uint256,bytes32,bytes32)"))
        && (log.topics().get(2).is_some_and(|value| topic_is_address(value, &owner))
            || log.topics().get(3).is_some_and(|value| topic_is_address(value, &owner))))
        || (topic.eq_ignore_ascii_case(&event_topic("FeeCharged(address,uint256)"))
            && log.topics().get(1).is_some_and(|value| topic_is_address(value, &owner)))
        || (topic.eq_ignore_ascii_case(&event_topic("OrdersMatched(bytes32,address,uint8,uint256,uint256,uint256)"))
            && log.topics().get(2).is_some_and(|value| topic_is_address(value, &owner)))
}

fn build_settlement(
    call: &FifthMatchOrdersCall,
    owner: Address,
    position_ids: [B256; 2],
    module: Address,
) -> Option<Settlement> {
    let taker = &call.taker_order;
    let exchange = Address::from_str(EXCHANGE_ADDRESS).ok()?;
    let fee_receiver = Address::from_str(FEE_RECEIVER).ok()?;
    let ids = position_ids.map(|id| U256::from_be_bytes(id.0));
    if taker.maker == Address::ZERO
        || taker.maker_amount.is_zero()
        || taker.taker_amount.is_zero()
        || call.taker_amounts.taker_fill_amount.is_zero()
        || call.taker_amounts.taker_fill_amount > taker.maker_amount
        || !ids.contains(&taker.token_id)
    {
        return None;
    }
    if matches!(
        taker.signature_type,
        super::fifth_match_orders_call::FifthOrderSignatureType::Eoa
            | super::fifth_match_orders_call::FifthOrderSignatureType::Poly1271
    ) && taker.maker != taker.signer
    {
        return None;
    }
    let maker_hashes = call
        .maker_orders
        .iter()
        .map(|order| fifth_order_eip712_hash(order, exchange))
        .collect::<Vec<_>>();
    let taker_hash = fifth_order_eip712_hash(taker, exchange);
    let mut takings = Vec::with_capacity(call.maker_orders.len());
    for (order, fill) in call.maker_orders.iter().zip(&call.maker_fill_amounts) {
        if order.maker == Address::ZERO
            || order.maker_amount.is_zero()
            || order.taker_amount.is_zero()
            || fill.is_zero()
            || fill > &order.maker_amount
            || !ids.contains(&order.token_id)
        {
            return None;
        }
        if matches!(
            order.signature_type,
            super::fifth_match_orders_call::FifthOrderSignatureType::Eoa
                | super::fifth_match_orders_call::FifthOrderSignatureType::Poly1271
        ) && order.maker != order.signer
        {
            return None;
        }
        takings.push(checked_mul_div(
            *fill,
            order.taker_amount,
            order.maker_amount,
        )?);
    }
    let complementary = call
        .maker_orders
        .iter()
        .all(|order| order.side != taker.side && order.token_id == taker.token_id);
    let (branch, taker_making, taker_taking, _fees, refund, logs) = if complementary {
        build_normal(
            call,
            &maker_hashes,
            &takings,
            taker_hash,
            exchange,
            fee_receiver,
        )?
    } else if taker.side == FifthOrderSide::Buy {
        build_batch_buy(
            call,
            &maker_hashes,
            &takings,
            taker_hash,
            position_ids,
            module,
            exchange,
            fee_receiver,
        )?
    } else {
        build_batch_sell(
            call,
            &maker_hashes,
            &takings,
            taker_hash,
            position_ids,
            module,
            exchange,
            fee_receiver,
        )?
    };
    if !exchange_net_is_zero(&logs, exchange, ids)? {
        return None;
    }
    let taker_cash_basis = if taker.side == FifthOrderSide::Buy {
        taker_making
    } else {
        taker_taking
    };
    if !fee_within_cap(call.taker_amounts.taker_fee_amount, taker_cash_basis)? {
        return None;
    }
    let mut owner_position_inflows = [U256::ZERO; 2];
    let mut owner_position_outflows = [U256::ZERO; 2];
    let mut owner_pusd_inflow = U256::ZERO;
    let mut owner_pusd_outflow = U256::ZERO;
    let mut order_fills = Vec::new();
    let mut owner_fee_amount = U256::ZERO;
    let owner_is_taker = taker.maker == owner;
    if owner_is_taker {
        owner_fee_amount = call.taker_amounts.taker_fee_amount;
        order_fills.push(order_fact(
            taker,
            taker_hash,
            taker_making,
            taker_taking,
            call.taker_amounts.taker_fee_amount,
            FifthTradeOwnerRole::Taker,
        ));
    }
    for (index, order) in call.maker_orders.iter().enumerate() {
        let taking = takings[index];
        let fill = call.maker_fill_amounts[index];
        let fee = call.maker_fee_amounts[index];
        if !fee_within_cap(
            fee,
            if order.side == FifthOrderSide::Buy {
                fill
            } else {
                taking
            },
        )? || (order.side == FifthOrderSide::Sell && fee > taking)
        {
            return None;
        }
        if order.maker == owner {
            owner_fee_amount = owner_fee_amount.checked_add(fee)?;
            order_fills.push(order_fact(
                order,
                maker_hashes[index],
                fill,
                taking,
                fee,
                FifthTradeOwnerRole::Maker,
            ));
        }
    }
    let owner_participates = owner_is_taker
        || order_fills
            .iter()
            .any(|fill| fill.owner_role == FifthTradeOwnerRole::Maker);
    if owner_participates {
        for log in &logs {
            match log {
                ExpectedLog::Position {
                    from,
                    to,
                    id,
                    amount,
                    ..
                } if *from != *to => {
                    if *to == owner {
                        add_asset_flow(&mut owner_position_inflows, *id, *amount, ids)?;
                    }
                    if *from == owner {
                        add_asset_flow(&mut owner_position_outflows, *id, *amount, ids)?;
                    }
                }
                ExpectedLog::Pusd { from, to, amount } if *from != *to => {
                    if *to == owner {
                        owner_pusd_inflow = owner_pusd_inflow.checked_add(*amount)?;
                    }
                    if *from == owner {
                        owner_pusd_outflow = owner_pusd_outflow.checked_add(*amount)?;
                    }
                }
                _ => {}
            }
        }
    }
    Some(Settlement {
        branch,
        expected_logs: logs,
        owner_position_inflows,
        owner_position_outflows,
        owner_pusd_inflow,
        owner_pusd_outflow,
        owner_fee_amount,
        owner_refund_amount: if owner_is_taker { refund } else { U256::ZERO },
        order_fills,
        owner_participates,
    })
}

fn order_fact(
    order: &FifthMatchOrder,
    hash: B256,
    making: U256,
    taking: U256,
    fee: U256,
    role: FifthTradeOwnerRole,
) -> FifthTradeOrderFillFact {
    FifthTradeOrderFillFact {
        order_hash: hash,
        // Filled from the exact matched receipt before a public fact is returned.
        log_index: 0,
        maker: order.maker,
        signer: order.signer,
        side: if order.side == FifthOrderSide::Buy {
            TradeSide::Buy
        } else {
            TradeSide::Sell
        },
        token_id: order.token_id,
        maker_amount_filled: making,
        taker_amount_filled: taking,
        fee_amount: fee,
        owner_role: role,
    }
}

fn build_normal(
    call: &FifthMatchOrdersCall,
    maker_hashes: &[B256],
    takings: &[U256],
    taker_hash: B256,
    exchange: Address,
    fee_receiver: Address,
) -> Option<(FifthTradeBranch, U256, U256, U256, U256, Vec<ExpectedLog>)> {
    let taker = &call.taker_order;
    let mut logs = Vec::new();
    let mut taker_making = U256::ZERO;
    let mut taker_taking = U256::ZERO;
    let mut total_fees = call.taker_amounts.taker_fee_amount;
    let any_fees = call.taker_amounts.taker_fee_amount > U256::ZERO
        || call.maker_fee_amounts.iter().any(|fee| *fee > U256::ZERO);
    for index in 0..call.maker_orders.len() {
        let maker = &call.maker_orders[index];
        let fill = call.maker_fill_amounts[index];
        let taking = takings[index];
        let fee = call.maker_fee_amounts[index];
        if !crosses(taker, maker)? {
            return None;
        }
        let hash = maker_hashes[index];
        total_fees = total_fees.checked_add(fee)?;
        taker_making = taker_making.checked_add(taking)?;
        taker_taking = taker_taking.checked_add(fill)?;
        if taker.side == FifthOrderSide::Buy {
            logs.push(ExpectedLog::Position {
                operator: exchange,
                from: maker.maker,
                to: taker.maker,
                id: maker.token_id,
                amount: fill,
            });
            logs.push(ExpectedLog::Pusd {
                from: taker.maker,
                to: maker.maker,
                amount: taking.checked_sub(fee)?,
            });
            logs.push(fill_log(hash, maker, taker.maker, fill, taking, fee));
            if fee > U256::ZERO {
                logs.push(ExpectedLog::Fee {
                    receiver: fee_receiver,
                    amount: fee,
                });
            }
        } else if any_fees {
            logs.push(fill_log(hash, maker, taker.maker, fill, taking, fee));
            logs.push(ExpectedLog::Pusd {
                from: maker.maker,
                to: exchange,
                amount: fill.checked_add(fee)?,
            });
            logs.push(ExpectedLog::Position {
                operator: exchange,
                from: taker.maker,
                to: maker.maker,
                id: taker.token_id,
                amount: taking,
            });
            if fee > U256::ZERO {
                logs.push(ExpectedLog::Fee {
                    receiver: fee_receiver,
                    amount: fee,
                });
            }
        } else {
            logs.push(ExpectedLog::Position {
                operator: exchange,
                from: taker.maker,
                to: maker.maker,
                id: taker.token_id,
                amount: taking,
            });
            logs.push(ExpectedLog::Pusd {
                from: maker.maker,
                to: taker.maker,
                amount: fill,
            });
            logs.push(fill_log(hash, maker, taker.maker, fill, taking, U256::ZERO));
        }
    }
    if taker_making > call.taker_amounts.taker_fill_amount
        || taker_taking != call.taker_amounts.taker_receive_amount
    {
        return None;
    }
    let min_take = checked_mul_div(taker_making, taker.taker_amount, taker.maker_amount)?;
    if taker_taking < min_take {
        return None;
    }
    let refund = U256::ZERO;
    if taker.side == FifthOrderSide::Buy {
        if call.taker_amounts.taker_fee_amount > U256::ZERO {
            logs.push(ExpectedLog::Fee {
                receiver: fee_receiver,
                amount: call.taker_amounts.taker_fee_amount,
            });
        }
        if total_fees > U256::ZERO {
            logs.push(ExpectedLog::Pusd {
                from: taker.maker,
                to: fee_receiver,
                amount: total_fees,
            });
        }
    } else if any_fees {
        logs.push(ExpectedLog::Pusd {
            from: exchange,
            to: taker.maker,
            amount: taker_taking.checked_sub(call.taker_amounts.taker_fee_amount)?,
        });
        if call.taker_amounts.taker_fee_amount > U256::ZERO {
            logs.push(ExpectedLog::Fee {
                receiver: fee_receiver,
                amount: call.taker_amounts.taker_fee_amount,
            });
        }
        if total_fees > U256::ZERO {
            logs.push(ExpectedLog::Pusd {
                from: exchange,
                to: fee_receiver,
                amount: total_fees,
            });
        }
    }
    logs.push(fill_log(
        taker_hash,
        taker,
        exchange,
        taker_making,
        taker_taking,
        call.taker_amounts.taker_fee_amount,
    ));
    logs.push(matched_log(taker_hash, taker, taker_making, taker_taking));
    Some((
        FifthTradeBranch::Normal,
        taker_making,
        taker_taking,
        total_fees,
        refund,
        logs,
    ))
}

#[allow(clippy::needless_range_loop, clippy::too_many_arguments)]
fn build_batch_buy(
    call: &FifthMatchOrdersCall,
    maker_hashes: &[B256],
    takings: &[U256],
    taker_hash: B256,
    position_ids: [B256; 2],
    module: Address,
    exchange: Address,
    fee_receiver: Address,
) -> Option<(FifthTradeBranch, U256, U256, U256, U256, Vec<ExpectedLog>)> {
    let taker = &call.taker_order;
    let mut logs = vec![ExpectedLog::Pusd {
        from: taker.maker,
        to: exchange,
        amount: call
            .taker_amounts
            .taker_fill_amount
            .checked_add(call.taker_amounts.taker_fee_amount)?,
    }];
    let ids = position_ids.map(|id| U256::from_be_bytes(id.0));
    let other = if taker.token_id == ids[0] {
        ids[1]
    } else if taker.token_id == ids[1] {
        ids[0]
    } else {
        return None;
    };
    let mut total_mint = U256::ZERO;
    let mut taker_token_in = U256::ZERO;
    let mut total_collateral_in = call
        .taker_amounts
        .taker_fill_amount
        .checked_add(call.taker_amounts.taker_fee_amount)?;
    let mut sell_maker_net_out = U256::ZERO;
    let mut total_fees = call.taker_amounts.taker_fee_amount;
    for index in 0..call.maker_orders.len() {
        let maker = &call.maker_orders[index];
        let fill = call.maker_fill_amounts[index];
        let taking = takings[index];
        let fee = call.maker_fee_amounts[index];
        if !valid_batch_pair(taker, maker, ids)? {
            return None;
        }
        total_fees = total_fees.checked_add(fee)?;
        if maker.side == FifthOrderSide::Buy {
            total_collateral_in = total_collateral_in.checked_add(fill.checked_add(fee)?)?;
            total_mint = total_mint.checked_add(taking)?;
            logs.push(ExpectedLog::Pusd {
                from: maker.maker,
                to: exchange,
                amount: fill.checked_add(fee)?,
            });
        } else {
            taker_token_in = taker_token_in.checked_add(fill)?;
            logs.push(ExpectedLog::Position {
                operator: exchange,
                from: maker.maker,
                to: exchange,
                id: maker.token_id,
                amount: fill,
            });
        }
        logs.push(fill_log(
            maker_hashes[index],
            maker,
            taker.maker,
            fill,
            taking,
            fee,
        ));
    }
    if total_mint > U256::ZERO {
        logs.push(ExpectedLog::Pusd {
            from: exchange,
            to: module,
            amount: total_mint,
        });
        logs.push(ExpectedLog::Position {
            operator: module,
            from: Address::ZERO,
            to: exchange,
            id: ids[0],
            amount: total_mint,
        });
        logs.push(ExpectedLog::Position {
            operator: module,
            from: Address::ZERO,
            to: exchange,
            id: ids[1],
            amount: total_mint,
        });
        logs.push(ExpectedLog::Pusd {
            from: module,
            to: Address::ZERO,
            amount: total_mint,
        });
        logs.push(ExpectedLog::Split {
            module,
            condition: B256::from_slice(&ids[0].to_be_bytes::<32>()),
            recipient_a: exchange,
            recipient_b: exchange,
            amount: total_mint,
        });
    }
    for index in 0..call.maker_orders.len() {
        let maker = &call.maker_orders[index];
        let taking = takings[index];
        let fee = call.maker_fee_amounts[index];
        if maker.side == FifthOrderSide::Sell {
            if fee > taking {
                return None;
            }
            sell_maker_net_out = sell_maker_net_out.checked_add(taking.checked_sub(fee)?)?;
            logs.push(ExpectedLog::Pusd {
                from: exchange,
                to: maker.maker,
                amount: taking.checked_sub(fee)?,
            });
        } else {
            logs.push(ExpectedLog::Position {
                operator: exchange,
                from: exchange,
                to: maker.maker,
                id: other,
                amount: taking,
            });
        }
        if fee > U256::ZERO {
            logs.push(ExpectedLog::Fee {
                receiver: fee_receiver,
                amount: fee,
            });
        }
    }
    let taker_taking = taker_token_in.checked_add(total_mint)?;
    if taker_taking != call.taker_amounts.taker_receive_amount {
        return None;
    }
    logs.push(ExpectedLog::Position {
        operator: exchange,
        from: exchange,
        to: taker.maker,
        id: taker.token_id,
        amount: taker_taking,
    });
    let refund = total_collateral_in
        .checked_sub(total_mint)?
        .checked_sub(sell_maker_net_out)?
        .checked_sub(total_fees)?;
    if refund > call.taker_amounts.taker_fill_amount {
        return None;
    }
    let taker_making = call.taker_amounts.taker_fill_amount.checked_sub(refund)?;
    if total_fees > U256::ZERO {
        logs.push(ExpectedLog::Pusd {
            from: exchange,
            to: fee_receiver,
            amount: total_fees,
        });
    }
    if refund > U256::ZERO {
        logs.push(ExpectedLog::Pusd {
            from: exchange,
            to: taker.maker,
            amount: refund,
        });
    }
    if call.taker_amounts.taker_fee_amount > U256::ZERO {
        logs.push(ExpectedLog::Fee {
            receiver: fee_receiver,
            amount: call.taker_amounts.taker_fee_amount,
        });
    }
    logs.push(fill_log(
        taker_hash,
        taker,
        exchange,
        taker_making,
        taker_taking,
        call.taker_amounts.taker_fee_amount,
    ));
    logs.push(matched_log(taker_hash, taker, taker_making, taker_taking));
    Some((
        FifthTradeBranch::Mint,
        taker_making,
        taker_taking,
        total_fees,
        refund,
        logs,
    ))
}

#[allow(clippy::needless_range_loop, clippy::too_many_arguments)]
fn build_batch_sell(
    call: &FifthMatchOrdersCall,
    maker_hashes: &[B256],
    takings: &[U256],
    taker_hash: B256,
    position_ids: [B256; 2],
    module: Address,
    exchange: Address,
    fee_receiver: Address,
) -> Option<(FifthTradeBranch, U256, U256, U256, U256, Vec<ExpectedLog>)> {
    let taker = &call.taker_order;
    let ids = position_ids.map(|id| U256::from_be_bytes(id.0));
    if taker.token_id != ids[0] && taker.token_id != ids[1] {
        return None;
    }
    let mut logs = Vec::new();
    let mut remaining = call.taker_amounts.taker_fill_amount;
    let mut merge_amount = U256::ZERO;
    let mut collateral_in = U256::ZERO;
    let mut sell_net_out = U256::ZERO;
    let mut maker_fees = U256::ZERO;
    for index in 0..call.maker_orders.len() {
        let maker = &call.maker_orders[index];
        let fill = call.maker_fill_amounts[index];
        let taking = takings[index];
        let fee = call.maker_fee_amounts[index];
        if !valid_batch_pair(taker, maker, ids)? {
            return None;
        }
        maker_fees = maker_fees.checked_add(fee)?;
        if maker.side == FifthOrderSide::Buy {
            remaining = remaining.checked_sub(taking)?;
            collateral_in = collateral_in.checked_add(fill.checked_add(fee)?)?;
            logs.push(ExpectedLog::Pusd {
                from: maker.maker,
                to: exchange,
                amount: fill.checked_add(fee)?,
            });
        } else {
            remaining = remaining.checked_sub(fill)?;
            merge_amount = merge_amount.checked_add(fill)?;
            logs.push(ExpectedLog::Position {
                operator: exchange,
                from: maker.maker,
                to: module,
                id: maker.token_id,
                amount: fill,
            });
        }
        logs.push(fill_log(
            maker_hashes[index],
            maker,
            taker.maker,
            fill,
            taking,
            fee,
        ));
    }
    if remaining != U256::ZERO || merge_amount.is_zero() {
        return None;
    }
    logs.push(ExpectedLog::Position {
        operator: exchange,
        from: taker.maker,
        to: module,
        id: taker.token_id,
        amount: merge_amount,
    });
    collateral_in = collateral_in.checked_add(merge_amount)?;
    logs.push(ExpectedLog::Pusd {
        from: Address::ZERO,
        to: exchange,
        amount: merge_amount,
    });
    logs.push(ExpectedLog::Position {
        operator: module,
        from: module,
        to: Address::ZERO,
        id: ids[0],
        amount: merge_amount,
    });
    logs.push(ExpectedLog::Position {
        operator: module,
        from: module,
        to: Address::ZERO,
        id: ids[1],
        amount: merge_amount,
    });
    logs.push(ExpectedLog::Merge {
        module,
        condition: B256::from_slice(&ids[0].to_be_bytes::<32>()),
        recipient: exchange,
        amount: merge_amount,
    });
    for index in 0..call.maker_orders.len() {
        let maker = &call.maker_orders[index];
        let taking = takings[index];
        let fee = call.maker_fee_amounts[index];
        if maker.side == FifthOrderSide::Buy {
            logs.push(ExpectedLog::Position {
                operator: exchange,
                from: taker.maker,
                to: maker.maker,
                id: taker.token_id,
                amount: taking,
            });
        } else {
            if fee > taking {
                return None;
            }
            let net = taking.checked_sub(fee)?;
            sell_net_out = sell_net_out.checked_add(net)?;
            logs.push(ExpectedLog::Pusd {
                from: exchange,
                to: maker.maker,
                amount: net,
            });
        }
        if fee > U256::ZERO {
            logs.push(ExpectedLog::Fee {
                receiver: fee_receiver,
                amount: fee,
            });
        }
    }
    let taker_taking = collateral_in
        .checked_sub(sell_net_out)?
        .checked_sub(maker_fees)?;
    if taker_taking != call.taker_amounts.taker_receive_amount
        || call.taker_amounts.taker_fee_amount > taker_taking
    {
        return None;
    }
    let taker_net = taker_taking.checked_sub(call.taker_amounts.taker_fee_amount)?;
    let total_fees = maker_fees.checked_add(call.taker_amounts.taker_fee_amount)?;
    logs.push(ExpectedLog::Pusd {
        from: exchange,
        to: taker.maker,
        amount: taker_net,
    });
    if total_fees > U256::ZERO {
        logs.push(ExpectedLog::Pusd {
            from: exchange,
            to: fee_receiver,
            amount: total_fees,
        });
    }
    if call.taker_amounts.taker_fee_amount > U256::ZERO {
        logs.push(ExpectedLog::Fee {
            receiver: fee_receiver,
            amount: call.taker_amounts.taker_fee_amount,
        });
    }
    logs.push(fill_log(
        taker_hash,
        taker,
        exchange,
        call.taker_amounts.taker_fill_amount,
        taker_taking,
        call.taker_amounts.taker_fee_amount,
    ));
    logs.push(matched_log(
        taker_hash,
        taker,
        call.taker_amounts.taker_fill_amount,
        taker_taking,
    ));
    Some((
        FifthTradeBranch::Merge,
        call.taker_amounts.taker_fill_amount,
        taker_taking,
        total_fees,
        U256::ZERO,
        logs,
    ))
}

fn valid_batch_pair(
    taker: &FifthMatchOrder,
    maker: &FifthMatchOrder,
    ids: [U256; 2],
) -> Option<bool> {
    let taker_index = ids.iter().position(|id| *id == taker.token_id)?;
    let maker_index = ids.iter().position(|id| *id == maker.token_id)?;
    if taker.side == FifthOrderSide::Buy {
        if maker.side == FifthOrderSide::Sell {
            if taker.token_id != maker.token_id {
                return Some(false);
            }
            return Some(
                checked_mul(taker.maker_amount, maker.maker_amount)?
                    >= checked_mul(taker.taker_amount, maker.taker_amount)?,
            );
        }
        if maker_index == taker_index {
            return Some(false);
        }
        let left = checked_mul(taker.taker_amount, maker.maker_amount)?
            .checked_add(checked_mul(maker.taker_amount, taker.maker_amount)?)?;
        Some(left >= checked_mul(taker.taker_amount, maker.taker_amount)?)
    } else if maker.side == FifthOrderSide::Buy {
        if taker.token_id != maker.token_id {
            return Some(false);
        }
        Some(
            checked_mul(taker.maker_amount, maker.maker_amount)?
                >= checked_mul(taker.taker_amount, maker.taker_amount)?,
        )
    } else {
        if maker_index == taker_index {
            return Some(false);
        }
        let left = checked_mul(taker.taker_amount, maker.maker_amount)?
            .checked_add(checked_mul(maker.taker_amount, taker.maker_amount)?)?;
        Some(left <= checked_mul(taker.maker_amount, maker.maker_amount)?)
    }
}

fn crosses(taker: &FifthMatchOrder, maker: &FifthMatchOrder) -> Option<bool> {
    Some(
        checked_mul(taker.maker_amount, maker.maker_amount)?
            >= checked_mul(taker.taker_amount, maker.taker_amount)?,
    )
}

fn fee_within_cap(fee: U256, cash: U256) -> Option<bool> {
    Some(fee <= checked_mul(cash, MAX_FEE_RATE_BPS)?.checked_div(U256::from(10_000_u64))?)
}

fn checked_mul_div(left: U256, right: U256, denominator: U256) -> Option<U256> {
    if denominator.is_zero() {
        return None;
    }
    checked_mul(left, right)?.checked_div(denominator)
}

fn checked_mul(left: U256, right: U256) -> Option<U256> {
    left.checked_mul(right)
}

fn add_asset_flow(flows: &mut [U256; 2], id: U256, amount: U256, ids: [U256; 2]) -> Option<()> {
    let index = ids.iter().position(|candidate| *candidate == id)?;
    flows[index] = flows[index].checked_add(amount)?;
    Some(())
}

fn exchange_net_is_zero(logs: &[ExpectedLog], exchange: Address, ids: [U256; 2]) -> Option<bool> {
    let mut position_in = [U256::ZERO; 2];
    let mut position_out = [U256::ZERO; 2];
    let mut cash_in = U256::ZERO;
    let mut cash_out = U256::ZERO;
    for log in logs {
        match log {
            ExpectedLog::Position {
                from,
                to,
                id,
                amount,
                ..
            } if *from != *to => {
                if *to == exchange {
                    add_asset_flow(&mut position_in, *id, *amount, ids)?;
                }
                if *from == exchange {
                    add_asset_flow(&mut position_out, *id, *amount, ids)?;
                }
            }
            ExpectedLog::Pusd { from, to, amount } if *from != *to => {
                if *to == exchange {
                    cash_in = cash_in.checked_add(*amount)?;
                }
                if *from == exchange {
                    cash_out = cash_out.checked_add(*amount)?;
                }
            }
            _ => {}
        }
    }
    Some(position_in == position_out && cash_in == cash_out)
}

fn fill_log(
    hash: B256,
    order: &FifthMatchOrder,
    taker: Address,
    making: U256,
    taking: U256,
    fee: U256,
) -> ExpectedLog {
    ExpectedLog::Filled {
        hash,
        maker: order.maker,
        taker,
        side: match order.side {
            FifthOrderSide::Buy => TradeSide::Buy,
            FifthOrderSide::Sell => TradeSide::Sell,
        },
        id: order.token_id,
        making,
        taking,
        fee,
        builder: order.builder,
        metadata: order.metadata,
    }
}

fn matched_log(hash: B256, order: &FifthMatchOrder, making: U256, taking: U256) -> ExpectedLog {
    ExpectedLog::Matched {
        hash,
        taker: order.maker,
        side: match order.side {
            FifthOrderSide::Buy => TradeSide::Buy,
            FifthOrderSide::Sell => TradeSide::Sell,
        },
        id: order.token_id,
        making,
        taking,
    }
}

impl ExpectedLog {
    fn matches(&self, log: &super::ChainReceiptLog, module: Address) -> bool {
        let topic = |signature: &str| event_topic(signature);
        match self {
            Self::Pusd { from, to, amount } => {
                log.address()
                    .eq_ignore_ascii_case("0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb")
                    && log.topics()
                        == [
                            topic("Transfer(address,address,uint256)"),
                            topic_address_word(*from),
                            topic_address_word(*to),
                        ]
                    && log.data().eq_ignore_ascii_case(&data_words(&[*amount]))
            }
            Self::Position {
                operator,
                from,
                to,
                id,
                amount,
            } => {
                log.address()
                    .eq_ignore_ascii_case(super::fifth_code_context::POSITION_MANAGER_PROXY)
                    && log.topics()
                        == [
                            topic("TransferSingle(address,address,address,uint256,uint256)"),
                            topic_address_word(*operator),
                            topic_address_word(*from),
                            topic_address_word(*to),
                        ]
                    && log
                        .data()
                        .eq_ignore_ascii_case(&data_words(&[*id, *amount]))
            }
            Self::Fee { receiver, amount } => {
                log.address().eq_ignore_ascii_case(EXCHANGE_ADDRESS)
                    && log.topics()
                        == [
                            topic("FeeCharged(address,uint256)"),
                            topic_address_word(*receiver),
                        ]
                    && log.data().eq_ignore_ascii_case(&data_words(&[*amount]))
            }
            Self::Filled {
                hash,
                maker,
                taker,
                side,
                id,
                making,
                taking,
                fee,
                builder,
                metadata,
            } => {
                log.address().eq_ignore_ascii_case(EXCHANGE_ADDRESS)
                    && log.topics()
                        == [
                            topic(
                                "OrderFilled(bytes32,address,address,uint8,uint256,uint256,uint256,uint256,bytes32,bytes32)",
                            ),
                            format!("{hash:#x}"),
                            topic_address_word(*maker),
                            topic_address_word(*taker),
                        ]
                    && log.data().eq_ignore_ascii_case(&data_words(&[
                        U256::from(side_word(*side)),
                        *id,
                        *making,
                        *taking,
                        *fee,
                        U256::from_be_bytes(builder.0),
                        U256::from_be_bytes(metadata.0),
                    ]))
            }
            Self::Matched {
                hash,
                taker,
                side,
                id,
                making,
                taking,
            } => {
                log.address().eq_ignore_ascii_case(EXCHANGE_ADDRESS)
                    && log.topics()
                        == [
                            topic("OrdersMatched(bytes32,address,uint8,uint256,uint256,uint256)"),
                            format!("{hash:#x}"),
                            topic_address_word(*taker),
                        ]
                    && log.data().eq_ignore_ascii_case(&data_words(&[
                        U256::from(side_word(*side)),
                        *id,
                        *making,
                        *taking,
                    ]))
            }
            Self::Split {
                module: expected_module,
                condition,
                recipient_a,
                recipient_b,
                amount,
            } => {
                log.address()
                    .eq_ignore_ascii_case(&format!("{expected_module:#x}"))
                    && *expected_module == module
                    && log.topics()
                        == [
                            topic("PositionsSplit(address,bytes31,address,address,uint256)"),
                            topic_address_word(
                                Address::from_str(EXCHANGE_ADDRESS).unwrap_or_default(),
                            ),
                            format!("{condition:#x}"),
                            topic_address_word(*recipient_a),
                        ]
                    && log.data().eq_ignore_ascii_case(&data_words(&[
                        U256::from_be_slice(recipient_b.as_slice()),
                        *amount,
                    ]))
            }
            Self::Merge {
                module: expected_module,
                condition,
                recipient,
                amount,
            } => {
                log.address()
                    .eq_ignore_ascii_case(&format!("{expected_module:#x}"))
                    && *expected_module == module
                    && log.topics()
                        == [
                            topic("PositionsMerged(address,bytes31,address,uint256)"),
                            topic_address_word(
                                Address::from_str(EXCHANGE_ADDRESS).unwrap_or_default(),
                            ),
                            format!("{condition:#x}"),
                            topic_address_word(*recipient),
                        ]
                    && log.data().eq_ignore_ascii_case(&data_words(&[*amount]))
            }
        }
    }
}

fn side_word(side: TradeSide) -> u8 {
    if side == TradeSide::Buy { 0 } else { 1 }
}
fn event_topic(signature: &str) -> String {
    format!("0x{}", hex::encode(Keccak256::digest(signature.as_bytes())))
}
fn topic_address_word(address: Address) -> String {
    format!("0x{}{}", "00".repeat(12), hex::encode(address.as_slice()))
}
fn data_words(words: &[U256]) -> String {
    format!(
        "0x{}",
        words
            .iter()
            .map(|word| hex::encode(word.to_be_bytes::<32>()))
            .collect::<String>()
    )
}
fn address_is(value: &str, address: Address) -> bool {
    value.eq_ignore_ascii_case(&format!("{address:#x}"))
}
fn topic_is_address(topic: &str, address: &str) -> bool {
    topic.len() == 66
        && topic[2..26].bytes().all(|byte| byte == b'0')
        && topic[26..].eq_ignore_ascii_case(address.trim_start_matches("0x"))
}

#[cfg(test)]
pub(super) mod tests {
    use super::{TransactionClassification, classify_transaction, event_topic};
    use crate::chain_log_audit::{
        ChainReceiptIntervalTransaction, FifthExchangeImplementationVersion,
        encode_signed_transaction_with_sender_recovery, fifth_code_context,
        fifth_match_orders_call, parse_fixed_b256,
        receipt_tests::{fifth_normal_buy_source_fixture, signed_polygon_transaction_with_key},
    };
    use alloy_primitives::{Address, B256, U256};
    use serde_json::Value;
    use std::str::FromStr;

    fn native_pair() -> [B256; 2] {
        let vectors: Value = serde_json::from_str(include_str!(
            "artifacts/fifth-native-binary-source-vectors.json"
        ))
        .unwrap();
        [
            parse_fixed_b256(vectors["vectors"][1]["position_ids"][0].as_str().unwrap()).unwrap(),
            parse_fixed_b256(vectors["vectors"][1]["position_ids"][1].as_str().unwrap()).unwrap(),
        ]
    }

    pub(in crate::chain_log_audit) fn native_pair_source_trade()
    -> (ChainReceiptIntervalTransaction, Address, [B256; 2]) {
        let (source_transaction, owner, mut logs) = fifth_normal_buy_source_fixture();
        let owner = Address::from_str(&owner).unwrap();
        let original_input = hex::decode(
            source_transaction["input"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
        )
        .unwrap();
        let mut call =
            fifth_match_orders_call::decode_fifth_match_orders_calldata(&original_input).unwrap();
        let exchange = Address::from_str(fifth_code_context::EXCHANGE_PROXY).unwrap();
        let old_taker_hash =
            fifth_match_orders_call::fifth_order_eip712_hash(&call.taker_order, exchange);
        let old_maker_hash =
            fifth_match_orders_call::fifth_order_eip712_hash(&call.maker_orders[0], exchange);
        let pair = native_pair();
        call.taker_order.token_id = U256::from_be_bytes(pair[0].0);
        call.maker_orders[0].token_id = U256::from_be_bytes(pair[0].0);
        let input = fifth_match_orders_call::tests::encode_call(
            &call.taker_order,
            &call.maker_orders,
            &call.maker_fill_amounts,
            &call.maker_fee_amounts,
            call.taker_amounts,
        );
        let new_taker_hash =
            fifth_match_orders_call::fifth_order_eip712_hash(&call.taker_order, exchange);
        let new_maker_hash =
            fifth_match_orders_call::fifth_order_eip712_hash(&call.maker_orders[0], exchange);

        for log in &mut logs {
            if log.topics.first().is_some_and(|topic| {
                topic == &event_topic("TransferSingle(address,address,address,uint256,uint256)")
            }) {
                let mut data = hex::decode(log.data.strip_prefix("0x").unwrap()).unwrap();
                data[..32].copy_from_slice(&call.taker_order.token_id.to_be_bytes::<32>());
                log.data = format!("0x{}", hex::encode(data));
            } else if log.topics.first().is_some_and(|topic| {
                topic == &event_topic("OrderFilled(bytes32,address,address,uint8,uint256,uint256,uint256,uint256,bytes32,bytes32)")
            }) {
                let mut data = hex::decode(log.data.strip_prefix("0x").unwrap()).unwrap();
                data[32..64].copy_from_slice(&call.taker_order.token_id.to_be_bytes::<32>());
                log.data = format!("0x{}", hex::encode(data));
                if log.topics[1] == format!("{old_taker_hash:#x}") {
                    log.topics[1] = format!("{new_taker_hash:#x}");
                } else if log.topics[1] == format!("{old_maker_hash:#x}") {
                    log.topics[1] = format!("{new_maker_hash:#x}");
                }
            } else if log.topics.first().is_some_and(|topic| {
                topic == &event_topic("OrdersMatched(bytes32,address,uint8,uint256,uint256,uint256)")
            }) {
                let mut data = hex::decode(log.data.strip_prefix("0x").unwrap()).unwrap();
                data[32..64].copy_from_slice(&call.taker_order.token_id.to_be_bytes::<32>());
                log.data = format!("0x{}", hex::encode(data));
                log.topics[1] = format!("{new_taker_hash:#x}");
            }
        }

        let (signed_transaction, recovered_from) =
            signed_polygon_transaction_with_key(fifth_code_context::EXCHANGE_PROXY, &input, 0x42);
        assert_eq!(
            signed_transaction["from"].as_str(),
            Some(recovered_from.as_str())
        );
        let encoded_transaction =
            encode_signed_transaction_with_sender_recovery(&signed_transaction, true).unwrap();
        assert_eq!(
            encoded_transaction.recovered_sender,
            Some(Address::from_str(&recovered_from).unwrap())
        );
        assert_eq!(
            encoded_transaction.eip155_chain_id,
            Some(U256::from(137_u64))
        );
        let transaction_hash = format!("{:#x}", encoded_transaction.hash);
        for log in &mut logs {
            log.transaction_hash.clone_from(&transaction_hash);
        }
        let transaction = ChainReceiptIntervalTransaction {
            transaction_hash,
            transaction_index: logs[0].transaction_index,
            status: 1,
            receipt_type: 0,
            to: signed_transaction["to"].as_str().map(str::to_owned),
            input: Some(input),
            recovered_from: Some(recovered_from),
            value: U256::ZERO,
            replay_protected_sender: true,
            native_gas: None,
            logs,
            movement_observations: Vec::new(),
        };
        (transaction, owner, pair)
    }

    #[test]
    fn pure_trade_classifier_accepts_native_pair_and_rejects_full_width_alias() {
        let (transaction, owner, pair) = native_pair_source_trade();
        let block_hash = transaction.logs[0].block_hash.clone();
        let module = Address::repeat_byte(0x33);
        let TransactionClassification::Fact(fact) = classify_transaction(
            &transaction,
            100,
            &block_hash,
            owner,
            pair,
            module,
            FifthExchangeImplementationVersion::Current641b,
        ) else {
            panic!("source-normal trade with the full native position ID pair must classify");
        };
        assert_eq!(fact.branch(), super::FifthTradeBranch::Normal);
        assert_eq!(fact.owner_position_inflows(), [U256::from(100), U256::ZERO]);
        assert_eq!(fact.owner_pusd_outflow(), U256::from(51));
        assert_eq!(fact.order_fills().len(), 1);
        assert!(fact.order_fills().iter().all(|fill| {
            pair.iter()
                .any(|position_id| fill.token_id() == U256::from_be_bytes(position_id.0))
        }));

        let mut alias = pair;
        let mut bytes = alias[0].0;
        bytes[0] ^= 1;
        alias[0] = B256::from(bytes);
        assert!(matches!(
            classify_transaction(
                &transaction,
                100,
                &block_hash,
                owner,
                alias,
                module,
                FifthExchangeImplementationVersion::Current641b,
            ),
            TransactionClassification::Unavailable(_)
        ));
    }

    #[test]
    fn module_event_abi_goldens_match_pinned_source_vectors() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "artifacts/fifth-binary-module-source-event-vectors.json"
        ))
        .unwrap();
        let events = vectors["events"].as_array().unwrap();
        assert_eq!(events.len(), 3);
        for (name, signature, topic) in [
            (
                "PositionsSplit",
                "PositionsSplit(address,bytes31,address,address,uint256)",
                "0xb6a6b8b17a43b07b9359dd12d304e42077eede9e672f8646144842c8604582a4",
            ),
            (
                "PositionsMerged",
                "PositionsMerged(address,bytes31,address,uint256)",
                "0xf233f7be4ce81130a78e8eb2fa626497586c56094d27bfec2e196471e9c60301",
            ),
        ] {
            let event = events
                .iter()
                .find(|event| event["abi"]["name"] == name)
                .unwrap();
            assert_eq!(event["signature"], signature);
            assert_eq!(event["topic"], topic);
            assert_eq!(event["topic"], event_topic(signature));
            assert_eq!(event["abi"]["inputs"][1]["type"], "bytes31");
            assert_eq!(event["abi"]["inputs"][1]["indexed"], true);
        }
    }
}
