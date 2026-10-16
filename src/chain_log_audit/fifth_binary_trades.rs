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
use super::fifth_provider_reported_event::{
    FifthEventImplementationVersion, FifthEventObservationSource,
};
use super::{
    ChainLogAuditError, ChainLogVerifier, ChainReceiptIntervalTransaction, MAX_RESPONSE_BYTES,
    POLYGON_CHAIN_ID, TransactionRequestBudget, field, parse_hex_u64, validate_hex,
};
use crate::TradeSide;
use crate::rpc_position_history::fifth_binary_context::{
    RpcCurrentFifthBinaryContext, RpcCurrentFifthBinaryContextSource,
    RpcCurrentFifthBinaryImplementationVersion,
};
use alloy_primitives::{Address, B256, U256};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use std::{str::FromStr, time::Duration};
use thiserror::Error;
use tokio::time::Instant;

pub const FIFTH_LEGACY_BINARY_TRADE_POLICY_VERSION: &str =
    "fifth-legacy-binary-match-orders-source-attribution/1";
pub const FIFTH_PROVIDER_REPORTED_SETTLEMENT_POLICY_VERSION: &str =
    "fifth-provider-reported-current-settlement/1";

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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProviderReportedFifthSettlementError {
    #[error("provider-reported fifth settlement input is invalid")]
    InvalidInput,
    #[error("provider-reported fifth transaction is malformed or unsupported")]
    MalformedTransaction,
    #[error("provider-reported fifth receipt is malformed or unsupported")]
    MalformedReceipt,
    #[error("provider-reported fifth transaction did not reconcile to the source settlement")]
    SettlementMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderReportedFifthAsset {
    Pusd,
    Position { token_id: U256 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderReportedFifthDirection {
    Inflow,
    Outflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderReportedFifthWalletLeg {
    log_index: u64,
    from: Address,
    to: Address,
    asset: ProviderReportedFifthAsset,
    direction: ProviderReportedFifthDirection,
    amount: U256,
}

impl ProviderReportedFifthWalletLeg {
    #[must_use]
    pub const fn log_index(&self) -> u64 {
        self.log_index
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
    pub const fn asset(&self) -> ProviderReportedFifthAsset {
        self.asset
    }
    #[must_use]
    pub const fn direction(&self) -> ProviderReportedFifthDirection {
        self.direction
    }
    #[must_use]
    pub const fn amount(&self) -> U256 {
        self.amount
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderReportedFifthOwnerFill {
    log_index: u64,
    order_hash: B256,
    owner_role: FifthTradeOwnerRole,
    token_id: U256,
    side: TradeSide,
    gross_making: U256,
    gross_taking: U256,
    fee: U256,
}

impl ProviderReportedFifthOwnerFill {
    #[must_use]
    pub const fn log_index(&self) -> u64 {
        self.log_index
    }
    #[must_use]
    pub const fn order_hash(&self) -> B256 {
        self.order_hash
    }
    #[must_use]
    pub const fn owner_role(&self) -> FifthTradeOwnerRole {
        self.owner_role
    }
    #[must_use]
    pub const fn token_id(&self) -> U256 {
        self.token_id
    }
    #[must_use]
    pub const fn side(&self) -> TradeSide {
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
}

/// A one-provider transaction-level match; legs and owner fills retain raw
/// source values. Fill fees and refund metadata do not create additional legs.
/// The supplied wallet/token/module context records scope and is not itself
/// authenticated by this observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderReportedFifthSettlement {
    chain_id: u64,
    block_number: u64,
    block_hash: String,
    transaction_hash: String,
    transaction_index: u64,
    owner: String,
    position_ids: [B256; 2],
    module_address: String,
    branch: FifthTradeBranch,
    source: FifthEventObservationSource,
    implementation_version: FifthEventImplementationVersion,
    wallet_legs: Vec<ProviderReportedFifthWalletLeg>,
    owner_fills: Vec<ProviderReportedFifthOwnerFill>,
    owner_refund_amount: U256,
    owner_refund_log_index: Option<u64>,
}

impl ProviderReportedFifthSettlement {
    #[must_use]
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }
    #[must_use]
    pub const fn source_policy_version(&self) -> &'static str {
        FIFTH_PROVIDER_REPORTED_SETTLEMENT_POLICY_VERSION
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
    pub fn owner(&self) -> &str {
        &self.owner
    }
    #[must_use]
    pub const fn position_ids(&self) -> [B256; 2] {
        self.position_ids
    }
    #[must_use]
    pub fn module_address(&self) -> &str {
        &self.module_address
    }
    #[must_use]
    pub const fn branch(&self) -> FifthTradeBranch {
        self.branch
    }
    #[must_use]
    pub const fn source(&self) -> FifthEventObservationSource {
        self.source
    }
    #[must_use]
    pub const fn implementation_version(&self) -> FifthEventImplementationVersion {
        self.implementation_version
    }
    #[must_use]
    pub fn wallet_legs(&self) -> &[ProviderReportedFifthWalletLeg] {
        &self.wallet_legs
    }
    #[must_use]
    pub fn owner_fills(&self) -> &[ProviderReportedFifthOwnerFill] {
        &self.owner_fills
    }
    /// Raw refund metadata already represented by a wallet leg when nonzero.
    #[must_use]
    pub const fn owner_refund_amount(&self) -> U256 {
        self.owner_refund_amount
    }
    #[must_use]
    pub const fn owner_refund_log_index(&self) -> Option<u64> {
        self.owner_refund_log_index
    }
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

#[derive(Debug, Clone)]
struct TransactionLogView {
    block_log_index: u64,
    address: String,
    topics: Vec<String>,
    data: String,
}

struct TransactionView<'a> {
    transaction_hash: &'a str,
    transaction_index: u64,
    status: u64,
    to: Option<&'a str>,
    input: Option<&'a [u8]>,
    recovered_from: Option<&'a str>,
    value: U256,
    replay_protected_sender: bool,
    logs: &'a [TransactionLogView],
    has_owner_activity: bool,
    has_owner_exchange_event: bool,
    block_number: u64,
    block_hash: &'a str,
}

struct MatchedSettlementProjection {
    block_number: u64,
    block_hash: String,
    transaction_hash: String,
    transaction_index: u64,
    settlement: Settlement,
}

enum TransactionProjectionClassification {
    Quiet,
    Matched(Box<MatchedSettlementProjection>),
    Unavailable(FifthLegacyBinaryTradeUnavailableReason),
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
    let logs = transaction
        .logs()
        .iter()
        .map(|log| TransactionLogView {
            block_log_index: log.block_log_index(),
            address: log.address().to_owned(),
            topics: log.topics().to_vec(),
            data: log.data().to_owned(),
        })
        .collect::<Vec<_>>();
    let has_owner_activity = transaction
        .movement_observations()
        .iter()
        .any(|observation| movement_observation_mentions_owner(observation, owner, position_ids));
    let has_owner_exchange_event = logs
        .iter()
        .any(|log| exchange_log_mentions_owner_fields(log, owner));
    match classify_transaction_view(
        TransactionView {
            transaction_hash: transaction.transaction_hash(),
            transaction_index: transaction.transaction_index(),
            status: transaction.status,
            to: transaction.to.as_deref(),
            input: transaction.input.as_deref(),
            recovered_from: transaction.recovered_from.as_deref(),
            value: transaction.value,
            replay_protected_sender: transaction.replay_protected_sender,
            logs: &logs,
            has_owner_activity,
            has_owner_exchange_event,
            block_number,
            block_hash,
        },
        owner,
        position_ids,
        module_address,
    ) {
        TransactionProjectionClassification::Quiet => TransactionClassification::Quiet,
        TransactionProjectionClassification::Unavailable(reason) => {
            TransactionClassification::Unavailable(reason)
        }
        TransactionProjectionClassification::Matched(projection) => {
            let settlement = projection.settlement;
            TransactionClassification::Fact(Box::new(FifthTradeTransactionFact {
                block_number: projection.block_number,
                block_hash: projection.block_hash,
                transaction_hash: projection.transaction_hash,
                transaction_index: projection.transaction_index,
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
    }
}

fn classify_transaction_view(
    view: TransactionView<'_>,
    owner: Address,
    position_ids: [B256; 2],
    module_address: Address,
) -> TransactionProjectionClassification {
    let TransactionView {
        transaction_hash,
        transaction_index,
        status,
        to,
        input,
        recovered_from,
        value,
        replay_protected_sender,
        logs,
        has_owner_activity,
        has_owner_exchange_event,
        block_number,
        block_hash,
    } = view;
    let exchange_call = to.is_some_and(|to| to.eq_ignore_ascii_case(EXCHANGE_ADDRESS));
    if status != 1 {
        return if has_owner_activity || has_owner_exchange_event {
            TransactionProjectionClassification::Unavailable(
                FifthLegacyBinaryTradeUnavailableReason::SourceSettlementMismatch,
            )
        } else {
            TransactionProjectionClassification::Quiet
        };
    }
    if !exchange_call {
        return if has_owner_activity || has_owner_exchange_event {
            TransactionProjectionClassification::Unavailable(
                FifthLegacyBinaryTradeUnavailableReason::UnsupportedOwnerActivity,
            )
        } else {
            TransactionProjectionClassification::Quiet
        };
    }
    let Some(input) = input else {
        return if has_owner_activity || has_owner_exchange_event {
            TransactionProjectionClassification::Unavailable(
                FifthLegacyBinaryTradeUnavailableReason::UnsupportedDirectCall,
            )
        } else {
            TransactionProjectionClassification::Quiet
        };
    };
    if !input.starts_with(&super::fifth_match_orders_call::FIFTH_MATCH_ORDERS_SELECTOR) {
        return if has_owner_activity || has_owner_exchange_event {
            TransactionProjectionClassification::Unavailable(
                FifthLegacyBinaryTradeUnavailableReason::UnsupportedDirectCall,
            )
        } else {
            TransactionProjectionClassification::Quiet
        };
    }
    if !replay_protected_sender || !value.is_zero() || recovered_from.is_none() {
        return TransactionProjectionClassification::Unavailable(
            FifthLegacyBinaryTradeUnavailableReason::UnsupportedDirectCall,
        );
    }
    let Some(call) = decode_fifth_match_orders_calldata(input) else {
        return TransactionProjectionClassification::Unavailable(
            FifthLegacyBinaryTradeUnavailableReason::InvalidCalldata,
        );
    };
    let Some(mut settlement) = build_settlement(&call, owner, position_ids, module_address) else {
        return TransactionProjectionClassification::Unavailable(
            FifthLegacyBinaryTradeUnavailableReason::ArithmeticUnavailable,
        );
    };
    if settlement.owner_participates && unsupported_owner_role(owner, module_address) {
        return TransactionProjectionClassification::Unavailable(
            FifthLegacyBinaryTradeUnavailableReason::UnsupportedOwnerRole,
        );
    }
    if !super::provider_reported_transaction::match_ordered_logs(
        &settlement.expected_logs,
        logs,
        |expected, actual| expected.matches_fields(actual, module_address),
    ) {
        return TransactionProjectionClassification::Unavailable(
            FifthLegacyBinaryTradeUnavailableReason::SourceSettlementMismatch,
        );
    }
    if !settlement.owner_participates && has_owner_activity {
        return TransactionProjectionClassification::Unavailable(
            FifthLegacyBinaryTradeUnavailableReason::UnsupportedOwnerRole,
        );
    }
    if !settlement.owner_participates {
        return TransactionProjectionClassification::Quiet;
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
            return TransactionProjectionClassification::Unavailable(
                FifthLegacyBinaryTradeUnavailableReason::SourceSettlementMismatch,
            );
        };
        used.insert(index);
        fill.log_index = logs[index].block_log_index;
    }
    TransactionProjectionClassification::Matched(Box::new(MatchedSettlementProjection {
        block_number,
        block_hash: block_hash.to_owned(),
        transaction_hash: transaction_hash.to_owned(),
        transaction_index,
        settlement,
    }))
}

/// Match one provider-reported current transaction against the pinned common
/// fifth Exchange settlement model. Caller-supplied wallet/token/module context
/// is only a scope. This does not establish receipt inclusion, proxy
/// implementation, interval completeness, or canonical trade identity.
///
/// The binary pair is derived from the owner's decoded order token ids, and
/// the module address comes from the block-bound provider context reader.
pub fn decode_provider_reported_fifth_binary_settlement(
    transaction: &Value,
    receipt: &Value,
    owner: &str,
    context: &RpcCurrentFifthBinaryContext,
) -> Result<ProviderReportedFifthSettlement, ProviderReportedFifthSettlementError> {
    if context.module_id() != 1
        || context.source() != RpcCurrentFifthBinaryContextSource::ProviderReported
        || context.implementation_version() != RpcCurrentFifthBinaryImplementationVersion::Unbound
    {
        return Err(ProviderReportedFifthSettlementError::InvalidInput);
    }
    let block_number = parse_hex_u64(
        field(transaction, "blockNumber")
            .map_err(|_| ProviderReportedFifthSettlementError::MalformedTransaction)?,
    )
    .map_err(|_| ProviderReportedFifthSettlementError::MalformedTransaction)?;
    let block_hash = validate_hex(
        field(transaction, "blockHash")
            .map_err(|_| ProviderReportedFifthSettlementError::MalformedTransaction)?,
        32,
    )
    .map_err(|_| ProviderReportedFifthSettlementError::MalformedTransaction)?;
    if block_number != context.block_number() || block_hash != context.block_hash() {
        return Err(ProviderReportedFifthSettlementError::SettlementMismatch);
    }
    let owner =
        validate_hex(owner, 20).map_err(|_| ProviderReportedFifthSettlementError::InvalidInput)?;
    let owner_address = Address::from_str(&owner)
        .map_err(|_| ProviderReportedFifthSettlementError::InvalidInput)?;
    let input = field(transaction, "input")
        .map_err(|_| ProviderReportedFifthSettlementError::MalformedTransaction)?
        .strip_prefix("0x")
        .ok_or(ProviderReportedFifthSettlementError::MalformedTransaction)?;
    if input.len() > super::fifth_match_orders_call::FIFTH_MATCH_ORDERS_MAX_CALLDATA_BYTES * 2 {
        return Err(ProviderReportedFifthSettlementError::MalformedTransaction);
    }
    let input = hex::decode(input)
        .map_err(|_| ProviderReportedFifthSettlementError::MalformedTransaction)?;
    let call = decode_fifth_match_orders_calldata(&input)
        .ok_or(ProviderReportedFifthSettlementError::MalformedTransaction)?;
    let position_ids = derive_provider_reported_binary_pair(&call, owner_address)?;
    decode_provider_reported_fifth_settlement(
        transaction,
        receipt,
        &owner,
        position_ids,
        context.module_address(),
    )
}

/// Return the provider-reported block anchor for a transaction sent to the
/// fifth Exchange proxy. This only selects bounded registry-context reads;
/// the settlement decoder remains responsible for validating the call.
pub fn provider_reported_fifth_settlement_context_candidate(
    transaction: &Value,
) -> Option<(u64, String)> {
    let to = field(transaction, "to").ok()?;
    if !to.eq_ignore_ascii_case(EXCHANGE_ADDRESS) {
        return None;
    }
    let block_number = parse_hex_u64(field(transaction, "blockNumber").ok()?).ok()?;
    let block_hash = validate_hex(field(transaction, "blockHash").ok()?, 32).ok()?;
    Some((block_number, block_hash))
}

fn derive_provider_reported_binary_pair(
    call: &FifthMatchOrdersCall,
    owner: Address,
) -> Result<[B256; 2], ProviderReportedFifthSettlementError> {
    let mut prefix: Option<[u8; 31]> = None;
    for order in std::iter::once(&call.taker_order).chain(&call.maker_orders) {
        if order.maker != owner {
            continue;
        }
        let token_id = order.token_id.to_be_bytes::<32>();
        if token_id[0] != 1 || token_id[31] > 1 {
            return Err(ProviderReportedFifthSettlementError::SettlementMismatch);
        }
        let current_prefix: [u8; 31] = token_id[..31]
            .try_into()
            .map_err(|_| ProviderReportedFifthSettlementError::SettlementMismatch)?;
        if prefix.is_some_and(|previous| previous != current_prefix) {
            return Err(ProviderReportedFifthSettlementError::SettlementMismatch);
        }
        prefix = Some(current_prefix);
    }
    let prefix = prefix.ok_or(ProviderReportedFifthSettlementError::SettlementMismatch)?;
    let mut first = [0_u8; 32];
    first[..31].copy_from_slice(&prefix);
    let mut second = first;
    second[31] = 1;
    Ok([B256::from(first), B256::from(second)])
}

/// Match one provider-reported current transaction against the pinned common
/// fifth Exchange settlement model. Caller-supplied wallet/token/module context
/// is only a scope. This does not establish receipt inclusion, proxy
/// implementation, interval completeness, or canonical trade identity.
pub fn decode_provider_reported_fifth_settlement(
    transaction: &Value,
    receipt: &Value,
    owner: &str,
    position_ids: [B256; 2],
    module_address: &str,
) -> Result<ProviderReportedFifthSettlement, ProviderReportedFifthSettlementError> {
    let transaction_bytes = serde_json::to_vec(transaction)
        .map_err(|_| ProviderReportedFifthSettlementError::MalformedTransaction)?;
    let receipt_bytes = serde_json::to_vec(receipt)
        .map_err(|_| ProviderReportedFifthSettlementError::MalformedReceipt)?;
    if transaction_bytes.len() > MAX_RESPONSE_BYTES || receipt_bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ProviderReportedFifthSettlementError::InvalidInput);
    }

    let owner =
        validate_hex(owner, 20).map_err(|_| ProviderReportedFifthSettlementError::InvalidInput)?;
    let owner_address = Address::from_str(&owner)
        .map_err(|_| ProviderReportedFifthSettlementError::InvalidInput)?;
    let module_address = validate_hex(module_address, 20)
        .map_err(|_| ProviderReportedFifthSettlementError::InvalidInput)?;
    let module = Address::from_str(&module_address)
        .map_err(|_| ProviderReportedFifthSettlementError::InvalidInput)?;
    let ids = position_ids.map(|id| U256::from_be_bytes(id.0));
    if owner_address == Address::ZERO
        || module == Address::ZERO
        || ids[0].is_zero()
        || ids[1].is_zero()
        || ids[0] == ids[1]
    {
        return Err(ProviderReportedFifthSettlementError::InvalidInput);
    }

    let bound =
        super::provider_reported_transaction::bind_provider_transaction(transaction, receipt)
            .map_err(|error| {
                match error {
        super::provider_reported_transaction::ProviderTransactionBindingError::Transaction => {
            ProviderReportedFifthSettlementError::MalformedTransaction
        }
        super::provider_reported_transaction::ProviderTransactionBindingError::Receipt => {
            ProviderReportedFifthSettlementError::MalformedReceipt
        }
    }
            })?;
    let transaction_hash = bound.transaction_hash.clone();
    let block_number = bound.block_number;
    let block_hash = bound.block_hash.clone();
    let transaction_index = bound.transaction_index;
    let status = bound.status;
    let to = bound.to.clone();
    let recovered_from = format!("{:#x}", bound.recovered_from);
    let logs = bound
        .logs
        .iter()
        .map(|log| TransactionLogView {
            block_log_index: log.log_index,
            address: log.address.clone(),
            topics: log.topics.clone(),
            data: log.data.clone(),
        })
        .collect::<Vec<_>>();
    let has_owner_activity = logs
        .iter()
        .any(|log| provider_log_mentions_owner(log, owner_address, position_ids));
    let has_owner_exchange_event = logs
        .iter()
        .any(|log| exchange_log_mentions_owner_fields(log, owner_address));
    let projection = match classify_transaction_view(
        TransactionView {
            transaction_hash: &transaction_hash,
            transaction_index,
            status,
            to: Some(&to),
            input: Some(&bound.input),
            recovered_from: Some(&recovered_from),
            value: bound.value,
            replay_protected_sender: true,
            logs: &logs,
            has_owner_activity,
            has_owner_exchange_event,
            block_number,
            block_hash: &block_hash,
        },
        owner_address,
        position_ids,
        module,
    ) {
        TransactionProjectionClassification::Matched(projection) => projection,
        TransactionProjectionClassification::Quiet
        | TransactionProjectionClassification::Unavailable(_) => {
            return Err(ProviderReportedFifthSettlementError::SettlementMismatch);
        }
    };

    let settlement = projection.settlement;
    let wallet_legs = settlement
        .expected_logs
        .iter()
        .zip(&logs)
        .filter_map(|(expected, actual)| provider_wallet_leg(expected, actual, owner_address))
        .collect();
    let owner_fills = settlement
        .order_fills
        .iter()
        .map(|fill| ProviderReportedFifthOwnerFill {
            log_index: fill.log_index,
            order_hash: fill.order_hash,
            owner_role: fill.owner_role,
            token_id: fill.token_id,
            side: fill.side,
            gross_making: fill.maker_amount_filled,
            gross_taking: fill.taker_amount_filled,
            fee: fill.fee_amount,
        })
        .collect();
    let owner_refund_log_index = if settlement.owner_refund_amount.is_zero() {
        None
    } else {
        settlement
            .expected_logs
            .iter()
            .zip(&logs)
            .find_map(|(expected, actual)| match expected {
                ExpectedLog::Pusd { from, to, amount }
                    if *from == Address::from_str(EXCHANGE_ADDRESS).unwrap()
                        && *to == owner_address
                        && *amount == settlement.owner_refund_amount =>
                {
                    Some(actual.block_log_index)
                }
                _ => None,
            })
    };
    if !settlement.owner_refund_amount.is_zero() && owner_refund_log_index.is_none() {
        return Err(ProviderReportedFifthSettlementError::SettlementMismatch);
    }

    Ok(ProviderReportedFifthSettlement {
        chain_id: POLYGON_CHAIN_ID,
        block_number: projection.block_number,
        block_hash: projection.block_hash,
        transaction_hash: projection.transaction_hash,
        transaction_index: projection.transaction_index,
        owner,
        position_ids,
        module_address,
        branch: settlement.branch,
        source: FifthEventObservationSource::ProviderReported,
        implementation_version: FifthEventImplementationVersion::Unbound,
        wallet_legs,
        owner_fills,
        owner_refund_amount: settlement.owner_refund_amount,
        owner_refund_log_index,
    })
}

fn provider_wallet_leg(
    expected: &ExpectedLog,
    actual: &TransactionLogView,
    owner: Address,
) -> Option<ProviderReportedFifthWalletLeg> {
    let (asset, from, to, amount) = match expected {
        ExpectedLog::Pusd { from, to, amount } => {
            (ProviderReportedFifthAsset::Pusd, *from, *to, *amount)
        }
        ExpectedLog::Position {
            from,
            to,
            id,
            amount,
            ..
        } => (
            ProviderReportedFifthAsset::Position { token_id: *id },
            *from,
            *to,
            *amount,
        ),
        _ => return None,
    };
    let direction = if from == owner && to != owner {
        ProviderReportedFifthDirection::Outflow
    } else if to == owner && from != owner {
        ProviderReportedFifthDirection::Inflow
    } else {
        return None;
    };
    Some(ProviderReportedFifthWalletLeg {
        log_index: actual.block_log_index,
        from,
        to,
        asset,
        direction,
        amount,
    })
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
    movement_fields_mention_owner(
        observation.emitter(),
        observation.status(),
        owner,
        position_ids,
    )
}

fn movement_fields_mention_owner(
    emitter: &str,
    status: &super::MovementObservationStatus,
    owner: Address,
    position_ids: [B256; 2],
) -> bool {
    let is_pusd = emitter.eq_ignore_ascii_case("0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb");
    let is_pm = emitter.eq_ignore_ascii_case(super::fifth_code_context::POSITION_MANAGER_PROXY);
    match status {
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

fn provider_log_mentions_owner(log: &TransactionLogView, owner: Address, ids: [B256; 2]) -> bool {
    let Some(movement) = super::decode_movement_fields(&log.topics, &log.data) else {
        return false;
    };
    let status = match movement {
        Ok(movement) => super::MovementObservationStatus::Decoded(movement),
        Err(reason) => super::MovementObservationStatus::Unsupported(reason),
    };
    movement_fields_mention_owner(&log.address, &status, owner, ids)
}

fn exchange_log_mentions_owner_fields(log: &TransactionLogView, owner: Address) -> bool {
    if !log.address.eq_ignore_ascii_case(EXCHANGE_ADDRESS) {
        return false;
    }
    let owner = format!("{owner:#x}");
    let topic = log.topics.first().map(String::as_str).unwrap_or_default();
    (topic.eq_ignore_ascii_case(&event_topic("OrderFilled(bytes32,address,address,uint8,uint256,uint256,uint256,uint256,bytes32,bytes32)"))
        && (log.topics.get(2).is_some_and(|value| topic_is_address(value, &owner))
            || log.topics.get(3).is_some_and(|value| topic_is_address(value, &owner))))
        || (topic.eq_ignore_ascii_case(&event_topic("FeeCharged(address,uint256)"))
            && log.topics.get(1).is_some_and(|value| topic_is_address(value, &owner)))
        || (topic.eq_ignore_ascii_case(&event_topic("OrdersMatched(bytes32,address,uint8,uint256,uint256,uint256)"))
            && log.topics.get(2).is_some_and(|value| topic_is_address(value, &owner)))
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
    fn matches_fields(&self, log: &TransactionLogView, module: Address) -> bool {
        let topic = |signature: &str| event_topic(signature);
        match self {
            Self::Pusd { from, to, amount } => {
                log.address
                    .eq_ignore_ascii_case("0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb")
                    && log.topics.as_slice()
                        == [
                            topic("Transfer(address,address,uint256)"),
                            topic_address_word(*from),
                            topic_address_word(*to),
                        ]
                    && log.data.eq_ignore_ascii_case(&data_words(&[*amount]))
            }
            Self::Position {
                operator,
                from,
                to,
                id,
                amount,
            } => {
                log.address
                    .eq_ignore_ascii_case(super::fifth_code_context::POSITION_MANAGER_PROXY)
                    && log.topics.as_slice()
                        == [
                            topic("TransferSingle(address,address,address,uint256,uint256)"),
                            topic_address_word(*operator),
                            topic_address_word(*from),
                            topic_address_word(*to),
                        ]
                    && log.data.eq_ignore_ascii_case(&data_words(&[*id, *amount]))
            }
            Self::Fee { receiver, amount } => {
                log.address.eq_ignore_ascii_case(EXCHANGE_ADDRESS)
                    && log.topics.as_slice()
                        == [
                            topic("FeeCharged(address,uint256)"),
                            topic_address_word(*receiver),
                        ]
                    && log.data.eq_ignore_ascii_case(&data_words(&[*amount]))
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
                log.address.eq_ignore_ascii_case(EXCHANGE_ADDRESS)
                    && log.topics.as_slice()
                        == [
                            topic(
                                "OrderFilled(bytes32,address,address,uint8,uint256,uint256,uint256,uint256,bytes32,bytes32)",
                            ),
                            format!("{hash:#x}"),
                            topic_address_word(*maker),
                            topic_address_word(*taker),
                        ]
                    && log.data.eq_ignore_ascii_case(&data_words(&[
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
                log.address.eq_ignore_ascii_case(EXCHANGE_ADDRESS)
                    && log.topics.as_slice()
                        == [
                            topic("OrdersMatched(bytes32,address,uint8,uint256,uint256,uint256)"),
                            format!("{hash:#x}"),
                            topic_address_word(*taker),
                        ]
                    && log.data.eq_ignore_ascii_case(&data_words(&[
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
                log.address
                    .eq_ignore_ascii_case(&format!("{expected_module:#x}"))
                    && *expected_module == module
                    && log.topics.as_slice()
                        == [
                            topic("PositionsSplit(address,bytes31,address,address,uint256)"),
                            topic_address_word(
                                Address::from_str(EXCHANGE_ADDRESS).unwrap_or_default(),
                            ),
                            format!("{condition:#x}"),
                            topic_address_word(*recipient_a),
                        ]
                    && log.data.eq_ignore_ascii_case(&data_words(&[
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
                log.address
                    .eq_ignore_ascii_case(&format!("{expected_module:#x}"))
                    && *expected_module == module
                    && log.topics
                        == [
                            topic("PositionsMerged(address,bytes31,address,uint256)"),
                            topic_address_word(
                                Address::from_str(EXCHANGE_ADDRESS).unwrap_or_default(),
                            ),
                            format!("{condition:#x}"),
                            topic_address_word(*recipient),
                        ]
                    && log.data.eq_ignore_ascii_case(&data_words(&[*amount]))
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
    use super::{
        ProviderReportedFifthAsset, ProviderReportedFifthDirection,
        ProviderReportedFifthSettlementError, TransactionClassification, classify_transaction,
        decode_provider_reported_fifth_binary_settlement,
        decode_provider_reported_fifth_settlement, derive_provider_reported_binary_pair,
        event_topic,
    };
    use crate::chain_log_audit::{
        ChainReceiptIntervalTransaction, FifthExchangeImplementationVersion, POLYGON_CHAIN_ID,
        encode_signed_transaction_with_sender_recovery, fifth_code_context,
        fifth_match_orders_call::{
            self, FifthMatchOrder, FifthOrderSide, FifthOrderSignatureType, FifthTakerAmounts,
        },
        parse_fixed_b256, parse_hex_u64,
        receipt_tests::{fifth_normal_buy_source_fixture, signed_polygon_transaction_with_key},
    };
    use alloy_primitives::{Address, B256, U256};
    use serde_json::{Value, json};
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

    fn provider_normal_buy_fixture() -> (Value, Value, String, [B256; 2], String) {
        let (mut transaction, owner, logs) = fifth_normal_buy_source_fixture();
        let encoded = encode_signed_transaction_with_sender_recovery(&transaction, true).unwrap();
        let transaction_hash = format!("{:#x}", encoded.hash);
        let block_hash = format!("0x{}", "aa".repeat(32));
        let block_number = 100_u64;
        let transaction_index = 3_u64;
        transaction["hash"] = json!(transaction_hash);
        transaction["blockNumber"] = json!(format!("{block_number:#x}"));
        transaction["blockHash"] = json!(block_hash);
        transaction["transactionIndex"] = json!(format!("{transaction_index:#x}"));
        let receipt_logs = logs
            .iter()
            .map(|log| {
                json!({
                    "address": log.address.clone(),
                    "topics": log.topics.clone(),
                    "data": log.data.clone(),
                    "blockNumber": format!("{block_number:#x}"),
                    "blockHash": block_hash.clone(),
                    "transactionHash": transaction_hash.clone(),
                    "transactionIndex": format!("{transaction_index:#x}"),
                    "logIndex": format!("{:#x}", log.block_log_index),
                    "removed": false,
                })
            })
            .collect::<Vec<_>>();
        let receipt = json!({
            "transactionHash": transaction_hash,
            "blockNumber": format!("{block_number:#x}"),
            "blockHash": block_hash,
            "transactionIndex": format!("{transaction_index:#x}"),
            "status": "0x1",
            "type": "0x0",
            "logs": receipt_logs,
        });
        let input = hex::decode(
            transaction["input"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
        )
        .unwrap();
        let call = fifth_match_orders_call::decode_fifth_match_orders_calldata(&input).unwrap();
        let token_id = B256::from(call.taker_order.token_id.to_be_bytes::<32>());
        let mut other_id = [0x99; 32];
        if other_id == token_id.0 {
            other_id[0] ^= 1;
        }
        (
            transaction,
            receipt,
            owner,
            [token_id, B256::from(other_id)],
            "0x3333333333333333333333333333333333333333".to_owned(),
        )
    }

    #[test]
    fn context_settlement_derives_binary_pair_and_checks_block_binding() {
        let (transaction, receipt, owner, _, module) = provider_normal_buy_fixture();
        let block_number = parse_hex_u64(transaction["blockNumber"].as_str().unwrap()).unwrap();
        let block_hash = transaction["blockHash"].as_str().unwrap();
        let context = crate::rpc_position_history::fifth_binary_context::test_context(
            block_number,
            block_hash,
            &module,
        );
        let observation = decode_provider_reported_fifth_binary_settlement(
            &transaction,
            &receipt,
            &owner,
            &context,
        )
        .unwrap();
        assert_eq!(observation.module_address(), module);
        let ids = observation.position_ids();
        assert_eq!(ids[0].0[0], 1);
        assert_eq!(ids[0].0[31], 0);
        assert_eq!(ids[1].0[31], 1);
        assert_eq!(&ids[0].0[..31], &ids[1].0[..31]);

        let wrong_block = crate::rpc_position_history::fifth_binary_context::test_context(
            block_number + 1,
            block_hash,
            &module,
        );
        assert_eq!(
            decode_provider_reported_fifth_binary_settlement(
                &transaction,
                &receipt,
                &owner,
                &wrong_block,
            ),
            Err(ProviderReportedFifthSettlementError::SettlementMismatch)
        );
        let wrong_hash = crate::rpc_position_history::fifth_binary_context::test_context(
            block_number,
            &format!("0x{}", "cc".repeat(32)),
            &module,
        );
        assert_eq!(
            decode_provider_reported_fifth_binary_settlement(
                &transaction,
                &receipt,
                &owner,
                &wrong_hash,
            ),
            Err(ProviderReportedFifthSettlementError::SettlementMismatch)
        );

        let input = hex::decode(
            transaction["input"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
        )
        .unwrap();
        let mut call = fifth_match_orders_call::decode_fifth_match_orders_calldata(&input).unwrap();
        let owner_address = Address::from_str(&owner).unwrap();
        let mut changed = false;
        for order in std::iter::once(&mut call.taker_order).chain(&mut call.maker_orders) {
            if order.maker == owner_address {
                let mut nonbinary = [0_u8; 32];
                nonbinary[0] = 2;
                nonbinary[31] = 0;
                order.token_id = U256::from_be_bytes(nonbinary);
                changed = true;
            }
        }
        assert!(changed);
        assert_eq!(
            derive_provider_reported_binary_pair(&call, owner_address),
            Err(ProviderReportedFifthSettlementError::SettlementMismatch)
        );
    }

    pub(crate) fn provider_normal_buy_settlement() -> super::ProviderReportedFifthSettlement {
        let (transaction, receipt, owner, ids, module) = provider_normal_buy_fixture();
        decode_provider_reported_fifth_settlement(&transaction, &receipt, &owner, ids, &module)
            .unwrap()
    }

    pub(crate) fn provider_mint_refund_settlement() -> super::ProviderReportedFifthSettlement {
        let owner = Address::repeat_byte(0x42);
        let maker_a = Address::repeat_byte(0x48);
        let maker_b = Address::repeat_byte(0x49);
        let ids = [B256::repeat_byte(0x01), B256::repeat_byte(0x02)];
        let module = Address::repeat_byte(0x33);
        let mk_order =
            |salt: u64, maker: Address, token_id: B256, maker_amount: u64, taker_amount: u64| {
                FifthMatchOrder {
                    salt: U256::from(salt),
                    maker,
                    signer: maker,
                    token_id: U256::from_be_bytes(token_id.0),
                    maker_amount: U256::from(maker_amount),
                    taker_amount: U256::from(taker_amount),
                    side: FifthOrderSide::Buy,
                    signature_type: FifthOrderSignatureType::Eoa,
                    timestamp: U256::from(1_700_000_000_u64),
                    metadata: B256::repeat_byte(0x31),
                    builder: B256::repeat_byte(0x32),
                    signature: vec![0x41],
                }
            };
        let taker_order = mk_order(51, owner, ids[0], 50, 100);
        let maker_orders = [
            mk_order(52, maker_a, ids[1], 30, 50),
            mk_order(53, maker_b, ids[1], 30, 50),
        ];
        let input = fifth_match_orders_call::tests::encode_call(
            &taker_order,
            &maker_orders,
            &[U256::from(30_u8), U256::from(30_u8)],
            &[U256::ONE, U256::ONE],
            FifthTakerAmounts {
                taker_fill_amount: U256::from(50_u8),
                taker_receive_amount: U256::from(100_u8),
                taker_fee_amount: U256::ONE,
            },
        );
        let call = fifth_match_orders_call::decode_fifth_match_orders_calldata(&input).unwrap();
        let settlement = super::build_settlement(&call, owner, ids, module).unwrap();
        let (transaction, receipt) =
            provider_inputs_for_settlement(&input, &settlement.expected_logs);
        decode_provider_reported_fifth_settlement(
            &transaction,
            &receipt,
            &format!("{owner:#x}"),
            ids,
            &format!("{module:#x}"),
        )
        .unwrap()
    }

    fn provider_inputs_for_settlement(
        input: &[u8],
        expected_logs: &[super::ExpectedLog],
    ) -> (Value, Value) {
        let (mut transaction, _) =
            signed_polygon_transaction_with_key(fifth_code_context::EXCHANGE_PROXY, input, 0x43);
        let encoded = encode_signed_transaction_with_sender_recovery(&transaction, true).unwrap();
        let transaction_hash = format!("{:#x}", encoded.hash);
        let block_hash = format!("0x{}", "aa".repeat(32));
        let block_number = 100_u64;
        let transaction_index = 3_u64;
        transaction["hash"] = json!(transaction_hash);
        transaction["blockNumber"] = json!(format!("{block_number:#x}"));
        transaction["blockHash"] = json!(block_hash);
        transaction["transactionIndex"] = json!(format!("{transaction_index:#x}"));

        let logs = expected_logs
            .iter()
            .enumerate()
            .map(|(index, expected)| {
                let (address, topics, data) = match expected {
                    super::ExpectedLog::Pusd { from, to, amount } => (
                        "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb".to_owned(),
                        vec![
                            event_topic("Transfer(address,address,uint256)"),
                            super::topic_address_word(*from),
                            super::topic_address_word(*to),
                        ],
                        super::data_words(&[*amount]),
                    ),
                    super::ExpectedLog::Position {
                        operator,
                        from,
                        to,
                        id,
                        amount,
                    } => (
                        fifth_code_context::POSITION_MANAGER_PROXY.to_owned(),
                        vec![
                            event_topic("TransferSingle(address,address,address,uint256,uint256)"),
                            super::topic_address_word(*operator),
                            super::topic_address_word(*from),
                            super::topic_address_word(*to),
                        ],
                        super::data_words(&[*id, *amount]),
                    ),
                    super::ExpectedLog::Fee { receiver, amount } => (
                        fifth_code_context::EXCHANGE_PROXY.to_owned(),
                        vec![
                            event_topic("FeeCharged(address,uint256)"),
                            super::topic_address_word(*receiver),
                        ],
                        super::data_words(&[*amount]),
                    ),
                    super::ExpectedLog::Filled {
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
                    } => (
                        fifth_code_context::EXCHANGE_PROXY.to_owned(),
                        vec![
                            event_topic("OrderFilled(bytes32,address,address,uint8,uint256,uint256,uint256,uint256,bytes32,bytes32)"),
                            format!("{hash:#x}"),
                            super::topic_address_word(*maker),
                            super::topic_address_word(*taker),
                        ],
                        super::data_words(&[
                            U256::from(if *side == crate::TradeSide::Buy { 0_u8 } else { 1_u8 }),
                            *id,
                            *making,
                            *taking,
                            *fee,
                            U256::from_be_bytes(builder.0),
                            U256::from_be_bytes(metadata.0),
                        ]),
                    ),
                    super::ExpectedLog::Matched {
                        hash,
                        taker,
                        side,
                        id,
                        making,
                        taking,
                    } => (
                        fifth_code_context::EXCHANGE_PROXY.to_owned(),
                        vec![
                            event_topic("OrdersMatched(bytes32,address,uint8,uint256,uint256,uint256)"),
                            format!("{hash:#x}"),
                            super::topic_address_word(*taker),
                        ],
                        super::data_words(&[
                            U256::from(if *side == crate::TradeSide::Buy { 0_u8 } else { 1_u8 }),
                            *id,
                            *making,
                            *taking,
                        ]),
                    ),
                    super::ExpectedLog::Split {
                        module,
                        condition,
                        recipient_a,
                        recipient_b,
                        amount,
                    } => (
                        format!("{module:#x}"),
                        vec![
                            event_topic("PositionsSplit(address,bytes31,address,address,uint256)"),
                            super::topic_address_word(Address::from_str(fifth_code_context::EXCHANGE_PROXY).unwrap()),
                            format!("{condition:#x}"),
                            super::topic_address_word(*recipient_a),
                        ],
                        super::data_words(&[
                            U256::from_be_slice(recipient_b.as_slice()),
                            *amount,
                        ]),
                    ),
                    super::ExpectedLog::Merge {
                        module,
                        condition,
                        recipient,
                        amount,
                    } => (
                        format!("{module:#x}"),
                        vec![
                            event_topic("PositionsMerged(address,bytes31,address,uint256)"),
                            super::topic_address_word(Address::from_str(fifth_code_context::EXCHANGE_PROXY).unwrap()),
                            format!("{condition:#x}"),
                            super::topic_address_word(*recipient),
                        ],
                        super::data_words(&[*amount]),
                    ),
                };
                json!({
                    "address": address,
                    "topics": topics,
                    "data": data,
                    "blockNumber": format!("{block_number:#x}"),
                    "blockHash": block_hash.clone(),
                    "transactionHash": transaction_hash.clone(),
                    "transactionIndex": format!("{transaction_index:#x}"),
                    "logIndex": format!("{:#x}", 10 + index),
                    "removed": false,
                })
            })
            .collect::<Vec<_>>();
        let receipt = json!({
            "transactionHash": transaction_hash,
            "blockNumber": format!("{block_number:#x}"),
            "blockHash": block_hash,
            "transactionIndex": format!("{transaction_index:#x}"),
            "status": "0x1",
            "type": "0x0",
            "logs": logs,
        });
        (transaction, receipt)
    }

    #[test]
    fn provider_settlement_returns_raw_wallet_legs_and_separate_fee_metadata() {
        let (transaction, receipt, owner, ids, module) = provider_normal_buy_fixture();
        let observation =
            decode_provider_reported_fifth_settlement(&transaction, &receipt, &owner, ids, &module)
                .unwrap();
        assert_eq!(observation.chain_id(), POLYGON_CHAIN_ID);
        assert_eq!(
            observation.source(),
            super::FifthEventObservationSource::ProviderReported
        );
        assert_eq!(
            observation.implementation_version(),
            super::FifthEventImplementationVersion::Unbound
        );
        assert_eq!(observation.owner(), owner.to_ascii_lowercase());
        assert_eq!(observation.position_ids(), ids);

        let mut pusd_out = U256::ZERO;
        let mut position_in = U256::ZERO;
        for leg in observation.wallet_legs() {
            match (leg.asset(), leg.direction()) {
                (ProviderReportedFifthAsset::Pusd, ProviderReportedFifthDirection::Outflow) => {
                    pusd_out = pusd_out.checked_add(leg.amount()).unwrap();
                }
                (
                    ProviderReportedFifthAsset::Position { token_id },
                    ProviderReportedFifthDirection::Inflow,
                ) => {
                    assert!(ids.contains(&B256::from(token_id.to_be_bytes::<32>())));
                    position_in = position_in.checked_add(leg.amount()).unwrap();
                }
                other => panic!("unexpected wallet leg: {other:?}"),
            }
        }
        assert_eq!(pusd_out, U256::from(51_u8));
        assert_eq!(position_in, U256::from(100_u8));
        assert_eq!(observation.owner_fills().len(), 1);
        assert_eq!(observation.owner_fills()[0].fee(), U256::ONE);
        assert_eq!(
            observation.owner_fills()[0].gross_taking(),
            U256::from(100_u8)
        );
        assert_eq!(observation.owner_fills()[0].side(), crate::TradeSide::Buy);
        assert!(observation.owner_fills()[0].log_index() > 0);
        assert_eq!(observation.owner_refund_amount(), U256::ZERO);
        assert_eq!(observation.owner_refund_log_index(), None);
        // Fee metadata is not another PUSD transfer; the legs remain the exact
        // receipt transfers (49 + 2), not those transfers plus the fee word.
    }

    #[test]
    fn provider_settlement_binds_signed_transaction_and_receipt_locators() {
        let (transaction, receipt, owner, ids, module) = provider_normal_buy_fixture();

        let mut wrong_hash = transaction.clone();
        wrong_hash["hash"] = json!(format!("0x{}", "cc".repeat(32)));
        assert_eq!(
            decode_provider_reported_fifth_settlement(&wrong_hash, &receipt, &owner, ids, &module),
            Err(ProviderReportedFifthSettlementError::MalformedTransaction)
        );

        let mut wrong_from = transaction.clone();
        wrong_from["from"] = json!("0x4444444444444444444444444444444444444444");
        assert_eq!(
            decode_provider_reported_fifth_settlement(&wrong_from, &receipt, &owner, ids, &module),
            Err(ProviderReportedFifthSettlementError::MalformedTransaction)
        );

        for chain_id in [json!(137), Value::Null, json!("0x089")] {
            let mut wrong_chain = transaction.clone();
            wrong_chain["chainId"] = chain_id;
            assert_eq!(
                decode_provider_reported_fifth_settlement(
                    &wrong_chain,
                    &receipt,
                    &owner,
                    ids,
                    &module,
                ),
                Err(ProviderReportedFifthSettlementError::MalformedTransaction)
            );
        }

        let mut wrong_receipt = receipt.clone();
        wrong_receipt["blockHash"] = json!(format!("0x{}", "dd".repeat(32)));
        assert_eq!(
            decode_provider_reported_fifth_settlement(
                &transaction,
                &wrong_receipt,
                &owner,
                ids,
                &module
            ),
            Err(ProviderReportedFifthSettlementError::MalformedReceipt)
        );

        let mut wrong_log = receipt.clone();
        wrong_log["logs"][0]["transactionIndex"] = json!("0x4");
        assert_eq!(
            decode_provider_reported_fifth_settlement(
                &transaction,
                &wrong_log,
                &owner,
                ids,
                &module
            ),
            Err(ProviderReportedFifthSettlementError::MalformedReceipt)
        );
    }

    #[test]
    fn provider_settlement_rejects_reordered_logs_unknown_targets_and_bad_scope() {
        let (transaction, receipt, owner, ids, module) = provider_normal_buy_fixture();
        let mut reordered = receipt.clone();
        reordered["logs"].as_array_mut().unwrap().swap(0, 1);
        assert_eq!(
            decode_provider_reported_fifth_settlement(
                &transaction,
                &reordered,
                &owner,
                ids,
                &module
            ),
            Err(ProviderReportedFifthSettlementError::MalformedReceipt)
        );

        let mut reordered_with_valid_locators = receipt.clone();
        let logs = reordered_with_valid_locators["logs"]
            .as_array_mut()
            .unwrap();
        logs.swap(0, 1);
        for (index, log) in logs.iter_mut().enumerate() {
            log["logIndex"] = json!(format!("{:#x}", index + 1));
        }
        assert_eq!(
            decode_provider_reported_fifth_settlement(
                &transaction,
                &reordered_with_valid_locators,
                &owner,
                ids,
                &module,
            ),
            Err(ProviderReportedFifthSettlementError::SettlementMismatch)
        );

        let mut wrong_cash_amount = receipt.clone();
        wrong_cash_amount["logs"][1]["data"] = json!(super::data_words(&[U256::from(48_u8)]));
        assert_eq!(
            decode_provider_reported_fifth_settlement(
                &transaction,
                &wrong_cash_amount,
                &owner,
                ids,
                &module,
            ),
            Err(ProviderReportedFifthSettlementError::SettlementMismatch)
        );

        let input = hex::decode(
            transaction["input"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
        )
        .unwrap();
        let targets = crate::chain_log_audit::EXCHANGES[..4]
            .iter()
            .copied()
            .chain(std::iter::once(
                "0x6666666666666666666666666666666666666666",
            ));
        for target in targets {
            let (mut unsupported, from) = signed_polygon_transaction_with_key(target, &input, 0x42);
            let encoded =
                encode_signed_transaction_with_sender_recovery(&unsupported, true).unwrap();
            let hash = format!("{:#x}", encoded.hash);
            unsupported["from"] = json!(from);
            unsupported["hash"] = json!(hash);
            unsupported["blockNumber"] = transaction["blockNumber"].clone();
            unsupported["blockHash"] = transaction["blockHash"].clone();
            unsupported["transactionIndex"] = transaction["transactionIndex"].clone();
            let mut unsupported_receipt = receipt.clone();
            unsupported_receipt["transactionHash"] = json!(hash);
            for log in unsupported_receipt["logs"].as_array_mut().unwrap() {
                log["transactionHash"] = json!(hash);
            }
            assert_eq!(
                decode_provider_reported_fifth_settlement(
                    &unsupported,
                    &unsupported_receipt,
                    &owner,
                    ids,
                    &module,
                ),
                Err(ProviderReportedFifthSettlementError::SettlementMismatch)
            );
        }

        assert_eq!(
            decode_provider_reported_fifth_settlement(
                &transaction,
                &receipt,
                &owner,
                [ids[0], ids[0]],
                &module,
            ),
            Err(ProviderReportedFifthSettlementError::InvalidInput)
        );
    }

    #[test]
    fn provider_settlement_keeps_refund_metadata_out_of_cash_legs() {
        let owner = Address::repeat_byte(0x42);
        let maker_a = Address::repeat_byte(0x48);
        let maker_b = Address::repeat_byte(0x49);
        let ids = [B256::repeat_byte(0x01), B256::repeat_byte(0x02)];
        let module = Address::repeat_byte(0x33);
        let mk_order =
            |salt: u64, maker: Address, token_id: B256, maker_amount: u64, taker_amount: u64| {
                FifthMatchOrder {
                    salt: U256::from(salt),
                    maker,
                    signer: maker,
                    token_id: U256::from_be_bytes(token_id.0),
                    maker_amount: U256::from(maker_amount),
                    taker_amount: U256::from(taker_amount),
                    side: FifthOrderSide::Buy,
                    signature_type: FifthOrderSignatureType::Eoa,
                    timestamp: U256::from(1_700_000_000_u64),
                    metadata: B256::repeat_byte(0x31),
                    builder: B256::repeat_byte(0x32),
                    signature: vec![0x41],
                }
            };
        let taker_order = mk_order(51, owner, ids[0], 50, 100);
        let maker_orders = [
            mk_order(52, maker_a, ids[1], 30, 50),
            mk_order(53, maker_b, ids[1], 30, 50),
        ];
        let input = fifth_match_orders_call::tests::encode_call(
            &taker_order,
            &maker_orders,
            &[U256::from(30_u8), U256::from(30_u8)],
            &[U256::ONE, U256::ONE],
            FifthTakerAmounts {
                taker_fill_amount: U256::from(50_u8),
                taker_receive_amount: U256::from(100_u8),
                taker_fee_amount: U256::ONE,
            },
        );
        let call = fifth_match_orders_call::decode_fifth_match_orders_calldata(&input).unwrap();
        let settlement = super::build_settlement(&call, owner, ids, module).unwrap();
        assert_eq!(settlement.owner_refund_amount, U256::from(10_u8));
        let (transaction, receipt) =
            provider_inputs_for_settlement(&input, &settlement.expected_logs);
        let observation = decode_provider_reported_fifth_settlement(
            &transaction,
            &receipt,
            &format!("{owner:#x}"),
            ids,
            &format!("{module:#x}"),
        )
        .unwrap();

        let mut pusd_in = U256::ZERO;
        let mut pusd_out = U256::ZERO;
        for leg in observation.wallet_legs() {
            if leg.asset() != ProviderReportedFifthAsset::Pusd {
                continue;
            }
            match leg.direction() {
                ProviderReportedFifthDirection::Inflow => {
                    pusd_in = pusd_in.checked_add(leg.amount()).unwrap();
                }
                ProviderReportedFifthDirection::Outflow => {
                    pusd_out = pusd_out.checked_add(leg.amount()).unwrap();
                }
            }
        }
        assert_eq!(pusd_in, U256::from(10_u8));
        assert_eq!(pusd_out, U256::from(51_u8));
        assert_eq!(observation.owner_refund_amount(), U256::from(10_u8));
        let refund_index = observation.owner_refund_log_index().unwrap();
        assert!(observation.wallet_legs().iter().any(|leg| {
            leg.log_index() == refund_index
                && leg.asset() == ProviderReportedFifthAsset::Pusd
                && leg.direction() == ProviderReportedFifthDirection::Inflow
                && leg.amount() == U256::from(10_u8)
        }));
        assert_eq!(observation.owner_fills()[0].fee(), U256::ONE);
        // The refund is already the inbound transfer, and the fee is already
        // reflected in the exact outbound transfer. Neither is another leg.
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
