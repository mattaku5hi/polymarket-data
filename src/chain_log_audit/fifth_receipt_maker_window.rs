//! Root-bound maker rows for a short, source-pinned fifth Exchange interval.
//! This is not a trade-history or economic-completeness claim.

use super::{
    BoundedFifthCodeContextError, ChainLogAuditError, ChainLogVerifier,
    ChainReceiptIntervalEvidence, ChainReceiptLog, FifthCodeContextObservation,
    FifthExchangeImplementationVersion, ProviderFinalityAttestation, TransactionRequestBudget,
    data_word, parse_fixed_b256, topic_address, v1_event_topic, validate_hex,
};
use crate::TradeSide;
use alloy_primitives::{B256, U256};
use std::time::Duration;
use thiserror::Error;

use super::fifth_code_context::{EXCHANGE_PROXY, POSITION_MANAGER_PROXY};

pub const FIFTH_RECEIPT_MAKER_WINDOW_POLICY_VERSION: &str =
    "fifth-exchange-rooted-receipt-maker-window/1";
const ORDER_FILLED_SIGNATURE: &str =
    "OrderFilled(bytes32,address,address,uint8,uint256,uint256,uint256,uint256,bytes32,bytes32)";
const ORDERS_MATCHED_SIGNATURE: &str =
    "OrdersMatched(bytes32,address,uint8,uint256,uint256,uint256)";
const UPGRADED_SIGNATURE: &str = "Upgraded(address)";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedFifthReceiptMakerWindowError {
    #[error("fifth receipt maker window RPC request budget exhausted")]
    RequestBudgetExceeded,
    #[error("fifth receipt maker window exceeded its total deadline")]
    Timeout,
    #[error(transparent)]
    Verification(#[from] ChainLogAuditError),
}

/// Source-decoded fifth Exchange order-owner fill at one receipt-rooted log.
/// Amounts and the fee stay full-width raw event values; this has no cash/P&L meaning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthReceiptMakerFill {
    block_number: u64,
    block_hash: String,
    transaction_hash: String,
    transaction_index: u64,
    log_index: u64,
    order_hash: B256,
    maker: String,
    taker: String,
    side: TradeSide,
    token_id: U256,
    maker_amount_filled: U256,
    taker_amount_filled: U256,
    fee_amount: U256,
    builder: B256,
    metadata: B256,
    implementation_version: FifthExchangeImplementationVersion,
}

impl FifthReceiptMakerFill {
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
    pub const fn log_index(&self) -> u64 {
        self.log_index
    }

    #[must_use]
    pub const fn order_hash(&self) -> B256 {
        self.order_hash
    }

    #[must_use]
    pub fn maker(&self) -> &str {
        &self.maker
    }

    #[must_use]
    pub fn taker(&self) -> &str {
        &self.taker
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
    pub const fn builder(&self) -> B256 {
        self.builder
    }

    #[must_use]
    pub const fn metadata(&self) -> B256 {
        self.metadata
    }

    #[must_use]
    pub const fn implementation_version(&self) -> FifthExchangeImplementationVersion {
        self.implementation_version
    }
}

/// Complete bounded receipt interval, code observations, and maker-only rows.
/// Private construction prevents caller-supplied JSON from asserting verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthReceiptMakerWindow {
    evidence: ChainReceiptIntervalEvidence,
    predecessor_code_context: FifthCodeContextObservation,
    block_code_contexts: Vec<FifthCodeContextObservation>,
    maker_fills: Vec<FifthReceiptMakerFill>,
    aggregate_count: usize,
}

impl FifthReceiptMakerWindow {
    #[must_use]
    pub fn evidence(&self) -> &ChainReceiptIntervalEvidence {
        &self.evidence
    }

    #[must_use]
    pub fn predecessor_code_context(&self) -> &FifthCodeContextObservation {
        &self.predecessor_code_context
    }

    #[must_use]
    pub fn block_code_contexts(&self) -> &[FifthCodeContextObservation] {
        &self.block_code_contexts
    }

    #[must_use]
    pub fn maker_fills(&self) -> &[FifthReceiptMakerFill] {
        &self.maker_fills
    }

    #[must_use]
    pub const fn aggregate_count(&self) -> usize {
        self.aggregate_count
    }

    #[must_use]
    pub const fn source_policy_version(&self) -> &'static str {
        FIFTH_RECEIPT_MAKER_WINDOW_POLICY_VERSION
    }

    #[must_use]
    pub const fn finality_attestation(&self) -> ProviderFinalityAttestation {
        ProviderFinalityAttestation::BothProvidersReportFinalized
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedOrderFilled {
    order_hash: B256,
    maker: String,
    taker: String,
    side: TradeSide,
    token_id: U256,
    maker_amount_filled: U256,
    taker_amount_filled: U256,
    fee_amount: U256,
    builder: B256,
    metadata: B256,
}

impl ChainLogVerifier {
    /// Verify complete receipts and the same source-pinned proxy context at the
    /// predecessor and every selected block root under one request/deadline scope.
    pub async fn verify_fifth_receipt_maker_window_bounded(
        &self,
        from_block: u64,
        through_block: u64,
        expected_parent_hash: &str,
        expected_end_hash: &str,
        max_requests: usize,
        total_timeout: Duration,
    ) -> Result<FifthReceiptMakerWindow, BoundedFifthReceiptMakerWindowError> {
        let expected_parent_hash = validate_hex(expected_parent_hash, 32).map_err(|_| {
            BoundedFifthReceiptMakerWindowError::Verification(ChainLogAuditError::InvalidInput)
        })?;
        let expected_end_hash = validate_hex(expected_end_hash, 32).map_err(|_| {
            BoundedFifthReceiptMakerWindowError::Verification(ChainLogAuditError::InvalidInput)
        })?;
        if from_block == 0
            || from_block > through_block
            || through_block - from_block >= super::MAX_BLOCKS
            || max_requests == 0
            || total_timeout.is_zero()
        {
            return Err(BoundedFifthReceiptMakerWindowError::Verification(
                ChainLogAuditError::InvalidInput,
            ));
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(total_timeout)
            .ok_or(BoundedFifthReceiptMakerWindowError::Verification(
                ChainLogAuditError::InvalidInput,
            ))?;
        let budget = TransactionRequestBudget::new(max_requests);
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let scoped = self.with_request_budget(budget.inner());
        let verification = scoped.verify_fifth_receipt_maker_window_inner(
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
            _ = exhaustion.wait_for(|is_exhausted| *is_exhausted) => {
                Err(BoundedFifthReceiptMakerWindowError::RequestBudgetExceeded)
            }
            () = &mut deadline_wait => {
                if budget.is_exhausted() {
                    Err(BoundedFifthReceiptMakerWindowError::RequestBudgetExceeded)
                } else {
                    Err(BoundedFifthReceiptMakerWindowError::Timeout)
                }
            }
            result = &mut verification => {
                if budget.is_exhausted() {
                    Err(BoundedFifthReceiptMakerWindowError::RequestBudgetExceeded)
                } else {
                    result
                }
            }
        }
    }

    async fn verify_fifth_receipt_maker_window_inner(
        &self,
        from_block: u64,
        through_block: u64,
        expected_parent_hash: &str,
        expected_end_hash: &str,
        deadline: tokio::time::Instant,
    ) -> Result<FifthReceiptMakerWindow, BoundedFifthReceiptMakerWindowError> {
        ensure_before_deadline(deadline)?;
        let evidence = self
            .verify_receipt_interval_inner(
                from_block,
                through_block,
                expected_parent_hash,
                expected_end_hash,
            )
            .await?;
        if evidence.blocks().len() != usize::try_from(through_block - from_block + 1).unwrap_or(0)
            || evidence.expected_parent_hash() != expected_parent_hash
            || evidence.expected_end_hash() != expected_end_hash
        {
            return Err(ChainLogAuditError::Unverified.into());
        }

        if evidence
            .blocks()
            .iter()
            .flat_map(|block| block.transactions())
            .flat_map(|transaction| transaction.logs())
            .any(is_fifth_proxy_upgrade)
        {
            return Err(ChainLogAuditError::Unverified.into());
        }

        let predecessor = self
            .verify_fifth_code_context_inner(from_block - 1, expected_parent_hash, deadline)
            .await
            .map_err(map_code_context_error)?;
        let mut block_code_contexts = Vec::with_capacity(evidence.blocks().len());
        for block in evidence.blocks() {
            ensure_before_deadline(deadline)?;
            let context = self
                .verify_fifth_code_context_inner(block.block_number(), block.block_hash(), deadline)
                .await
                .map_err(map_code_context_error)?;
            if context.block_hash() != block.block_hash()
                || context.state_root() != block.state_root()
                || context.exchange_implementation_version()
                    != predecessor.exchange_implementation_version()
            {
                return Err(ChainLogAuditError::Divergent.into());
            }
            block_code_contexts.push(context);
        }

        let mut maker_fills = Vec::new();
        let mut aggregate_count = 0_usize;
        for (block, context) in evidence.blocks().iter().zip(&block_code_contexts) {
            ensure_before_deadline(deadline)?;
            let version = context.exchange_implementation_version();
            for transaction in block.transactions() {
                let mut pending_aggregate: Option<ParsedOrderFilled> = None;
                let mut maker_count = 0_usize;
                let mut aggregate_count_for_transaction = 0_usize;
                let mut has_order_filled = false;
                for log in transaction.logs() {
                    let exchange_emitter = log.address().eq_ignore_ascii_case(EXCHANGE_PROXY);
                    let Some(topic) = log.topics().first() else {
                        if pending_aggregate.is_some() {
                            return Err(ChainLogAuditError::Unverified.into());
                        }
                        continue;
                    };
                    if let Some(aggregate) = pending_aggregate.take() {
                        if !exchange_emitter
                            || !topic
                                .eq_ignore_ascii_case(&v1_event_topic(ORDERS_MATCHED_SIGNATURE))
                        {
                            return Err(ChainLogAuditError::Unverified.into());
                        }
                        verify_aggregate_pair(&aggregate, log)?;
                        aggregate_count = aggregate_count
                            .checked_add(1)
                            .ok_or(ChainLogAuditError::Unverified)?;
                        aggregate_count_for_transaction = aggregate_count_for_transaction
                            .checked_add(1)
                            .ok_or(ChainLogAuditError::Unverified)?;
                        continue;
                    }
                    if !exchange_emitter {
                        continue;
                    }
                    if topic.eq_ignore_ascii_case(&v1_event_topic(ORDERS_MATCHED_SIGNATURE)) {
                        return Err(ChainLogAuditError::Unverified.into());
                    }
                    if !topic.eq_ignore_ascii_case(&v1_event_topic(ORDER_FILLED_SIGNATURE)) {
                        continue;
                    }
                    has_order_filled = true;
                    let parsed = decode_fifth_order_filled(log)?;
                    if parsed.taker.eq_ignore_ascii_case(EXCHANGE_PROXY) {
                        pending_aggregate = Some(parsed);
                    } else {
                        maker_fills.push(FifthReceiptMakerFill {
                            block_number: log.block_number(),
                            block_hash: log.block_hash().to_owned(),
                            transaction_hash: log.transaction_hash().to_owned(),
                            transaction_index: log.transaction_index(),
                            log_index: log.block_log_index(),
                            order_hash: parsed.order_hash,
                            maker: parsed.maker,
                            taker: parsed.taker,
                            side: parsed.side,
                            token_id: parsed.token_id,
                            maker_amount_filled: parsed.maker_amount_filled,
                            taker_amount_filled: parsed.taker_amount_filled,
                            fee_amount: parsed.fee_amount,
                            builder: parsed.builder,
                            metadata: parsed.metadata,
                            implementation_version: version,
                        });
                        maker_count = maker_count
                            .checked_add(1)
                            .ok_or(ChainLogAuditError::Unverified)?;
                    }
                }
                if pending_aggregate.is_some()
                    || (has_order_filled
                        && (maker_count == 0 || aggregate_count_for_transaction == 0))
                {
                    return Err(ChainLogAuditError::Unverified.into());
                }
            }
        }
        ensure_before_deadline(deadline)?;
        Ok(FifthReceiptMakerWindow {
            evidence,
            predecessor_code_context: predecessor,
            block_code_contexts,
            maker_fills,
            aggregate_count,
        })
    }
}

fn ensure_before_deadline(
    deadline: tokio::time::Instant,
) -> Result<(), BoundedFifthReceiptMakerWindowError> {
    if tokio::time::Instant::now() >= deadline {
        Err(BoundedFifthReceiptMakerWindowError::Timeout)
    } else {
        Ok(())
    }
}

fn map_code_context_error(
    error: BoundedFifthCodeContextError,
) -> BoundedFifthReceiptMakerWindowError {
    match error {
        BoundedFifthCodeContextError::RequestBudgetExceeded => {
            BoundedFifthReceiptMakerWindowError::RequestBudgetExceeded
        }
        BoundedFifthCodeContextError::Timeout => BoundedFifthReceiptMakerWindowError::Timeout,
        BoundedFifthCodeContextError::Verification(error) => {
            BoundedFifthReceiptMakerWindowError::Verification(error)
        }
    }
}

fn is_fifth_proxy_upgrade(log: &ChainReceiptLog) -> bool {
    (log.address().eq_ignore_ascii_case(EXCHANGE_PROXY)
        || log.address().eq_ignore_ascii_case(POSITION_MANAGER_PROXY))
        && log
            .topics()
            .first()
            .is_some_and(|topic| topic.eq_ignore_ascii_case(&v1_event_topic(UPGRADED_SIGNATURE)))
}

fn decode_fifth_order_filled(
    log: &ChainReceiptLog,
) -> Result<ParsedOrderFilled, ChainLogAuditError> {
    let topics = log.topics();
    if topics.len() != 4 || log.data().len() != 2 + 7 * 64 {
        return Err(ChainLogAuditError::Unverified);
    }
    let order_hash = parse_fixed_b256(&topics[1])?;
    let maker = topic_address(&topics[2]).ok_or(ChainLogAuditError::Unverified)?;
    let taker = topic_address(&topics[3]).ok_or(ChainLogAuditError::Unverified)?;
    if maker == format!("0x{}", "00".repeat(20)) {
        return Err(ChainLogAuditError::Unverified);
    }
    let data = hex::decode(
        log.data()
            .strip_prefix("0x")
            .ok_or(ChainLogAuditError::Unverified)?,
    )
    .map_err(|_| ChainLogAuditError::Unverified)?;
    if data.len() != 7 * 32 {
        return Err(ChainLogAuditError::Unverified);
    }
    let side_word = data_word(&data, 0).ok_or(ChainLogAuditError::Unverified)?;
    let side = match side_word {
        U256::ZERO => TradeSide::Buy,
        value if value == U256::from(1_u8) => TradeSide::Sell,
        _ => return Err(ChainLogAuditError::Unverified),
    };
    Ok(ParsedOrderFilled {
        order_hash,
        maker,
        taker,
        side,
        token_id: data_word(&data, 1).ok_or(ChainLogAuditError::Unverified)?,
        maker_amount_filled: data_word(&data, 2).ok_or(ChainLogAuditError::Unverified)?,
        taker_amount_filled: data_word(&data, 3).ok_or(ChainLogAuditError::Unverified)?,
        fee_amount: data_word(&data, 4).ok_or(ChainLogAuditError::Unverified)?,
        builder: B256::from_slice(
            data.get(5 * 32..6 * 32)
                .ok_or(ChainLogAuditError::Unverified)?,
        ),
        metadata: B256::from_slice(
            data.get(6 * 32..7 * 32)
                .ok_or(ChainLogAuditError::Unverified)?,
        ),
    })
}

fn decode_fifth_orders_matched(
    log: &ChainReceiptLog,
) -> Result<ParsedOrderFilled, ChainLogAuditError> {
    let topics = log.topics();
    if topics.len() != 3 || log.data().len() != 2 + 4 * 64 {
        return Err(ChainLogAuditError::Unverified);
    }
    let order_hash = parse_fixed_b256(&topics[1])?;
    let maker = topic_address(&topics[2]).ok_or(ChainLogAuditError::Unverified)?;
    let data = hex::decode(
        log.data()
            .strip_prefix("0x")
            .ok_or(ChainLogAuditError::Unverified)?,
    )
    .map_err(|_| ChainLogAuditError::Unverified)?;
    if data.len() != 4 * 32 {
        return Err(ChainLogAuditError::Unverified);
    }
    let side_word = data_word(&data, 0).ok_or(ChainLogAuditError::Unverified)?;
    let side = match side_word {
        U256::ZERO => TradeSide::Buy,
        value if value == U256::from(1_u8) => TradeSide::Sell,
        _ => return Err(ChainLogAuditError::Unverified),
    };
    Ok(ParsedOrderFilled {
        order_hash,
        maker,
        taker: String::new(),
        side,
        token_id: data_word(&data, 1).ok_or(ChainLogAuditError::Unverified)?,
        maker_amount_filled: data_word(&data, 2).ok_or(ChainLogAuditError::Unverified)?,
        taker_amount_filled: data_word(&data, 3).ok_or(ChainLogAuditError::Unverified)?,
        fee_amount: U256::ZERO,
        builder: B256::ZERO,
        metadata: B256::ZERO,
    })
}

fn verify_aggregate_pair(
    aggregate: &ParsedOrderFilled,
    matched_log: &ChainReceiptLog,
) -> Result<(), ChainLogAuditError> {
    if !matched_log.address().eq_ignore_ascii_case(EXCHANGE_PROXY) {
        return Err(ChainLogAuditError::Unverified);
    }
    let matched = decode_fifth_orders_matched(matched_log)?;
    if aggregate.order_hash != matched.order_hash
        || aggregate.maker != matched.maker
        || aggregate.side != matched.side
        || aggregate.token_id != matched.token_id
        || aggregate.maker_amount_filled != matched.maker_amount_filled
        || aggregate.taker_amount_filled != matched.taker_amount_filled
    {
        return Err(ChainLogAuditError::Unverified);
    }
    Ok(())
}
