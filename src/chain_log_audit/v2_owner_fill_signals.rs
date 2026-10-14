//! Order-owner fill rows from a sealed, fully receipt-root-verified interval.
//!
//! This extraction is limited to the two CTF V2 deployments e111/e222. It is
//! not a complete Polymarket venue set, an RTDS mapping, or accepted trade data.

use super::{
    CHAIN_ID, ChainLogAuditError, ChainMakerFill, ChainReceiptIntervalEvidence,
    ChainReceiptIntervalTransaction, ChainReceiptLog, CtfDecoderVersion, FeeAsset, TradeSide,
    V2_ORDER_FILLED, decode_maker_fill,
};

pub const CTF_V2_OWNER_FILL_SIGNAL_POLICY_VERSION: &str =
    "ctf-v2-rooted-receipt-owner-fill-signals-e111-e222/2";

/// Observable OrderFilled owner role inferred from the raw counterparty topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2OwnerFillRole {
    /// The counterparty topic differs from the emitting exchange address.
    OrdinaryMaker,
    /// The counterparty topic equals the emitting exchange address.
    ExchangeAggregateOwner,
}

/// One CTF V2 OrderFilled owner row tied to a root-verified receipt log.
///
/// Gross share/collateral and fee base units preserve event semantics. They do
/// not establish net proceeds, RTDS correspondence, or wallet economics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2OwnerFillSignal {
    chain_id: u64,
    block_number: u64,
    block_hash: String,
    parent_hash: String,
    block_timestamp: u64,
    transaction_hash: String,
    transaction_index: u64,
    transaction_local_log_ordinal: u64,
    global_log_index: u64,
    exchange: String,
    order_hash: String,
    wallet: String,
    raw_counterparty: String,
    role: V2OwnerFillRole,
    decoder_version: CtfDecoderVersion,
    token_id: String,
    side: TradeSide,
    share_base_units: u128,
    collateral_base_units: u128,
    fee_asset: FeeAsset,
    fee_base_units: u128,
    builder: String,
    metadata: String,
}

impl V2OwnerFillSignal {
    #[must_use]
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
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
    pub fn parent_hash(&self) -> &str {
        &self.parent_hash
    }
    #[must_use]
    pub const fn block_timestamp(&self) -> u64 {
        self.block_timestamp
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
    pub const fn transaction_local_log_ordinal(&self) -> u64 {
        self.transaction_local_log_ordinal
    }
    #[must_use]
    pub const fn global_log_index(&self) -> u64 {
        self.global_log_index
    }
    #[must_use]
    pub fn exchange(&self) -> &str {
        &self.exchange
    }
    #[must_use]
    pub fn order_hash(&self) -> &str {
        &self.order_hash
    }
    #[must_use]
    pub fn wallet(&self) -> &str {
        &self.wallet
    }
    #[must_use]
    pub fn raw_counterparty(&self) -> &str {
        &self.raw_counterparty
    }
    #[must_use]
    pub const fn role(&self) -> V2OwnerFillRole {
        self.role
    }
    #[must_use]
    pub const fn decoder_version(&self) -> CtfDecoderVersion {
        self.decoder_version
    }
    #[must_use]
    pub fn token_id(&self) -> &str {
        &self.token_id
    }
    #[must_use]
    pub const fn side(&self) -> TradeSide {
        self.side
    }
    #[must_use]
    pub const fn share_base_units(&self) -> u128 {
        self.share_base_units
    }
    #[must_use]
    pub const fn collateral_base_units(&self) -> u128 {
        self.collateral_base_units
    }
    #[must_use]
    pub const fn fee_asset(&self) -> FeeAsset {
        self.fee_asset
    }
    #[must_use]
    pub const fn fee_base_units(&self) -> u128 {
        self.fee_base_units
    }
    /// Raw final `bytes32` event word, prefixed with `0x`.
    #[must_use]
    pub fn builder(&self) -> &str {
        &self.builder
    }
    /// Raw final `bytes32` event word, prefixed with `0x`.
    #[must_use]
    pub fn metadata(&self) -> &str {
        &self.metadata
    }
}

/// Extract CTF V2 owner fills from privately constructed, receipt-root-verified
/// evidence. Selected malformed e111/e222 OrderFilled logs refuse the interval.
pub fn extract_ctf_v2_owner_fill_signals(
    evidence: &ChainReceiptIntervalEvidence,
) -> Result<Vec<V2OwnerFillSignal>, ChainLogAuditError> {
    if evidence.chain_id() != CHAIN_ID
        || evidence.from_block() == 0
        || evidence.from_block() > evidence.through_block()
        || evidence.blocks().is_empty()
        || evidence.blocks().first().map(|block| block.block_number())
            != Some(evidence.from_block())
        || evidence.blocks().last().map(|block| block.block_number())
            != Some(evidence.through_block())
    {
        return Err(ChainLogAuditError::Unverified);
    }

    let mut output = Vec::new();
    let mut expected_number = evidence.from_block();
    let mut expected_parent = evidence.expected_parent_hash();
    let mut previous_block_hash: Option<&str> = None;
    for block in evidence.blocks() {
        if block.block_number() != expected_number
            || block.parent_hash() != expected_parent
            || previous_block_hash.is_some_and(|hash| hash != block.parent_hash())
        {
            return Err(ChainLogAuditError::Divergent);
        }
        previous_block_hash = Some(block.block_hash());
        expected_parent = block.block_hash();
        expected_number = expected_number
            .checked_add(1)
            .ok_or(ChainLogAuditError::Unverified)?;

        let mut next_global_log_index = 0_u64;
        for (expected_index, transaction) in block.transactions().iter().enumerate() {
            if transaction.transaction_index()
                != u64::try_from(expected_index).map_err(|_| ChainLogAuditError::Unverified)?
            {
                return Err(ChainLogAuditError::Unverified);
            }
            validate_transaction_context(block, transaction)?;
            for (local_ordinal, receipt_log) in transaction.logs().iter().enumerate() {
                if receipt_log.block_log_index() != next_global_log_index {
                    return Err(ChainLogAuditError::Unverified);
                }
                next_global_log_index = next_global_log_index
                    .checked_add(1)
                    .ok_or(ChainLogAuditError::Unverified)?;

                if !is_v2_exchange(receipt_log.address())
                    || receipt_log
                        .topics()
                        .first()
                        .is_none_or(|topic| !topic.eq_ignore_ascii_case(V2_ORDER_FILLED))
                {
                    continue;
                }
                if transaction.status() != 1
                    || receipt_log.topics().len() != 4
                    || receipt_log.data().len() != 2 + 7 * 64
                {
                    return Err(ChainLogAuditError::Unverified);
                }
                let canonical = receipt_log.canonical_log();
                let fill = decode_maker_fill(&canonical)?;
                if fill.decoder_version != CtfDecoderVersion::V2 {
                    return Err(ChainLogAuditError::Unverified);
                }
                output.push(signal_from_fill(
                    evidence,
                    block,
                    transaction,
                    receipt_log,
                    u64::try_from(local_ordinal).map_err(|_| ChainLogAuditError::Unverified)?,
                    fill,
                ));
            }
        }
    }
    if expected_number.checked_sub(1) != Some(evidence.through_block())
        || previous_block_hash != Some(evidence.expected_end_hash())
    {
        return Err(ChainLogAuditError::Divergent);
    }
    Ok(output)
}

fn validate_transaction_context(
    block: &super::ChainReceiptIntervalBlock,
    transaction: &ChainReceiptIntervalTransaction,
) -> Result<(), ChainLogAuditError> {
    for log in transaction.logs() {
        if log.block_number() != block.block_number()
            || log.block_hash() != block.block_hash()
            || log.transaction_hash() != transaction.transaction_hash()
            || log.transaction_index() != transaction.transaction_index()
        {
            return Err(ChainLogAuditError::Unverified);
        }
    }
    Ok(())
}

fn is_v2_exchange(address: &str) -> bool {
    super::EXCHANGES[2..4]
        .iter()
        .any(|exchange| exchange.eq_ignore_ascii_case(address))
}

fn signal_from_fill(
    evidence: &ChainReceiptIntervalEvidence,
    block: &super::ChainReceiptIntervalBlock,
    transaction: &ChainReceiptIntervalTransaction,
    log: &ChainReceiptLog,
    local_ordinal: u64,
    fill: ChainMakerFill,
) -> V2OwnerFillSignal {
    let role = if fill.exchange_counterparty_aggregate_shape {
        V2OwnerFillRole::ExchangeAggregateOwner
    } else {
        V2OwnerFillRole::OrdinaryMaker
    };
    V2OwnerFillSignal {
        chain_id: evidence.chain_id(),
        block_number: block.block_number(),
        block_hash: block.block_hash().to_owned(),
        parent_hash: block.parent_hash().to_owned(),
        block_timestamp: block.timestamp(),
        transaction_hash: transaction.transaction_hash().to_owned(),
        transaction_index: transaction.transaction_index(),
        transaction_local_log_ordinal: local_ordinal,
        global_log_index: log.block_log_index(),
        exchange: log.address().to_owned(),
        order_hash: fill.order_hash,
        wallet: fill.wallet,
        raw_counterparty: fill.raw_counterparty,
        role,
        decoder_version: fill.decoder_version,
        token_id: fill.token_id,
        side: fill.side,
        share_base_units: fill.share_base_units,
        collateral_base_units: fill.collateral_base_units,
        fee_asset: fill.fee_asset,
        fee_base_units: fill.fee_base_units,
        builder: format!("0x{}", &log.data()[2 + 5 * 64..2 + 6 * 64]),
        metadata: format!("0x{}", &log.data()[2 + 6 * 64..2 + 7 * 64]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_log_audit::{
        ChainReceiptIntervalBlock, ChainReceiptIntervalEvidence, ChainReceiptIntervalTransaction,
        ProviderFinalityAttestation,
    };
    use alloy_primitives::U256;

    fn repeated_hash(byte: &str) -> String {
        format!("0x{}", byte.repeat(32))
    }

    fn topic_address(address: &str) -> String {
        format!("0x{}{}", "00".repeat(12), &address[2..])
    }

    fn word(value: u64) -> String {
        format!("{value:064x}")
    }

    fn fill_log(exchange: &str, counterparty: &str, side: u64) -> ChainReceiptLog {
        ChainReceiptLog {
            block_number: 100,
            block_hash: repeated_hash("aa"),
            transaction_hash: repeated_hash("bb"),
            transaction_index: 0,
            block_log_index: 0,
            address: exchange.to_owned(),
            topics: vec![
                V2_ORDER_FILLED.to_owned(),
                repeated_hash("cc"),
                topic_address(&format!("0x{}", "11".repeat(20))),
                topic_address(counterparty),
            ],
            data: format!(
                "0x{}",
                [
                    word(side),
                    word(9),
                    word(100),
                    word(100),
                    word(5),
                    word(0xb017),
                    word(0xcafe),
                ]
                .join("")
            ),
        }
    }

    fn interval(mut logs: Vec<ChainReceiptLog>) -> ChainReceiptIntervalEvidence {
        let block_hash = repeated_hash("aa");
        let parent_hash = repeated_hash("88");
        let tx_hash = repeated_hash("bb");
        for (index, log) in logs.iter_mut().enumerate() {
            log.block_number = 100;
            log.block_hash.clone_from(&block_hash);
            log.transaction_hash.clone_from(&tx_hash);
            log.transaction_index = 0;
            log.block_log_index = u64::try_from(index).unwrap();
        }
        let transaction = ChainReceiptIntervalTransaction {
            transaction_hash: tx_hash,
            transaction_index: 0,
            status: 1,
            receipt_type: 0,
            to: None,
            input: None,
            recovered_from: None,
            value: U256::ZERO,
            replay_protected_sender: false,
            native_gas: None,
            logs,
            movement_observations: Vec::new(),
        };
        ChainReceiptIntervalEvidence {
            chain_id: CHAIN_ID,
            from_block: 100,
            through_block: 100,
            expected_parent_hash: parent_hash.clone(),
            expected_end_hash: block_hash.clone(),
            finality_attestation: ProviderFinalityAttestation::BothProvidersReportFinalized,
            policy_version: "synthetic-rooted-interval-test",
            blocks: vec![ChainReceiptIntervalBlock {
                block_number: 100,
                block_hash,
                parent_hash,
                timestamp: 1_800_000_000,
                state_root: repeated_hash("22"),
                receipts_root: repeated_hash("33"),
                transactions_root: repeated_hash("44"),
                native_gas_available: false,
                transactions: vec![transaction],
            }],
        }
    }

    #[test]
    fn extracts_both_owner_roles_and_preserves_equal_distinct_logs() {
        let exchange = super::super::EXCHANGES[2];
        let evidence = interval(vec![
            ChainReceiptLog {
                address: "0x9999999999999999999999999999999999999999".to_owned(),
                topics: vec![V2_ORDER_FILLED.to_owned()],
                ..fill_log(exchange, "0x2222222222222222222222222222222222222222", 0)
            },
            fill_log(exchange, "0x2222222222222222222222222222222222222222", 0),
            fill_log(exchange, exchange, 0),
            fill_log(
                super::super::EXCHANGES[3],
                "0x2222222222222222222222222222222222222222",
                1,
            ),
        ]);
        let rows = extract_ctf_v2_owner_fill_signals(&evidence).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].role(), V2OwnerFillRole::OrdinaryMaker);
        assert_eq!(rows[1].role(), V2OwnerFillRole::ExchangeAggregateOwner);
        assert_eq!(rows[0].transaction_local_log_ordinal(), 1);
        assert_eq!(rows[1].transaction_local_log_ordinal(), 2);
        assert_eq!(rows[0].global_log_index(), 1);
        assert_eq!(rows[1].global_log_index(), 2);
        assert_eq!(rows[2].exchange(), super::super::EXCHANGES[3]);
        assert_eq!(rows[2].side(), TradeSide::Sell);
        assert_eq!(rows[2].transaction_local_log_ordinal(), 3);
        assert_eq!(rows[0].token_id(), "9");
        assert_eq!(rows[0].share_base_units(), 100);
        assert_eq!(rows[0].collateral_base_units(), 100);
        assert_eq!(rows[0].fee_base_units(), 5);
        assert_eq!(rows[0].builder(), &format!("0x{}", word(0xb017)));
        assert_eq!(rows[0].metadata(), &format!("0x{}", word(0xcafe)));
        assert_eq!(rows[0].decoder_version(), CtfDecoderVersion::V2);
        assert_eq!(rows[0].block_timestamp(), 1_800_000_000);
        assert_eq!(rows[0].parent_hash(), repeated_hash("88"));
    }

    #[test]
    fn selected_v2_fill_requires_exactly_seven_data_words() {
        let exchange = super::super::EXCHANGES[3];
        let valid = fill_log(exchange, "0x2222222222222222222222222222222222222222", 0);
        let mut five_words = valid.clone();
        five_words.data.truncate(2 + 5 * 64);
        let mut truncated = valid.clone();
        truncated.data.truncate(truncated.data.len() - 1);
        let mut eight_words = valid;
        eight_words.data.push_str(&word(1));

        for malformed in [five_words, truncated, eight_words] {
            assert_eq!(
                extract_ctf_v2_owner_fill_signals(&interval(vec![malformed])),
                Err(ChainLogAuditError::Unverified)
            );
        }
    }

    #[test]
    fn bad_receipt_context_refuses_interval() {
        let exchange = super::super::EXCHANGES[3];

        let mut bad_context = interval(vec![fill_log(
            exchange,
            "0x2222222222222222222222222222222222222222",
            0,
        )]);
        bad_context.blocks[0].transactions[0].logs[0].transaction_index = 1;
        assert_eq!(
            extract_ctf_v2_owner_fill_signals(&bad_context),
            Err(ChainLogAuditError::Unverified)
        );

        let mut transaction_gap = interval(vec![fill_log(
            exchange,
            "0x2222222222222222222222222222222222222222",
            0,
        )]);
        let mut skipped_transaction = transaction_gap.blocks[0].transactions[0].clone();
        skipped_transaction.transaction_hash = repeated_hash("dd");
        skipped_transaction.transaction_index = 2;
        skipped_transaction.logs.clear();
        transaction_gap.blocks[0]
            .transactions
            .push(skipped_transaction);
        assert_eq!(
            extract_ctf_v2_owner_fill_signals(&transaction_gap),
            Err(ChainLogAuditError::Unverified)
        );
    }

    #[test]
    fn unsupported_fifth_emitter_is_not_claimed_as_ctf_v2() {
        let evidence = interval(vec![fill_log(
            super::super::EXCHANGES[4],
            "0x2222222222222222222222222222222222222222",
            0,
        )]);
        assert!(
            extract_ctf_v2_owner_fill_signals(&evidence)
                .unwrap()
                .is_empty()
        );
    }
}
