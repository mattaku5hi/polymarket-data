//! Reconciles bounded RPC position-history hints with root-bound receipts.
//!
//! A successful result is a candidate ID observation for the requested interval. It does not
//! establish complete wallet history, opening inventory, asset identity, economics, or qualification.

use std::collections::BTreeMap;

use alloy_primitives::U256;

use crate::rpc_position_history::{
    RecordedRpcPositionHistorySegmentObservation,
    validate_recorded_position_history_segment_source_agreement,
};
use crate::{
    chain_log_audit::{
        ChainReceiptLog, ChainTransactionReceiptEvidence, MovementObservationStatus,
        ObservedAssetMovement, RawMovementObservation,
    },
    position_history::{
        CTF_EMITTER, POSITION_MANAGER_EMITTER, PositionLedger, PositionTransferLog,
        TRANSFER_BATCH_TOPIC, TRANSFER_SINGLE_TOPIC,
    },
    rpc_position_history::RpcPositionHistoryObservation,
};

pub const POSITION_HISTORY_RECEIPT_JOIN_POLICY_VERSION: &str =
    "bounded-position-history-rooted-receipt-join/1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PositionHistoryReceiptJoinError {
    #[error("position-history receipt join input is invalid")]
    InvalidInput,
    #[error("position-history sources disagree")]
    SourceMismatch,
    #[error("position-history receipt set is incomplete or contains extras")]
    ReceiptSetMismatch,
    #[error("position-history receipt set contains a duplicate transaction")]
    DuplicateReceipt,
    #[error("position-history receipt locator does not match the source event")]
    ReceiptLocatorMismatch,
    #[error("rooted receipt does not contain the exact source event")]
    RootLogMismatch,
    #[error("rooted receipt is missing the source event's global log index")]
    MissingRootedLog,
    #[error("rooted receipt contains an unsupported position movement")]
    UnsupportedMovement,
    #[error("rooted position movement does not match the observed holder direction")]
    HolderMismatch,
    #[error("rooted receipt status is not successful")]
    FailedReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PositionHistoryEventLocator {
    block_number: u64,
    block_hash: String,
    transaction_hash: String,
    transaction_index: u64,
    log_index: u64,
}

impl PositionHistoryEventLocator {
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PositionHistoryCandidateId {
    ledger: PositionLedger,
    id: U256,
    locators: Vec<PositionHistoryEventLocator>,
}

impl PositionHistoryCandidateId {
    #[must_use]
    pub const fn ledger(&self) -> PositionLedger {
        self.ledger
    }
    #[must_use]
    pub const fn id(&self) -> U256 {
        self.id
    }
    #[must_use]
    pub fn id_hex(&self) -> String {
        format!("{:#x}", self.id)
    }
    #[must_use]
    pub fn locators(&self) -> &[PositionHistoryEventLocator] {
        &self.locators
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PositionHistoryReceiptObservation {
    source_kind: PositionHistoryReceiptSourceKind,
    holder_address: String,
    from_block: u64,
    through_block: u64,
    terminal_hash: String,
    terminal_state_root: String,
    terminal_transactions_root: String,
    terminal_receipts_root: String,
    source_event_count: usize,
    unique_transaction_count: usize,
    receipt_count: usize,
    candidate_ids: Vec<PositionHistoryCandidateId>,
}

/// Identifies whether the joined history content came from online reads or recorded transcripts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PositionHistoryReceiptSourceKind {
    NetworkObservation,
    RecordedTranscript,
}

impl PositionHistoryReceiptObservation {
    #[must_use]
    pub const fn source_kind(&self) -> PositionHistoryReceiptSourceKind {
        self.source_kind
    }
    #[must_use]
    pub fn holder_address(&self) -> &str {
        &self.holder_address
    }
    #[must_use]
    pub const fn from_block(&self) -> u64 {
        self.from_block
    }
    #[must_use]
    pub const fn through_block(&self) -> u64 {
        self.through_block
    }
    #[must_use]
    pub fn terminal_hash(&self) -> &str {
        &self.terminal_hash
    }
    #[must_use]
    pub fn terminal_state_root(&self) -> &str {
        &self.terminal_state_root
    }
    #[must_use]
    pub fn terminal_transactions_root(&self) -> &str {
        &self.terminal_transactions_root
    }
    #[must_use]
    pub fn terminal_receipts_root(&self) -> &str {
        &self.terminal_receipts_root
    }
    #[must_use]
    pub const fn source_event_count(&self) -> usize {
        self.source_event_count
    }
    #[must_use]
    pub const fn unique_transaction_count(&self) -> usize {
        self.unique_transaction_count
    }
    #[must_use]
    pub const fn receipt_count(&self) -> usize {
        self.receipt_count
    }
    #[must_use]
    pub fn candidate_ids(&self) -> &[PositionHistoryCandidateId] {
        &self.candidate_ids
    }
    #[must_use]
    pub const fn policy_version(&self) -> &'static str {
        POSITION_HISTORY_RECEIPT_JOIN_POLICY_VERSION
    }
    #[must_use]
    pub const fn history_coverage(&self) -> &'static str {
        "partial_interval_only"
    }
    #[must_use]
    pub const fn opening_inventory(&self) -> &'static str {
        "unknown"
    }
    #[must_use]
    pub const fn complete_wallet_history(&self) -> bool {
        false
    }
    #[must_use]
    pub const fn qualification(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CanonicalEvent {
    ledger: PositionLedger,
    block_number: u64,
    block_hash: String,
    transaction_hash: String,
    transaction_index: u64,
    log_index: u64,
    emitter: String,
    topics: Vec<String>,
    data: String,
}

struct ReceiptJoinContext<'a> {
    holder: &'a str,
    from_block: u64,
    through_block: u64,
    terminal_hash: &'a str,
    terminal_state_root: &'a str,
    terminal_transactions_root: &'a str,
    terminal_receipts_root: &'a str,
    source_kind: PositionHistoryReceiptSourceKind,
}

impl From<&PositionTransferLog> for CanonicalEvent {
    fn from(log: &PositionTransferLog) -> Self {
        Self {
            ledger: log.ledger(),
            block_number: log.block_number(),
            block_hash: log.block_hash().to_owned(),
            transaction_hash: log.transaction_hash().to_owned(),
            transaction_index: log.transaction_index(),
            log_index: log.log_index(),
            emitter: log.emitter().to_owned(),
            topics: log.topics().to_vec(),
            data: log.data().to_owned(),
        }
    }
}

impl CanonicalEvent {
    fn locator(&self) -> PositionHistoryEventLocator {
        PositionHistoryEventLocator {
            block_number: self.block_number,
            block_hash: self.block_hash.clone(),
            transaction_hash: self.transaction_hash.clone(),
            transaction_index: self.transaction_index,
            log_index: self.log_index,
        }
    }
}

/// Validates matching source scope, terminal roots, and canonical event sets before receipt I/O.
/// It does not bind source logs to transaction receipts.
pub fn validate_position_history_source_agreement(
    source_a: &RpcPositionHistoryObservation,
    source_b: &RpcPositionHistoryObservation,
) -> Result<(), PositionHistoryReceiptJoinError> {
    agreeing_source_events(source_a, source_b).map(|_| ())
}

fn agreeing_source_events(
    source_a: &RpcPositionHistoryObservation,
    source_b: &RpcPositionHistoryObservation,
) -> Result<Vec<CanonicalEvent>, PositionHistoryReceiptJoinError> {
    if source_a.from_block() > source_a.through_block()
        || source_a.holder_address() != source_b.holder_address()
        || source_a.from_block() != source_b.from_block()
        || source_a.through_block() != source_b.through_block()
        || source_a.expected_through_hash() != source_b.expected_through_hash()
        || source_a.terminal_number() != source_a.through_block()
        || source_b.terminal_number() != source_b.through_block()
        || source_a.terminal_hash() != source_a.expected_through_hash()
        || source_b.terminal_hash() != source_b.expected_through_hash()
        || source_a.terminal_hash() != source_b.terminal_hash()
        || source_a.terminal_state_root() != source_b.terminal_state_root()
        || source_a.terminal_transactions_root() != source_b.terminal_transactions_root()
        || source_a.terminal_receipts_root() != source_b.terminal_receipts_root()
    {
        return Err(PositionHistoryReceiptJoinError::InvalidInput);
    }

    let mut events = source_a
        .logs()
        .iter()
        .map(CanonicalEvent::from)
        .collect::<Vec<_>>();
    let mut second_events = source_b
        .logs()
        .iter()
        .map(CanonicalEvent::from)
        .collect::<Vec<_>>();
    events.sort();
    second_events.sort();
    if events != second_events {
        return Err(PositionHistoryReceiptJoinError::SourceMismatch);
    }
    validate_canonical_event_set(&events, source_a.from_block(), source_a.through_block())?;
    Ok(events)
}

fn validate_canonical_event_set(
    events: &[CanonicalEvent],
    from_block: u64,
    through_block: u64,
) -> Result<(), PositionHistoryReceiptJoinError> {
    if events.windows(2).any(|pair| pair[0] == pair[1])
        || events
            .iter()
            .any(|event| !(from_block..=through_block).contains(&event.block_number))
    {
        return Err(PositionHistoryReceiptJoinError::InvalidInput);
    }
    Ok(())
}

/// Joins two agreeing bounded source scans to exactly the supplied verified transaction receipts.
/// The reverse check covers every known-ledger holder ERC-1155 log within each supplied receipt;
/// it cannot detect omissions in transactions neither source hinted.
pub fn bind_position_history_receipts(
    source_a: &RpcPositionHistoryObservation,
    source_b: &RpcPositionHistoryObservation,
    receipts: &[ChainTransactionReceiptEvidence],
) -> Result<PositionHistoryReceiptObservation, PositionHistoryReceiptJoinError> {
    let events = agreeing_source_events(source_a, source_b)?;
    bind_position_history_events(
        ReceiptJoinContext {
            holder: source_a.holder_address(),
            from_block: source_a.from_block(),
            through_block: source_a.through_block(),
            terminal_hash: source_a.terminal_hash(),
            terminal_state_root: source_a.terminal_state_root(),
            terminal_transactions_root: source_a.terminal_transactions_root(),
            terminal_receipts_root: source_a.terminal_receipts_root(),
            source_kind: PositionHistoryReceiptSourceKind::NetworkObservation,
        },
        &events,
        receipts,
    )
}

/// Joins two agreeing offline-reverified transcripts to exactly the supplied verified receipts.
/// Reverification establishes transcript content consistency, not that an RPC occurred.
pub fn bind_recorded_position_history_receipts(
    source_a: &RecordedRpcPositionHistorySegmentObservation,
    source_b: &RecordedRpcPositionHistorySegmentObservation,
    receipts: &[ChainTransactionReceiptEvidence],
) -> Result<PositionHistoryReceiptObservation, PositionHistoryReceiptJoinError> {
    validate_recorded_position_history_segment_source_agreement(source_a, source_b)?;
    let mut events = source_a
        .logs()
        .iter()
        .map(CanonicalEvent::from)
        .collect::<Vec<_>>();
    events.sort();
    validate_canonical_event_set(&events, source_a.from_block(), source_a.through_block())?;
    bind_position_history_events(
        ReceiptJoinContext {
            holder: source_a.holder_address(),
            from_block: source_a.from_block(),
            through_block: source_a.through_block(),
            terminal_hash: source_a.terminal_hash(),
            terminal_state_root: source_a.terminal_state_root(),
            terminal_transactions_root: source_a.terminal_transactions_root(),
            terminal_receipts_root: source_a.terminal_receipts_root(),
            source_kind: PositionHistoryReceiptSourceKind::RecordedTranscript,
        },
        &events,
        receipts,
    )
}

fn bind_position_history_events(
    context: ReceiptJoinContext<'_>,
    events: &[CanonicalEvent],
    receipts: &[ChainTransactionReceiptEvidence],
) -> Result<PositionHistoryReceiptObservation, PositionHistoryReceiptJoinError> {
    let holder = context.holder.to_owned();
    let holder_topic = format!("0x{:0>64}", &holder[2..]);

    let mut events_by_transaction: BTreeMap<&str, Vec<&CanonicalEvent>> = BTreeMap::new();
    for event in events {
        events_by_transaction
            .entry(event.transaction_hash.as_str())
            .or_default()
            .push(event);
    }

    let mut receipts_by_transaction = BTreeMap::new();
    for receipt in receipts {
        if receipts_by_transaction
            .insert(receipt.transaction_hash(), receipt)
            .is_some()
        {
            return Err(PositionHistoryReceiptJoinError::DuplicateReceipt);
        }
    }
    if receipts_by_transaction.len() != events_by_transaction.len()
        || receipts_by_transaction
            .keys()
            .any(|transaction_hash| !events_by_transaction.contains_key(transaction_hash))
    {
        return Err(PositionHistoryReceiptJoinError::ReceiptSetMismatch);
    }

    let mut candidates: BTreeMap<(PositionLedger, U256), Vec<PositionHistoryEventLocator>> =
        BTreeMap::new();
    for (transaction_hash, transaction_events) in &events_by_transaction {
        let receipt = receipts_by_transaction
            .get(transaction_hash)
            .ok_or(PositionHistoryReceiptJoinError::ReceiptSetMismatch)?;
        if receipt.chain_id() != 137 {
            return Err(PositionHistoryReceiptJoinError::ReceiptLocatorMismatch);
        }
        if receipt.receipt_status() != 1 {
            return Err(PositionHistoryReceiptJoinError::FailedReceipt);
        }

        if transaction_events.iter().any(|event| {
            event.block_number != receipt.block_number()
                || event.block_hash != receipt.block_hash()
                || event.transaction_hash != receipt.transaction_hash()
                || event.transaction_index != receipt.transaction_index()
        }) {
            return Err(PositionHistoryReceiptJoinError::ReceiptLocatorMismatch);
        }
        let rooted_logs = receipt
            .receipt_logs()
            .iter()
            .map(|log| (log.block_log_index(), log))
            .collect::<BTreeMap<_, _>>();
        let movements = receipt
            .movement_observations()
            .iter()
            .map(|movement| (movement.log_index(), movement))
            .collect::<BTreeMap<_, _>>();
        let events_by_log_index = transaction_events
            .iter()
            .map(|event| (event.log_index, *event))
            .collect::<BTreeMap<_, _>>();
        if events_by_log_index.len() != transaction_events.len() {
            return Err(PositionHistoryReceiptJoinError::InvalidInput);
        }
        for event in transaction_events {
            let rooted = rooted_logs
                .get(&event.log_index)
                .ok_or(PositionHistoryReceiptJoinError::MissingRootedLog)?;
            if rooted.block_number() != event.block_number
                || rooted.block_hash() != event.block_hash
                || rooted.transaction_hash() != event.transaction_hash
                || rooted.transaction_index() != event.transaction_index
            {
                return Err(PositionHistoryReceiptJoinError::ReceiptLocatorMismatch);
            }
            if rooted.address() != event.emitter
                || rooted.topics() != event.topics
                || rooted.data() != event.data
            {
                return Err(PositionHistoryReceiptJoinError::RootLogMismatch);
            }
            let movement = movement_for_log(&movements, rooted)?;
            validate_holder_direction(&holder, movement)?;
        }

        for rooted in receipt.receipt_logs() {
            let Some(topic) = rooted.topics().first() else {
                continue;
            };
            let ledger = match rooted.address() {
                CTF_EMITTER => PositionLedger::Ctf,
                POSITION_MANAGER_EMITTER => PositionLedger::PositionManager,
                _ => continue,
            };
            if topic != TRANSFER_SINGLE_TOPIC && topic != TRANSFER_BATCH_TOPIC {
                continue;
            }
            let topics = rooted.topics();
            let matches_holder = topics
                .get(2)
                .is_some_and(|indexed| indexed == &holder_topic)
                || topics
                    .get(3)
                    .is_some_and(|indexed| indexed == &holder_topic);
            if !matches_holder {
                continue;
            }
            if topics.len() != 4 {
                return Err(PositionHistoryReceiptJoinError::UnsupportedMovement);
            }
            let event = events_by_log_index
                .get(&rooted.block_log_index())
                .ok_or(PositionHistoryReceiptJoinError::MissingRootedLog)?;
            if event.ledger != ledger {
                return Err(PositionHistoryReceiptJoinError::RootLogMismatch);
            }
            let movement = movement_for_log(&movements, rooted)?;
            add_candidate_ids(&mut candidates, event, &holder, movement)?;
        }
    }

    let candidate_ids = candidates
        .into_iter()
        .map(|((ledger, id), mut locators)| {
            locators.sort();
            locators.dedup();
            PositionHistoryCandidateId {
                ledger,
                id,
                locators,
            }
        })
        .collect();

    Ok(PositionHistoryReceiptObservation {
        source_kind: context.source_kind,
        holder_address: holder,
        from_block: context.from_block,
        through_block: context.through_block,
        terminal_hash: context.terminal_hash.to_owned(),
        terminal_state_root: context.terminal_state_root.to_owned(),
        terminal_transactions_root: context.terminal_transactions_root.to_owned(),
        terminal_receipts_root: context.terminal_receipts_root.to_owned(),
        source_event_count: events.len(),
        unique_transaction_count: events_by_transaction.len(),
        receipt_count: receipts.len(),
        candidate_ids,
    })
}

fn movement_for_log<'a>(
    movements: &BTreeMap<u64, &'a RawMovementObservation>,
    log: &ChainReceiptLog,
) -> Result<&'a ObservedAssetMovement, PositionHistoryReceiptJoinError> {
    let observation = *movements
        .get(&log.block_log_index())
        .ok_or(PositionHistoryReceiptJoinError::UnsupportedMovement)?;
    if observation.transaction_hash() != log.transaction_hash()
        || observation.transaction_index() != log.transaction_index()
        || observation.emitter() != log.address()
    {
        return Err(PositionHistoryReceiptJoinError::UnsupportedMovement);
    }
    match observation.status() {
        MovementObservationStatus::Decoded(movement) => Ok(movement),
        MovementObservationStatus::Unsupported(_) => {
            Err(PositionHistoryReceiptJoinError::UnsupportedMovement)
        }
    }
}

fn add_candidate_ids(
    candidates: &mut BTreeMap<(PositionLedger, U256), Vec<PositionHistoryEventLocator>>,
    event: &CanonicalEvent,
    holder: &str,
    movement: &ObservedAssetMovement,
) -> Result<(), PositionHistoryReceiptJoinError> {
    let (from, to, ids): (&str, &str, Vec<U256>) = match movement {
        ObservedAssetMovement::Erc1155TransferSingle { from, to, id, .. } => (from, to, vec![*id]),
        ObservedAssetMovement::Erc1155TransferBatch {
            from,
            to,
            ids,
            amounts,
            ..
        } if ids.len() == amounts.len() => (from, to, ids.clone()),
        ObservedAssetMovement::Erc1155TransferBatch { .. } => {
            return Err(PositionHistoryReceiptJoinError::UnsupportedMovement);
        }
        ObservedAssetMovement::Erc20Transfer { .. } => {
            return Err(PositionHistoryReceiptJoinError::UnsupportedMovement);
        }
    };
    if from != holder && to != holder {
        return Err(PositionHistoryReceiptJoinError::HolderMismatch);
    }
    let locator = event.locator();
    for id in ids {
        candidates
            .entry((event.ledger, id))
            .or_default()
            .push(locator.clone());
    }
    Ok(())
}

fn validate_holder_direction(
    holder: &str,
    movement: &ObservedAssetMovement,
) -> Result<(), PositionHistoryReceiptJoinError> {
    let (from, to) = match movement {
        ObservedAssetMovement::Erc1155TransferSingle { from, to, .. }
        | ObservedAssetMovement::Erc1155TransferBatch { from, to, .. } => (from, to),
        ObservedAssetMovement::Erc20Transfer { .. } => {
            return Err(PositionHistoryReceiptJoinError::UnsupportedMovement);
        }
    };
    if from != holder && to != holder {
        return Err(PositionHistoryReceiptJoinError::HolderMismatch);
    }
    Ok(())
}
