use super::*;
use std::str::FromStr;

const SPLIT_SELECTOR: [u8; 4] = [0x72, 0xce, 0x42, 0x75];
const MERGE_SELECTOR: [u8; 4] = [0x9e, 0x72, 0x12, 0xad];
const REDEEM_SELECTOR: [u8; 4] = [0x01, 0xb7, 0x03, 0x7c];
const PREPARE_SELECTOR: [u8; 4] = [0xd9, 0x6e, 0xe7, 0x54];
const REPORT_PAYOUTS_SELECTOR: [u8; 4] = [0xc4, 0x92, 0x98, 0xac];
const POSITION_SPLIT_TOPIC: &str =
    "0x2e6bb91f8cbcda0c93623c54d0403a43514fabc40084ec96b6d5379a74786298";
const POSITIONS_MERGE_TOPIC: &str =
    "0x6f13ca62553fcc2bcd2372180a43949c1e4cebba603901ede2f4e14f36b282ca";
const PAYOUT_REDEMPTION_TOPIC: &str =
    "0x2682012a4a4f1973119f1c9b90745d1bd91fa2bab387344f044cb3586864d18d";
const CONDITION_PREPARATION_TOPIC: &str =
    "0xab3760c3bd2bb38b5bcf54dc79802ed67338b4cf29f3054ded67ed24661e4177";
const CONDITION_RESOLUTION_TOPIC: &str =
    "0xb44d84d3289691f71497564b85d4233648d9dbae8cbdbb4329f301c3a0185894";
const USDC_APPROVAL_TOPIC: &str =
    "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";

type OperationMatch = (
    CtfOperationKind,
    Option<U256>,
    [U256; 2],
    Vec<U256>,
    Vec<u64>,
);
type OperationEvent = (String, String, B256, B256, Vec<U256>, U256);
type BatchMovement = (String, String, String, Vec<U256>, Vec<U256>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtfOperationKind {
    PrepareCondition,
    ResolveCondition,
    Split,
    Merge,
    Redeem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtfOperationTransactionStatus {
    Matched,
    ExternalMovement,
    Unavailable,
    FailedNoAssetOperation,
    OutsideSelectedPairScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtfOperationTransactionFact {
    block_number: u64,
    block_hash: String,
    transaction_hash: String,
    transaction_index: u64,
    status: CtfOperationTransactionStatus,
    kind: Option<CtfOperationKind>,
    reason: Option<&'static str>,
    collateral_amount: Option<U256>,
    position_amounts: [U256; 2],
    index_sets: Vec<U256>,
    payout: Option<U256>,
    log_indices: Vec<u64>,
    transfer_references: Vec<ComplementaryInventoryTransferReference>,
}

impl CtfOperationTransactionFact {
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
    pub const fn status(&self) -> CtfOperationTransactionStatus {
        self.status
    }
    #[must_use]
    pub const fn kind(&self) -> Option<CtfOperationKind> {
        self.kind
    }
    #[must_use]
    pub const fn reason(&self) -> Option<&'static str> {
        self.reason
    }
    #[must_use]
    pub const fn collateral_amount(&self) -> Option<U256> {
        self.collateral_amount
    }
    #[must_use]
    pub const fn position_amounts(&self) -> [U256; 2] {
        self.position_amounts
    }
    #[must_use]
    pub fn index_sets(&self) -> &[U256] {
        &self.index_sets
    }
    #[must_use]
    pub const fn payout(&self) -> Option<U256> {
        self.payout
    }
    #[must_use]
    pub fn log_indices(&self) -> &[u64] {
        &self.log_indices
    }
    #[must_use]
    pub fn transfer_references(&self) -> &[ComplementaryInventoryTransferReference] {
        &self.transfer_references
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtfOperationClassificationEvidence {
    owner: String,
    condition_id: String,
    position_ids: [U256; 2],
    snapshots: Vec<ComplementaryCtfBalanceSnapshot>,
    transactions: Vec<CtfOperationTransactionFact>,
    complete_for_selected_pair_scope: bool,
    inventory_and_lifecycle_consistent: bool,
}

impl CtfOperationClassificationEvidence {
    #[must_use]
    pub const fn policy_version(&self) -> &'static str {
        CTF_OPERATION_CLASSIFICATION_POLICY_VERSION
    }
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }
    #[must_use]
    pub fn condition_id(&self) -> &str {
        &self.condition_id
    }
    #[must_use]
    pub const fn position_ids(&self) -> [U256; 2] {
        self.position_ids
    }
    #[must_use]
    pub fn snapshots(&self) -> &[ComplementaryCtfBalanceSnapshot] {
        &self.snapshots
    }
    #[must_use]
    pub fn transactions(&self) -> &[CtfOperationTransactionFact] {
        &self.transactions
    }
    #[must_use]
    pub const fn complete_for_selected_pair_scope(&self) -> bool {
        self.complete_for_selected_pair_scope
    }
    #[must_use]
    pub const fn inventory_and_lifecycle_consistent(&self) -> bool {
        self.inventory_and_lifecycle_consistent
    }
    #[must_use]
    pub const fn source_log_order_inference(&self) -> bool {
        true
    }
    #[must_use]
    pub const fn intra_transaction_state_proven(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OperationCall {
    Prepare {
        oracle: String,
        question_id: B256,
        outcome_count: U256,
    },
    Resolve {
        question_id: B256,
        numerators: Vec<U256>,
    },
    Split {
        collateral: String,
        parent: B256,
        condition: B256,
        partition: Vec<U256>,
        amount: U256,
    },
    Merge {
        collateral: String,
        parent: B256,
        condition: B256,
        partition: Vec<U256>,
        amount: U256,
    },
    Redeem {
        collateral: String,
        parent: B256,
        condition: B256,
        index_sets: Vec<U256>,
    },
}

fn decode_call(input: &[u8]) -> Option<OperationCall> {
    let selector = input.get(..4)?;
    let args = input.get(4..)?;
    if selector == SPLIT_SELECTOR || selector == MERGE_SELECTOR {
        if args.len() < 192 || word(args, 96)? != U256::from(160) {
            return None;
        }
        let collateral = abi_address(word(args, 0)?)?;
        let parent = word_b256(args, 32)?;
        let condition = word_b256(args, 64)?;
        let partition = decode_dynamic_words(args, 160, 2)?;
        if partition.len() != 2
            || !matches!(partition.as_slice(), [a,b] if (*a==U256::ONE && *b==U256::from(2)) || (*a==U256::from(2) && *b==U256::ONE))
        {
            return None;
        }
        let amount = word(args, 128)?;
        return Some(if selector == SPLIT_SELECTOR {
            OperationCall::Split {
                collateral,
                parent,
                condition,
                partition,
                amount,
            }
        } else {
            OperationCall::Merge {
                collateral,
                parent,
                condition,
                partition,
                amount,
            }
        });
    }
    if selector == REDEEM_SELECTOR {
        if args.len() < 160 || word(args, 96)? != U256::from(128) {
            return None;
        }
        let collateral = abi_address(word(args, 0)?)?;
        let parent = word_b256(args, 32)?;
        let condition = word_b256(args, 64)?;
        let index_sets = decode_dynamic_words(args, 128, 128)?;
        if index_sets
            .iter()
            .any(|set| *set != U256::ONE && *set != U256::from(2))
        {
            return None;
        }
        return Some(OperationCall::Redeem {
            collateral,
            parent,
            condition,
            index_sets,
        });
    }
    if selector == PREPARE_SELECTOR {
        if args.len() != 96 {
            return None;
        }
        return Some(OperationCall::Prepare {
            oracle: abi_address(word(args, 0)?)?,
            question_id: word_b256(args, 32)?,
            outcome_count: word(args, 64)?,
        });
    }
    if selector == REPORT_PAYOUTS_SELECTOR {
        if args.len() < 96 || word(args, 32)? != U256::from(64) {
            return None;
        }
        let question_id = word_b256(args, 0)?;
        let numerators = decode_dynamic_words(args, 64, 256)?;
        return Some(OperationCall::Resolve {
            question_id,
            numerators,
        });
    }
    None
}

fn word(bytes: &[u8], offset: usize) -> Option<U256> {
    Some(U256::from_be_slice(
        bytes.get(offset..offset.checked_add(32)?)?,
    ))
}

fn word_b256(bytes: &[u8], offset: usize) -> Option<B256> {
    Some(B256::from_slice(
        bytes.get(offset..offset.checked_add(32)?)?,
    ))
}

fn abi_address(value: U256) -> Option<String> {
    if value >> 160 != U256::ZERO {
        return None;
    }
    Some(format!("0x{value:040x}"))
}

fn derive_condition_id(oracle: &str, question_id: B256, outcome_count: U256) -> Option<B256> {
    let oracle = hex::decode(oracle.strip_prefix("0x")?).ok()?;
    if oracle.len() != 20 {
        return None;
    }
    let mut preimage = Vec::with_capacity(84);
    preimage.extend_from_slice(&oracle);
    preimage.extend_from_slice(question_id.as_slice());
    preimage.extend_from_slice(&outcome_count.to_be_bytes::<32>());
    Some(B256::from_slice(&Keccak256::digest(preimage)))
}

fn decode_dynamic_words(bytes: &[u8], offset: usize, max: usize) -> Option<Vec<U256>> {
    let (words, end) = decode_dynamic_words_with_end(bytes, offset, max)?;
    (end == bytes.len()).then_some(words)
}

fn decode_dynamic_words_with_end(
    bytes: &[u8],
    offset: usize,
    max: usize,
) -> Option<(Vec<U256>, usize)> {
    let length = usize::try_from(word(bytes, offset)?).ok()?;
    if length > max {
        return None;
    }
    let start = offset.checked_add(32)?;
    let end = start.checked_add(length.checked_mul(32)?)?;
    if end > bytes.len() {
        return None;
    }
    let words = (0..length)
        .map(|i| word(bytes, start.checked_add(i.checked_mul(32)?)?))
        .collect::<Option<Vec<_>>>()?;
    Some((words, end))
}

fn log_data(log: &ChainReceiptLog) -> Option<Vec<u8>> {
    movement_data(&log.data).ok()
}

fn is_topic(log: &ChainReceiptLog, topic: &str) -> bool {
    log.topics
        .first()
        .is_some_and(|actual| actual.eq_ignore_ascii_case(topic))
}

fn is_ctf_log(log: &ChainReceiptLog, topic: &str) -> bool {
    log.address
        .eq_ignore_ascii_case(CTF_CONDITIONAL_TOKENS_ADDRESS)
        && is_topic(log, topic)
}

fn parse_condition_preparation(log: &ChainReceiptLog, condition: B256) -> Option<(u64, ())> {
    let (count, event_condition, oracle, question) = parse_condition_preparation_full(log)?;
    (event_condition == condition
        && derive_condition_id(&oracle, question, count) == Some(condition))
    .then_some((u256_to_u64(count).ok()?, ()))
}

fn parse_condition_preparation_full(log: &ChainReceiptLog) -> Option<(U256, B256, String, B256)> {
    if !is_ctf_log(log, CONDITION_PREPARATION_TOPIC) || log.topics.len() != 4 {
        return None;
    }
    let condition = B256::from_str(log.topics.get(1)?).ok()?;
    let oracle = topic_address(log.topics.get(2)?)?;
    let question = B256::from_str(log.topics.get(3)?).ok()?;
    let data = log_data(log)?;
    if data.len() != 32 {
        return None;
    }
    Some((word(&data, 0)?, condition, oracle, question))
}

fn parse_condition_resolution_full(
    log: &ChainReceiptLog,
) -> Option<(U256, B256, String, B256, Vec<U256>)> {
    if !is_ctf_log(log, CONDITION_RESOLUTION_TOPIC) || log.topics.len() != 4 {
        return None;
    }
    let condition = B256::from_str(log.topics.get(1)?).ok()?;
    let oracle = topic_address(log.topics.get(2)?)?;
    let question = B256::from_str(log.topics.get(3)?).ok()?;
    let data = log_data(log)?;
    if data.len() < 64 || word(&data, 32)? != U256::from(64) {
        return None;
    }
    Some((
        word(&data, 0)?,
        condition,
        oracle,
        question,
        decode_dynamic_words(&data, 64, 256)?,
    ))
}

fn parse_operation_event(log: &ChainReceiptLog, topic: &str) -> Option<OperationEvent> {
    if !is_ctf_log(log, topic) || log.topics.len() != 4 {
        return None;
    }
    let stakeholder = topic_address(log.topics.get(1)?)?;
    let parent = B256::from_str(log.topics.get(2)?).ok()?;
    let condition = B256::from_str(log.topics.get(3)?).ok()?;
    let data = log_data(log)?;
    if data.len() < 160 || word(&data, 32)? != U256::from(96) {
        return None;
    }
    let collateral = abi_address(word(&data, 0)?)?;
    let partition = decode_dynamic_words(&data, 96, 2)?;
    let amount = word(&data, 64)?;
    Some((
        stakeholder,
        collateral,
        parent,
        condition,
        partition,
        amount,
    ))
}

fn parse_payout_event(
    log: &ChainReceiptLog,
) -> Option<(String, String, B256, B256, Vec<U256>, U256)> {
    if !is_ctf_log(log, PAYOUT_REDEMPTION_TOPIC) || log.topics.len() != 4 {
        return None;
    }
    let redeemer = topic_address(log.topics.get(1)?)?;
    let collateral = topic_address(log.topics.get(2)?)?;
    let parent = B256::from_str(log.topics.get(3)?).ok()?;
    let data = log_data(log)?;
    if data.len() < 96 || word(&data, 32)? != U256::from(96) {
        return None;
    }
    Some((
        redeemer,
        collateral,
        parent,
        word_b256(&data, 0)?,
        decode_dynamic_words(&data, 96, 128)?,
        word(&data, 64)?,
    ))
}

fn log_transfer_single(log: &ChainReceiptLog) -> Option<(String, String, String, U256, U256)> {
    if !log
        .address
        .eq_ignore_ascii_case(CTF_CONDITIONAL_TOKENS_ADDRESS)
        || !is_topic(log, ERC1155_TRANSFER_SINGLE)
        || log.topics.len() != 4
    {
        return None;
    }
    let data = log_data(log)?;
    if data.len() != 64 {
        return None;
    }
    Some((
        topic_address(log.topics.get(1)?)?,
        topic_address(log.topics.get(2)?)?,
        topic_address(log.topics.get(3)?)?,
        word(&data, 0)?,
        word(&data, 32)?,
    ))
}

fn log_transfer_batch(log: &ChainReceiptLog) -> Option<BatchMovement> {
    if !log
        .address
        .eq_ignore_ascii_case(CTF_CONDITIONAL_TOKENS_ADDRESS)
        || !is_topic(log, ERC1155_TRANSFER_BATCH)
        || log.topics.len() != 4
    {
        return None;
    }
    let data = log_data(log)?;
    if data.len() < 64 || word(&data, 0)? != U256::from(64) {
        return None;
    }
    let (ids, ids_end) = decode_dynamic_words_with_end(&data, 64, MAX_ERC1155_BATCH_ITEMS)?;
    let amounts_offset = 96_usize.checked_add(ids.len().checked_mul(32)?)?;
    if word(&data, 32)? != U256::from(amounts_offset) {
        return None;
    }
    if ids_end != amounts_offset {
        return None;
    }
    let (amounts, amounts_end) =
        decode_dynamic_words_with_end(&data, amounts_offset, MAX_ERC1155_BATCH_ITEMS)?;
    if amounts_end != data.len() {
        return None;
    }
    if ids.len() != amounts.len() {
        return None;
    }
    Some((
        topic_address(log.topics.get(1)?)?,
        topic_address(log.topics.get(2)?)?,
        topic_address(log.topics.get(3)?)?,
        ids,
        amounts,
    ))
}

fn log_transfer_erc20(log: &ChainReceiptLog) -> Option<(String, String, U256)> {
    if !log.address.eq_ignore_ascii_case(USDC_E_PROXY_ADDRESS)
        || !is_topic(log, ERC20_TRANSFER)
        || log.topics.len() != 3
    {
        return None;
    }
    let data = log_data(log)?;
    if data.len() != 32 {
        return None;
    }
    Some((
        topic_address(log.topics.get(1)?)?,
        topic_address(log.topics.get(2)?)?,
        word(&data, 0)?,
    ))
}

fn log_approval(log: &ChainReceiptLog) -> Option<(String, String, U256)> {
    if !log.address.eq_ignore_ascii_case(USDC_E_PROXY_ADDRESS)
        || !is_topic(log, USDC_APPROVAL_TOPIC)
        || log.topics.len() != 3
    {
        return None;
    }
    let data = log_data(log)?;
    if data.len() != 32 {
        return None;
    }
    Some((
        topic_address(log.topics.get(1)?)?,
        topic_address(log.topics.get(2)?)?,
        word(&data, 0)?,
    ))
}

pub(super) fn usdc_transfer_from_approval_matches(
    log: &ChainReceiptLog,
    owner: &str,
    spender: &str,
    spent: U256,
) -> bool {
    log_approval(log).is_some_and(|(actual_owner, actual_spender, remaining)| {
        actual_owner.eq_ignore_ascii_case(owner)
            && actual_spender.eq_ignore_ascii_case(spender)
            && remaining.checked_add(spent).is_some()
    })
}

/// Matches only the source-ordered Exchange custody logs for a binary root split/merge.
pub(super) fn exchange_operation_log_indices(
    logs: &[ChainReceiptLog],
    identity: &ctf_position_identity::DerivedRootBinaryIdentity,
    amount: U256,
    split: bool,
) -> Option<Vec<u64>> {
    let partition = [U256::ONE, U256::from(2)];
    let ids = position_ids_for_partition(identity, &partition)?;
    let exchange = EXCHANGES[0];
    let zero = format!("0x{}", "00".repeat(20));
    let width = if split { 4 } else { 3 };
    for start in 0..=logs.len().checked_sub(width)? {
        let window = &logs[start..start + width];
        let matches = if split {
            let transfer = log_transfer_erc20(&window[0]);
            let approval = log_approval(&window[1]);
            let batch = log_transfer_batch(&window[2]);
            let event = parse_operation_event(&window[3], POSITION_SPLIT_TOPIC);
            transfer.clone().is_some_and(|(from, to, value)| {
                from.eq_ignore_ascii_case(exchange)
                    && to.eq_ignore_ascii_case(CTF_CONDITIONAL_TOKENS_ADDRESS)
                    && value == amount
            }) && approval.is_some_and(|(owner, spender, remaining)| {
                owner.eq_ignore_ascii_case(exchange)
                    && spender.eq_ignore_ascii_case(CTF_CONDITIONAL_TOKENS_ADDRESS)
                    && remaining.checked_add(amount).is_some()
            }) && batch.is_some_and(|(operator, from, to, event_ids, amounts)| {
                operator.eq_ignore_ascii_case(exchange)
                    && from == zero
                    && to.eq_ignore_ascii_case(exchange)
                    && event_ids == ids
                    && amounts == [amount, amount]
            }) && event.is_some_and(
                |(stakeholder, collateral, parent, condition, event_partition, event_amount)| {
                    stakeholder.eq_ignore_ascii_case(exchange)
                        && collateral.eq_ignore_ascii_case(USDC_E_PROXY_ADDRESS)
                        && parent == B256::ZERO
                        && condition == identity.condition_id
                        && event_partition == partition
                        && event_amount == amount
                },
            )
        } else {
            let batch = log_transfer_batch(&window[0]);
            let transfer = log_transfer_erc20(&window[1]);
            let event = parse_operation_event(&window[2], POSITIONS_MERGE_TOPIC);
            batch
                .clone()
                .is_some_and(|(operator, from, to, event_ids, amounts)| {
                    operator.eq_ignore_ascii_case(exchange)
                        && from.eq_ignore_ascii_case(exchange)
                        && to == zero
                        && event_ids == ids
                        && amounts == [amount, amount]
                })
                && transfer.is_some_and(|(from, to, value)| {
                    from.eq_ignore_ascii_case(CTF_CONDITIONAL_TOKENS_ADDRESS)
                        && to.eq_ignore_ascii_case(exchange)
                        && value == amount
                })
                && event.is_some_and(
                    |(
                        stakeholder,
                        collateral,
                        parent,
                        condition,
                        event_partition,
                        event_amount,
                    )| {
                        stakeholder.eq_ignore_ascii_case(exchange)
                            && collateral.eq_ignore_ascii_case(USDC_E_PROXY_ADDRESS)
                            && parent == B256::ZERO
                            && condition == identity.condition_id
                            && event_partition == partition
                            && event_amount == amount
                    },
                )
        };
        if matches {
            return Some(window.iter().map(|log| log.block_log_index).collect());
        }
    }
    None
}

fn position_ids_for_partition(
    identity: &ctf_position_identity::DerivedRootBinaryIdentity,
    partition: &[U256],
) -> Option<Vec<U256>> {
    partition
        .iter()
        .map(|set| match *set {
            U256::ONE => Some(U256::from_be_bytes(identity.position_ids[0].0)),
            value if value == U256::from(2) => {
                Some(U256::from_be_bytes(identity.position_ids[1].0))
            }
            _ => None,
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn check_split_or_merge(
    transaction: &ChainReceiptIntervalTransaction,
    owner: &str,
    identity: &ctf_position_identity::DerivedRootBinaryIdentity,
    collateral: &str,
    parent: B256,
    condition: B256,
    partition: &[U256],
    amount: U256,
    balances: [U256; 2],
    prepared: bool,
    split: bool,
) -> Option<OperationMatch> {
    if !prepared
        || !collateral.eq_ignore_ascii_case(USDC_E_PROXY_ADDRESS)
        || parent != B256::ZERO
        || condition != identity.condition_id
    {
        return None;
    }
    let ids = position_ids_for_partition(identity, partition)?;
    let mut indices = [0_usize; 2];
    for (n, id) in ids.iter().enumerate() {
        indices[n] = usize::from(*id == U256::from_be_bytes(identity.position_ids[1].0));
    }
    let logs = &transaction.logs;
    if split {
        if logs.len() != 4 {
            return None;
        }
        let transfer = log_transfer_erc20(&logs[0])?;
        let approval = log_approval(&logs[1])?;
        let batch = log_transfer_batch(&logs[2])?;
        let event = parse_operation_event(&logs[3], POSITION_SPLIT_TOPIC)?;
        if transfer
            != (
                owner.to_owned(),
                CTF_CONDITIONAL_TOKENS_ADDRESS.to_owned(),
                amount,
            )
            || approval.0 != owner
            || !approval
                .1
                .eq_ignore_ascii_case(CTF_CONDITIONAL_TOKENS_ADDRESS)
            || approval.2.checked_add(amount).is_none()
            || batch.0 != owner
            || batch.1 != format!("0x{}", "00".repeat(20))
            || batch.2 != owner
            || batch.3 != ids
            || batch.4 != [amount, amount]
            || event.0 != owner
            || !event.1.eq_ignore_ascii_case(collateral)
            || event.2 != parent
            || event.3 != condition
            || event.4 != partition
            || event.5 != amount
        {
            return None;
        }
        Some((
            CtfOperationKind::Split,
            Some(amount),
            [amount; 2],
            partition.to_vec(),
            logs.iter().map(|log| log.block_log_index).collect(),
        ))
    } else {
        if logs.len() != 3 {
            return None;
        }
        let batch = log_transfer_batch(&logs[0])?;
        let transfer = log_transfer_erc20(&logs[1])?;
        let event = parse_operation_event(&logs[2], POSITIONS_MERGE_TOPIC)?;
        if batch.0 != owner
            || batch.1 != owner
            || batch.2 != format!("0x{}", "00".repeat(20))
            || batch.3 != ids
            || batch.4 != [amount, amount]
            || transfer
                != (
                    CTF_CONDITIONAL_TOKENS_ADDRESS.to_owned(),
                    owner.to_owned(),
                    amount,
                )
            || event.0 != owner
            || !event.1.eq_ignore_ascii_case(collateral)
            || event.2 != parent
            || event.3 != condition
            || event.4 != partition
            || event.5 != amount
            || indices.iter().any(|index| balances[*index] < amount)
        {
            return None;
        }
        Some((
            CtfOperationKind::Merge,
            Some(amount),
            [amount; 2],
            partition.to_vec(),
            logs.iter().map(|log| log.block_log_index).collect(),
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn check_redeem(
    transaction: &ChainReceiptIntervalTransaction,
    owner: &str,
    identity: &ctf_position_identity::DerivedRootBinaryIdentity,
    collateral: &str,
    parent: B256,
    condition: B256,
    index_sets: &[U256],
    balances: [U256; 2],
    payout_state: Option<([U256; 2], U256)>,
) -> Option<OperationMatch> {
    if !collateral.eq_ignore_ascii_case(USDC_E_PROXY_ADDRESS)
        || parent != B256::ZERO
        || condition != identity.condition_id
    {
        return None;
    }
    let (numerators, denominator) = payout_state?;
    if denominator.is_zero() {
        return None;
    }
    let mut remaining = balances;
    let mut burned = [U256::ZERO; 2];
    let mut payout = U256::ZERO;
    let mut expected_burns = Vec::new();
    for set in index_sets {
        let slot = if *set == U256::ONE {
            0
        } else if *set == U256::from(2) {
            1
        } else {
            return None;
        };
        let stake = remaining[slot];
        if !stake.is_zero() {
            let token = U256::from_be_bytes(identity.position_ids[slot].0);
            expected_burns.push((token, stake));
            remaining[slot] = U256::ZERO;
            burned[slot] = burned[slot].checked_add(stake)?;
            payout = payout.checked_add(
                stake
                    .checked_mul(numerators[slot])?
                    .checked_div(denominator)?,
            )?;
        }
    }
    let cash_count = usize::from(!payout.is_zero());
    if transaction.logs.len() != expected_burns.len() + cash_count + 1 {
        return None;
    }
    for (index, (token, amount)) in expected_burns.iter().enumerate() {
        let (operator, from, to, id, value) = log_transfer_single(transaction.logs.get(index)?)?;
        if operator != owner
            || from != owner
            || to != format!("0x{}", "00".repeat(20))
            || id != *token
            || value != *amount
        {
            return None;
        }
    }
    let mut event_index = expected_burns.len();
    if cash_count == 1 {
        let (from, to, value) = log_transfer_erc20(transaction.logs.get(event_index)?)?;
        if from != CTF_CONDITIONAL_TOKENS_ADDRESS || to != owner || value != payout {
            return None;
        }
        event_index += 1;
    }
    let event = parse_payout_event(transaction.logs.get(event_index)?)?;
    if event.0 != owner
        || !event.1.eq_ignore_ascii_case(collateral)
        || event.2 != parent
        || event.3 != condition
        || event.4 != index_sets
        || event.5 != payout
    {
        return None;
    }
    Some((
        CtfOperationKind::Redeem,
        Some(payout),
        burned,
        index_sets.to_vec(),
        transaction
            .logs
            .iter()
            .map(|log| log.block_log_index)
            .collect(),
    ))
}

async fn apply_movements(
    transaction: &ChainReceiptIntervalTransaction,
    owner: &str,
    token_ids: [U256; 2],
    balances: &mut [U256; 2],
    cash: &mut U256,
    deadline: tokio::time::Instant,
) -> bool {
    for (index, movement) in transaction.movement_observations.iter().enumerate() {
        if index % 256 == 0 {
            tokio::task::yield_now().await;
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
        }
        match movement.status() {
            MovementObservationStatus::Unsupported(_) => {
                if movement
                    .emitter
                    .eq_ignore_ascii_case(CTF_CONDITIONAL_TOKENS_ADDRESS)
                    || movement.emitter.eq_ignore_ascii_case(USDC_E_PROXY_ADDRESS)
                {
                    return false;
                }
            }
            MovementObservationStatus::Decoded(ObservedAssetMovement::Erc1155TransferSingle {
                from,
                to,
                id,
                amount,
                ..
            }) if movement
                .emitter
                .eq_ignore_ascii_case(CTF_CONDITIONAL_TOKENS_ADDRESS)
                && token_ids.contains(id) =>
            {
                if !apply_owner_delta(balances, token_ids, owner, from, to, *id, *amount) {
                    return false;
                }
            }
            MovementObservationStatus::Decoded(ObservedAssetMovement::Erc1155TransferBatch {
                from,
                to,
                ids,
                amounts,
                ..
            }) if movement
                .emitter
                .eq_ignore_ascii_case(CTF_CONDITIONAL_TOKENS_ADDRESS) =>
            {
                if ids.len() != amounts.len() {
                    return false;
                }
                for (id, amount) in ids.iter().zip(amounts) {
                    if token_ids.contains(id)
                        && !apply_owner_delta(balances, token_ids, owner, from, to, *id, *amount)
                    {
                        return false;
                    }
                }
            }
            MovementObservationStatus::Decoded(ObservedAssetMovement::Erc20Transfer {
                from,
                to,
                amount,
            }) if movement.emitter.eq_ignore_ascii_case(USDC_E_PROXY_ADDRESS) => {
                let owner_from = from.eq_ignore_ascii_case(owner);
                let owner_to = to.eq_ignore_ascii_case(owner);
                if owner_from && !owner_to {
                    let Some(next) = cash.checked_sub(*amount) else {
                        return false;
                    };
                    *cash = next;
                }
                if owner_to && !owner_from {
                    let Some(next) = cash.checked_add(*amount) else {
                        return false;
                    };
                    *cash = next;
                }
            }
            _ => {}
        }
    }
    true
}

fn apply_owner_delta(
    balances: &mut [U256; 2],
    token_ids: [U256; 2],
    owner: &str,
    from: &str,
    to: &str,
    id: U256,
    amount: U256,
) -> bool {
    let owner_from = from.eq_ignore_ascii_case(owner);
    let owner_to = to.eq_ignore_ascii_case(owner);
    if owner_from == owner_to {
        return true;
    }
    let Some(slot) = token_ids.iter().position(|token| *token == id) else {
        return false;
    };
    let target = &mut balances[slot];
    if owner_from {
        let Some(next) = target.checked_sub(amount) else {
            return false;
        };
        *target = next;
    } else {
        let Some(next) = target.checked_add(amount) else {
            return false;
        };
        *target = next;
    }
    true
}

pub(super) async fn classify_report(
    report: &V1TradeAttributionReport,
    owner: &str,
    identity: &ctf_position_identity::DerivedRootBinaryIdentity,
    deadline: tokio::time::Instant,
) -> Result<CtfOperationClassificationEvidence, ChainLogAuditError> {
    let inventory = report
        .complementary_inventory
        .as_ref()
        .ok_or(ChainLogAuditError::Unverified)?;
    let condition = report
        .ctf_condition_state
        .as_ref()
        .ok_or(ChainLogAuditError::Unverified)?;
    if tokio::time::Instant::now() >= deadline {
        return Err(ChainLogAuditError::Unavailable);
    }
    let mut transactions = Vec::new();
    let mut complete = inventory
        .statuses
        .iter()
        .all(|status| matches!(status, PairedInventoryAssetStatus::Matched));
    let collateral_proxy_upgrade =
        report.unavailable_reason() == Some("collateral_proxy_upgrade_observed_in_interval");
    complete &= !collateral_proxy_upgrade;
    let mut inventory_and_lifecycle_consistent = complete;
    let mut balances = inventory
        .snapshots
        .first()
        .ok_or(ChainLogAuditError::Unverified)?
        .balances;
    let mut cash = report
        .paired_inventory
        .usdc_e_proofs
        .first()
        .ok_or(ChainLogAuditError::Unverified)?
        .balance;
    let mut condition_state = condition
        .proofs
        .first()
        .ok_or(ChainLogAuditError::Unverified)?
        .clone();
    let mut prepared = matches!(
        condition_state.status,
        CtfConditionStateStatus::PreparedBinaryUnresolved | CtfConditionStateStatus::ResolvedBinary
    );
    let mut payout =
        (condition_state.status == CtfConditionStateStatus::ResolvedBinary).then_some((
            condition_state.payout_numerators,
            condition_state.payout_denominator,
        ));
    for block in &report.interval_evidence.blocks {
        let starting_condition_status = condition_state.status;
        let mut preparation_event_seen = false;
        let mut resolution_event_seen = false;
        for (position, transaction) in block.transactions.iter().enumerate() {
            if position % 32 == 0 {
                tokio::task::yield_now().await;
                if tokio::time::Instant::now() >= deadline {
                    return Err(ChainLogAuditError::Unavailable);
                }
            }
            let references = inventory
                .transfer_references
                .iter()
                .filter(|reference| {
                    reference.transaction_hash == transaction.transaction_hash
                        && reference.transaction_index == transaction.transaction_index
                })
                .cloned()
                .collect::<Vec<_>>();
            let mut fact = CtfOperationTransactionFact {
                block_number: block.block_number,
                block_hash: block.block_hash.clone(),
                transaction_hash: transaction.transaction_hash.clone(),
                transaction_index: transaction.transaction_index,
                status: CtfOperationTransactionStatus::OutsideSelectedPairScope,
                kind: None,
                reason: None,
                collateral_amount: None,
                position_amounts: [U256::ZERO; 2],
                index_sets: Vec::new(),
                payout: None,
                log_indices: Vec::new(),
                transfer_references: references,
            };
            if transaction.status == 0 {
                fact.status = CtfOperationTransactionStatus::FailedNoAssetOperation;
                transactions.push(fact);
                continue;
            }
            let ctf_call = transaction
                .to
                .as_deref()
                .is_some_and(|to| to.eq_ignore_ascii_case(CTF_CONDITIONAL_TOKENS_ADDRESS));
            let exchange_call = transaction
                .to
                .as_deref()
                .is_some_and(|to| to.eq_ignore_ascii_case(EXCHANGES[0]));
            let has_lifecycle = transaction.logs.iter().any(|log| {
                log.address
                    .eq_ignore_ascii_case(CTF_CONDITIONAL_TOKENS_ADDRESS)
                    && log.topics.first().is_some_and(|topic| {
                        [CONDITION_PREPARATION_TOPIC, CONDITION_RESOLUTION_TOPIC]
                            .iter()
                            .any(|known| topic.eq_ignore_ascii_case(known))
                    })
            });
            let has_operation_event = transaction.logs.iter().any(|log| {
                log.address
                    .eq_ignore_ascii_case(CTF_CONDITIONAL_TOKENS_ADDRESS)
                    && log.topics.first().is_some_and(|topic| {
                        [
                            POSITION_SPLIT_TOPIC,
                            POSITIONS_MERGE_TOPIC,
                            PAYOUT_REDEMPTION_TOPIC,
                        ]
                        .iter()
                        .any(|known| topic.eq_ignore_ascii_case(known))
                    })
            });
            let mut lifecycle_seen = false;
            for (log_index, log) in transaction.logs.iter().enumerate() {
                if log_index % 256 == 0 {
                    tokio::task::yield_now().await;
                    if tokio::time::Instant::now() >= deadline {
                        return Err(ChainLogAuditError::Unavailable);
                    }
                }
                if log
                    .address
                    .eq_ignore_ascii_case(CTF_CONDITIONAL_TOKENS_ADDRESS)
                    && log.topics.first().is_some_and(|topic| {
                        topic.eq_ignore_ascii_case(CONDITION_PREPARATION_TOPIC)
                    })
                {
                    let endpoint_is_prepared = condition
                        .proofs
                        .iter()
                        .find(|proof| proof.block_number == block.block_number)
                        .is_some_and(|proof| {
                            matches!(
                                proof.status,
                                CtfConditionStateStatus::PreparedBinaryUnresolved
                                    | CtfConditionStateStatus::ResolvedBinary
                            )
                        });
                    if prepared
                        || !endpoint_is_prepared
                        || !matches!(
                            parse_condition_preparation(log, identity.condition_id),
                            Some((2, _))
                        )
                    {
                        fact.status = CtfOperationTransactionStatus::Unavailable;
                        fact.reason = Some("condition_preparation_event_mismatch");
                        complete = false;
                        lifecycle_seen = true;
                        break;
                    }
                    prepared = true;
                    preparation_event_seen = true;
                    lifecycle_seen = true;
                } else if log
                    .address
                    .eq_ignore_ascii_case(CTF_CONDITIONAL_TOKENS_ADDRESS)
                    && log
                        .topics
                        .first()
                        .is_some_and(|topic| topic.eq_ignore_ascii_case(CONDITION_RESOLUTION_TOPIC))
                {
                    let Some((count, event_condition, oracle, question, event_numerators)) =
                        parse_condition_resolution_full(log)
                    else {
                        fact.status = CtfOperationTransactionStatus::Unavailable;
                        fact.reason = Some("condition_resolution_event_malformed");
                        complete = false;
                        lifecycle_seen = true;
                        break;
                    };
                    let endpoint = condition
                        .proofs
                        .iter()
                        .find(|proof| proof.block_number == block.block_number);
                    let Some(numerators) = <[U256; 2]>::try_from(event_numerators.as_slice()).ok()
                    else {
                        fact.status = CtfOperationTransactionStatus::Unavailable;
                        fact.reason = Some("condition_resolution_event_nonbinary");
                        complete = false;
                        lifecycle_seen = true;
                        break;
                    };
                    if !prepared
                        || payout.is_some()
                        || transaction.logs.len() != 1
                        || count != U256::from(2)
                        || event_condition != identity.condition_id
                        || derive_condition_id(&oracle, question, count)
                            != Some(identity.condition_id)
                        || endpoint.is_none_or(|proof| {
                            proof.status != CtfConditionStateStatus::ResolvedBinary
                                || proof.payout_numerators != numerators
                        })
                    {
                        fact.status = CtfOperationTransactionStatus::Unavailable;
                        fact.reason = Some("condition_resolution_event_mismatches_root_state");
                        complete = false;
                        lifecycle_seen = true;
                        break;
                    }
                    let Some(OperationCall::Resolve {
                        question_id,
                        numerators: call_numerators,
                    }) = transaction.input.as_deref().and_then(decode_call)
                    else {
                        fact.status = CtfOperationTransactionStatus::Unavailable;
                        fact.reason = Some("condition_resolution_call_unbound");
                        complete = false;
                        lifecycle_seen = true;
                        break;
                    };
                    let caller = transaction.recovered_from.as_deref();
                    if call_numerators != numerators
                        || question_id != question
                        || caller.is_none_or(|caller| !caller.eq_ignore_ascii_case(&oracle))
                        || !transaction.replay_protected_sender
                        || !transaction.value.is_zero()
                    {
                        fact.status = CtfOperationTransactionStatus::Unavailable;
                        fact.reason = Some("condition_resolution_call_event_mismatch");
                        complete = false;
                        lifecycle_seen = true;
                        break;
                    }
                    payout = Some((numerators, endpoint.unwrap().payout_denominator));
                    resolution_event_seen = true;
                    fact.kind = Some(CtfOperationKind::ResolveCondition);
                    fact.status = CtfOperationTransactionStatus::Matched;
                    fact.log_indices.push(log.block_log_index);
                    lifecycle_seen = true;
                }
            }
            if fact.status == CtfOperationTransactionStatus::Unavailable {
                if lifecycle_seen {
                    inventory_and_lifecycle_consistent = false;
                }
                transactions.push(fact);
                continue;
            }
            if ctf_call {
                let decoded = transaction.input.as_deref().and_then(decode_call);
                if let Some(OperationCall::Prepare {
                    oracle,
                    question_id,
                    outcome_count,
                }) = decoded.as_ref()
                {
                    let Some((count, event_condition, event_oracle, event_question)) = transaction
                        .logs
                        .iter()
                        .find_map(parse_condition_preparation_full)
                    else {
                        fact.status = CtfOperationTransactionStatus::Unavailable;
                        fact.reason = Some("condition_preparation_event_missing");
                        complete = false;
                        transactions.push(fact);
                        continue;
                    };
                    if transaction.recovered_from.is_none()
                        || !transaction.replay_protected_sender
                        || !transaction.value.is_zero()
                        || transaction.logs.len() != 1
                        || *outcome_count != U256::from(2)
                        || count != U256::from(2)
                        || event_condition != identity.condition_id
                        || derive_condition_id(&event_oracle, event_question, count)
                            != Some(identity.condition_id)
                        || event_oracle != *oracle
                        || event_question != *question_id
                    {
                        fact.status = CtfOperationTransactionStatus::Unavailable;
                        fact.reason = Some("condition_preparation_call_event_mismatch");
                        complete = false;
                    } else {
                        fact.status = CtfOperationTransactionStatus::Matched;
                        fact.kind = Some(CtfOperationKind::PrepareCondition);
                        fact.log_indices = transaction
                            .logs
                            .iter()
                            .map(|log| log.block_log_index)
                            .collect();
                    }
                } else if !fact.transfer_references.is_empty()
                    || decoded.as_ref().is_some_and(|call| {
                        matches!(
                            call,
                            OperationCall::Split { .. }
                                | OperationCall::Merge { .. }
                                | OperationCall::Redeem { .. }
                        )
                    })
                {
                    let owner_call = transaction
                        .recovered_from
                        .as_deref()
                        .is_some_and(|caller| caller.eq_ignore_ascii_case(owner))
                        && transaction.replay_protected_sender
                        && transaction.value.is_zero();
                    let result = decoded.as_ref().and_then(|call| match call {
                        OperationCall::Split {
                            collateral,
                            parent,
                            condition,
                            partition,
                            amount,
                        } => Some(check_split_or_merge(
                            transaction,
                            owner,
                            identity,
                            collateral,
                            *parent,
                            *condition,
                            partition,
                            *amount,
                            balances,
                            prepared,
                            true,
                        )),
                        OperationCall::Merge {
                            collateral,
                            parent,
                            condition,
                            partition,
                            amount,
                        } => Some(check_split_or_merge(
                            transaction,
                            owner,
                            identity,
                            collateral,
                            *parent,
                            *condition,
                            partition,
                            *amount,
                            balances,
                            prepared,
                            false,
                        )),
                        OperationCall::Redeem {
                            collateral,
                            parent,
                            condition,
                            index_sets,
                        } => Some(check_redeem(
                            transaction,
                            owner,
                            identity,
                            collateral,
                            *parent,
                            *condition,
                            index_sets,
                            balances,
                            payout,
                        )),
                        OperationCall::Prepare { .. } | OperationCall::Resolve { .. } => None,
                    });
                    if !owner_call {
                        fact.status = CtfOperationTransactionStatus::Unavailable;
                        fact.reason = Some("direct_ctf_call_sender_value_or_chain_mismatch");
                        complete = false;
                    } else if let Some((kind, amount, positions, index_sets, event_logs)) =
                        result.flatten()
                    {
                        fact.kind = Some(kind);
                        fact.collateral_amount = amount;
                        fact.position_amounts = positions;
                        fact.index_sets = index_sets;
                        fact.payout = (kind == CtfOperationKind::Redeem)
                            .then_some(amount.unwrap_or_default());
                        fact.log_indices = event_logs;
                        if collateral_proxy_upgrade
                            && matches!(
                                kind,
                                CtfOperationKind::Split
                                    | CtfOperationKind::Merge
                                    | CtfOperationKind::Redeem
                            )
                        {
                            fact.status = CtfOperationTransactionStatus::Unavailable;
                            fact.reason = Some("collateral_proxy_upgrade_observed_in_interval");
                        } else {
                            fact.status = CtfOperationTransactionStatus::Matched;
                        }
                    } else {
                        fact.status = CtfOperationTransactionStatus::Unavailable;
                        fact.reason = Some(if collateral_proxy_upgrade {
                            "collateral_proxy_upgrade_observed_in_interval"
                        } else {
                            "direct_ctf_operation_logs_or_state_mismatch"
                        });
                        complete = false;
                    }
                } else if has_lifecycle {
                    if fact.kind.is_none() {
                        fact.status = CtfOperationTransactionStatus::Unavailable;
                        fact.reason = Some("condition_lifecycle_event_without_supported_call");
                        complete = false;
                    } else if fact.status == CtfOperationTransactionStatus::OutsideSelectedPairScope
                    {
                        fact.status = CtfOperationTransactionStatus::Matched;
                        fact.log_indices = transaction
                            .logs
                            .iter()
                            .map(|log| log.block_log_index)
                            .collect();
                    }
                } else if decoded.is_some() {
                    fact.status = CtfOperationTransactionStatus::Unavailable;
                    fact.reason = Some("direct_ctf_operation_without_exact_owner_scope");
                    complete = false;
                } else if has_operation_event {
                    fact.status = CtfOperationTransactionStatus::Unavailable;
                    fact.reason = Some("direct_ctf_operation_call_malformed_or_unsupported");
                    complete = false;
                }
            } else if !fact.transfer_references.is_empty() {
                if exchange_call || has_operation_event {
                    fact.status = CtfOperationTransactionStatus::Unavailable;
                    fact.reason = Some(if exchange_call {
                        "v1_exchange_operation_classification_pending"
                    } else {
                        "ctf_operation_event_from_unsupported_target"
                    });
                    complete = false;
                } else {
                    fact.status = CtfOperationTransactionStatus::ExternalMovement;
                    fact.reason = Some("external_transfer_basis_consideration_and_control_unknown");
                }
                fact.log_indices = fact
                    .transfer_references
                    .iter()
                    .map(|reference| reference.log_index)
                    .collect();
            } else if lifecycle_seen {
                fact.status = CtfOperationTransactionStatus::Unavailable;
                fact.reason = Some("condition_lifecycle_event_from_unsupported_target");
                complete = false;
            }

            if !apply_movements(
                transaction,
                owner,
                identity.position_ids.map(|id| U256::from_be_bytes(id.0)),
                &mut balances,
                &mut cash,
                deadline,
            )
            .await
            {
                if tokio::time::Instant::now() >= deadline {
                    return Err(ChainLogAuditError::Unavailable);
                }
                fact.status = CtfOperationTransactionStatus::Unavailable;
                fact.reason = Some("rooted_owner_movement_replay_failed");
                complete = false;
                inventory_and_lifecycle_consistent = false;
            }
            if lifecycle_seen && fact.status == CtfOperationTransactionStatus::Unavailable {
                inventory_and_lifecycle_consistent = false;
            }
            transactions.push(fact);
        }
        let proof_index = report
            .interval_evidence
            .blocks
            .iter()
            .position(|candidate| candidate.block_number == block.block_number)
            .ok_or(ChainLogAuditError::Unverified)?
            + 1;
        let snapshot = inventory
            .snapshots
            .get(proof_index)
            .ok_or(ChainLogAuditError::Unverified)?;
        let cash_proof = report
            .paired_inventory
            .usdc_e_proofs
            .get(proof_index)
            .ok_or(ChainLogAuditError::Unverified)?;
        if balances != snapshot.balances || cash != cash_proof.balance {
            complete = false;
            inventory_and_lifecycle_consistent = false;
        }
        condition_state = condition
            .proofs
            .get(proof_index)
            .ok_or(ChainLogAuditError::Unverified)?
            .clone();
        if starting_condition_status == CtfConditionStateStatus::Unprepared
            && condition_state.status != CtfConditionStateStatus::Unprepared
            && !preparation_event_seen
        {
            complete = false;
            inventory_and_lifecycle_consistent = false;
        }
        if starting_condition_status != CtfConditionStateStatus::ResolvedBinary
            && condition_state.status == CtfConditionStateStatus::ResolvedBinary
            && !resolution_event_seen
        {
            complete = false;
            inventory_and_lifecycle_consistent = false;
        }
        prepared = matches!(
            condition_state.status,
            CtfConditionStateStatus::PreparedBinaryUnresolved
                | CtfConditionStateStatus::ResolvedBinary
        );
        if condition_state.status == CtfConditionStateStatus::ResolvedBinary {
            payout = Some((
                condition_state.payout_numerators,
                condition_state.payout_denominator,
            ));
        }
    }
    Ok(CtfOperationClassificationEvidence {
        owner: owner.to_owned(),
        condition_id: format!("{:#x}", identity.condition_id),
        position_ids: identity.position_ids.map(|id| U256::from_be_bytes(id.0)),
        snapshots: inventory.snapshots.clone(),
        transactions,
        complete_for_selected_pair_scope: complete,
        inventory_and_lifecycle_consistent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topic_address(address: &str) -> String {
        format!("0x{}{}", "00".repeat(12), &address[2..])
    }

    fn word_bytes(value: U256, target: &mut Vec<u8>) {
        target.extend_from_slice(&value.to_be_bytes::<32>());
    }

    fn log(
        address: &str,
        signature: &str,
        topics: Vec<String>,
        data: Vec<u8>,
        index: u64,
    ) -> ChainReceiptLog {
        ChainReceiptLog {
            block_number: 100,
            block_hash: format!("0x{}", "11".repeat(32)),
            transaction_hash: format!("0x{}", "22".repeat(32)),
            transaction_index: 0,
            block_log_index: index,
            address: address.to_owned(),
            topics: std::iter::once(signature.to_owned())
                .chain(topics)
                .collect(),
            data: format!("0x{}", hex::encode(data)),
        }
    }

    fn redeem_transaction(logs: Vec<ChainReceiptLog>) -> ChainReceiptIntervalTransaction {
        ChainReceiptIntervalTransaction {
            transaction_hash: format!("0x{}", "22".repeat(32)),
            transaction_index: 0,
            status: 1,
            receipt_type: 0,
            to: Some(CTF_CONDITIONAL_TOKENS_ADDRESS.to_owned()),
            input: None,
            recovered_from: None,
            value: U256::ZERO,
            replay_protected_sender: true,
            native_gas: None,
            logs,
            movement_observations: Vec::new(),
        }
    }

    fn payout_event(
        owner: &str,
        condition: B256,
        index_sets: &[U256],
        payout: U256,
    ) -> ChainReceiptLog {
        let mut data = Vec::new();
        word_bytes(U256::from_be_bytes(condition.0), &mut data);
        word_bytes(U256::from(96), &mut data);
        word_bytes(payout, &mut data);
        word_bytes(U256::from(index_sets.len()), &mut data);
        for index_set in index_sets {
            word_bytes(*index_set, &mut data);
        }
        log(
            CTF_CONDITIONAL_TOKENS_ADDRESS,
            PAYOUT_REDEMPTION_TOPIC,
            vec![
                topic_address(owner),
                topic_address(USDC_E_PROXY_ADDRESS),
                format!("{:#x}", B256::ZERO),
            ],
            data,
            0,
        )
    }

    fn identity() -> ctf_position_identity::DerivedRootBinaryIdentity {
        ctf_position_identity::DerivedRootBinaryIdentity {
            condition_id: B256::repeat_byte(0x33),
            collection_ids: [B256::repeat_byte(0x44), B256::repeat_byte(0x55)],
            position_ids: [B256::repeat_byte(0x66), B256::repeat_byte(0x77)],
            registry_keys: [B256::ZERO; 4],
            selected_index_set: 1,
        }
    }

    #[test]
    fn redemption_uses_source_floor_and_checked_uint256_arithmetic() {
        let owner = format!("0x{}", "88".repeat(20));
        let identity = identity();
        let condition = identity.condition_id;
        let index_sets = [U256::ONE];
        let mut burn_data = Vec::new();
        word_bytes(
            U256::from_be_bytes(identity.position_ids[0].0),
            &mut burn_data,
        );
        word_bytes(U256::ONE, &mut burn_data);
        let burn = log(
            CTF_CONDITIONAL_TOKENS_ADDRESS,
            ERC1155_TRANSFER_SINGLE,
            vec![
                topic_address(&owner),
                topic_address(&owner),
                topic_address(&format!("0x{}", "00".repeat(20))),
            ],
            burn_data,
            0,
        );
        let floor_transaction = redeem_transaction(vec![
            burn,
            payout_event(&owner, condition, &index_sets, U256::ZERO),
        ]);
        let floor = check_redeem(
            &floor_transaction,
            &owner,
            &identity,
            USDC_E_PROXY_ADDRESS,
            B256::ZERO,
            condition,
            &index_sets,
            [U256::ONE, U256::ZERO],
            Some(([U256::ONE, U256::ZERO], U256::from(3))),
        )
        .unwrap();
        assert_eq!(floor.0, CtfOperationKind::Redeem);
        assert_eq!(floor.1, Some(U256::ZERO));

        let empty_sets = [];
        let empty_transaction = redeem_transaction(vec![payout_event(
            &owner,
            condition,
            &empty_sets,
            U256::ZERO,
        )]);
        assert!(
            check_redeem(
                &empty_transaction,
                &owner,
                &identity,
                USDC_E_PROXY_ADDRESS,
                B256::ZERO,
                condition,
                &empty_sets,
                [U256::ZERO; 2],
                Some(([U256::ONE, U256::ZERO], U256::from(3))),
            )
            .is_some()
        );

        let empty = redeem_transaction(Vec::new());
        assert!(
            check_redeem(
                &empty,
                &owner,
                &identity,
                USDC_E_PROXY_ADDRESS,
                B256::ZERO,
                condition,
                &index_sets,
                [U256::MAX, U256::ZERO],
                Some(([U256::from(2), U256::ZERO], U256::ONE)),
            )
            .is_none()
        );
        assert!(
            check_redeem(
                &empty,
                &owner,
                &identity,
                USDC_E_PROXY_ADDRESS,
                B256::ZERO,
                condition,
                &[U256::ONE, U256::from(2)],
                [U256::MAX; 2],
                Some(([U256::ONE; 2], U256::ONE)),
            )
            .is_none()
        );
    }
}
