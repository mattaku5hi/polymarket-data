use super::*;

pub const V1_BINARY_TRADES_POLICY_VERSION: &str = "v1-binary-trades-exchange-inventory/1";
const V1_MAX_FEE_RATE_BPS: U256 = U256::from_limbs([1_000, 0, 0, 0]);

fn v1_fee_rate_is_contract_bounded(order: &V1DirectOrderCall) -> bool {
    order.fee_rate_bps <= V1_MAX_FEE_RATE_BPS
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V1BinaryTradeTransactionStatus {
    DirectCtfOperation,
    ExternalMovement,
    ExchangeTrade,
    Unavailable,
    FailedNoAssetOperation,
    OutsideSelectedPairScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V1ExchangeInventorySnapshot {
    block_number: u64,
    block_hash: String,
    state_root: String,
    ctf_code_hash: String,
    ctf_balance_storage_keys: [String; 2],
    ctf_balances: [U256; 2],
    usdc_e_proxy_code_hash: String,
    usdc_e_implementation_code_hash: String,
    usdc_e_balance_storage_key: String,
    usdc_e_balance: U256,
}

impl V1ExchangeInventorySnapshot {
    #[must_use]
    pub const fn block_number(&self) -> u64 {
        self.block_number
    }
    #[must_use]
    pub fn block_hash(&self) -> &str {
        &self.block_hash
    }
    #[must_use]
    pub fn state_root(&self) -> &str {
        &self.state_root
    }
    #[must_use]
    pub fn ctf_balance_storage_keys(&self) -> &[String; 2] {
        &self.ctf_balance_storage_keys
    }
    #[must_use]
    pub const fn ctf_balances(&self) -> [U256; 2] {
        self.ctf_balances
    }
    #[must_use]
    pub fn usdc_e_balance_storage_key(&self) -> &str {
        &self.usdc_e_balance_storage_key
    }
    #[must_use]
    pub const fn usdc_e_balance(&self) -> U256 {
        self.usdc_e_balance
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V1BinaryTradeTransactionFact {
    block_number: u64,
    block_hash: String,
    transaction_hash: String,
    transaction_index: u64,
    status: V1BinaryTradeTransactionStatus,
    reason: Option<&'static str>,
    trade_order_hashes: Vec<String>,
    log_indices: Vec<u64>,
}

impl V1BinaryTradeTransactionFact {
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
    pub const fn status(&self) -> V1BinaryTradeTransactionStatus {
        self.status
    }
    #[must_use]
    pub const fn reason(&self) -> Option<&'static str> {
        self.reason
    }
    #[must_use]
    pub fn trade_order_hashes(&self) -> &[String] {
        &self.trade_order_hashes
    }
    #[must_use]
    pub fn log_indices(&self) -> &[u64] {
        &self.log_indices
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V1BinaryTradesEvidence {
    condition_id: String,
    owner: String,
    position_ids: [U256; 2],
    snapshots: Vec<V1ExchangeInventorySnapshot>,
    transactions: Vec<V1BinaryTradeTransactionFact>,
    trades: Vec<V1AttributedTradeFact>,
    complete_for_binary_trade_scope: bool,
    exchange_inventory_replayed: bool,
    inventory_and_lifecycle_consistent: bool,
}

impl V1BinaryTradesEvidence {
    #[must_use]
    pub const fn policy_version(&self) -> &'static str {
        V1_BINARY_TRADES_POLICY_VERSION
    }
    #[must_use]
    pub fn condition_id(&self) -> &str {
        &self.condition_id
    }
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }
    #[must_use]
    pub const fn position_ids(&self) -> [U256; 2] {
        self.position_ids
    }
    #[must_use]
    pub fn snapshots(&self) -> &[V1ExchangeInventorySnapshot] {
        &self.snapshots
    }
    #[must_use]
    pub fn transactions(&self) -> &[V1BinaryTradeTransactionFact] {
        &self.transactions
    }
    #[must_use]
    pub fn trades(&self) -> &[V1AttributedTradeFact] {
        &self.trades
    }
    #[must_use]
    pub const fn complete_for_binary_trade_scope(&self) -> bool {
        self.complete_for_binary_trade_scope
    }
    #[must_use]
    pub const fn exchange_inventory_replayed(&self) -> bool {
        self.exchange_inventory_replayed
    }
    #[must_use]
    pub const fn inventory_and_lifecycle_consistent(&self) -> bool {
        self.inventory_and_lifecycle_consistent
    }
}

pub(super) async fn verify_exchange_inventory_inner(
    verifier: &ChainLogVerifier,
    report: &V1TradeAttributionReport,
    identity: &ctf_position_identity::DerivedRootBinaryIdentity,
    deadline: tokio::time::Instant,
) -> Result<Vec<V1ExchangeInventorySnapshot>, ChainLogAuditError> {
    let owner_inventory = report
        .complementary_inventory
        .as_ref()
        .ok_or(ChainLogAuditError::Unverified)?;
    let selected_usdc = &report.paired_inventory.usdc_e_proofs;
    let identity_contexts = report
        .ctf_position_identity
        .as_ref()
        .ok_or(ChainLogAuditError::Unverified)?;
    if owner_inventory.snapshots.len() != identity_contexts.proofs.len()
        || selected_usdc.len() != identity_contexts.proofs.len()
        || identity_contexts.proofs.is_empty()
    {
        return Err(ChainLogAuditError::Unverified);
    }
    let pair = identity.position_ids.map(|id| U256::from_be_bytes(id.0));
    let exchange = Address::from_slice(
        &hex::decode(&EXCHANGES[0][2..]).map_err(|_| ChainLogAuditError::Unverified)?,
    );
    let mut snapshots = Vec::with_capacity(identity_contexts.proofs.len());
    for (index, context) in identity_contexts.proofs.iter().enumerate() {
        if tokio::time::Instant::now() >= deadline {
            return Err(ChainLogAuditError::Unavailable);
        }
        let owner_pair = &owner_inventory.snapshots[index];
        let owner_cash = &selected_usdc[index];
        if context.block_number != owner_pair.block_number
            || context.block_hash != owner_pair.block_hash
            || context.state_root != owner_pair.state_root
            || owner_cash.block_number != context.block_number
            || owner_cash.block_hash != context.block_hash
            || owner_cash.state_root != context.state_root
            || owner_pair.token_ids != pair
        {
            return Err(ChainLogAuditError::Unverified);
        }
        let (left, right) = tokio::try_join!(
            exchange_inventory_provider(
                verifier,
                &verifier.primary,
                context.block_number,
                &context.state_root,
                pair,
                exchange
            ),
            exchange_inventory_provider(
                verifier,
                &verifier.secondary,
                context.block_number,
                &context.state_root,
                pair,
                exchange
            ),
        )?;
        if left != right {
            return Err(ChainLogAuditError::Divergent);
        }
        snapshots.push(V1ExchangeInventorySnapshot {
            block_number: context.block_number,
            block_hash: context.block_hash.clone(),
            state_root: context.state_root.clone(),
            ctf_code_hash: left.ctf_code_hash,
            ctf_balance_storage_keys: left.ctf_keys,
            ctf_balances: left.ctf_balances,
            usdc_e_proxy_code_hash: left.usdc_proxy_code_hash,
            usdc_e_implementation_code_hash: owner_cash.implementation_code_hash.clone(),
            usdc_e_balance_storage_key: left.usdc_key,
            usdc_e_balance: left.usdc_balance,
        });
    }
    Ok(snapshots)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderInventory {
    ctf_code_hash: String,
    ctf_keys: [String; 2],
    ctf_balances: [U256; 2],
    usdc_proxy_code_hash: String,
    usdc_key: String,
    usdc_balance: U256,
}

async fn exchange_inventory_provider(
    verifier: &ChainLogVerifier,
    endpoint: &str,
    block_number: u64,
    expected_state_root: &str,
    pair: [U256; 2],
    exchange: Address,
) -> Result<ProviderInventory, ChainLogAuditError> {
    let tag = format!("{block_number:#x}");
    let ctf_address = CTF_CONDITIONAL_TOKENS_ADDRESS;
    let ctf_keys = pair.map(|id| ctf_erc1155_balance_storage_key(exchange, id));
    let usdc_key = usdc_e_erc20_balance_storage_key(exchange);
    let (ctf_proof, usdc_proof) = tokio::try_join!(
        verifier.rpc(
            endpoint,
            "eth_getProof",
            json!([
                ctf_address,
                ctf_keys.map(|key| format!("{key:#x}")),
                tag.clone()
            ])
        ),
        verifier.rpc(
            endpoint,
            "eth_getProof",
            json!([USDC_E_PROXY_ADDRESS, [format!("{usdc_key:#x}")], tag])
        ),
    )?;
    let ctf_account = verify_eip1186_account_proof(expected_state_root, ctf_address, &ctf_proof)?;
    if ctf_account.code_hash != B256::from(CTF_CONDITIONAL_TOKENS_CODE_HASH_CANDIDATE) {
        return Err(ChainLogAuditError::Unverified);
    }
    let ctf_entries = exact_eip1186_storage_entries(&ctf_proof, &ctf_keys)?;
    let mut ctf_balances = [U256::ZERO; 2];
    for index in 0..2 {
        ctf_balances[index] = parse_eip1186_storage_value(field(ctf_entries[index], "value")?)?;
        verify_eip1186_storage_proof(
            &ctf_account,
            ctf_keys[index],
            ctf_entries[index],
            (!ctf_balances[index].is_zero()).then(|| rlp_u256(ctf_balances[index])),
            true,
        )?;
    }
    let usdc_account =
        verify_eip1186_account_proof(expected_state_root, USDC_E_PROXY_ADDRESS, &usdc_proof)?;
    if usdc_account.code_hash != parse_fixed_b256(USDC_E_PROXY_CODE_HASH_CANDIDATE)? {
        return Err(ChainLogAuditError::Unverified);
    }
    let usdc_entries = exact_eip1186_storage_entries(&usdc_proof, &[usdc_key])?;
    let usdc_balance = parse_eip1186_storage_value(field(usdc_entries[0], "value")?)?;
    verify_eip1186_storage_proof(
        &usdc_account,
        usdc_key,
        usdc_entries[0],
        (!usdc_balance.is_zero()).then(|| rlp_u256(usdc_balance)),
        true,
    )?;
    Ok(ProviderInventory {
        ctf_code_hash: format!("{:#x}", ctf_account.code_hash),
        ctf_keys: ctf_keys.map(|key| format!("{key:#x}")),
        ctf_balances,
        usdc_proxy_code_hash: format!("{:#x}", usdc_account.code_hash),
        usdc_key: format!("{usdc_key:#x}"),
        usdc_balance,
    })
}

pub(super) async fn classify_report(
    report: &V1TradeAttributionReport,
    snapshots: Vec<V1ExchangeInventorySnapshot>,
    owner: &str,
    identity: &ctf_position_identity::DerivedRootBinaryIdentity,
    deadline: tokio::time::Instant,
) -> Result<V1BinaryTradesEvidence, ChainLogAuditError> {
    if snapshots.len() != report.interval_evidence.blocks.len() + 1 {
        return Err(ChainLogAuditError::Unverified);
    }
    let position_ids = identity.position_ids.map(|id| U256::from_be_bytes(id.0));
    let mut exchange_positions = snapshots[0].ctf_balances;
    let mut exchange_cash = snapshots[0].usdc_e_balance;
    let condition_proofs = report
        .ctf_condition_state
        .as_ref()
        .ok_or(ChainLogAuditError::Unverified)?;
    let opening_condition_status = condition_proofs.proofs.first().map(|proof| proof.status);
    let mut prepared = condition_proofs
        .proofs
        .first()
        .is_some_and(|proof| binary_condition_ready(proof.status));
    let inventory_and_lifecycle_consistent = report
        .ctf_operations
        .as_ref()
        .is_some_and(CtfOperationClassificationEvidence::inventory_and_lifecycle_consistent);
    let mut transactions = Vec::new();
    let mut complete = inventory_and_lifecycle_consistent
        && opening_condition_status.is_some_and(condition_scope_supported);
    let mut replayed = true;
    let mut trades = Vec::new();
    for (block_index, block) in report.interval_evidence.blocks.iter().enumerate() {
        for transaction in &block.transactions {
            if transactions.len() % 32 == 0 {
                tokio::task::yield_now().await;
                if tokio::time::Instant::now() >= deadline {
                    return Err(ChainLogAuditError::Unavailable);
                }
            }
            let ctf_fact = report.ctf_operations.as_ref().and_then(|e| {
                e.transactions()
                    .iter()
                    .find(|f| f.transaction_hash() == transaction.transaction_hash)
            });
            let mut classified = None;
            let exchange_target = transaction
                .to
                .as_deref()
                .is_some_and(|to| to.eq_ignore_ascii_case(EXCHANGES[0]));
            let can_replace_ctf_pending = ctf_fact.is_none_or(|fact| {
                fact.status() != CtfOperationTransactionStatus::Unavailable
                    || fact.reason() == Some("v1_exchange_operation_classification_pending")
            });
            if exchange_target && transaction.status == 1 && can_replace_ctf_pending {
                if let Some(input) = transaction.input.as_deref() {
                    if v1_match_orders_selector(input)
                        && match_orders_is_in_pair_scope(input, owner, position_ids)
                    {
                        classified = Some(classify_match_orders_binary(
                            transaction,
                            owner,
                            identity,
                            ExchangeMatchContext {
                                block_number: block.block_number,
                                block_hash: &block.block_hash,
                                prepared,
                                opening_positions: exchange_positions,
                                opening_cash: exchange_cash,
                            },
                        ));
                    } else if direct_orders_is_in_pair_scope(input, owner, position_ids) {
                        classified = Some(classify_direct_orders_binary(
                            block.block_number,
                            &block.block_hash,
                            transaction,
                            owner,
                            position_ids,
                        ));
                    }
                }
            }
            let (status, reason, hashes, logs) = match classified {
                Some(Ok(found)) => {
                    trades.extend(found.owner_trades);
                    (
                        V1BinaryTradeTransactionStatus::ExchangeTrade,
                        None,
                        found.order_hashes,
                        found.log_indices,
                    )
                }
                Some(Err(classification_reason)) => {
                    complete = false;
                    (
                        V1BinaryTradeTransactionStatus::Unavailable,
                        Some(classification_reason),
                        Vec::new(),
                        ctf_fact.map_or_else(Vec::new, |fact| fact.log_indices().to_vec()),
                    )
                }
                None => match ctf_fact {
                    Some(fact) if fact.status() == CtfOperationTransactionStatus::Matched => (
                        V1BinaryTradeTransactionStatus::DirectCtfOperation,
                        None,
                        Vec::new(),
                        fact.log_indices().to_vec(),
                    ),
                    Some(fact)
                        if fact.status() == CtfOperationTransactionStatus::ExternalMovement =>
                    {
                        (
                            V1BinaryTradeTransactionStatus::ExternalMovement,
                            fact.reason(),
                            Vec::new(),
                            fact.log_indices().to_vec(),
                        )
                    }
                    Some(fact)
                        if fact.status()
                            == CtfOperationTransactionStatus::FailedNoAssetOperation =>
                    {
                        (
                            V1BinaryTradeTransactionStatus::FailedNoAssetOperation,
                            fact.reason(),
                            Vec::new(),
                            Vec::new(),
                        )
                    }
                    Some(fact)
                        if fact.status() == CtfOperationTransactionStatus::Unavailable
                            && fact.reason()
                                != Some("v1_exchange_operation_classification_pending") =>
                    {
                        complete = false;
                        (
                            V1BinaryTradeTransactionStatus::Unavailable,
                            fact.reason(),
                            Vec::new(),
                            fact.log_indices().to_vec(),
                        )
                    }
                    Some(fact)
                        if fact.status()
                            == CtfOperationTransactionStatus::OutsideSelectedPairScope =>
                    {
                        (
                            V1BinaryTradeTransactionStatus::OutsideSelectedPairScope,
                            None,
                            Vec::new(),
                            Vec::new(),
                        )
                    }
                    Some(fact)
                        if fact.reason()
                            == Some("v1_exchange_operation_classification_pending") =>
                    {
                        complete = false;
                        (
                            V1BinaryTradeTransactionStatus::Unavailable,
                            Some("v1_binary_exchange_receipt_unsupported"),
                            Vec::new(),
                            fact.log_indices().to_vec(),
                        )
                    }
                    _ => (
                        V1BinaryTradeTransactionStatus::OutsideSelectedPairScope,
                        None,
                        Vec::new(),
                        Vec::new(),
                    ),
                },
            };
            if transaction.status == 0 {
                // Failed receipts do not change Exchange asset balances.
            } else if !apply_exchange_movement_observations(
                transaction,
                &mut exchange_positions,
                &mut exchange_cash,
                position_ids,
            ) {
                replayed = false;
                complete = false;
            }
            if ctf_fact.is_some_and(|fact| {
                fact.status() == CtfOperationTransactionStatus::Matched
                    && fact.kind() == Some(CtfOperationKind::PrepareCondition)
            }) {
                prepared = true;
            }
            transactions.push(V1BinaryTradeTransactionFact {
                block_number: block.block_number,
                block_hash: block.block_hash.clone(),
                transaction_hash: transaction.transaction_hash.clone(),
                transaction_index: transaction.transaction_index,
                status,
                reason,
                trade_order_hashes: hashes,
                log_indices: logs,
            });
        }
        let end = &snapshots[block_index + 1];
        if end.block_number != block.block_number
            || end.block_hash != block.block_hash
            || end.ctf_balances != exchange_positions
            || end.usdc_e_balance != exchange_cash
        {
            replayed = false;
            complete = false;
        }
        let condition_status = condition_proofs
            .proofs
            .get(block_index + 1)
            .map(|proof| proof.status);
        prepared = condition_status.is_some_and(binary_condition_ready);
        complete &= condition_status.is_some_and(condition_scope_supported);
    }
    complete &= replayed;
    Ok(V1BinaryTradesEvidence {
        condition_id: format!("{:#x}", identity.condition_id),
        owner: owner.to_owned(),
        position_ids: identity.position_ids.map(|id| U256::from_be_bytes(id.0)),
        snapshots,
        transactions,
        trades,
        complete_for_binary_trade_scope: complete,
        exchange_inventory_replayed: replayed,
        inventory_and_lifecycle_consistent,
    })
}

fn binary_condition_ready(status: CtfConditionStateStatus) -> bool {
    matches!(
        status,
        CtfConditionStateStatus::PreparedBinaryUnresolved | CtfConditionStateStatus::ResolvedBinary
    )
}

fn condition_scope_supported(status: CtfConditionStateStatus) -> bool {
    status != CtfConditionStateStatus::UnsupportedNonBinary
}

struct ClassifiedExchangeTransaction {
    owner_trades: Vec<V1AttributedTradeFact>,
    order_hashes: Vec<String>,
    log_indices: Vec<u64>,
}

struct ExchangeMatchContext<'a> {
    block_number: u64,
    block_hash: &'a str,
    prepared: bool,
    opening_positions: [U256; 2],
    opening_cash: U256,
}

enum ExpectedLog<'a> {
    Transfer {
        asset: U256,
        from: String,
        to: String,
        amount: U256,
        approval: Option<(String, String, U256)>,
    },
    CtfOperation {
        amount: U256,
        split: bool,
    },
    FeeCharged {
        receiver: String,
        token_id: U256,
        amount: U256,
    },
    OrderFilled {
        order: &'a V1DirectOrderCall,
        taker: String,
        making: U256,
        taking: U256,
        fee: U256,
    },
    OrdersMatched {
        order_hash: String,
        order: &'a V1DirectOrderCall,
        making: U256,
        taking: U256,
    },
}

fn classify_match_orders_binary(
    transaction: &ChainReceiptIntervalTransaction,
    owner: &str,
    identity: &ctf_position_identity::DerivedRootBinaryIdentity,
    context: ExchangeMatchContext<'_>,
) -> Result<ClassifiedExchangeTransaction, &'static str> {
    let operator = transaction
        .recovered_from
        .as_deref()
        .ok_or("root_bound_match_orders_sender_unavailable")?;
    if !transaction.replay_protected_sender || !transaction.value.is_zero() {
        return Err("match_orders_sender_chain_or_value_mismatch");
    }
    let call = transaction
        .input
        .as_deref()
        .and_then(decode_v1_match_orders_call)
        .ok_or("unsupported_or_malformed_match_orders_calldata")?;
    let active = &call.taker_order;
    let position_ids = identity.position_ids.map(|id| U256::from_be_bytes(id.0));
    if !position_ids.contains(&active.token_id)
        || call.taker_fill_amount.is_zero()
        || active.maker_amount.is_zero()
        || active.taker_amount.is_zero()
        || call.taker_fill_amount > active.maker_amount
        || !v1_fee_rate_is_contract_bounded(active)
    {
        return Err("match_orders_active_order_is_not_a_valid_binary_fill");
    }
    if call.maker_orders.is_empty() || call.maker_orders.len() != call.maker_fill_amounts.len() {
        return Err("match_orders_parallel_maker_arrays_disagree");
    }
    let zero = zero_address();
    if active.taker != zero && !active.taker.eq_ignore_ascii_case(operator) {
        return Err("match_orders_taker_restriction_disagrees_with_operator");
    }
    if !valid_v1_trade_party(&active.maker, operator) || owner.eq_ignore_ascii_case(operator) {
        return Err("match_orders_parties_are_not_distinct_valid_roles");
    }
    let active_hash = v1_order_hash(active).ok_or("active_order_hash_unavailable")?;
    let mut hashes = Vec::with_capacity(call.maker_orders.len());
    let mut takings = Vec::with_capacity(call.maker_orders.len());
    let mut fees = Vec::with_capacity(call.maker_orders.len());
    let mut nets = Vec::with_capacity(call.maker_orders.len());
    let mut passive_log_refs = Vec::with_capacity(call.maker_orders.len());
    let mut balances = context.opening_positions;
    let mut cash = context.opening_cash;
    let (active_maker_asset, active_taker_asset) = order_asset_ids(active);
    let mut expected = Vec::new();
    let active_making_expected_index = expected.len();
    push_transfer(
        &mut expected,
        active_maker_asset,
        active.maker.clone(),
        EXCHANGES[0].to_owned(),
        call.taker_fill_amount,
        true,
    );
    move_balance_for_asset(
        &mut balances,
        &mut cash,
        position_ids,
        active_maker_asset,
        true,
        call.taker_fill_amount,
    )
    .ok_or("exchange_opening_or_active_making_balance_overflow")?;

    for (maker, maker_fill) in call.maker_orders.iter().zip(&call.maker_fill_amounts) {
        if maker.maker_amount.is_zero()
            || maker.taker_amount.is_zero()
            || maker_fill.is_zero()
            || *maker_fill > maker.maker_amount
            || !v1_fee_rate_is_contract_bounded(maker)
            || (maker.taker != zero && !maker.taker.eq_ignore_ascii_case(operator))
            || !valid_v1_trade_party(&maker.maker, operator)
            || maker.maker.eq_ignore_ascii_case(&active.maker)
        {
            return Err("match_orders_passive_order_role_or_amount_invalid");
        }
        let hash = v1_order_hash(maker).ok_or("passive_order_hash_unavailable")?;
        if hash.eq_ignore_ascii_case(&active_hash)
            || hashes
                .iter()
                .any(|prior: &String| prior.eq_ignore_ascii_case(&hash))
        {
            return Err("repeated_match_orders_order_hash_unsupported");
        }
        let (maker_asset, taker_asset) = order_asset_ids(maker);
        let same_side = maker.side == active.side;
        if same_side {
            if !context.prepared
                || !position_ids.contains(&maker.token_id)
                || maker.token_id == active.token_id
            {
                return Err("same_side_passive_token_is_not_derived_complement");
            }
        } else if maker.token_id != active.token_id {
            return Err("opposite_side_passive_token_does_not_match_active");
        }
        let active_price = order_price(active).ok_or("active_order_price_overflow")?;
        let maker_price = order_price(maker).ok_or("passive_order_price_overflow")?;
        let crossing = match (active.side, maker.side) {
            (V1DirectFillSide::Buy, V1DirectFillSide::Buy) => active_price
                .checked_add(maker_price)
                .is_some_and(|sum| sum >= one()),
            (V1DirectFillSide::Buy, V1DirectFillSide::Sell)
            | (V1DirectFillSide::Sell, V1DirectFillSide::Buy) => {
                let (buy, sell) = if active.side == V1DirectFillSide::Buy {
                    (active_price, maker_price)
                } else {
                    (maker_price, active_price)
                };
                buy >= sell
            }
            (V1DirectFillSide::Sell, V1DirectFillSide::Sell) => active_price
                .checked_add(maker_price)
                .is_some_and(|sum| sum <= one()),
        };
        if !crossing {
            return Err("match_orders_orders_are_not_source_price_crossing");
        }
        let taking = checked_mul_div(*maker_fill, maker.taker_amount, maker.maker_amount)
            .ok_or("passive_taking_checked_u256_overflow")?;
        let fee =
            calculate_v1_match_order_fee(maker, *maker_fill, taking, V1MatchFeePrice::SignedOrder)
                .ok_or("passive_fee_checked_u256_overflow")?;
        if fee > taking {
            return Err("passive_fee_exceeds_taking_amount");
        }
        let making_expected_index = expected.len();
        push_transfer(
            &mut expected,
            maker_asset,
            maker.maker.clone(),
            EXCHANGES[0].to_owned(),
            *maker_fill,
            true,
        );
        move_balance_for_asset(
            &mut balances,
            &mut cash,
            position_ids,
            maker_asset,
            true,
            *maker_fill,
        )
        .ok_or("passive_making_balance_overflow")?;
        if same_side {
            let split = active.side == V1DirectFillSide::Buy;
            let operation_amount = if split { taking } else { *maker_fill };
            expected.push(ExpectedLog::CtfOperation {
                amount: operation_amount,
                split,
            });
            if split {
                cash = cash
                    .checked_sub(operation_amount)
                    .ok_or("exchange_split_collateral_underflow")?;
                for balance in &mut balances {
                    *balance = balance
                        .checked_add(operation_amount)
                        .ok_or("exchange_split_position_overflow")?;
                }
            } else {
                for balance in &mut balances {
                    *balance = balance
                        .checked_sub(operation_amount)
                        .ok_or("exchange_merge_position_underflow")?;
                }
                cash = cash
                    .checked_add(operation_amount)
                    .ok_or("exchange_merge_collateral_overflow")?;
            }
        }
        let receiving_expected_index = expected.len();
        push_transfer(
            &mut expected,
            taker_asset,
            EXCHANGES[0].to_owned(),
            maker.maker.clone(),
            taking - fee,
            false,
        );
        move_balance_for_asset(
            &mut balances,
            &mut cash,
            position_ids,
            taker_asset,
            false,
            taking,
        )
        .ok_or("passive_payout_balance_underflow")?;
        if !fee.is_zero() {
            expected.push(ExpectedLog::Transfer {
                asset: taker_asset,
                from: EXCHANGES[0].to_owned(),
                to: operator.to_owned(),
                amount: fee,
                approval: None,
            });
            expected.push(ExpectedLog::FeeCharged {
                receiver: operator.to_owned(),
                token_id: taker_asset,
                amount: fee,
            });
        }
        let order_filled_expected_index = expected.len();
        expected.push(ExpectedLog::OrderFilled {
            order: maker,
            taker: active.maker.clone(),
            making: *maker_fill,
            taking,
            fee,
        });
        passive_log_refs.push((
            making_expected_index,
            receiving_expected_index,
            order_filled_expected_index,
        ));
        hashes.push(hash);
        takings.push(taking);
        fees.push(fee);
        nets.push(taking - fee);
    }

    let minimum = checked_mul_div(
        call.taker_fill_amount,
        active.taker_amount,
        active.maker_amount,
    )
    .ok_or("active_minimum_taking_overflow")?;
    let active_taking = balance_for_asset(balances, cash, position_ids, active_taker_asset)
        .ok_or("active_taking_asset_not_in_binary_scope")?;
    if active_taking < minimum {
        return Err("exchange_actual_taking_below_source_minimum");
    }
    let active_fee = calculate_v1_match_order_fee(
        active,
        call.taker_fill_amount,
        active_taking,
        V1MatchFeePrice::ActualFill,
    )
    .ok_or("active_fee_checked_u256_overflow")?;
    if active_fee > active_taking {
        return Err("active_fee_exceeds_taking_amount");
    }
    let active_net = active_taking - active_fee;
    move_balance_for_asset(
        &mut balances,
        &mut cash,
        position_ids,
        active_taker_asset,
        false,
        active_taking,
    )
    .ok_or("active_taking_balance_underflow")?;
    let active_receiving_expected_index = expected.len();
    push_transfer(
        &mut expected,
        active_taker_asset,
        EXCHANGES[0].to_owned(),
        active.maker.clone(),
        active_net,
        false,
    );
    if !active_fee.is_zero() {
        expected.push(ExpectedLog::Transfer {
            asset: active_taker_asset,
            from: EXCHANGES[0].to_owned(),
            to: operator.to_owned(),
            amount: active_fee,
            approval: None,
        });
        expected.push(ExpectedLog::FeeCharged {
            receiver: operator.to_owned(),
            token_id: active_taker_asset,
            amount: active_fee,
        });
    }
    let refund = balance_for_asset(balances, cash, position_ids, active_maker_asset)
        .ok_or("active_refund_asset_not_in_binary_scope")?;
    let refund_expected_index = if !refund.is_zero() {
        let index = expected.len();
        expected.push(ExpectedLog::Transfer {
            asset: active_maker_asset,
            from: EXCHANGES[0].to_owned(),
            to: active.maker.clone(),
            amount: refund,
            approval: None,
        });
        move_balance_for_asset(
            &mut balances,
            &mut cash,
            position_ids,
            active_maker_asset,
            false,
            refund,
        )
        .ok_or("active_refund_balance_underflow")?;
        Some(index)
    } else {
        None
    };
    let active_order_filled_expected_index = expected.len();
    expected.push(ExpectedLog::OrderFilled {
        order: active,
        taker: EXCHANGES[0].to_owned(),
        making: call.taker_fill_amount,
        taking: active_taking,
        fee: active_fee,
    });
    expected.push(ExpectedLog::OrdersMatched {
        order_hash: active_hash.clone(),
        order: active,
        making: call.taker_fill_amount,
        taking: active_taking,
    });
    let matched_logs = match_expected_logs(&transaction.logs, &expected, Some(identity))?;
    let active_making_log_index = matched_logs[active_making_expected_index][0];
    let active_receiving_log_index = matched_logs[active_receiving_expected_index][0];
    let refund_log_index = refund_expected_index.map(|index| matched_logs[index][0]);

    let mut owner_trades = Vec::new();
    let owner_is_active = active.maker.eq_ignore_ascii_case(owner);
    let owner_passives = call
        .maker_orders
        .iter()
        .enumerate()
        .filter(|(_, order)| order.maker.eq_ignore_ascii_case(owner))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if owner_is_active && !owner_passives.is_empty() {
        return Err("owner_cannot_be_both_active_and_passive");
    }
    if owner_is_active {
        let amount_delta = if call.taker_fill_amount >= refund {
            call.taker_fill_amount - refund
        } else {
            refund - call.taker_fill_amount
        };
        let (collateral_direction, collateral_amount, token_direction, token_amount) =
            if active.side == V1DirectFillSide::Buy {
                (
                    if call.taker_fill_amount >= refund {
                        V1DirectFillAssetDirection::Out
                    } else {
                        V1DirectFillAssetDirection::In
                    },
                    amount_delta,
                    V1DirectFillAssetDirection::In,
                    active_net,
                )
            } else {
                (
                    V1DirectFillAssetDirection::In,
                    active_net,
                    if call.taker_fill_amount >= refund {
                        V1DirectFillAssetDirection::Out
                    } else {
                        V1DirectFillAssetDirection::In
                    },
                    amount_delta,
                )
            };
        let order_event_log = matched_logs[active_order_filled_expected_index][0];
        owner_trades.push(V1AttributedTradeFact {
            token_id: active.token_id,
            block_number: context.block_number,
            block_hash: context.block_hash.to_owned(),
            transaction_hash: transaction.transaction_hash.clone(),
            transaction_index: transaction.transaction_index,
            order_hash: active_hash.clone(),
            matched_order_hashes: hashes.clone(),
            kind: V1TradeAttributionKind::MatchedActiveOrder,
            side: active.side,
            fee_amount: active_fee,
            fee_asset: fee_asset(active),
            owner_collateral_direction: collateral_direction,
            owner_collateral_amount: collateral_amount,
            owner_token_direction: token_direction,
            owner_token_amount: token_amount,
            gross_making_amount: call.taker_fill_amount,
            refund_amount: refund,
            refund_transfer_log_index: refund_log_index,
            gross_received_amount: active_taking,
            received_fee_amount: active_fee,
            order_filled_log_index: order_event_log,
            making_transfer_log_index: active_making_log_index,
            receiving_transfer_log_index: active_receiving_log_index,
        });
    } else {
        for index in owner_passives {
            let order = &call.maker_orders[index];
            let making = call.maker_fill_amounts[index];
            let taking = takings[index];
            let fee = fees[index];
            let net = nets[index];
            let (collateral_direction, collateral_amount, token_direction, token_amount) =
                if order.side == V1DirectFillSide::Buy {
                    (
                        V1DirectFillAssetDirection::Out,
                        making,
                        V1DirectFillAssetDirection::In,
                        net,
                    )
                } else {
                    (
                        V1DirectFillAssetDirection::In,
                        net,
                        V1DirectFillAssetDirection::Out,
                        making,
                    )
                };
            let hash = &hashes[index];
            owner_trades.push(V1AttributedTradeFact {
                token_id: order.token_id,
                block_number: context.block_number,
                block_hash: context.block_hash.to_owned(),
                transaction_hash: transaction.transaction_hash.clone(),
                transaction_index: transaction.transaction_index,
                order_hash: hash.clone(),
                matched_order_hashes: vec![active_hash.clone()],
                kind: V1TradeAttributionKind::MatchedPassiveOrder,
                side: order.side,
                fee_amount: fee,
                fee_asset: fee_asset(order),
                owner_collateral_direction: collateral_direction,
                owner_collateral_amount: collateral_amount,
                owner_token_direction: token_direction,
                owner_token_amount: token_amount,
                gross_making_amount: making,
                refund_amount: U256::ZERO,
                refund_transfer_log_index: None,
                gross_received_amount: taking,
                received_fee_amount: fee,
                order_filled_log_index: matched_logs[passive_log_refs[index].2][0],
                making_transfer_log_index: matched_logs[passive_log_refs[index].0][0],
                receiving_transfer_log_index: matched_logs[passive_log_refs[index].1][0],
            });
        }
    }
    Ok(ClassifiedExchangeTransaction {
        owner_trades,
        order_hashes: std::iter::once(active_hash).chain(hashes).collect(),
        log_indices: transaction
            .logs
            .iter()
            .map(|log| log.block_log_index)
            .collect(),
    })
}

fn direct_orders_is_in_pair_scope(input: &[u8], owner: &str, position_ids: [U256; 2]) -> bool {
    decode_v1_direct_orders(input).is_some_and(|orders| {
        orders.iter().any(|order| {
            position_ids.contains(&order.token_id) || order.maker.eq_ignore_ascii_case(owner)
        })
    })
}

pub(super) fn decode_v1_direct_orders(input: &[u8]) -> Option<Vec<V1DirectOrderCall>> {
    let (selector, args) = input.split_at_checked(4)?;
    let selector: [u8; 4] = selector.try_into().ok()?;
    if selector == V1_FILL_ORDER_SELECTOR {
        return decode_v1_direct_order_call(input).map(|order| vec![order]);
    }
    if selector != V1_FILL_ORDERS_SELECTOR {
        return None;
    }
    let orders_offset = abi_usize(abi_u256_word(args, 0)?)?;
    let fill_amounts_offset = abi_usize(abi_u256_word(args, 32)?)?;
    if orders_offset != 64 {
        return None;
    }
    let count = abi_usize(abi_u256_word(args, orders_offset)?)?;
    if !(1..=V1_MATCH_ORDERS_MAX_MAKERS).contains(&count) {
        return None;
    }
    let heads_start = orders_offset.checked_add(32)?;
    let heads_bytes = count.checked_mul(32)?;
    let mut cursor = heads_start.checked_add(heads_bytes)?;
    let mut orders = Vec::with_capacity(count);
    for index in 0..count {
        let head_offset = heads_start.checked_add(index.checked_mul(32)?)?;
        if abi_usize(abi_u256_word(args, head_offset)?)? != cursor.checked_sub(heads_start)? {
            return None;
        }
        let (order, end) = decode_v1_order_tuple(args, cursor)?;
        orders.push(order);
        cursor = end;
    }
    if fill_amounts_offset != cursor
        || abi_usize(abi_u256_word(args, fill_amounts_offset)?)? != count
    {
        return None;
    }
    let amounts_start = fill_amounts_offset.checked_add(32)?;
    if args.len() != amounts_start.checked_add(count.checked_mul(32)?)? {
        return None;
    }
    for (index, order) in orders.iter_mut().enumerate() {
        order.fill_amount =
            abi_u256_word(args, amounts_start.checked_add(index.checked_mul(32)?)?)?;
    }
    Some(orders)
}

fn classify_direct_orders_binary(
    block_number: u64,
    block_hash: &str,
    transaction: &ChainReceiptIntervalTransaction,
    owner: &str,
    position_ids: [U256; 2],
) -> Result<ClassifiedExchangeTransaction, &'static str> {
    if !transaction
        .to
        .as_deref()
        .is_some_and(|to| to.eq_ignore_ascii_case(EXCHANGES[0]))
    {
        return Err("direct_fill_was_not_a_direct_exchange_call");
    }
    let caller = transaction
        .recovered_from
        .as_deref()
        .ok_or("direct_fill_caller_unavailable")?;
    if !transaction.replay_protected_sender || !transaction.value.is_zero() {
        return Err("direct_fill_caller_chain_or_value_mismatch");
    }
    let input = transaction
        .input
        .as_deref()
        .ok_or("direct_fill_calldata_missing")?;
    let mut orders =
        decode_v1_direct_orders(input).ok_or("unsupported_or_malformed_direct_fill_calldata")?;
    let mut expected = Vec::new();
    let mut owner_trades = Vec::new();
    let mut hashes = Vec::with_capacity(orders.len());
    let mut order_log_refs = Vec::with_capacity(orders.len());
    let mut seen_hashes = BTreeSet::new();
    for order in &mut orders {
        if !position_ids.contains(&order.token_id)
            || order.fill_amount.is_zero()
            || order.fill_amount > order.maker_amount
            || order.maker_amount.is_zero()
            || order.taker_amount.is_zero()
            || !v1_fee_rate_is_contract_bounded(order)
            || (order.taker != zero_address() && !order.taker.eq_ignore_ascii_case(caller))
            || !valid_v1_trade_party(&order.maker, caller)
        {
            return Err("direct_fill_order_identity_or_amount_invalid");
        }
        let order_hash = v1_order_hash(order).ok_or("direct_fill_order_hash_unavailable")?;
        if !seen_hashes.insert(order_hash.to_ascii_lowercase()) {
            return Err("repeated_direct_fill_order_hash_unsupported");
        }
        let taking = checked_mul_div(order.fill_amount, order.taker_amount, order.maker_amount)
            .ok_or("direct_fill_taking_checked_u256_overflow")?;
        let fee = calculate_v1_direct_fill_fee(order, taking)
            .ok_or("direct_fill_fee_checked_u256_overflow")?;
        if fee > taking {
            return Err("direct_fill_fee_exceeds_taking");
        }
        let net = taking - fee;
        let (maker_asset, taker_asset) = order_asset_ids(order);
        let receiving_expected_index = expected.len();
        push_transfer(
            &mut expected,
            taker_asset,
            caller.to_owned(),
            order.maker.clone(),
            net,
            true,
        );
        let making_expected_index = expected.len();
        push_transfer(
            &mut expected,
            maker_asset,
            order.maker.clone(),
            caller.to_owned(),
            order.fill_amount,
            true,
        );
        let event_expected_index = expected.len();
        expected.push(ExpectedLog::OrderFilled {
            order,
            taker: caller.to_owned(),
            making: order.fill_amount,
            taking,
            fee,
        });
        order_log_refs.push((
            making_expected_index,
            receiving_expected_index,
            event_expected_index,
        ));
        if order.maker.eq_ignore_ascii_case(owner) {
            let (collateral_direction, collateral_amount, token_direction, token_amount) =
                if order.side == V1DirectFillSide::Buy {
                    (
                        V1DirectFillAssetDirection::Out,
                        order.fill_amount,
                        V1DirectFillAssetDirection::In,
                        net,
                    )
                } else {
                    (
                        V1DirectFillAssetDirection::In,
                        net,
                        V1DirectFillAssetDirection::Out,
                        order.fill_amount,
                    )
                };
            owner_trades.push(V1AttributedTradeFact {
                token_id: order.token_id,
                block_number,
                block_hash: block_hash.to_owned(),
                transaction_hash: transaction.transaction_hash.clone(),
                transaction_index: transaction.transaction_index,
                order_hash: order_hash.clone(),
                matched_order_hashes: Vec::new(),
                kind: V1TradeAttributionKind::DirectFill,
                side: order.side,
                fee_amount: fee,
                fee_asset: fee_asset(order),
                owner_collateral_direction: collateral_direction,
                owner_collateral_amount: collateral_amount,
                owner_token_direction: token_direction,
                owner_token_amount: token_amount,
                gross_making_amount: order.fill_amount,
                refund_amount: U256::ZERO,
                refund_transfer_log_index: None,
                gross_received_amount: taking,
                received_fee_amount: fee,
                order_filled_log_index: 0,
                making_transfer_log_index: 0,
                receiving_transfer_log_index: 0,
            });
        } else if caller.eq_ignore_ascii_case(owner) {
            let (collateral_direction, collateral_amount, token_direction, token_amount) =
                if order.side == V1DirectFillSide::Buy {
                    (
                        V1DirectFillAssetDirection::In,
                        order.fill_amount,
                        V1DirectFillAssetDirection::Out,
                        net,
                    )
                } else {
                    (
                        V1DirectFillAssetDirection::Out,
                        net,
                        V1DirectFillAssetDirection::In,
                        order.fill_amount,
                    )
                };
            owner_trades.push(V1AttributedTradeFact {
                token_id: order.token_id,
                block_number,
                block_hash: block_hash.to_owned(),
                transaction_hash: transaction.transaction_hash.clone(),
                transaction_index: transaction.transaction_index,
                order_hash: order_hash.clone(),
                matched_order_hashes: Vec::new(),
                kind: V1TradeAttributionKind::DirectFill,
                side: order.side,
                fee_amount: fee,
                fee_asset: fee_asset(order),
                owner_collateral_direction: collateral_direction,
                owner_collateral_amount: collateral_amount,
                owner_token_direction: token_direction,
                owner_token_amount: token_amount,
                gross_making_amount: net,
                refund_amount: U256::ZERO,
                refund_transfer_log_index: None,
                gross_received_amount: order.fill_amount,
                received_fee_amount: U256::ZERO,
                order_filled_log_index: 0,
                making_transfer_log_index: 0,
                receiving_transfer_log_index: 0,
            });
        }
        hashes.push(order_hash);
    }
    let matched_logs = match_expected_logs(&transaction.logs, &expected, None)?;
    for trade in &mut owner_trades {
        let index = orders
            .iter()
            .position(|order| v1_order_hash(order).as_deref() == Some(trade.order_hash.as_str()))
            .ok_or("direct_fill_trade_order_missing")?;
        let refs = order_log_refs[index];
        if trade.kind == V1TradeAttributionKind::DirectFill {
            let order = orders
                .iter()
                .find(|order| v1_order_hash(order).as_deref() == Some(trade.order_hash.as_str()))
                .ok_or("direct_fill_trade_order_missing")?;
            if !order.maker.eq_ignore_ascii_case(owner) {
                trade.making_transfer_log_index = matched_logs[refs.1][0];
                trade.receiving_transfer_log_index = matched_logs[refs.0][0];
            } else {
                trade.making_transfer_log_index = matched_logs[refs.0][0];
                trade.receiving_transfer_log_index = matched_logs[refs.1][0];
            }
        }
        trade.order_filled_log_index = matched_logs[refs.2][0];
    }
    Ok(ClassifiedExchangeTransaction {
        owner_trades,
        order_hashes: hashes,
        log_indices: transaction
            .logs
            .iter()
            .map(|log| log.block_log_index)
            .collect(),
    })
}

fn one() -> U256 {
    U256::from(1_000_000_000_000_000_000_u64)
}

fn order_price(order: &V1DirectOrderCall) -> Option<U256> {
    match order.side {
        V1DirectFillSide::Buy => checked_mul_div(order.maker_amount, one(), order.taker_amount),
        V1DirectFillSide::Sell => checked_mul_div(order.taker_amount, one(), order.maker_amount),
    }
}

fn fee_asset(order: &V1DirectOrderCall) -> V1DirectFillFeeAsset {
    if order.side == V1DirectFillSide::Buy {
        V1DirectFillFeeAsset::OutcomeToken
    } else {
        V1DirectFillFeeAsset::Collateral
    }
}

fn balance_for_asset(
    positions: [U256; 2],
    cash: U256,
    position_ids: [U256; 2],
    asset: U256,
) -> Option<U256> {
    if asset.is_zero() {
        Some(cash)
    } else {
        position_ids
            .iter()
            .position(|id| *id == asset)
            .map(|index| positions[index])
    }
}

fn move_balance_for_asset(
    positions: &mut [U256; 2],
    cash: &mut U256,
    position_ids: [U256; 2],
    asset: U256,
    inflow: bool,
    amount: U256,
) -> Option<()> {
    let target = if asset.is_zero() {
        cash
    } else {
        &mut positions[position_ids.iter().position(|id| *id == asset)?]
    };
    *target = if inflow {
        target.checked_add(amount)?
    } else {
        target.checked_sub(amount)?
    };
    Some(())
}

fn push_transfer(
    expected: &mut Vec<ExpectedLog<'_>>,
    asset: U256,
    from: String,
    to: String,
    amount: U256,
    transfer_from: bool,
) {
    let approval = (transfer_from && asset.is_zero()).then(|| {
        (
            from.clone(),
            if from.eq_ignore_ascii_case(EXCHANGES[0]) {
                CTF_CONDITIONAL_TOKENS_ADDRESS.to_owned()
            } else {
                EXCHANGES[0].to_owned()
            },
            amount,
        )
    });
    expected.push(ExpectedLog::Transfer {
        asset,
        approval,
        from,
        to,
        amount,
    });
}

fn match_expected_logs(
    logs: &[ChainReceiptLog],
    expected: &[ExpectedLog<'_>],
    identity: Option<&ctf_position_identity::DerivedRootBinaryIdentity>,
) -> Result<Vec<Vec<u64>>, &'static str> {
    let mut cursor = 0usize;
    let mut matched = Vec::with_capacity(expected.len());
    for item in expected {
        let start = cursor;
        match item {
            ExpectedLog::Transfer {
                asset,
                from,
                to,
                amount,
                approval,
            } => {
                let log = logs.get(cursor).ok_or("source_transfer_log_missing")?;
                if !transfer_matches(log, *asset, from, to, *amount) {
                    return Err("source_transfer_log_mismatch");
                }
                cursor += 1;
                if let Some((approval_owner, spender, spent)) = approval {
                    let approval_log = logs.get(cursor).ok_or("transfer_from_approval_missing")?;
                    if !ctf_operations::usdc_transfer_from_approval_matches(
                        approval_log,
                        approval_owner,
                        spender,
                        *spent,
                    ) {
                        return Err("transfer_from_approval_mismatch_or_overflow");
                    }
                    cursor += 1;
                }
            }
            ExpectedLog::CtfOperation { amount, split } => {
                let width = if *split { 4 } else { 3 };
                let selection = logs
                    .get(cursor..cursor + width)
                    .ok_or("exchange_ctf_operation_logs_missing")?;
                let identity = identity.ok_or("exchange_ctf_operation_identity_missing")?;
                if ctf_operations::exchange_operation_log_indices(
                    selection, identity, *amount, *split,
                )
                .is_none()
                {
                    return Err("exchange_ctf_operation_logs_mismatch");
                }
                cursor += width;
            }
            ExpectedLog::FeeCharged {
                receiver,
                token_id,
                amount,
            } => {
                let log = logs.get(cursor).ok_or("fee_charged_event_missing")?;
                if !log.address.eq_ignore_ascii_case(EXCHANGES[0])
                    || !decode_v1_fee_charged(log).is_some_and(|fact| {
                        fact.receiver.eq_ignore_ascii_case(receiver)
                            && fact.token_id == *token_id
                            && fact.amount == *amount
                    })
                {
                    return Err("fee_charged_event_mismatch");
                }
                cursor += 1;
            }
            ExpectedLog::OrderFilled {
                order,
                taker,
                making,
                taking,
                fee,
            } => {
                let log = logs.get(cursor).ok_or("order_filled_event_missing")?;
                let assets = order_asset_ids(order);
                let actual = decode_v1_order_filled(log).ok_or("order_filled_event_malformed")?;
                if !log.address.eq_ignore_ascii_case(EXCHANGES[0])
                    || !order_filled_matches(
                        &actual,
                        &V1ExpectedOrderFilled {
                            order_hash: &v1_order_hash(order).ok_or("order_hash_unavailable")?,
                            maker: &order.maker,
                            taker,
                            assets,
                            making: *making,
                            taking: *taking,
                            fee: *fee,
                        },
                    )
                {
                    return Err("order_filled_event_mismatch");
                }
                cursor += 1;
            }
            ExpectedLog::OrdersMatched {
                order_hash,
                order,
                making,
                taking,
            } => {
                let log = logs.get(cursor).ok_or("orders_matched_event_missing")?;
                let (maker_asset, taker_asset) = order_asset_ids(order);
                let actual =
                    decode_v1_orders_matched(log).ok_or("orders_matched_event_malformed")?;
                if !log.address.eq_ignore_ascii_case(EXCHANGES[0])
                    || !actual.order_hash.eq_ignore_ascii_case(order_hash)
                    || !actual.taker.eq_ignore_ascii_case(&order.maker)
                    || actual.maker_asset_id != maker_asset
                    || actual.taker_asset_id != taker_asset
                    || actual.maker_amount != *making
                    || actual.taker_amount != *taking
                {
                    return Err("orders_matched_event_mismatch");
                }
                cursor += 1;
            }
        }
        matched.push(
            logs[start..cursor]
                .iter()
                .map(|log| log.block_log_index)
                .collect(),
        );
    }
    if cursor != logs.len() {
        return Err("unexpected_or_reordered_exchange_receipt_log");
    }
    Ok(matched)
}

fn transfer_matches(
    log: &ChainReceiptLog,
    asset: U256,
    from: &str,
    to: &str,
    amount: U256,
) -> bool {
    if asset.is_zero() {
        log.address.eq_ignore_ascii_case(USDC_E_PROXY_ADDRESS)
            && matches!(decode_erc20_transfer(log), Ok(ObservedAssetMovement::Erc20Transfer { from: actual_from, to: actual_to, amount: actual_amount }) if actual_from.eq_ignore_ascii_case(from) && actual_to.eq_ignore_ascii_case(to) && actual_amount == amount)
    } else {
        log.address
            .eq_ignore_ascii_case(CTF_CONDITIONAL_TOKENS_ADDRESS)
            && matches!(decode_erc1155_single(log), Ok(ObservedAssetMovement::Erc1155TransferSingle { operator, from: actual_from, to: actual_to, id, amount: actual_amount }) if operator.eq_ignore_ascii_case(EXCHANGES[0]) && actual_from.eq_ignore_ascii_case(from) && actual_to.eq_ignore_ascii_case(to) && id == asset && actual_amount == amount)
    }
}

fn match_orders_is_in_pair_scope(input: &[u8], owner: &str, position_ids: [U256; 2]) -> bool {
    decode_v1_match_orders_call(input).is_some_and(|call| {
        std::iter::once(&call.taker_order)
            .chain(call.maker_orders.iter())
            .any(|order| {
                position_ids.contains(&order.token_id) || order.maker.eq_ignore_ascii_case(owner)
            })
    })
}

fn apply_exchange_movement_observations(
    transaction: &ChainReceiptIntervalTransaction,
    positions: &mut [U256; 2],
    cash: &mut U256,
    position_ids: [U256; 2],
) -> bool {
    for movement in &transaction.movement_observations {
        match &movement.status {
            MovementObservationStatus::Unsupported(_)
                if movement
                    .emitter
                    .eq_ignore_ascii_case(CTF_CONDITIONAL_TOKENS_ADDRESS)
                    || movement.emitter.eq_ignore_ascii_case(USDC_E_PROXY_ADDRESS) =>
            {
                return false;
            }
            MovementObservationStatus::Decoded(ObservedAssetMovement::Erc20Transfer {
                from,
                to,
                amount,
            }) if movement.emitter.eq_ignore_ascii_case(USDC_E_PROXY_ADDRESS) => {
                if !apply_exchange_delta(cash, from, to, *amount) {
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
                .eq_ignore_ascii_case(CTF_CONDITIONAL_TOKENS_ADDRESS) =>
            {
                if let Some(index) = position_ids.iter().position(|candidate| candidate == id)
                    && !apply_exchange_delta(&mut positions[index], from, to, *amount)
                {
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
                    if let Some(index) = position_ids.iter().position(|candidate| candidate == id)
                        && !apply_exchange_delta(&mut positions[index], from, to, *amount)
                    {
                        return false;
                    }
                }
            }
            _ => {}
        }
    }
    true
}

fn apply_exchange_delta(balance: &mut U256, from: &str, to: &str, amount: U256) -> bool {
    let exchange = EXCHANGES[0];
    let from_exchange = from.eq_ignore_ascii_case(exchange);
    let to_exchange = to.eq_ignore_ascii_case(exchange);
    if from_exchange == to_exchange {
        return true;
    }
    let next = if from_exchange {
        balance.checked_sub(amount)
    } else {
        balance.checked_add(amount)
    };
    let Some(next) = next else {
        return false;
    };
    *balance = next;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_scope_requires_a_proven_binary_condition_at_each_boundary() {
        assert!(binary_condition_ready(
            CtfConditionStateStatus::PreparedBinaryUnresolved
        ));
        assert!(binary_condition_ready(
            CtfConditionStateStatus::ResolvedBinary
        ));
        assert!(!binary_condition_ready(CtfConditionStateStatus::Unprepared));
        assert!(!binary_condition_ready(
            CtfConditionStateStatus::UnsupportedNonBinary
        ));
        assert!(condition_scope_supported(
            CtfConditionStateStatus::Unprepared
        ));
        assert!(!condition_scope_supported(
            CtfConditionStateStatus::UnsupportedNonBinary
        ));
    }
}
