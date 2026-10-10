//! One-root, source-ordered trade attribution across two native conditions.

use super::fifth_binary_trades::{
    FifthTradeTransactionFact, TransactionClassification, classify_transaction,
};
use super::fifth_code_context::EXCHANGE_PROXY;
use super::fifth_direct_module_operations::{has_minter_role, module_balance_role_proofs};
use super::fifth_exchange_controls::FifthExchangeControlsObservation;
use super::fifth_match_orders_call::{
    FIFTH_MATCH_ORDERS_SELECTOR, decode_fifth_match_orders_calldata,
};
use super::fifth_native_binary::{
    BoundedFifthNativeBinaryError, is_canonical_native_binary_condition,
};
use super::fifth_native_binary_trades::verify_native_trade_controls;
use super::fifth_native_module_operations::{
    BoundedFifthNativeBinaryModuleOperationsError, FifthNativeBinaryModuleOperationBoundary,
};
use super::{
    ChainLogAuditError, ChainLogVerifier, ChainReceiptIntervalEvidence, MAX_BLOCKS,
    MovementObservationStatus, ObservedAssetMovement, TransactionRequestBudget, parse_fixed_b256,
    validate_hex,
};
use alloy_primitives::{Address, B256, U256};
use std::{str::FromStr, time::Duration};
use thiserror::Error;
use tokio::time::Instant;

const POLICY_VERSION: &str =
    "fifth-native-binary-two-condition-trade-source-and-shared-pusd-replay/1";

pub const FIFTH_NATIVE_TWO_CONDITION_TRADE_POLICY_VERSION: &str = POLICY_VERSION;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedFifthNativeBinaryTwoConditionTradeError {
    #[error("two-condition native trade RPC request budget exhausted")]
    RequestBudgetExceeded,
    #[error("two-condition native trade exceeded its total deadline")]
    Timeout,
    #[error(transparent)]
    Verification(#[from] ChainLogAuditError),
}

/// One transaction's sealed native trade fact, tagged with its selected pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthNativeTwoConditionTradeTransaction {
    condition_index: usize,
    transaction: FifthTradeTransactionFact,
}

impl FifthNativeTwoConditionTradeTransaction {
    #[must_use]
    pub const fn condition_index(&self) -> usize {
        self.condition_index
    }

    #[must_use]
    pub const fn transaction(&self) -> &FifthTradeTransactionFact {
        &self.transaction
    }
}

pub(super) fn tag_trade_fact(
    condition_index: usize,
    transaction: FifthTradeTransactionFact,
) -> FifthNativeTwoConditionTradeTransaction {
    FifthNativeTwoConditionTradeTransaction {
        condition_index,
        transaction,
    }
}

/// Complete rooted evidence for one shared owner/cash interval across two conditions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthNativeBinaryTwoConditionTradeObservation {
    evidence: ChainReceiptIntervalEvidence,
    opening: [FifthNativeBinaryModuleOperationBoundary; 2],
    block_observations: Vec<[FifthNativeBinaryModuleOperationBoundary; 2]>,
    transactions: Vec<FifthNativeTwoConditionTradeTransaction>,
    controls: Vec<FifthExchangeControlsObservation>,
}

impl FifthNativeBinaryTwoConditionTradeObservation {
    #[must_use]
    pub const fn evidence(&self) -> &ChainReceiptIntervalEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn opening(&self) -> &[FifthNativeBinaryModuleOperationBoundary; 2] {
        &self.opening
    }

    #[must_use]
    pub fn block_observations(&self) -> &[[FifthNativeBinaryModuleOperationBoundary; 2]] {
        &self.block_observations
    }

    #[must_use]
    pub fn transactions(&self) -> &[FifthNativeTwoConditionTradeTransaction] {
        &self.transactions
    }

    #[must_use]
    pub fn controls(&self) -> &[FifthExchangeControlsObservation] {
        &self.controls
    }

    #[must_use]
    pub const fn source_policy_version(&self) -> &'static str {
        POLICY_VERSION
    }
}

impl ChainLogVerifier {
    #[allow(clippy::too_many_arguments)]
    pub async fn verify_fifth_native_binary_two_condition_trades_bounded(
        &self,
        owner: &str,
        conditions: [&str; 2],
        from_block: u64,
        through_block: u64,
        expected_parent_hash: &str,
        expected_end_hash: &str,
        max_requests: usize,
        total_timeout: Duration,
    ) -> Result<
        FifthNativeBinaryTwoConditionTradeObservation,
        BoundedFifthNativeBinaryTwoConditionTradeError,
    > {
        let owner = validate_hex(owner, 20).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let owner_bytes = hex::decode(&owner[2..]).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let condition_ids = [
            parse_fixed_b256(conditions[0]).map_err(|_| ChainLogAuditError::InvalidInput)?,
            parse_fixed_b256(conditions[1]).map_err(|_| ChainLogAuditError::InvalidInput)?,
        ];
        let parent_hash =
            validate_hex(expected_parent_hash, 32).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let end_hash =
            validate_hex(expected_end_hash, 32).map_err(|_| ChainLogAuditError::InvalidInput)?;
        if owner_bytes.iter().all(|byte| *byte == 0)
            || condition_ids[0] == condition_ids[1]
            || from_block == 0
            || from_block > through_block
            || through_block - from_block >= MAX_BLOCKS
            || max_requests == 0
            || total_timeout.is_zero()
            || condition_ids
                .iter()
                .any(|condition| !is_canonical_native_binary_condition(*condition))
        {
            return Err(ChainLogAuditError::InvalidInput.into());
        }

        let owner_address = Address::from_slice(&owner_bytes);
        let ids = condition_ids.map(native_position_ids);
        let deadline = Instant::now()
            .checked_add(total_timeout)
            .ok_or(ChainLogAuditError::InvalidInput)?;
        let budget = TransactionRequestBudget::new(max_requests);
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let scoped = self.with_request_budget(budget.inner());
        let verification = scoped.verify_two_condition_trade_inner(
            owner_address,
            ids,
            from_block,
            through_block,
            &parent_hash,
            &end_hash,
            deadline,
        );
        tokio::pin!(verification);
        let deadline_wait = tokio::time::sleep_until(deadline);
        tokio::pin!(deadline_wait);
        tokio::select! {
            biased;
            _ = exhaustion.wait_for(|is_exhausted| *is_exhausted) => {
                Err(BoundedFifthNativeBinaryTwoConditionTradeError::RequestBudgetExceeded)
            }
            () = &mut deadline_wait => {
                if budget.is_exhausted() {
                    Err(BoundedFifthNativeBinaryTwoConditionTradeError::RequestBudgetExceeded)
                } else {
                    Err(BoundedFifthNativeBinaryTwoConditionTradeError::Timeout)
                }
            }
            result = &mut verification => {
                if budget.is_exhausted() {
                    Err(BoundedFifthNativeBinaryTwoConditionTradeError::RequestBudgetExceeded)
                } else if Instant::now() >= deadline {
                    Err(BoundedFifthNativeBinaryTwoConditionTradeError::Timeout)
                } else {
                    result
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn verify_two_condition_trade_inner(
        &self,
        owner_address: Address,
        ids: [[B256; 2]; 2],
        from_block: u64,
        through_block: u64,
        parent_hash: &str,
        end_hash: &str,
        deadline: Instant,
    ) -> Result<
        FifthNativeBinaryTwoConditionTradeObservation,
        BoundedFifthNativeBinaryTwoConditionTradeError,
    > {
        let collected = collect_two_condition_evidence(
            self,
            owner_address,
            ids,
            TwoConditionAnchor {
                from_block,
                through_block,
                parent_hash,
                end_hash,
                deadline,
            },
            |_| Ok(()),
            |_, _, _, _| Ok(()),
        )
        .await?;
        let TwoConditionEvidence {
            evidence,
            opening,
            block_observations: points,
        } = collected;
        let module = opening[0].native_context().module_proxy();
        ensure_deadline(deadline)?;
        validate_boundaries(&opening, &points, &evidence, ids)?;
        let ScannedTwoConditionTransactions {
            facts,
            actors,
            candidates,
        } = scan_transactions(&evidence, &points, owner_address, ids, module, deadline)?;
        let boundaries = std::iter::once(&opening[0])
            .chain(points.iter().map(|pair| &pair[0]))
            .collect::<Vec<_>>();
        let control_assessment = verify_native_trade_controls(
            self,
            &evidence,
            &boundaries,
            &actors,
            &candidates,
            deadline,
        )
        .await
        .map_err(map_trade_error)?;
        if control_assessment.refusal.is_some() {
            return Err(ChainLogAuditError::Unverified.into());
        }
        let controls = control_assessment.controls;
        replay_shared_balances(&opening, &points, &evidence, &facts)?;
        ensure_deadline(deadline)?;
        Ok(FifthNativeBinaryTwoConditionTradeObservation {
            evidence,
            opening,
            block_observations: points,
            transactions: facts,
            controls,
        })
    }
}

pub(super) struct TwoConditionEvidence {
    pub(super) evidence: ChainReceiptIntervalEvidence,
    pub(super) opening: [FifthNativeBinaryModuleOperationBoundary; 2],
    pub(super) block_observations: Vec<[FifthNativeBinaryModuleOperationBoundary; 2]>,
}

pub(super) struct TwoConditionAnchor<'a> {
    pub(super) from_block: u64,
    pub(super) through_block: u64,
    pub(super) parent_hash: &'a str,
    pub(super) end_hash: &'a str,
    pub(super) deadline: Instant,
}

pub(super) async fn collect_two_condition_evidence<OpeningCheck, BlockCheck>(
    verifier: &ChainLogVerifier,
    owner: Address,
    ids: [[B256; 2]; 2],
    anchor: TwoConditionAnchor<'_>,
    check_opening: OpeningCheck,
    mut check_block: BlockCheck,
) -> Result<TwoConditionEvidence, BoundedFifthNativeBinaryTwoConditionTradeError>
where
    OpeningCheck:
        FnOnce(&[FifthNativeBinaryModuleOperationBoundary; 2]) -> Result<(), ChainLogAuditError>,
    BlockCheck: FnMut(
        &[FifthNativeBinaryModuleOperationBoundary; 2],
        &[FifthNativeBinaryModuleOperationBoundary; 2],
        &[FifthNativeBinaryModuleOperationBoundary; 2],
        &super::ChainReceiptIntervalBlock,
    ) -> Result<(), ChainLogAuditError>,
{
    let TwoConditionAnchor {
        from_block,
        through_block,
        parent_hash,
        end_hash,
        deadline,
    } = anchor;
    ensure_deadline(deadline)?;
    let opening = [
        pair_boundary(
            verifier,
            owner,
            ids[0][0],
            ids[0],
            from_block - 1,
            parent_hash,
            deadline,
        )
        .await?,
        pair_boundary(
            verifier,
            owner,
            ids[1][0],
            ids[1],
            from_block - 1,
            parent_hash,
            deadline,
        )
        .await?,
    ];
    if !same_shared_boundary(&opening[0], &opening[1]) {
        return Err(ChainLogAuditError::Unverified.into());
    }
    check_opening(&opening)?;

    let module = opening[0].native_context().module_proxy();
    let scoped = verifier.with_fifth_module_call_targets(module);
    let evidence = scoped
        .verify_receipt_interval_inner(from_block, through_block, parent_hash, end_hash)
        .await?;
    let mut block_observations = Vec::with_capacity(evidence.blocks().len());
    for block in evidence.blocks() {
        ensure_deadline(deadline)?;
        let pair = [
            pair_boundary(
                &scoped,
                owner,
                ids[0][0],
                ids[0],
                block.block_number(),
                block.block_hash(),
                deadline,
            )
            .await?,
            pair_boundary(
                &scoped,
                owner,
                ids[1][0],
                ids[1],
                block.block_number(),
                block.block_hash(),
                deadline,
            )
            .await?,
        ];
        if pair.iter().any(|boundary| {
            boundary.native_context().selected_balances().state_root() != block.state_root()
        }) || !same_shared_boundary(&pair[0], &pair[1])
        {
            return Err(ChainLogAuditError::Unverified.into());
        }
        let previous = block_observations.last().unwrap_or(&opening);
        check_block(&opening, previous, &pair, block)?;
        block_observations.push(pair);
    }
    Ok(TwoConditionEvidence {
        evidence,
        opening,
        block_observations,
    })
}

pub(super) fn native_position_ids(condition: B256) -> [B256; 2] {
    let mut second = condition.0;
    second[31] = 1;
    [condition, B256::from(second)]
}

pub(super) async fn pair_boundary(
    verifier: &ChainLogVerifier,
    owner_address: Address,
    condition: B256,
    ids: [B256; 2],
    block: u64,
    hash: &str,
    deadline: Instant,
) -> Result<FifthNativeBinaryModuleOperationBoundary, BoundedFifthNativeBinaryTwoConditionTradeError>
{
    ensure_deadline(deadline)?;
    let native = verifier
        .verify_fifth_native_binary_inner(
            format!("{owner_address:#x}"),
            owner_address,
            condition,
            ids,
            block,
            hash,
            deadline,
        )
        .await
        .map_err(map_native_error)?;
    if native.selected_balances().block_hash() != hash {
        return Err(ChainLogAuditError::Unverified.into());
    }
    let module = native.module_proxy();
    let (positions, cash, role) = module_balance_role_proofs(
        verifier,
        native.selected_balances(),
        module,
        ids,
        block,
        deadline,
    )
    .await
    .map_err(super::fifth_native_module_operations::map_module_error)
    .map_err(map_module_error)?;
    Ok(
        FifthNativeBinaryModuleOperationBoundary::from_verified_parts(
            native, positions, cash, role,
        ),
    )
}

pub(super) fn same_shared_boundary(
    left: &FifthNativeBinaryModuleOperationBoundary,
    right: &FifthNativeBinaryModuleOperationBoundary,
) -> bool {
    let a = left.native_context();
    let b = right.native_context();
    let ab = a.selected_balances();
    let bb = b.selected_balances();
    let a_code = ab.code_context();
    let b_code = bb.code_context();
    ab.chain_id() == bb.chain_id()
        && ab.block_number() == bb.block_number()
        && ab.block_hash() == bb.block_hash()
        && ab.state_root() == bb.state_root()
        && ab.owner() == bb.owner()
        && ab.pusd_balance() == bb.pusd_balance()
        && a_code.block_number() == b_code.block_number()
        && a_code.block_hash() == b_code.block_hash()
        && a_code.state_root() == b_code.state_root()
        && a_code.exchange_implementation_version() == b_code.exchange_implementation_version()
        && ab.position_manager_proxy() == bb.position_manager_proxy()
        && ab.position_manager_proxy_code_hash() == bb.position_manager_proxy_code_hash()
        && ab.position_manager_implementation() == bb.position_manager_implementation()
        && ab.position_manager_implementation_code_hash()
            == bb.position_manager_implementation_code_hash()
        && ab.pusd_proxy() == bb.pusd_proxy()
        && ab.pusd_proxy_code_hash() == bb.pusd_proxy_code_hash()
        && ab.pusd_implementation() == bb.pusd_implementation()
        && ab.pusd_implementation_code_hash() == bb.pusd_implementation_code_hash()
        && a.module_proxy() == b.module_proxy()
        && a.module_implementation() == b.module_implementation()
        && a.module_implementation_code_hash() == b.module_implementation_code_hash()
        && left.module_pusd_balance() == right.module_pusd_balance()
        && left.module_role_bitmap() == right.module_role_bitmap()
}

fn validate_boundaries(
    opening: &[FifthNativeBinaryModuleOperationBoundary; 2],
    points: &[[FifthNativeBinaryModuleOperationBoundary; 2]],
    evidence: &ChainReceiptIntervalEvidence,
    ids: [[B256; 2]; 2],
) -> Result<(), ChainLogAuditError> {
    if points.len() != evidence.blocks().len() {
        return Err(ChainLogAuditError::Unverified);
    }
    let mut previous = opening;
    for (index, pair) in std::iter::once(opening).chain(points.iter()).enumerate() {
        for condition_index in 0..2 {
            let boundary = &pair[condition_index];
            let native = boundary.native_context();
            if native.position_ids() != ids[condition_index]
                || !native.legacy_mapping_value().is_zero()
                || boundary.module_position_balances() != [U256::ZERO; 2]
                || !boundary.module_pusd_balance().is_zero()
                || !has_minter_role(boundary.module_role_bitmap())
            {
                return Err(ChainLogAuditError::Unverified);
            }
            if index > 0
                && !super::fifth_direct_module_operations::ModuleOperationPoint::source_identity_continues(
                    &previous[condition_index], boundary,
                )
            {
                return Err(ChainLogAuditError::Unverified);
            }
        }
        if index > 0 && !same_shared_boundary(&pair[0], &pair[1]) {
            return Err(ChainLogAuditError::Unverified);
        }
        previous = pair;
    }
    Ok(())
}

struct ScannedTwoConditionTransactions {
    facts: Vec<FifthNativeTwoConditionTradeTransaction>,
    actors: Vec<(Address, Address)>,
    candidates: Vec<(usize, usize, Address, Vec<Address>)>,
}

pub(super) struct RoutedTwoConditionExchangeTransaction {
    pub(super) condition_index: usize,
    pub(super) fact: Option<FifthTradeTransactionFact>,
    pub(super) submitter: Address,
    pub(super) makers: Vec<Address>,
}

pub(super) fn classify_two_condition_exchange_transaction(
    transaction: &super::ChainReceiptIntervalTransaction,
    block_number: u64,
    block_hash: &str,
    owner: Address,
    ids: [[B256; 2]; 2],
    module: Address,
    versions: [super::fifth_code_context::FifthExchangeImplementationVersion; 2],
) -> Result<RoutedTwoConditionExchangeTransaction, ChainLogAuditError> {
    let input = transaction
        .input
        .as_deref()
        .filter(|input| input.starts_with(&FIFTH_MATCH_ORDERS_SELECTOR))
        .ok_or(ChainLogAuditError::Unverified)?;
    let call = decode_fifth_match_orders_calldata(input).ok_or(ChainLogAuditError::Unverified)?;
    let token_ids = std::iter::once(call.taker_order.token_id)
        .chain(call.maker_orders.iter().map(|order| order.token_id))
        .collect::<Vec<_>>();
    let matching = (0..2)
        .filter(|index| {
            token_ids.iter().all(|token| {
                ids[*index]
                    .iter()
                    .any(|id| U256::from_be_bytes(id.0) == *token)
            })
        })
        .collect::<Vec<_>>();
    let [condition_index] = matching.as_slice() else {
        return Err(ChainLogAuditError::Unverified);
    };
    let condition_index = *condition_index;
    let fact = match classify_transaction(
        transaction,
        block_number,
        block_hash,
        owner,
        ids[condition_index],
        module,
        versions[condition_index],
    ) {
        TransactionClassification::Fact(fact) => Some(*fact),
        TransactionClassification::Unavailable(_) => {
            return Err(ChainLogAuditError::Unverified);
        }
        TransactionClassification::Quiet => None,
    };
    let submitter = Address::from_str(
        transaction
            .recovered_from
            .as_deref()
            .ok_or(ChainLogAuditError::Unverified)?,
    )
    .map_err(|_| ChainLogAuditError::Unverified)?;
    let mut makers = vec![call.taker_order.maker];
    makers.extend(call.maker_orders.iter().map(|order| order.maker));
    makers.sort_unstable();
    makers.dedup();
    Ok(RoutedTwoConditionExchangeTransaction {
        condition_index,
        fact,
        submitter,
        makers,
    })
}

fn scan_transactions(
    evidence: &ChainReceiptIntervalEvidence,
    points: &[[FifthNativeBinaryModuleOperationBoundary; 2]],
    owner: Address,
    ids: [[B256; 2]; 2],
    module: Address,
    deadline: Instant,
) -> Result<ScannedTwoConditionTransactions, BoundedFifthNativeBinaryTwoConditionTradeError> {
    let mut facts = Vec::new();
    let mut actors = Vec::new();
    let mut candidates = Vec::new();
    for (block_index, block) in evidence.blocks().iter().enumerate() {
        ensure_deadline(deadline)?;
        for (transaction_index, transaction) in block.transactions().iter().enumerate() {
            ensure_deadline(deadline)?;
            if transaction.status() == 0 {
                if !transaction.logs().is_empty() {
                    return Err(ChainLogAuditError::Unverified.into());
                }
                continue;
            }
            if transaction.status() != 1 {
                return Err(ChainLogAuditError::Unverified.into());
            }
            let exchange_call = transaction
                .to
                .as_deref()
                .is_some_and(|to| to.eq_ignore_ascii_case(EXCHANGE_PROXY));
            let input_has_match = transaction
                .input
                .as_deref()
                .is_some_and(|input| input.starts_with(&FIFTH_MATCH_ORDERS_SELECTOR));
            if exchange_call && !input_has_match {
                return Err(ChainLogAuditError::Unverified.into());
            }
            if !exchange_call
                && transaction.to.as_deref().is_some_and(|to| {
                    to.eq_ignore_ascii_case(&format!("{module:#x}"))
                        || to
                            .eq_ignore_ascii_case(super::fifth_code_context::POSITION_MANAGER_PROXY)
                        || to.eq_ignore_ascii_case("0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb")
                })
            {
                return Err(ChainLogAuditError::Unverified.into());
            }
            let class = if exchange_call {
                let versions = [0, 1].map(|index| {
                    points[block_index][index]
                        .native_context()
                        .selected_balances()
                        .code_context()
                        .exchange_implementation_version()
                });
                let routed = classify_two_condition_exchange_transaction(
                    transaction,
                    block.block_number(),
                    block.block_hash(),
                    owner,
                    ids,
                    module,
                    versions,
                )?;
                for maker in &routed.makers {
                    let submitter = routed.submitter;
                    if !actors.contains(&(submitter, *maker)) {
                        actors.push((submitter, *maker));
                    }
                }
                candidates.push((
                    block_index,
                    transaction_index,
                    routed.submitter,
                    routed.makers,
                ));
                routed.fact.map(|fact| (routed.condition_index, fact))
            } else {
                if has_owner_position_or_cash_movement(transaction, owner) {
                    return Err(ChainLogAuditError::Unverified.into());
                }
                for (condition_index, condition_ids) in ids.iter().enumerate() {
                    let version = points[block_index][condition_index]
                        .native_context()
                        .selected_balances()
                        .code_context()
                        .exchange_implementation_version();
                    match classify_transaction(
                        transaction,
                        block.block_number(),
                        block.block_hash(),
                        owner,
                        *condition_ids,
                        module,
                        version,
                    ) {
                        TransactionClassification::Fact(_)
                        | TransactionClassification::Unavailable(_) => {
                            return Err(ChainLogAuditError::Unverified.into());
                        }
                        TransactionClassification::Quiet => {}
                    }
                }
                None
            };
            if super::fifth_native_binary_trades::transaction_has_control_or_upgrade_event(
                transaction,
                module,
            ) {
                return Err(ChainLogAuditError::Unverified.into());
            }
            if let Some((condition_index, transaction)) = class {
                facts.push(tag_trade_fact(condition_index, transaction));
            }
        }
    }
    Ok(ScannedTwoConditionTransactions {
        facts,
        actors,
        candidates,
    })
}

pub(super) fn has_owner_position_or_cash_movement(
    transaction: &super::ChainReceiptIntervalTransaction,
    owner: Address,
) -> bool {
    transaction
        .movement_observations()
        .iter()
        .any(|observation| {
            let pm = observation
                .emitter()
                .eq_ignore_ascii_case(super::fifth_code_context::POSITION_MANAGER_PROXY);
            let pusd = observation
                .emitter()
                .eq_ignore_ascii_case("0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb");
            if !pm && !pusd {
                return false;
            }
            match observation.status() {
                MovementObservationStatus::Unsupported(_) => true,
                MovementObservationStatus::Decoded(ObservedAssetMovement::Erc20Transfer {
                    from,
                    to,
                    ..
                })
                | MovementObservationStatus::Decoded(
                    ObservedAssetMovement::Erc1155TransferSingle { from, to, .. },
                )
                | MovementObservationStatus::Decoded(
                    ObservedAssetMovement::Erc1155TransferBatch { from, to, .. },
                ) => {
                    let owner = format!("{owner:#x}");
                    from.eq_ignore_ascii_case(&owner) || to.eq_ignore_ascii_case(&owner)
                }
            }
        })
}

fn replay_shared_balances(
    opening: &[FifthNativeBinaryModuleOperationBoundary; 2],
    points: &[[FifthNativeBinaryModuleOperationBoundary; 2]],
    evidence: &ChainReceiptIntervalEvidence,
    facts: &[FifthNativeTwoConditionTradeTransaction],
) -> Result<(), ChainLogAuditError> {
    let mut balances = [
        opening[0]
            .native_context()
            .selected_balances()
            .position_balance_a(),
        opening[0]
            .native_context()
            .selected_balances()
            .position_balance_b(),
        opening[1]
            .native_context()
            .selected_balances()
            .position_balance_a(),
        opening[1]
            .native_context()
            .selected_balances()
            .position_balance_b(),
    ];
    let mut cash = opening[0]
        .native_context()
        .selected_balances()
        .pusd_balance();
    for (index, block) in evidence.blocks().iter().enumerate() {
        for tagged in facts
            .iter()
            .filter(|fact| fact.transaction.block_number() == block.block_number())
        {
            let fact = &tagged.transaction;
            let offset = tagged.condition_index * 2;
            for side in 0..2 {
                balances[offset + side] = balances[offset + side]
                    .checked_add(fact.owner_position_inflows()[side])
                    .and_then(|value| value.checked_sub(fact.owner_position_outflows()[side]))
                    .ok_or(ChainLogAuditError::Unverified)?;
            }
            cash = cash
                .checked_add(fact.owner_pusd_inflow())
                .and_then(|value| value.checked_sub(fact.owner_pusd_outflow()))
                .ok_or(ChainLogAuditError::Unverified)?;
        }
        let expected = [
            points[index][0]
                .native_context()
                .selected_balances()
                .position_balance_a(),
            points[index][0]
                .native_context()
                .selected_balances()
                .position_balance_b(),
            points[index][1]
                .native_context()
                .selected_balances()
                .position_balance_a(),
            points[index][1]
                .native_context()
                .selected_balances()
                .position_balance_b(),
        ];
        if balances != expected
            || cash
                != points[index][0]
                    .native_context()
                    .selected_balances()
                    .pusd_balance()
        {
            return Err(ChainLogAuditError::Unverified);
        }
    }
    Ok(())
}

fn ensure_deadline(
    deadline: Instant,
) -> Result<(), BoundedFifthNativeBinaryTwoConditionTradeError> {
    if Instant::now() >= deadline {
        Err(BoundedFifthNativeBinaryTwoConditionTradeError::Timeout)
    } else {
        Ok(())
    }
}

fn map_native_error(
    error: BoundedFifthNativeBinaryError,
) -> BoundedFifthNativeBinaryTwoConditionTradeError {
    match error {
        BoundedFifthNativeBinaryError::RequestBudgetExceeded => {
            BoundedFifthNativeBinaryTwoConditionTradeError::RequestBudgetExceeded
        }
        BoundedFifthNativeBinaryError::Timeout => {
            BoundedFifthNativeBinaryTwoConditionTradeError::Timeout
        }
        BoundedFifthNativeBinaryError::Verification(error) => {
            BoundedFifthNativeBinaryTwoConditionTradeError::Verification(error)
        }
    }
}
fn map_module_error(
    error: BoundedFifthNativeBinaryModuleOperationsError,
) -> BoundedFifthNativeBinaryTwoConditionTradeError {
    match error {
        BoundedFifthNativeBinaryModuleOperationsError::RequestBudgetExceeded => {
            BoundedFifthNativeBinaryTwoConditionTradeError::RequestBudgetExceeded
        }
        BoundedFifthNativeBinaryModuleOperationsError::Timeout => {
            BoundedFifthNativeBinaryTwoConditionTradeError::Timeout
        }
        BoundedFifthNativeBinaryModuleOperationsError::Verification(error) => {
            BoundedFifthNativeBinaryTwoConditionTradeError::Verification(error)
        }
    }
}
fn map_trade_error(
    error: super::fifth_native_binary_trades::BoundedFifthNativeBinaryTradeError,
) -> BoundedFifthNativeBinaryTwoConditionTradeError {
    match error { super::fifth_native_binary_trades::BoundedFifthNativeBinaryTradeError::RequestBudgetExceeded => BoundedFifthNativeBinaryTwoConditionTradeError::RequestBudgetExceeded, super::fifth_native_binary_trades::BoundedFifthNativeBinaryTradeError::Timeout => BoundedFifthNativeBinaryTwoConditionTradeError::Timeout, super::fifth_native_binary_trades::BoundedFifthNativeBinaryTradeError::Verification(error) => BoundedFifthNativeBinaryTwoConditionTradeError::Verification(error) }
}
