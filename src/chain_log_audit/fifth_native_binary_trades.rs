//! Rooted source attribution for native Binary `matchOrders` intervals.

use super::fifth_binary_trades::{
    FifthLegacyBinaryTradeUnavailableReason, FifthTradeTransactionFact, TransactionClassification,
    classify_transaction,
};
use super::fifth_code_context::EXCHANGE_PROXY;
use super::fifth_direct_module_operations::has_minter_role;
use super::fifth_exchange_controls::{
    BoundedFifthExchangeControlsError, FifthExchangeControlsObservation,
};
use super::fifth_match_orders_call::{
    FIFTH_MATCH_ORDERS_SELECTOR, decode_fifth_match_orders_calldata,
};
use super::fifth_native_binary::is_canonical_native_binary_condition;
use super::fifth_native_module_operations::{
    BoundedFifthNativeBinaryModuleOperationsError, FifthNativeBinaryModuleOperationBoundary,
};
use super::{
    ChainLogAuditError, ChainLogVerifier, ChainReceiptIntervalEvidence, MAX_BLOCKS,
    TransactionRequestBudget, validate_hex,
};
use alloy_primitives::{Address, B256, U256};
use sha3::{Digest, Keccak256};
use std::{collections::BTreeMap, str::FromStr, time::Duration};
use thiserror::Error;
use tokio::time::Instant;

const POLICY_VERSION: &str = "fifth-native-binary-match-orders-source-attribution/1";
const PUSD_PROXY: &str = "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb";

pub const FIFTH_NATIVE_BINARY_TRADE_POLICY_VERSION: &str = POLICY_VERSION;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedFifthNativeBinaryTradeError {
    #[error("fifth native binary trade RPC request budget exhausted")]
    RequestBudgetExceeded,
    #[error("fifth native binary trade exceeded its total deadline")]
    Timeout,
    #[error(transparent)]
    Verification(#[from] ChainLogAuditError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthNativeBinaryTradeAsset {
    OwnerPositionA,
    OwnerPositionB,
    OwnerPusd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthNativeBinaryTradeUnavailableReason {
    NativeBoundaryMismatch,
    ModuleStateUnavailable,
    UnsupportedDirectCall,
    UnsupportedOwnerActivity,
    InvalidCalldata,
    SourceSettlementMismatch,
    ArithmeticUnavailable,
    UnsupportedOwnerRole,
    ExchangeControlTransition,
    ExchangeControlUnavailable,
    ExchangePaused,
    SubmitterNotOperator,
    MakerPaused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FifthNativeBinaryTradeStatus {
    Matched,
    Mismatch {
        block_number: u64,
        asset: FifthNativeBinaryTradeAsset,
        authenticated_balance: U256,
        reconstructed_balance: U256,
    },
    Unavailable {
        block_number: Option<u64>,
        transaction_hash: Option<String>,
        reason: FifthNativeBinaryTradeUnavailableReason,
    },
}

/// A sealed bounded native interval; it carries no legacy CTF inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthNativeBinaryTradeObservation {
    evidence: ChainReceiptIntervalEvidence,
    opening: FifthNativeBinaryModuleOperationBoundary,
    block_observations: Vec<FifthNativeBinaryModuleOperationBoundary>,
    status: FifthNativeBinaryTradeStatus,
    transactions: Vec<FifthTradeTransactionFact>,
    controls: Vec<FifthExchangeControlsObservation>,
}

impl FifthNativeBinaryTradeObservation {
    #[must_use]
    pub const fn evidence(&self) -> &ChainReceiptIntervalEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn opening(&self) -> &FifthNativeBinaryModuleOperationBoundary {
        &self.opening
    }

    #[must_use]
    pub fn block_observations(&self) -> &[FifthNativeBinaryModuleOperationBoundary] {
        &self.block_observations
    }

    #[must_use]
    pub const fn status(&self) -> &FifthNativeBinaryTradeStatus {
        &self.status
    }

    #[must_use]
    pub fn transactions(&self) -> &[FifthTradeTransactionFact] {
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
    pub async fn verify_fifth_native_binary_trade_interval_bounded(
        &self,
        owner: &str,
        condition_id: &str,
        from_block: u64,
        through_block: u64,
        expected_parent_hash: &str,
        expected_end_hash: &str,
        max_requests: usize,
        total_timeout: Duration,
    ) -> Result<FifthNativeBinaryTradeObservation, BoundedFifthNativeBinaryTradeError> {
        let owner = validate_hex(owner, 20).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let owner_bytes = hex::decode(&owner[2..]).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let condition =
            super::parse_fixed_b256(condition_id).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let parent_hash =
            validate_hex(expected_parent_hash, 32).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let end_hash =
            validate_hex(expected_end_hash, 32).map_err(|_| ChainLogAuditError::InvalidInput)?;
        if owner_bytes.iter().all(|byte| *byte == 0)
            || from_block == 0
            || from_block > through_block
            || through_block - from_block >= MAX_BLOCKS
            || max_requests == 0
            || total_timeout.is_zero()
            || !is_canonical_native_binary_condition(condition)
        {
            return Err(ChainLogAuditError::InvalidInput.into());
        }
        let owner_address = Address::from_slice(&owner_bytes);
        let ids = [condition, derive_position_id(condition)];
        let deadline = Instant::now()
            .checked_add(total_timeout)
            .ok_or(ChainLogAuditError::InvalidInput)?;
        let budget = TransactionRequestBudget::new(max_requests);
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let scoped = self.with_request_budget(budget.inner());
        let verification = scoped.verify_native_binary_trade_inner(
            owner,
            owner_address,
            condition,
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
            _ = exhaustion.wait_for(|exhausted| *exhausted) => {
                Err(BoundedFifthNativeBinaryTradeError::RequestBudgetExceeded)
            }
            () = &mut deadline_wait => {
                if budget.is_exhausted() {
                    Err(BoundedFifthNativeBinaryTradeError::RequestBudgetExceeded)
                } else {
                    Err(BoundedFifthNativeBinaryTradeError::Timeout)
                }
            }
            result = &mut verification => {
                if budget.is_exhausted() {
                    Err(BoundedFifthNativeBinaryTradeError::RequestBudgetExceeded)
                } else if Instant::now() >= deadline {
                    Err(BoundedFifthNativeBinaryTradeError::Timeout)
                } else {
                    result
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn verify_native_binary_trade_inner(
        &self,
        owner: String,
        owner_address: Address,
        condition: B256,
        ids: [B256; 2],
        from_block: u64,
        through_block: u64,
        parent_hash: &str,
        end_hash: &str,
        deadline: Instant,
    ) -> Result<FifthNativeBinaryTradeObservation, BoundedFifthNativeBinaryTradeError> {
        ensure_deadline(deadline)?;
        let interval = self
            .verify_fifth_native_module_interval_evidence_inner(
                owner.clone(),
                owner_address,
                condition,
                ids,
                from_block,
                through_block,
                parent_hash,
                end_hash,
                deadline,
            )
            .await
            .map_err(map_module_operations_error)?;
        let (evidence, opening, points) = interval.into_parts();
        classify_native_interval(
            self,
            evidence,
            opening,
            points,
            owner_address,
            ids,
            deadline,
        )
        .await
    }
}

async fn classify_native_interval(
    verifier: &ChainLogVerifier,
    evidence: ChainReceiptIntervalEvidence,
    opening: FifthNativeBinaryModuleOperationBoundary,
    points: Vec<FifthNativeBinaryModuleOperationBoundary>,
    owner_address: Address,
    ids: [B256; 2],
    deadline: Instant,
) -> Result<FifthNativeBinaryTradeObservation, BoundedFifthNativeBinaryTradeError> {
    ensure_deadline(deadline)?;
    let boundaries = std::iter::once(&opening)
        .chain(points.iter())
        .collect::<Vec<_>>();
    if boundaries.len() != evidence.blocks().len() + 1
        || !module_identity_continues(&opening, &points)
    {
        return Ok(unavailable(
            evidence,
            opening,
            points,
            Vec::new(),
            None,
            None,
            FifthNativeBinaryTradeUnavailableReason::NativeBoundaryMismatch,
        ));
    }
    let mut module_state_failure = None;
    for (index, point) in boundaries.iter().enumerate() {
        let native = point.native_context();
        if native.condition_id() != ids[0]
            || native.position_ids() != ids
            || !native.legacy_mapping_value().is_zero()
            || !module_balances_are_zero(point)
            || !has_minter_role(point.module_role_bitmap())
        {
            let block_number = if index == 0 {
                evidence.from_block() - 1
            } else {
                evidence.blocks()[index - 1].block_number()
            };
            module_state_failure = Some(block_number);
            break;
        }
    }
    if let Some(block_number) = module_state_failure {
        return Ok(unavailable(
            evidence,
            opening,
            points,
            Vec::new(),
            Some(block_number),
            None,
            FifthNativeBinaryTradeUnavailableReason::ModuleStateUnavailable,
        ));
    }

    let assessment = verify_native_trade_sources_and_controls(
        verifier,
        &evidence,
        &opening,
        &points,
        owner_address,
        ids,
        false,
        deadline,
    )
    .await?;
    if let Some(failure) = assessment.refusal {
        return Ok(unavailable(
            evidence,
            opening,
            points,
            assessment.controls,
            failure.block_number,
            failure.transaction_hash,
            failure.reason,
        ));
    }
    let facts = assessment.facts;
    let controls = assessment.controls;

    match replay_owner_balances(&evidence, &opening, &points, &facts) {
        Err(()) => {
            return Ok(unavailable(
                evidence,
                opening,
                points,
                controls,
                None,
                None,
                FifthNativeBinaryTradeUnavailableReason::ArithmeticUnavailable,
            ));
        }
        Ok(Some(mismatch)) => {
            return Ok(FifthNativeBinaryTradeObservation {
                evidence,
                opening,
                block_observations: points,
                status: FifthNativeBinaryTradeStatus::Mismatch {
                    block_number: mismatch.block_number,
                    asset: mismatch.asset,
                    authenticated_balance: mismatch.authenticated_balance,
                    reconstructed_balance: mismatch.reconstructed_balance,
                },
                transactions: Vec::new(),
                controls,
            });
        }
        Ok(None) => {}
    }
    ensure_deadline(deadline)?;
    Ok(FifthNativeBinaryTradeObservation {
        evidence,
        opening,
        block_observations: points,
        status: FifthNativeBinaryTradeStatus::Matched,
        transactions: facts,
        controls,
    })
}

pub(super) struct NativeTradeSourceAssessment {
    pub(super) facts: Vec<FifthTradeTransactionFact>,
    pub(super) controls: Vec<FifthExchangeControlsObservation>,
    pub(super) refusal: Option<NativeTradeSourceFailure>,
}

pub(super) struct NativeTradeSourceFailure {
    pub(super) block_number: Option<u64>,
    pub(super) transaction_hash: Option<String>,
    pub(super) reason: FifthNativeBinaryTradeUnavailableReason,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn verify_native_trade_sources_and_controls(
    verifier: &ChainLogVerifier,
    evidence: &ChainReceiptIntervalEvidence,
    opening: &FifthNativeBinaryModuleOperationBoundary,
    points: &[FifthNativeBinaryModuleOperationBoundary],
    owner: Address,
    ids: [B256; 2],
    allow_module_operations: bool,
    deadline: Instant,
) -> Result<NativeTradeSourceAssessment, BoundedFifthNativeBinaryTradeError> {
    ensure_deadline(deadline)?;
    let module = opening.native_context().module_proxy();
    let scan = match scan_native_transactions(
        evidence,
        points,
        owner,
        ids,
        module,
        allow_module_operations,
        deadline,
    ) {
        Ok(scan) => scan,
        Err(NativeTransactionScanError::Unavailable(failure)) => {
            return Ok(NativeTradeSourceAssessment {
                facts: Vec::new(),
                controls: Vec::new(),
                refusal: Some(NativeTradeSourceFailure {
                    block_number: Some(failure.block_number),
                    transaction_hash: Some(failure.transaction_hash),
                    reason: failure.reason,
                }),
            });
        }
        Err(NativeTransactionScanError::Bounded(error)) => return Err(error),
    };
    let ScannedNativeTransactions {
        facts,
        actors,
        candidates,
    } = scan;
    let boundaries = std::iter::once(opening)
        .chain(points.iter())
        .collect::<Vec<_>>();
    let control_assessment = verify_native_trade_controls(
        verifier,
        evidence,
        &boundaries,
        &actors,
        &candidates,
        deadline,
    )
    .await?;
    let controls = control_assessment.controls;
    let refusal = control_assessment.refusal;
    ensure_deadline(deadline)?;
    Ok(NativeTradeSourceAssessment {
        facts: if refusal.is_some() { Vec::new() } else { facts },
        controls,
        refusal,
    })
}

pub(super) struct NativeTradeControlAssessment {
    pub(super) controls: Vec<FifthExchangeControlsObservation>,
    pub(super) refusal: Option<NativeTradeSourceFailure>,
}

pub(super) async fn verify_native_trade_controls(
    verifier: &ChainLogVerifier,
    evidence: &ChainReceiptIntervalEvidence,
    boundaries: &[&FifthNativeBinaryModuleOperationBoundary],
    actors: &[(Address, Address)],
    candidates: &[(usize, usize, Address, Vec<Address>)],
    deadline: Instant,
) -> Result<NativeTradeControlAssessment, BoundedFifthNativeBinaryTradeError> {
    let mut controls = Vec::new();
    let mut control_failure = None;
    'boundaries: for (boundary_index, point) in boundaries.iter().enumerate() {
        ensure_deadline(deadline)?;
        let context = point
            .native_context()
            .selected_balances()
            .code_context()
            .clone();
        for (submitter, maker) in actors {
            ensure_deadline(deadline)?;
            let control = verifier
                .verify_fifth_exchange_controls_from_code_context_inner(
                    context.clone(),
                    *submitter,
                    *maker,
                    deadline,
                )
                .await
                .map_err(map_controls_error)?;
            if control.global_paused() {
                control_failure = Some((
                    point_block_number(boundary_index, evidence),
                    FifthNativeBinaryTradeUnavailableReason::ExchangePaused,
                ));
                break 'boundaries;
            }
            if !control.submitter_has_operator_role() {
                control_failure = Some((
                    point_block_number(boundary_index, evidence),
                    FifthNativeBinaryTradeUnavailableReason::SubmitterNotOperator,
                ));
                break 'boundaries;
            }
            controls.push(control);
        }
    }
    let refusal = if let Some((block_number, reason)) = control_failure {
        Some(NativeTradeSourceFailure {
            block_number: Some(block_number),
            transaction_hash: None,
            reason,
        })
    } else if !controls_stable(&controls) {
        Some(NativeTradeSourceFailure {
            block_number: None,
            transaction_hash: None,
            reason: FifthNativeBinaryTradeUnavailableReason::ExchangeControlTransition,
        })
    } else {
        let mut refusal = None;
        'candidates: for (block_index, transaction_index, submitter, makers) in candidates {
            let block_number = evidence.blocks()[*block_index].block_number();
            let transaction_hash = evidence.blocks()[*block_index].transactions()
                [*transaction_index]
                .transaction_hash()
                .to_owned();
            for maker in makers {
                let Some(control) = controls.iter().find(|control| {
                    control.code_context().block_number() == block_number
                        && control.submitter() == *submitter
                        && control.maker() == *maker
                }) else {
                    refusal = Some(NativeTradeSourceFailure {
                        block_number: Some(block_number),
                        transaction_hash: Some(transaction_hash.clone()),
                        reason: FifthNativeBinaryTradeUnavailableReason::ExchangeControlUnavailable,
                    });
                    break 'candidates;
                };
                let activation = control.maker_pause_activation_block();
                if !activation.is_zero() && U256::from(block_number) >= activation {
                    refusal = Some(NativeTradeSourceFailure {
                        block_number: Some(block_number),
                        transaction_hash: Some(transaction_hash.clone()),
                        reason: FifthNativeBinaryTradeUnavailableReason::MakerPaused,
                    });
                    break 'candidates;
                }
            }
        }
        refusal
    };
    ensure_deadline(deadline)?;
    Ok(NativeTradeControlAssessment { controls, refusal })
}

struct ScannedNativeTransactions {
    facts: Vec<FifthTradeTransactionFact>,
    actors: Vec<(Address, Address)>,
    candidates: Vec<(usize, usize, Address, Vec<Address>)>,
}

struct NativeTransactionScanFailure {
    block_number: u64,
    transaction_hash: String,
    reason: FifthNativeBinaryTradeUnavailableReason,
}

enum NativeTransactionScanError {
    Unavailable(NativeTransactionScanFailure),
    Bounded(BoundedFifthNativeBinaryTradeError),
}

fn scan_native_transactions(
    evidence: &ChainReceiptIntervalEvidence,
    points: &[FifthNativeBinaryModuleOperationBoundary],
    owner: Address,
    ids: [B256; 2],
    module: Address,
    allow_module_operations: bool,
    deadline: Instant,
) -> Result<ScannedNativeTransactions, NativeTransactionScanError> {
    let mut facts = Vec::new();
    let mut actors = Vec::new();
    let mut candidates = Vec::new();
    for (block_index, block) in evidence.blocks().iter().enumerate() {
        ensure_deadline(deadline).map_err(NativeTransactionScanError::Bounded)?;
        let version = points[block_index]
            .native_context()
            .selected_balances()
            .code_context()
            .exchange_implementation_version();
        for (transaction_index, transaction) in block.transactions().iter().enumerate() {
            let block_number = block.block_number();
            let transaction_hash = transaction.transaction_hash().to_owned();
            let failure = |reason| {
                NativeTransactionScanError::Unavailable(NativeTransactionScanFailure {
                    block_number,
                    transaction_hash: transaction_hash.clone(),
                    reason,
                })
            };
            if transaction_has_control_or_upgrade_event(transaction, module) {
                return Err(failure(
                    FifthNativeBinaryTradeUnavailableReason::ExchangeControlTransition,
                ));
            }
            let is_module_operation_target = allow_module_operations
                && transaction.to.as_deref().is_some_and(|to| {
                    to.eq_ignore_ascii_case(&format!("{module:#x}"))
                        || to
                            .eq_ignore_ascii_case(super::fifth_code_context::POSITION_MANAGER_PROXY)
                        || to.eq_ignore_ascii_case(PUSD_PROXY)
                });
            if is_module_operation_target {
                continue;
            }
            let exchange_call = transaction
                .to
                .as_deref()
                .is_some_and(|to| to.eq_ignore_ascii_case(EXCHANGE_PROXY));
            let input_has_match = transaction
                .input
                .as_deref()
                .is_some_and(input_has_match_orders_selector);
            if exchange_call && !input_has_match {
                return Err(failure(
                    FifthNativeBinaryTradeUnavailableReason::UnsupportedDirectCall,
                ));
            }
            let classified = classify_transaction(
                transaction,
                block_number,
                block.block_hash(),
                owner,
                ids,
                module,
                version,
            );
            let is_successful_match = exchange_call && transaction.status() == 1 && input_has_match;
            let fact = match classified {
                TransactionClassification::Quiet => None,
                TransactionClassification::Fact(fact) => Some(*fact),
                TransactionClassification::Unavailable(reason) => {
                    return Err(failure(map_trade_reason(reason)));
                }
            };
            if !is_successful_match {
                if fact.is_some() {
                    return Err(failure(
                        FifthNativeBinaryTradeUnavailableReason::UnsupportedOwnerActivity,
                    ));
                }
                continue;
            }
            let Some(input) = transaction.input.as_deref() else {
                return Err(failure(
                    FifthNativeBinaryTradeUnavailableReason::InvalidCalldata,
                ));
            };
            let Some(call) = decode_fifth_match_orders_calldata(input) else {
                return Err(failure(
                    FifthNativeBinaryTradeUnavailableReason::InvalidCalldata,
                ));
            };
            let Some(recovered_from) = transaction.recovered_from.as_deref() else {
                return Err(failure(
                    FifthNativeBinaryTradeUnavailableReason::UnsupportedDirectCall,
                ));
            };
            let Ok(submitter) = Address::from_str(recovered_from) else {
                return Err(failure(
                    FifthNativeBinaryTradeUnavailableReason::UnsupportedDirectCall,
                ));
            };
            let mut makers = vec![call.taker_order.maker];
            makers.extend(call.maker_orders.iter().map(|order| order.maker));
            makers.sort_unstable();
            makers.dedup();
            for maker in &makers {
                let actor = (submitter, *maker);
                if !actors.contains(&actor) {
                    actors.push(actor);
                }
            }
            candidates.push((block_index, transaction_index, submitter, makers));
            if let Some(fact) = fact {
                facts.push(fact);
            }
        }
    }
    Ok(ScannedNativeTransactions {
        facts,
        actors,
        candidates,
    })
}

struct OwnerBalanceMismatch {
    block_number: u64,
    asset: FifthNativeBinaryTradeAsset,
    authenticated_balance: U256,
    reconstructed_balance: U256,
}

fn replay_owner_balances(
    evidence: &ChainReceiptIntervalEvidence,
    opening: &FifthNativeBinaryModuleOperationBoundary,
    points: &[FifthNativeBinaryModuleOperationBoundary],
    facts: &[FifthTradeTransactionFact],
) -> Result<Option<OwnerBalanceMismatch>, ()> {
    let opening_balances = opening.native_context().selected_balances();
    let mut reconstructed = [
        opening_balances.position_balance_a(),
        opening_balances.position_balance_b(),
        opening_balances.pusd_balance(),
    ];
    for (index, block) in evidence.blocks().iter().enumerate() {
        for fact in facts
            .iter()
            .filter(|fact| fact.block_number() == block.block_number())
        {
            let inflows = fact.owner_position_inflows();
            let outflows = fact.owner_position_outflows();
            for side in 0..2 {
                reconstructed[side] = reconstructed[side]
                    .checked_add(inflows[side])
                    .ok_or(())?
                    .checked_sub(outflows[side])
                    .ok_or(())?;
            }
            reconstructed[2] = reconstructed[2]
                .checked_add(fact.owner_pusd_inflow())
                .ok_or(())?
                .checked_sub(fact.owner_pusd_outflow())
                .ok_or(())?;
        }
        let selected = points[index].native_context().selected_balances();
        let authenticated = [
            selected.position_balance_a(),
            selected.position_balance_b(),
            selected.pusd_balance(),
        ];
        let assets = [
            FifthNativeBinaryTradeAsset::OwnerPositionA,
            FifthNativeBinaryTradeAsset::OwnerPositionB,
            FifthNativeBinaryTradeAsset::OwnerPusd,
        ];
        for asset_index in 0..3 {
            if reconstructed[asset_index] != authenticated[asset_index] {
                return Ok(Some(OwnerBalanceMismatch {
                    block_number: block.block_number(),
                    asset: assets[asset_index],
                    authenticated_balance: authenticated[asset_index],
                    reconstructed_balance: reconstructed[asset_index],
                }));
            }
        }
    }
    Ok(None)
}

pub(super) fn module_identity_continues(
    opening: &FifthNativeBinaryModuleOperationBoundary,
    points: &[FifthNativeBinaryModuleOperationBoundary],
) -> bool {
    let mut previous = opening;
    for point in points {
        if !super::fifth_direct_module_operations::ModuleOperationPoint::source_identity_continues(
            previous, point,
        ) {
            return false;
        }
        previous = point;
    }
    true
}

fn module_balances_are_zero(point: &FifthNativeBinaryModuleOperationBoundary) -> bool {
    point.module_position_balances() == [U256::ZERO; 2] && point.module_pusd_balance().is_zero()
}

fn input_has_match_orders_selector(input: &[u8]) -> bool {
    input.starts_with(&FIFTH_MATCH_ORDERS_SELECTOR)
}

pub(super) fn controls_stable(controls: &[FifthExchangeControlsObservation]) -> bool {
    let mut exchange_state = None;
    let mut submitter_roles = BTreeMap::new();
    let mut maker_states = BTreeMap::new();
    for control in controls {
        let exchange = (
            control.global_pause_word(),
            control.user_pause_block_interval(),
        );
        if exchange_state.is_some_and(|previous| previous != exchange) {
            return false;
        }
        exchange_state = Some(exchange);
        if submitter_roles
            .insert(control.submitter(), control.submitter_role_bitmap())
            .is_some_and(|previous| previous != control.submitter_role_bitmap())
        {
            return false;
        }
        if maker_states
            .insert(control.maker(), control.maker_pause_activation_block())
            .is_some_and(|previous| previous != control.maker_pause_activation_block())
        {
            return false;
        }
    }
    true
}

pub(super) fn transaction_has_control_or_upgrade_event(
    transaction: &super::ChainReceiptIntervalTransaction,
    module: Address,
) -> bool {
    const EXCHANGE_CONTROL_SIGNATURES: [&str; 8] = [
        "RolesUpdated(address,uint256)",
        "TradingPaused(address)",
        "TradingUnpaused(address)",
        "UserPaused(address,uint256)",
        "UserUnpaused(address)",
        "UserPauseBlockIntervalUpdated(uint256,uint256)",
        "Upgraded(address)",
        "ProxyUpdated(address,address)",
    ];
    let control_topics = EXCHANGE_CONTROL_SIGNATURES
        .iter()
        .map(|signature| format!("0x{}", hex::encode(Keccak256::digest(signature.as_bytes()))))
        .collect::<Vec<_>>();
    let relevant_emitters = [
        EXCHANGE_PROXY.to_owned(),
        format!("{module:#x}"),
        super::fifth_code_context::POSITION_MANAGER_PROXY.to_owned(),
        PUSD_PROXY.to_owned(),
    ];
    transaction.logs().iter().any(|log| {
        let relevant = relevant_emitters
            .iter()
            .any(|address| log.address().eq_ignore_ascii_case(address));
        relevant
            && log.topics().first().is_some_and(|topic| {
                control_topics
                    .iter()
                    .any(|expected| expected.eq_ignore_ascii_case(topic))
            })
    })
}

fn point_block_number(boundary_index: usize, evidence: &ChainReceiptIntervalEvidence) -> u64 {
    if boundary_index == 0 {
        evidence.from_block() - 1
    } else {
        evidence.blocks()[boundary_index - 1].block_number()
    }
}

fn unavailable(
    evidence: ChainReceiptIntervalEvidence,
    opening: FifthNativeBinaryModuleOperationBoundary,
    block_observations: Vec<FifthNativeBinaryModuleOperationBoundary>,
    controls: Vec<FifthExchangeControlsObservation>,
    block_number: Option<u64>,
    transaction_hash: Option<String>,
    reason: FifthNativeBinaryTradeUnavailableReason,
) -> FifthNativeBinaryTradeObservation {
    FifthNativeBinaryTradeObservation {
        evidence,
        opening,
        block_observations,
        status: FifthNativeBinaryTradeStatus::Unavailable {
            block_number,
            transaction_hash,
            reason,
        },
        transactions: Vec::new(),
        controls,
    }
}

fn derive_position_id(condition: B256) -> B256 {
    let mut bytes = condition.0;
    bytes[31] = 1;
    B256::from(bytes)
}

pub(super) fn map_trade_reason(
    reason: FifthLegacyBinaryTradeUnavailableReason,
) -> FifthNativeBinaryTradeUnavailableReason {
    match reason {
        FifthLegacyBinaryTradeUnavailableReason::InventoryUnreconciled => {
            FifthNativeBinaryTradeUnavailableReason::NativeBoundaryMismatch
        }
        FifthLegacyBinaryTradeUnavailableReason::UnsupportedOwnerActivity => {
            FifthNativeBinaryTradeUnavailableReason::UnsupportedOwnerActivity
        }
        FifthLegacyBinaryTradeUnavailableReason::UnsupportedDirectCall => {
            FifthNativeBinaryTradeUnavailableReason::UnsupportedDirectCall
        }
        FifthLegacyBinaryTradeUnavailableReason::InvalidCalldata => {
            FifthNativeBinaryTradeUnavailableReason::InvalidCalldata
        }
        FifthLegacyBinaryTradeUnavailableReason::SourceSettlementMismatch => {
            FifthNativeBinaryTradeUnavailableReason::SourceSettlementMismatch
        }
        FifthLegacyBinaryTradeUnavailableReason::ArithmeticUnavailable => {
            FifthNativeBinaryTradeUnavailableReason::ArithmeticUnavailable
        }
        FifthLegacyBinaryTradeUnavailableReason::UnsupportedOwnerRole => {
            FifthNativeBinaryTradeUnavailableReason::UnsupportedOwnerRole
        }
    }
}

fn map_module_operations_error(
    error: BoundedFifthNativeBinaryModuleOperationsError,
) -> BoundedFifthNativeBinaryTradeError {
    match error {
        BoundedFifthNativeBinaryModuleOperationsError::RequestBudgetExceeded => {
            BoundedFifthNativeBinaryTradeError::RequestBudgetExceeded
        }
        BoundedFifthNativeBinaryModuleOperationsError::Timeout => {
            BoundedFifthNativeBinaryTradeError::Timeout
        }
        BoundedFifthNativeBinaryModuleOperationsError::Verification(error) => {
            BoundedFifthNativeBinaryTradeError::Verification(error)
        }
    }
}

fn map_controls_error(
    error: BoundedFifthExchangeControlsError,
) -> BoundedFifthNativeBinaryTradeError {
    match error {
        BoundedFifthExchangeControlsError::RequestBudgetExceeded => {
            BoundedFifthNativeBinaryTradeError::RequestBudgetExceeded
        }
        BoundedFifthExchangeControlsError::Timeout => BoundedFifthNativeBinaryTradeError::Timeout,
        BoundedFifthExchangeControlsError::Verification(error) => {
            BoundedFifthNativeBinaryTradeError::Verification(error)
        }
    }
}

fn ensure_deadline(deadline: Instant) -> Result<(), BoundedFifthNativeBinaryTradeError> {
    if Instant::now() >= deadline {
        Err(BoundedFifthNativeBinaryTradeError::Timeout)
    } else {
        Ok(())
    }
}
