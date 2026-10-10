//! One rooted owner/module activity replay across two native conditions.

use super::fifth_binary_trades::{TransactionClassification, classify_transaction};
use super::fifth_code_context::EXCHANGE_PROXY;
use super::fifth_direct_module_operations::{
    self as source, FifthDirectModuleFundingFact, FundingCall, ModuleCall, ModuleOperationPoint,
};
use super::fifth_exchange_controls::FifthExchangeControlsObservation;
use super::fifth_native_activity::FifthNativeBinaryActivityIntervalAnchor;
use super::fifth_native_binary::is_canonical_native_binary_condition;
use super::fifth_native_binary_trades::{
    BoundedFifthNativeBinaryTradeError, transaction_has_control_or_upgrade_event,
    verify_native_trade_controls,
};
use super::fifth_native_module_operations::FifthNativeBinaryModuleOperationBoundary;
use super::fifth_native_two_condition_splits::{
    FifthNativeTwoConditionSplitFact, relevant_unclassified_movement, split_fact,
    validate_owner_source,
};
use super::fifth_native_two_condition_trades::{
    BoundedFifthNativeBinaryTwoConditionTradeError, FifthNativeTwoConditionTradeTransaction,
    TwoConditionAnchor, TwoConditionEvidence, classify_two_condition_exchange_transaction,
    collect_two_condition_evidence, has_owner_position_or_cash_movement, native_position_ids,
    tag_trade_fact,
};
use super::{
    CHAIN_ID, ChainLogAuditError, ChainLogVerifier, ChainReceiptIntervalEvidence, MAX_BLOCKS,
    RECEIPT_INTERVAL_POLICY_VERSION, TransactionRequestBudget, parse_fixed_b256, validate_hex,
};
use alloy_primitives::{Address, B256, U256};
use std::{collections::BTreeSet, time::Duration};
use thiserror::Error;
use tokio::time::Instant;

const POLICY_VERSION: &str =
    "fifth-native-binary-two-condition-activity-source-and-shared-pusd-replay/1";
const INTERVALS_POLICY_VERSION: &str =
    "fifth-native-binary-two-condition-activity-contiguous-shared-custody-replay/1";

pub const FIFTH_NATIVE_TWO_CONDITION_ACTIVITY_POLICY_VERSION: &str = POLICY_VERSION;
pub const FIFTH_NATIVE_TWO_CONDITION_ACTIVITY_INTERVALS_POLICY_VERSION: &str =
    INTERVALS_POLICY_VERSION;

const MAX_ACTIVITY_INTERVALS: usize = 16;
const MAX_ACTIVITY_INTERVAL_BLOCKS: u64 = 16;
const MAX_ACTIVITY_TOTAL_BLOCKS: u64 = 256;

struct ValidatedActivityInterval {
    from_block: u64,
    through_block: u64,
    parent_hash: String,
    end_hash: String,
}

struct CollectedActivity {
    evidence: ChainReceiptIntervalEvidence,
    intervals: Vec<FifthNativeBinaryActivityIntervalAnchor>,
    policy: &'static str,
    opening: [FifthNativeBinaryModuleOperationBoundary; 2],
    block_observations: Vec<[FifthNativeBinaryModuleOperationBoundary; 2]>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedFifthNativeBinaryTwoConditionActivityError {
    #[error("two-condition native activity RPC request budget exhausted")]
    RequestBudgetExceeded,
    #[error("two-condition native activity exceeded its total deadline")]
    Timeout,
    #[error(transparent)]
    Verification(#[from] ChainLogAuditError),
}

/// Complete rooted source facts for one funding/splits/trades interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthNativeBinaryTwoConditionActivityObservation {
    evidence: ChainReceiptIntervalEvidence,
    intervals: Vec<FifthNativeBinaryActivityIntervalAnchor>,
    source_policy_version: &'static str,
    opening: [FifthNativeBinaryModuleOperationBoundary; 2],
    block_observations: Vec<[FifthNativeBinaryModuleOperationBoundary; 2]>,
    funding: FifthDirectModuleFundingFact,
    splits: Vec<FifthNativeTwoConditionSplitFact>,
    trades: Vec<FifthNativeTwoConditionTradeTransaction>,
    controls: Vec<FifthExchangeControlsObservation>,
}

impl FifthNativeBinaryTwoConditionActivityObservation {
    #[must_use]
    pub const fn evidence(&self) -> &ChainReceiptIntervalEvidence {
        &self.evidence
    }

    #[must_use]
    pub fn intervals(&self) -> &[FifthNativeBinaryActivityIntervalAnchor] {
        &self.intervals
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
    pub const fn funding(&self) -> &FifthDirectModuleFundingFact {
        &self.funding
    }

    #[must_use]
    pub fn splits(&self) -> &[FifthNativeTwoConditionSplitFact] {
        &self.splits
    }

    #[must_use]
    pub fn trades(&self) -> &[FifthNativeTwoConditionTradeTransaction] {
        &self.trades
    }

    #[must_use]
    pub fn controls(&self) -> &[FifthExchangeControlsObservation] {
        &self.controls
    }

    #[must_use]
    pub const fn source_policy_version(&self) -> &'static str {
        self.source_policy_version
    }
}

impl ChainLogVerifier {
    #[allow(clippy::too_many_arguments)]
    pub async fn verify_fifth_native_binary_two_condition_activity_bounded(
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
        FifthNativeBinaryTwoConditionActivityObservation,
        BoundedFifthNativeBinaryTwoConditionActivityError,
    > {
        let owner = validate_hex(owner, 20).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let owner_bytes = hex::decode(&owner[2..]).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let conditions = [
            parse_fixed_b256(conditions[0]).map_err(|_| ChainLogAuditError::InvalidInput)?,
            parse_fixed_b256(conditions[1]).map_err(|_| ChainLogAuditError::InvalidInput)?,
        ];
        let parent_hash =
            validate_hex(expected_parent_hash, 32).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let end_hash =
            validate_hex(expected_end_hash, 32).map_err(|_| ChainLogAuditError::InvalidInput)?;
        if owner_bytes.iter().all(|byte| *byte == 0)
            || conditions[0] == conditions[1]
            || from_block == 0
            || from_block > through_block
            || through_block - from_block >= MAX_BLOCKS
            || max_requests == 0
            || total_timeout.is_zero()
            || conditions
                .iter()
                .any(|condition| !is_canonical_native_binary_condition(*condition))
        {
            return Err(ChainLogAuditError::InvalidInput.into());
        }

        let owner = Address::from_slice(&owner_bytes);
        let ids = conditions.map(native_position_ids);
        let deadline = Instant::now()
            .checked_add(total_timeout)
            .ok_or(ChainLogAuditError::InvalidInput)?;
        let budget = TransactionRequestBudget::new(max_requests);
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let scoped = self.with_request_budget(budget.inner());
        let verification = scoped.verify_two_condition_activity_inner(
            owner,
            ids,
            from_block,
            through_block,
            &parent_hash,
            &end_hash,
            deadline,
            vec![FifthNativeBinaryActivityIntervalAnchor::new(
                from_block,
                through_block,
                parent_hash.clone(),
                end_hash.clone(),
            )],
            POLICY_VERSION,
        );
        tokio::pin!(verification);
        let deadline_wait = tokio::time::sleep_until(deadline);
        tokio::pin!(deadline_wait);
        tokio::select! {
            biased;
            _ = exhaustion.wait_for(|is_exhausted| *is_exhausted) => {
                Err(BoundedFifthNativeBinaryTwoConditionActivityError::RequestBudgetExceeded)
            }
            () = &mut deadline_wait => {
                if budget.is_exhausted() {
                    Err(BoundedFifthNativeBinaryTwoConditionActivityError::RequestBudgetExceeded)
                } else {
                    Err(BoundedFifthNativeBinaryTwoConditionActivityError::Timeout)
                }
            }
            result = &mut verification => {
                if budget.is_exhausted() {
                    Err(BoundedFifthNativeBinaryTwoConditionActivityError::RequestBudgetExceeded)
                } else if Instant::now() >= deadline {
                    Err(BoundedFifthNativeBinaryTwoConditionActivityError::Timeout)
                } else {
                    result
                }
            }
        }
    }

    pub async fn verify_fifth_native_binary_two_condition_activity_intervals_bounded(
        &self,
        owner: &str,
        conditions: [&str; 2],
        intervals: &[FifthNativeBinaryActivityIntervalAnchor],
        max_requests: usize,
        total_timeout: Duration,
    ) -> Result<
        FifthNativeBinaryTwoConditionActivityObservation,
        BoundedFifthNativeBinaryTwoConditionActivityError,
    > {
        let owner = validate_hex(owner, 20).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let owner_bytes = hex::decode(&owner[2..]).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let conditions = [
            parse_fixed_b256(conditions[0]).map_err(|_| ChainLogAuditError::InvalidInput)?,
            parse_fixed_b256(conditions[1]).map_err(|_| ChainLogAuditError::InvalidInput)?,
        ];
        if owner_bytes.iter().all(|byte| *byte == 0)
            || conditions[0] == conditions[1]
            || !(1..=MAX_ACTIVITY_INTERVALS).contains(&intervals.len())
            || max_requests == 0
            || total_timeout.is_zero()
            || conditions
                .iter()
                .any(|condition| !is_canonical_native_binary_condition(*condition))
        {
            return Err(ChainLogAuditError::InvalidInput.into());
        }

        let mut validated: Vec<ValidatedActivityInterval> = Vec::with_capacity(intervals.len());
        let mut total_blocks = 0_u64;
        for anchor in intervals {
            if anchor.from_block == 0
                || anchor.from_block > anchor.through_block
                || anchor.through_block - anchor.from_block >= MAX_ACTIVITY_INTERVAL_BLOCKS
            {
                return Err(ChainLogAuditError::InvalidInput.into());
            }
            let parent_hash = validate_hex(&anchor.expected_parent_hash, 32)
                .map_err(|_| ChainLogAuditError::InvalidInput)?;
            let end_hash = validate_hex(&anchor.expected_end_hash, 32)
                .map_err(|_| ChainLogAuditError::InvalidInput)?;
            let blocks = anchor
                .through_block
                .checked_sub(anchor.from_block)
                .and_then(|length| length.checked_add(1))
                .ok_or(ChainLogAuditError::InvalidInput)?;
            total_blocks = total_blocks
                .checked_add(blocks)
                .ok_or(ChainLogAuditError::InvalidInput)?;
            if total_blocks > MAX_ACTIVITY_TOTAL_BLOCKS {
                return Err(ChainLogAuditError::InvalidInput.into());
            }
            if let Some(previous) = validated.last()
                && (previous.through_block.checked_add(1) != Some(anchor.from_block)
                    || previous.end_hash != parent_hash)
            {
                return Err(ChainLogAuditError::InvalidInput.into());
            }
            validated.push(ValidatedActivityInterval {
                from_block: anchor.from_block,
                through_block: anchor.through_block,
                parent_hash,
                end_hash,
            });
        }

        let owner = Address::from_slice(&owner_bytes);
        let ids = conditions.map(native_position_ids);
        let deadline = Instant::now()
            .checked_add(total_timeout)
            .ok_or(ChainLogAuditError::InvalidInput)?;
        let budget = TransactionRequestBudget::new(max_requests);
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let scoped = self.with_request_budget(budget.inner());
        let verification =
            scoped.verify_two_condition_activity_intervals_inner(owner, ids, validated, deadline);
        tokio::pin!(verification);
        let deadline_wait = tokio::time::sleep_until(deadline);
        tokio::pin!(deadline_wait);
        tokio::select! {
            biased;
            _ = exhaustion.wait_for(|is_exhausted| *is_exhausted) => {
                Err(BoundedFifthNativeBinaryTwoConditionActivityError::RequestBudgetExceeded)
            }
            () = &mut deadline_wait => {
                if budget.is_exhausted() {
                    Err(BoundedFifthNativeBinaryTwoConditionActivityError::RequestBudgetExceeded)
                } else {
                    Err(BoundedFifthNativeBinaryTwoConditionActivityError::Timeout)
                }
            }
            result = &mut verification => {
                if budget.is_exhausted() {
                    Err(BoundedFifthNativeBinaryTwoConditionActivityError::RequestBudgetExceeded)
                } else if Instant::now() >= deadline {
                    Err(BoundedFifthNativeBinaryTwoConditionActivityError::Timeout)
                } else {
                    result
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn verify_two_condition_activity_inner(
        &self,
        owner: Address,
        ids: [[B256; 2]; 2],
        from_block: u64,
        through_block: u64,
        parent_hash: &str,
        end_hash: &str,
        deadline: Instant,
        intervals: Vec<FifthNativeBinaryActivityIntervalAnchor>,
        policy: &'static str,
    ) -> Result<
        FifthNativeBinaryTwoConditionActivityObservation,
        BoundedFifthNativeBinaryTwoConditionActivityError,
    > {
        let collected = collect_two_condition_evidence(
            self,
            owner,
            ids,
            TwoConditionAnchor {
                from_block,
                through_block,
                parent_hash,
                end_hash,
                deadline,
            },
            |opening| {
                if opening.iter().any(|point| {
                    point.module_position_balances() != [U256::ZERO; 2]
                        || !point.module_pusd_balance().is_zero()
                        || !source::has_minter_role(point.module_role_bitmap())
                }) {
                    return Err(ChainLogAuditError::Unverified);
                }
                Ok(())
            },
            |opening, previous, pair, _block| {
                if pair.iter().any(|point| {
                    point.native_context().legacy_mapping_value() != U256::ZERO
                        || !source::has_minter_role(point.module_role_bitmap())
                }) {
                    return Err(ChainLogAuditError::Unverified);
                }
                for index in 0..2 {
                    if !ModuleOperationPoint::source_identity_continues(
                        &previous[index],
                        &pair[index],
                    ) || pair[index].module_role_bitmap() != opening[index].module_role_bitmap()
                    {
                        return Err(ChainLogAuditError::Unverified);
                    }
                }
                Ok(())
            },
        )
        .await
        .map_err(map_trade_error)?;
        let TwoConditionEvidence {
            evidence,
            opening,
            block_observations,
        } = collected;
        let module = opening[0].native_context().module_proxy();
        let scanned = scan_activity(&evidence, &block_observations, owner, ids, module, deadline)?;
        self.finish_collected_activity(
            CollectedActivity {
                evidence,
                intervals,
                policy,
                opening,
                block_observations,
            },
            deadline,
            scanned,
        )
        .await
    }

    async fn verify_two_condition_activity_intervals_inner(
        &self,
        owner: Address,
        ids: [[B256; 2]; 2],
        intervals: Vec<ValidatedActivityInterval>,
        deadline: Instant,
    ) -> Result<
        FifthNativeBinaryTwoConditionActivityObservation,
        BoundedFifthNativeBinaryTwoConditionActivityError,
    > {
        let mut collected = Vec::with_capacity(intervals.len());
        let mut global_opening: Option<[FifthNativeBinaryModuleOperationBoundary; 2]> = None;
        let mut previous_closing: Option<[FifthNativeBinaryModuleOperationBoundary; 2]> = None;
        let mut module = None;
        for (interval_index, anchor) in intervals.iter().enumerate() {
            ensure_deadline(deadline)?;
            let chunk = collect_two_condition_evidence(
                self,
                owner,
                ids,
                TwoConditionAnchor {
                    from_block: anchor.from_block,
                    through_block: anchor.through_block,
                    parent_hash: &anchor.parent_hash,
                    end_hash: &anchor.end_hash,
                    deadline,
                },
                |opening| {
                    if opening.iter().any(|point| {
                        point.module_position_balances() != [U256::ZERO; 2]
                            || !source::has_minter_role(point.module_role_bitmap())
                            || (interval_index == 0 && !point.module_pusd_balance().is_zero())
                    }) {
                        return Err(ChainLogAuditError::Unverified);
                    }
                    if let Some(previous) = previous_closing.as_ref()
                        && !same_activity_pair_boundary(previous, opening)
                    {
                        return Err(ChainLogAuditError::Unverified);
                    }
                    if let Some(opening0) = global_opening.as_ref()
                        && opening.iter().any(|point| {
                            point.module_role_bitmap() != opening0[0].module_role_bitmap()
                        })
                    {
                        return Err(ChainLogAuditError::Unverified);
                    }
                    Ok(())
                },
                |opening, previous, pair, _block| {
                    if pair.iter().any(|point| {
                        point.native_context().legacy_mapping_value() != U256::ZERO
                            || point.module_position_balances() != [U256::ZERO; 2]
                            || !source::has_minter_role(point.module_role_bitmap())
                    }) {
                        return Err(ChainLogAuditError::Unverified);
                    }
                    for index in 0..2 {
                        if !ModuleOperationPoint::source_identity_continues(
                            &previous[index],
                            &pair[index],
                        ) || pair[index].module_role_bitmap()
                            != opening[index].module_role_bitmap()
                        {
                            return Err(ChainLogAuditError::Unverified);
                        }
                    }
                    Ok(())
                },
            )
            .await
            .map_err(map_trade_error)?;
            if global_opening.is_none() {
                module = Some(chunk.opening[0].native_context().module_proxy());
                global_opening = Some(chunk.opening.clone());
            }
            previous_closing = chunk.block_observations.last().cloned();
            collected.push(chunk);
        }

        let opening = global_opening.ok_or(ChainLogAuditError::Unverified)?;
        let module = module.ok_or(ChainLogAuditError::Unverified)?;
        let evidence = flatten_activity_evidence(&collected, &intervals)?;
        let mut block_observations = Vec::with_capacity(evidence.blocks().len());
        for chunk in &collected {
            block_observations.extend(chunk.block_observations.iter().cloned());
        }
        let scanned = scan_activity(&evidence, &block_observations, owner, ids, module, deadline)?;
        self.finish_collected_activity(
            CollectedActivity {
                evidence,
                intervals: intervals
                    .iter()
                    .map(|anchor| {
                        FifthNativeBinaryActivityIntervalAnchor::new(
                            anchor.from_block,
                            anchor.through_block,
                            anchor.parent_hash.clone(),
                            anchor.end_hash.clone(),
                        )
                    })
                    .collect(),
                policy: INTERVALS_POLICY_VERSION,
                opening,
                block_observations,
            },
            deadline,
            scanned,
        )
        .await
    }

    async fn finish_collected_activity(
        &self,
        collected: CollectedActivity,
        deadline: Instant,
        scanned: ScannedActivity,
    ) -> Result<
        FifthNativeBinaryTwoConditionActivityObservation,
        BoundedFifthNativeBinaryTwoConditionActivityError,
    > {
        let CollectedActivity {
            evidence,
            intervals,
            policy,
            opening,
            block_observations,
        } = collected;
        let boundaries = std::iter::once(&opening[0])
            .chain(block_observations.iter().map(|pair| &pair[0]))
            .collect::<Vec<_>>();
        let assessment = verify_native_trade_controls(
            self,
            &evidence,
            &boundaries,
            &scanned.actors,
            &scanned.candidates,
            deadline,
        )
        .await
        .map_err(map_trade_control_error)?;
        if assessment.refusal.is_some() {
            return Err(ChainLogAuditError::Unverified.into());
        }
        replay_activity(&opening, &block_observations, &evidence, &scanned)?;
        ensure_deadline(deadline)?;
        Ok(FifthNativeBinaryTwoConditionActivityObservation {
            evidence,
            intervals,
            source_policy_version: policy,
            opening,
            block_observations,
            funding: scanned.funding,
            splits: scanned.splits,
            trades: scanned.trades,
            controls: assessment.controls,
        })
    }
}

#[derive(Clone, Copy)]
enum ActivityRef {
    Funding,
    Split(usize),
    Trade(usize),
}

struct LocatedActivity {
    block_number: u64,
    transaction_index: u64,
    activity: ActivityRef,
}

struct ScannedActivity {
    funding: FifthDirectModuleFundingFact,
    splits: Vec<FifthNativeTwoConditionSplitFact>,
    trades: Vec<FifthNativeTwoConditionTradeTransaction>,
    ordered: Vec<LocatedActivity>,
    actors: Vec<(Address, Address)>,
    candidates: Vec<(usize, usize, Address, Vec<Address>)>,
}

fn scan_activity(
    evidence: &ChainReceiptIntervalEvidence,
    points: &[[FifthNativeBinaryModuleOperationBoundary; 2]],
    owner: Address,
    ids: [[B256; 2]; 2],
    module: Address,
    deadline: Instant,
) -> Result<ScannedActivity, ChainLogAuditError> {
    let module_text = format!("{module:#x}");
    let owner_text = format!("{owner:#x}");
    let mut funding = None;
    let mut funding_amount = None;
    let mut splits = Vec::with_capacity(2);
    let mut trades = Vec::new();
    let mut ordered = Vec::new();
    let mut actors = Vec::new();
    let mut candidates = Vec::new();
    let mut split_conditions = [false; 2];

    for (block_index, block) in evidence.blocks().iter().enumerate() {
        if Instant::now() >= deadline {
            return Err(ChainLogAuditError::Unverified);
        }
        for (transaction_index, transaction) in block.transactions().iter().enumerate() {
            if Instant::now() >= deadline {
                return Err(ChainLogAuditError::Unverified);
            }
            if transaction.status() == 0 {
                if !transaction.logs().is_empty() {
                    return Err(ChainLogAuditError::Unverified);
                }
                continue;
            }
            if transaction.status() != 1
                || transaction_has_control_or_upgrade_event(transaction, module)
            {
                return Err(ChainLogAuditError::Unverified);
            }
            let to = transaction.to.as_deref();
            let exchange_call =
                to.is_some_and(|target| target.eq_ignore_ascii_case(EXCHANGE_PROXY));
            let direct_pusd =
                to.is_some_and(|target| target.eq_ignore_ascii_case(source::PUSD_PROXY));
            let direct_module = to.is_some_and(|target| target.eq_ignore_ascii_case(&module_text));
            let direct_pm = to.is_some_and(|target| {
                target.eq_ignore_ascii_case(super::fifth_code_context::POSITION_MANAGER_PROXY)
            });

            if exchange_call {
                if transaction.input.as_deref().is_none_or(|input| {
                    !input.starts_with(&super::fifth_match_orders_call::FIFTH_MATCH_ORDERS_SELECTOR)
                }) {
                    return Err(ChainLogAuditError::Unverified);
                }
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
                    let actor = (routed.submitter, *maker);
                    if !actors.contains(&actor) {
                        actors.push(actor);
                    }
                }
                candidates.push((
                    block_index,
                    transaction_index,
                    routed.submitter,
                    routed.makers,
                ));
                if let Some(fact) = routed.fact {
                    let trade = tag_trade_fact(routed.condition_index, fact);
                    let trade_index = trades.len();
                    let transaction_index = trade.transaction().transaction_index();
                    trades.push(trade);
                    ordered.push(LocatedActivity {
                        block_number: block.block_number(),
                        transaction_index,
                        activity: ActivityRef::Trade(trade_index),
                    });
                }
            } else if direct_pusd {
                if funding.is_some() || !splits.is_empty() {
                    return Err(ChainLogAuditError::Unverified);
                }
                let call = transaction
                    .input
                    .as_deref()
                    .and_then(|input| source::parse_pusd_funding(input, module))
                    .ok_or(ChainLogAuditError::Unverified)?;
                let FundingCall::Pusd(amount) = call else {
                    return Err(ChainLogAuditError::Unverified);
                };
                validate_owner_source(transaction, &owner_text)?;
                if !source::exact_logs(
                    transaction.logs(),
                    &source::expected_funding_logs(&call, owner, module),
                ) {
                    return Err(ChainLogAuditError::Unverified);
                }
                let fact =
                    source::funding_fact(block.block_number(), block, transaction, &call, ids[0]);
                let located = LocatedActivity {
                    block_number: block.block_number(),
                    transaction_index: fact.transaction().transaction_index(),
                    activity: ActivityRef::Funding,
                };
                funding_amount = Some(amount);
                funding = Some(fact);
                ordered.push(located);
            } else if direct_module {
                if funding.is_none() || splits.len() >= 2 {
                    return Err(ChainLogAuditError::Unverified);
                }
                let input = transaction
                    .input
                    .as_deref()
                    .ok_or(ChainLogAuditError::Unverified)?;
                let matching = (0..2)
                    .filter_map(|index| {
                        source::parse_module_call(input, owner, ids[index][0], ids[index])
                            .map(|call| (index, call))
                    })
                    .collect::<Vec<_>>();
                let [(condition_index, call)] = matching.as_slice() else {
                    return Err(ChainLogAuditError::Unverified);
                };
                let ModuleCall::Split { amount } = *call else {
                    return Err(ChainLogAuditError::Unverified);
                };
                let condition_index = *condition_index;
                if split_conditions[condition_index] {
                    return Err(ChainLogAuditError::Unverified);
                }
                validate_owner_source(transaction, &owner_text)?;
                if !source::exact_logs(
                    transaction.logs(),
                    &source::expected_operation_logs(
                        call,
                        None,
                        owner,
                        module,
                        ids[condition_index][0],
                        ids[condition_index],
                    )?,
                ) {
                    return Err(ChainLogAuditError::Unverified);
                }
                let locator = source::locator(block.block_number(), block, transaction);
                let split_index = splits.len();
                splits.push(split_fact(
                    condition_index,
                    ids[condition_index][0],
                    amount,
                    locator,
                ));
                split_conditions[condition_index] = true;
                ordered.push(LocatedActivity {
                    block_number: block.block_number(),
                    transaction_index: transaction.transaction_index(),
                    activity: ActivityRef::Split(split_index),
                });
            } else {
                if direct_pm
                    || has_owner_position_or_cash_movement(transaction, owner)
                    || relevant_unclassified_movement(transaction, owner, module).is_some()
                {
                    return Err(ChainLogAuditError::Unverified);
                }
                for (index, condition_ids) in ids.iter().enumerate() {
                    let version = points[block_index][index]
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
                            return Err(ChainLogAuditError::Unverified);
                        }
                        TransactionClassification::Quiet => {}
                    }
                }
            }
        }
        if source::has_relevant_upgrade_or_role_update(block, &module_text) {
            return Err(ChainLogAuditError::Unverified);
        }
    }

    let funding = funding.ok_or(ChainLogAuditError::Unverified)?;
    let funding_amount = funding_amount.ok_or(ChainLogAuditError::Unverified)?;
    if splits.len() != 2
        || !split_conditions.into_iter().all(|condition| condition)
        || splits
            .iter()
            .try_fold(U256::ZERO, |sum, split| sum.checked_add(split.amount()))
            != Some(funding_amount)
        || ordered.windows(2).any(|pair| {
            pair[0].block_number > pair[1].block_number
                || (pair[0].block_number == pair[1].block_number
                    && pair[0].transaction_index >= pair[1].transaction_index)
        })
    {
        return Err(ChainLogAuditError::Unverified);
    }
    Ok(ScannedActivity {
        funding,
        splits,
        trades,
        ordered,
        actors,
        candidates,
    })
}

fn replay_activity(
    opening: &[FifthNativeBinaryModuleOperationBoundary; 2],
    points: &[[FifthNativeBinaryModuleOperationBoundary; 2]],
    evidence: &ChainReceiptIntervalEvidence,
    activity: &ScannedActivity,
) -> Result<(), ChainLogAuditError> {
    if points.len() != evidence.blocks().len() {
        return Err(ChainLogAuditError::Unverified);
    }
    let mut owner_positions = [
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
    let module_positions = [
        opening[0].module_position_balances()[0],
        opening[0].module_position_balances()[1],
        opening[1].module_position_balances()[0],
        opening[1].module_position_balances()[1],
    ];
    let mut owner_cash = opening[0]
        .native_context()
        .selected_balances()
        .pusd_balance();
    let mut module_cash = opening[0].module_pusd_balance();
    let mut next_activity = 0;
    for (block_index, block) in evidence.blocks().iter().enumerate() {
        while let Some(located) = activity.ordered.get(next_activity) {
            if located.block_number != block.block_number() {
                break;
            }
            match located.activity {
                ActivityRef::Funding => {
                    let amount = activity.funding.amount();
                    owner_cash = owner_cash
                        .checked_sub(amount)
                        .ok_or(ChainLogAuditError::Unverified)?;
                    module_cash = module_cash
                        .checked_add(amount)
                        .ok_or(ChainLogAuditError::Unverified)?;
                }
                ActivityRef::Split(index) => {
                    let split = &activity.splits[index];
                    let offset = split.condition_index() * 2;
                    module_cash = module_cash
                        .checked_sub(split.amount())
                        .ok_or(ChainLogAuditError::Unverified)?;
                    owner_positions[offset] = owner_positions[offset]
                        .checked_add(split.amount())
                        .ok_or(ChainLogAuditError::Unverified)?;
                    owner_positions[offset + 1] = owner_positions[offset + 1]
                        .checked_add(split.amount())
                        .ok_or(ChainLogAuditError::Unverified)?;
                }
                ActivityRef::Trade(index) => {
                    let trade = activity.trades[index].transaction();
                    let offset = activity.trades[index].condition_index() * 2;
                    for side in 0..2 {
                        owner_positions[offset + side] = apply_net_leg(
                            owner_positions[offset + side],
                            trade.owner_position_inflows()[side],
                            trade.owner_position_outflows()[side],
                        )
                        .ok_or(ChainLogAuditError::Unverified)?;
                    }
                    owner_cash = apply_net_leg(
                        owner_cash,
                        trade.owner_pusd_inflow(),
                        trade.owner_pusd_outflow(),
                    )
                    .ok_or(ChainLogAuditError::Unverified)?;
                }
            }
            next_activity += 1;
        }
        let pair = &points[block_index];
        let expected_owner = [
            pair[0]
                .native_context()
                .selected_balances()
                .position_balance_a(),
            pair[0]
                .native_context()
                .selected_balances()
                .position_balance_b(),
            pair[1]
                .native_context()
                .selected_balances()
                .position_balance_a(),
            pair[1]
                .native_context()
                .selected_balances()
                .position_balance_b(),
        ];
        let expected_module = [
            pair[0].module_position_balances()[0],
            pair[0].module_position_balances()[1],
            pair[1].module_position_balances()[0],
            pair[1].module_position_balances()[1],
        ];
        if owner_positions != expected_owner
            || module_positions != expected_module
            || owner_cash != pair[0].native_context().selected_balances().pusd_balance()
            || module_cash != pair[0].module_pusd_balance()
        {
            return Err(ChainLogAuditError::Unverified);
        }
    }
    if next_activity != activity.ordered.len()
        || module_positions != [U256::ZERO; 4]
        || !module_cash.is_zero()
    {
        return Err(ChainLogAuditError::Unverified);
    }
    Ok(())
}

fn same_activity_pair_boundary(
    left: &[FifthNativeBinaryModuleOperationBoundary; 2],
    right: &[FifthNativeBinaryModuleOperationBoundary; 2],
) -> bool {
    same_activity_boundary(&left[0], &right[0])
        && same_activity_boundary(&left[1], &right[1])
        && super::fifth_native_two_condition_trades::same_shared_boundary(&left[0], &left[1])
        && super::fifth_native_two_condition_trades::same_shared_boundary(&right[0], &right[1])
}

fn same_activity_boundary(
    left: &FifthNativeBinaryModuleOperationBoundary,
    right: &FifthNativeBinaryModuleOperationBoundary,
) -> bool {
    let a = left.native_context();
    let b = right.native_context();
    let ab = a.selected_balances();
    let bb = b.selected_balances();
    ModuleOperationPoint::source_identity_continues(left, right)
        && ab.block_number() == bb.block_number()
        && ab.block_hash() == bb.block_hash()
        && ab.state_root() == bb.state_root()
        && a.condition_id() == b.condition_id()
        && a.position_ids() == b.position_ids()
        && a.legacy_mapping_value() == b.legacy_mapping_value()
        && ab.owner() == bb.owner()
        && ab.pusd_balance() == bb.pusd_balance()
        && ab.position_balance_a() == bb.position_balance_a()
        && ab.position_balance_b() == bb.position_balance_b()
        && left.module_position_balances() == right.module_position_balances()
        && left.module_pusd_balance() == right.module_pusd_balance()
        && left.module_role_bitmap() == right.module_role_bitmap()
        && ModuleOperationPoint::result_length(left) == ModuleOperationPoint::result_length(right)
        && ModuleOperationPoint::normalized_numerators(left)
            == ModuleOperationPoint::normalized_numerators(right)
}

fn flatten_activity_evidence(
    chunks: &[TwoConditionEvidence],
    anchors: &[ValidatedActivityInterval],
) -> Result<ChainReceiptIntervalEvidence, ChainLogAuditError> {
    if chunks.is_empty() || chunks.len() != anchors.len() {
        return Err(ChainLogAuditError::Unverified);
    }
    let first_evidence = &chunks[0].evidence;
    let last_evidence = &chunks[chunks.len() - 1].evidence;
    let mut blocks = Vec::new();
    let mut expected_block = anchors[0].from_block;
    let mut expected_parent = anchors[0].parent_hash.as_str();
    let mut seen_locators = BTreeSet::new();
    let mut seen_transactions = BTreeSet::new();
    for (chunk, anchor) in chunks.iter().zip(anchors) {
        let evidence = &chunk.evidence;
        let expected_count = usize::try_from(anchor.through_block - anchor.from_block + 1)
            .map_err(|_| ChainLogAuditError::Unverified)?;
        if evidence.chain_id() != CHAIN_ID
            || evidence.chain_id() != first_evidence.chain_id()
            || evidence.policy_version() != first_evidence.policy_version()
            || evidence.from_block() != anchor.from_block
            || evidence.through_block() != anchor.through_block
            || evidence.expected_parent_hash() != anchor.parent_hash
            || evidence.expected_end_hash() != anchor.end_hash
            || evidence.blocks().len() != expected_count
        {
            return Err(ChainLogAuditError::Unverified);
        }
        for block in evidence.blocks() {
            if block.block_number() != expected_block || block.parent_hash() != expected_parent {
                return Err(ChainLogAuditError::Unverified);
            }
            for transaction in block.transactions() {
                if !seen_locators.insert((block.block_number(), transaction.transaction_index()))
                    || !seen_transactions.insert(transaction.transaction_hash().to_owned())
                {
                    return Err(ChainLogAuditError::Unverified);
                }
            }
            expected_block = expected_block
                .checked_add(1)
                .ok_or(ChainLogAuditError::Unverified)?;
            expected_parent = block.block_hash();
            blocks.push(block.clone());
        }
    }
    if expected_block != anchors.last().unwrap().through_block.saturating_add(1)
        || expected_parent != anchors.last().unwrap().end_hash
        || first_evidence.expected_parent_hash() != anchors[0].parent_hash
        || last_evidence.expected_end_hash() != anchors.last().unwrap().end_hash
    {
        return Err(ChainLogAuditError::Unverified);
    }
    Ok(ChainReceiptIntervalEvidence {
        chain_id: CHAIN_ID,
        from_block: anchors[0].from_block,
        through_block: anchors.last().unwrap().through_block,
        expected_parent_hash: anchors[0].parent_hash.clone(),
        expected_end_hash: anchors.last().unwrap().end_hash.clone(),
        finality_attestation: last_evidence.finality_attestation(),
        policy_version: RECEIPT_INTERVAL_POLICY_VERSION,
        blocks,
    })
}

fn apply_net_leg(balance: U256, inflow: U256, outflow: U256) -> Option<U256> {
    if inflow >= outflow {
        balance.checked_add(inflow - outflow)
    } else {
        balance.checked_sub(outflow - inflow)
    }
}

fn ensure_deadline(
    deadline: Instant,
) -> Result<(), BoundedFifthNativeBinaryTwoConditionActivityError> {
    if Instant::now() >= deadline {
        Err(BoundedFifthNativeBinaryTwoConditionActivityError::Timeout)
    } else {
        Ok(())
    }
}

fn map_trade_error(
    error: BoundedFifthNativeBinaryTwoConditionTradeError,
) -> BoundedFifthNativeBinaryTwoConditionActivityError {
    match error {
        BoundedFifthNativeBinaryTwoConditionTradeError::RequestBudgetExceeded => {
            BoundedFifthNativeBinaryTwoConditionActivityError::RequestBudgetExceeded
        }
        BoundedFifthNativeBinaryTwoConditionTradeError::Timeout => {
            BoundedFifthNativeBinaryTwoConditionActivityError::Timeout
        }
        BoundedFifthNativeBinaryTwoConditionTradeError::Verification(error) => {
            BoundedFifthNativeBinaryTwoConditionActivityError::Verification(error)
        }
    }
}

fn map_trade_control_error(
    error: BoundedFifthNativeBinaryTradeError,
) -> BoundedFifthNativeBinaryTwoConditionActivityError {
    match error {
        BoundedFifthNativeBinaryTradeError::RequestBudgetExceeded => {
            BoundedFifthNativeBinaryTwoConditionActivityError::RequestBudgetExceeded
        }
        BoundedFifthNativeBinaryTradeError::Timeout => {
            BoundedFifthNativeBinaryTwoConditionActivityError::Timeout
        }
        BoundedFifthNativeBinaryTradeError::Verification(error) => {
            BoundedFifthNativeBinaryTwoConditionActivityError::Verification(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::apply_net_leg;
    use alloy_primitives::U256;

    #[test]
    fn net_leg_applies_refund_before_checked_balance_math() {
        assert_eq!(
            apply_net_leg(U256::MAX, U256::from(3_u8), U256::from(4_u8)),
            Some(U256::MAX - U256::ONE)
        );
        assert_eq!(
            apply_net_leg(U256::MAX, U256::from(4_u8), U256::from(3_u8)),
            None
        );
        assert_eq!(
            apply_net_leg(U256::from(3_u8), U256::from(2_u8), U256::from(4_u8)),
            Some(U256::ONE)
        );
    }
}
