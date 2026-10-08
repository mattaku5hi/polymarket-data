//! One rooted owner/module activity replay across two native conditions.

use super::fifth_binary_trades::{TransactionClassification, classify_transaction};
use super::fifth_code_context::EXCHANGE_PROXY;
use super::fifth_direct_module_operations::{
    self as source, FifthDirectModuleFundingFact, FundingCall, ModuleCall, ModuleOperationPoint,
};
use super::fifth_exchange_controls::FifthExchangeControlsObservation;
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
    ChainLogAuditError, ChainLogVerifier, ChainReceiptIntervalEvidence, MAX_BLOCKS,
    TransactionRequestBudget, parse_fixed_b256, validate_hex,
};
use alloy_primitives::{Address, B256, U256};
use std::time::Duration;
use thiserror::Error;
use tokio::time::Instant;

const POLICY_VERSION: &str =
    "fifth-native-binary-two-condition-activity-source-and-shared-pusd-replay/1";

pub const FIFTH_NATIVE_TWO_CONDITION_ACTIVITY_POLICY_VERSION: &str = POLICY_VERSION;

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
        POLICY_VERSION
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
                for index in 0..2 {
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
                        ids[index],
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
