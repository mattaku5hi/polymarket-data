//! One shared owner/module pUSD deposit split across two native conditions.

use super::fifth_direct_module_operations::{
    self as source, FifthDirectModuleFundingFact, FifthDirectModuleTransactionLocator, FundingCall,
    ModuleCall, ModuleOperationPoint,
};
use super::fifth_native_binary::is_canonical_native_binary_condition;
use super::fifth_native_binary_trades::transaction_has_control_or_upgrade_event;
use super::fifth_native_module_operations::FifthNativeBinaryModuleOperationBoundary;
use super::fifth_native_two_condition_trades::{
    BoundedFifthNativeBinaryTwoConditionTradeError, TwoConditionAnchor, TwoConditionEvidence,
    collect_two_condition_evidence,
};
use super::{
    ChainLogAuditError, ChainLogVerifier, ChainReceiptIntervalEvidence, MAX_BLOCKS,
    TransactionRequestBudget, parse_fixed_b256, validate_hex,
};
use alloy_primitives::{Address, B256, U256};
use std::time::Duration;
use thiserror::Error;
use tokio::time::Instant;

const POLICY_VERSION: &str = "fifth-native-binary-two-condition-funded-splits/1";

pub const FIFTH_NATIVE_TWO_CONDITION_SPLIT_POLICY_VERSION: &str = POLICY_VERSION;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedFifthNativeBinaryTwoConditionSplitError {
    #[error("two-condition native split RPC request budget exhausted")]
    RequestBudgetExceeded,
    #[error("two-condition native split exceeded its total deadline")]
    Timeout,
    #[error(transparent)]
    Verification(#[from] ChainLogAuditError),
}

/// A source-matched split tagged with the one selected condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthNativeTwoConditionSplitFact {
    condition_index: usize,
    condition_id: B256,
    amount: U256,
    operation_transaction: FifthDirectModuleTransactionLocator,
}

impl FifthNativeTwoConditionSplitFact {
    #[must_use]
    pub const fn condition_index(&self) -> usize {
        self.condition_index
    }

    #[must_use]
    pub const fn condition_id(&self) -> B256 {
        self.condition_id
    }

    #[must_use]
    pub const fn amount(&self) -> U256 {
        self.amount
    }

    #[must_use]
    pub const fn operation_transaction(
        &self,
    ) -> &super::fifth_direct_module_operations::FifthDirectModuleTransactionLocator {
        &self.operation_transaction
    }
}

pub(super) fn split_fact(
    condition_index: usize,
    condition_id: B256,
    amount: U256,
    operation_transaction: FifthDirectModuleTransactionLocator,
) -> FifthNativeTwoConditionSplitFact {
    FifthNativeTwoConditionSplitFact {
        condition_index,
        condition_id,
        amount,
        operation_transaction,
    }
}

/// Complete rooted evidence and source facts for one owner-funded two-condition interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthNativeBinaryTwoConditionSplitObservation {
    evidence: ChainReceiptIntervalEvidence,
    opening: [FifthNativeBinaryModuleOperationBoundary; 2],
    block_observations: Vec<[FifthNativeBinaryModuleOperationBoundary; 2]>,
    funding: FifthDirectModuleFundingFact,
    splits: Vec<FifthNativeTwoConditionSplitFact>,
}

impl FifthNativeBinaryTwoConditionSplitObservation {
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
    pub const fn source_policy_version(&self) -> &'static str {
        POLICY_VERSION
    }
}

impl ChainLogVerifier {
    #[allow(clippy::too_many_arguments)]
    pub async fn verify_fifth_native_binary_two_condition_splits_bounded(
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
        FifthNativeBinaryTwoConditionSplitObservation,
        BoundedFifthNativeBinaryTwoConditionSplitError,
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

        let owner = Address::from_slice(&owner_bytes);
        let ids = condition_ids.map(native_position_ids);
        let deadline = Instant::now()
            .checked_add(total_timeout)
            .ok_or(ChainLogAuditError::InvalidInput)?;
        let budget = TransactionRequestBudget::new(max_requests);
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let scoped = self.with_request_budget(budget.inner());
        let verification = scoped.verify_two_condition_splits_inner(
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
                Err(BoundedFifthNativeBinaryTwoConditionSplitError::RequestBudgetExceeded)
            }
            () = &mut deadline_wait => {
                if budget.is_exhausted() {
                    Err(BoundedFifthNativeBinaryTwoConditionSplitError::RequestBudgetExceeded)
                } else {
                    Err(BoundedFifthNativeBinaryTwoConditionSplitError::Timeout)
                }
            }
            result = &mut verification => {
                if budget.is_exhausted() {
                    Err(BoundedFifthNativeBinaryTwoConditionSplitError::RequestBudgetExceeded)
                } else if Instant::now() >= deadline {
                    Err(BoundedFifthNativeBinaryTwoConditionSplitError::Timeout)
                } else {
                    result
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn verify_two_condition_splits_inner(
        &self,
        owner: Address,
        ids: [[B256; 2]; 2],
        from_block: u64,
        through_block: u64,
        parent_hash: &str,
        end_hash: &str,
        deadline: Instant,
    ) -> Result<
        FifthNativeBinaryTwoConditionSplitObservation,
        BoundedFifthNativeBinaryTwoConditionSplitError,
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
        .map_err(map_pair_error)?;
        let TwoConditionEvidence {
            evidence,
            opening,
            block_observations: points,
        } = collected;
        ensure_deadline(deadline)?;
        let module = opening[0].native_context().module_proxy();
        let (funding, splits) =
            scan_and_replay(&evidence, &opening, &points, owner, ids, module, deadline)?;
        ensure_deadline(deadline)?;
        Ok(FifthNativeBinaryTwoConditionSplitObservation {
            evidence,
            opening,
            block_observations: points,
            funding,
            splits,
        })
    }
}

fn scan_and_replay(
    evidence: &ChainReceiptIntervalEvidence,
    opening: &[FifthNativeBinaryModuleOperationBoundary; 2],
    points: &[[FifthNativeBinaryModuleOperationBoundary; 2]],
    owner: Address,
    ids: [[B256; 2]; 2],
    module: Address,
    deadline: Instant,
) -> Result<
    (
        FifthDirectModuleFundingFact,
        Vec<FifthNativeTwoConditionSplitFact>,
    ),
    ChainLogAuditError,
> {
    if points.len() != evidence.blocks().len() {
        return Err(ChainLogAuditError::Unverified);
    }
    let module_text = format!("{module:#x}");
    let owner_text = format!("{owner:#x}");
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
    let mut owner_cash = opening[0]
        .native_context()
        .selected_balances()
        .pusd_balance();
    let module_positions = [
        opening[0].module_position_balances()[0],
        opening[0].module_position_balances()[1],
        opening[1].module_position_balances()[0],
        opening[1].module_position_balances()[1],
    ];
    let mut module_cash = opening[0].module_pusd_balance();
    let mut funding_call = None;
    let mut funding_fact = None;
    let mut split_facts = Vec::with_capacity(2);
    let mut seen_conditions = [false; 2];

    for (block_index, block) in evidence.blocks().iter().enumerate() {
        if Instant::now() >= deadline {
            return Err(ChainLogAuditError::Unverified);
        }
        for transaction in block.transactions() {
            if Instant::now() >= deadline {
                return Err(ChainLogAuditError::Unverified);
            }
            if transaction.status() == 0 {
                if !transaction.logs().is_empty() {
                    return Err(ChainLogAuditError::Unverified);
                }
                continue;
            }
            if transaction.status() != 1 {
                return Err(ChainLogAuditError::Unverified);
            }
            if transaction_has_control_or_upgrade_event(transaction, module)
                || transaction.to.as_deref().is_some_and(|to| {
                    to.eq_ignore_ascii_case(super::fifth_code_context::EXCHANGE_PROXY)
                })
            {
                return Err(ChainLogAuditError::Unverified);
            }

            let to = transaction.to.as_deref();
            let handled = if to.is_some_and(|to| to.eq_ignore_ascii_case(source::PUSD_PROXY)) {
                if funding_fact.is_some() || !split_facts.is_empty() {
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
                validate_owner_source(transaction, owner_text.as_str())?;
                if !source::exact_logs(
                    transaction.logs(),
                    &source::expected_funding_logs(&call, owner, module),
                ) {
                    return Err(ChainLogAuditError::Unverified);
                }
                owner_cash = owner_cash
                    .checked_sub(amount)
                    .ok_or(ChainLogAuditError::Unverified)?;
                module_cash = module_cash
                    .checked_add(amount)
                    .ok_or(ChainLogAuditError::Unverified)?;
                let fact =
                    source::funding_fact(block.block_number(), block, transaction, &call, ids[0]);
                funding_call = Some(call);
                funding_fact = Some(fact);
                true
            } else if to.is_some_and(|to| to.eq_ignore_ascii_case(&module_text)) {
                if funding_fact.is_none() || split_facts.len() >= 2 {
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
                if seen_conditions[condition_index] {
                    return Err(ChainLogAuditError::Unverified);
                }
                validate_owner_source(transaction, owner_text.as_str())?;
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
                let offset = condition_index * 2;
                module_cash = module_cash
                    .checked_sub(amount)
                    .ok_or(ChainLogAuditError::Unverified)?;
                owner_positions[offset] = owner_positions[offset]
                    .checked_add(amount)
                    .ok_or(ChainLogAuditError::Unverified)?;
                owner_positions[offset + 1] = owner_positions[offset + 1]
                    .checked_add(amount)
                    .ok_or(ChainLogAuditError::Unverified)?;
                let operation_transaction =
                    source::locator(block.block_number(), block, transaction);
                split_facts.push(split_fact(
                    condition_index,
                    ids[condition_index][0],
                    amount,
                    operation_transaction,
                ));
                seen_conditions[condition_index] = true;
                true
            } else {
                false
            };

            if !handled && relevant_unclassified_movement(transaction, owner, module).is_some() {
                return Err(ChainLogAuditError::Unverified);
            }
            if to.is_some_and(|to| {
                to.eq_ignore_ascii_case(super::fifth_code_context::POSITION_MANAGER_PROXY)
            }) || source::has_relevant_upgrade_or_role_update(block, &module_text)
            {
                return Err(ChainLogAuditError::Unverified);
            }
        }

        let point = &points[block_index];
        let expected_owner = [
            point[0]
                .native_context()
                .selected_balances()
                .position_balance_a(),
            point[0]
                .native_context()
                .selected_balances()
                .position_balance_b(),
            point[1]
                .native_context()
                .selected_balances()
                .position_balance_a(),
            point[1]
                .native_context()
                .selected_balances()
                .position_balance_b(),
        ];
        let expected_module = [
            point[0].module_position_balances()[0],
            point[0].module_position_balances()[1],
            point[1].module_position_balances()[0],
            point[1].module_position_balances()[1],
        ];
        if owner_positions != expected_owner
            || module_positions != expected_module
            || owner_cash != point[0].native_context().selected_balances().pusd_balance()
            || module_cash != point[0].module_pusd_balance()
        {
            return Err(ChainLogAuditError::Unverified);
        }
    }

    let funding = funding_fact.ok_or(ChainLogAuditError::Unverified)?;
    let FundingCall::Pusd(funding_amount) = funding_call.ok_or(ChainLogAuditError::Unverified)?
    else {
        return Err(ChainLogAuditError::Unverified);
    };
    if split_facts.len() != 2
        || !seen_conditions.into_iter().all(|seen| seen)
        || split_facts
            .iter()
            .try_fold(U256::ZERO, |sum, split| sum.checked_add(split.amount()))
            != Some(funding_amount)
        || module_positions != [U256::ZERO; 4]
        || !module_cash.is_zero()
    {
        return Err(ChainLogAuditError::Unverified);
    }
    Ok((funding, split_facts))
}

pub(super) fn validate_owner_source(
    transaction: &super::ChainReceiptIntervalTransaction,
    owner: &str,
) -> Result<(), ChainLogAuditError> {
    if transaction
        .recovered_from
        .as_deref()
        .is_none_or(|sender| !sender.eq_ignore_ascii_case(owner))
        || !transaction.value.is_zero()
        || !transaction.replay_protected_sender
    {
        return Err(ChainLogAuditError::Unverified);
    }
    Ok(())
}

pub(super) fn relevant_unclassified_movement(
    transaction: &super::ChainReceiptIntervalTransaction,
    owner: Address,
    module: Address,
) -> Option<()> {
    transaction
        .movement_observations()
        .iter()
        .find_map(|movement| {
            let recognized = movement.emitter().eq_ignore_ascii_case(source::PUSD_PROXY)
                || movement
                    .emitter()
                    .eq_ignore_ascii_case(super::fifth_code_context::POSITION_MANAGER_PROXY);
            if !recognized {
                return None;
            }
            match movement.status() {
                super::MovementObservationStatus::Unsupported(_) => Some(()),
                super::MovementObservationStatus::Decoded(
                    super::ObservedAssetMovement::Erc20Transfer { from, to, .. }
                    | super::ObservedAssetMovement::Erc1155TransferSingle { from, to, .. }
                    | super::ObservedAssetMovement::Erc1155TransferBatch { from, to, .. },
                ) if [owner, module].iter().any(|address| {
                    let address = format!("{address:#x}");
                    from.eq_ignore_ascii_case(&address) || to.eq_ignore_ascii_case(&address)
                }) =>
                {
                    Some(())
                }
                _ => None,
            }
        })
}

fn native_position_ids(condition: B256) -> [B256; 2] {
    let mut opposite = condition.0;
    opposite[31] = 1;
    [condition, B256::from(opposite)]
}

fn map_pair_error(
    error: BoundedFifthNativeBinaryTwoConditionTradeError,
) -> BoundedFifthNativeBinaryTwoConditionSplitError {
    match error {
        BoundedFifthNativeBinaryTwoConditionTradeError::RequestBudgetExceeded => {
            BoundedFifthNativeBinaryTwoConditionSplitError::RequestBudgetExceeded
        }
        BoundedFifthNativeBinaryTwoConditionTradeError::Timeout => {
            BoundedFifthNativeBinaryTwoConditionSplitError::Timeout
        }
        BoundedFifthNativeBinaryTwoConditionTradeError::Verification(error) => {
            BoundedFifthNativeBinaryTwoConditionSplitError::Verification(error)
        }
    }
}

fn ensure_deadline(
    deadline: Instant,
) -> Result<(), BoundedFifthNativeBinaryTwoConditionSplitError> {
    if Instant::now() >= deadline {
        Err(BoundedFifthNativeBinaryTwoConditionSplitError::Timeout)
    } else {
        Ok(())
    }
}
