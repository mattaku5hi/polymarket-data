//! One rooted replay of native Binary owner funding, module operations and trades.

use super::fifth_binary_trades::FifthTradeTransactionFact;
use super::fifth_direct_module_operations::{
    FifthDirectModuleOperationFact, FifthDirectModuleOperationsAsset,
    FifthDirectModuleOperationsHolder, FifthLegacyBinaryModuleOperationsStatus,
    FifthLegacyBinaryModuleOperationsUnavailableReason, classify_module_interval_with_trades,
    has_minter_role,
};
use super::fifth_exchange_controls::FifthExchangeControlsObservation;
use super::fifth_native_binary::is_canonical_native_binary_condition;
use super::fifth_native_binary_trades::{
    BoundedFifthNativeBinaryTradeError, FifthNativeBinaryTradeUnavailableReason,
    module_identity_continues, verify_native_trade_sources_and_controls,
};
use super::fifth_native_module_operations::{
    BoundedFifthNativeBinaryModuleOperationsError, FifthNativeBinaryModuleOperationBoundary,
};
use super::{
    ChainLogAuditError, ChainLogVerifier, ChainReceiptIntervalEvidence, MAX_BLOCKS,
    TransactionRequestBudget, validate_hex,
};
use alloy_primitives::{Address, B256, U256};
use std::time::Duration;
use thiserror::Error;
use tokio::time::Instant;

pub const FIFTH_NATIVE_BINARY_ACTIVITY_POLICY_VERSION: &str =
    "fifth-native-binary-module-and-trade-source-attribution/1";

const MAX_ACTIVITY_SEGMENTS: usize = 16;
const MAX_ACTIVITY_SEGMENT_BLOCKS: u64 = 16;
const MAX_ACTIVITY_BATCH_BLOCKS: u64 = 256;

/// Caller-supplied anchors for one contiguous native activity interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthNativeBinaryActivityIntervalAnchor {
    pub from_block: u64,
    pub through_block: u64,
    pub expected_parent_hash: String,
    pub expected_end_hash: String,
}

impl FifthNativeBinaryActivityIntervalAnchor {
    #[must_use]
    pub fn new(
        from_block: u64,
        through_block: u64,
        expected_parent_hash: impl Into<String>,
        expected_end_hash: impl Into<String>,
    ) -> Self {
        Self {
            from_block,
            through_block,
            expected_parent_hash: expected_parent_hash.into(),
            expected_end_hash: expected_end_hash.into(),
        }
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
    pub fn expected_parent_hash(&self) -> &str {
        &self.expected_parent_hash
    }

    #[must_use]
    pub fn expected_end_hash(&self) -> &str {
        &self.expected_end_hash
    }
}

struct ValidatedActivityAnchor {
    from_block: u64,
    through_block: u64,
    parent_hash: String,
    end_hash: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedFifthNativeBinaryActivityError {
    #[error("fifth native binary activity RPC request budget exhausted")]
    RequestBudgetExceeded,
    #[error("fifth native binary activity exceeded its total deadline")]
    Timeout,
    #[error("fifth native binary activity segment {segment_index} was not matched")]
    SegmentUnavailable { segment_index: usize },
    #[error("fifth native binary activity boundary before segment {segment_index} did not match")]
    BoundaryMismatch { segment_index: usize },
    #[error(transparent)]
    Verification(#[from] ChainLogAuditError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthNativeBinaryActivityUnavailableReason {
    NativeBoundaryMismatch,
    ModuleStateUnavailable,
    Trade(FifthNativeBinaryTradeUnavailableReason),
    Module(FifthLegacyBinaryModuleOperationsUnavailableReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FifthNativeBinaryActivityStatus {
    Matched,
    Mismatch {
        block_number: u64,
        holder: FifthDirectModuleOperationsHolder,
        asset: FifthDirectModuleOperationsAsset,
        authenticated_balance: U256,
        reconstructed_balance: U256,
    },
    Unavailable {
        block_number: Option<u64>,
        transaction_hash: Option<String>,
        reason: FifthNativeBinaryActivityUnavailableReason,
    },
}

/// Sealed source facts and a single owner/module balance replay, without cost basis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthNativeBinaryActivityObservation {
    evidence: ChainReceiptIntervalEvidence,
    opening: FifthNativeBinaryModuleOperationBoundary,
    block_observations: Vec<FifthNativeBinaryModuleOperationBoundary>,
    status: FifthNativeBinaryActivityStatus,
    transactions: Vec<FifthTradeTransactionFact>,
    module_operations: Vec<FifthDirectModuleOperationFact>,
    controls: Vec<FifthExchangeControlsObservation>,
}

impl FifthNativeBinaryActivityObservation {
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
    pub const fn status(&self) -> &FifthNativeBinaryActivityStatus {
        &self.status
    }

    #[must_use]
    pub fn transactions(&self) -> &[FifthTradeTransactionFact] {
        &self.transactions
    }

    #[must_use]
    pub fn module_operations(&self) -> &[FifthDirectModuleOperationFact] {
        &self.module_operations
    }

    #[must_use]
    pub fn controls(&self) -> &[FifthExchangeControlsObservation] {
        &self.controls
    }

    #[must_use]
    pub const fn source_policy_version(&self) -> &'static str {
        FIFTH_NATIVE_BINARY_ACTIVITY_POLICY_VERSION
    }
}

impl ChainLogVerifier {
    /// Verifies adjacent native activity intervals under one request budget and deadline.
    pub async fn verify_fifth_native_binary_activity_intervals_bounded(
        &self,
        owner: &str,
        condition_id: &str,
        intervals: &[FifthNativeBinaryActivityIntervalAnchor],
        max_requests: usize,
        total_timeout: Duration,
    ) -> Result<Vec<FifthNativeBinaryActivityObservation>, BoundedFifthNativeBinaryActivityError>
    {
        let owner = validate_hex(owner, 20).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let owner_bytes = hex::decode(&owner[2..]).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let condition =
            super::parse_fixed_b256(condition_id).map_err(|_| ChainLogAuditError::InvalidInput)?;
        if owner_bytes.iter().all(|byte| *byte == 0)
            || !is_canonical_native_binary_condition(condition)
            || !(1..=MAX_ACTIVITY_SEGMENTS).contains(&intervals.len())
            || max_requests == 0
            || total_timeout.is_zero()
        {
            return Err(ChainLogAuditError::InvalidInput.into());
        }

        let mut validated: Vec<ValidatedActivityAnchor> = Vec::with_capacity(intervals.len());
        let mut aggregate_blocks = 0_u64;
        for anchor in intervals {
            if anchor.from_block == 0
                || anchor.from_block > anchor.through_block
                || anchor.through_block - anchor.from_block >= MAX_ACTIVITY_SEGMENT_BLOCKS
            {
                return Err(ChainLogAuditError::InvalidInput.into());
            }
            let parent_hash = validate_hex(&anchor.expected_parent_hash, 32)
                .map_err(|_| ChainLogAuditError::InvalidInput)?;
            let end_hash = validate_hex(&anchor.expected_end_hash, 32)
                .map_err(|_| ChainLogAuditError::InvalidInput)?;
            let segment_blocks = anchor
                .through_block
                .checked_sub(anchor.from_block)
                .and_then(|count| count.checked_add(1))
                .ok_or(ChainLogAuditError::InvalidInput)?;
            aggregate_blocks = aggregate_blocks
                .checked_add(segment_blocks)
                .ok_or(ChainLogAuditError::InvalidInput)?;
            if aggregate_blocks > MAX_ACTIVITY_BATCH_BLOCKS {
                return Err(ChainLogAuditError::InvalidInput.into());
            }
            if let Some(previous) = validated.last() {
                if previous.through_block.checked_add(1) != Some(anchor.from_block)
                    || previous.end_hash != parent_hash
                {
                    return Err(ChainLogAuditError::InvalidInput.into());
                }
            }
            validated.push(ValidatedActivityAnchor {
                from_block: anchor.from_block,
                through_block: anchor.through_block,
                parent_hash,
                end_hash,
            });
        }

        let owner_address = Address::from_slice(&owner_bytes);
        let mut complement = condition.0;
        complement[31] = 1;
        let ids = [condition, B256::from(complement)];
        let deadline = Instant::now()
            .checked_add(total_timeout)
            .ok_or(ChainLogAuditError::InvalidInput)?;
        let budget = TransactionRequestBudget::new(max_requests);
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let scoped = self.with_request_budget(budget.inner());
        let verification = async {
            let mut reports: Vec<FifthNativeBinaryActivityObservation> =
                Vec::with_capacity(validated.len());
            for (index, anchor) in validated.iter().enumerate() {
                let report = scoped
                    .verify_native_binary_activity_inner(
                        owner.clone(),
                        owner_address,
                        condition,
                        ids,
                        anchor.from_block,
                        anchor.through_block,
                        &anchor.parent_hash,
                        &anchor.end_hash,
                        deadline,
                    )
                    .await?;
                ensure_deadline(deadline)?;
                if report.status() != &FifthNativeBinaryActivityStatus::Matched
                    || report.opening().module_position_balances() != [U256::ZERO; 2]
                    || !report.opening().module_pusd_balance().is_zero()
                    || report.block_observations().last().is_none_or(|closing| {
                        closing.module_position_balances() != [U256::ZERO; 2]
                            || !closing.module_pusd_balance().is_zero()
                    })
                {
                    return Err(BoundedFifthNativeBinaryActivityError::SegmentUnavailable {
                        segment_index: index,
                    });
                }
                if let Some(previous) = reports.last()
                    && previous.block_observations().last() != Some(report.opening())
                {
                    return Err(BoundedFifthNativeBinaryActivityError::BoundaryMismatch {
                        segment_index: index,
                    });
                }
                reports.push(report);
            }
            Ok(reports)
        };
        tokio::pin!(verification);
        let deadline_wait = tokio::time::sleep_until(deadline);
        tokio::pin!(deadline_wait);
        tokio::select! {
            biased;
            _ = exhaustion.wait_for(|exhausted| *exhausted) => {
                Err(BoundedFifthNativeBinaryActivityError::RequestBudgetExceeded)
            }
            () = &mut deadline_wait => {
                if budget.is_exhausted() {
                    Err(BoundedFifthNativeBinaryActivityError::RequestBudgetExceeded)
                } else {
                    Err(BoundedFifthNativeBinaryActivityError::Timeout)
                }
            }
            result = &mut verification => {
                if budget.is_exhausted() {
                    Err(BoundedFifthNativeBinaryActivityError::RequestBudgetExceeded)
                } else if Instant::now() >= deadline {
                    Err(BoundedFifthNativeBinaryActivityError::Timeout)
                } else {
                    result
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn verify_fifth_native_binary_activity_interval_bounded(
        &self,
        owner: &str,
        condition_id: &str,
        from_block: u64,
        through_block: u64,
        expected_parent_hash: &str,
        expected_end_hash: &str,
        max_requests: usize,
        total_timeout: Duration,
    ) -> Result<FifthNativeBinaryActivityObservation, BoundedFifthNativeBinaryActivityError> {
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
        let mut complement = condition.0;
        complement[31] = 1;
        let ids = [condition, B256::from(complement)];
        let deadline = Instant::now()
            .checked_add(total_timeout)
            .ok_or(ChainLogAuditError::InvalidInput)?;
        let budget = TransactionRequestBudget::new(max_requests);
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let scoped = self.with_request_budget(budget.inner());
        let verification = scoped.verify_native_binary_activity_inner(
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
                Err(BoundedFifthNativeBinaryActivityError::RequestBudgetExceeded)
            }
            () = &mut deadline_wait => {
                if budget.is_exhausted() {
                    Err(BoundedFifthNativeBinaryActivityError::RequestBudgetExceeded)
                } else {
                    Err(BoundedFifthNativeBinaryActivityError::Timeout)
                }
            }
            result = &mut verification => {
                if budget.is_exhausted() {
                    Err(BoundedFifthNativeBinaryActivityError::RequestBudgetExceeded)
                } else if Instant::now() >= deadline {
                    Err(BoundedFifthNativeBinaryActivityError::Timeout)
                } else {
                    result
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn verify_native_binary_activity_inner(
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
    ) -> Result<FifthNativeBinaryActivityObservation, BoundedFifthNativeBinaryActivityError> {
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
            .map_err(map_module_error)?;
        let (evidence, opening, points) = interval.into_parts();
        let mut report = FifthNativeBinaryActivityObservation {
            evidence,
            opening,
            block_observations: points,
            status: FifthNativeBinaryActivityStatus::Matched,
            transactions: Vec::new(),
            module_operations: Vec::new(),
            controls: Vec::new(),
        };
        if report.block_observations.len() != report.evidence.blocks().len()
            || !module_identity_continues(&report.opening, &report.block_observations)
        {
            report.status = refused(
                None,
                None,
                FifthNativeBinaryActivityUnavailableReason::NativeBoundaryMismatch,
            );
            return Ok(report);
        }
        if report.opening.module_position_balances() != [U256::ZERO; 2]
            || !report.opening.module_pusd_balance().is_zero()
            || !has_minter_role(report.opening.module_role_bitmap())
        {
            report.status = refused(
                Some(from_block - 1),
                None,
                FifthNativeBinaryActivityUnavailableReason::ModuleStateUnavailable,
            );
            return Ok(report);
        }
        if std::iter::once(&report.opening)
            .chain(report.block_observations.iter())
            .any(|boundary| {
                let native = boundary.native_context();
                native.condition_id() != condition
                    || native.position_ids() != ids
                    || !native.legacy_mapping_value().is_zero()
            })
        {
            report.status = refused(
                None,
                None,
                FifthNativeBinaryActivityUnavailableReason::NativeBoundaryMismatch,
            );
            return Ok(report);
        }
        let sources = verify_native_trade_sources_and_controls(
            self,
            &report.evidence,
            &report.opening,
            &report.block_observations,
            owner_address,
            ids,
            true,
            deadline,
        )
        .await
        .map_err(map_trade_error)?;
        report.controls = sources.controls;
        if let Some(failure) = sources.refusal {
            report.status = refused(
                failure.block_number,
                failure.transaction_hash,
                FifthNativeBinaryActivityUnavailableReason::Trade(failure.reason),
            );
            return Ok(report);
        }
        ensure_deadline(deadline)?;
        let (status, operations) = classify_module_interval_with_trades(
            &report.evidence,
            &owner,
            &report.opening,
            &report.block_observations,
            &sources.facts,
        )?;
        ensure_deadline(deadline)?;
        report.status = match status {
            FifthLegacyBinaryModuleOperationsStatus::Matched => {
                report.transactions = sources.facts;
                report.module_operations = operations;
                FifthNativeBinaryActivityStatus::Matched
            }
            FifthLegacyBinaryModuleOperationsStatus::Mismatch {
                block_number,
                holder,
                asset,
                authenticated_balance,
                reconstructed_balance,
            } => FifthNativeBinaryActivityStatus::Mismatch {
                block_number,
                holder,
                asset,
                authenticated_balance,
                reconstructed_balance,
            },
            FifthLegacyBinaryModuleOperationsStatus::Unavailable {
                block_number,
                transaction_hash,
                reason,
            } => refused(
                block_number,
                transaction_hash,
                FifthNativeBinaryActivityUnavailableReason::Module(reason),
            ),
        };
        Ok(report)
    }
}

fn refused(
    block_number: Option<u64>,
    transaction_hash: Option<String>,
    reason: FifthNativeBinaryActivityUnavailableReason,
) -> FifthNativeBinaryActivityStatus {
    FifthNativeBinaryActivityStatus::Unavailable {
        block_number,
        transaction_hash,
        reason,
    }
}

fn ensure_deadline(deadline: Instant) -> Result<(), BoundedFifthNativeBinaryActivityError> {
    if Instant::now() >= deadline {
        Err(BoundedFifthNativeBinaryActivityError::Timeout)
    } else {
        Ok(())
    }
}

fn map_module_error(
    error: BoundedFifthNativeBinaryModuleOperationsError,
) -> BoundedFifthNativeBinaryActivityError {
    match error {
        BoundedFifthNativeBinaryModuleOperationsError::RequestBudgetExceeded => {
            BoundedFifthNativeBinaryActivityError::RequestBudgetExceeded
        }
        BoundedFifthNativeBinaryModuleOperationsError::Timeout => {
            BoundedFifthNativeBinaryActivityError::Timeout
        }
        BoundedFifthNativeBinaryModuleOperationsError::Verification(error) => {
            BoundedFifthNativeBinaryActivityError::Verification(error)
        }
    }
}

fn map_trade_error(
    error: BoundedFifthNativeBinaryTradeError,
) -> BoundedFifthNativeBinaryActivityError {
    match error {
        BoundedFifthNativeBinaryTradeError::RequestBudgetExceeded => {
            BoundedFifthNativeBinaryActivityError::RequestBudgetExceeded
        }
        BoundedFifthNativeBinaryTradeError::Timeout => {
            BoundedFifthNativeBinaryActivityError::Timeout
        }
        BoundedFifthNativeBinaryTradeError::Verification(error) => {
            BoundedFifthNativeBinaryActivityError::Verification(error)
        }
    }
}
