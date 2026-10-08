//! Source-ordered direct funding and operations for a native Binary condition.

use super::fifth_direct_module_operations::{
    BoundedFifthLegacyBinaryModuleOperationsError, FifthDirectModuleOperationFact,
    FifthDirectModuleOperationsAsset, FifthDirectModuleOperationsHolder,
    FifthLegacyBinaryModuleOperationsStatus, FifthLegacyBinaryModuleOperationsUnavailableReason,
    ModuleOperationPoint,
};
use super::fifth_native_binary::{BoundedFifthNativeBinaryError, FifthNativeBinaryObservation};
use super::{
    ChainLogAuditError, ChainLogVerifier, ChainReceiptIntervalEvidence, MAX_BLOCKS,
    TransactionRequestBudget, fifth_direct_module_operations,
};
use alloy_primitives::{Address, B256, U256};
use std::time::Duration;
use thiserror::Error;
use tokio::time::Instant;

const POLICY_VERSION: &str = "fifth-native-binary-module-operations/1";

pub const FIFTH_NATIVE_BINARY_MODULE_OPERATIONS_POLICY_VERSION: &str = POLICY_VERSION;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedFifthNativeBinaryModuleOperationsError {
    #[error("fifth native Binary module operation RPC request budget exhausted")]
    RequestBudgetExceeded,
    #[error("fifth native Binary module operation exceeded its total deadline")]
    Timeout,
    #[error(transparent)]
    Verification(#[from] ChainLogAuditError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FifthNativeBinaryModuleOperationsStatus {
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
        reason: FifthLegacyBinaryModuleOperationsUnavailableReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthNativeBinaryModuleOperationBoundary {
    native_context: FifthNativeBinaryObservation,
    module_position_balances: [U256; 2],
    module_pusd_balance: U256,
    module_role_bitmap: U256,
}

impl FifthNativeBinaryModuleOperationBoundary {
    #[must_use]
    pub const fn native_context(&self) -> &FifthNativeBinaryObservation {
        &self.native_context
    }
    #[must_use]
    pub const fn module_position_balances(&self) -> [U256; 2] {
        self.module_position_balances
    }
    #[must_use]
    pub const fn module_pusd_balance(&self) -> U256 {
        self.module_pusd_balance
    }
    #[must_use]
    pub const fn module_role_bitmap(&self) -> U256 {
        self.module_role_bitmap
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FifthNativeModuleIntervalEvidence {
    evidence: ChainReceiptIntervalEvidence,
    opening: FifthNativeBinaryModuleOperationBoundary,
    block_observations: Vec<FifthNativeBinaryModuleOperationBoundary>,
}

impl FifthNativeModuleIntervalEvidence {
    #[must_use]
    pub(super) fn into_parts(
        self,
    ) -> (
        ChainReceiptIntervalEvidence,
        FifthNativeBinaryModuleOperationBoundary,
        Vec<FifthNativeBinaryModuleOperationBoundary>,
    ) {
        (self.evidence, self.opening, self.block_observations)
    }
}

impl ModuleOperationPoint for FifthNativeBinaryModuleOperationBoundary {
    fn selected_balances(&self) -> &super::FifthSelectedBalancesObservation {
        self.native_context.selected_balances()
    }
    fn module_proxy(&self) -> Address {
        self.native_context.module_proxy()
    }
    fn condition_id(&self) -> B256 {
        self.native_context.condition_id()
    }
    fn position_ids(&self) -> [B256; 2] {
        self.native_context.position_ids()
    }
    fn module_position_balances(&self) -> [U256; 2] {
        self.module_position_balances
    }
    fn module_pusd_balance(&self) -> U256 {
        self.module_pusd_balance
    }
    fn module_role_bitmap(&self) -> U256 {
        self.module_role_bitmap
    }
    fn result_length(&self) -> U256 {
        self.native_context.result_length()
    }
    fn normalized_numerators(&self) -> Option<[U256; 2]> {
        self.native_context.normalized_numerators()
    }
    fn source_identity_continues(&self, next: &Self) -> bool {
        let prior = &self.native_context;
        let next = &next.native_context;
        prior.condition_id() == next.condition_id()
            && prior.position_ids() == next.position_ids()
            && prior.module_proxy() == next.module_proxy()
            && prior.module_implementation() == next.module_implementation()
            && prior.module_implementation_code_hash() == next.module_implementation_code_hash()
            && prior.legacy_mapping_value().is_zero()
            && next.legacy_mapping_value().is_zero()
            && prior.selected_balances().owner() == next.selected_balances().owner()
            && prior
                .selected_balances()
                .code_context()
                .exchange_implementation_version()
                == next
                    .selected_balances()
                    .code_context()
                    .exchange_implementation_version()
            && prior
                .selected_balances()
                .code_context()
                .position_manager_proxy_code_hash()
                == next
                    .selected_balances()
                    .code_context()
                    .position_manager_proxy_code_hash()
            && prior.selected_balances().position_manager_proxy_code_hash()
                == next.selected_balances().position_manager_proxy_code_hash()
            && prior.selected_balances().pusd_proxy_code_hash()
                == next.selected_balances().pusd_proxy_code_hash()
            && prior.result_length() == next.result_length()
            && prior.normalized_numerators() == next.normalized_numerators()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthNativeBinaryModuleOperationsObservation {
    evidence: ChainReceiptIntervalEvidence,
    opening: FifthNativeBinaryModuleOperationBoundary,
    block_observations: Vec<FifthNativeBinaryModuleOperationBoundary>,
    status: FifthNativeBinaryModuleOperationsStatus,
    operations: Vec<FifthDirectModuleOperationFact>,
}

impl FifthNativeBinaryModuleOperationsObservation {
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
    pub const fn status(&self) -> &FifthNativeBinaryModuleOperationsStatus {
        &self.status
    }
    #[must_use]
    pub fn operations(&self) -> &[FifthDirectModuleOperationFact] {
        &self.operations
    }
    #[must_use]
    pub const fn source_policy_version(&self) -> &'static str {
        POLICY_VERSION
    }
}

impl ChainLogVerifier {
    #[allow(clippy::too_many_arguments)]
    pub async fn verify_fifth_native_binary_module_operations_interval_bounded(
        &self,
        owner: &str,
        condition_id: &str,
        from_block: u64,
        through_block: u64,
        expected_parent_hash: &str,
        expected_end_hash: &str,
        max_requests: usize,
        total_timeout: Duration,
    ) -> Result<
        FifthNativeBinaryModuleOperationsObservation,
        BoundedFifthNativeBinaryModuleOperationsError,
    > {
        let owner = super::validate_hex(owner, 20).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let owner_bytes = hex::decode(&owner[2..]).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let condition =
            super::parse_fixed_b256(condition_id).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let parent_hash = super::validate_hex(expected_parent_hash, 32)
            .map_err(|_| ChainLogAuditError::InvalidInput)?;
        let end_hash = super::validate_hex(expected_end_hash, 32)
            .map_err(|_| ChainLogAuditError::InvalidInput)?;
        if owner_bytes.iter().all(|byte| *byte == 0)
            || from_block == 0
            || from_block > through_block
            || through_block - from_block >= MAX_BLOCKS
            || max_requests == 0
            || total_timeout.is_zero()
            || !super::fifth_native_binary::is_canonical_native_binary_condition(condition)
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
        let verification = scoped.verify_native_module_operations_inner(
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
            _ = exhaustion.wait_for(|is_exhausted| *is_exhausted) => {
                Err(BoundedFifthNativeBinaryModuleOperationsError::RequestBudgetExceeded)
            }
            () = &mut deadline_wait => {
                if budget.is_exhausted() {
                    Err(BoundedFifthNativeBinaryModuleOperationsError::RequestBudgetExceeded)
                } else {
                    Err(BoundedFifthNativeBinaryModuleOperationsError::Timeout)
                }
            }
            result = &mut verification => {
                if budget.is_exhausted() {
                    Err(BoundedFifthNativeBinaryModuleOperationsError::RequestBudgetExceeded)
                } else if Instant::now() >= deadline {
                    Err(BoundedFifthNativeBinaryModuleOperationsError::Timeout)
                } else {
                    result
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn verify_native_module_operations_inner(
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
    ) -> Result<
        FifthNativeBinaryModuleOperationsObservation,
        BoundedFifthNativeBinaryModuleOperationsError,
    > {
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
            .await?;
        let (evidence, opening, points) = interval.into_parts();
        let status = if !module_balances_are_zero(&opening) {
            FifthNativeBinaryModuleOperationsStatus::Unavailable {
                block_number: Some(from_block - 1),
                transaction_hash: None,
                reason: FifthLegacyBinaryModuleOperationsUnavailableReason::ModuleNotEmpty,
            }
        } else if !fifth_direct_module_operations::has_minter_role(opening.module_role_bitmap()) {
            FifthNativeBinaryModuleOperationsStatus::Unavailable {
                block_number: Some(from_block - 1),
                transaction_hash: None,
                reason: FifthLegacyBinaryModuleOperationsUnavailableReason::MinterRoleUnavailable,
            }
        } else {
            let (status, operations) = fifth_direct_module_operations::classify_module_interval(
                &evidence, &owner, &opening, &points,
            )?;
            let operations = if matches!(status, FifthLegacyBinaryModuleOperationsStatus::Matched)
                && points.last().is_some_and(module_balances_are_zero)
            {
                operations
            } else if matches!(status, FifthLegacyBinaryModuleOperationsStatus::Matched) {
                return Ok(FifthNativeBinaryModuleOperationsObservation {
                    evidence,
                    opening,
                    block_observations: points,
                    status: FifthNativeBinaryModuleOperationsStatus::Unavailable {
                        block_number: Some(through_block),
                        transaction_hash: None,
                        reason: FifthLegacyBinaryModuleOperationsUnavailableReason::ModuleNotEmpty,
                    },
                    operations: Vec::new(),
                });
            } else {
                Vec::new()
            };
            ensure_deadline(deadline)?;
            return Ok(FifthNativeBinaryModuleOperationsObservation {
                evidence,
                opening,
                block_observations: points,
                status: map_classification_status(status),
                operations,
            });
        };
        ensure_deadline(deadline)?;
        Ok(FifthNativeBinaryModuleOperationsObservation {
            evidence,
            opening,
            block_observations: points,
            status,
            operations: Vec::new(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn verify_fifth_native_module_interval_evidence_inner(
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
    ) -> Result<FifthNativeModuleIntervalEvidence, BoundedFifthNativeBinaryModuleOperationsError>
    {
        ensure_deadline(deadline)?;
        let opening_context = self
            .verify_fifth_native_binary_inner(
                owner.clone(),
                owner_address,
                condition,
                ids,
                from_block - 1,
                parent_hash,
                deadline,
            )
            .await
            .map_err(map_native_error)?;
        if opening_context.selected_balances().block_hash() != parent_hash {
            return Err(ChainLogAuditError::Unverified.into());
        }
        let module = opening_context.module_proxy();
        let opening =
            native_module_boundary(self, opening_context, module, ids, from_block - 1, deadline)
                .await?;
        let scoped = self.with_fifth_module_call_targets(module);
        let evidence = scoped
            .verify_receipt_interval_inner(from_block, through_block, parent_hash, end_hash)
            .await?;
        ensure_deadline(deadline)?;
        let mut points = Vec::with_capacity(evidence.blocks().len());
        for block in evidence.blocks() {
            let context = scoped
                .verify_fifth_native_binary_inner(
                    owner.clone(),
                    owner_address,
                    condition,
                    ids,
                    block.block_number(),
                    block.block_hash(),
                    deadline,
                )
                .await
                .map_err(map_native_error)?;
            if context.selected_balances().state_root() != block.state_root()
                || context.selected_balances().block_hash() != block.block_hash()
            {
                return Err(ChainLogAuditError::Unverified.into());
            }
            points.push(
                native_module_boundary(
                    &scoped,
                    context,
                    module,
                    ids,
                    block.block_number(),
                    deadline,
                )
                .await?,
            );
        }
        ensure_deadline(deadline)?;
        Ok(FifthNativeModuleIntervalEvidence {
            evidence,
            opening,
            block_observations: points,
        })
    }
}

async fn native_module_boundary(
    verifier: &ChainLogVerifier,
    native_context: FifthNativeBinaryObservation,
    module: Address,
    ids: [B256; 2],
    block: u64,
    deadline: Instant,
) -> Result<FifthNativeBinaryModuleOperationBoundary, BoundedFifthNativeBinaryModuleOperationsError>
{
    let (module_position_balances, module_pusd_balance, module_role_bitmap) =
        fifth_direct_module_operations::module_balance_role_proofs(
            verifier,
            native_context.selected_balances(),
            module,
            ids,
            block,
            deadline,
        )
        .await
        .map_err(map_module_error)?;
    Ok(FifthNativeBinaryModuleOperationBoundary {
        native_context,
        module_position_balances,
        module_pusd_balance,
        module_role_bitmap,
    })
}

fn derive_position_id(condition: B256) -> B256 {
    let mut bytes = condition.0;
    bytes[31] = 1;
    B256::from(bytes)
}

fn module_balances_are_zero(point: &FifthNativeBinaryModuleOperationBoundary) -> bool {
    point.module_position_balances == [U256::ZERO; 2] && point.module_pusd_balance.is_zero()
}

fn map_classification_status(
    status: FifthLegacyBinaryModuleOperationsStatus,
) -> FifthNativeBinaryModuleOperationsStatus {
    match status {
        FifthLegacyBinaryModuleOperationsStatus::Matched => {
            FifthNativeBinaryModuleOperationsStatus::Matched
        }
        FifthLegacyBinaryModuleOperationsStatus::Mismatch {
            block_number,
            holder,
            asset,
            authenticated_balance,
            reconstructed_balance,
        } => FifthNativeBinaryModuleOperationsStatus::Mismatch {
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
        } => FifthNativeBinaryModuleOperationsStatus::Unavailable {
            block_number,
            transaction_hash,
            reason,
        },
    }
}

fn map_native_error(
    error: BoundedFifthNativeBinaryError,
) -> BoundedFifthNativeBinaryModuleOperationsError {
    match error {
        BoundedFifthNativeBinaryError::RequestBudgetExceeded => {
            BoundedFifthNativeBinaryModuleOperationsError::RequestBudgetExceeded
        }
        BoundedFifthNativeBinaryError::Timeout => {
            BoundedFifthNativeBinaryModuleOperationsError::Timeout
        }
        BoundedFifthNativeBinaryError::Verification(error) => {
            BoundedFifthNativeBinaryModuleOperationsError::Verification(error)
        }
    }
}

fn map_module_error(
    error: BoundedFifthLegacyBinaryModuleOperationsError,
) -> BoundedFifthNativeBinaryModuleOperationsError {
    match error {
        BoundedFifthLegacyBinaryModuleOperationsError::RequestBudgetExceeded => {
            BoundedFifthNativeBinaryModuleOperationsError::RequestBudgetExceeded
        }
        BoundedFifthLegacyBinaryModuleOperationsError::Timeout => {
            BoundedFifthNativeBinaryModuleOperationsError::Timeout
        }
        BoundedFifthLegacyBinaryModuleOperationsError::Verification(error) => {
            BoundedFifthNativeBinaryModuleOperationsError::Verification(error)
        }
    }
}

fn ensure_deadline(deadline: Instant) -> Result<(), BoundedFifthNativeBinaryModuleOperationsError> {
    if Instant::now() >= deadline {
        Err(BoundedFifthNativeBinaryModuleOperationsError::Timeout)
    } else {
        Ok(())
    }
}
