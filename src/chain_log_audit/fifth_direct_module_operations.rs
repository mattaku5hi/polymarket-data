//! Root-bound attribution for one EOA's direct funding and BinaryModule calls.

use super::fifth_code_context::POSITION_MANAGER_PROXY;
use super::fifth_legacy_binary_result::{
    BoundedFifthLegacyBinaryResultError, FifthLegacyBinaryResultObservation,
};
use super::fifth_selected_balances::FifthSelectedBalancesObservation;
use super::{
    ChainLogAuditError, ChainLogVerifier, ChainReceiptIntervalBlock, ChainReceiptIntervalEvidence,
    TransactionRequestBudget, exact_eip1186_storage_entries, field, parse_eip1186_storage_value,
    parse_fixed_b256, rlp_u256, validate_hex, verify_eip1186_account_proof,
    verify_eip1186_storage_proof,
};
use alloy_primitives::{Address, B256, U256};
use serde_json::json;
use sha3::{Digest, Keccak256};
use std::time::Duration;
use thiserror::Error;
use tokio::time::Instant;

const PUSD_PROXY: &str = "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb";
const PUSD_ROLE_SEED: [u8; 4] = [0x8b, 0x78, 0xc6, 0xd8];
const PUSD_BALANCE_SEED: [u8; 4] = [0x87, 0xa2, 0x11, 0xa2];
const POSITION_BALANCE_SEED: u64 = 0x9a31110384e0b0c9;
const MINTER_ROLE: U256 = U256::ONE;
const POLICY_VERSION: &str = "fifth-direct-funded-binary-module-operations/1";
const PUSD_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const PM_SAFE_TRANSFER_FROM: [u8; 4] = [0xf2, 0x42, 0x43, 0x2a];
const MODULE_SPLIT: [u8; 4] = [0x2d, 0x20, 0xcf, 0xfd];
const MODULE_MERGE: [u8; 4] = [0x1d, 0x47, 0x9a, 0x82];
const MODULE_REDEEM: [u8; 4] = [0x2b, 0x83, 0xcc, 0xcd];
const ERC20_TRANSFER_TOPIC: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const ERC1155_TRANSFER_SINGLE_TOPIC: &str =
    "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62";
const POSITIONS_SPLIT_TOPIC: &str =
    "0xb6a6b8b17a43b07b9359dd12d304e42077eede9e672f8646144842c8604582a4";
const POSITIONS_MERGED_TOPIC: &str =
    "0xf233f7be4ce81130a78e8eb2fa626497586c56094d27bfec2e196471e9c60301";
const POSITION_REDEEMED_TOPIC: &str =
    "0x4fd474b703f46b453536518b4cbc159dfbea6fd663233763d321a9bc8ccdf97f";
const ROLES_UPDATED_TOPIC: &str =
    "0x715ad5ce61fc9595c7b415289d59cf203f23a94fa06f04af7e489a0a76e1fe26";

pub const FIFTH_LEGACY_BINARY_MODULE_OPERATIONS_POLICY_VERSION: &str = POLICY_VERSION;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedFifthLegacyBinaryModuleOperationsError {
    #[error("fifth direct BinaryModule operation RPC request budget exhausted")]
    RequestBudgetExceeded,
    #[error("fifth direct BinaryModule operation exceeded its total deadline")]
    Timeout,
    #[error(transparent)]
    Verification(#[from] ChainLogAuditError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthDirectModuleOperationKind {
    Split,
    Merge,
    Redeem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthDirectModuleOperationsHolder {
    Owner,
    Module,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthDirectModuleOperationsAsset {
    PositionA,
    PositionB,
    Pusd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthDirectModuleFundingAsset {
    PositionA,
    PositionB,
    Pusd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthLegacyBinaryModuleOperationsUnavailableReason {
    UnsupportedOwnerActivity,
    UnsupportedDirectCall,
    InvalidCalldata,
    SourceSettlementMismatch,
    ArithmeticUnavailable,
    ModuleNotEmpty,
    MinterRoleUnavailable,
    ResultUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FifthLegacyBinaryModuleOperationsStatus {
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
pub struct FifthDirectModuleTransactionLocator {
    block_number: u64,
    block_hash: String,
    transaction_hash: String,
    transaction_index: u64,
}

impl FifthDirectModuleTransactionLocator {
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthDirectModuleFundingFact {
    transaction: FifthDirectModuleTransactionLocator,
    asset: FifthDirectModuleFundingAsset,
    position_id: Option<B256>,
    amount: U256,
}

impl FifthDirectModuleFundingFact {
    #[must_use]
    pub const fn transaction(&self) -> &FifthDirectModuleTransactionLocator {
        &self.transaction
    }
    #[must_use]
    pub const fn asset(&self) -> FifthDirectModuleFundingAsset {
        self.asset
    }
    #[must_use]
    pub const fn position_id(&self) -> Option<B256> {
        self.position_id
    }
    #[must_use]
    pub const fn amount(&self) -> U256 {
        self.amount
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthDirectModuleOperationFact {
    kind: FifthDirectModuleOperationKind,
    condition_id: B256,
    position_id: Option<B256>,
    amount: U256,
    payout: Option<U256>,
    owner_position_inflows: [U256; 2],
    owner_position_outflows: [U256; 2],
    owner_pusd_inflow: U256,
    owner_pusd_outflow: U256,
    funding_transactions: Vec<FifthDirectModuleFundingFact>,
    operation_transaction: FifthDirectModuleTransactionLocator,
}

impl FifthDirectModuleOperationFact {
    #[must_use]
    pub const fn kind(&self) -> FifthDirectModuleOperationKind {
        self.kind
    }
    #[must_use]
    pub const fn condition_id(&self) -> B256 {
        self.condition_id
    }
    #[must_use]
    pub const fn position_id(&self) -> Option<B256> {
        self.position_id
    }
    #[must_use]
    pub const fn amount(&self) -> U256 {
        self.amount
    }
    #[must_use]
    pub const fn payout(&self) -> Option<U256> {
        self.payout
    }
    #[must_use]
    pub const fn owner_position_inflows(&self) -> [U256; 2] {
        self.owner_position_inflows
    }
    #[must_use]
    pub const fn owner_position_outflows(&self) -> [U256; 2] {
        self.owner_position_outflows
    }
    #[must_use]
    pub const fn owner_pusd_inflow(&self) -> U256 {
        self.owner_pusd_inflow
    }
    #[must_use]
    pub const fn owner_pusd_outflow(&self) -> U256 {
        self.owner_pusd_outflow
    }
    #[must_use]
    pub fn funding_transactions(&self) -> &[FifthDirectModuleFundingFact] {
        &self.funding_transactions
    }
    #[must_use]
    pub const fn operation_transaction(&self) -> &FifthDirectModuleTransactionLocator {
        &self.operation_transaction
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthLegacyBinaryModuleOperationBoundary {
    result: FifthLegacyBinaryResultObservation,
    module_position_balances: [U256; 2],
    module_pusd_balance: U256,
    module_role_bitmap: U256,
}

/// The source-specific point adapter consumed by the shared funding/operation replay.
pub(super) trait ModuleOperationPoint {
    fn selected_balances(&self) -> &FifthSelectedBalancesObservation;
    fn module_proxy(&self) -> Address;
    fn condition_id(&self) -> B256;
    fn position_ids(&self) -> [B256; 2];
    fn module_position_balances(&self) -> [U256; 2];
    fn module_pusd_balance(&self) -> U256;
    fn module_role_bitmap(&self) -> U256;
    fn result_length(&self) -> U256;
    fn normalized_numerators(&self) -> Option<[U256; 2]>;
    fn source_identity_continues(&self, next: &Self) -> bool;
}

impl ModuleOperationPoint for FifthLegacyBinaryModuleOperationBoundary {
    fn selected_balances(&self) -> &FifthSelectedBalancesObservation {
        self.result.balances().selected_balances()
    }
    fn module_proxy(&self) -> Address {
        self.result.balances().module_proxy()
    }
    fn condition_id(&self) -> B256 {
        self.result.balances().v2_condition_id()
    }
    fn position_ids(&self) -> [B256; 2] {
        self.result.balances().v2_position_ids()
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
        self.result.result_length()
    }
    fn normalized_numerators(&self) -> Option<[U256; 2]> {
        self.result.normalized_numerators()
    }
    fn source_identity_continues(&self, next: &Self) -> bool {
        let prior = self.result.balances();
        let next_balances = next.result.balances();
        prior.legacy_condition_id() == next_balances.legacy_condition_id()
            && prior.legacy_collection_ids() == next_balances.legacy_collection_ids()
            && prior.legacy_position_ids() == next_balances.legacy_position_ids()
            && prior.v2_condition_id() == next_balances.v2_condition_id()
            && prior.v2_position_ids() == next_balances.v2_position_ids()
            && prior.module_proxy() == next_balances.module_proxy()
            && prior.module_implementation() == next_balances.module_implementation()
            && prior.module_implementation_code_hash()
                == next_balances.module_implementation_code_hash()
            && prior.selected_balances().owner() == next_balances.selected_balances().owner()
            && prior
                .selected_balances()
                .code_context()
                .exchange_implementation_version()
                == next_balances
                    .selected_balances()
                    .code_context()
                    .exchange_implementation_version()
            && prior
                .selected_balances()
                .code_context()
                .position_manager_proxy_code_hash()
                == next_balances
                    .selected_balances()
                    .code_context()
                    .position_manager_proxy_code_hash()
            && prior.selected_balances().position_manager_proxy_code_hash()
                == next_balances
                    .selected_balances()
                    .position_manager_proxy_code_hash()
            && prior.selected_balances().pusd_proxy_code_hash()
                == next_balances.selected_balances().pusd_proxy_code_hash()
            && {
                let prior_ctf = prior.ctf_condition_state();
                let next_ctf = next_balances.ctf_condition_state();
                prior_ctf.status() == next_ctf.status()
                    && prior_ctf.payout_numerator_count() == next_ctf.payout_numerator_count()
                    && prior_ctf.payout_denominator() == next_ctf.payout_denominator()
                    && prior_ctf.payout_numerators() == next_ctf.payout_numerators()
            }
            && self.result.result_length() == next.result.result_length()
            && self.result.normalized_numerators() == next.result.normalized_numerators()
    }
}

impl FifthLegacyBinaryModuleOperationBoundary {
    #[must_use]
    pub const fn result(&self) -> &FifthLegacyBinaryResultObservation {
        &self.result
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
pub struct FifthLegacyBinaryModuleOperationsObservation {
    evidence: ChainReceiptIntervalEvidence,
    opening: FifthLegacyBinaryModuleOperationBoundary,
    block_observations: Vec<FifthLegacyBinaryModuleOperationBoundary>,
    status: FifthLegacyBinaryModuleOperationsStatus,
    operations: Vec<FifthDirectModuleOperationFact>,
}

impl FifthLegacyBinaryModuleOperationsObservation {
    #[must_use]
    pub const fn evidence(&self) -> &ChainReceiptIntervalEvidence {
        &self.evidence
    }
    #[must_use]
    pub const fn opening(&self) -> &FifthLegacyBinaryModuleOperationBoundary {
        &self.opening
    }
    #[must_use]
    pub fn block_observations(&self) -> &[FifthLegacyBinaryModuleOperationBoundary] {
        &self.block_observations
    }
    #[must_use]
    pub const fn status(&self) -> &FifthLegacyBinaryModuleOperationsStatus {
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
    pub async fn verify_fifth_legacy_binary_module_operations_interval_bounded(
        &self,
        owner: &str,
        legacy_condition_id: &str,
        from_block: u64,
        through_block: u64,
        expected_parent_hash: &str,
        expected_end_hash: &str,
        max_requests: usize,
        total_timeout: Duration,
    ) -> Result<
        FifthLegacyBinaryModuleOperationsObservation,
        BoundedFifthLegacyBinaryModuleOperationsError,
    > {
        let owner = validate_hex(owner, 20).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let owner_bytes = hex::decode(&owner[2..]).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let legacy =
            parse_fixed_b256(legacy_condition_id).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let parent_hash =
            validate_hex(expected_parent_hash, 32).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let end_hash =
            validate_hex(expected_end_hash, 32).map_err(|_| ChainLogAuditError::InvalidInput)?;
        if owner_bytes.iter().all(|byte| *byte == 0)
            || from_block == 0
            || from_block > through_block
            || through_block - from_block >= 16
            || max_requests == 0
            || total_timeout.is_zero()
        {
            return Err(ChainLogAuditError::InvalidInput.into());
        }
        let owner_address = Address::from_slice(&owner_bytes);
        let deadline = Instant::now()
            .checked_add(total_timeout)
            .ok_or(ChainLogAuditError::InvalidInput)?;
        let budget = TransactionRequestBudget::new(max_requests);
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let scoped = self.with_request_budget(budget.inner());
        let verification = scoped.verify_module_operations_inner(
            owner,
            owner_address,
            legacy,
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
                Err(BoundedFifthLegacyBinaryModuleOperationsError::RequestBudgetExceeded)
            }
            () = &mut deadline_wait => {
                if budget.is_exhausted() {
                    Err(BoundedFifthLegacyBinaryModuleOperationsError::RequestBudgetExceeded)
                } else {
                    Err(BoundedFifthLegacyBinaryModuleOperationsError::Timeout)
                }
            }
            result = &mut verification => {
                if budget.is_exhausted() {
                    Err(BoundedFifthLegacyBinaryModuleOperationsError::RequestBudgetExceeded)
                } else if Instant::now() >= deadline {
                    Err(BoundedFifthLegacyBinaryModuleOperationsError::Timeout)
                } else {
                    result
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn verify_module_operations_inner(
        &self,
        owner: String,
        owner_address: Address,
        legacy: B256,
        from_block: u64,
        through_block: u64,
        parent_hash: &str,
        end_hash: &str,
        deadline: Instant,
    ) -> Result<
        FifthLegacyBinaryModuleOperationsObservation,
        BoundedFifthLegacyBinaryModuleOperationsError,
    > {
        ensure_deadline(deadline)?;
        let base = self;
        let opening_result = base
            .verify_fifth_legacy_binary_result_inner(
                owner.clone(),
                owner_address,
                legacy,
                from_block - 1,
                parent_hash,
                deadline,
            )
            .await
            .map_err(map_result_error)?;
        ensure_deadline(deadline)?;
        if opening_result.balances().selected_balances().block_hash() != parent_hash {
            return Err(ChainLogAuditError::Unverified.into());
        }
        let opening = module_boundary(base, opening_result, from_block - 1, deadline).await?;
        let module_proxy = opening.result.balances().module_proxy();
        let scoped = base.with_fifth_module_call_targets(module_proxy);
        let evidence = scoped
            .verify_receipt_interval_inner(from_block, through_block, parent_hash, end_hash)
            .await?;
        ensure_deadline(deadline)?;
        let mut points = Vec::with_capacity(evidence.blocks().len());
        for block in evidence.blocks() {
            let result = scoped
                .verify_fifth_legacy_binary_result_inner(
                    owner.clone(),
                    owner_address,
                    legacy,
                    block.block_number(),
                    block.block_hash(),
                    deadline,
                )
                .await
                .map_err(map_result_error)?;
            if result.balances().selected_balances().state_root() != block.state_root()
                || result.balances().selected_balances().block_hash() != block.block_hash()
            {
                return Err(ChainLogAuditError::Unverified.into());
            }
            points.push(module_boundary(&scoped, result, block.block_number(), deadline).await?);
        }
        ensure_deadline(deadline)?;
        let (status, classified_operations) = if !module_balances_are_zero(&opening)
            || !has_minter_role(opening.module_role_bitmap)
        {
            (
                FifthLegacyBinaryModuleOperationsStatus::Unavailable {
                    block_number: Some(from_block - 1),
                    transaction_hash: None,
                    reason: if !module_balances_are_zero(&opening) {
                        FifthLegacyBinaryModuleOperationsUnavailableReason::ModuleNotEmpty
                    } else {
                        FifthLegacyBinaryModuleOperationsUnavailableReason::MinterRoleUnavailable
                    },
                },
                Vec::new(),
            )
        } else {
            classify_module_interval(&evidence, &owner, &opening, &points)?
        };
        ensure_deadline(deadline)?;
        let operations = if matches!(status, FifthLegacyBinaryModuleOperationsStatus::Matched)
            && points.last().is_some_and(module_balances_are_zero)
        {
            classified_operations
        } else if matches!(status, FifthLegacyBinaryModuleOperationsStatus::Matched) {
            return Ok(FifthLegacyBinaryModuleOperationsObservation {
                evidence,
                opening,
                block_observations: points,
                status: FifthLegacyBinaryModuleOperationsStatus::Unavailable {
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
        Ok(FifthLegacyBinaryModuleOperationsObservation {
            evidence,
            opening,
            block_observations: points,
            status,
            operations,
        })
    }
}

async fn module_boundary(
    verifier: &ChainLogVerifier,
    result: FifthLegacyBinaryResultObservation,
    block: u64,
    deadline: Instant,
) -> Result<FifthLegacyBinaryModuleOperationBoundary, BoundedFifthLegacyBinaryModuleOperationsError>
{
    ensure_deadline(deadline)?;
    let balances = result.balances();
    let module = balances.module_proxy();
    let selected = balances.selected_balances();
    let ids = balances.v2_position_ids();
    let (position_values, cash, role) =
        module_balance_role_proofs(verifier, selected, module, ids, block, deadline).await?;
    Ok(FifthLegacyBinaryModuleOperationBoundary {
        result,
        module_position_balances: position_values,
        module_pusd_balance: cash,
        module_role_bitmap: role,
    })
}

pub(super) async fn module_balance_role_proofs(
    verifier: &ChainLogVerifier,
    selected: &FifthSelectedBalancesObservation,
    module: Address,
    ids: [B256; 2],
    block: u64,
    deadline: Instant,
) -> Result<([U256; 2], U256, U256), BoundedFifthLegacyBinaryModuleOperationsError> {
    ensure_deadline(deadline)?;
    let root = selected.state_root();
    let (position_values, (cash, role)) = tokio::try_join!(
        module_position_proof(
            verifier,
            &verifier.primary,
            selected,
            block,
            root,
            module,
            ids
        ),
        module_pusd_and_role_proof(verifier, &verifier.primary, selected, block, root, module),
    )?;
    let (secondary_positions, (secondary_cash, secondary_role)) = tokio::try_join!(
        module_position_proof(
            verifier,
            &verifier.secondary,
            selected,
            block,
            root,
            module,
            ids
        ),
        module_pusd_and_role_proof(verifier, &verifier.secondary, selected, block, root, module),
    )?;
    ensure_deadline(deadline)?;
    if position_values != secondary_positions || cash != secondary_cash || role != secondary_role {
        return Err(ChainLogAuditError::Divergent.into());
    }
    Ok((position_values, cash, role))
}

async fn module_position_proof(
    verifier: &ChainLogVerifier,
    endpoint: &str,
    selected: &FifthSelectedBalancesObservation,
    block: u64,
    state_root: &str,
    module: Address,
    ids: [B256; 2],
) -> Result<[U256; 2], ChainLogAuditError> {
    let keys = [
        position_balance_key(module, ids[0]),
        position_balance_key(module, ids[1]),
    ];
    let proof = verifier
        .rpc(
            endpoint,
            "eth_getProof",
            json!([
                POSITION_MANAGER_PROXY,
                keys.iter()
                    .map(|key| format!("{key:#x}"))
                    .collect::<Vec<_>>(),
                format!("{block:#x}")
            ]),
        )
        .await?;
    let account = verify_eip1186_account_proof(state_root, POSITION_MANAGER_PROXY, &proof)?;
    if account.code_hash
        != parse_fixed_b256(selected.code_context().position_manager_proxy_code_hash())?
    {
        return Err(ChainLogAuditError::Unverified);
    }
    let entries = exact_eip1186_storage_entries(&proof, &keys)?;
    let mut values = [U256::ZERO; 2];
    for index in 0..keys.len() {
        values[index] = parse_eip1186_storage_value(field(entries[index], "value")?)?;
        verify_eip1186_storage_proof(
            &account,
            keys[index],
            entries[index],
            (!values[index].is_zero()).then(|| rlp_u256(values[index])),
            values[index].is_zero(),
        )?;
    }
    Ok(values)
}

async fn module_pusd_and_role_proof(
    verifier: &ChainLogVerifier,
    endpoint: &str,
    selected: &FifthSelectedBalancesObservation,
    block: u64,
    state_root: &str,
    module: Address,
) -> Result<(U256, U256), ChainLogAuditError> {
    let keys = [pusd_balance_key(module), role_bitmap_key(module)];
    let proof = verifier
        .rpc(
            endpoint,
            "eth_getProof",
            json!([
                PUSD_PROXY,
                keys.iter()
                    .map(|key| format!("{key:#x}"))
                    .collect::<Vec<_>>(),
                format!("{block:#x}")
            ]),
        )
        .await?;
    let account = verify_eip1186_account_proof(state_root, PUSD_PROXY, &proof)?;
    if account.code_hash != parse_fixed_b256(selected.pusd_proxy_code_hash())? {
        return Err(ChainLogAuditError::Unverified);
    }
    let entries = exact_eip1186_storage_entries(&proof, &keys)?;
    let mut values = [U256::ZERO; 2];
    for index in 0..keys.len() {
        values[index] = parse_eip1186_storage_value(field(entries[index], "value")?)?;
        verify_eip1186_storage_proof(
            &account,
            keys[index],
            entries[index],
            (!values[index].is_zero()).then(|| rlp_u256(values[index])),
            values[index].is_zero(),
        )?;
    }
    Ok((values[0], values[1]))
}

fn position_balance_key(owner: Address, id: B256) -> B256 {
    let owner_value = U256::from_be_slice(owner.as_slice());
    let seed = (owner_value << 96_u32) | U256::from(POSITION_BALANCE_SEED);
    let mut preimage = [0_u8; 64];
    preimage[..32].copy_from_slice(id.as_slice());
    preimage[32..].copy_from_slice(&seed.to_be_bytes::<32>());
    B256::from_slice(&Keccak256::digest(preimage))
}

fn pusd_balance_key(owner: Address) -> B256 {
    let mut preimage = [0_u8; 32];
    preimage[..20].copy_from_slice(owner.as_slice());
    preimage[28..].copy_from_slice(&PUSD_BALANCE_SEED);
    B256::from_slice(&Keccak256::digest(preimage))
}

fn role_bitmap_key(owner: Address) -> B256 {
    let mut preimage = [0_u8; 32];
    preimage[..20].copy_from_slice(owner.as_slice());
    preimage[28..].copy_from_slice(&PUSD_ROLE_SEED);
    B256::from_slice(&Keccak256::digest(preimage))
}

pub(super) fn module_balances_are_zero<P: ModuleOperationPoint>(point: &P) -> bool {
    point.module_position_balances() == [U256::ZERO; 2] && point.module_pusd_balance().is_zero()
}

pub(super) fn has_minter_role(roles: U256) -> bool {
    roles & MINTER_ROLE != U256::ZERO
}

fn ensure_deadline(deadline: Instant) -> Result<(), BoundedFifthLegacyBinaryModuleOperationsError> {
    if Instant::now() >= deadline {
        Err(BoundedFifthLegacyBinaryModuleOperationsError::Timeout)
    } else {
        Ok(())
    }
}

fn map_result_error(
    error: BoundedFifthLegacyBinaryResultError,
) -> BoundedFifthLegacyBinaryModuleOperationsError {
    match error {
        BoundedFifthLegacyBinaryResultError::RequestBudgetExceeded => {
            BoundedFifthLegacyBinaryModuleOperationsError::RequestBudgetExceeded
        }
        BoundedFifthLegacyBinaryResultError::Timeout => {
            BoundedFifthLegacyBinaryModuleOperationsError::Timeout
        }
        BoundedFifthLegacyBinaryResultError::Verification(error) => {
            BoundedFifthLegacyBinaryModuleOperationsError::Verification(error)
        }
    }
}

pub(super) fn classify_module_interval<P: ModuleOperationPoint>(
    evidence: &ChainReceiptIntervalEvidence,
    owner: &str,
    opening: &P,
    points: &[P],
) -> Result<
    (
        FifthLegacyBinaryModuleOperationsStatus,
        Vec<FifthDirectModuleOperationFact>,
    ),
    ChainLogAuditError,
> {
    if points.len() != evidence.blocks().len() {
        return Err(ChainLogAuditError::Unverified);
    }
    let module_address = opening.module_proxy();
    let module = format!("{module_address:#x}");
    let owner_address = owner
        .parse::<Address>()
        .map_err(|_| ChainLogAuditError::Unverified)?;
    let v2 = opening.condition_id();
    let ids = opening.position_ids();
    let mut owner_balances = owner_balances(opening);
    let mut module_balances = ModuleBalances::default();
    let mut pending = Vec::<FifthDirectModuleFundingFact>::new();
    let mut operations = Vec::<FifthDirectModuleOperationFact>::new();
    for (block, point) in evidence.blocks().iter().zip(points) {
        for transaction in block.transactions() {
            let transaction_status = transaction.status();
            let to = transaction.to.as_deref();
            let is_module_call = to.is_some_and(|to| to.eq_ignore_ascii_case(&module));
            let call = if is_module_call {
                match transaction
                    .input
                    .as_deref()
                    .and_then(|input| parse_module_call(input, owner_address, v2, ids))
                {
                    Some(call) => Some(call),
                    None if transaction
                        .input
                        .as_deref()
                        .is_some_and(|input| !input.is_empty()) =>
                    {
                        if transaction
                            .recovered_from
                            .as_deref()
                            .is_some_and(|from| from.eq_ignore_ascii_case(owner))
                        {
                            return Ok(unavailable(block, transaction, FifthLegacyBinaryModuleOperationsUnavailableReason::UnsupportedDirectCall));
                        }
                        None
                    }
                    None => None,
                }
            } else {
                None
            };
            if is_module_call && call.is_none() {
                return Ok(unavailable(
                    block,
                    transaction,
                    FifthLegacyBinaryModuleOperationsUnavailableReason::UnsupportedDirectCall,
                ));
            }
            let funding = if to.is_some_and(|to| to.eq_ignore_ascii_case(PUSD_PROXY)) {
                parse_pusd_funding(
                    transaction.input.as_deref().unwrap_or_default(),
                    module_address,
                )
            } else if to.is_some_and(|to| to.eq_ignore_ascii_case(POSITION_MANAGER_PROXY)) {
                parse_position_funding(
                    transaction.input.as_deref().unwrap_or_default(),
                    owner_address,
                    module_address,
                    ids,
                )
            } else {
                None
            };
            if transaction_status != 1 {
                if is_module_call
                    || funding.is_some()
                    || transaction_has_relevant_movement(
                        transaction,
                        owner_address,
                        module_address,
                        ids,
                    )
                {
                    return Ok(unavailable(block, transaction, FifthLegacyBinaryModuleOperationsUnavailableReason::SourceSettlementMismatch));
                }
                continue;
            }
            if let Some(call) = funding {
                if transaction
                    .recovered_from
                    .as_deref()
                    .is_none_or(|from| !from.eq_ignore_ascii_case(owner))
                {
                    return Ok(unavailable(block, transaction, FifthLegacyBinaryModuleOperationsUnavailableReason::UnsupportedOwnerActivity));
                }
                if !transaction.value.is_zero() || !transaction.replay_protected_sender {
                    return Ok(unavailable(block, transaction, FifthLegacyBinaryModuleOperationsUnavailableReason::UnsupportedOwnerActivity));
                }
                let expected = expected_funding_logs(&call, owner_address, module_address);
                if !exact_logs(transaction.logs(), &expected) {
                    return Ok(unavailable(block, transaction, FifthLegacyBinaryModuleOperationsUnavailableReason::SourceSettlementMismatch));
                }
                let fact = funding_fact(block.block_number(), block, transaction, &call, ids);
                apply_funding(&mut owner_balances, &mut module_balances, &call, ids)?;
                pending.push(fact);
                continue;
            }
            if let Some(call) = call {
                if transaction
                    .recovered_from
                    .as_deref()
                    .is_none_or(|from| !from.eq_ignore_ascii_case(owner))
                {
                    return Ok(unavailable(block, transaction, FifthLegacyBinaryModuleOperationsUnavailableReason::UnsupportedOwnerActivity));
                }
                if !transaction.value.is_zero() || !transaction.replay_protected_sender {
                    return Ok(unavailable(block, transaction, FifthLegacyBinaryModuleOperationsUnavailableReason::UnsupportedOwnerActivity));
                }
                if !pending_matches(&pending, &call) {
                    return Ok(unavailable(block, transaction, FifthLegacyBinaryModuleOperationsUnavailableReason::SourceSettlementMismatch));
                }
                let payout = match call {
                    ModuleCall::Redeem {
                        position_id,
                        amount,
                        ..
                    } => {
                        let Some(numerators) = opening.normalized_numerators() else {
                            return Ok(unavailable(block, transaction, FifthLegacyBinaryModuleOperationsUnavailableReason::ResultUnavailable));
                        };
                        if opening.result_length() != U256::from(2)
                            || numerators[0].checked_add(numerators[1])
                                != Some(U256::from(1_000_000))
                        {
                            return Ok(unavailable(block, transaction, FifthLegacyBinaryModuleOperationsUnavailableReason::ResultUnavailable));
                        }
                        let outcome = if position_id == ids[0] { 0 } else { 1 };
                        match amount.checked_mul(numerators[outcome]).map(|product| product / U256::from(1_000_000)) {
                            Some(value) => Some(value),
                            None => return Ok(unavailable(block, transaction, FifthLegacyBinaryModuleOperationsUnavailableReason::ArithmeticUnavailable)),
                        }
                    }
                    _ => None,
                };
                let expected =
                    expected_operation_logs(&call, payout, owner_address, module_address, v2, ids)?;
                if !exact_logs(transaction.logs(), &expected) {
                    return Ok(unavailable(block, transaction, FifthLegacyBinaryModuleOperationsUnavailableReason::SourceSettlementMismatch));
                }
                let fact = operation_fact(
                    block,
                    transaction,
                    call,
                    payout,
                    std::mem::take(&mut pending),
                    v2,
                    ids,
                );
                apply_operation(&mut owner_balances, &mut module_balances, &fact, ids)?;
                operations.push(fact);
                continue;
            }
            if transaction_has_relevant_movement(transaction, owner_address, module_address, ids) {
                return Ok(unavailable(
                    block,
                    transaction,
                    FifthLegacyBinaryModuleOperationsUnavailableReason::UnsupportedOwnerActivity,
                ));
            }
        }
        if !result_state_continues(
            if block.block_number() == evidence.from_block() {
                opening
            } else {
                &points[(block.block_number() - evidence.from_block() - 1) as usize]
            },
            point,
            v2,
            ids,
        ) {
            return Ok((
                FifthLegacyBinaryModuleOperationsStatus::Unavailable {
                    block_number: Some(block.block_number()),
                    transaction_hash: None,
                    reason: FifthLegacyBinaryModuleOperationsUnavailableReason::ResultUnavailable,
                },
                Vec::new(),
            ));
        }
        if has_relevant_upgrade_or_role_update(block, &module) {
            return Ok((
                FifthLegacyBinaryModuleOperationsStatus::Unavailable {
                    block_number: Some(block.block_number()),
                    transaction_hash: None,
                    reason:
                        FifthLegacyBinaryModuleOperationsUnavailableReason::UnsupportedOwnerActivity,
                },
                Vec::new(),
            ));
        }
        if !has_minter_role(point.module_role_bitmap())
            || point.module_role_bitmap() != opening.module_role_bitmap()
        {
            return Ok((
                FifthLegacyBinaryModuleOperationsStatus::Unavailable {
                    block_number: Some(block.block_number()),
                    transaction_hash: None,
                    reason:
                        FifthLegacyBinaryModuleOperationsUnavailableReason::MinterRoleUnavailable,
                },
                Vec::new(),
            ));
        }
        if let Some((holder, asset, auth, replay)) =
            compare_module_boundary(&owner_balances, &module_balances, point)
        {
            return Ok((
                FifthLegacyBinaryModuleOperationsStatus::Mismatch {
                    block_number: block.block_number(),
                    holder,
                    asset,
                    authenticated_balance: auth,
                    reconstructed_balance: replay,
                },
                Vec::new(),
            ));
        }
    }
    if !pending.is_empty() {
        return Ok((
            FifthLegacyBinaryModuleOperationsStatus::Unavailable {
                block_number: Some(evidence.through_block()),
                transaction_hash: None,
                reason:
                    FifthLegacyBinaryModuleOperationsUnavailableReason::SourceSettlementMismatch,
            },
            Vec::new(),
        ));
    }
    if !module_balances.is_zero() {
        return Ok((
            FifthLegacyBinaryModuleOperationsStatus::Unavailable {
                block_number: Some(evidence.through_block()),
                transaction_hash: None,
                reason: FifthLegacyBinaryModuleOperationsUnavailableReason::ModuleNotEmpty,
            },
            Vec::new(),
        ));
    }
    Ok((FifthLegacyBinaryModuleOperationsStatus::Matched, operations))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FundingCall {
    Pusd(U256),
    Position { id: B256, amount: U256 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModuleCall {
    Split { amount: U256 },
    Merge { amount: U256 },
    Redeem { position_id: B256, amount: U256 },
}

#[derive(Debug, Clone)]
struct ExpectedLog {
    address: String,
    topics: Vec<String>,
    data: String,
}

#[derive(Debug, Clone, Copy, Default)]
struct ModuleBalances {
    positions: [U256; 2],
    cash: U256,
}

impl ModuleBalances {
    fn is_zero(self) -> bool {
        self.positions == [U256::ZERO; 2] && self.cash.is_zero()
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct OwnerBalances {
    positions: [U256; 2],
    cash: U256,
}

fn unavailable(
    block: &ChainReceiptIntervalBlock,
    transaction: &super::ChainReceiptIntervalTransaction,
    reason: FifthLegacyBinaryModuleOperationsUnavailableReason,
) -> (
    FifthLegacyBinaryModuleOperationsStatus,
    Vec<FifthDirectModuleOperationFact>,
) {
    (
        FifthLegacyBinaryModuleOperationsStatus::Unavailable {
            block_number: Some(block.block_number()),
            transaction_hash: Some(transaction.transaction_hash().to_owned()),
            reason,
        },
        Vec::new(),
    )
}

fn owner_balances<P: ModuleOperationPoint>(point: &P) -> OwnerBalances {
    let selected = point.selected_balances();
    OwnerBalances {
        positions: [selected.position_balance_a(), selected.position_balance_b()],
        cash: selected.pusd_balance(),
    }
}

fn parse_module_call(
    input: &[u8],
    owner: Address,
    condition_id: B256,
    ids: [B256; 2],
) -> Option<ModuleCall> {
    let selector: [u8; 4] = input.get(..4)?.try_into().ok()?;
    let args = input.get(4..)?;
    match selector {
        MODULE_SPLIT => {
            if args.len() != 192
                || word_u256(args, 0)? != U256::from(96)
                || word_u256(args, 64)?.is_zero()
            {
                return None;
            }
            let condition = word_b256(args, 32)?;
            if condition[31] != 0
                || condition != condition_id
                || word_u256(args, 96)? != U256::from(2)
                || canonical_address_word(args, 128)? != owner
                || canonical_address_word(args, 160)? != owner
            {
                return None;
            }
            Some(ModuleCall::Split {
                amount: word_u256(args, 64)?,
            })
        }
        MODULE_MERGE => {
            if args.len() != 96
                || canonical_address_word(args, 0)? != owner
                || word_b256(args, 32)? != condition_id
                || condition_id[31] != 0
            {
                return None;
            }
            let amount = word_u256(args, 64)?;
            (!amount.is_zero()).then_some(ModuleCall::Merge { amount })
        }
        MODULE_REDEEM => {
            if args.len() != 96 || canonical_address_word(args, 0)? != owner {
                return None;
            }
            let id = B256::from(word_u256(args, 32)?.to_be_bytes::<32>());
            let amount = word_u256(args, 64)?;
            (ids.contains(&id) && !amount.is_zero()).then_some(ModuleCall::Redeem {
                position_id: id,
                amount,
            })
        }
        _ => None,
    }
}

fn parse_pusd_funding(input: &[u8], module: Address) -> Option<FundingCall> {
    if input.len() != 68 || input.get(..4)? != PUSD_TRANSFER {
        return None;
    }
    if canonical_address_word(&input[4..], 0)? != module {
        return None;
    }
    let amount = word_u256(&input[4..], 32)?;
    (!amount.is_zero()).then_some(FundingCall::Pusd(amount))
}

fn parse_position_funding(
    input: &[u8],
    owner: Address,
    module: Address,
    ids: [B256; 2],
) -> Option<FundingCall> {
    if input.len() != 4 + 6 * 32 || input.get(..4)? != PM_SAFE_TRANSFER_FROM {
        return None;
    }
    let args = &input[4..];
    if canonical_address_word(args, 0)? != owner
        || canonical_address_word(args, 32)? != module
        || word_u256(args, 128)? != U256::from(160)
        || word_u256(args, 160)? != U256::ZERO
    {
        return None;
    }
    let id = B256::from(word_u256(args, 64)?.to_be_bytes::<32>());
    let amount = word_u256(args, 96)?;
    (ids.contains(&id) && !amount.is_zero()).then_some(FundingCall::Position { id, amount })
}

fn word_u256(data: &[u8], offset: usize) -> Option<U256> {
    Some(U256::from_be_slice(
        data.get(offset..offset.checked_add(32)?)?,
    ))
}

fn word_b256(data: &[u8], offset: usize) -> Option<B256> {
    Some(B256::from_slice(data.get(offset..offset.checked_add(32)?)?))
}

fn canonical_address_word(data: &[u8], offset: usize) -> Option<Address> {
    let word = data.get(offset..offset.checked_add(32)?)?;
    if word[..12].iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(Address::from_slice(&word[12..]))
}

fn pending_matches(pending: &[FifthDirectModuleFundingFact], call: &ModuleCall) -> bool {
    match call {
        ModuleCall::Split { amount } => {
            !pending.is_empty()
                && pending
                    .iter()
                    .all(|item| item.asset == FifthDirectModuleFundingAsset::Pusd)
                && checked_sum(pending.iter().map(|item| item.amount)) == Some(*amount)
        }
        ModuleCall::Merge { amount } => {
            !pending.is_empty()
                && pending
                    .iter()
                    .all(|item| item.asset != FifthDirectModuleFundingAsset::Pusd)
                && checked_sum(
                    pending
                        .iter()
                        .filter(|item| item.asset == FifthDirectModuleFundingAsset::PositionA)
                        .map(|item| item.amount),
                ) == Some(*amount)
                && checked_sum(
                    pending
                        .iter()
                        .filter(|item| item.asset == FifthDirectModuleFundingAsset::PositionB)
                        .map(|item| item.amount),
                ) == Some(*amount)
        }
        ModuleCall::Redeem {
            position_id,
            amount,
        } => {
            !pending.is_empty()
                && pending
                    .iter()
                    .all(|item| item.position_id == Some(*position_id))
                && checked_sum(pending.iter().map(|item| item.amount)) == Some(*amount)
        }
    }
}

fn checked_sum(mut values: impl Iterator<Item = U256>) -> Option<U256> {
    values.try_fold(U256::ZERO, U256::checked_add)
}

fn expected_funding_logs(call: &FundingCall, owner: Address, module: Address) -> Vec<ExpectedLog> {
    match call {
        FundingCall::Pusd(amount) => vec![erc20_log(PUSD_PROXY, owner, module, *amount)],
        FundingCall::Position { id, amount } => vec![erc1155_log(
            POSITION_MANAGER_PROXY,
            owner,
            owner,
            module,
            U256::from_be_bytes(id.0),
            *amount,
        )],
    }
}

fn expected_operation_logs(
    call: &ModuleCall,
    payout: Option<U256>,
    owner: Address,
    module: Address,
    condition: B256,
    ids: [B256; 2],
) -> Result<Vec<ExpectedLog>, ChainLogAuditError> {
    let mut logs = Vec::new();
    match call {
        ModuleCall::Split { amount } => {
            logs.push(erc1155_log(
                POSITION_MANAGER_PROXY,
                module,
                Address::ZERO,
                owner,
                U256::from_be_bytes(ids[0].0),
                *amount,
            ));
            logs.push(erc1155_log(
                POSITION_MANAGER_PROXY,
                module,
                Address::ZERO,
                owner,
                U256::from_be_bytes(ids[1].0),
                *amount,
            ));
            logs.push(erc20_log(PUSD_PROXY, module, Address::ZERO, *amount));
            logs.push(module_event(
                module,
                POSITIONS_SPLIT_TOPIC,
                vec![
                    topic_address(owner),
                    topic_b256(condition),
                    topic_address(owner),
                ],
                vec![word_address(owner), word_u256_data(*amount)],
            ));
        }
        ModuleCall::Merge { amount } => {
            logs.push(erc20_log(PUSD_PROXY, Address::ZERO, owner, *amount));
            logs.push(erc1155_log(
                POSITION_MANAGER_PROXY,
                module,
                module,
                Address::ZERO,
                U256::from_be_bytes(ids[0].0),
                *amount,
            ));
            logs.push(erc1155_log(
                POSITION_MANAGER_PROXY,
                module,
                module,
                Address::ZERO,
                U256::from_be_bytes(ids[1].0),
                *amount,
            ));
            logs.push(module_event(
                module,
                POSITIONS_MERGED_TOPIC,
                vec![
                    topic_address(owner),
                    topic_b256(condition),
                    topic_address(owner),
                ],
                vec![word_u256_data(*amount)],
            ));
        }
        ModuleCall::Redeem {
            position_id,
            amount,
        } => {
            let payout = payout.ok_or(ChainLogAuditError::Unverified)?;
            let index = ids
                .iter()
                .position(|id| id == position_id)
                .ok_or(ChainLogAuditError::Unverified)?;
            logs.push(erc20_log(PUSD_PROXY, Address::ZERO, owner, payout));
            logs.push(erc1155_log(
                POSITION_MANAGER_PROXY,
                module,
                module,
                Address::ZERO,
                U256::from_be_bytes(position_id.0),
                *amount,
            ));
            let _ = index;
            logs.push(module_event(
                module,
                POSITION_REDEEMED_TOPIC,
                vec![
                    topic_address(owner),
                    topic_b256(*position_id),
                    topic_address(owner),
                ],
                vec![word_u256_data(*amount), word_u256_data(payout)],
            ));
        }
    }
    Ok(logs)
}

fn erc20_log(emitter: &str, from: Address, to: Address, amount: U256) -> ExpectedLog {
    ExpectedLog {
        address: emitter.to_owned(),
        topics: vec![
            ERC20_TRANSFER_TOPIC.to_owned(),
            topic_address(from),
            topic_address(to),
        ],
        data: word_u256_data(amount),
    }
}

fn erc1155_log(
    emitter: &str,
    operator: Address,
    from: Address,
    to: Address,
    id: U256,
    amount: U256,
) -> ExpectedLog {
    ExpectedLog {
        address: emitter.to_owned(),
        topics: vec![
            ERC1155_TRANSFER_SINGLE_TOPIC.to_owned(),
            topic_address(operator),
            topic_address(from),
            topic_address(to),
        ],
        data: format!(
            "0x{}{}",
            word_u256_data(id).trim_start_matches("0x"),
            word_u256_data(amount).trim_start_matches("0x")
        ),
    }
}

fn module_event(
    emitter: Address,
    topic: &str,
    indexed: Vec<String>,
    data_words: Vec<String>,
) -> ExpectedLog {
    let mut topics = vec![topic.to_owned()];
    topics.extend(indexed);
    let data = data_words.iter().fold(String::new(), |mut data, word| {
        data.push_str(word.trim_start_matches("0x"));
        data
    });
    ExpectedLog {
        address: format!("{emitter:#x}"),
        topics,
        data: format!("0x{data}"),
    }
}

fn topic_address(address: Address) -> String {
    format!("0x{:0>64}", hex::encode(address))
}
fn topic_b256(value: B256) -> String {
    format!("{value:#x}")
}
fn word_address(address: Address) -> String {
    topic_address(address)
}
fn word_u256_data(value: U256) -> String {
    format!("0x{}", hex::encode(value.to_be_bytes::<32>()))
}

fn exact_logs(actual: &[super::ChainReceiptLog], expected: &[ExpectedLog]) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            actual.address().eq_ignore_ascii_case(&expected.address)
                && actual.topics().len() == expected.topics.len()
                && actual
                    .topics()
                    .iter()
                    .zip(&expected.topics)
                    .all(|(left, right)| left.eq_ignore_ascii_case(right))
                && actual.data().eq_ignore_ascii_case(&expected.data)
        })
}

fn funding_fact(
    block_number: u64,
    block: &ChainReceiptIntervalBlock,
    transaction: &super::ChainReceiptIntervalTransaction,
    call: &FundingCall,
    ids: [B256; 2],
) -> FifthDirectModuleFundingFact {
    let (asset, position_id, amount) = match call {
        FundingCall::Pusd(amount) => (FifthDirectModuleFundingAsset::Pusd, None, *amount),
        FundingCall::Position { id, amount } => (
            if *id == ids[0] {
                FifthDirectModuleFundingAsset::PositionA
            } else {
                FifthDirectModuleFundingAsset::PositionB
            },
            Some(*id),
            *amount,
        ),
    };
    FifthDirectModuleFundingFact {
        transaction: locator(block_number, block, transaction),
        asset,
        position_id,
        amount,
    }
}

fn locator(
    block_number: u64,
    block: &ChainReceiptIntervalBlock,
    transaction: &super::ChainReceiptIntervalTransaction,
) -> FifthDirectModuleTransactionLocator {
    FifthDirectModuleTransactionLocator {
        block_number,
        block_hash: block.block_hash().to_owned(),
        transaction_hash: transaction.transaction_hash().to_owned(),
        transaction_index: transaction.transaction_index(),
    }
}

fn apply_funding(
    owner: &mut OwnerBalances,
    module: &mut ModuleBalances,
    call: &FundingCall,
    ids: [B256; 2],
) -> Result<(), ChainLogAuditError> {
    match call {
        FundingCall::Pusd(amount) => {
            owner.cash = owner
                .cash
                .checked_sub(*amount)
                .ok_or(ChainLogAuditError::Unverified)?;
            module.cash = module
                .cash
                .checked_add(*amount)
                .ok_or(ChainLogAuditError::Unverified)?;
        }
        FundingCall::Position { id, amount } => {
            let index = ids
                .iter()
                .position(|candidate| candidate == id)
                .ok_or(ChainLogAuditError::Unverified)?;
            owner.positions[index] = owner.positions[index]
                .checked_sub(*amount)
                .ok_or(ChainLogAuditError::Unverified)?;
            module.positions[index] = module.positions[index]
                .checked_add(*amount)
                .ok_or(ChainLogAuditError::Unverified)?;
        }
    }
    Ok(())
}

fn apply_operation(
    owner: &mut OwnerBalances,
    module: &mut ModuleBalances,
    fact: &FifthDirectModuleOperationFact,
    ids: [B256; 2],
) -> Result<(), ChainLogAuditError> {
    for index in 0..2 {
        owner.positions[index] = owner.positions[index]
            .checked_add(fact.owner_position_inflows[index])
            .ok_or(ChainLogAuditError::Unverified)?;
    }
    owner.cash = owner
        .cash
        .checked_add(fact.owner_pusd_inflow)
        .ok_or(ChainLogAuditError::Unverified)?;
    match fact.kind {
        FifthDirectModuleOperationKind::Split => {
            module.cash = module
                .cash
                .checked_sub(fact.amount)
                .ok_or(ChainLogAuditError::Unverified)?;
        }
        FifthDirectModuleOperationKind::Merge => {
            for balance in &mut module.positions {
                *balance = balance
                    .checked_sub(fact.amount)
                    .ok_or(ChainLogAuditError::Unverified)?;
            }
        }
        FifthDirectModuleOperationKind::Redeem => {
            let index = ids
                .iter()
                .position(|id| Some(*id) == fact.position_id)
                .ok_or(ChainLogAuditError::Unverified)?;
            module.positions[index] = module.positions[index]
                .checked_sub(fact.amount)
                .ok_or(ChainLogAuditError::Unverified)?;
        }
    }
    Ok(())
}

fn operation_fact(
    block: &ChainReceiptIntervalBlock,
    transaction: &super::ChainReceiptIntervalTransaction,
    call: ModuleCall,
    payout: Option<U256>,
    funding_transactions: Vec<FifthDirectModuleFundingFact>,
    condition_id: B256,
    ids: [B256; 2],
) -> FifthDirectModuleOperationFact {
    let (kind, condition_id, position_id, amount) = match call {
        ModuleCall::Split { amount } => (
            FifthDirectModuleOperationKind::Split,
            condition_id,
            None,
            amount,
        ),
        ModuleCall::Merge { amount } => (
            FifthDirectModuleOperationKind::Merge,
            condition_id,
            None,
            amount,
        ),
        ModuleCall::Redeem {
            position_id,
            amount,
        } => (
            FifthDirectModuleOperationKind::Redeem,
            condition_id,
            Some(position_id),
            amount,
        ),
    };
    let mut owner_position_inflows = [U256::ZERO; 2];
    let mut owner_position_outflows = [U256::ZERO; 2];
    let (owner_pusd_inflow, owner_pusd_outflow) = match kind {
        FifthDirectModuleOperationKind::Split => {
            owner_position_inflows = [amount; 2];
            (U256::ZERO, amount)
        }
        FifthDirectModuleOperationKind::Merge => {
            owner_position_outflows = [amount; 2];
            (amount, U256::ZERO)
        }
        FifthDirectModuleOperationKind::Redeem => {
            let index = usize::from(position_id == Some(ids[1]));
            owner_position_outflows[index] = amount;
            (payout.unwrap_or_default(), U256::ZERO)
        }
    };
    FifthDirectModuleOperationFact {
        kind,
        condition_id,
        position_id,
        amount,
        payout,
        owner_position_inflows,
        owner_position_outflows,
        owner_pusd_inflow,
        owner_pusd_outflow,
        funding_transactions,
        operation_transaction: locator(block.block_number(), block, transaction),
    }
}

fn transaction_has_relevant_movement(
    transaction: &super::ChainReceiptIntervalTransaction,
    owner: Address,
    module: Address,
    ids: [B256; 2],
) -> bool {
    transaction.movement_observations().iter().any(|movement| {
        let emitter = movement.emitter();
        let recognized = emitter.eq_ignore_ascii_case(PUSD_PROXY)
            || emitter.eq_ignore_ascii_case(POSITION_MANAGER_PROXY);
        if !recognized {
            return false;
        }
        match movement.status() {
            super::MovementObservationStatus::Unsupported(_) => true,
            super::MovementObservationStatus::Decoded(
                super::ObservedAssetMovement::Erc20Transfer { from, to, .. },
            ) => {
                emitter.eq_ignore_ascii_case(PUSD_PROXY)
                    && (address_equals(from, owner)
                        || address_equals(to, owner)
                        || address_equals(from, module)
                        || address_equals(to, module))
            }
            super::MovementObservationStatus::Decoded(
                super::ObservedAssetMovement::Erc1155TransferSingle { from, to, id, .. },
            ) => {
                emitter.eq_ignore_ascii_case(POSITION_MANAGER_PROXY)
                    && (address_equals(from, owner)
                        || address_equals(to, owner)
                        || address_equals(from, module)
                        || address_equals(to, module))
                    && ids
                        .iter()
                        .any(|candidate| U256::from_be_bytes(candidate.0) == *id)
            }
            super::MovementObservationStatus::Decoded(
                super::ObservedAssetMovement::Erc1155TransferBatch {
                    from,
                    to,
                    ids: moved,
                    ..
                },
            ) => {
                emitter.eq_ignore_ascii_case(POSITION_MANAGER_PROXY)
                    && (address_equals(from, owner)
                        || address_equals(to, owner)
                        || address_equals(from, module)
                        || address_equals(to, module))
                    && moved.iter().any(|id| {
                        ids.iter()
                            .any(|candidate| U256::from_be_bytes(candidate.0) == *id)
                    })
            }
        }
    })
}

fn address_equals(value: &str, address: Address) -> bool {
    value.eq_ignore_ascii_case(&format!("{address:#x}"))
}

fn compare_module_boundary<P: ModuleOperationPoint>(
    owner: &OwnerBalances,
    module: &ModuleBalances,
    point: &P,
) -> Option<(
    FifthDirectModuleOperationsHolder,
    FifthDirectModuleOperationsAsset,
    U256,
    U256,
)> {
    let selected = point.selected_balances();
    let owner_auth = [
        selected.position_balance_a(),
        selected.position_balance_b(),
        selected.pusd_balance(),
    ];
    let owner_replay = [owner.positions[0], owner.positions[1], owner.cash];
    let module_auth = [
        point.module_position_balances()[0],
        point.module_position_balances()[1],
        point.module_pusd_balance(),
    ];
    let module_replay = [module.positions[0], module.positions[1], module.cash];
    let assets = [
        FifthDirectModuleOperationsAsset::PositionA,
        FifthDirectModuleOperationsAsset::PositionB,
        FifthDirectModuleOperationsAsset::Pusd,
    ];
    for index in 0..3 {
        if owner_auth[index] != owner_replay[index] {
            return Some((
                FifthDirectModuleOperationsHolder::Owner,
                assets[index],
                owner_auth[index],
                owner_replay[index],
            ));
        }
        if module_auth[index] != module_replay[index] {
            return Some((
                FifthDirectModuleOperationsHolder::Module,
                assets[index],
                module_auth[index],
                module_replay[index],
            ));
        }
    }
    None
}

fn result_state_continues<P: ModuleOperationPoint>(
    previous: &P,
    current: &P,
    condition: B256,
    ids: [B256; 2],
) -> bool {
    previous.condition_id() == condition
        && current.condition_id() == condition
        && previous.position_ids() == ids
        && current.position_ids() == ids
        && previous.source_identity_continues(current)
}

fn has_relevant_upgrade_or_role_update(block: &ChainReceiptIntervalBlock, module: &str) -> bool {
    let upgraded = format!("0x{}", hex::encode(Keccak256::digest(b"Upgraded(address)")));
    let condition_resolution = "0xb44d84d3289691f71497564b85d4233648d9dbae8cbdbb4329f301c3a0185894";
    block.transactions().iter().any(|transaction| {
        transaction.logs().iter().any(|log| {
            let Some(topic) = log.topics().first() else {
                return false;
            };
            let emitter = log.address();
            (emitter.eq_ignore_ascii_case(POSITION_MANAGER_PROXY)
                || emitter.eq_ignore_ascii_case(PUSD_PROXY)
                || emitter.eq_ignore_ascii_case(module)
                || emitter.eq_ignore_ascii_case(super::fifth_code_context::EXCHANGE_PROXY))
                && topic.eq_ignore_ascii_case(&upgraded)
                || emitter.eq_ignore_ascii_case(module)
                    && ![
                        POSITIONS_SPLIT_TOPIC,
                        POSITIONS_MERGED_TOPIC,
                        POSITION_REDEEMED_TOPIC,
                    ]
                    .iter()
                    .any(|allowed| topic.eq_ignore_ascii_case(allowed))
                || emitter.eq_ignore_ascii_case(PUSD_PROXY)
                    && topic.eq_ignore_ascii_case(ROLES_UPDATED_TOPIC)
                || emitter.eq_ignore_ascii_case(super::CTF_CONDITIONAL_TOKENS_ADDRESS)
                    && topic.eq_ignore_ascii_case(condition_resolution)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn independent_canonical_call_vectors_decode_with_full_width_identity() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "artifacts/fifth-direct-module-call-vectors.json"
        ))
        .unwrap();
        assert_eq!(
            vectors["source_vectors_sha256"],
            "a1282a30aaea1e43234b6fd80a35b0aa9166fb8fb0ba6481c3e8aa4b7df52bb7"
        );
        use sha2::{Digest as _, Sha256};
        assert_eq!(
            hex::encode(Sha256::digest(include_bytes!(
                "artifacts/fifth-direct-module-call-vectors.json"
            ))),
            "a568748ad69e12cc98a030412148f2abb09fa0f4da535316609e567e1867f225"
        );
        let owner = Address::from_str("0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025").unwrap();
        let module = Address::from_str("0x3333333333333333333333333333333333333333").unwrap();
        let legacy = B256::repeat_byte(0x12);
        let condition =
            B256::from_str("0x0112121212121212121212121212121212000000000000000000000000000000")
                .unwrap();
        let mut derived_condition = [0_u8; 32];
        derived_condition[0] = 1;
        derived_condition[1..17].copy_from_slice(&legacy.as_slice()[16..]);
        assert_eq!(B256::from(derived_condition), condition);
        let mut derived_a = condition.0;
        derived_a[31] = 0;
        let mut derived_b = condition.0;
        derived_b[31] = 1;
        let ids = [B256::from(derived_a), B256::from(derived_b)];
        assert_eq!(
            format!("{:#x}", role_bitmap_key(module)),
            "0xf6882f2cabea9eb100ca4ed8847c87f0e39a87c5c6fd5c03c87ae070c084b7e2"
        );
        assert_eq!(
            format!("{:#x}", pusd_balance_key(module)),
            "0x0a5fdb825949145b03ce661f42727ba1f1ce871640f4c5d1fbd06ef66688fa13"
        );
        assert_eq!(
            format!("{:#x}", position_balance_key(module, ids[0])),
            "0xcda748dc0493e3da5980283f818de2b854ccfa0cb40ce5e7b5821cacb2e1809a"
        );
        for (name, expected) in [
            ("pusd-fund-split10", Some(FundingCall::Pusd(U256::from(10)))),
            (
                "pm-fund-a3",
                Some(FundingCall::Position {
                    id: ids[0],
                    amount: U256::from(3),
                }),
            ),
            (
                "pm-fund-b3",
                Some(FundingCall::Position {
                    id: ids[1],
                    amount: U256::from(3),
                }),
            ),
        ] {
            let input = vector_calldata(&vectors, name);
            let decoded = if name.starts_with("pusd") {
                parse_pusd_funding(&input, module)
            } else {
                parse_position_funding(&input, owner, module, ids)
            };
            assert_eq!(decoded, expected, "{name}");
        }
        for (name, expected) in [
            (
                "split-owner10",
                ModuleCall::Split {
                    amount: U256::from(10),
                },
            ),
            (
                "merge-owner3",
                ModuleCall::Merge {
                    amount: U256::from(3),
                },
            ),
            (
                "redeem-owner-a3",
                ModuleCall::Redeem {
                    position_id: ids[0],
                    amount: U256::from(3),
                },
            ),
            (
                "redeem-owner-b3",
                ModuleCall::Redeem {
                    position_id: ids[1],
                    amount: U256::from(3),
                },
            ),
        ] {
            assert_eq!(
                parse_module_call(&vector_calldata(&vectors, name), owner, condition, ids),
                Some(expected),
                "{name}"
            );
        }
        let mut noncanonical = vector_calldata(&vectors, "split-owner10");
        noncanonical[35] = 0x40;
        assert!(parse_module_call(&noncanonical, owner, condition, ids).is_none());
    }

    #[test]
    fn canonical_transfer_single_and_module_event_words_keep_abi_data_prefix_and_order() {
        let owner = Address::from_str("0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025").unwrap();
        let module = Address::from_str("0x3333333333333333333333333333333333333333").unwrap();
        let zero = Address::ZERO;
        let id = U256::from_be_slice(&[0x11; 32]);
        let amount = U256::from(3);
        let log = erc1155_log(POSITION_MANAGER_PROXY, module, zero, owner, id, amount);
        assert_eq!(log.topics[0], ERC1155_TRANSFER_SINGLE_TOPIC);
        assert_eq!(log.topics[1], topic_address(module));
        assert_eq!(log.topics[2], topic_address(zero));
        assert_eq!(log.topics[3], topic_address(owner));
        assert_eq!(log.data, format!("0x{}{amount:064x}", "11".repeat(32)));

        let split = module_event(
            module,
            POSITIONS_SPLIT_TOPIC,
            vec![
                topic_address(owner),
                "0x0112121212121212121212121212121212000000000000000000000000000000".to_owned(),
                topic_address(owner),
            ],
            vec![word_address(owner), word_u256_data(amount)],
        );
        assert_eq!(
            split.data,
            format!("0x{:0>64}{amount:064x}", hex::encode(owner))
        );
    }

    fn vector_calldata(vectors: &serde_json::Value, name: &str) -> Vec<u8> {
        let row = vectors["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == name)
            .unwrap();
        let calldata = row["calldata"].as_str().unwrap();
        let bytes = hex::decode(calldata.trim_start_matches("0x")).unwrap();
        assert_eq!(bytes.len(), row["byte_length"].as_u64().unwrap() as usize);
        bytes
    }
}
