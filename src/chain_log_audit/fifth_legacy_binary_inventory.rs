//! Receipt-rooted selected-balance replay for the source-bound legacy binary pair.
//! This is interval inventory evidence, not wallet-history completeness or P&L.

use super::fifth_code_context::{EXCHANGE_PROXY, POSITION_MANAGER_PROXY};
use super::fifth_legacy_binary_balances::{
    BoundedFifthLegacyBinaryBalancesError, FifthLegacyBinaryBalancesObservation,
};
use super::{
    ChainLogAuditError, ChainLogVerifier, ChainReceiptIntervalEvidence,
    CtfInventoryUnavailableReason, MovementObservationStatus, ObservedAssetMovement,
    TransactionRequestBudget, UnsupportedMovementReason, apply_ctf_owner_transfer, validate_hex,
};
use alloy_primitives::{Address, B256, U256};
use sha3::{Digest, Keccak256};
use std::time::Duration;
use thiserror::Error;
use tokio::time::Instant;

const PUSD_PROXY: &str = "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb";
const POLICY_VERSION: &str = "fifth-legacy-binary-receipt-interval-inventory/1";

pub const FIFTH_LEGACY_BINARY_INVENTORY_POLICY_VERSION: &str = POLICY_VERSION;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedFifthLegacyBinaryInventoryError {
    #[error("fifth legacy binary inventory RPC request budget exhausted")]
    RequestBudgetExceeded,
    #[error("fifth legacy binary inventory exceeded its total deadline")]
    Timeout,
    #[error(transparent)]
    Verification(#[from] ChainLogAuditError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthLegacyBinaryInventoryAsset {
    PositionA,
    PositionB,
    Pusd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthLegacyBinaryInventoryUnavailableReason {
    UnsupportedMovement(UnsupportedMovementReason),
    BalanceUnderflow,
    BalanceOverflow,
    UnexpectedMovementKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FifthLegacyBinaryInventoryStatus {
    Matched,
    Mismatch {
        block_number: u64,
        asset: FifthLegacyBinaryInventoryAsset,
        authenticated_balance: U256,
        reconstructed_balance: U256,
    },
    Unavailable {
        block_number: u64,
        asset: FifthLegacyBinaryInventoryAsset,
        reason: FifthLegacyBinaryInventoryUnavailableReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthLegacyBinaryInventoryObservation {
    evidence: ChainReceiptIntervalEvidence,
    opening: FifthLegacyBinaryBalancesObservation,
    block_observations: Vec<FifthLegacyBinaryBalancesObservation>,
    status: FifthLegacyBinaryInventoryStatus,
    selected_owner_transfer_entries: Option<[usize; 3]>,
}

impl FifthLegacyBinaryInventoryObservation {
    #[must_use]
    pub const fn evidence(&self) -> &ChainReceiptIntervalEvidence {
        &self.evidence
    }
    #[must_use]
    pub const fn opening(&self) -> &FifthLegacyBinaryBalancesObservation {
        &self.opening
    }
    #[must_use]
    pub fn block_observations(&self) -> &[FifthLegacyBinaryBalancesObservation] {
        &self.block_observations
    }
    #[must_use]
    pub const fn status(&self) -> &FifthLegacyBinaryInventoryStatus {
        &self.status
    }
    #[must_use]
    pub const fn selected_owner_transfer_entries(&self) -> Option<[usize; 3]> {
        self.selected_owner_transfer_entries
    }
    #[must_use]
    pub const fn source_policy_version(&self) -> &'static str {
        POLICY_VERSION
    }
}

impl ChainLogVerifier {
    /// Verify one complete receipt interval and reconcile the caller's selected
    /// legacy pair and pUSD balances at its opening and every block boundary.
    #[allow(clippy::too_many_arguments)]
    pub async fn verify_fifth_legacy_binary_inventory_interval_bounded(
        &self,
        owner: &str,
        legacy_condition_id: &str,
        from_block: u64,
        through_block: u64,
        expected_parent_hash: &str,
        expected_end_hash: &str,
        max_requests: usize,
        total_timeout: Duration,
    ) -> Result<FifthLegacyBinaryInventoryObservation, BoundedFifthLegacyBinaryInventoryError> {
        let owner = validate_hex(owner, 20).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let owner_bytes = hex::decode(&owner[2..]).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let legacy_condition_id = super::parse_fixed_b256(legacy_condition_id)
            .map_err(|_| ChainLogAuditError::InvalidInput)?;
        let expected_parent_hash =
            validate_hex(expected_parent_hash, 32).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let expected_end_hash =
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
        let deadline = Instant::now()
            .checked_add(total_timeout)
            .ok_or(ChainLogAuditError::InvalidInput)?;
        let budget = TransactionRequestBudget::new(max_requests);
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let scoped = self.with_request_budget(budget.inner());
        let owner_address = Address::from_slice(&owner_bytes);
        let verification = scoped.verify_fifth_legacy_binary_inventory_inner(
            owner,
            owner_address,
            legacy_condition_id,
            from_block,
            through_block,
            &expected_parent_hash,
            &expected_end_hash,
            deadline,
        );
        tokio::pin!(verification);
        let deadline_wait = tokio::time::sleep_until(deadline);
        tokio::pin!(deadline_wait);
        tokio::select! {
            biased;
            _ = exhaustion.wait_for(|is_exhausted| *is_exhausted) => {
                Err(BoundedFifthLegacyBinaryInventoryError::RequestBudgetExceeded)
            }
            () = &mut deadline_wait => {
                if budget.is_exhausted() {
                    Err(BoundedFifthLegacyBinaryInventoryError::RequestBudgetExceeded)
                } else {
                    Err(BoundedFifthLegacyBinaryInventoryError::Timeout)
                }
            }
            result = &mut verification => {
                if budget.is_exhausted() {
                    Err(BoundedFifthLegacyBinaryInventoryError::RequestBudgetExceeded)
                } else {
                    result
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn verify_fifth_legacy_binary_inventory_inner(
        &self,
        owner: String,
        owner_address: Address,
        legacy_condition_id: B256,
        from_block: u64,
        through_block: u64,
        expected_parent_hash: &str,
        expected_end_hash: &str,
        deadline: Instant,
    ) -> Result<FifthLegacyBinaryInventoryObservation, BoundedFifthLegacyBinaryInventoryError> {
        ensure_deadline(deadline)?;
        let evidence = self
            .verify_receipt_interval_inner(
                from_block,
                through_block,
                expected_parent_hash,
                expected_end_hash,
            )
            .await?;
        ensure_deadline(deadline)?;
        let opening = self
            .verify_fifth_legacy_binary_balances_inner(
                owner.clone(),
                owner_address,
                legacy_condition_id,
                from_block - 1,
                expected_parent_hash,
                deadline,
            )
            .await
            .map_err(map_point_error)?;
        validate_point(
            &opening,
            &owner,
            legacy_condition_id,
            from_block - 1,
            expected_parent_hash,
            None,
        )?;
        let mut observations: Vec<FifthLegacyBinaryBalancesObservation> =
            Vec::with_capacity(evidence.blocks.len());
        for block in evidence.blocks() {
            ensure_deadline(deadline)?;
            let observation = self
                .verify_fifth_legacy_binary_balances_inner(
                    owner.clone(),
                    owner_address,
                    legacy_condition_id,
                    block.block_number(),
                    block.block_hash(),
                    deadline,
                )
                .await
                .map_err(map_point_error)?;
            validate_point(
                &observation,
                &owner,
                legacy_condition_id,
                block.block_number(),
                block.block_hash(),
                Some(block.state_root()),
            )?;
            let previous = observations.last().unwrap_or(&opening);
            if !identity_continues(previous, &observation)
                || !super::ctf_condition_state::transition_is_valid(
                    previous.ctf_condition_state(),
                    observation.ctf_condition_state(),
                )
            {
                return Err(ChainLogAuditError::Unverified.into());
            }
            observations.push(observation);
        }
        ensure_deadline(deadline)?;
        reject_proxy_upgrade_topics(&evidence, opening.module_proxy())?;
        let (status, entries) =
            replay_selected_owner_inventory(&evidence, &owner, &opening, &observations)?;
        ensure_deadline(deadline)?;
        Ok(FifthLegacyBinaryInventoryObservation {
            evidence,
            opening,
            block_observations: observations,
            selected_owner_transfer_entries: matches!(
                &status,
                FifthLegacyBinaryInventoryStatus::Matched
            )
            .then_some(entries),
            status,
        })
    }
}

fn validate_point(
    observation: &FifthLegacyBinaryBalancesObservation,
    owner: &str,
    legacy_condition_id: B256,
    block_number: u64,
    block_hash: &str,
    state_root: Option<&str>,
) -> Result<(), ChainLogAuditError> {
    let selected = observation.selected_balances();
    if selected.owner() != owner
        || observation.legacy_condition_id() != legacy_condition_id
        || selected.block_number() != block_number
        || selected.block_hash() != block_hash
        || state_root.is_some_and(|root| selected.state_root() != root)
    {
        return Err(ChainLogAuditError::Unverified);
    }
    Ok(())
}

fn identity_continues(
    previous: &FifthLegacyBinaryBalancesObservation,
    current: &FifthLegacyBinaryBalancesObservation,
) -> bool {
    previous.legacy_condition_id() == current.legacy_condition_id()
        && previous.v2_condition_id() == current.v2_condition_id()
        && previous.v2_position_ids() == current.v2_position_ids()
        && previous.legacy_collection_ids() == current.legacy_collection_ids()
        && previous.legacy_position_ids() == current.legacy_position_ids()
        && previous.module_proxy() == current.module_proxy()
        && previous.module_implementation() == current.module_implementation()
        && previous.module_implementation_code_hash() == current.module_implementation_code_hash()
        && previous
            .selected_balances()
            .code_context()
            .exchange_implementation_version()
            == current
                .selected_balances()
                .code_context()
                .exchange_implementation_version()
}

fn reject_proxy_upgrade_topics(
    evidence: &ChainReceiptIntervalEvidence,
    module_proxy: Address,
) -> Result<(), ChainLogAuditError> {
    let upgraded_topic = format!("0x{}", hex::encode(Keccak256::digest(b"Upgraded(address)")));
    let module_proxy = format!("{module_proxy:#x}");
    for block in evidence.blocks() {
        for transaction in block.transactions() {
            for log in transaction.logs() {
                if ![
                    EXCHANGE_PROXY,
                    POSITION_MANAGER_PROXY,
                    PUSD_PROXY,
                    module_proxy.as_str(),
                ]
                .iter()
                .any(|proxy| log.address().eq_ignore_ascii_case(proxy))
                {
                    continue;
                }
                if log
                    .topics()
                    .first()
                    .is_some_and(|topic| topic.eq_ignore_ascii_case(&upgraded_topic))
                {
                    return Err(ChainLogAuditError::Unverified);
                }
            }
        }
    }
    Ok(())
}

fn replay_selected_owner_inventory(
    evidence: &ChainReceiptIntervalEvidence,
    owner: &str,
    opening: &FifthLegacyBinaryBalancesObservation,
    observations: &[FifthLegacyBinaryBalancesObservation],
) -> Result<(FifthLegacyBinaryInventoryStatus, [usize; 3]), ChainLogAuditError> {
    if evidence.blocks().len() != observations.len() {
        return Err(ChainLogAuditError::Unverified);
    }
    let pm = POSITION_MANAGER_PROXY;
    let pusd = PUSD_PROXY;
    let mut reconstructed = [
        opening.selected_balances().position_balance_a(),
        opening.selected_balances().position_balance_b(),
        opening.selected_balances().pusd_balance(),
    ];
    let mut entries = [0_usize; 3];
    let mut first_mismatch = None;
    for (block, point) in evidence.blocks().iter().zip(observations) {
        for transaction in block.transactions() {
            for movement in transaction.movement_observations() {
                let emitter = movement.emitter();
                let is_pm = emitter.eq_ignore_ascii_case(pm);
                let is_pusd = emitter.eq_ignore_ascii_case(pusd);
                if !is_pm && !is_pusd {
                    continue;
                }
                match movement.status() {
                    MovementObservationStatus::Unsupported(reason) => {
                        let asset = if is_pusd {
                            FifthLegacyBinaryInventoryAsset::Pusd
                        } else {
                            FifthLegacyBinaryInventoryAsset::PositionA
                        };
                        return Ok((
                            FifthLegacyBinaryInventoryStatus::Unavailable {
                                block_number: block.block_number(),
                                asset,
                                reason: FifthLegacyBinaryInventoryUnavailableReason::UnsupportedMovement(*reason),
                            },
                            entries,
                        ));
                    }
                    MovementObservationStatus::Decoded(observation) if is_pm => {
                        match observation {
                            ObservedAssetMovement::Erc1155TransferSingle { from, to, id, amount, .. } => {
                                let Some(index) = selected_position_index(opening, *id) else { continue; };
                                if let Err(status) = apply_selected_transfer(owner, from, to, *amount, index, block.block_number(), position_asset(index), &mut reconstructed, &mut entries) { return Ok((status, entries)); }
                            }
                            ObservedAssetMovement::Erc1155TransferBatch { from, to, ids, amounts, .. } => {
                                if ids.len() != amounts.len() {
                                    return Err(ChainLogAuditError::Unverified);
                                }
                                for (id, amount) in ids.iter().copied().zip(amounts.iter().copied()) {
                                    let Some(index) = selected_position_index(opening, id) else { continue; };
                                    if let Err(status) = apply_selected_transfer(owner, from, to, amount, index, block.block_number(), position_asset(index), &mut reconstructed, &mut entries) { return Ok((status, entries)); }
                                }
                            }
                            _ => return Ok((
                                FifthLegacyBinaryInventoryStatus::Unavailable {
                                    block_number: block.block_number(),
                                    asset: FifthLegacyBinaryInventoryAsset::PositionA,
                                    reason: FifthLegacyBinaryInventoryUnavailableReason::UnexpectedMovementKind,
                                },
                                entries,
                            )),
                        }
                    }
                    MovementObservationStatus::Decoded(ObservedAssetMovement::Erc20Transfer { from, to, amount }) if is_pusd => {
                        if let Err(status) = apply_selected_transfer(owner, from, to, *amount, 2, block.block_number(), FifthLegacyBinaryInventoryAsset::Pusd, &mut reconstructed, &mut entries) { return Ok((status, entries)); }
                    }
                    MovementObservationStatus::Decoded(_) => {
                        let asset = if is_pusd {
                            FifthLegacyBinaryInventoryAsset::Pusd
                        } else {
                            FifthLegacyBinaryInventoryAsset::PositionA
                        };
                        return Ok((
                            FifthLegacyBinaryInventoryStatus::Unavailable {
                                block_number: block.block_number(),
                                asset,
                                reason: FifthLegacyBinaryInventoryUnavailableReason::UnexpectedMovementKind,
                            },
                            entries,
                        ));
                    }
                }
            }
        }
        let authenticated = [
            point.selected_balances().position_balance_a(),
            point.selected_balances().position_balance_b(),
            point.selected_balances().pusd_balance(),
        ];
        for index in 0..3 {
            if reconstructed[index] != authenticated[index] && first_mismatch.is_none() {
                first_mismatch = Some(FifthLegacyBinaryInventoryStatus::Mismatch {
                    block_number: block.block_number(),
                    asset: inventory_asset(index),
                    authenticated_balance: authenticated[index],
                    reconstructed_balance: reconstructed[index],
                });
            }
        }
    }
    Ok((
        first_mismatch.unwrap_or(FifthLegacyBinaryInventoryStatus::Matched),
        entries,
    ))
}

fn selected_position_index(
    opening: &FifthLegacyBinaryBalancesObservation,
    id: U256,
) -> Option<usize> {
    if id == U256::from_be_bytes(opening.v2_position_ids()[0].0) {
        Some(0)
    } else if id == U256::from_be_bytes(opening.v2_position_ids()[1].0) {
        Some(1)
    } else {
        None
    }
}

fn position_asset(index: usize) -> FifthLegacyBinaryInventoryAsset {
    if index == 0 {
        FifthLegacyBinaryInventoryAsset::PositionA
    } else {
        FifthLegacyBinaryInventoryAsset::PositionB
    }
}

fn inventory_asset(index: usize) -> FifthLegacyBinaryInventoryAsset {
    match index {
        0 => FifthLegacyBinaryInventoryAsset::PositionA,
        1 => FifthLegacyBinaryInventoryAsset::PositionB,
        _ => FifthLegacyBinaryInventoryAsset::Pusd,
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_selected_transfer(
    owner: &str,
    from: &str,
    to: &str,
    amount: U256,
    asset_index: usize,
    block_number: u64,
    asset: FifthLegacyBinaryInventoryAsset,
    reconstructed: &mut [U256; 3],
    entries: &mut [usize; 3],
) -> Result<(), FifthLegacyBinaryInventoryStatus> {
    if from.eq_ignore_ascii_case(owner) || to.eq_ignore_ascii_case(owner) {
        entries[asset_index] = entries[asset_index].checked_add(1).ok_or(
            FifthLegacyBinaryInventoryStatus::Unavailable {
                block_number,
                asset,
                reason: FifthLegacyBinaryInventoryUnavailableReason::BalanceOverflow,
            },
        )?;
    }
    reconstructed[asset_index] =
        match apply_ctf_owner_transfer(reconstructed[asset_index], owner, from, to, amount) {
            Ok(balance) => balance,
            Err(CtfInventoryUnavailableReason::BalanceUnderflow) => {
                return Err(FifthLegacyBinaryInventoryStatus::Unavailable {
                    block_number,
                    asset,
                    reason: FifthLegacyBinaryInventoryUnavailableReason::BalanceUnderflow,
                });
            }
            Err(CtfInventoryUnavailableReason::BalanceOverflow) => {
                return Err(FifthLegacyBinaryInventoryStatus::Unavailable {
                    block_number,
                    asset,
                    reason: FifthLegacyBinaryInventoryUnavailableReason::BalanceOverflow,
                });
            }
            Err(CtfInventoryUnavailableReason::UnsupportedMovement(reason)) => {
                return Err(FifthLegacyBinaryInventoryStatus::Unavailable {
                    block_number,
                    asset,
                    reason: FifthLegacyBinaryInventoryUnavailableReason::UnsupportedMovement(
                        reason,
                    ),
                });
            }
        };
    Ok(())
}

fn map_point_error(
    error: BoundedFifthLegacyBinaryBalancesError,
) -> BoundedFifthLegacyBinaryInventoryError {
    match error {
        BoundedFifthLegacyBinaryBalancesError::RequestBudgetExceeded => {
            BoundedFifthLegacyBinaryInventoryError::RequestBudgetExceeded
        }
        BoundedFifthLegacyBinaryBalancesError::Timeout => {
            BoundedFifthLegacyBinaryInventoryError::Timeout
        }
        BoundedFifthLegacyBinaryBalancesError::Verification(error) => {
            BoundedFifthLegacyBinaryInventoryError::Verification(error)
        }
    }
}

fn ensure_deadline(deadline: Instant) -> Result<(), BoundedFifthLegacyBinaryInventoryError> {
    if Instant::now() >= deadline {
        Err(BoundedFifthLegacyBinaryInventoryError::Timeout)
    } else {
        Ok(())
    }
}
