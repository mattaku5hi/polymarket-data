//! Root-bound read-only proof of a legacy-mapped BinaryModule result.

use super::fifth_legacy_binary_balances::{
    BoundedFifthLegacyBinaryBalancesError, FifthLegacyBinaryBalancesObservation,
};
use super::{
    ChainLogAuditError, ChainLogVerifier, TransactionRequestBudget, exact_eip1186_storage_entries,
    field, parse_eip1186_storage_value, parse_fixed_b256, rlp_u256, validate_hex,
    verify_eip1186_account_proof, verify_eip1186_storage_proof,
};
use alloy_primitives::{Address, B256, U256};
use serde_json::json;
use sha3::{Digest, Keccak256};
use std::time::Duration;
use thiserror::Error;
use tokio::time::Instant;

const MODULE_PROXY_CODE_HASH: &str =
    "0xaaa52c8cc8a0e3fd27ce756cc6b4e70c51423e9b597b11f32d3e49f8b1fc890d";
const RESULT_MAPPING_SLOT: u8 = 50;
const PAYOUT_DENOMINATOR: U256 = U256::from_limbs([1_000_000, 0, 0, 0]);
const POLICY_VERSION: &str = "fifth-legacy-binary-module-stored-result-proof/1";

pub const FIFTH_LEGACY_BINARY_RESULT_POLICY_VERSION: &str = POLICY_VERSION;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedFifthLegacyBinaryResultError {
    #[error("fifth legacy binary result RPC request budget exhausted")]
    RequestBudgetExceeded,
    #[error("fifth legacy binary result exceeded its total deadline")]
    Timeout,
    #[error(transparent)]
    Verification(#[from] ChainLogAuditError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthLegacyBinaryResultStatus {
    StoredUnresolved,
    ResolvedBinary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthLegacyBinaryResultObservation {
    balances: FifthLegacyBinaryBalancesObservation,
    status: FifthLegacyBinaryResultStatus,
    result_length: U256,
    normalized_numerators: Option<[U256; 2]>,
    storage_keys: [B256; 3],
}

impl FifthLegacyBinaryResultObservation {
    #[must_use]
    pub const fn balances(&self) -> &FifthLegacyBinaryBalancesObservation {
        &self.balances
    }

    #[must_use]
    pub const fn status(&self) -> &FifthLegacyBinaryResultStatus {
        &self.status
    }

    #[must_use]
    pub const fn result_length(&self) -> U256 {
        self.result_length
    }

    #[must_use]
    pub const fn payout_denominator(&self) -> U256 {
        PAYOUT_DENOMINATOR
    }

    #[must_use]
    pub const fn normalized_numerators(&self) -> Option<[U256; 2]> {
        self.normalized_numerators
    }

    #[must_use]
    pub const fn storage_keys(&self) -> [B256; 3] {
        self.storage_keys
    }

    #[must_use]
    pub const fn source_policy_version(&self) -> &'static str {
        POLICY_VERSION
    }
}

impl ChainLogVerifier {
    /// Prove the stored BinaryModule result at the same root as the legacy
    /// identity, selected balances and CTF payout state.
    #[allow(clippy::too_many_arguments)]
    pub async fn verify_fifth_legacy_binary_result_bounded(
        &self,
        owner: &str,
        legacy_condition_id: &str,
        block: u64,
        expected_hash: &str,
        max_requests: usize,
        total_timeout: Duration,
    ) -> Result<FifthLegacyBinaryResultObservation, BoundedFifthLegacyBinaryResultError> {
        let owner = validate_hex(owner, 20).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let owner_bytes = hex::decode(&owner[2..]).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let legacy_condition_id =
            parse_fixed_b256(legacy_condition_id).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let expected_hash =
            validate_hex(expected_hash, 32).map_err(|_| ChainLogAuditError::InvalidInput)?;
        if owner_bytes.iter().all(|byte| *byte == 0) || max_requests == 0 || total_timeout.is_zero()
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
        let verification = scoped.verify_fifth_legacy_binary_result_inner(
            owner,
            owner_address,
            legacy_condition_id,
            block,
            &expected_hash,
            deadline,
        );
        tokio::pin!(verification);
        let deadline_wait = tokio::time::sleep_until(deadline);
        tokio::pin!(deadline_wait);
        tokio::select! {
            biased;
            _ = exhaustion.wait_for(|is_exhausted| *is_exhausted) => {
                Err(BoundedFifthLegacyBinaryResultError::RequestBudgetExceeded)
            }
            () = &mut deadline_wait => {
                if budget.is_exhausted() {
                    Err(BoundedFifthLegacyBinaryResultError::RequestBudgetExceeded)
                } else {
                    Err(BoundedFifthLegacyBinaryResultError::Timeout)
                }
            }
            result = &mut verification => {
                if budget.is_exhausted() {
                    Err(BoundedFifthLegacyBinaryResultError::RequestBudgetExceeded)
                } else if Instant::now() >= deadline {
                    Err(BoundedFifthLegacyBinaryResultError::Timeout)
                } else {
                    result
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn verify_fifth_legacy_binary_result_inner(
        &self,
        owner: String,
        owner_address: Address,
        legacy_condition_id: B256,
        block: u64,
        expected_hash: &str,
        deadline: Instant,
    ) -> Result<FifthLegacyBinaryResultObservation, BoundedFifthLegacyBinaryResultError> {
        let balances = self
            .verify_fifth_legacy_binary_balances_inner(
                owner,
                owner_address,
                legacy_condition_id,
                block,
                expected_hash,
                deadline,
            )
            .await
            .map_err(map_balances_error)?;
        ensure_deadline(deadline)?;
        let keys = result_storage_keys(balances.v2_condition_id())?;
        let (primary, secondary) = tokio::try_join!(
            result_storage_proof(self, &self.primary, &balances, block, keys),
            result_storage_proof(self, &self.secondary, &balances, block, keys),
        )?;
        ensure_deadline(deadline)?;
        if primary != secondary {
            return Err(ChainLogAuditError::Divergent.into());
        }
        let result_length = primary[0];
        let (status, normalized_numerators) = match result_length {
            length if length.is_zero() => (FifthLegacyBinaryResultStatus::StoredUnresolved, None),
            length if length == U256::from(2) => {
                let numerators = [primary[1], primary[2]];
                validate_stored_result(&balances, numerators)?;
                (
                    FifthLegacyBinaryResultStatus::ResolvedBinary,
                    Some(numerators),
                )
            }
            _ => return Err(ChainLogAuditError::Unverified.into()),
        };
        ensure_deadline(deadline)?;
        Ok(FifthLegacyBinaryResultObservation {
            balances,
            status,
            result_length,
            normalized_numerators,
            storage_keys: keys,
        })
    }
}

async fn result_storage_proof(
    verifier: &ChainLogVerifier,
    endpoint: &str,
    balances: &FifthLegacyBinaryBalancesObservation,
    block: u64,
    keys: [B256; 3],
) -> Result<[U256; 3], ChainLogAuditError> {
    let proxy = balances.module_proxy();
    let state_root = balances.selected_balances().state_root();
    let proof = verifier
        .rpc(
            endpoint,
            "eth_getProof",
            json!([
                format!("{proxy:#x}"),
                keys.iter()
                    .map(|key| format!("{key:#x}"))
                    .collect::<Vec<_>>(),
                format!("{block:#x}")
            ]),
        )
        .await?;
    let account = verify_eip1186_account_proof(state_root, &format!("{proxy:#x}"), &proof)?;
    if account.code_hash != parse_fixed_b256(MODULE_PROXY_CODE_HASH)? {
        return Err(ChainLogAuditError::Unverified);
    }
    let entries = exact_eip1186_storage_entries(&proof, &keys)?;
    let mut values = [U256::ZERO; 3];
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

pub(super) fn result_storage_keys(condition: B256) -> Result<[B256; 3], ChainLogAuditError> {
    let mut preimage = [0_u8; 64];
    preimage[..31].copy_from_slice(&condition.as_slice()[..31]);
    preimage[63] = RESULT_MAPPING_SLOT;
    let head = B256::from_slice(&Keccak256::digest(preimage));
    let first = B256::from_slice(&Keccak256::digest(head.as_slice()));
    let first_word = U256::from_be_bytes(first.0);
    let second = first_word
        .checked_add(U256::ONE)
        .map(|value| B256::from(value.to_be_bytes::<32>()))
        .ok_or(ChainLogAuditError::Unverified)?;
    Ok([head, first, second])
}

fn validate_stored_result(
    balances: &FifthLegacyBinaryBalancesObservation,
    stored: [U256; 2],
) -> Result<(), ChainLogAuditError> {
    if stored[0].checked_add(stored[1]) != Some(PAYOUT_DENOMINATOR) {
        return Err(ChainLogAuditError::Unverified);
    }
    let ctf = balances.ctf_condition_state();
    if ctf.status() != super::CtfConditionStateStatus::ResolvedBinary {
        return Err(ChainLogAuditError::Unverified);
    }
    let ctf_numerators = ctf.payout_numerators();
    let denominator = ctf_numerators[0]
        .checked_add(ctf_numerators[1])
        .filter(|sum| !sum.is_zero())
        .ok_or(ChainLogAuditError::Unverified)?;
    if denominator != ctf.payout_denominator() {
        return Err(ChainLogAuditError::Unverified);
    }
    if stored != source_normalized_payouts(ctf_numerators)? {
        return Err(ChainLogAuditError::Unverified);
    }
    Ok(())
}

fn source_normalized_payouts(ctf_numerators: [U256; 2]) -> Result<[U256; 2], ChainLogAuditError> {
    let denominator = ctf_numerators[0]
        .checked_add(ctf_numerators[1])
        .filter(|sum| !sum.is_zero())
        .ok_or(ChainLogAuditError::Unverified)?;
    let first = ctf_numerators[0]
        .checked_mul(PAYOUT_DENOMINATOR)
        .ok_or(ChainLogAuditError::Unverified)?
        / denominator;
    let second = PAYOUT_DENOMINATOR
        .checked_sub(first)
        .ok_or(ChainLogAuditError::Unverified)?;
    Ok([first, second])
}

fn map_balances_error(
    error: BoundedFifthLegacyBinaryBalancesError,
) -> BoundedFifthLegacyBinaryResultError {
    match error {
        BoundedFifthLegacyBinaryBalancesError::RequestBudgetExceeded => {
            BoundedFifthLegacyBinaryResultError::RequestBudgetExceeded
        }
        BoundedFifthLegacyBinaryBalancesError::Timeout => {
            BoundedFifthLegacyBinaryResultError::Timeout
        }
        BoundedFifthLegacyBinaryBalancesError::Verification(error) => {
            BoundedFifthLegacyBinaryResultError::Verification(error)
        }
    }
}

fn ensure_deadline(deadline: Instant) -> Result<(), BoundedFifthLegacyBinaryResultError> {
    if Instant::now() >= deadline {
        Err(BoundedFifthLegacyBinaryResultError::Timeout)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_layout_key_and_checked_normalization_vectors_match_goldens() {
        use std::str::FromStr;

        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "artifacts/fifth-legacy-module-result-source-vectors.json"
        ))
        .unwrap();
        assert_eq!(
            vectors["source_commit"],
            "741f8bbe88c3f29a1c55d1248a3dd411f622f111"
        );
        assert_eq!(vectors["compiler_result_storage_entry"]["slot"], "50");
        assert_eq!(
            vectors["compiler_mapping_type"]["key"],
            "t_userDefinedValueType(ConditionId)5366"
        );
        assert_eq!(
            vectors["compiler_mapping_type"]["value"],
            "t_array(t_uint256)dyn_storage"
        );
        let condition = B256::from_slice(
            &hex::decode(
                vectors["v2_condition_word"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
            )
            .unwrap(),
        );
        let actual_keys = result_storage_keys(condition).unwrap();
        let expected_keys = vectors["storage_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| {
                B256::from_slice(
                    &hex::decode(key.as_str().unwrap().trim_start_matches("0x")).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(actual_keys.as_slice(), expected_keys.as_slice());

        for vector in vectors["normalization_vectors"].as_array().unwrap() {
            let pair = vector["ctf_numerators"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| U256::from_str(value.as_str().unwrap()).unwrap())
                .collect::<Vec<_>>();
            let numerators = [pair[0], pair[1]];
            if vector["module_result"].is_array() {
                let expected = vector["module_result"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| U256::from_str(value.as_str().unwrap()).unwrap())
                    .collect::<Vec<_>>();
                assert_eq!(
                    source_normalized_payouts(numerators).unwrap(),
                    [expected[0], expected[1]]
                );
            } else {
                assert!(source_normalized_payouts(numerators).is_err());
            }
        }
    }
}
