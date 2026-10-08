//! Root-bound point evidence for the source-defined native BinaryModule.
//!
//! This proves current code, storage, and selected balances at one caller-anchored
//! root. It does not prove historical creation, the truncated hash preimage, or
//! market semantics.

use super::fifth_code_context::{ERC1967_IMPLEMENTATION_SLOT, POSITION_MANAGER_PROXY};
use super::fifth_legacy_binary_balances::{MODULE_PROXY_CODE_HASH, expected_runtime_hash};
use super::fifth_legacy_binary_result::result_storage_keys;
use super::fifth_selected_balances::{
    BoundedFifthSelectedBalancesError, FifthSelectedBalancesObservation,
};
use super::{
    ChainLogAuditError, ChainLogVerifier, TransactionRequestBudget, exact_eip1186_storage_entries,
    field, parse_eip1186_storage_value, parse_fixed_b256, rlp_u256, validate_hex,
    verify_eip1186_account_proof, verify_eip1186_storage_proof,
};
use alloy_primitives::{Address, B256, U256};
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};
use std::{str::FromStr, time::Duration};
use thiserror::Error;
use tokio::time::Instant;

const MODULE_REGISTRY_ID: U256 = U256::ONE;
const MODULE_REGISTRY_SLOT: U256 = U256::ZERO;
const MODULE_LEGACY_MAPPING_SLOT: u64 = 150;
const POLICY_VERSION: &str = "fifth-native-binary-current-point-context-and-result/1";
const PAYOUT_DENOMINATOR: U256 = U256::from_limbs([1_000_000, 0, 0, 0]);
const PUSD_PROXY: &str = "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb";

pub const FIFTH_NATIVE_BINARY_POLICY_VERSION: &str = POLICY_VERSION;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedFifthNativeBinaryError {
    #[error("fifth native Binary point RPC request budget exhausted")]
    RequestBudgetExceeded,
    #[error("fifth native Binary point exceeded its total deadline")]
    Timeout,
    #[error(transparent)]
    Verification(#[from] ChainLogAuditError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthNativeBinaryResultStatus {
    StoredUnresolved,
    ResolvedBinary,
}

/// Sealed current-point evidence. No public constructor or serialization path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthNativeBinaryObservation {
    selected_balances: FifthSelectedBalancesObservation,
    module_proxy: Address,
    module_implementation: Address,
    module_implementation_code_hash: B256,
    result_status: FifthNativeBinaryResultStatus,
    result_length: U256,
    normalized_numerators: Option<[U256; 2]>,
    storage_keys: [B256; 4],
}

impl FifthNativeBinaryObservation {
    #[must_use]
    pub const fn selected_balances(&self) -> &FifthSelectedBalancesObservation {
        &self.selected_balances
    }

    #[must_use]
    pub const fn condition_id(&self) -> B256 {
        self.selected_balances.position_id_a()
    }

    #[must_use]
    pub const fn position_ids(&self) -> [B256; 2] {
        [
            self.selected_balances.position_id_a(),
            self.selected_balances.position_id_b(),
        ]
    }

    #[must_use]
    pub const fn module_proxy(&self) -> Address {
        self.module_proxy
    }

    #[must_use]
    pub const fn module_implementation(&self) -> Address {
        self.module_implementation
    }

    #[must_use]
    pub const fn module_implementation_code_hash(&self) -> B256 {
        self.module_implementation_code_hash
    }

    /// This is a verified zero mapping value at this point, not a history claim.
    #[must_use]
    pub const fn legacy_mapping_value(&self) -> U256 {
        U256::ZERO
    }

    #[must_use]
    pub const fn result_status(&self) -> FifthNativeBinaryResultStatus {
        self.result_status
    }

    #[must_use]
    pub const fn result_length(&self) -> U256 {
        self.result_length
    }

    #[must_use]
    pub const fn normalized_numerators(&self) -> Option<[U256; 2]> {
        self.normalized_numerators
    }

    #[must_use]
    pub const fn payout_denominator(&self) -> U256 {
        PAYOUT_DENOMINATOR
    }

    /// Mapping head, array length, numerator zero, numerator one.
    #[must_use]
    pub const fn storage_keys(&self) -> [B256; 4] {
        self.storage_keys
    }

    #[must_use]
    pub const fn source_policy_version(&self) -> &'static str {
        POLICY_VERSION
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderNativeBinary {
    module_proxy: Address,
    implementation: Address,
    implementation_code_hash: B256,
    result_length: U256,
    numerators: Option<[U256; 2]>,
}

impl ChainLogVerifier {
    /// Prove the native Binary condition context and the selected owner's current balances.
    #[allow(clippy::too_many_arguments)]
    pub async fn verify_fifth_native_binary_bounded(
        &self,
        owner: &str,
        condition_id: &str,
        block: u64,
        expected_hash: &str,
        max_requests: usize,
        total_timeout: Duration,
    ) -> Result<FifthNativeBinaryObservation, BoundedFifthNativeBinaryError> {
        let owner = validate_hex(owner, 20).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let owner_bytes = hex::decode(&owner[2..]).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let condition_id =
            parse_fixed_b256(condition_id).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let expected_hash =
            validate_hex(expected_hash, 32).map_err(|_| ChainLogAuditError::InvalidInput)?;
        if owner_bytes.iter().all(|byte| *byte == 0)
            || max_requests == 0
            || total_timeout.is_zero()
            || !is_canonical_native_binary_condition(condition_id)
        {
            return Err(ChainLogAuditError::InvalidInput.into());
        }
        let owner_address = Address::from_slice(&owner_bytes);
        let position_ids = [condition_id, derive_position_id(condition_id, 1)];
        let deadline = Instant::now()
            .checked_add(total_timeout)
            .ok_or(ChainLogAuditError::InvalidInput)?;
        let budget = TransactionRequestBudget::new(max_requests);
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let scoped = self.with_request_budget(budget.inner());
        let verification = scoped.verify_fifth_native_binary_inner(
            owner,
            owner_address,
            condition_id,
            position_ids,
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
                Err(BoundedFifthNativeBinaryError::RequestBudgetExceeded)
            }
            () = &mut deadline_wait => {
                if budget.is_exhausted() {
                    Err(BoundedFifthNativeBinaryError::RequestBudgetExceeded)
                } else {
                    Err(BoundedFifthNativeBinaryError::Timeout)
                }
            }
            result = &mut verification => {
                if budget.is_exhausted() {
                    Err(BoundedFifthNativeBinaryError::RequestBudgetExceeded)
                } else if Instant::now() >= deadline {
                    Err(BoundedFifthNativeBinaryError::Timeout)
                } else {
                    result
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn verify_fifth_native_binary_inner(
        &self,
        owner: String,
        owner_address: Address,
        condition_id: B256,
        position_ids: [B256; 2],
        block: u64,
        expected_hash: &str,
        deadline: Instant,
    ) -> Result<FifthNativeBinaryObservation, BoundedFifthNativeBinaryError> {
        ensure_deadline(deadline)?;
        let selected_balances = self
            .verify_fifth_selected_balances_inner(
                owner,
                owner_address,
                position_ids[0],
                position_ids[1],
                block,
                expected_hash,
                deadline,
            )
            .await
            .map_err(map_selected_error)?;
        ensure_deadline(deadline)?;
        if selected_balances.position_id_a() != condition_id
            || selected_balances.position_id_b() != position_ids[1]
        {
            return Err(ChainLogAuditError::Unverified.into());
        }
        let (primary, secondary) = tokio::try_join!(
            native_binary_provider(self, &self.primary, block, &selected_balances, condition_id),
            native_binary_provider(
                self,
                &self.secondary,
                block,
                &selected_balances,
                condition_id
            ),
        )?;
        ensure_deadline(deadline)?;
        if primary != secondary {
            return Err(ChainLogAuditError::Divergent.into());
        }
        let result_status = if primary.result_length.is_zero() {
            FifthNativeBinaryResultStatus::StoredUnresolved
        } else {
            FifthNativeBinaryResultStatus::ResolvedBinary
        };
        let mapping_key = mapping_key_bytes31(condition_id, MODULE_LEGACY_MAPPING_SLOT);
        let result_keys = result_storage_keys(condition_id)?;
        ensure_deadline(deadline)?;
        Ok(FifthNativeBinaryObservation {
            selected_balances,
            module_proxy: primary.module_proxy,
            module_implementation: primary.implementation,
            module_implementation_code_hash: primary.implementation_code_hash,
            result_status,
            result_length: primary.result_length,
            normalized_numerators: primary.numerators,
            storage_keys: [mapping_key, result_keys[0], result_keys[1], result_keys[2]],
        })
    }
}

async fn native_binary_provider(
    verifier: &ChainLogVerifier,
    endpoint: &str,
    block: u64,
    selected: &FifthSelectedBalancesObservation,
    condition_id: B256,
) -> Result<ProviderNativeBinary, ChainLogAuditError> {
    let state_root = selected.state_root();
    let pm_proxy = POSITION_MANAGER_PROXY;
    let registry_key = mapping_key_u256(MODULE_REGISTRY_ID, MODULE_REGISTRY_SLOT);
    let registry_proof = verifier
        .rpc(
            endpoint,
            "eth_getProof",
            json!([
                pm_proxy,
                [format!("{registry_key:#x}")],
                format!("{block:#x}")
            ]),
        )
        .await?;
    let registry_account = verify_eip1186_account_proof(state_root, pm_proxy, &registry_proof)?;
    if registry_account.code_hash != parse_fixed_b256(selected.position_manager_proxy_code_hash())?
    {
        return Err(ChainLogAuditError::Unverified);
    }
    let registry_entries = exact_eip1186_storage_entries(&registry_proof, &[registry_key])?;
    let module_word = parse_eip1186_storage_value(field(registry_entries[0], "value")?)?;
    if module_word.is_zero() || module_word >> 160 != U256::ZERO {
        return Err(ChainLogAuditError::Unverified);
    }
    verify_eip1186_storage_proof(
        &registry_account,
        registry_key,
        registry_entries[0],
        Some(rlp_u256(module_word)),
        false,
    )?;
    let module_proxy = Address::from_word(B256::from(module_word.to_be_bytes::<32>()));
    if module_proxy == Address::ZERO
        || module_proxy
            == Address::from_str(pm_proxy).map_err(|_| ChainLogAuditError::Unverified)?
        || module_proxy
            == Address::from_str(PUSD_PROXY).map_err(|_| ChainLogAuditError::Unverified)?
    {
        return Err(ChainLogAuditError::Unverified);
    }

    let implementation_slot = parse_fixed_b256(ERC1967_IMPLEMENTATION_SLOT)?;
    let legacy_key = mapping_key_bytes31(condition_id, MODULE_LEGACY_MAPPING_SLOT);
    let result_keys = result_storage_keys(condition_id)?;
    let module_keys = [
        implementation_slot,
        legacy_key,
        result_keys[0],
        result_keys[1],
        result_keys[2],
    ];
    let module_proof = verifier
        .rpc(
            endpoint,
            "eth_getProof",
            json!([
                format!("{module_proxy:#x}"),
                module_keys
                    .iter()
                    .map(|key| format!("{key:#x}"))
                    .collect::<Vec<_>>(),
                format!("{block:#x}")
            ]),
        )
        .await?;
    let module_account =
        verify_eip1186_account_proof(state_root, &format!("{module_proxy:#x}"), &module_proof)?;
    if module_account.code_hash != parse_fixed_b256(MODULE_PROXY_CODE_HASH)? {
        return Err(ChainLogAuditError::Unverified);
    }
    let module_entries = exact_eip1186_storage_entries(&module_proof, &module_keys)?;
    let implementation_word = parse_eip1186_storage_value(field(module_entries[0], "value")?)?;
    if implementation_word.is_zero() || implementation_word >> 160 != U256::ZERO {
        return Err(ChainLogAuditError::Unverified);
    }
    let implementation = Address::from_word(B256::from(implementation_word.to_be_bytes::<32>()));
    if implementation == Address::ZERO
        || implementation == module_proxy
        || implementation
            == Address::from_str(pm_proxy).map_err(|_| ChainLogAuditError::Unverified)?
    {
        return Err(ChainLogAuditError::Unverified);
    }
    verify_eip1186_storage_proof(
        &module_account,
        implementation_slot,
        module_entries[0],
        Some(rlp_u256(implementation_word)),
        false,
    )?;
    let legacy_value = parse_eip1186_storage_value(field(module_entries[1], "value")?)?;
    if !legacy_value.is_zero() {
        return Err(ChainLogAuditError::Unverified);
    }
    verify_eip1186_storage_proof(&module_account, legacy_key, module_entries[1], None, true)?;

    let mut result_values = [U256::ZERO; 3];
    for index in 0..3 {
        result_values[index] =
            parse_eip1186_storage_value(field(module_entries[index + 2], "value")?)?;
        verify_eip1186_storage_proof(
            &module_account,
            result_keys[index],
            module_entries[index + 2],
            (!result_values[index].is_zero()).then(|| rlp_u256(result_values[index])),
            result_values[index].is_zero(),
        )?;
    }
    let result_length = result_values[0];
    let numerators = match result_length {
        length if length.is_zero() => None,
        length if length == U256::from(2) => {
            let values = [result_values[1], result_values[2]];
            if values[0].checked_add(values[1]) != Some(PAYOUT_DENOMINATOR) {
                return Err(ChainLogAuditError::Unverified);
            }
            Some(values)
        }
        _ => return Err(ChainLogAuditError::Unverified),
    };

    let implementation_proof = verifier
        .rpc(
            endpoint,
            "eth_getProof",
            json!([format!("{implementation:#x}"), [], format!("{block:#x}")]),
        )
        .await?;
    if implementation_proof
        .get("storageProof")
        .and_then(Value::as_array)
        .is_none_or(|entries| !entries.is_empty())
    {
        return Err(ChainLogAuditError::Unverified);
    }
    let implementation_account = verify_eip1186_account_proof(
        state_root,
        &format!("{implementation:#x}"),
        &implementation_proof,
    )?;
    let implementation_code_hash = implementation_account.code_hash;
    if implementation_code_hash != expected_runtime_hash(implementation)? {
        return Err(ChainLogAuditError::Unverified);
    }
    Ok(ProviderNativeBinary {
        module_proxy,
        implementation,
        implementation_code_hash,
        result_length,
        numerators,
    })
}

pub(super) fn is_canonical_native_binary_condition(condition: B256) -> bool {
    let bytes = condition.as_slice();
    bytes[0] == 1 && bytes[17..].iter().all(|byte| *byte == 0)
}

fn derive_position_id(condition: B256, outcome: u8) -> B256 {
    let mut bytes = condition.0;
    bytes[31] = outcome;
    B256::from(bytes)
}

fn mapping_key_u256(key: U256, slot: U256) -> B256 {
    let mut preimage = [0_u8; 64];
    preimage[..32].copy_from_slice(&key.to_be_bytes::<32>());
    preimage[32..].copy_from_slice(&slot.to_be_bytes::<32>());
    B256::from_slice(&Keccak256::digest(preimage))
}

fn mapping_key_bytes31(key: B256, slot: u64) -> B256 {
    let mut preimage = [0_u8; 64];
    preimage[..31].copy_from_slice(&key.as_slice()[..31]);
    preimage[63] = slot as u8;
    B256::from_slice(&Keccak256::digest(preimage))
}

fn ensure_deadline(deadline: Instant) -> Result<(), BoundedFifthNativeBinaryError> {
    if Instant::now() >= deadline {
        Err(BoundedFifthNativeBinaryError::Timeout)
    } else {
        Ok(())
    }
}

fn map_selected_error(error: BoundedFifthSelectedBalancesError) -> BoundedFifthNativeBinaryError {
    match error {
        BoundedFifthSelectedBalancesError::RequestBudgetExceeded => {
            BoundedFifthNativeBinaryError::RequestBudgetExceeded
        }
        BoundedFifthSelectedBalancesError::Timeout => BoundedFifthNativeBinaryError::Timeout,
        BoundedFifthSelectedBalancesError::Verification(error) => {
            BoundedFifthNativeBinaryError::Verification(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_VECTORS: &str = include_str!("artifacts/fifth-native-binary-source-vectors.json");

    #[test]
    fn native_condition_and_storage_keys_match_independent_source_vectors() {
        let vectors: Value = serde_json::from_str(SOURCE_VECTORS).unwrap();
        assert_eq!(
            vectors["normalization_denominator"].as_u64(),
            Some(1_000_000)
        );
        assert_eq!(
            vectors["module_registry_key"].as_str(),
            Some("0xada5013122d395ba3c54772283fb069b10426056ef8ca54750cb9bb552a59e7d")
        );
        for vector in vectors["vectors"].as_array().unwrap() {
            let condition =
                parse_fixed_b256(vector["canonical_condition_id"].as_str().unwrap()).unwrap();
            let base_hash = parse_fixed_b256(vector["full_base_hash"].as_str().unwrap()).unwrap();
            assert!(is_canonical_native_binary_condition(condition));
            assert_eq!(&condition.as_slice()[1..17], &base_hash.as_slice()[16..]);
            assert_eq!(
                derive_position_id(condition, 0),
                parse_fixed_b256(vector["position_ids"][0].as_str().unwrap()).unwrap()
            );
            assert_eq!(
                derive_position_id(condition, 1),
                parse_fixed_b256(vector["position_ids"][1].as_str().unwrap()).unwrap()
            );
            assert_eq!(
                mapping_key_bytes31(condition, MODULE_LEGACY_MAPPING_SLOT),
                parse_fixed_b256(
                    vector["module_storage_keys"]["legacy_mapping"]
                        .as_str()
                        .unwrap()
                )
                .unwrap()
            );
            let result_keys = result_storage_keys(condition).unwrap();
            assert_eq!(
                result_keys[0],
                parse_fixed_b256(
                    vector["module_storage_keys"]["result_length"]
                        .as_str()
                        .unwrap()
                )
                .unwrap()
            );
            assert_eq!(
                result_keys[1],
                parse_fixed_b256(
                    vector["module_storage_keys"]["result_numerator0"]
                        .as_str()
                        .unwrap()
                )
                .unwrap()
            );
            assert_eq!(
                result_keys[2],
                parse_fixed_b256(
                    vector["module_storage_keys"]["result_numerator1"]
                        .as_str()
                        .unwrap()
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn native_condition_requires_all_encoder_fields() {
        let vectors: Value = serde_json::from_str(SOURCE_VECTORS).unwrap();
        let condition = parse_fixed_b256(
            vectors["vectors"][1]["canonical_condition_id"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        for byte in std::iter::once(0_usize).chain(17..32) {
            let mut invalid = condition.0;
            invalid[byte] ^= 1;
            assert!(!is_canonical_native_binary_condition(B256::from(invalid)));
        }
    }
}
