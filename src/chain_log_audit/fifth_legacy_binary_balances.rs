//! Root-bound proof of a legacy BinaryModule identity and the selected owner's
//! current balances. The migration identity does not add market semantics.

use super::ctf_condition_state;
use super::ctf_position_identity::{get_root_collection_id_bounded, position_id};
use super::fifth_code_context::{ERC1967_IMPLEMENTATION_SLOT, POSITION_MANAGER_PROXY};
use super::fifth_selected_balances::{
    BoundedFifthSelectedBalancesError, FifthSelectedBalancesObservation,
};
use super::{
    ChainLogAuditError, ChainLogVerifier, CtfConditionStateBlockProof, CtfConditionStateStatus,
    TransactionRequestBudget, exact_eip1186_storage_entries, field, parse_eip1186_storage_value,
    parse_fixed_b256, rlp_u256, validate_hex, verify_eip1186_account_proof,
    verify_eip1186_storage_proof,
};
use alloy_primitives::{Address, B256, U256};
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};
use std::{str::FromStr, time::Duration};
use thiserror::Error;
use tokio::time::Instant;

const TEMPLATE: &[u8] = include_bytes!("artifacts/binary-module-source-template.json");
pub(super) const MODULE_PROXY_CODE_HASH: &str =
    "0xaaa52c8cc8a0e3fd27ce756cc6b4e70c51423e9b597b11f32d3e49f8b1fc890d";
const CONDITIONAL_TOKENS: &str = "0x4d97dcd97ec945f40cf65f87097ace5ea0476045";
const PUSD_COLLATERAL: &str = "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb";
const CONFIGURED_USDCE: &str = "0x2791bca1f2de4661ed88a30c99a7a9449aa84174";
const MODULE_MAPPING_SLOT: u64 = 150;
const POLICY_VERSION: &str = "fifth-legacy-binary-module-full-runtime-root-identity/1";

pub const FIFTH_LEGACY_BINARY_BALANCES_POLICY_VERSION: &str = POLICY_VERSION;

#[cfg(test)]
pub(super) fn test_rooted_point_proof_packet(
    position_balances: [U256; 2],
    pusd_balance: U256,
) -> (String, std::collections::BTreeMap<String, Value>) {
    tests::rooted_point_proof_packet(position_balances, pusd_balance)
}

#[cfg(test)]
pub(super) fn test_rooted_point_proof_packet_with_identity(
    position_balances: [U256; 2],
    pusd_balance: U256,
    module_implementation: &str,
    ctf_values: [U256; 4],
) -> (String, std::collections::BTreeMap<String, Value>) {
    tests::rooted_point_proof_packet_with_identity(
        position_balances,
        pusd_balance,
        module_implementation,
        ctf_values,
    )
}

#[cfg(test)]
pub(super) fn test_rooted_module_point_proof_packet(
    owner: &str,
    owner_positions: [U256; 2],
    owner_cash: U256,
    module_positions: [U256; 2],
    module_cash: U256,
    module_roles: U256,
) -> (String, std::collections::BTreeMap<String, Value>) {
    tests::rooted_module_point_proof_packet(
        owner,
        owner_positions,
        owner_cash,
        module_positions,
        module_cash,
        module_roles,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn test_rooted_module_point_proof_packet_with_result(
    owner: &str,
    owner_positions: [U256; 2],
    owner_cash: U256,
    module_positions: [U256; 2],
    module_cash: U256,
    module_roles: U256,
    ctf_values: [U256; 4],
    result_values: [U256; 3],
) -> (String, std::collections::BTreeMap<String, Value>) {
    tests::rooted_module_point_proof_packet_with_result(
        owner,
        owner_positions,
        owner_cash,
        module_positions,
        module_cash,
        module_roles,
        ctf_values,
        result_values,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn test_rooted_migration_point_proof_packet(
    owner: &str,
    owner_positions: [U256; 2],
    owner_cash: U256,
    module_positions: [U256; 2],
    module_cash: U256,
    module_roles: U256,
    ctf_values: [U256; 4],
    result_values: [U256; 3],
    migration_ctf_values: [U256; 5],
    migration_usdce_values: [U256; 3],
    pause_timestamp: U256,
) -> (String, std::collections::BTreeMap<String, Value>) {
    tests::rooted_migration_point_proof_packet(
        owner,
        owner_positions,
        owner_cash,
        module_positions,
        module_cash,
        module_roles,
        ctf_values,
        result_values,
        migration_ctf_values,
        migration_usdce_values,
        pause_timestamp,
    )
}

#[cfg(test)]
pub(super) fn test_rooted_native_binary_point_proof_packet(
    owner: &str,
    condition_id: B256,
    owner_positions: [U256; 2],
    owner_cash: U256,
    result_values: [U256; 3],
) -> (String, std::collections::BTreeMap<String, Value>) {
    tests::rooted_native_binary_point_proof_packet(
        owner,
        condition_id,
        owner_positions,
        owner_cash,
        result_values,
    )
}

#[cfg(test)]
pub(super) fn test_rooted_native_binary_alias_point_proof_packet(
    owner: &str,
    condition_id: B256,
    owner_positions: [U256; 2],
    owner_cash: U256,
    result_values: [U256; 3],
) -> (String, std::collections::BTreeMap<String, Value>) {
    tests::rooted_native_binary_alias_point_proof_packet(
        owner,
        condition_id,
        owner_positions,
        owner_cash,
        result_values,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn test_rooted_native_module_operation_point_packet(
    owner: &str,
    condition_id: B256,
    owner_positions: [U256; 2],
    owner_cash: U256,
    module_positions: [U256; 2],
    module_cash: U256,
    module_roles: U256,
    result_values: [U256; 3],
) -> (String, std::collections::BTreeMap<String, Value>) {
    tests::rooted_native_module_operation_point_packet(
        owner,
        condition_id,
        owner_positions,
        owner_cash,
        module_positions,
        module_cash,
        module_roles,
        result_values,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn test_rooted_native_module_operation_point_packet_with_exchange_storage(
    owner: &str,
    condition_id: B256,
    owner_positions: [U256; 2],
    owner_cash: U256,
    module_positions: [U256; 2],
    module_cash: U256,
    module_roles: U256,
    result_values: [U256; 3],
    exchange_storage_words: &[(B256, U256)],
) -> (String, std::collections::BTreeMap<String, Value>) {
    tests::rooted_native_module_operation_point_packet_with_exchange_storage(
        owner,
        condition_id,
        owner_positions,
        owner_cash,
        module_positions,
        module_cash,
        module_roles,
        result_values,
        exchange_storage_words,
    )
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedFifthLegacyBinaryBalancesError {
    #[error("fifth legacy binary balances RPC request budget exhausted")]
    RequestBudgetExceeded,
    #[error("fifth legacy binary balances exceeded its total deadline")]
    Timeout,
    #[error(transparent)]
    Verification(#[from] ChainLogAuditError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthLegacyBinaryBalancesObservation {
    selected_balances: FifthSelectedBalancesObservation,
    legacy_condition_id: B256,
    v2_condition_id: B256,
    v2_position_ids: [B256; 2],
    legacy_collection_ids: [B256; 2],
    legacy_position_ids: [B256; 2],
    module_proxy: Address,
    module_implementation: Address,
    module_implementation_code_hash: B256,
    ctf_condition_state: CtfConditionStateBlockProof,
}

impl FifthLegacyBinaryBalancesObservation {
    #[must_use]
    pub const fn selected_balances(&self) -> &FifthSelectedBalancesObservation {
        &self.selected_balances
    }
    #[must_use]
    pub const fn legacy_condition_id(&self) -> B256 {
        self.legacy_condition_id
    }
    #[must_use]
    pub const fn v2_condition_id(&self) -> B256 {
        self.v2_condition_id
    }
    #[must_use]
    pub const fn v2_position_ids(&self) -> [B256; 2] {
        self.v2_position_ids
    }
    #[must_use]
    pub const fn legacy_collection_ids(&self) -> [B256; 2] {
        self.legacy_collection_ids
    }
    #[must_use]
    pub const fn legacy_position_ids(&self) -> [B256; 2] {
        self.legacy_position_ids
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
    #[must_use]
    pub const fn ctf_condition_state(&self) -> &CtfConditionStateBlockProof {
        &self.ctf_condition_state
    }
    #[must_use]
    pub const fn source_policy_version(&self) -> &'static str {
        POLICY_VERSION
    }
}

impl ChainLogVerifier {
    /// Verify the canonical legacy condition and source-derived V2 pair at one
    /// agreed state root, sharing the selected-balance call's request budget.
    #[allow(clippy::too_many_arguments)]
    pub async fn verify_fifth_legacy_binary_balances_bounded(
        &self,
        owner: &str,
        legacy_condition_id: &str,
        block: u64,
        expected_hash: &str,
        max_requests: usize,
        total_timeout: Duration,
    ) -> Result<FifthLegacyBinaryBalancesObservation, BoundedFifthLegacyBinaryBalancesError> {
        let owner = validate_hex(owner, 20).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let owner_bytes = hex::decode(&owner[2..]).map_err(|_| ChainLogAuditError::InvalidInput)?;
        if owner_bytes.iter().all(|byte| *byte == 0) || max_requests == 0 || total_timeout.is_zero()
        {
            return Err(ChainLogAuditError::InvalidInput.into());
        }
        let legacy_condition_id =
            parse_fixed_b256(legacy_condition_id).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let expected_hash =
            validate_hex(expected_hash, 32).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let owner_address = Address::from_slice(&owner_bytes);
        let deadline = Instant::now()
            .checked_add(total_timeout)
            .ok_or(ChainLogAuditError::InvalidInput)?;
        let budget = TransactionRequestBudget::new(max_requests);
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let scoped = self.with_request_budget(budget.inner());
        let verification = scoped.verify_fifth_legacy_binary_balances_inner(
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
                Err(BoundedFifthLegacyBinaryBalancesError::RequestBudgetExceeded)
            }
            () = &mut deadline_wait => {
                if budget.is_exhausted() {
                    Err(BoundedFifthLegacyBinaryBalancesError::RequestBudgetExceeded)
                } else {
                    Err(BoundedFifthLegacyBinaryBalancesError::Timeout)
                }
            }
            result = &mut verification => {
                if budget.is_exhausted() {
                    Err(BoundedFifthLegacyBinaryBalancesError::RequestBudgetExceeded)
                } else {
                    result
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn verify_fifth_legacy_binary_balances_inner(
        &self,
        owner: String,
        owner_address: Address,
        legacy_condition_id: B256,
        block: u64,
        expected_hash: &str,
        deadline: Instant,
    ) -> Result<FifthLegacyBinaryBalancesObservation, BoundedFifthLegacyBinaryBalancesError> {
        let v2_condition_id = derive_v2_condition_id(legacy_condition_id);
        if v2_condition_id == B256::ZERO {
            return Err(ChainLogAuditError::InvalidInput.into());
        }
        let v2_position_ids = [
            derive_v2_position_id(v2_condition_id, 0),
            derive_v2_position_id(v2_condition_id, 1),
        ];
        ensure_deadline(deadline)?;
        let selected_balances = self
            .verify_fifth_selected_balances_inner(
                owner,
                owner_address,
                v2_position_ids[0],
                v2_position_ids[1],
                block,
                expected_hash,
                deadline,
            )
            .await
            .map_err(map_selected_error)?;
        ensure_deadline(deadline)?;
        let identity = tokio::try_join!(
            module_identity_provider(
                self,
                &self.primary,
                block,
                selected_balances.state_root(),
                legacy_condition_id,
                v2_condition_id,
                &selected_balances,
            ),
            module_identity_provider(
                self,
                &self.secondary,
                block,
                selected_balances.state_root(),
                legacy_condition_id,
                v2_condition_id,
                &selected_balances,
            ),
        )?;
        ensure_deadline(deadline)?;
        if identity.0 != identity.1 {
            return Err(ChainLogAuditError::Divergent.into());
        }
        let ProviderIdentity {
            proxy,
            implementation,
            implementation_code_hash,
            ctf_state: state,
        } = identity.0;
        let collateral = parse_address(CONFIGURED_USDCE)?;
        let collections = [
            get_root_collection_id_bounded(legacy_condition_id, 1, 128, deadline)
                .await
                .map_err(map_identity_math_error)?,
            get_root_collection_id_bounded(legacy_condition_id, 2, 128, deadline)
                .await
                .map_err(map_identity_math_error)?,
        ];
        let legacy_position_ids = collections.map(|id| position_id(collateral, id));
        ensure_deadline(deadline)?;
        Ok(FifthLegacyBinaryBalancesObservation {
            selected_balances,
            legacy_condition_id,
            v2_condition_id,
            v2_position_ids,
            legacy_collection_ids: collections,
            legacy_position_ids,
            module_proxy: proxy,
            module_implementation: implementation,
            module_implementation_code_hash: implementation_code_hash,
            ctf_condition_state: state,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderIdentity {
    proxy: Address,
    implementation: Address,
    implementation_code_hash: B256,
    ctf_state: CtfConditionStateBlockProof,
}

async fn module_identity_provider(
    verifier: &ChainLogVerifier,
    endpoint: &str,
    block: u64,
    state_root: &str,
    legacy_condition_id: B256,
    v2_condition_id: B256,
    selected: &FifthSelectedBalancesObservation,
) -> Result<ProviderIdentity, ChainLogAuditError> {
    let pm_proxy = POSITION_MANAGER_PROXY;
    let pm_key = mapping_key_u256(U256::from(1), U256::ZERO);
    let module_registry = verifier
        .rpc(
            endpoint,
            "eth_getProof",
            json!([pm_proxy, [format!("{pm_key:#x}")], format!("{block:#x}")]),
        )
        .await?;
    let pm_account = verify_eip1186_account_proof(state_root, pm_proxy, &module_registry)?;
    if pm_account.code_hash
        != parse_fixed_b256(selected.code_context().position_manager_proxy_code_hash())?
    {
        return Err(ChainLogAuditError::Unverified);
    }
    let pm_entries = exact_eip1186_storage_entries(&module_registry, &[pm_key])?;
    let module_word = parse_eip1186_storage_value(field(pm_entries[0], "value")?)?;
    if module_word.is_zero() || module_word >> 160 != U256::ZERO {
        return Err(ChainLogAuditError::Unverified);
    }
    verify_eip1186_storage_proof(
        &pm_account,
        pm_key,
        pm_entries[0],
        Some(rlp_u256(module_word)),
        false,
    )?;
    let proxy = Address::from_word(B256::from(module_word.to_be_bytes::<32>()));
    if proxy == Address::ZERO
        || proxy == parse_address(pm_proxy)?
        || proxy == parse_address(PUSD_COLLATERAL)?
    {
        return Err(ChainLogAuditError::Unverified);
    }

    let implementation_slot = parse_fixed_b256(ERC1967_IMPLEMENTATION_SLOT)?;
    let legacy_key = mapping_key_bytes31(v2_condition_id, MODULE_MAPPING_SLOT);
    let module_keys = [implementation_slot, legacy_key];
    let module_proof = verifier
        .rpc(
            endpoint,
            "eth_getProof",
            json!([
                format!("{proxy:#x}"),
                module_keys
                    .iter()
                    .map(|key| format!("{key:#x}"))
                    .collect::<Vec<_>>(),
                format!("{block:#x}")
            ]),
        )
        .await?;
    let module_account =
        verify_eip1186_account_proof(state_root, &format!("{proxy:#x}"), &module_proof)?;
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
        || implementation == proxy
        || implementation == parse_address(pm_proxy)?
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
    let stored_legacy = parse_eip1186_storage_value(field(module_entries[1], "value")?)?;
    if stored_legacy != U256::from_be_bytes(legacy_condition_id.0) {
        return Err(ChainLogAuditError::Unverified);
    }
    verify_eip1186_storage_proof(
        &module_account,
        legacy_key,
        module_entries[1],
        Some(rlp_u256(stored_legacy)),
        false,
    )?;

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
    let code_hash = implementation_account.code_hash;
    if code_hash != expected_runtime_hash(implementation)? {
        return Err(ChainLogAuditError::Unverified);
    }

    let ctf_state = ctf_condition_proof(
        verifier,
        endpoint,
        block,
        state_root,
        legacy_condition_id,
        selected,
    )
    .await?;
    Ok(ProviderIdentity {
        proxy,
        implementation,
        implementation_code_hash: code_hash,
        ctf_state,
    })
}

async fn ctf_condition_proof(
    verifier: &ChainLogVerifier,
    endpoint: &str,
    block: u64,
    state_root: &str,
    condition: B256,
    selected: &FifthSelectedBalancesObservation,
) -> Result<CtfConditionStateBlockProof, ChainLogAuditError> {
    let address = CONDITIONAL_TOKENS;
    let keys = ctf_condition_state::storage_keys(condition);
    let proof = verifier
        .rpc(
            endpoint,
            "eth_getProof",
            json!([
                address,
                keys.iter()
                    .map(|key| format!("{key:#x}"))
                    .collect::<Vec<_>>(),
                format!("{block:#x}")
            ]),
        )
        .await?;
    let account = verify_eip1186_account_proof(state_root, address, &proof)?;
    let expected_ctf_hash = B256::from(super::CTF_CONDITIONAL_TOKENS_CODE_HASH_CANDIDATE);
    if account.code_hash != expected_ctf_hash {
        return Err(ChainLogAuditError::Unverified);
    }
    let entries = exact_eip1186_storage_entries(&proof, &keys)?;
    let mut values = [U256::ZERO; 4];
    for (index, key) in keys.iter().enumerate() {
        values[index] = parse_eip1186_storage_value(field(entries[index], "value")?)?;
        verify_eip1186_storage_proof(
            &account,
            *key,
            entries[index],
            (!values[index].is_zero()).then(|| rlp_u256(values[index])),
            values[index].is_zero(),
        )?;
    }
    let status = ctf_condition_state::interpret(values[0], values[1], [values[2], values[3]])?;
    if !matches!(
        status,
        CtfConditionStateStatus::PreparedBinaryUnresolved | CtfConditionStateStatus::ResolvedBinary
    ) {
        return Err(ChainLogAuditError::Unverified);
    }
    Ok(CtfConditionStateBlockProof {
        block_number: selected.block_number(),
        block_hash: selected.block_hash().to_owned(),
        state_root: selected.state_root().to_owned(),
        payout_numerator_count: values[0],
        payout_denominator: values[1],
        payout_numerators: [values[2], values[3]],
        status,
    })
}

pub(super) fn expected_runtime_hash(implementation: Address) -> Result<B256, ChainLogAuditError> {
    if hex::encode(sha2::Sha256::digest(TEMPLATE))
        != "f85b516d96b221375c47655e85a03ec2b4dc96ba1d7eb19794936b4794627ad2"
    {
        return Err(ChainLogAuditError::Unverified);
    }
    let template: Value =
        serde_json::from_slice(TEMPLATE).map_err(|_| ChainLogAuditError::Unverified)?;
    if template.get("source_commit").and_then(Value::as_str)
        != Some("741f8bbe88c3f29a1c55d1248a3dd411f622f111")
        || template.get("input_sha256").and_then(Value::as_str)
            != Some("4b507b2ba2cf92430d1344e389bf9c4e4d77561334b424f8797aa32a0c77a31d")
    {
        return Err(ChainLogAuditError::Unverified);
    }
    let skeleton = template
        .get("runtime_skeleton_hex")
        .and_then(Value::as_str)
        .ok_or(ChainLogAuditError::Unverified)?;
    let mut runtime = hex::decode(skeleton).map_err(|_| ChainLogAuditError::Unverified)?;
    if template.get("runtime_bytes").and_then(Value::as_u64) != Some(runtime.len() as u64) {
        return Err(ChainLogAuditError::Unverified);
    }
    let sites = template
        .get("immutable_sites")
        .and_then(Value::as_object)
        .ok_or(ChainLogAuditError::Unverified)?;
    let values = [
        ("__self", U256::from_be_slice(implementation.as_slice())),
        ("POSITION_MANAGER", address_word(POSITION_MANAGER_PROXY)?),
        ("COLLATERAL_TOKEN", address_word(PUSD_COLLATERAL)?),
        ("RESOLUTION_CHAIN", U256::from(0)),
        ("CONDITIONAL_TOKENS", address_word(CONDITIONAL_TOKENS)?),
        ("USDCE", address_word(CONFIGURED_USDCE)?),
    ];
    if sites.len() != values.len() {
        return Err(ChainLogAuditError::Unverified);
    }
    let mut all = Vec::new();
    for (name, value) in values {
        let offsets = sites
            .get(name)
            .and_then(Value::as_array)
            .ok_or(ChainLogAuditError::Unverified)?;
        let expected_count = match name {
            "__self" => 2,
            "POSITION_MANAGER" => 10,
            "COLLATERAL_TOKEN" => 6,
            "RESOLUTION_CHAIN" => 5,
            "CONDITIONAL_TOKENS" => 9,
            "USDCE" => 8,
            _ => return Err(ChainLogAuditError::Unverified),
        };
        if offsets.len() != expected_count {
            return Err(ChainLogAuditError::Unverified);
        }
        let bytes = value.to_be_bytes::<32>();
        for offset in offsets {
            let start = offset
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .ok_or(ChainLogAuditError::Unverified)?;
            let end = start
                .checked_add(32)
                .ok_or(ChainLogAuditError::Unverified)?;
            if end > runtime.len() || runtime[start..end].iter().any(|byte| *byte != 0) {
                return Err(ChainLogAuditError::Unverified);
            }
            all.push((start, end));
            runtime[start..end].copy_from_slice(&bytes);
        }
    }
    all.sort_unstable();
    if all.len() != 40 || all.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(ChainLogAuditError::Unverified);
    }
    Ok(B256::from_slice(&Keccak256::digest(runtime)))
}

fn address_word(address: &str) -> Result<U256, ChainLogAuditError> {
    let address = validate_hex(address, 20)?;
    let bytes = hex::decode(&address[2..]).map_err(|_| ChainLogAuditError::InvalidInput)?;
    Ok(U256::from_be_slice(&bytes))
}

fn parse_address(address: &str) -> Result<Address, ChainLogAuditError> {
    Address::from_str(address).map_err(|_| ChainLogAuditError::Unverified)
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

fn derive_v2_condition_id(legacy: B256) -> B256 {
    let mut condition = [0_u8; 32];
    condition[0] = 1;
    condition[1..17].copy_from_slice(&legacy.as_slice()[16..32]);
    B256::from(condition)
}

fn derive_v2_position_id(condition: B256, outcome: u8) -> B256 {
    let mut id = condition.0;
    id[31] = outcome;
    B256::from(id)
}

fn map_selected_error(
    error: BoundedFifthSelectedBalancesError,
) -> BoundedFifthLegacyBinaryBalancesError {
    match error {
        BoundedFifthSelectedBalancesError::RequestBudgetExceeded => {
            BoundedFifthLegacyBinaryBalancesError::RequestBudgetExceeded
        }
        BoundedFifthSelectedBalancesError::Timeout => {
            BoundedFifthLegacyBinaryBalancesError::Timeout
        }
        BoundedFifthSelectedBalancesError::Verification(error) => {
            BoundedFifthLegacyBinaryBalancesError::Verification(error)
        }
    }
}

fn map_identity_math_error(
    error: super::BoundedV1TradeAttributionError,
) -> BoundedFifthLegacyBinaryBalancesError {
    match error {
        super::BoundedV1TradeAttributionError::RequestBudgetExceeded => {
            BoundedFifthLegacyBinaryBalancesError::RequestBudgetExceeded
        }
        super::BoundedV1TradeAttributionError::Timeout => {
            BoundedFifthLegacyBinaryBalancesError::Timeout
        }
        super::BoundedV1TradeAttributionError::Verification(error) => {
            BoundedFifthLegacyBinaryBalancesError::Verification(error)
        }
    }
}

fn ensure_deadline(deadline: Instant) -> Result<(), BoundedFifthLegacyBinaryBalancesError> {
    if Instant::now() >= deadline {
        Err(BoundedFifthLegacyBinaryBalancesError::Timeout)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::fifth_code_context::{
        CURRENT_EXCHANGE_CODE_HASH, CURRENT_EXCHANGE_IMPLEMENTATION, ERC1967_PROXY_CODE_HASH,
        EXCHANGE_PROXY, POSITION_MANAGER_CODE_HASH, POSITION_MANAGER_IMPLEMENTATION,
    };
    use super::super::fifth_legacy_binary_result::{
        BoundedFifthLegacyBinaryResultError, FifthLegacyBinaryResultStatus,
    };
    use super::*;
    use alloy_trie::{EMPTY_ROOT_HASH, HashBuilder, Nibbles, TrieAccount, proof::ProofRetainer};
    use axum::{Json, Router, extract::State, routing::post};
    use serde_json::Value;
    use std::{
        collections::BTreeMap,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::task::JoinHandle;

    const TEST_PUSD_PROXY: &str = "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb";
    const TEST_PUSD_IMPLEMENTATION: &str = "0xce84e053301a82937f90ee2c2c1889cab1db25de";
    const TEST_PUSD_PROXY_CODE_HASH: &str =
        "0xaaa52c8cc8a0e3fd27ce756cc6b4e70c51423e9b597b11f32d3e49f8b1fc890d";
    const TEST_PUSD_IMPLEMENTATION_CODE_HASH: &str =
        "0x740b9ebbb47b33a28e47c999b330fe79f878b7e0f1f7e7e09b8a0928ef4e1cb0";

    const BLOCK: u64 = 100;
    const LEGACY: &str = "0x1212121212121212121212121212121212121212121212121212121212121212";
    const OWNER: &str = "0x1111111111111111111111111111111111111111";
    const MODULE_PROXY: &str = "0x3333333333333333333333333333333333333333";
    const MODULE_IMPL: &str = "0x2222222222222222222222222222222222222222";
    const LEGACY_VAULT: &str = "0xc417fd8e9661c0d2120b64a04bb3278c17e99db1";

    #[derive(Clone, Copy)]
    struct MigrationFixtureState {
        ctf_values: [U256; 5],
        usdce_values: [U256; 3],
        pause_timestamp: U256,
    }
    type AccountData = (String, TrieAccount, Vec<(B256, U256, Vec<String>)>);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FixtureFault {
        None,
        WrongRuntimeCode,
        AliasMapping,
        UnpreparedCtf,
        NonBinaryCtf,
        WrongCtfCode,
        MissingRegistryEntry,
        ExtraRegistryEntry,
        MissingResultEntry,
        ExtraResultEntry,
        WrongResultKey,
        WrongResultAddress,
        WrongResultStorageRoot,
        WrongResultValue,
        NativeBinary,
        DeadlineEarlyAndLate,
        ResultDeadlineEarlyAndLate,
        GateProof,
        GateResultProof,
    }

    struct Fixture {
        block_header: Value,
        finalized_header: Value,
        proofs: BTreeMap<String, Value>,
        responses: Arc<Mutex<Vec<Value>>>,
        requests: Arc<AtomicUsize>,
        fault: FixtureFault,
        proof_started: Arc<tokio::sync::Notify>,
        early_delay_completed: std::sync::atomic::AtomicBool,
        early_delay_release: tokio::sync::Notify,
        late_ctf_started: std::sync::atomic::AtomicBool,
        late_result_started: std::sync::atomic::AtomicBool,
    }

    async fn advance_paired_fixture_deadline<T: std::fmt::Debug>(
        fixtures: [&Fixture; 2],
        task: &mut tokio::task::JoinHandle<T>,
        late_started: impl Fn(&Fixture) -> bool,
    ) -> T {
        let started_at = tokio::time::Instant::now();
        for late in [false, true] {
            let stages_started = async {
                loop {
                    let ready = fixtures.iter().all(|fixture| {
                        if late {
                            late_started(fixture)
                        } else {
                            fixture.requests.load(Ordering::Acquire) > 0
                        }
                    });
                    if ready {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            };
            tokio::select! {
                _ = stages_started => {}
                result = &mut *task => panic!("verifier finished before delay stage: {result:?}"),
                _ = crate::chain_log_audit::receipt_tests::test_wall_timeout(Duration::from_secs(30)) => {
                    panic!("paired RPC delay stage did not start before wall bound");
                }
            }
            assert_eq!(
                started_at.elapsed(),
                Duration::from_millis(if late { 500 } else { 0 })
            );
            tokio::time::advance(Duration::from_millis(if late { 600 } else { 500 })).await;
            if !late {
                fixtures[0].early_delay_release.notify_one();
                fixtures[1].early_delay_release.notify_one();
            }
        }
        let result = tokio::select! {
            result = &mut *task => result.unwrap(),
            _ = crate::chain_log_audit::receipt_tests::test_wall_timeout(Duration::from_secs(30)) => {
                panic!("verifier did not enforce the shared deadline");
            }
        };
        assert_eq!(started_at.elapsed(), Duration::from_millis(1100));
        result
    }

    async fn rpc(State(fixture): State<Arc<Fixture>>, Json(request): Json<Value>) -> Json<Value> {
        fixture.requests.fetch_add(1, Ordering::Relaxed);
        let method = request["method"].as_str().unwrap_or_default();
        let params = request["params"].clone();
        if method == "eth_chainId"
            && matches!(
                fixture.fault,
                FixtureFault::DeadlineEarlyAndLate | FixtureFault::ResultDeadlineEarlyAndLate
            )
        {
            fixture.early_delay_release.notified().await;
            fixture.early_delay_completed.store(true, Ordering::Release);
        }
        if method == "eth_getProof" {
            if fixture.fault == FixtureFault::GateProof {
                fixture.proof_started.notify_one();
                std::future::pending::<()>().await;
            }
            if fixture.fault == FixtureFault::GateResultProof
                && params[0]
                    .as_str()
                    .is_some_and(|address| address.eq_ignore_ascii_case(MODULE_PROXY))
                && params[1].as_array().is_some_and(|keys| keys.len() == 3)
            {
                fixture.proof_started.notify_one();
                std::future::pending::<()>().await;
            }
            if fixture.fault == FixtureFault::DeadlineEarlyAndLate
                && params[0]
                    .as_str()
                    .is_some_and(|address| address.eq_ignore_ascii_case(CONDITIONAL_TOKENS))
            {
                fixture.late_ctf_started.store(true, Ordering::Release);
                tokio::time::sleep(Duration::from_millis(600)).await;
            }
            if fixture.fault == FixtureFault::ResultDeadlineEarlyAndLate
                && params[0]
                    .as_str()
                    .is_some_and(|address| address.eq_ignore_ascii_case(MODULE_PROXY))
                && params[1].as_array().is_some_and(|keys| keys.len() == 3)
            {
                fixture.late_result_started.store(true, Ordering::Release);
                tokio::time::sleep(Duration::from_millis(600)).await;
            }
        }
        let result = match method {
            "eth_chainId" => json!("0x89"),
            "eth_getBlockByNumber" if params[0] == "finalized" => fixture.finalized_header.clone(),
            "eth_getBlockByNumber" => fixture.block_header.clone(),
            "eth_getProof" => {
                let address = params[0].as_str().unwrap_or_default().to_ascii_lowercase();
                fixture
                    .proofs
                    .get(&address)
                    .map(|proof| select_proof_entries(proof, &params[1], &address, fixture.fault))
                    .unwrap_or(Value::Null)
            }
            _ => Value::Null,
        };
        fixture
            .responses
            .lock()
            .unwrap()
            .push(json!({"method":method,"params":params,"result":result.clone()}));
        Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
    }

    fn select_proof_entries(
        proof: &Value,
        requested_keys: &Value,
        address: &str,
        fault: FixtureFault,
    ) -> Value {
        let requested = requested_keys
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        let mut entries = proof["storageProof"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|entry| {
                requested
                    .iter()
                    .any(|key| entry["key"].as_str() == Some(*key))
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut selected = proof.clone();
        let registry_key = format!("{:#x}", mapping_key_u256(U256::ONE, U256::ZERO));
        if address == POSITION_MANAGER_PROXY && requested.len() == 1 && requested[0] == registry_key
        {
            match fault {
                FixtureFault::MissingRegistryEntry => {
                    entries.clear();
                }
                FixtureFault::ExtraRegistryEntry => entries
                    .push(json!({"key":format!("0x{}", "77".repeat(32)),"value":"0x0","proof":[]})),
                _ => {}
            }
        }
        if address == MODULE_PROXY && requested.len() == 3 {
            match fault {
                FixtureFault::MissingResultEntry => {
                    entries.pop();
                }
                FixtureFault::ExtraResultEntry => entries
                    .push(json!({"key":format!("0x{}", "77".repeat(32)),"value":"0x0","proof":[]})),
                FixtureFault::WrongResultKey => {
                    if let Some(entry) = entries.first_mut() {
                        entry["key"] = json!(format!("0x{}", "66".repeat(32)));
                    }
                }
                FixtureFault::WrongResultAddress => {
                    selected["address"] = json!(format!("0x{}", "44".repeat(20)));
                }
                FixtureFault::WrongResultStorageRoot => {
                    selected["storageHash"] = json!(format!("0x{}", "55".repeat(32)));
                }
                FixtureFault::WrongResultValue => {
                    if let Some(entry) = entries.first_mut() {
                        entry["value"] = json!("0x1");
                    }
                }
                _ => {}
            }
        }
        selected["storageProof"] = json!(entries);
        selected
    }

    struct Pair {
        verifier: ChainLogVerifier,
        expected_hash: String,
        primary: Arc<Fixture>,
        secondary: Arc<Fixture>,
        primary_task: JoinHandle<()>,
        secondary_task: JoinHandle<()>,
    }

    async fn verifier_pair(resolved: bool) -> Pair {
        verifier_pair_with_faults(resolved, FixtureFault::None, FixtureFault::None).await
    }

    async fn verifier_pair_with_faults(
        resolved: bool,
        primary_fault: FixtureFault,
        secondary_fault: FixtureFault,
    ) -> Pair {
        let primary = rooted_fixture(resolved, primary_fault);
        let secondary = rooted_fixture(resolved, secondary_fault);
        let expected_hash = primary.block_header["hash"].as_str().unwrap().to_owned();
        let (primary_endpoint, primary_task) = serve_with_arc(primary.clone()).await;
        let (secondary_endpoint, secondary_task) = serve_with_arc(secondary.clone()).await;
        Pair {
            verifier: ChainLogVerifier::new(&primary_endpoint, &secondary_endpoint).unwrap(),
            expected_hash,
            primary,
            secondary,
            primary_task,
            secondary_task,
        }
    }

    async fn result_verifier_pair(
        result_values: [U256; 3],
        ctf_values: [U256; 4],
        primary_fault: FixtureFault,
        secondary_fault: FixtureFault,
    ) -> Pair {
        let balances = [U256::from(100_u64), U256::from(200_u64)];
        let primary = rooted_fixture_with_result(
            false,
            primary_fault,
            balances,
            U256::from(1_000_u64),
            MODULE_IMPL,
            Some(ctf_values),
            Some(result_values),
        );
        let secondary = rooted_fixture_with_result(
            false,
            secondary_fault,
            balances,
            U256::from(1_000_u64),
            MODULE_IMPL,
            Some(ctf_values),
            Some(result_values),
        );
        let expected_hash = primary.block_header["hash"].as_str().unwrap().to_owned();
        let (primary_endpoint, primary_task) = serve_with_arc(primary.clone()).await;
        let (secondary_endpoint, secondary_task) = serve_with_arc(secondary.clone()).await;
        Pair {
            verifier: ChainLogVerifier::new(&primary_endpoint, &secondary_endpoint).unwrap(),
            expected_hash,
            primary,
            secondary,
            primary_task,
            secondary_task,
        }
    }

    async fn serve_with_arc(fixture: Arc<Fixture>) -> (String, JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/", post(rpc)).with_state(fixture),
            )
            .await
            .unwrap();
        });
        (endpoint, task)
    }

    fn rooted_fixture(resolved: bool, fault: FixtureFault) -> Arc<Fixture> {
        rooted_fixture_with_balances(
            resolved,
            fault,
            [U256::from_be_slice(&[0x80; 32]), U256::from(42)],
            U256::from_be_slice(&[0x91; 32]),
        )
    }

    fn rooted_fixture_with_balances(
        resolved: bool,
        fault: FixtureFault,
        position_balances: [U256; 2],
        pusd_balance: U256,
    ) -> Arc<Fixture> {
        rooted_fixture_with_identity(
            resolved,
            fault,
            position_balances,
            pusd_balance,
            MODULE_IMPL,
            None,
        )
    }

    fn rooted_fixture_with_identity(
        resolved: bool,
        fault: FixtureFault,
        position_balances: [U256; 2],
        pusd_balance: U256,
        module_impl_address: &str,
        ctf_values_override: Option<[U256; 4]>,
    ) -> Arc<Fixture> {
        rooted_fixture_with_result(
            resolved,
            fault,
            position_balances,
            pusd_balance,
            module_impl_address,
            ctf_values_override,
            None,
        )
    }

    fn rooted_fixture_with_result(
        resolved: bool,
        fault: FixtureFault,
        position_balances: [U256; 2],
        pusd_balance: U256,
        module_impl_address: &str,
        ctf_values_override: Option<[U256; 4]>,
        module_result: Option<[U256; 3]>,
    ) -> Arc<Fixture> {
        rooted_fixture_with_owner_module_state(
            resolved,
            fault,
            position_balances,
            pusd_balance,
            module_impl_address,
            ctf_values_override,
            module_result,
            OWNER,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn rooted_fixture_with_owner_module_state(
        resolved: bool,
        fault: FixtureFault,
        position_balances: [U256; 2],
        pusd_balance: U256,
        module_impl_address: &str,
        ctf_values_override: Option<[U256; 4]>,
        module_result: Option<[U256; 3]>,
        owner_text: &str,
        module_state: Option<([U256; 2], U256, U256)>,
        condition_override: Option<B256>,
    ) -> Arc<Fixture> {
        rooted_fixture_with_owner_module_state_and_exchange_storage(
            resolved,
            fault,
            position_balances,
            pusd_balance,
            module_impl_address,
            ctf_values_override,
            module_result,
            owner_text,
            module_state,
            condition_override,
            &[],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn rooted_fixture_with_owner_module_state_and_exchange_storage(
        resolved: bool,
        fault: FixtureFault,
        position_balances: [U256; 2],
        pusd_balance: U256,
        module_impl_address: &str,
        ctf_values_override: Option<[U256; 4]>,
        module_result: Option<[U256; 3]>,
        owner_text: &str,
        module_state: Option<([U256; 2], U256, U256)>,
        condition_override: Option<B256>,
        exchange_storage_words: &[(B256, U256)],
    ) -> Arc<Fixture> {
        rooted_fixture_with_migration_state_and_exchange_storage(
            resolved,
            fault,
            position_balances,
            pusd_balance,
            module_impl_address,
            ctf_values_override,
            module_result,
            owner_text,
            module_state,
            None,
            condition_override,
            exchange_storage_words,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn rooted_fixture_with_migration_state(
        resolved: bool,
        fault: FixtureFault,
        position_balances: [U256; 2],
        pusd_balance: U256,
        module_impl_address: &str,
        ctf_values_override: Option<[U256; 4]>,
        module_result: Option<[U256; 3]>,
        owner_text: &str,
        module_state: Option<([U256; 2], U256, U256)>,
        migration_state: Option<MigrationFixtureState>,
        condition_override: Option<B256>,
    ) -> Arc<Fixture> {
        rooted_fixture_with_migration_state_and_exchange_storage(
            resolved,
            fault,
            position_balances,
            pusd_balance,
            module_impl_address,
            ctf_values_override,
            module_result,
            owner_text,
            module_state,
            migration_state,
            condition_override,
            &[],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn rooted_fixture_with_migration_state_and_exchange_storage(
        resolved: bool,
        fault: FixtureFault,
        position_balances: [U256; 2],
        pusd_balance: U256,
        module_impl_address: &str,
        ctf_values_override: Option<[U256; 4]>,
        module_result: Option<[U256; 3]>,
        owner_text: &str,
        module_state: Option<([U256; 2], U256, U256)>,
        migration_state: Option<MigrationFixtureState>,
        condition_override: Option<B256>,
        exchange_storage_words: &[(B256, U256)],
    ) -> Arc<Fixture> {
        let owner = parse_address(owner_text).unwrap();
        let legacy = parse_fixed_b256(LEGACY).unwrap();
        let v2 = condition_override.unwrap_or_else(|| derive_v2_condition_id(legacy));
        let ids = [derive_v2_position_id(v2, 0), derive_v2_position_id(v2, 1)];
        let slot = parse_fixed_b256(ERC1967_IMPLEMENTATION_SLOT).unwrap();
        let module_impl = parse_address(module_impl_address).unwrap();
        let module = parse_address(MODULE_PROXY).unwrap();
        let mut module_storage = vec![
            (slot, U256::from_be_slice(module_impl.as_slice())),
            (
                mapping_key_bytes31(v2, MODULE_MAPPING_SLOT),
                if fault == FixtureFault::AliasMapping {
                    U256::from_be_bytes(
                        B256::from_slice(&[&[0x34; 16][..], &legacy.as_slice()[16..]].concat()).0,
                    )
                } else if fault == FixtureFault::NativeBinary {
                    U256::ZERO
                } else {
                    U256::from_be_bytes(legacy.0)
                },
            ),
        ];
        if let Some(values) = module_result {
            let keys = super::super::fifth_legacy_binary_result::result_storage_keys(v2).unwrap();
            module_storage.extend(keys.into_iter().zip(values));
        }
        let legacy_ids = [
            B256::from_str("0xd46b4e85dd2cb18425b643d2523673a90491b1131f9cb3465f431899359eb026")
                .unwrap(),
            B256::from_str("0x35d0161b478b3564d56bab3f931e54f5b58ad0257625144f6025365403c74781")
                .unwrap(),
        ];
        let mut ctf_storage = {
            let keys = ctf_condition_state::storage_keys(legacy);
            let values = if let Some(values) = ctf_values_override {
                values
            } else if fault == FixtureFault::UnpreparedCtf {
                [U256::ZERO; 4]
            } else if fault == FixtureFault::NonBinaryCtf {
                [U256::from(3), U256::ZERO, U256::ZERO, U256::ZERO]
            } else if resolved {
                [U256::from(2), U256::from(4), U256::ONE, U256::from(3)]
            } else {
                [U256::from(2), U256::ZERO, U256::ZERO, U256::ZERO]
            };
            keys.into_iter().zip(values).collect::<Vec<_>>()
        };
        if let Some(migration) = migration_state {
            ctf_storage.extend([
                (
                    ctf_position_balance_key(owner, legacy_ids[0]),
                    migration.ctf_values[0],
                ),
                (
                    ctf_position_balance_key(owner, legacy_ids[1]),
                    migration.ctf_values[1],
                ),
                (
                    ctf_position_balance_key(module, legacy_ids[0]),
                    migration.ctf_values[2],
                ),
                (
                    ctf_position_balance_key(module, legacy_ids[1]),
                    migration.ctf_values[3],
                ),
                (ctf_approval_key(owner, module), migration.ctf_values[4]),
            ]);
            module_storage.push((migration_pause_key(v2), migration.pause_timestamp));
        }
        let mut position_storage = vec![
            (slot, address_word(POSITION_MANAGER_IMPLEMENTATION).unwrap()),
            (position_balance_key(owner, ids[0]), position_balances[0]),
            (position_balance_key(owner, ids[1]), position_balances[1]),
            (
                mapping_key_u256(U256::ONE, U256::ZERO),
                address_word(MODULE_PROXY).unwrap(),
            ),
        ];
        let mut pusd_storage = vec![
            (slot, address_word(TEST_PUSD_IMPLEMENTATION).unwrap()),
            (pusd_balance_key(owner), pusd_balance),
        ];
        if let Some((module_positions, module_cash, module_roles)) = module_state {
            position_storage.extend([
                (position_balance_key(module, ids[0]), module_positions[0]),
                (position_balance_key(module, ids[1]), module_positions[1]),
            ]);
            pusd_storage.extend([
                (pusd_balance_key(module), module_cash),
                (roles_storage_key(module), module_roles),
            ]);
        }
        let mut exchange_storage =
            vec![(slot, address_word(CURRENT_EXCHANGE_IMPLEMENTATION).unwrap())];
        for (key, value) in exchange_storage_words {
            assert_ne!(
                *key, slot,
                "additional Exchange key must not replace the implementation slot"
            );
            assert!(
                exchange_storage.iter().all(|(existing, _)| existing != key),
                "additional Exchange storage keys must be unique"
            );
            exchange_storage.push((*key, *value));
        }
        let mut accounts = vec![
            account_with_storage(
                EXCHANGE_PROXY,
                parse_fixed_b256(ERC1967_PROXY_CODE_HASH).unwrap(),
                exchange_storage,
            ),
            account_without_storage(
                CURRENT_EXCHANGE_IMPLEMENTATION,
                parse_fixed_b256(CURRENT_EXCHANGE_CODE_HASH).unwrap(),
            ),
            account_with_storage(
                POSITION_MANAGER_PROXY,
                parse_fixed_b256(ERC1967_PROXY_CODE_HASH).unwrap(),
                position_storage,
            ),
            account_without_storage(
                POSITION_MANAGER_IMPLEMENTATION,
                parse_fixed_b256(POSITION_MANAGER_CODE_HASH).unwrap(),
            ),
            account_with_storage(
                TEST_PUSD_PROXY,
                parse_fixed_b256(TEST_PUSD_PROXY_CODE_HASH).unwrap(),
                pusd_storage,
            ),
            account_without_storage(
                TEST_PUSD_IMPLEMENTATION,
                parse_fixed_b256(TEST_PUSD_IMPLEMENTATION_CODE_HASH).unwrap(),
            ),
            account_with_storage(
                MODULE_PROXY,
                parse_fixed_b256(MODULE_PROXY_CODE_HASH).unwrap(),
                module_storage,
            ),
            account_without_storage(
                module_impl_address,
                if fault == FixtureFault::WrongRuntimeCode {
                    B256::repeat_byte(0x77)
                } else {
                    expected_runtime_hash(module_impl).unwrap()
                },
            ),
            account_with_storage(
                CONDITIONAL_TOKENS,
                if fault == FixtureFault::WrongCtfCode {
                    B256::repeat_byte(0x77)
                } else {
                    B256::from(super::super::CTF_CONDITIONAL_TOKENS_CODE_HASH_CANDIDATE)
                },
                ctf_storage,
            ),
        ];
        if let Some(migration) = migration_state {
            let usdce_impl = super::super::USDC_E_IMPLEMENTATION_ADDRESS;
            let usdce_proxy = super::super::USDC_E_PROXY_ADDRESS;
            let usdce_keys = [
                parse_fixed_b256(super::super::USDC_E_MATIC_IMPLEMENTATION_SLOT).unwrap(),
                super::super::u256_slot(super::super::USDC_E_DECIMALS_SLOT),
                usdce_balance_key(module),
                usdce_balance_key(parse_address(CONDITIONAL_TOKENS).unwrap()),
                usdce_balance_key(parse_address(LEGACY_VAULT).unwrap()),
            ];
            accounts.extend([
                account_with_storage(
                    usdce_proxy,
                    parse_fixed_b256(super::super::USDC_E_PROXY_CODE_HASH_CANDIDATE).unwrap(),
                    usdce_keys
                        .into_iter()
                        .zip([
                            address_word(usdce_impl).unwrap(),
                            U256::from(6),
                            migration.usdce_values[0],
                            migration.usdce_values[1],
                            migration.usdce_values[2],
                        ])
                        .collect(),
                ),
                account_without_storage(
                    usdce_impl,
                    parse_fixed_b256(super::super::USDC_E_IMPLEMENTATION_CODE_HASH_CANDIDATE)
                        .unwrap(),
                ),
            ]);
        }
        let mut trie = HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter(
            accounts.iter().map(|(address, _, _)| account_path(address)),
        ));
        let mut sorted = accounts
            .iter_mut()
            .map(|(address, account, entries)| {
                (
                    account_path(address),
                    address.clone(),
                    *account,
                    entries.clone(),
                )
            })
            .collect::<Vec<_>>();
        sorted.sort_by_key(|(path, _, _, _)| *path);
        for (path, _, account, _) in &sorted {
            trie.add_leaf(*path, &alloy_rlp::encode(*account));
        }
        let state_root = trie.root();
        let nodes = trie.take_proof_nodes();
        let proofs = sorted.into_iter().map(|(path, address, account, entries)| {
            let account_proof = nodes.matching_nodes_sorted(&path).into_iter().map(|(_, node)| format!("0x{}", hex::encode(node))).collect::<Vec<_>>();
            let storage_proof = entries.into_iter().map(|(key, value, proof)| json!({"key":format!("{key:#x}"),"value":format!("{value:#x}"),"proof":proof})).collect::<Vec<_>>();
            (address.clone(), json!({"address":address,"nonce":format!("0x{:x}",account.nonce),"balance":format!("{:#x}",account.balance),"storageHash":format!("{:#x}",account.storage_root),"codeHash":format!("{:#x}",account.code_hash),"accountProof":account_proof,"storageProof":storage_proof}))
        }).collect::<BTreeMap<_, _>>();
        let block_header = super::super::header_binding::fixture_header(
            BLOCK,
            &format!("0x{}", "11".repeat(32)),
            &format!("{state_root:#x}"),
            &format!("0x{}", "00".repeat(32)),
            &format!("0x{}", "00".repeat(32)),
        );
        let finalized_header = super::super::header_binding::fixture_header(
            BLOCK + 1,
            block_header["hash"].as_str().unwrap(),
            &format!("{state_root:#x}"),
            &format!("0x{}", "00".repeat(32)),
            &format!("0x{}", "00".repeat(32)),
        );
        Arc::new(Fixture {
            block_header,
            finalized_header,
            proofs,
            responses: Arc::new(Mutex::new(Vec::new())),
            requests: Arc::new(AtomicUsize::new(0)),
            fault,
            proof_started: Arc::new(tokio::sync::Notify::new()),
            early_delay_completed: std::sync::atomic::AtomicBool::new(false),
            early_delay_release: tokio::sync::Notify::new(),
            late_ctf_started: std::sync::atomic::AtomicBool::new(false),
            late_result_started: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub(super) fn rooted_point_proof_packet(
        position_balances: [U256; 2],
        pusd_balance: U256,
    ) -> (String, BTreeMap<String, Value>) {
        let fixture = rooted_fixture_with_balances(
            false,
            FixtureFault::None,
            position_balances,
            pusd_balance,
        );
        (
            fixture.block_header["stateRoot"]
                .as_str()
                .unwrap()
                .to_owned(),
            fixture.proofs.clone(),
        )
    }

    pub(super) fn rooted_module_point_proof_packet(
        owner: &str,
        owner_positions: [U256; 2],
        owner_cash: U256,
        module_positions: [U256; 2],
        module_cash: U256,
        module_roles: U256,
    ) -> (String, BTreeMap<String, Value>) {
        rooted_module_point_proof_packet_with_result(
            owner,
            owner_positions,
            owner_cash,
            module_positions,
            module_cash,
            module_roles,
            [U256::from(2), U256::ZERO, U256::ZERO, U256::ZERO],
            [U256::ZERO; 3],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn rooted_module_point_proof_packet_with_result(
        owner: &str,
        owner_positions: [U256; 2],
        owner_cash: U256,
        module_positions: [U256; 2],
        module_cash: U256,
        module_roles: U256,
        ctf_values: [U256; 4],
        result_values: [U256; 3],
    ) -> (String, BTreeMap<String, Value>) {
        let fixture = rooted_fixture_with_owner_module_state(
            false,
            FixtureFault::None,
            owner_positions,
            owner_cash,
            MODULE_IMPL,
            Some(ctf_values),
            Some(result_values),
            owner,
            Some((module_positions, module_cash, module_roles)),
            None,
        );
        (
            fixture.block_header["stateRoot"]
                .as_str()
                .unwrap()
                .to_owned(),
            fixture.proofs.clone(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn rooted_native_module_operation_point_packet(
        owner: &str,
        condition_id: B256,
        owner_positions: [U256; 2],
        owner_cash: U256,
        module_positions: [U256; 2],
        module_cash: U256,
        module_roles: U256,
        result_values: [U256; 3],
    ) -> (String, BTreeMap<String, Value>) {
        rooted_native_module_operation_point_packet_with_exchange_storage(
            owner,
            condition_id,
            owner_positions,
            owner_cash,
            module_positions,
            module_cash,
            module_roles,
            result_values,
            &[],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn rooted_native_module_operation_point_packet_with_exchange_storage(
        owner: &str,
        condition_id: B256,
        owner_positions: [U256; 2],
        owner_cash: U256,
        module_positions: [U256; 2],
        module_cash: U256,
        module_roles: U256,
        result_values: [U256; 3],
        exchange_storage_words: &[(B256, U256)],
    ) -> (String, BTreeMap<String, Value>) {
        let fixture = rooted_fixture_with_owner_module_state_and_exchange_storage(
            false,
            FixtureFault::NativeBinary,
            owner_positions,
            owner_cash,
            MODULE_IMPL,
            Some([U256::ZERO; 4]),
            Some(result_values),
            owner,
            Some((module_positions, module_cash, module_roles)),
            Some(condition_id),
            exchange_storage_words,
        );
        (
            fixture.block_header["stateRoot"]
                .as_str()
                .unwrap()
                .to_owned(),
            fixture.proofs.clone(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn rooted_migration_point_proof_packet(
        owner: &str,
        owner_positions: [U256; 2],
        owner_cash: U256,
        module_positions: [U256; 2],
        module_cash: U256,
        module_roles: U256,
        ctf_values: [U256; 4],
        result_values: [U256; 3],
        migration_ctf_values: [U256; 5],
        migration_usdce_values: [U256; 3],
        pause_timestamp: U256,
    ) -> (String, BTreeMap<String, Value>) {
        let fixture = rooted_fixture_with_migration_state(
            false,
            FixtureFault::None,
            owner_positions,
            owner_cash,
            MODULE_IMPL,
            Some(ctf_values),
            Some(result_values),
            owner,
            Some((module_positions, module_cash, module_roles)),
            Some(MigrationFixtureState {
                ctf_values: migration_ctf_values,
                usdce_values: migration_usdce_values,
                pause_timestamp,
            }),
            None,
        );
        (
            fixture.block_header["stateRoot"]
                .as_str()
                .unwrap()
                .to_owned(),
            fixture.proofs.clone(),
        )
    }

    pub(super) fn rooted_native_binary_point_proof_packet(
        owner: &str,
        condition_id: B256,
        owner_positions: [U256; 2],
        owner_cash: U256,
        result_values: [U256; 3],
    ) -> (String, BTreeMap<String, Value>) {
        let fixture = rooted_fixture_with_migration_state(
            false,
            FixtureFault::NativeBinary,
            owner_positions,
            owner_cash,
            MODULE_IMPL,
            Some([U256::ZERO; 4]),
            Some(result_values),
            owner,
            None,
            None,
            Some(condition_id),
        );
        (
            fixture.block_header["stateRoot"]
                .as_str()
                .unwrap()
                .to_owned(),
            fixture.proofs.clone(),
        )
    }

    pub(super) fn rooted_native_binary_alias_point_proof_packet(
        owner: &str,
        condition_id: B256,
        owner_positions: [U256; 2],
        owner_cash: U256,
        result_values: [U256; 3],
    ) -> (String, BTreeMap<String, Value>) {
        let fixture = rooted_fixture_with_migration_state(
            false,
            FixtureFault::AliasMapping,
            owner_positions,
            owner_cash,
            MODULE_IMPL,
            Some([U256::ZERO; 4]),
            Some(result_values),
            owner,
            None,
            None,
            Some(condition_id),
        );
        (
            fixture.block_header["stateRoot"]
                .as_str()
                .unwrap()
                .to_owned(),
            fixture.proofs.clone(),
        )
    }

    pub(super) fn rooted_point_proof_packet_with_identity(
        position_balances: [U256; 2],
        pusd_balance: U256,
        module_implementation: &str,
        ctf_values: [U256; 4],
    ) -> (String, BTreeMap<String, Value>) {
        let fixture = rooted_fixture_with_identity(
            false,
            FixtureFault::None,
            position_balances,
            pusd_balance,
            module_implementation,
            Some(ctf_values),
        );
        (
            fixture.block_header["stateRoot"]
                .as_str()
                .unwrap()
                .to_owned(),
            fixture.proofs.clone(),
        )
    }

    fn account_with_storage(
        address: &str,
        code_hash: B256,
        entries: Vec<(B256, U256)>,
    ) -> AccountData {
        let mut trie = HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter(
            entries.iter().map(|(key, _)| storage_path(*key)),
        ));
        let mut sorted = entries
            .into_iter()
            .map(|(key, value)| (storage_path(key), key, value))
            .collect::<Vec<_>>();
        sorted.sort_by_key(|(path, _, _)| *path);
        for (path, _, value) in &sorted {
            if !value.is_zero() {
                trie.add_leaf(*path, &rlp_u256(*value));
            }
        }
        let storage_root = trie.root();
        let nodes = trie.take_proof_nodes();
        let proofs = sorted
            .into_iter()
            .map(|(path, key, value)| {
                let proof = nodes
                    .matching_nodes_sorted(&path)
                    .into_iter()
                    .map(|(_, node)| format!("0x{}", hex::encode(node)))
                    .collect();
                (key, value, proof)
            })
            .collect();
        (
            address.to_ascii_lowercase(),
            TrieAccount {
                nonce: 1,
                balance: U256::ZERO,
                storage_root,
                code_hash,
            },
            proofs,
        )
    }

    fn account_without_storage(address: &str, code_hash: B256) -> AccountData {
        (
            address.to_ascii_lowercase(),
            TrieAccount {
                nonce: 1,
                balance: U256::ZERO,
                storage_root: EMPTY_ROOT_HASH,
                code_hash,
            },
            Vec::new(),
        )
    }

    fn account_path(address: &str) -> Nibbles {
        Nibbles::unpack(B256::from_slice(&Keccak256::digest(
            hex::decode(&address[2..]).unwrap(),
        )))
    }
    fn storage_path(key: B256) -> Nibbles {
        Nibbles::unpack(B256::from_slice(&Keccak256::digest(key.as_slice())))
    }

    fn ctf_position_balance_key(owner: Address, id: B256) -> B256 {
        let mut outer = [0_u8; 64];
        outer[..32].copy_from_slice(id.as_slice());
        outer[63] = 1;
        let outer_hash = Keccak256::digest(outer);
        let mut inner = [0_u8; 64];
        inner[12..32].copy_from_slice(owner.as_slice());
        inner[32..].copy_from_slice(&outer_hash);
        B256::from_slice(&Keccak256::digest(inner))
    }

    fn ctf_approval_key(owner: Address, operator: Address) -> B256 {
        let mut outer = [0_u8; 64];
        outer[12..32].copy_from_slice(owner.as_slice());
        outer[63] = 2;
        let outer_hash = Keccak256::digest(outer);
        let mut inner = [0_u8; 64];
        inner[12..32].copy_from_slice(operator.as_slice());
        inner[32..].copy_from_slice(&outer_hash);
        B256::from_slice(&Keccak256::digest(inner))
    }

    fn usdce_balance_key(account: Address) -> B256 {
        let mut preimage = [0_u8; 64];
        preimage[12..32].copy_from_slice(account.as_slice());
        B256::from_slice(&Keccak256::digest(preimage))
    }

    fn migration_pause_key(condition: B256) -> B256 {
        let mut preimage = [0_u8; 64];
        preimage[..29].copy_from_slice(&condition.as_slice()[..29]);
        preimage[63] = 1;
        B256::from_slice(&Keccak256::digest(preimage))
    }

    fn position_balance_key(owner: Address, id: B256) -> B256 {
        let owner_value = U256::from_be_slice(owner.as_slice());
        let seed = (owner_value << 96_u32) | U256::from(0x9a31110384e0b0c9_u64);
        let mut preimage = [0_u8; 64];
        preimage[..32].copy_from_slice(id.as_slice());
        preimage[32..].copy_from_slice(&seed.to_be_bytes::<32>());
        B256::from_slice(&Keccak256::digest(preimage))
    }

    fn pusd_balance_key(owner: Address) -> B256 {
        let mut preimage = [0_u8; 32];
        preimage[..20].copy_from_slice(owner.as_slice());
        preimage[28..].copy_from_slice(&[0x87, 0xa2, 0x11, 0xa2]);
        B256::from_slice(&Keccak256::digest(preimage))
    }

    fn roles_storage_key(owner: Address) -> B256 {
        let mut preimage = [0_u8; 32];
        preimage[..20].copy_from_slice(owner.as_slice());
        preimage[28..].copy_from_slice(&[0x8b, 0x78, 0xc6, 0xd8]);
        B256::from_slice(&Keccak256::digest(preimage))
    }

    #[tokio::test]
    async fn full_legacy_binary_balance_proof_binds_mapping_runtime_and_ctf_state() {
        for (case, resolved) in [("unresolved", false), ("resolved", true)] {
            let pair = verifier_pair(resolved).await;
            let observation = pair
                .verifier
                .verify_fifth_legacy_binary_balances_bounded(
                    OWNER,
                    LEGACY,
                    BLOCK,
                    &pair.expected_hash,
                    28,
                    Duration::from_secs(5),
                )
                .await
                .unwrap();
            assert_eq!(
                observation.legacy_condition_id(),
                parse_fixed_b256(LEGACY).unwrap()
            );
            assert_eq!(
                observation.v2_condition_id(),
                parse_fixed_b256(
                    "0x0112121212121212121212121212121212000000000000000000000000000000"
                )
                .unwrap()
            );
            assert_eq!(observation.v2_position_ids()[0].as_slice()[31], 0);
            assert_eq!(observation.v2_position_ids()[1].as_slice()[31], 1);
            assert_eq!(
                observation.module_proxy(),
                parse_address(MODULE_PROXY).unwrap()
            );
            assert_eq!(
                observation.module_implementation(),
                parse_address(MODULE_IMPL).unwrap()
            );
            assert_eq!(
                observation.module_implementation_code_hash(),
                expected_runtime_hash(parse_address(MODULE_IMPL).unwrap()).unwrap()
            );
            assert_eq!(
                observation.ctf_condition_state().status(),
                if resolved {
                    CtfConditionStateStatus::ResolvedBinary
                } else {
                    CtfConditionStateStatus::PreparedBinaryUnresolved
                }
            );
            assert_eq!(observation.ctf_condition_state().block_number(), BLOCK);
            assert_eq!(
                observation.selected_balances().position_balance_a(),
                U256::from_be_slice(&[0x80; 32])
            );
            assert_eq!(
                observation.selected_balances().position_balance_b(),
                U256::from(42)
            );
            assert_eq!(
                observation.selected_balances().pusd_balance(),
                U256::from_be_slice(&[0x91; 32])
            );
            assert_eq!(pair.primary.requests.load(Ordering::Acquire), 14);
            assert_eq!(pair.secondary.requests.load(Ordering::Acquire), 14);
            capture(case, &observation, &pair.primary, &pair.secondary);
            pair.primary_task.abort();
            pair.secondary_task.abort();
        }
    }

    #[tokio::test]
    async fn legacy_binary_identity_rejects_unbound_code_mapping_and_ctf_states() {
        for fault in [
            FixtureFault::WrongRuntimeCode,
            FixtureFault::AliasMapping,
            FixtureFault::UnpreparedCtf,
            FixtureFault::NonBinaryCtf,
            FixtureFault::WrongCtfCode,
            FixtureFault::MissingRegistryEntry,
            FixtureFault::ExtraRegistryEntry,
        ] {
            let pair = verifier_pair_with_faults(false, fault, fault).await;
            let result = pair
                .verifier
                .verify_fifth_legacy_binary_balances_bounded(
                    OWNER,
                    LEGACY,
                    BLOCK,
                    &pair.expected_hash,
                    28,
                    Duration::from_secs(5),
                )
                .await;
            assert!(
                result.is_err(),
                "fault {fault:?} must not yield identity evidence"
            );
            pair.primary_task.abort();
            pair.secondary_task.abort();
        }
    }

    #[tokio::test]
    async fn legacy_binary_identity_rejects_provider_root_divergence() {
        let pair =
            verifier_pair_with_faults(false, FixtureFault::None, FixtureFault::NonBinaryCtf).await;
        let result = pair
            .verifier
            .verify_fifth_legacy_binary_balances_bounded(
                OWNER,
                LEGACY,
                BLOCK,
                &pair.expected_hash,
                28,
                Duration::from_secs(5),
            )
            .await;
        assert!(result.is_err());
        pair.primary_task.abort();
        pair.secondary_task.abort();
    }

    #[tokio::test]
    async fn legacy_binary_identity_uses_one_request_budget_and_deadline() {
        let pair = verifier_pair(false).await;
        let result = pair
            .verifier
            .verify_fifth_legacy_binary_balances_bounded(
                OWNER,
                LEGACY,
                BLOCK,
                &pair.expected_hash,
                27,
                Duration::from_secs(5),
            )
            .await;
        assert_eq!(
            result.unwrap_err(),
            BoundedFifthLegacyBinaryBalancesError::RequestBudgetExceeded
        );
        let sent = pair.primary.requests.load(Ordering::Acquire)
            + pair.secondary.requests.load(Ordering::Acquire);
        assert!((26..=27).contains(&sent));
        for fixture in [&pair.primary, &pair.secondary] {
            assert!(fixture.responses.lock().unwrap().iter().any(|row| {
                row["method"] == "eth_getProof"
                    && row["params"][0]
                        .as_str()
                        .is_some_and(|address| address.eq_ignore_ascii_case(MODULE_IMPL))
            }));
        }
        pair.primary_task.abort();
        pair.secondary_task.abort();

        let pair = verifier_pair_with_faults(
            false,
            FixtureFault::DeadlineEarlyAndLate,
            FixtureFault::DeadlineEarlyAndLate,
        )
        .await;
        tokio::time::pause();
        let verifier = pair.verifier;
        let expected_hash = pair.expected_hash.clone();
        let mut task = tokio::spawn(async move {
            verifier
                .verify_fifth_legacy_binary_balances_bounded(
                    OWNER,
                    LEGACY,
                    BLOCK,
                    &expected_hash,
                    28,
                    Duration::from_secs(1),
                )
                .await
        });
        let result = advance_paired_fixture_deadline(
            [&pair.primary, &pair.secondary],
            &mut task,
            |fixture| fixture.late_ctf_started.load(Ordering::Acquire),
        )
        .await;
        assert_eq!(
            result.unwrap_err(),
            BoundedFifthLegacyBinaryBalancesError::Timeout
        );
        for fixture in [&pair.primary, &pair.secondary] {
            assert!(fixture.early_delay_completed.load(Ordering::Acquire));
            assert!(fixture.late_ctf_started.load(Ordering::Acquire));
        }
        tokio::time::resume();
        pair.primary_task.abort();
        pair.secondary_task.abort();
    }

    #[tokio::test]
    async fn legacy_binary_identity_cancels_when_caller_drops_the_future() {
        let pair =
            verifier_pair_with_faults(false, FixtureFault::GateProof, FixtureFault::GateProof)
                .await;
        let started = pair.primary.proof_started.clone();
        let verifier = pair.verifier;
        let expected_hash = pair.expected_hash.clone();
        let task = tokio::spawn(async move {
            verifier
                .verify_fifth_legacy_binary_balances_bounded(
                    OWNER,
                    LEGACY,
                    BLOCK,
                    &expected_hash,
                    28,
                    Duration::from_secs(30),
                )
                .await
        });
        let notified = started.notified();
        tokio::pin!(notified);
        tokio::select! {
            () = &mut notified => {},
            () = tokio::time::sleep(Duration::from_secs(2)) => panic!("root proof request did not start"),
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        pair.primary_task.abort();
        pair.secondary_task.abort();
    }

    #[tokio::test]
    async fn legacy_binary_identity_rejects_invalid_inputs_before_rpc() {
        let pair = verifier_pair(false).await;
        for (owner, condition, block_hash, budget, timeout) in [
            (
                "0x0000000000000000000000000000000000000000",
                LEGACY,
                pair.expected_hash.as_str(),
                28,
                Duration::from_secs(1),
            ),
            (
                OWNER,
                "0x12",
                pair.expected_hash.as_str(),
                28,
                Duration::from_secs(1),
            ),
            (OWNER, LEGACY, "0x01", 28, Duration::from_secs(1)),
            (
                OWNER,
                LEGACY,
                pair.expected_hash.as_str(),
                0,
                Duration::from_secs(1),
            ),
            (
                OWNER,
                LEGACY,
                pair.expected_hash.as_str(),
                28,
                Duration::ZERO,
            ),
        ] {
            assert!(matches!(
                pair.verifier
                    .verify_fifth_legacy_binary_balances_bounded(
                        owner, condition, BLOCK, block_hash, budget, timeout
                    )
                    .await,
                Err(BoundedFifthLegacyBinaryBalancesError::Verification(
                    ChainLogAuditError::InvalidInput
                ))
            ));
        }
        assert_eq!(pair.primary.requests.load(Ordering::Acquire), 0);
        assert_eq!(pair.secondary.requests.load(Ordering::Acquire), 0);
        pair.primary_task.abort();
        pair.secondary_task.abort();
    }

    fn capture(
        case: &str,
        observation: &FifthLegacyBinaryBalancesObservation,
        primary: &Fixture,
        secondary: &Fixture,
    ) {
        let Ok(directory) = std::env::var("PDH_CAPTURE_FIFTH_LEGACY_BINARY_DIRECTORY") else {
            return;
        };
        let mut unique = BTreeMap::new();
        let primary_rows = primary.responses.lock().unwrap().clone();
        let secondary_rows = secondary.responses.lock().unwrap().clone();
        for row in primary_rows.iter().chain(secondary_rows.iter()) {
            let key = serde_json::to_string(&json!([row["method"], row["params"]])).unwrap();
            if let Some(previous) = unique.insert(key, row.clone()) {
                assert_eq!(previous["result"], row["result"]);
            }
        }
        let selected = observation.selected_balances();
        let rows = unique.into_values().collect::<Vec<_>>();
        let envelope = json!({
            "provenance":"Synthetic deterministic rooted loopback fixture; no provider or chain retrieval.",
            "case":case,
            "owner":selected.owner(),
            "legacy_condition_id":format!("{:#x}",observation.legacy_condition_id()),
            "block_number":selected.block_number(),
            "block_hash":selected.block_hash(),
            "state_root":selected.state_root(),
            "v2_condition_id":format!("{:#x}",observation.v2_condition_id()),
            "v2_position_ids":observation.v2_position_ids().map(|id| format!("{id:#x}")),
            "legacy_collection_ids":observation.legacy_collection_ids().map(|id| format!("{id:#x}")),
            "legacy_position_ids":observation.legacy_position_ids().map(|id| format!("{id:#x}")),
            "module_proxy":format!("{:#x}",observation.module_proxy()),
            "module_implementation":format!("{:#x}",observation.module_implementation()),
            "module_implementation_code_hash":format!("{:#x}",observation.module_implementation_code_hash()),
            "ctf_payout_numerator_count":format!("{:#x}",observation.ctf_condition_state().payout_numerator_count()),
            "ctf_payout_denominator":format!("{:#x}",observation.ctf_condition_state().payout_denominator()),
            "ctf_payout_numerators":observation.ctf_condition_state().payout_numerators().map(|value| format!("{value:#x}")),
            "ctf_state":match observation.ctf_condition_state().status() { CtfConditionStateStatus::PreparedBinaryUnresolved => "prepared_binary_unresolved", CtfConditionStateStatus::ResolvedBinary => "resolved_binary", _ => "unsupported" },
            "rpc_responses":rows,
        });
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../")
            .join(directory)
            .join(format!("fifth-legacy-binary-{case}-rpc.json"));
        let bytes = serde_json::to_vec(&envelope).unwrap();
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
    }

    fn capture_result(
        case: &str,
        observation: &super::super::fifth_legacy_binary_result::FifthLegacyBinaryResultObservation,
        primary: &Fixture,
        secondary: &Fixture,
    ) {
        let Ok(directory) = std::env::var("PDH_CAPTURE_FIFTH_LEGACY_BINARY_RESULT_DIRECTORY")
        else {
            return;
        };
        let mut unique = BTreeMap::new();
        let primary_rows = primary.responses.lock().unwrap().clone();
        let secondary_rows = secondary.responses.lock().unwrap().clone();
        for row in primary_rows.iter().chain(secondary_rows.iter()) {
            let key = serde_json::to_string(&json!([row["method"], row["params"]])).unwrap();
            if let Some(previous) = unique.insert(key, row.clone()) {
                assert_eq!(previous["result"], row["result"]);
            }
        }
        let balances = observation.balances();
        let selected = balances.selected_balances();
        let envelope = json!({
            "provenance":"Synthetic deterministic rooted loopback fixture; no provider or chain retrieval.",
            "case":case,
            "owner":selected.owner(),
            "legacy_condition_id":format!("{:#x}",balances.legacy_condition_id()),
            "block_number":selected.block_number(),
            "block_hash":selected.block_hash(),
            "state_root":selected.state_root(),
            "module_proxy":format!("{:#x}",balances.module_proxy()),
            "module_implementation":format!("{:#x}",balances.module_implementation()),
            "module_implementation_code_hash":format!("{:#x}",balances.module_implementation_code_hash()),
            "ctf_payout_denominator":format!("{:#x}",balances.ctf_condition_state().payout_denominator()),
            "ctf_payout_numerators":balances.ctf_condition_state().payout_numerators().map(|value| format!("{value:#x}")),
            "ctf_state":format!("{:?}",balances.ctf_condition_state().status()),
            "result_status":format!("{:?}",observation.status()),
            "result_length":format!("{:#x}",observation.result_length()),
            "normalized_numerators":observation.normalized_numerators().map(|values| values.map(|value| format!("{value:#x}"))),
            "payout_denominator":format!("{:#x}",observation.payout_denominator()),
            "storage_keys":observation.storage_keys().map(|key| format!("{key:#x}")),
            "source_policy_version":observation.source_policy_version(),
            "rpc_responses":unique.into_values().collect::<Vec<_>>(),
        });
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../")
            .join(directory)
            .join(format!("fifth-legacy-binary-result-{case}-rpc.json"));
        let bytes = serde_json::to_vec(&envelope).unwrap();
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
    }

    #[test]
    fn legacy_id_maps_to_canonical_low_128_v2_condition_and_distinct_outcomes() {
        let legacy = B256::repeat_byte(0x12);
        let condition = derive_v2_condition_id(legacy);
        assert_eq!(
            format!("{condition:064x}"),
            format!("01{}{}", "12".repeat(16), "00".repeat(15))
        );
        assert_eq!(
            format!("{:064x}", mapping_key_bytes31(condition, 150)),
            "31bae0cc7b3cf22a81742bfdb5cdc92a21ade48d1b63534af17d0cb34bf5ac80"
        );
        assert_eq!(
            mapping_key_u256(U256::from(1), U256::ZERO),
            B256::from_str("0xada5013122d395ba3c54772283fb069b10426056ef8ca54750cb9bb552a59e7d")
                .unwrap()
        );
        let ids = [
            derive_v2_position_id(condition, 0),
            derive_v2_position_id(condition, 1),
        ];
        assert_ne!(ids[0], ids[1]);
        assert_eq!(ids[0].as_slice()[..31], condition.as_slice()[..31]);
        assert_eq!(ids[0].as_slice()[31], 0);
        assert_eq!(ids[1].as_slice()[31], 1);
        let aliased = B256::from_slice(&[&[0xab; 16][..], &legacy.as_slice()[16..]].concat());
        assert_eq!(derive_v2_condition_id(aliased), condition);
        assert_ne!(aliased, legacy);
    }

    #[test]
    fn complete_runtime_hash_is_address_bound_and_changes_only_via_declared_self_sites() {
        let first = expected_runtime_hash(
            Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
        )
        .unwrap();
        let second = expected_runtime_hash(
            Address::from_str("0x2222222222222222222222222222222222222222").unwrap(),
        )
        .unwrap();
        assert_eq!(
            first,
            B256::from_str("0x905aeec7d25e04ec682ca56efb24c771c55d38df32ef3fe4213ad7c43bc17d86")
                .unwrap()
        );
        assert_eq!(
            second,
            B256::from_str("0x2a08ade368db7baf27694469198054f230de81c4469af120355b5fa43aa462dd")
                .unwrap()
        );
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn legacy_binary_result_states_use_authenticated_storage_and_capture_cli_cases() {
        for (case, values, ctf, expected_status, expected_numerators) in [
            (
                "unresolved",
                [U256::ZERO, U256::from(123_u64), U256::from(456_u64)],
                [U256::from(2), U256::ZERO, U256::ZERO, U256::ZERO],
                FifthLegacyBinaryResultStatus::StoredUnresolved,
                None,
            ),
            (
                "pending",
                [U256::ZERO, U256::from(250_000_u64), U256::from(750_000_u64)],
                [U256::from(2), U256::from(4), U256::ONE, U256::from(3)],
                FifthLegacyBinaryResultStatus::StoredUnresolved,
                None,
            ),
            (
                "resolved-remainder",
                [
                    U256::from(2),
                    U256::from(333_333_u64),
                    U256::from(666_667_u64),
                ],
                [U256::from(2), U256::from(3), U256::ONE, U256::from(2)],
                FifthLegacyBinaryResultStatus::ResolvedBinary,
                Some([U256::from(333_333_u64), U256::from(666_667_u64)]),
            ),
            (
                "resolved-zero-one",
                [U256::from(2), U256::ZERO, U256::from(1_000_000_u64)],
                [U256::from(2), U256::from(5), U256::ZERO, U256::from(5)],
                FifthLegacyBinaryResultStatus::ResolvedBinary,
                Some([U256::ZERO, U256::from(1_000_000_u64)]),
            ),
            (
                "resolved-one-zero",
                [U256::from(2), U256::from(1_000_000_u64), U256::ZERO],
                [U256::from(2), U256::from(7), U256::from(7), U256::ZERO],
                FifthLegacyBinaryResultStatus::ResolvedBinary,
                Some([U256::from(1_000_000_u64), U256::ZERO]),
            ),
        ] {
            let pair =
                result_verifier_pair(values, ctf, FixtureFault::None, FixtureFault::None).await;
            let observation = pair
                .verifier
                .verify_fifth_legacy_binary_result_bounded(
                    OWNER,
                    LEGACY,
                    BLOCK,
                    &pair.expected_hash,
                    30,
                    Duration::from_secs(10),
                )
                .await
                .unwrap();
            assert_eq!(observation.status(), &expected_status, "{case}");
            assert_eq!(
                observation.result_length(),
                if expected_numerators.is_some() {
                    U256::from(2)
                } else {
                    U256::ZERO
                },
                "{case}"
            );
            assert_eq!(
                observation.normalized_numerators(),
                expected_numerators,
                "{case}"
            );
            assert_eq!(observation.payout_denominator(), U256::from(1_000_000_u64));
            assert_eq!(
                pair.primary.requests.load(Ordering::Acquire)
                    + pair.secondary.requests.load(Ordering::Acquire),
                30
            );
            if matches!(case, "unresolved" | "pending" | "resolved-remainder") {
                capture_result(case, &observation, &pair.primary, &pair.secondary);
            }
            pair.primary_task.abort();
            pair.secondary_task.abort();
        }
    }

    #[tokio::test]
    async fn legacy_binary_result_rejects_invalid_lengths_values_ctf_and_proofs() {
        for (result, ctf) in [
            (
                [U256::ONE, U256::ZERO, U256::ZERO],
                [U256::from(2), U256::from(4), U256::ONE, U256::from(3)],
            ),
            (
                [
                    U256::from(2),
                    U256::from(250_000_u64),
                    U256::from(700_000_u64),
                ],
                [U256::from(2), U256::from(4), U256::ONE, U256::from(3)],
            ),
            (
                [
                    U256::from(2),
                    U256::from(333_333_u64),
                    U256::from(666_667_u64),
                ],
                [U256::from(2), U256::from(4), U256::ONE, U256::from(3)],
            ),
            (
                [
                    U256::from(2),
                    U256::from(250_000_u64),
                    U256::from(750_000_u64),
                ],
                [U256::from(2), U256::ZERO, U256::ZERO, U256::ZERO],
            ),
            (
                [U256::from(2), U256::from(1_000_000_u64), U256::ZERO],
                [U256::from(2), U256::MAX, U256::MAX, U256::ZERO],
            ),
            (
                [U256::from(3), U256::from(1_000_000_u64), U256::ZERO],
                [U256::from(2), U256::from(7), U256::from(7), U256::ZERO],
            ),
        ] {
            let pair =
                result_verifier_pair(result, ctf, FixtureFault::None, FixtureFault::None).await;
            let observation = pair
                .verifier
                .verify_fifth_legacy_binary_result_bounded(
                    OWNER,
                    LEGACY,
                    BLOCK,
                    &pair.expected_hash,
                    40,
                    Duration::from_secs(10),
                )
                .await;
            assert!(matches!(
                observation,
                Err(BoundedFifthLegacyBinaryResultError::Verification(
                    ChainLogAuditError::Unverified
                ))
            ));
            pair.primary_task.abort();
            pair.secondary_task.abort();
        }

        for fault in [
            FixtureFault::MissingResultEntry,
            FixtureFault::ExtraResultEntry,
            FixtureFault::WrongResultKey,
            FixtureFault::WrongResultAddress,
            FixtureFault::WrongResultStorageRoot,
            FixtureFault::WrongResultValue,
        ] {
            let pair = result_verifier_pair(
                [
                    U256::from(2),
                    U256::from(250_000_u64),
                    U256::from(750_000_u64),
                ],
                [U256::from(2), U256::from(4), U256::ONE, U256::from(3)],
                fault,
                fault,
            )
            .await;
            assert!(matches!(
                pair.verifier
                    .verify_fifth_legacy_binary_result_bounded(
                        OWNER,
                        LEGACY,
                        BLOCK,
                        &pair.expected_hash,
                        40,
                        Duration::from_secs(10),
                    )
                    .await,
                Err(BoundedFifthLegacyBinaryResultError::Verification(
                    ChainLogAuditError::Unverified
                ))
            ));
            pair.primary_task.abort();
            pair.secondary_task.abort();
        }
    }

    #[tokio::test]
    async fn legacy_binary_result_shares_budget_deadline_and_cancellation() {
        let pair = result_verifier_pair(
            [U256::ZERO, U256::ZERO, U256::ZERO],
            [U256::from(2), U256::ZERO, U256::ZERO, U256::ZERO],
            FixtureFault::None,
            FixtureFault::None,
        )
        .await;
        assert_eq!(
            pair.verifier
                .verify_fifth_legacy_binary_result_bounded(
                    OWNER,
                    LEGACY,
                    BLOCK,
                    &pair.expected_hash,
                    29,
                    Duration::from_secs(10),
                )
                .await
                .unwrap_err(),
            BoundedFifthLegacyBinaryResultError::RequestBudgetExceeded
        );
        let arrivals = pair.primary.requests.load(Ordering::Acquire)
            + pair.secondary.requests.load(Ordering::Acquire);
        assert!(
            (28..=29).contains(&arrivals),
            "observed {arrivals} server arrivals"
        );
        pair.primary_task.abort();
        pair.secondary_task.abort();

        let pair = result_verifier_pair(
            [U256::ZERO, U256::ZERO, U256::ZERO],
            [U256::from(2), U256::ZERO, U256::ZERO, U256::ZERO],
            FixtureFault::ResultDeadlineEarlyAndLate,
            FixtureFault::ResultDeadlineEarlyAndLate,
        )
        .await;
        // Advance only the injected delays; loopback I/O and proof work must not
        // consume the shared one-second deadline on a busy test host.
        tokio::time::pause();
        let verifier = pair.verifier;
        let expected_hash = pair.expected_hash.clone();
        let mut task = tokio::spawn(async move {
            verifier
                .verify_fifth_legacy_binary_result_bounded(
                    OWNER,
                    LEGACY,
                    BLOCK,
                    &expected_hash,
                    30,
                    Duration::from_secs(1),
                )
                .await
        });
        let result = advance_paired_fixture_deadline(
            [&pair.primary, &pair.secondary],
            &mut task,
            |fixture| fixture.late_result_started.load(Ordering::Acquire),
        )
        .await;
        assert_eq!(
            result.unwrap_err(),
            BoundedFifthLegacyBinaryResultError::Timeout
        );
        for fixture in [&pair.primary, &pair.secondary] {
            assert!(fixture.early_delay_completed.load(Ordering::Acquire));
            assert!(fixture.late_result_started.load(Ordering::Acquire));
        }
        tokio::time::resume();
        pair.primary_task.abort();
        pair.secondary_task.abort();

        let pair = result_verifier_pair(
            [U256::ZERO, U256::ZERO, U256::ZERO],
            [U256::from(2), U256::ZERO, U256::ZERO, U256::ZERO],
            FixtureFault::GateResultProof,
            FixtureFault::GateResultProof,
        )
        .await;
        let started = pair.primary.proof_started.clone();
        let verifier = pair.verifier;
        let expected_hash = pair.expected_hash.clone();
        let task = tokio::spawn(async move {
            verifier
                .verify_fifth_legacy_binary_result_bounded(
                    OWNER,
                    LEGACY,
                    BLOCK,
                    &expected_hash,
                    30,
                    Duration::from_secs(30),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), started.notified())
            .await
            .expect("result storage proof request did not start");
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        pair.primary_task.abort();
        pair.secondary_task.abort();
    }

    #[tokio::test]
    async fn legacy_ctf_pair_vectors_use_the_complete_caller_condition_id() {
        let legacy = B256::repeat_byte(0x12);
        let alias = B256::from_slice(&[&[0x34; 16][..], &legacy.as_slice()[16..]].concat());
        let deadline = Instant::now() + Duration::from_secs(2);
        let legacy_one = get_root_collection_id_bounded(legacy, 1, 128, deadline)
            .await
            .unwrap();
        let legacy_two = get_root_collection_id_bounded(legacy, 2, 128, deadline)
            .await
            .unwrap();
        let alias_one = get_root_collection_id_bounded(alias, 1, 128, deadline)
            .await
            .unwrap();
        let alias_two = get_root_collection_id_bounded(alias, 2, 128, deadline)
            .await
            .unwrap();
        assert_eq!(
            legacy_one,
            B256::from_str("0x4c27815e79741f9c08834a547f0f248b4417ae0f4ec0d2c789cd7f8393f3feb2")
                .unwrap()
        );
        assert_eq!(
            legacy_two,
            B256::from_str("0x2bf26376d30599e6b28eff3ab5f425368d4f58243d9b05db1fbaa23abd065a0c")
                .unwrap()
        );
        assert_eq!(
            position_id(parse_address(CONFIGURED_USDCE).unwrap(), legacy_one),
            B256::from_str("0xd46b4e85dd2cb18425b643d2523673a90491b1131f9cb3465f431899359eb026")
                .unwrap()
        );
        assert_eq!(
            position_id(parse_address(CONFIGURED_USDCE).unwrap(), legacy_two),
            B256::from_str("0x35d0161b478b3564d56bab3f931e54f5b58ad0257625144f6025365403c74781")
                .unwrap()
        );
        assert_ne!([legacy_one, legacy_two], [alias_one, alias_two]);
    }
}
