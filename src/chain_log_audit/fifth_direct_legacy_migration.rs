//! Root-bound attribution for the pinned direct BinaryModule legacy migration.
//!
//! This records source-specific inventory movement only. It is not cash value,
//! P&L, wallet-history completeness, or a claim of USDCE/pUSD equivalence.

use super::fifth_legacy_binary_balances::FifthLegacyBinaryBalancesObservation;
use super::fifth_legacy_binary_result::{
    BoundedFifthLegacyBinaryResultError, FifthLegacyBinaryResultObservation,
};
use super::{
    ChainLogAuditError, ChainLogVerifier, ChainReceiptIntervalBlock, ChainReceiptIntervalEvidence,
    ChainReceiptIntervalTransaction, TransactionRequestBudget, exact_eip1186_storage_entries,
    field, parse_eip1186_storage_value, parse_fixed_b256, rlp_u256, u256_slot, validate_hex,
    verify_eip1186_account_proof, verify_eip1186_storage_proof,
};
use alloy_primitives::{Address, B256, U256};
use serde_json::json;
use sha3::{Digest, Keccak256};
use std::{str::FromStr, time::Duration};
use thiserror::Error;
use tokio::time::Instant;

const POLICY_VERSION: &str = "fifth-direct-legacy-binary-migration/1";
const CTF_BALANCES_SLOT: u64 = 1;
const CTF_OPERATOR_APPROVALS_SLOT: u64 = 2;
const USDC_E_BALANCES_SLOT: u64 = 0;
const USDC_E_DECIMALS_SLOT: u64 = 5;
const MODULE_RESOLUTION_PAUSED_SLOT: u64 = 1;
const MODULE_PROXY_CODE_HASH: &str =
    "0xaaa52c8cc8a0e3fd27ce756cc6b4e70c51423e9b597b11f32d3e49f8b1fc890d";
const USDC_E_PROXY_ADDRESS: &str = "0x2791bca1f2de4661ed88a30c99a7a9449aa84174";
const USDC_E_PROXY_HASH: &str =
    "0xa97604bff5b11d790aca38bf9f6189369ea260f08365b428fc2ef73390fddcef";
const USDC_E_IMPLEMENTATION_ADDRESS: &str = "0xdd9185db084f5c4fff3b4f70e7ba62123b812226";
const USDC_E_IMPLEMENTATION_HASH: &str =
    "0x6c32454db1ae150566833039d7172656e03f7fc718e96d2a4c4fd842f700e3c8";
const USDC_E_IMPLEMENTATION_SLOT: &str =
    "0xbaab7dbf64751104133af04abc7d9979f0fda3b059a322a8333f533d3f32bf7f";
const LEGACY_VAULT: &str = "0xc417fd8e9661c0d2120b64a04bb3278c17e99db1";
const MIGRATE_SELECTOR: [u8; 4] = [0xae, 0xda, 0xc6, 0x20];

pub const FIFTH_DIRECT_LEGACY_MIGRATION_POLICY_VERSION: &str = POLICY_VERSION;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedFifthDirectLegacyMigrationError {
    #[error("fifth direct legacy migration RPC request budget exhausted")]
    RequestBudgetExceeded,
    #[error("fifth direct legacy migration exceeded its total deadline")]
    Timeout,
    #[error(transparent)]
    Verification(#[from] ChainLogAuditError),
}

async fn migration_storage_proof(
    verifier: &ChainLogVerifier,
    endpoint: &str,
    account_address: &str,
    expected_code_hash: &str,
    state_root: &str,
    block: u64,
    keys: &[B256],
) -> Result<Vec<U256>, ChainLogAuditError> {
    let proof = verifier
        .rpc(
            endpoint,
            "eth_getProof",
            json!([
                account_address,
                keys.iter()
                    .map(|key| format!("{key:#x}"))
                    .collect::<Vec<_>>(),
                format!("{block:#x}")
            ]),
        )
        .await?;
    let account = verify_eip1186_account_proof(state_root, account_address, &proof)?;
    if account.code_hash != parse_fixed_b256(expected_code_hash)? {
        return Err(ChainLogAuditError::Unverified);
    }
    let entries = exact_eip1186_storage_entries(&proof, keys)?;
    let mut values = Vec::with_capacity(keys.len());
    for (key, entry) in keys.iter().zip(entries) {
        let value = parse_eip1186_storage_value(field(entry, "value")?)?;
        verify_eip1186_storage_proof(
            &account,
            *key,
            entry,
            (!value.is_zero()).then(|| rlp_u256(value)),
            value.is_zero(),
        )?;
        values.push(value);
    }
    Ok(values)
}

async fn implementation_account_proof(
    verifier: &ChainLogVerifier,
    endpoint: &str,
    address: &str,
    expected_code_hash: &str,
    state_root: &str,
    block: u64,
) -> Result<B256, ChainLogAuditError> {
    let proof = verifier
        .rpc(
            endpoint,
            "eth_getProof",
            json!([address, [], format!("{block:#x}")]),
        )
        .await?;
    let account = verify_eip1186_account_proof(state_root, address, &proof)?;
    let expected_code_hash = parse_fixed_b256(expected_code_hash)?;
    if account.code_hash != expected_code_hash {
        return Err(ChainLogAuditError::Unverified);
    }
    Ok(account.code_hash)
}

fn ctf_balance_key(position_id: B256, account: Address) -> B256 {
    let mut outer = [0_u8; 64];
    outer[..32].copy_from_slice(position_id.as_slice());
    outer[63] = CTF_BALANCES_SLOT as u8;
    let outer_hash = Keccak256::digest(outer);
    let mut inner = [0_u8; 64];
    inner[12..32].copy_from_slice(account.as_slice());
    inner[32..].copy_from_slice(&outer_hash);
    B256::from_slice(&Keccak256::digest(inner))
}

fn ctf_approval_key(owner: Address, operator: Address) -> B256 {
    let mut outer = [0_u8; 64];
    outer[12..32].copy_from_slice(owner.as_slice());
    outer[63] = CTF_OPERATOR_APPROVALS_SLOT as u8;
    let outer_hash = Keccak256::digest(outer);
    let mut inner = [0_u8; 64];
    inner[12..32].copy_from_slice(operator.as_slice());
    inner[32..].copy_from_slice(&outer_hash);
    B256::from_slice(&Keccak256::digest(inner))
}

fn usdce_balance_key(account: Address) -> B256 {
    let mut preimage = [0_u8; 64];
    preimage[12..32].copy_from_slice(account.as_slice());
    preimage[63] = USDC_E_BALANCES_SLOT as u8;
    B256::from_slice(&Keccak256::digest(preimage))
}

fn module_pause_key(condition_id: B256) -> Result<B256, ChainLogAuditError> {
    let mut preimage = [0_u8; 64];
    preimage[..29].copy_from_slice(&condition_id.as_slice()[..29]);
    preimage[63] = MODULE_RESOLUTION_PAUSED_SLOT as u8;
    Ok(B256::from_slice(&Keccak256::digest(preimage)))
}

fn address_word(address: &str) -> Result<U256, ChainLogAuditError> {
    let address = validate_hex(address, 20)?;
    let bytes = hex::decode(&address[2..]).map_err(|_| ChainLogAuditError::Unverified)?;
    let mut word = [0_u8; 32];
    word[12..].copy_from_slice(&bytes);
    Ok(U256::from_be_bytes(word))
}

fn ensure_deadline(deadline: Instant) -> Result<(), BoundedFifthDirectLegacyMigrationError> {
    if Instant::now() >= deadline {
        Err(BoundedFifthDirectLegacyMigrationError::Timeout)
    } else {
        Ok(())
    }
}

fn validate_boundary(
    boundary: &FifthDirectLegacyMigrationBoundary,
    owner: &str,
    legacy_condition_id: B256,
    block_number: u64,
    expected_state_root: Option<&str>,
) -> Result<(), ChainLogAuditError> {
    let balances = boundary.balances();
    let selected = balances.selected_balances();
    if selected.owner() != owner
        || selected.block_number() != block_number
        || balances.legacy_condition_id() != legacy_condition_id
        || boundary.owner_module_approval() != U256::ONE
        || boundary.usdce_decimals() != U256::from(6)
        || expected_state_root.is_some_and(|root| selected.state_root() != root)
    {
        return Err(ChainLogAuditError::Unverified);
    }
    if !matches!(
        balances.ctf_condition_state().status(),
        super::CtfConditionStateStatus::PreparedBinaryUnresolved
            | super::CtfConditionStateStatus::ResolvedBinary
    ) {
        return Err(ChainLogAuditError::Unverified);
    }
    let context = selected.code_context();
    if context.chain_id() != super::POLYGON_CHAIN_ID
        || balances.module_proxy() == Address::ZERO
        || balances.module_implementation() == Address::ZERO
        || balances.module_implementation_code_hash() == B256::ZERO
        || selected.position_manager_proxy().is_empty()
    {
        return Err(ChainLogAuditError::Unverified);
    }
    Ok(())
}

fn boundary_identity_continues(
    previous: &FifthDirectLegacyMigrationBoundary,
    current: &FifthDirectLegacyMigrationBoundary,
) -> bool {
    let before = previous.balances();
    let after = current.balances();
    let before_selected = before.selected_balances();
    let after_selected = after.selected_balances();
    before.legacy_condition_id() == after.legacy_condition_id()
        && before.v2_condition_id() == after.v2_condition_id()
        && before.v2_position_ids() == after.v2_position_ids()
        && before.legacy_position_ids() == after.legacy_position_ids()
        && before.module_proxy() == after.module_proxy()
        && before.module_implementation() == after.module_implementation()
        && before.module_implementation_code_hash() == after.module_implementation_code_hash()
        && before_selected.owner() == after_selected.owner()
        && before_selected.position_manager_proxy() == after_selected.position_manager_proxy()
        && before_selected.position_manager_proxy_code_hash()
            == after_selected.position_manager_proxy_code_hash()
        && before_selected.pusd_proxy() == after_selected.pusd_proxy()
        && before_selected.pusd_proxy_code_hash() == after_selected.pusd_proxy_code_hash()
        && before_selected.pusd_implementation() == after_selected.pusd_implementation()
        && before_selected.pusd_implementation_code_hash()
            == after_selected.pusd_implementation_code_hash()
        && before.ctf_condition_state().payout_numerator_count()
            == after.ctf_condition_state().payout_numerator_count()
        && before.ctf_condition_state().payout_denominator()
            == after.ctf_condition_state().payout_denominator()
        && before.ctf_condition_state().payout_numerators()
            == after.ctf_condition_state().payout_numerators()
        && previous.usdce_implementation() == current.usdce_implementation()
        && previous.usdce_implementation_code_hash() == current.usdce_implementation_code_hash()
        && previous.usdce_decimals() == current.usdce_decimals()
        && (previous.result().status() == current.result().status()
            || (previous.result().status()
                == &super::FifthLegacyBinaryResultStatus::StoredUnresolved
                && current.result().status()
                    == &super::FifthLegacyBinaryResultStatus::ResolvedBinary))
}

fn classify_migration_interval(
    evidence: &ChainReceiptIntervalEvidence,
    owner: &str,
    opening: &FifthDirectLegacyMigrationBoundary,
    boundaries: &[FifthDirectLegacyMigrationBoundary],
) -> Result<
    (
        FifthDirectLegacyMigrationStatus,
        Vec<FifthDirectLegacyMigrationTransactionFact>,
    ),
    BoundedFifthDirectLegacyMigrationError,
> {
    let module = format!("{:#x}", opening.balances().module_proxy());
    let owner_address = owner.to_ascii_lowercase();
    let balances = opening.balances();
    let selected = balances.selected_balances();
    let mut state = MigrationReplayState {
        owner_legacy: opening.owner_legacy_positions(),
        module_legacy: opening.module_legacy_positions(),
        owner_v2: [selected.position_balance_a(), selected.position_balance_b()],
        owner_pusd: selected.pusd_balance(),
        module_usdce: opening.module_usdce(),
        ctf_usdce: opening.ctf_usdce(),
        vault_usdce: opening.vault_usdce(),
        result_status: *opening.result().status(),
    };
    if state.module_legacy != [U256::ZERO; 2] || !state.module_usdce.is_zero() {
        return Ok(unavailable(
            Some(evidence.from_block() - 1),
            None,
            FifthDirectLegacyMigrationUnavailableReason::ModuleNotEmpty,
        ));
    }
    if opening.owner_module_approval() != U256::ONE {
        return Ok(unavailable(
            Some(evidence.from_block() - 1),
            None,
            FifthDirectLegacyMigrationUnavailableReason::ApprovalUnavailable,
        ));
    }
    let mut transactions = Vec::new();
    let mut result_transition_seen = false;
    let mut prior_pause = opening.pause_timestamp();
    for (block_index, block) in evidence.blocks().iter().enumerate() {
        let boundary = &boundaries[block_index];
        if boundary.pause_timestamp() != prior_pause {
            return Ok(unavailable(
                Some(block.block_number()),
                None,
                FifthDirectLegacyMigrationUnavailableReason::ResolutionStateUnavailable,
            ));
        }
        prior_pause = boundary.pause_timestamp();
        for transaction in block.transactions() {
            if has_forbidden_migration_control_event(transaction, opening) {
                return Ok(unavailable(
                    Some(block.block_number()),
                    Some(transaction.transaction_hash().to_owned()),
                    FifthDirectLegacyMigrationUnavailableReason::ResolutionStateUnavailable,
                ));
            }
            let to_module = transaction
                .to
                .as_deref()
                .is_some_and(|to| to.eq_ignore_ascii_case(&module));
            let input = transaction.input.as_deref().unwrap_or_default();
            let is_migration_call =
                to_module && input.get(..4) == Some(MIGRATE_SELECTOR.as_slice());
            if to_module && !is_migration_call {
                return Ok(unavailable(
                    Some(block.block_number()),
                    Some(transaction.transaction_hash().to_owned()),
                    FifthDirectLegacyMigrationUnavailableReason::UnsupportedDirectCall,
                ));
            }
            if !is_migration_call {
                if has_relevant_non_migration_activity(transaction, owner, opening) {
                    return Ok(unavailable(
                        Some(block.block_number()),
                        Some(transaction.transaction_hash().to_owned()),
                        FifthDirectLegacyMigrationUnavailableReason::UnsupportedOwnerActivity,
                    ));
                }
                if !apply_unrelated_usdce_transfers(transaction, &mut state, opening) {
                    return Ok(unavailable(
                        Some(block.block_number()),
                        Some(transaction.transaction_hash().to_owned()),
                        FifthDirectLegacyMigrationUnavailableReason::UnsupportedOwnerActivity,
                    ));
                }
                continue;
            }
            if transaction.status() != 1
                || !transaction.replay_protected_sender
                || transaction.value != U256::ZERO
                || !transaction
                    .recovered_from
                    .as_deref()
                    .is_some_and(|from| from.eq_ignore_ascii_case(&owner_address))
            {
                return Ok(unavailable(
                    Some(block.block_number()),
                    Some(transaction.transaction_hash().to_owned()),
                    FifthDirectLegacyMigrationUnavailableReason::UnsupportedOwnerActivity,
                ));
            }
            let rows = match decode_migration_rows(input, balances) {
                Ok(rows) => rows,
                Err(reason) => {
                    return Ok(unavailable(
                        Some(block.block_number()),
                        Some(transaction.transaction_hash().to_owned()),
                        reason,
                    ));
                }
            };
            let previous_result = state.result_status;
            let Some((fact, expected_logs, next_state)) =
                replay_migration_transaction(transaction, block, rows, state.clone(), opening)
            else {
                return Ok(unavailable(
                    Some(block.block_number()),
                    Some(transaction.transaction_hash().to_owned()),
                    FifthDirectLegacyMigrationUnavailableReason::SourceSettlementMismatch,
                ));
            };
            if !logs_match(transaction.logs(), &expected_logs) {
                return Ok(unavailable(
                    Some(block.block_number()),
                    Some(transaction.transaction_hash().to_owned()),
                    FifthDirectLegacyMigrationUnavailableReason::SourceSettlementMismatch,
                ));
            }
            if previous_result == super::FifthLegacyBinaryResultStatus::StoredUnresolved
                && next_state.result_status == super::FifthLegacyBinaryResultStatus::ResolvedBinary
            {
                result_transition_seen = true;
            }
            transactions.push(fact);
            state = next_state;
        }
        if !boundary_matches_state(boundary, &state) {
            let status = first_boundary_mismatch(block.block_number(), boundary, &state);
            return Ok((status, Vec::new()));
        }
    }
    let expected_result = if result_transition_seen {
        super::FifthLegacyBinaryResultStatus::ResolvedBinary
    } else {
        state.result_status
    };
    if boundaries
        .last()
        .is_some_and(|boundary| boundary.result().status() != &expected_result)
    {
        return Ok(unavailable(
            Some(evidence.through_block()),
            None,
            FifthDirectLegacyMigrationUnavailableReason::ResolutionStateUnavailable,
        ));
    }
    Ok((FifthDirectLegacyMigrationStatus::Matched, transactions))
}

fn unavailable(
    block_number: Option<u64>,
    transaction_hash: Option<String>,
    reason: FifthDirectLegacyMigrationUnavailableReason,
) -> (
    FifthDirectLegacyMigrationStatus,
    Vec<FifthDirectLegacyMigrationTransactionFact>,
) {
    (
        FifthDirectLegacyMigrationStatus::Unavailable {
            block_number,
            transaction_hash,
            reason,
        },
        Vec::new(),
    )
}

#[derive(Clone)]
struct MigrationReplayState {
    owner_legacy: [U256; 2],
    module_legacy: [U256; 2],
    owner_v2: [U256; 2],
    owner_pusd: U256,
    module_usdce: U256,
    ctf_usdce: U256,
    vault_usdce: U256,
    result_status: super::FifthLegacyBinaryResultStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedMigrationLog {
    address: String,
    topics: Vec<String>,
    data: String,
}

fn push_first_resolution_logs(
    logs: &mut Vec<ExpectedMigrationLog>,
    module: Address,
    condition: B256,
    legacy_condition: B256,
    legacy_payouts: [U256; 2],
    normalized: [U256; 2],
) {
    let module_address = format!("{module:#x}");
    let condition_topic = format!("{condition:#x}");
    let normalized_array = abi_single_dynamic_array(&normalized);
    logs.push(ExpectedMigrationLog {
        address: module_address.clone(),
        topics: vec![
            "0xe560c1a2847d4cf2e66de11fe592605556989449f38cc3ab96e2e287daa68caa".into(),
            condition_topic.clone(),
        ],
        data: normalized_array.clone(),
    });
    logs.push(ExpectedMigrationLog {
        address: module_address.clone(),
        topics: vec![
            "0x669c053fe14f2493990c0c90d8d2870cd45e2630b34b8a2b4f02869301987713".into(),
            address_topic(module),
            condition_topic.clone(),
        ],
        data: normalized_array,
    });
    logs.push(ExpectedMigrationLog {
        address: module_address,
        topics: vec![
            "0xf87100968b0fe70751acf87590ffac515231c5b999cba36e6820c7d312dcc8af".into(),
            condition_topic,
            format!("{legacy_condition:#x}"),
        ],
        data: abi_data(&[
            legacy_payouts[0],
            legacy_payouts[1],
            normalized[0],
            normalized[1],
        ]),
    });
}

fn normalize_legacy_payouts(raw: [U256; 2]) -> Option<[U256; 2]> {
    let denominator = raw[0].checked_add(raw[1]).filter(|sum| !sum.is_zero())?;
    let numerator0 = raw[0].checked_mul(U256::from(1_000_000_u64))? / denominator;
    let numerator1 = U256::from(1_000_000_u64).checked_sub(numerator0)?;
    Some([numerator0, numerator1])
}

fn erc1155_batch_log(
    token: Address,
    operator: Address,
    from: Address,
    to: Address,
    ids: &[U256],
    amounts: &[U256],
) -> ExpectedMigrationLog {
    let ids_data = abi_dynamic_u256(ids);
    let amounts_data = abi_dynamic_u256(amounts);
    let mut data = abi_word(U256::from(64)).to_vec();
    data.extend_from_slice(&abi_word(U256::from(64 + ids_data.len())));
    data.extend_from_slice(&ids_data);
    data.extend_from_slice(&amounts_data);
    ExpectedMigrationLog {
        address: format!("{token:#x}"),
        topics: vec![
            "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb".into(),
            address_topic(operator),
            address_topic(from),
            address_topic(to),
        ],
        data: format!("0x{}", hex::encode(data)),
    }
}

fn erc1155_single_log(
    token: Address,
    operator: Address,
    from: Address,
    to: Address,
    id: U256,
    amount: U256,
) -> ExpectedMigrationLog {
    ExpectedMigrationLog {
        address: format!("{token:#x}"),
        topics: vec![
            "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62".into(),
            address_topic(operator),
            address_topic(from),
            address_topic(to),
        ],
        data: abi_data(&[id, amount]),
    }
}

fn erc20_transfer_log(
    token: Address,
    from: Address,
    to: Address,
    amount: U256,
) -> ExpectedMigrationLog {
    ExpectedMigrationLog {
        address: format!("{token:#x}"),
        topics: vec![
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef".into(),
            address_topic(from),
            address_topic(to),
        ],
        data: abi_data(&[amount]),
    }
}

fn positions_merge_log(
    module: Address,
    ctf: Address,
    usdce: Address,
    condition: B256,
    amount: U256,
) -> ExpectedMigrationLog {
    let partition = abi_dynamic_u256(&[U256::ONE, U256::from(2)]);
    let mut data = abi_address_word(usdce).to_vec();
    data.extend_from_slice(&abi_word(U256::from(96)));
    data.extend_from_slice(&abi_word(amount));
    data.extend_from_slice(&partition);
    ExpectedMigrationLog {
        address: format!("{ctf:#x}"),
        topics: vec![
            "0x6f13ca62553fcc2bcd2372180a43949c1e4cebba603901ede2f4e14f36b282ca".into(),
            address_topic(module),
            format!("{:#x}", B256::ZERO),
            format!("{condition:#x}"),
        ],
        data: format!("0x{}", hex::encode(data)),
    }
}

fn payout_redemption_log(
    module: Address,
    ctf: Address,
    usdce: Address,
    condition: B256,
    payout: U256,
) -> ExpectedMigrationLog {
    let sets = abi_dynamic_u256(&[U256::ONE, U256::from(2)]);
    let mut data = abi_word(U256::from_be_bytes(condition.0)).to_vec();
    data.extend_from_slice(&abi_word(U256::from(96)));
    data.extend_from_slice(&abi_word(payout));
    data.extend_from_slice(&sets);
    ExpectedMigrationLog {
        address: format!("{ctf:#x}"),
        topics: vec![
            "0x2682012a4a4f1973119f1c9b90745d1bd91fa2bab387344f044cb3586864d18d".into(),
            address_topic(module),
            address_topic(usdce),
            format!("{:#x}", B256::ZERO),
        ],
        data: format!("0x{}", hex::encode(data)),
    }
}

fn position_migrated_log(
    module: Address,
    owner: Address,
    condition: B256,
    row: &FifthDirectLegacyMigrationRowFact,
) -> ExpectedMigrationLog {
    ExpectedMigrationLog {
        address: format!("{module:#x}"),
        topics: vec![
            "0xe8d329e97d555e1e9d0da49d3b12d41a966458eee02ff4c869e54c6711d7c80b".into(),
            address_topic(owner),
            format!("{condition:#x}"),
            format!("{:#x}", B256::from(row.v2_position_id.0)),
        ],
        data: abi_data(&[U256::from(row.outcome_index), row.amount]),
    }
}

fn legacy_collateral_settled_log(
    module: Address,
    usdce: Address,
    vault: Address,
    amount: U256,
) -> ExpectedMigrationLog {
    ExpectedMigrationLog {
        address: format!("{module:#x}"),
        topics: vec![
            "0x7a07cc3efaf017520e4ad55e66052f0398632c810a3fab73e58e4c7050746825".into(),
            address_topic(usdce),
            address_topic(vault),
        ],
        data: abi_data(&[amount]),
    }
}

fn abi_word(value: U256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

fn abi_data(words: &[U256]) -> String {
    let mut data = Vec::with_capacity(words.len() * 32 + 2);
    for word in words {
        data.extend_from_slice(&abi_word(*word));
    }
    format!("0x{}", hex::encode(data))
}

fn abi_dynamic_u256(words: &[U256]) -> Vec<u8> {
    let mut data = abi_word(U256::from(words.len())).to_vec();
    for word in words {
        data.extend_from_slice(&abi_word(*word));
    }
    data
}

fn abi_single_dynamic_array(words: &[U256]) -> String {
    let mut data = abi_word(U256::from(32)).to_vec();
    data.extend_from_slice(&abi_dynamic_u256(words));
    format!("0x{}", hex::encode(data))
}

fn abi_address_word(address: Address) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[12..].copy_from_slice(address.as_slice());
    word
}

fn address_topic(address: Address) -> String {
    let mut topic = [0_u8; 32];
    topic[12..].copy_from_slice(address.as_slice());
    format!("0x{}", hex::encode(topic))
}

fn logs_match(actual: &[super::ChainReceiptLog], expected: &[ExpectedMigrationLog]) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            actual.address().eq_ignore_ascii_case(&expected.address)
                && actual
                    .topics()
                    .iter()
                    .map(|topic| topic.to_ascii_lowercase())
                    .eq(expected
                        .topics
                        .iter()
                        .map(|topic| topic.to_ascii_lowercase()))
                && actual.data().eq_ignore_ascii_case(&expected.data)
        })
}

fn replay_migration_transaction(
    transaction: &ChainReceiptIntervalTransaction,
    block: &ChainReceiptIntervalBlock,
    rows: Vec<FifthDirectLegacyMigrationRowFact>,
    mut state: MigrationReplayState,
    opening: &FifthDirectLegacyMigrationBoundary,
) -> Option<(
    FifthDirectLegacyMigrationTransactionFact,
    Vec<ExpectedMigrationLog>,
    MigrationReplayState,
)> {
    let balances = opening.balances();
    let module = balances.module_proxy();
    let owner = Address::from_str(balances.selected_balances().owner()).ok()?;
    let ctf = Address::from_str(super::CTF_CONDITIONAL_TOKENS_ADDRESS).ok()?;
    let usdce = Address::from_str(USDC_E_PROXY_ADDRESS).ok()?;
    let vault = Address::from_str(LEGACY_VAULT).ok()?;
    let pm = Address::from_str(super::fifth_code_context::POSITION_MANAGER_PROXY).ok()?;
    let cid = balances.v2_condition_id();
    let legacy_cid = balances.legacy_condition_id();
    let legacy_ids = balances.legacy_position_ids();
    let v2_ids = balances.v2_position_ids();
    let ctf_state = balances.ctf_condition_state();
    let mut logs = Vec::new();

    let mut deposit_ids = Vec::with_capacity(rows.len());
    let mut deposit_amounts = Vec::with_capacity(rows.len());
    let mut mint_ids = Vec::with_capacity(rows.len());
    let mut mint_amounts = Vec::with_capacity(rows.len());
    let mut owner_legacy_outflows = [U256::ZERO; 2];
    let mut owner_v2_inflows = [U256::ZERO; 2];
    for row in &rows {
        let index = usize::from(row.outcome_index);
        state.owner_legacy[index] = state.owner_legacy[index].checked_sub(row.amount)?;
        state.module_legacy[index] = state.module_legacy[index].checked_add(row.amount)?;
        state.owner_v2[index] = state.owner_v2[index].checked_add(row.amount)?;
        owner_legacy_outflows[index] = owner_legacy_outflows[index].checked_add(row.amount)?;
        owner_v2_inflows[index] = owner_v2_inflows[index].checked_add(row.amount)?;
        deposit_ids.push(U256::from_be_bytes(legacy_ids[index].0));
        deposit_amounts.push(row.amount);
        mint_ids.push(U256::from_be_bytes(v2_ids[index].0));
        mint_amounts.push(row.amount);
    }
    logs.push(erc1155_batch_log(
        ctf,
        module,
        owner,
        module,
        &deposit_ids,
        &deposit_amounts,
    ));
    logs.push(erc1155_batch_log(
        pm,
        module,
        Address::ZERO,
        owner,
        &mint_ids,
        &mint_amounts,
    ));

    let payout_numerators = ctf_state.payout_numerators();
    let payout_sum = payout_numerators[0].checked_add(payout_numerators[1])?;
    let (branch, first_resolution_numerators) = if payout_sum.is_zero() {
        if state.result_status != super::FifthLegacyBinaryResultStatus::StoredUnresolved {
            return None;
        }
        (FifthDirectLegacyMigrationBranch::Unresolved, None)
    } else {
        if ctf_state.status() != super::CtfConditionStateStatus::ResolvedBinary
            || ctf_state.payout_denominator().is_zero()
        {
            return None;
        }
        match state.result_status {
            super::FifthLegacyBinaryResultStatus::StoredUnresolved => {
                if !opening.pause_timestamp().is_zero() {
                    return None;
                }
                let normalized = normalize_legacy_payouts(payout_numerators)?;
                push_first_resolution_logs(
                    &mut logs,
                    module,
                    cid,
                    legacy_cid,
                    payout_numerators,
                    normalized,
                );
                state.result_status = super::FifthLegacyBinaryResultStatus::ResolvedBinary;
                (
                    FifthDirectLegacyMigrationBranch::FirstResolution,
                    Some(normalized),
                )
            }
            super::FifthLegacyBinaryResultStatus::ResolvedBinary => {
                (FifthDirectLegacyMigrationBranch::StoredResolved, None)
            }
        }
    };

    let mut merged = U256::ZERO;
    let mut redeemed = U256::ZERO;
    if branch == FifthDirectLegacyMigrationBranch::Unresolved {
        let merge = state.module_legacy[0].min(state.module_legacy[1]);
        if !merge.is_zero() {
            logs.push(erc1155_batch_log(
                ctf,
                module,
                module,
                Address::ZERO,
                &[
                    U256::from_be_bytes(legacy_ids[0].0),
                    U256::from_be_bytes(legacy_ids[1].0),
                ],
                &[merge, merge],
            ));
            logs.push(erc20_transfer_log(usdce, ctf, module, merge));
            logs.push(positions_merge_log(module, ctf, usdce, legacy_cid, merge));
            state.module_legacy[0] = state.module_legacy[0].checked_sub(merge)?;
            state.module_legacy[1] = state.module_legacy[1].checked_sub(merge)?;
            state.ctf_usdce = state.ctf_usdce.checked_sub(merge)?;
            state.module_usdce = state.module_usdce.checked_add(merge)?;
            merged = merge;
        }
    } else {
        let denominator = ctf_state.payout_denominator();
        let mut total = U256::ZERO;
        for index in 0..2 {
            let amount = state.module_legacy[index];
            if !amount.is_zero() {
                logs.push(erc1155_single_log(
                    ctf,
                    module,
                    module,
                    Address::ZERO,
                    U256::from_be_bytes(legacy_ids[index].0),
                    amount,
                ));
                let payout = amount.checked_mul(payout_numerators[index])? / denominator;
                total = total.checked_add(payout)?;
                state.module_legacy[index] = U256::ZERO;
            }
        }
        if !total.is_zero() {
            logs.push(erc20_transfer_log(usdce, ctf, module, total));
            state.ctf_usdce = state.ctf_usdce.checked_sub(total)?;
            state.module_usdce = state.module_usdce.checked_add(total)?;
        }
        logs.push(payout_redemption_log(module, ctf, usdce, legacy_cid, total));
        redeemed = total;
    }

    for row in &rows {
        logs.push(position_migrated_log(module, owner, cid, row));
    }
    let sweep = state.module_usdce;
    if !sweep.is_zero() {
        logs.push(erc20_transfer_log(usdce, module, vault, sweep));
        logs.push(legacy_collateral_settled_log(module, usdce, vault, sweep));
        state.module_usdce = U256::ZERO;
        state.vault_usdce = state.vault_usdce.checked_add(sweep)?;
    }
    let fact = FifthDirectLegacyMigrationTransactionFact {
        block_number: block.block_number(),
        block_hash: block.block_hash().to_owned(),
        transaction_hash: transaction.transaction_hash().to_owned(),
        transaction_index: transaction.transaction_index(),
        branch,
        rows,
        owner_legacy_outflows,
        owner_v2_inflows,
        module_legacy_residue: state.module_legacy,
        merged_legacy_amount: merged,
        redeemed_usdce: redeemed,
        vault_sweep_usdce: sweep,
        first_resolution_numerators,
    };
    Some((fact, logs, state))
}

fn has_relevant_non_migration_activity(
    transaction: &ChainReceiptIntervalTransaction,
    owner: &str,
    opening: &FifthDirectLegacyMigrationBoundary,
) -> bool {
    let balances = opening.balances();
    let module = format!("{:#x}", balances.module_proxy());
    let owner = owner.to_ascii_lowercase();
    let ctf = super::CTF_CONDITIONAL_TOKENS_ADDRESS;
    let usdce = USDC_E_PROXY_ADDRESS;
    let pusd = balances.selected_balances().pusd_proxy();
    let pm = super::fifth_code_context::POSITION_MANAGER_PROXY;
    let legacy = balances.legacy_position_ids();
    let v2 = balances.v2_position_ids();
    transaction.logs().iter().any(|log| {
        let address = log.address();
        if address.eq_ignore_ascii_case(&module) && !log.topics().is_empty() {
            return true;
        }
        let movement = transaction
            .movement_observations()
            .iter()
            .find(|movement| movement.log_index() == log.block_log_index());
        let Some(movement) = movement else {
            return address.eq_ignore_ascii_case(ctf);
        };
        match movement.status() {
            super::MovementObservationStatus::Unsupported(_) => {
                address.eq_ignore_ascii_case(ctf)
                    || address.eq_ignore_ascii_case(pm)
                    || address.eq_ignore_ascii_case(usdce)
                    || address.eq_ignore_ascii_case(pusd)
            }
            super::MovementObservationStatus::Decoded(movement) => match movement {
                super::ObservedAssetMovement::Erc20Transfer { from, to, .. } => {
                    (address.eq_ignore_ascii_case(usdce)
                        && (from.eq_ignore_ascii_case(&module) || to.eq_ignore_ascii_case(&module)))
                        || (address.eq_ignore_ascii_case(pusd)
                            && (from.eq_ignore_ascii_case(&owner)
                                || to.eq_ignore_ascii_case(&owner)))
                }
                super::ObservedAssetMovement::Erc1155TransferSingle { from, to, id, .. } => {
                    let id = B256::from(id.to_be_bytes::<32>());
                    (address.eq_ignore_ascii_case(ctf)
                        && (legacy.contains(&id)
                            || [owner.as_str(), module.as_str()].iter().any(|tracked| {
                                from.eq_ignore_ascii_case(tracked)
                                    || to.eq_ignore_ascii_case(tracked)
                            })))
                        || (address.eq_ignore_ascii_case(pm)
                            && (v2.contains(&id)
                                && (from.eq_ignore_ascii_case(&owner)
                                    || to.eq_ignore_ascii_case(&owner))))
                }
                super::ObservedAssetMovement::Erc1155TransferBatch { from, to, ids, .. } => {
                    let ids = ids
                        .iter()
                        .map(|id| B256::from(id.to_be_bytes::<32>()))
                        .collect::<Vec<_>>();
                    (address.eq_ignore_ascii_case(ctf)
                        && (ids.iter().any(|id| legacy.contains(id))
                            || [owner.as_str(), module.as_str()].iter().any(|tracked| {
                                from.eq_ignore_ascii_case(tracked)
                                    || to.eq_ignore_ascii_case(tracked)
                            })))
                        || (address.eq_ignore_ascii_case(pm)
                            && (ids.iter().any(|id| v2.contains(id))
                                && (from.eq_ignore_ascii_case(&owner)
                                    || to.eq_ignore_ascii_case(&owner))))
                }
            },
        }
    })
}

fn apply_unrelated_usdce_transfers(
    transaction: &ChainReceiptIntervalTransaction,
    state: &mut MigrationReplayState,
    opening: &FifthDirectLegacyMigrationBoundary,
) -> bool {
    let module = format!("{:#x}", opening.balances().module_proxy());
    let ctf = super::CTF_CONDITIONAL_TOKENS_ADDRESS;
    let vault = LEGACY_VAULT;
    for movement in transaction.movement_observations() {
        if !movement
            .emitter()
            .eq_ignore_ascii_case(USDC_E_PROXY_ADDRESS)
        {
            continue;
        }
        match movement.status() {
            super::MovementObservationStatus::Unsupported(_) => return false,
            super::MovementObservationStatus::Decoded(
                super::ObservedAssetMovement::Erc20Transfer { from, to, amount },
            ) => {
                if from.eq_ignore_ascii_case(&module) || to.eq_ignore_ascii_case(&module) {
                    return false;
                }
                let from_ctf = from.eq_ignore_ascii_case(ctf);
                let to_ctf = to.eq_ignore_ascii_case(ctf);
                let from_vault = from.eq_ignore_ascii_case(vault);
                let to_vault = to.eq_ignore_ascii_case(vault);
                if from_ctf {
                    let Some(value) = state.ctf_usdce.checked_sub(*amount) else {
                        return false;
                    };
                    state.ctf_usdce = value;
                }
                if from_vault {
                    let Some(value) = state.vault_usdce.checked_sub(*amount) else {
                        return false;
                    };
                    state.vault_usdce = value;
                }
                if to_ctf {
                    let Some(value) = state.ctf_usdce.checked_add(*amount) else {
                        return false;
                    };
                    state.ctf_usdce = value;
                }
                if to_vault {
                    let Some(value) = state.vault_usdce.checked_add(*amount) else {
                        return false;
                    };
                    state.vault_usdce = value;
                }
            }
            super::MovementObservationStatus::Decoded(_) => return false,
        }
    }
    true
}

fn has_forbidden_migration_control_event(
    transaction: &ChainReceiptIntervalTransaction,
    opening: &FifthDirectLegacyMigrationBoundary,
) -> bool {
    let module = format!("{:#x}", opening.balances().module_proxy());
    let owner = opening.balances().selected_balances().owner();
    let proxies = [
        module.as_str(),
        super::CTF_CONDITIONAL_TOKENS_ADDRESS,
        super::fifth_code_context::POSITION_MANAGER_PROXY,
        USDC_E_PROXY_ADDRESS,
        opening.balances().selected_balances().pusd_proxy(),
    ];
    let upgraded = format!("0x{}", hex::encode(Keccak256::digest(b"Upgraded(address)")));
    transaction.logs().iter().any(|log| {
        if !proxies
            .iter()
            .any(|proxy| log.address().eq_ignore_ascii_case(proxy))
        {
            return false;
        }
        let Some(topic) = log.topics().first() else {
            return false;
        };
        topic.eq_ignore_ascii_case(&upgraded)
            || (log.address().eq_ignore_ascii_case(USDC_E_PROXY_ADDRESS)
                && topic.eq_ignore_ascii_case(super::USDC_E_PROXY_UPDATED_TOPIC))
            || (log
                .address()
                .eq_ignore_ascii_case(super::CTF_CONDITIONAL_TOKENS_ADDRESS)
                && topic.eq_ignore_ascii_case(
                    "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31",
                )
                && log.topics().len() == 3
                && log.topics()[1].eq_ignore_ascii_case(&address_topic(
                    Address::from_str(owner).unwrap_or(Address::ZERO),
                ))
                && log.topics()[2]
                    .eq_ignore_ascii_case(&address_topic(opening.balances().module_proxy())))
            || (log.address().eq_ignore_ascii_case(&module)
                && (topic.eq_ignore_ascii_case(
                    "0xdc9b357849b1f270abed270e8b7b026ba0a6c0a0137ad63fe62595e9a5ef338e",
                ) || topic.eq_ignore_ascii_case(
                    "0x7c4b1aa57f3709ea7889a5749c87fea12721ab4484993ecc65c07cba4b99bd46",
                ) && log.topics().get(1).is_some_and(|id| {
                    let mut event_id = [0_u8; 32];
                    event_id[..29]
                        .copy_from_slice(&opening.balances().v2_condition_id().as_slice()[..29]);
                    id.eq_ignore_ascii_case(&format!("0x{}", hex::encode(event_id)))
                })))
    })
}

fn boundary_matches_state(
    boundary: &FifthDirectLegacyMigrationBoundary,
    state: &MigrationReplayState,
) -> bool {
    let selected = boundary.balances().selected_balances();
    boundary.owner_legacy_positions() == state.owner_legacy
        && boundary.module_legacy_positions() == state.module_legacy
        && [selected.position_balance_a(), selected.position_balance_b()] == state.owner_v2
        && selected.pusd_balance() == state.owner_pusd
        && boundary.module_usdce() == state.module_usdce
        && boundary.ctf_usdce() == state.ctf_usdce
        && boundary.vault_usdce() == state.vault_usdce
        && *boundary.result().status() == state.result_status
}

fn first_boundary_mismatch(
    block_number: u64,
    boundary: &FifthDirectLegacyMigrationBoundary,
    state: &MigrationReplayState,
) -> FifthDirectLegacyMigrationStatus {
    let selected = boundary.balances().selected_balances();
    for (index, asset) in [
        FifthDirectLegacyMigrationAsset::LegacyPositionA,
        FifthDirectLegacyMigrationAsset::LegacyPositionB,
    ]
    .into_iter()
    .enumerate()
    {
        if boundary.owner_legacy_positions()[index] != state.owner_legacy[index] {
            return FifthDirectLegacyMigrationStatus::Mismatch {
                block_number,
                holder: FifthDirectLegacyMigrationHolder::Owner,
                asset,
                authenticated_balance: boundary.owner_legacy_positions()[index],
                reconstructed_balance: state.owner_legacy[index],
            };
        }
        if boundary.module_legacy_positions()[index] != state.module_legacy[index] {
            return FifthDirectLegacyMigrationStatus::Mismatch {
                block_number,
                holder: FifthDirectLegacyMigrationHolder::Module,
                asset,
                authenticated_balance: boundary.module_legacy_positions()[index],
                reconstructed_balance: state.module_legacy[index],
            };
        }
    }
    for (index, asset) in [
        FifthDirectLegacyMigrationAsset::V2PositionA,
        FifthDirectLegacyMigrationAsset::V2PositionB,
    ]
    .into_iter()
    .enumerate()
    {
        let authenticated = if index == 0 {
            selected.position_balance_a()
        } else {
            selected.position_balance_b()
        };
        if authenticated != state.owner_v2[index] {
            return FifthDirectLegacyMigrationStatus::Mismatch {
                block_number,
                holder: FifthDirectLegacyMigrationHolder::Owner,
                asset,
                authenticated_balance: authenticated,
                reconstructed_balance: state.owner_v2[index],
            };
        }
    }
    for (holder, authenticated, reconstructed) in [
        (
            FifthDirectLegacyMigrationHolder::Owner,
            selected.pusd_balance(),
            state.owner_pusd,
        ),
        (
            FifthDirectLegacyMigrationHolder::Module,
            boundary.module_usdce(),
            state.module_usdce,
        ),
        (
            FifthDirectLegacyMigrationHolder::Ctf,
            boundary.ctf_usdce(),
            state.ctf_usdce,
        ),
        (
            FifthDirectLegacyMigrationHolder::Vault,
            boundary.vault_usdce(),
            state.vault_usdce,
        ),
    ] {
        if authenticated != reconstructed {
            return FifthDirectLegacyMigrationStatus::Mismatch {
                block_number,
                holder,
                asset: if holder == FifthDirectLegacyMigrationHolder::Owner {
                    FifthDirectLegacyMigrationAsset::Pusd
                } else {
                    FifthDirectLegacyMigrationAsset::Usdce
                },
                authenticated_balance: authenticated,
                reconstructed_balance: reconstructed,
            };
        }
    }
    FifthDirectLegacyMigrationStatus::Unavailable {
        block_number: Some(block_number),
        transaction_hash: None,
        reason: FifthDirectLegacyMigrationUnavailableReason::SourceSettlementMismatch,
    }
}

fn decode_migration_rows(
    input: &[u8],
    balances: &FifthLegacyBinaryBalancesObservation,
) -> Result<Vec<FifthDirectLegacyMigrationRowFact>, FifthDirectLegacyMigrationUnavailableReason> {
    if input.len() < 4 + 96 || input.len() > 256 * 1024 || input.len() % 32 != 4 {
        return Err(FifthDirectLegacyMigrationUnavailableReason::InvalidCalldata);
    }
    let args = &input[4..];
    let offsets = [
        read_usize(args, 0)?,
        read_usize(args, 32)?,
        read_usize(args, 64)?,
    ];
    if offsets[0] != 96 || offsets[0] % 32 != 0 {
        return Err(FifthDirectLegacyMigrationUnavailableReason::InvalidCalldata);
    }
    let legacy = read_dynamic_words(args, offsets[0])?;
    if legacy.is_empty() || legacy.len() > 2 {
        return Err(FifthDirectLegacyMigrationUnavailableReason::InvalidCalldata);
    }
    let expected_second = offsets[0] + 32 + legacy.len() * 32;
    if offsets[1] != expected_second {
        return Err(FifthDirectLegacyMigrationUnavailableReason::InvalidCalldata);
    }
    let outcomes = read_dynamic_words(args, offsets[1])?;
    let expected_third = offsets[1] + 32 + outcomes.len() * 32;
    if offsets[2] != expected_third {
        return Err(FifthDirectLegacyMigrationUnavailableReason::InvalidCalldata);
    }
    let amounts = read_dynamic_words(args, offsets[2])?;
    if outcomes.len() != legacy.len() || amounts.len() != legacy.len() {
        return Err(FifthDirectLegacyMigrationUnavailableReason::InvalidCalldata);
    }
    let expected_end = offsets[2] + 32 + amounts.len() * 32;
    if expected_end != args.len() {
        return Err(FifthDirectLegacyMigrationUnavailableReason::InvalidCalldata);
    }
    let mut seen = [false; 2];
    let v2_ids = balances.v2_position_ids();
    let legacy_ids = balances.legacy_position_ids();
    let mut rows = Vec::with_capacity(legacy.len());
    for ((condition, outcome), amount) in legacy.iter().zip(outcomes).zip(amounts) {
        if B256::from((*condition).to_be_bytes()) != balances.legacy_condition_id()
            || amount == U256::ZERO
        {
            return Err(FifthDirectLegacyMigrationUnavailableReason::InvalidCalldata);
        }
        let index = outcome
            .try_into()
            .ok()
            .filter(|index: &u8| *index < 2)
            .ok_or(FifthDirectLegacyMigrationUnavailableReason::InvalidCalldata)?;
        if seen[usize::from(index)] {
            return Err(FifthDirectLegacyMigrationUnavailableReason::InvalidCalldata);
        }
        seen[usize::from(index)] = true;
        rows.push(FifthDirectLegacyMigrationRowFact {
            outcome_index: index,
            legacy_position_id: legacy_ids[usize::from(index)],
            v2_position_id: v2_ids[usize::from(index)],
            amount,
        });
    }
    Ok(rows)
}

fn read_usize(
    data: &[u8],
    offset: usize,
) -> Result<usize, FifthDirectLegacyMigrationUnavailableReason> {
    let end = offset
        .checked_add(32)
        .ok_or(FifthDirectLegacyMigrationUnavailableReason::InvalidCalldata)?;
    let word = data
        .get(offset..end)
        .ok_or(FifthDirectLegacyMigrationUnavailableReason::InvalidCalldata)?;
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err(FifthDirectLegacyMigrationUnavailableReason::InvalidCalldata);
    }
    let value = U256::from_be_slice(word);
    usize::try_from(value).map_err(|_| FifthDirectLegacyMigrationUnavailableReason::InvalidCalldata)
}

fn read_dynamic_words(
    data: &[u8],
    offset: usize,
) -> Result<Vec<U256>, FifthDirectLegacyMigrationUnavailableReason> {
    if offset % 32 != 0 {
        return Err(FifthDirectLegacyMigrationUnavailableReason::InvalidCalldata);
    }
    let length = read_usize(data, offset)?;
    if length > 2 {
        return Err(FifthDirectLegacyMigrationUnavailableReason::InvalidCalldata);
    }
    (0..length)
        .map(|index| {
            let start = offset
                .checked_add(32 + index * 32)
                .ok_or(FifthDirectLegacyMigrationUnavailableReason::InvalidCalldata)?;
            let end = start
                .checked_add(32)
                .ok_or(FifthDirectLegacyMigrationUnavailableReason::InvalidCalldata)?;
            let word = data
                .get(start..end)
                .ok_or(FifthDirectLegacyMigrationUnavailableReason::InvalidCalldata)?;
            Ok(U256::from_be_slice(word))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVENT_VECTORS: &str =
        include_str!("artifacts/fifth-direct-migration-source-event-vectors.json");
    const KEY_VECTORS: &str = include_str!("artifacts/fifth-direct-migration-source-vectors.json");

    fn vector_address(value: &str) -> Address {
        Address::from_str(value).unwrap()
    }

    fn vector_b256(value: &str) -> B256 {
        super::super::parse_fixed_b256(value).unwrap()
    }

    fn vector_amounts(value: &serde_json::Value) -> Vec<U256> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|value| U256::from(value.as_u64().unwrap()))
            .collect()
    }

    fn compare_log_vectors(actual: &[ExpectedMigrationLog], expected: &[serde_json::Value]) {
        assert_eq!(actual.len(), expected.len());
        for (actual, expected) in actual.iter().zip(expected) {
            assert_eq!(actual.address, expected["address"].as_str().unwrap());
            assert_eq!(
                actual.topics,
                expected["topics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|topic| topic.as_str().unwrap().to_owned())
                    .collect::<Vec<_>>()
            );
            assert_eq!(actual.data, expected["data"].as_str().unwrap());
        }
    }

    #[test]
    fn exact_five_source_receipt_sequences_match_compiler_goldens() {
        let vectors: serde_json::Value = serde_json::from_str(EVENT_VECTORS).unwrap();
        let owner = vector_address("0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025");
        let module = vector_address("0x3333333333333333333333333333333333333333");
        let ctf = vector_address(super::super::CTF_CONDITIONAL_TOKENS_ADDRESS);
        let usdce = vector_address(USDC_E_PROXY_ADDRESS);
        let vault = vector_address(LEGACY_VAULT);
        let condition =
            vector_b256("0x0112121212121212121212121212121212000000000000000000000000000000");
        let legacy_condition =
            vector_b256("0x1212121212121212121212121212121212121212121212121212121212121212");
        let legacy_ids = [
            vector_b256("0xd46b4e85dd2cb18425b643d2523673a90491b1131f9cb3465f431899359eb026"),
            vector_b256("0x35d0161b478b3564d56bab3f931e54f5b58ad0257625144f6025365403c74781"),
        ];
        let v2_ids = [
            condition,
            B256::from({
                let mut word = condition.0;
                word[31] = 1;
                word
            }),
        ];

        for case in vectors["cases"].as_array().unwrap() {
            let outcomes = case["outcomes"].as_array().unwrap();
            let amounts = vector_amounts(&case["amounts"]);
            let raw = vector_amounts(&case["raw_ctf_numerators"]);
            let mut module_positions = [U256::ZERO; 2];
            let rows = outcomes
                .iter()
                .zip(&amounts)
                .map(|(outcome, amount)| {
                    let index = outcome.as_u64().unwrap() as usize;
                    module_positions[index] += *amount;
                    FifthDirectLegacyMigrationRowFact {
                        outcome_index: index as u8,
                        legacy_position_id: legacy_ids[index],
                        v2_position_id: v2_ids[index],
                        amount: *amount,
                    }
                })
                .collect::<Vec<_>>();
            let mut actual = Vec::new();
            let deposit_ids = rows
                .iter()
                .map(|row| U256::from_be_bytes(row.legacy_position_id.0))
                .collect::<Vec<_>>();
            let deposit_amounts = rows.iter().map(|row| row.amount).collect::<Vec<_>>();
            let mint_ids = rows
                .iter()
                .map(|row| U256::from_be_bytes(row.v2_position_id.0))
                .collect::<Vec<_>>();
            actual.push(erc1155_batch_log(
                ctf,
                module,
                owner,
                module,
                &deposit_ids,
                &deposit_amounts,
            ));
            actual.push(erc1155_batch_log(
                vector_address(super::super::fifth_code_context::POSITION_MANAGER_PROXY),
                module,
                Address::ZERO,
                owner,
                &mint_ids,
                &deposit_amounts,
            ));
            let raw_sum = raw[0] + raw[1];
            let mut merge = U256::ZERO;
            let mut payout = U256::ZERO;
            if raw_sum.is_zero() {
                merge = module_positions[0].min(module_positions[1]);
                if !merge.is_zero() {
                    actual.push(erc1155_batch_log(
                        ctf,
                        module,
                        module,
                        Address::ZERO,
                        &[
                            U256::from_be_bytes(legacy_ids[0].0),
                            U256::from_be_bytes(legacy_ids[1].0),
                        ],
                        &[merge, merge],
                    ));
                    actual.push(erc20_transfer_log(usdce, ctf, module, merge));
                    actual.push(positions_merge_log(
                        module,
                        ctf,
                        usdce,
                        legacy_condition,
                        merge,
                    ));
                }
            } else {
                if !case["module_result_already_stored"].as_bool().unwrap() {
                    let normalized = vector_amounts(&case["normalized_numerators"]);
                    push_first_resolution_logs(
                        &mut actual,
                        module,
                        condition,
                        legacy_condition,
                        [raw[0], raw[1]],
                        [normalized[0], normalized[1]],
                    );
                }
                for index in 0..2 {
                    if !module_positions[index].is_zero() {
                        actual.push(erc1155_single_log(
                            ctf,
                            module,
                            module,
                            Address::ZERO,
                            U256::from_be_bytes(legacy_ids[index].0),
                            module_positions[index],
                        ));
                        payout += module_positions[index] * raw[index] / raw_sum;
                    }
                }
                if !payout.is_zero() {
                    actual.push(erc20_transfer_log(usdce, ctf, module, payout));
                }
                actual.push(payout_redemption_log(
                    module,
                    ctf,
                    usdce,
                    legacy_condition,
                    payout,
                ));
            }
            for row in &rows {
                actual.push(position_migrated_log(module, owner, condition, row));
            }
            let sweep = U256::from(case["vault_sweep_usdce"].as_u64().unwrap());
            if !sweep.is_zero() {
                actual.push(erc20_transfer_log(usdce, module, vault, sweep));
                actual.push(legacy_collateral_settled_log(module, usdce, vault, sweep));
            }
            assert_eq!(
                merge,
                U256::from(case["merged_legacy_amount"].as_u64().unwrap()),
                "{}",
                case["name"].as_str().unwrap()
            );
            assert_eq!(
                merge + payout,
                U256::from(case["ctf_usdce_outflow"].as_u64().unwrap()),
                "{}",
                case["name"].as_str().unwrap()
            );
            let residue = vector_amounts(&case["module_legacy_residue"]);
            let reconstructed_residue = if raw_sum.is_zero() {
                [module_positions[0] - merge, module_positions[1] - merge]
            } else {
                [U256::ZERO; 2]
            };
            assert_eq!(
                reconstructed_residue,
                [residue[0], residue[1]],
                "{}",
                case["name"].as_str().unwrap()
            );
            compare_log_vectors(&actual, case["source_logs"].as_array().unwrap());
        }
    }

    #[test]
    fn mapping_slots_match_independent_keccak_vectors() {
        let vectors: serde_json::Value = serde_json::from_str(KEY_VECTORS).unwrap();
        let owner = vector_address(vectors["owner"].as_str().unwrap());
        let module = vector_address(vectors["module"].as_str().unwrap());
        let legacy_ids = vectors["legacy_position_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| vector_b256(id.as_str().unwrap()))
            .collect::<Vec<_>>();
        let owner_keys = legacy_ids
            .iter()
            .map(|id| format!("{:#x}", ctf_balance_key(*id, owner)))
            .collect::<Vec<_>>();
        let module_keys = legacy_ids
            .iter()
            .map(|id| format!("{:#x}", ctf_balance_key(*id, module)))
            .collect::<Vec<_>>();
        assert_eq!(
            serde_json::to_value(&owner_keys).unwrap(),
            vectors["storage_keys"]["ctf_owner_pair"]
        );
        assert_eq!(
            serde_json::to_value(&module_keys).unwrap(),
            vectors["storage_keys"]["ctf_module_pair"]
        );
        assert_eq!(
            format!("{:#x}", ctf_approval_key(owner, module)),
            vectors["storage_keys"]["ctf_owner_to_module_approval"]
        );
        assert_eq!(
            format!(
                "{:#x}",
                module_pause_key(vector_b256(vectors["v2_condition_id"].as_str().unwrap()))
                    .unwrap()
            ),
            vectors["storage_keys"]["module_event_pause"]
        );
        assert_eq!(
            format!("{:#x}", usdce_balance_key(module)),
            vectors["storage_keys"]["usdce_module"]
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthDirectLegacyMigrationAsset {
    LegacyPositionA,
    LegacyPositionB,
    V2PositionA,
    V2PositionB,
    Pusd,
    Usdce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthDirectLegacyMigrationHolder {
    Owner,
    Module,
    Ctf,
    Vault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthDirectLegacyMigrationUnavailableReason {
    UnsupportedOwnerActivity,
    UnsupportedDirectCall,
    InvalidCalldata,
    SourceSettlementMismatch,
    ArithmeticUnavailable,
    ApprovalUnavailable,
    ResolutionStateUnavailable,
    ModuleNotEmpty,
    ImplementationUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FifthDirectLegacyMigrationStatus {
    Matched,
    Mismatch {
        block_number: u64,
        holder: FifthDirectLegacyMigrationHolder,
        asset: FifthDirectLegacyMigrationAsset,
        authenticated_balance: U256,
        reconstructed_balance: U256,
    },
    Unavailable {
        block_number: Option<u64>,
        transaction_hash: Option<String>,
        reason: FifthDirectLegacyMigrationUnavailableReason,
    },
}

/// Authenticated migration-specific state at one boundary. Construction is private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthDirectLegacyMigrationBoundary {
    result: FifthLegacyBinaryResultObservation,
    owner_legacy_positions: [U256; 2],
    module_legacy_positions: [U256; 2],
    owner_module_approval: U256,
    module_usdce: U256,
    ctf_usdce: U256,
    vault_usdce: U256,
    usdce_implementation: Address,
    usdce_implementation_code_hash: B256,
    usdce_decimals: U256,
    pause_timestamp: U256,
    storage_keys: [B256; 11],
}

impl FifthDirectLegacyMigrationBoundary {
    #[must_use]
    pub const fn balances(&self) -> &FifthLegacyBinaryBalancesObservation {
        self.result.balances()
    }
    #[must_use]
    pub const fn result(&self) -> &FifthLegacyBinaryResultObservation {
        &self.result
    }
    #[must_use]
    pub const fn owner_legacy_positions(&self) -> [U256; 2] {
        self.owner_legacy_positions
    }
    #[must_use]
    pub const fn module_legacy_positions(&self) -> [U256; 2] {
        self.module_legacy_positions
    }
    #[must_use]
    pub const fn owner_module_approval(&self) -> U256 {
        self.owner_module_approval
    }
    #[must_use]
    pub const fn module_usdce(&self) -> U256 {
        self.module_usdce
    }
    #[must_use]
    pub const fn ctf_usdce(&self) -> U256 {
        self.ctf_usdce
    }
    #[must_use]
    pub const fn vault_usdce(&self) -> U256 {
        self.vault_usdce
    }
    #[must_use]
    pub const fn usdce_implementation(&self) -> Address {
        self.usdce_implementation
    }
    #[must_use]
    pub const fn usdce_implementation_code_hash(&self) -> B256 {
        self.usdce_implementation_code_hash
    }
    #[must_use]
    pub const fn usdce_decimals(&self) -> U256 {
        self.usdce_decimals
    }
    #[must_use]
    pub const fn pause_timestamp(&self) -> U256 {
        self.pause_timestamp
    }
    #[must_use]
    pub const fn storage_keys(&self) -> [B256; 11] {
        self.storage_keys
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthDirectLegacyMigrationBranch {
    Unresolved,
    StoredResolved,
    FirstResolution,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthDirectLegacyMigrationRowFact {
    outcome_index: u8,
    legacy_position_id: B256,
    v2_position_id: B256,
    amount: U256,
}

impl FifthDirectLegacyMigrationRowFact {
    #[must_use]
    pub const fn outcome_index(&self) -> u8 {
        self.outcome_index
    }
    #[must_use]
    pub const fn legacy_position_id(&self) -> B256 {
        self.legacy_position_id
    }
    #[must_use]
    pub const fn v2_position_id(&self) -> B256 {
        self.v2_position_id
    }
    #[must_use]
    pub const fn amount(&self) -> U256 {
        self.amount
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthDirectLegacyMigrationTransactionFact {
    block_number: u64,
    block_hash: String,
    transaction_hash: String,
    transaction_index: u64,
    branch: FifthDirectLegacyMigrationBranch,
    rows: Vec<FifthDirectLegacyMigrationRowFact>,
    owner_legacy_outflows: [U256; 2],
    owner_v2_inflows: [U256; 2],
    module_legacy_residue: [U256; 2],
    merged_legacy_amount: U256,
    redeemed_usdce: U256,
    vault_sweep_usdce: U256,
    first_resolution_numerators: Option<[U256; 2]>,
}

impl FifthDirectLegacyMigrationTransactionFact {
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
    #[must_use]
    pub const fn branch(&self) -> FifthDirectLegacyMigrationBranch {
        self.branch
    }
    #[must_use]
    pub fn rows(&self) -> &[FifthDirectLegacyMigrationRowFact] {
        &self.rows
    }
    #[must_use]
    pub const fn owner_legacy_outflows(&self) -> [U256; 2] {
        self.owner_legacy_outflows
    }
    #[must_use]
    pub const fn owner_v2_inflows(&self) -> [U256; 2] {
        self.owner_v2_inflows
    }
    #[must_use]
    pub const fn module_legacy_residue(&self) -> [U256; 2] {
        self.module_legacy_residue
    }
    #[must_use]
    pub const fn merged_legacy_amount(&self) -> U256 {
        self.merged_legacy_amount
    }
    #[must_use]
    pub const fn redeemed_usdce(&self) -> U256 {
        self.redeemed_usdce
    }
    #[must_use]
    pub const fn vault_sweep_usdce(&self) -> U256 {
        self.vault_sweep_usdce
    }
    #[must_use]
    pub const fn first_resolution_numerators(&self) -> Option<[U256; 2]> {
        self.first_resolution_numerators
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthDirectLegacyMigrationObservation {
    evidence: ChainReceiptIntervalEvidence,
    opening: FifthDirectLegacyMigrationBoundary,
    block_observations: Vec<FifthDirectLegacyMigrationBoundary>,
    status: FifthDirectLegacyMigrationStatus,
    transactions: Vec<FifthDirectLegacyMigrationTransactionFact>,
}

impl FifthDirectLegacyMigrationObservation {
    #[must_use]
    pub const fn evidence(&self) -> &ChainReceiptIntervalEvidence {
        &self.evidence
    }
    #[must_use]
    pub const fn opening(&self) -> &FifthDirectLegacyMigrationBoundary {
        &self.opening
    }
    #[must_use]
    pub fn block_observations(&self) -> &[FifthDirectLegacyMigrationBoundary] {
        &self.block_observations
    }
    #[must_use]
    pub const fn status(&self) -> &FifthDirectLegacyMigrationStatus {
        &self.status
    }
    #[must_use]
    pub fn transactions(&self) -> &[FifthDirectLegacyMigrationTransactionFact] {
        &self.transactions
    }
    #[must_use]
    pub const fn source_policy_version(&self) -> &'static str {
        POLICY_VERSION
    }
}

impl ChainLogVerifier {
    /// Authenticate and replay direct-owner legacy migration across one bounded interval.
    #[allow(clippy::too_many_arguments)]
    pub async fn verify_fifth_direct_legacy_migration_interval_bounded(
        &self,
        owner: &str,
        legacy_condition_id: &str,
        from_block: u64,
        through_block: u64,
        expected_parent_hash: &str,
        expected_end_hash: &str,
        max_requests: usize,
        total_timeout: Duration,
    ) -> Result<FifthDirectLegacyMigrationObservation, BoundedFifthDirectLegacyMigrationError> {
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
        let verification = scoped.verify_fifth_direct_legacy_migration_inner(
            owner,
            Address::from_slice(&owner_bytes),
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
                Err(BoundedFifthDirectLegacyMigrationError::RequestBudgetExceeded)
            }
            () = &mut deadline_wait => {
                if budget.is_exhausted() {
                    Err(BoundedFifthDirectLegacyMigrationError::RequestBudgetExceeded)
                } else {
                    Err(BoundedFifthDirectLegacyMigrationError::Timeout)
                }
            }
            result = &mut verification => {
                if budget.is_exhausted() {
                    Err(BoundedFifthDirectLegacyMigrationError::RequestBudgetExceeded)
                } else if Instant::now() >= deadline {
                    Err(BoundedFifthDirectLegacyMigrationError::Timeout)
                } else {
                    result
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn verify_fifth_direct_legacy_migration_inner(
        &self,
        owner: String,
        owner_address: Address,
        legacy_condition_id: B256,
        from_block: u64,
        through_block: u64,
        expected_parent_hash: &str,
        expected_end_hash: &str,
        deadline: Instant,
    ) -> Result<FifthDirectLegacyMigrationObservation, BoundedFifthDirectLegacyMigrationError> {
        ensure_deadline(deadline)?;
        let opening = self
            .migration_boundary_inner(
                owner.clone(),
                owner_address,
                legacy_condition_id,
                from_block - 1,
                expected_parent_hash,
                deadline,
            )
            .await?;
        validate_boundary(&opening, &owner, legacy_condition_id, from_block - 1, None)?;
        ensure_deadline(deadline)?;
        let scoped = self.with_fifth_module_call_targets(opening.balances().module_proxy());
        let evidence = scoped
            .verify_receipt_interval_inner(
                from_block,
                through_block,
                expected_parent_hash,
                expected_end_hash,
            )
            .await?;
        ensure_deadline(deadline)?;
        let mut boundaries = Vec::with_capacity(evidence.blocks().len());
        for block in evidence.blocks() {
            ensure_deadline(deadline)?;
            let boundary = scoped
                .migration_boundary_inner(
                    owner.clone(),
                    owner_address,
                    legacy_condition_id,
                    block.block_number(),
                    block.block_hash(),
                    deadline,
                )
                .await?;
            validate_boundary(
                &boundary,
                &owner,
                legacy_condition_id,
                block.block_number(),
                Some(block.state_root()),
            )?;
            let previous = boundaries.last().unwrap_or(&opening);
            if !boundary_identity_continues(previous, &boundary)
                || !super::ctf_condition_state::transition_is_valid(
                    previous.balances().ctf_condition_state(),
                    boundary.balances().ctf_condition_state(),
                )
            {
                return Err(ChainLogAuditError::Unverified.into());
            }
            boundaries.push(boundary);
        }
        ensure_deadline(deadline)?;
        let (status, transactions) =
            classify_migration_interval(&evidence, &owner, &opening, &boundaries)?;
        ensure_deadline(deadline)?;
        Ok(FifthDirectLegacyMigrationObservation {
            evidence,
            opening,
            block_observations: boundaries,
            status,
            transactions,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn migration_boundary_inner(
        &self,
        owner: String,
        owner_address: Address,
        legacy_condition_id: B256,
        block: u64,
        expected_hash: &str,
        deadline: Instant,
    ) -> Result<FifthDirectLegacyMigrationBoundary, BoundedFifthDirectLegacyMigrationError> {
        let result = self
            .verify_fifth_legacy_binary_result_inner(
                owner,
                owner_address,
                legacy_condition_id,
                block,
                expected_hash,
                deadline,
            )
            .await
            .map_err(map_result_error)?;
        ensure_deadline(deadline)?;
        let balances = result.balances();
        let owner = Address::from_str(balances.selected_balances().owner())
            .map_err(|_| ChainLogAuditError::Unverified)?;
        let module = balances.module_proxy();
        let ctf = Address::from_str(super::CTF_CONDITIONAL_TOKENS_ADDRESS)
            .map_err(|_| ChainLogAuditError::Unverified)?;
        let vault = Address::from_str(LEGACY_VAULT).map_err(|_| ChainLogAuditError::Unverified)?;
        let state_root = balances.selected_balances().state_root().to_owned();
        let legacy_ids = balances.legacy_position_ids();
        let ctf_keys = [
            ctf_balance_key(legacy_ids[0], owner),
            ctf_balance_key(legacy_ids[1], owner),
            ctf_balance_key(legacy_ids[0], module),
            ctf_balance_key(legacy_ids[1], module),
            ctf_approval_key(owner, module),
        ];
        let usdce_keys = [
            parse_fixed_b256(USDC_E_IMPLEMENTATION_SLOT)?,
            u256_slot(USDC_E_DECIMALS_SLOT),
            usdce_balance_key(module),
            usdce_balance_key(ctf),
            usdce_balance_key(vault),
        ];
        let pause_key = module_pause_key(balances.v2_condition_id())?;
        let ctf_code_hash = format!(
            "0x{}",
            hex::encode(super::CTF_CONDITIONAL_TOKENS_CODE_HASH_CANDIDATE)
        );
        let module_address = format!("{module:#x}");
        let pause_keys = [pause_key];
        let (
            primary_ctf,
            secondary_ctf,
            primary_usdce,
            secondary_usdce,
            primary_impl,
            secondary_impl,
            primary_pause,
            secondary_pause,
        ) = tokio::try_join!(
            migration_storage_proof(
                self,
                &self.primary,
                super::CTF_CONDITIONAL_TOKENS_ADDRESS,
                &ctf_code_hash,
                &state_root,
                block,
                &ctf_keys
            ),
            migration_storage_proof(
                self,
                &self.secondary,
                super::CTF_CONDITIONAL_TOKENS_ADDRESS,
                &ctf_code_hash,
                &state_root,
                block,
                &ctf_keys
            ),
            migration_storage_proof(
                self,
                &self.primary,
                USDC_E_PROXY_ADDRESS,
                USDC_E_PROXY_HASH,
                &state_root,
                block,
                &usdce_keys
            ),
            migration_storage_proof(
                self,
                &self.secondary,
                USDC_E_PROXY_ADDRESS,
                USDC_E_PROXY_HASH,
                &state_root,
                block,
                &usdce_keys
            ),
            implementation_account_proof(
                self,
                &self.primary,
                USDC_E_IMPLEMENTATION_ADDRESS,
                USDC_E_IMPLEMENTATION_HASH,
                &state_root,
                block
            ),
            implementation_account_proof(
                self,
                &self.secondary,
                USDC_E_IMPLEMENTATION_ADDRESS,
                USDC_E_IMPLEMENTATION_HASH,
                &state_root,
                block
            ),
            migration_storage_proof(
                self,
                &self.primary,
                &module_address,
                MODULE_PROXY_CODE_HASH,
                &state_root,
                block,
                &pause_keys
            ),
            migration_storage_proof(
                self,
                &self.secondary,
                &module_address,
                MODULE_PROXY_CODE_HASH,
                &state_root,
                block,
                &pause_keys
            ),
        )?;
        ensure_deadline(deadline)?;
        if primary_ctf != secondary_ctf
            || primary_usdce != secondary_usdce
            || primary_pause != secondary_pause
            || primary_impl != secondary_impl
        {
            return Err(ChainLogAuditError::Divergent.into());
        }
        if primary_ctf.len() != 5 || primary_usdce.len() != 5 || primary_pause.len() != 1 {
            return Err(ChainLogAuditError::Unverified.into());
        }
        if primary_usdce[0] != address_word(USDC_E_IMPLEMENTATION_ADDRESS)?
            || primary_usdce[1] != U256::from(6)
        {
            return Err(ChainLogAuditError::Unverified.into());
        }
        let keys = [
            ctf_keys[0],
            ctf_keys[1],
            ctf_keys[2],
            ctf_keys[3],
            ctf_keys[4],
            usdce_keys[0],
            usdce_keys[1],
            usdce_keys[2],
            usdce_keys[3],
            usdce_keys[4],
            pause_key,
        ];
        Ok(FifthDirectLegacyMigrationBoundary {
            result,
            owner_legacy_positions: [primary_ctf[0], primary_ctf[1]],
            module_legacy_positions: [primary_ctf[2], primary_ctf[3]],
            owner_module_approval: primary_ctf[4],
            module_usdce: primary_usdce[2],
            ctf_usdce: primary_usdce[3],
            vault_usdce: primary_usdce[4],
            usdce_implementation: Address::from_str(USDC_E_IMPLEMENTATION_ADDRESS)
                .map_err(|_| ChainLogAuditError::Unverified)?,
            usdce_implementation_code_hash: primary_impl,
            usdce_decimals: primary_usdce[1],
            pause_timestamp: primary_pause[0],
            storage_keys: keys,
        })
    }
}

#[allow(dead_code)]
fn map_result_error(
    error: BoundedFifthLegacyBinaryResultError,
) -> BoundedFifthDirectLegacyMigrationError {
    match error {
        BoundedFifthLegacyBinaryResultError::RequestBudgetExceeded => {
            BoundedFifthDirectLegacyMigrationError::RequestBudgetExceeded
        }
        BoundedFifthLegacyBinaryResultError::Timeout => {
            BoundedFifthDirectLegacyMigrationError::Timeout
        }
        BoundedFifthLegacyBinaryResultError::Verification(error) => {
            BoundedFifthDirectLegacyMigrationError::Verification(error)
        }
    }
}
