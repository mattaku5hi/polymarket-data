//! Rooted point-in-time fifth Exchange control storage.
//!
//! These fields are source prerequisites only; they do not authorize an order
//! or reconstruct control state at a transaction within the block.

use super::fifth_code_context::{
    BoundedFifthCodeContextError, EXCHANGE_PROXY, FifthCodeContextObservation,
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

const ROLE_SEED: [u8; 4] = [0x8b, 0x78, 0xc6, 0xd8];
const OPERATOR_ROLE: U256 = U256::from_limbs([2, 0, 0, 0]);
const POLICY_VERSION: &str = "fifth-exchange-rooted-control-state/1";

pub const FIFTH_EXCHANGE_CONTROLS_POLICY_VERSION: &str = POLICY_VERSION;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedFifthExchangeControlsError {
    #[error("fifth Exchange controls RPC request budget exhausted")]
    RequestBudgetExceeded,
    #[error("fifth Exchange controls exceeded its total deadline")]
    Timeout,
    #[error(transparent)]
    Verification(#[from] ChainLogAuditError),
}

/// Sealed control words proved against the already-bound Exchange proxy root.
/// This is an observation, not an execution permit or control history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthExchangeControlsObservation {
    code_context: FifthCodeContextObservation,
    submitter: Address,
    maker: Address,
    global_pause_word: U256,
    user_pause_block_interval: U256,
    submitter_role_bitmap: U256,
    maker_pause_activation_block: U256,
    storage_keys: [B256; 4],
}

impl FifthExchangeControlsObservation {
    #[must_use]
    pub const fn code_context(&self) -> &FifthCodeContextObservation {
        &self.code_context
    }

    #[must_use]
    pub const fn submitter(&self) -> Address {
        self.submitter
    }

    #[must_use]
    pub const fn maker(&self) -> Address {
        self.maker
    }

    #[must_use]
    pub const fn global_pause_word(&self) -> U256 {
        self.global_pause_word
    }

    #[must_use]
    pub fn global_paused(&self) -> bool {
        !self.global_pause_word.is_zero()
    }

    #[must_use]
    pub const fn user_pause_block_interval(&self) -> U256 {
        self.user_pause_block_interval
    }

    #[must_use]
    pub const fn submitter_role_bitmap(&self) -> U256 {
        self.submitter_role_bitmap
    }

    #[must_use]
    pub fn submitter_has_operator_role(&self) -> bool {
        !(self.submitter_role_bitmap & OPERATOR_ROLE).is_zero()
    }

    #[must_use]
    pub const fn maker_pause_activation_block(&self) -> U256 {
        self.maker_pause_activation_block
    }

    #[must_use]
    pub fn maker_pause_active(&self) -> bool {
        !self.maker_pause_activation_block.is_zero()
            && U256::from(self.code_context.block_number()) >= self.maker_pause_activation_block
    }

    #[must_use]
    pub const fn storage_keys(&self) -> [B256; 4] {
        self.storage_keys
    }

    #[must_use]
    pub const fn source_policy_version(&self) -> &'static str {
        POLICY_VERSION
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProviderControls {
    global_pause_word: U256,
    user_pause_block_interval: U256,
    submitter_role_bitmap: U256,
    maker_pause_activation_block: U256,
}

impl ChainLogVerifier {
    /// Proves current Exchange controls at a caller-anchored finalized root.
    /// The paired providers and all sixteen RPC sends share one budget/deadline.
    #[allow(clippy::too_many_arguments)]
    pub async fn verify_fifth_exchange_controls_bounded(
        &self,
        submitter: &str,
        maker: &str,
        block: u64,
        expected_hash: &str,
        max_requests: usize,
        total_timeout: Duration,
    ) -> Result<FifthExchangeControlsObservation, BoundedFifthExchangeControlsError> {
        let submitter = validate_address(submitter)?;
        let maker = validate_address(maker)?;
        let expected_hash =
            validate_hex(expected_hash, 32).map_err(|_| ChainLogAuditError::InvalidInput)?;
        if block == 0 || max_requests == 0 || total_timeout.is_zero() {
            return Err(ChainLogAuditError::InvalidInput.into());
        }
        let deadline = Instant::now()
            .checked_add(total_timeout)
            .ok_or(ChainLogAuditError::InvalidInput)?;
        let keys = exchange_control_storage_keys(submitter, maker);
        let budget = TransactionRequestBudget::new(max_requests);
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let scoped = self.with_request_budget(budget.inner());
        let verification = scoped.verify_fifth_exchange_controls_inner(
            submitter,
            maker,
            block,
            &expected_hash,
            keys,
            deadline,
        );
        tokio::pin!(verification);
        let deadline_wait = tokio::time::sleep_until(deadline);
        tokio::pin!(deadline_wait);
        tokio::select! {
            biased;
            _ = exhaustion.wait_for(|is_exhausted| *is_exhausted) => {
                Err(BoundedFifthExchangeControlsError::RequestBudgetExceeded)
            }
            () = &mut deadline_wait => {
                if budget.is_exhausted() {
                    Err(BoundedFifthExchangeControlsError::RequestBudgetExceeded)
                } else {
                    Err(BoundedFifthExchangeControlsError::Timeout)
                }
            }
            result = &mut verification => {
                if budget.is_exhausted() {
                    Err(BoundedFifthExchangeControlsError::RequestBudgetExceeded)
                } else if Instant::now() >= deadline {
                    Err(BoundedFifthExchangeControlsError::Timeout)
                } else {
                    result
                }
            }
        }
    }

    pub(super) async fn verify_fifth_exchange_controls_inner(
        &self,
        submitter: Address,
        maker: Address,
        block: u64,
        expected_hash: &str,
        keys: [B256; 4],
        deadline: Instant,
    ) -> Result<FifthExchangeControlsObservation, BoundedFifthExchangeControlsError> {
        ensure_before_deadline(deadline)?;
        let code_context = self
            .verify_fifth_code_context_inner(block, expected_hash, deadline)
            .await
            .map_err(map_code_context_error)?;
        let (primary, secondary) = tokio::try_join!(
            exchange_controls_provider(self, &self.primary, block, &code_context, &keys,),
            exchange_controls_provider(self, &self.secondary, block, &code_context, &keys,),
        )?;
        ensure_before_deadline(deadline)?;
        if primary != secondary {
            return Err(ChainLogAuditError::Divergent.into());
        }
        if primary.global_pause_word > U256::ONE {
            return Err(ChainLogAuditError::Unverified.into());
        }
        ensure_before_deadline(deadline)?;
        Ok(FifthExchangeControlsObservation {
            code_context,
            submitter,
            maker,
            global_pause_word: primary.global_pause_word,
            user_pause_block_interval: primary.user_pause_block_interval,
            submitter_role_bitmap: primary.submitter_role_bitmap,
            maker_pause_activation_block: primary.maker_pause_activation_block,
            storage_keys: keys,
        })
    }
}

async fn exchange_controls_provider(
    verifier: &ChainLogVerifier,
    endpoint: &str,
    block: u64,
    code_context: &FifthCodeContextObservation,
    keys: &[B256; 4],
) -> Result<ProviderControls, ChainLogAuditError> {
    let proof = verifier
        .rpc(
            endpoint,
            "eth_getProof",
            json!([
                EXCHANGE_PROXY,
                keys.iter()
                    .map(|key| format!("{key:#x}"))
                    .collect::<Vec<_>>(),
                format!("{block:#x}")
            ]),
        )
        .await?;
    let account = verify_eip1186_account_proof(code_context.state_root(), EXCHANGE_PROXY, &proof)?;
    if account.code_hash != parse_fixed_b256(code_context.exchange_proxy_code_hash())? {
        return Err(ChainLogAuditError::Unverified);
    }
    let entries = exact_eip1186_storage_entries(&proof, keys)?;
    let mut values = [U256::ZERO; 4];
    for (index, (key, entry)) in keys.iter().zip(entries).enumerate() {
        let value = parse_eip1186_storage_value(field(entry, "value")?)?;
        verify_eip1186_storage_proof(
            &account,
            *key,
            entry,
            (!value.is_zero()).then(|| rlp_u256(value)),
            value.is_zero(),
        )?;
        values[index] = value;
    }
    Ok(ProviderControls {
        global_pause_word: values[0],
        user_pause_block_interval: values[1],
        submitter_role_bitmap: values[2],
        maker_pause_activation_block: values[3],
    })
}

fn validate_address(value: &str) -> Result<Address, ChainLogAuditError> {
    let value = validate_hex(value, 20).map_err(|_| ChainLogAuditError::InvalidInput)?;
    let bytes = hex::decode(&value[2..]).map_err(|_| ChainLogAuditError::InvalidInput)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(ChainLogAuditError::InvalidInput);
    }
    Ok(Address::from_slice(&bytes))
}

fn exchange_control_storage_keys(submitter: Address, maker: Address) -> [B256; 4] {
    let global_pause = B256::ZERO;
    let user_pause_interval = B256::with_last_byte(1);
    let mut role_preimage = [0_u8; 32];
    role_preimage[..20].copy_from_slice(submitter.as_slice());
    role_preimage[28..].copy_from_slice(&ROLE_SEED);
    let submitter_roles = B256::from_slice(&Keccak256::digest(role_preimage));
    let mut maker_pause_preimage = [0_u8; 64];
    maker_pause_preimage[12..32].copy_from_slice(maker.as_slice());
    maker_pause_preimage[63] = 3;
    let maker_pause = B256::from_slice(&Keccak256::digest(maker_pause_preimage));
    [
        global_pause,
        user_pause_interval,
        submitter_roles,
        maker_pause,
    ]
}

fn ensure_before_deadline(deadline: Instant) -> Result<(), BoundedFifthExchangeControlsError> {
    if Instant::now() >= deadline {
        Err(BoundedFifthExchangeControlsError::Timeout)
    } else {
        Ok(())
    }
}

fn map_code_context_error(
    error: BoundedFifthCodeContextError,
) -> BoundedFifthExchangeControlsError {
    match error {
        BoundedFifthCodeContextError::RequestBudgetExceeded => {
            BoundedFifthExchangeControlsError::RequestBudgetExceeded
        }
        BoundedFifthCodeContextError::Timeout => BoundedFifthExchangeControlsError::Timeout,
        BoundedFifthCodeContextError::Verification(error) => {
            BoundedFifthExchangeControlsError::Verification(error)
        }
    }
}
