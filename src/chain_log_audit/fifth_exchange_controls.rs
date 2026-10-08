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
        let budget = TransactionRequestBudget::new(max_requests);
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let scoped = self.with_request_budget(budget.inner());
        let verification = scoped.verify_fifth_exchange_controls_inner(
            submitter,
            maker,
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
        deadline: Instant,
    ) -> Result<FifthExchangeControlsObservation, BoundedFifthExchangeControlsError> {
        ensure_before_deadline(deadline)?;
        let code_context = self
            .verify_fifth_code_context_inner(block, expected_hash, deadline)
            .await
            .map_err(map_code_context_error)?;
        self.verify_fifth_exchange_controls_from_code_context_inner(
            code_context,
            submitter,
            maker,
            deadline,
        )
        .await
    }

    pub(super) async fn verify_fifth_exchange_controls_from_code_context_inner(
        &self,
        code_context: FifthCodeContextObservation,
        submitter: Address,
        maker: Address,
        deadline: Instant,
    ) -> Result<FifthExchangeControlsObservation, BoundedFifthExchangeControlsError> {
        ensure_before_deadline(deadline)?;
        let keys = exchange_control_storage_keys(submitter, maker);
        let block = code_context.block_number();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_log_audit::fifth_code_context::{
        FifthExchangeImplementationVersion,
        tests::{rooted_exchange_controls_pair, rpc_rows, test_wall_timeout},
    };
    use alloy_primitives::Address;
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex};

    const TEST_BLOCK: u64 = 100;
    const SUBMITTER: &str = "0x1111111111111111111111111111111111111111";
    const MAKER: &str = "0x2222222222222222222222222222222222222222";

    fn rooted_values(submitter: &str, maker: &str, words: [U256; 4]) -> Vec<(B256, U256)> {
        let submitter = Address::parse_checksummed(submitter, None).unwrap();
        let maker = Address::parse_checksummed(maker, None).unwrap();
        exchange_control_storage_keys(submitter, maker)
            .into_iter()
            .zip(words)
            .collect()
    }

    fn capture_fixture(
        case: &str,
        observation: &FifthExchangeControlsObservation,
        primary: &Arc<Mutex<Vec<Value>>>,
        secondary: &Arc<Mutex<Vec<Value>>>,
    ) {
        let Ok(directory) = std::env::var("POLYMARKET_DATA_CAPTURE_FIFTH_CONTROLS_FIXTURES") else {
            return;
        };
        let mut responses = primary.lock().unwrap().clone();
        let actual_request_count = responses.len() + secondary.lock().unwrap().len();
        responses.extend(secondary.lock().unwrap().iter().cloned());
        let rows = rpc_rows(&responses);
        let storage_keys = observation
            .storage_keys()
            .into_iter()
            .map(|key| format!("{key:#x}"))
            .collect::<Vec<_>>();
        let bytes = serde_json::to_vec(&json!({
            "provenance": "Rooted deterministic loopback Exchange control storage proofs; no live provider or chain retrieval.",
            "case": case,
            "source_policy_version": observation.source_policy_version(),
            "exchange_implementation_version": observation.code_context().exchange_implementation_version().as_str(),
            "block_number": observation.code_context().block_number(),
            "block_hash": observation.code_context().block_hash(),
            "state_root": observation.code_context().state_root(),
            "submitter": format!("{:#x}", observation.submitter()),
            "maker": format!("{:#x}", observation.maker()),
            "global_pause_word": format!("{:#x}", observation.global_pause_word()),
            "global_paused": observation.global_paused(),
            "user_pause_block_interval": format!("{:#x}", observation.user_pause_block_interval()),
            "submitter_role_bitmap": format!("{:#x}", observation.submitter_role_bitmap()),
            "submitter_has_operator_role": observation.submitter_has_operator_role(),
            "maker_pause_activation_block": format!("{:#x}", observation.maker_pause_activation_block()),
            "maker_pause_active": observation.maker_pause_active(),
            "storage_keys": storage_keys,
            "actual_request_count": actual_request_count,
            "deduplicated_request_count": rows.len(),
            "rpc_responses": rows,
        }))
        .unwrap();
        let path = std::path::Path::new(&directory)
            .join(format!("fifth-exchange-controls-{case}-rpc.json"));
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
    }

    async fn run(
        version: FifthExchangeImplementationVersion,
        submitter: &str,
        maker: &str,
        words: [U256; 4],
        budget: usize,
        gate: bool,
        mutation: Option<&str>,
    ) -> (
        Result<FifthExchangeControlsObservation, BoundedFifthExchangeControlsError>,
        usize,
        usize,
    ) {
        let values = rooted_values(submitter, maker, words);
        let (
            verifier,
            primary_server,
            secondary_server,
            primary_calls,
            secondary_calls,
            _proof_gate,
            expected_hash,
        ) = rooted_exchange_controls_pair(version, &values, gate, mutation).await;
        let result = verifier
            .verify_fifth_exchange_controls_bounded(
                submitter,
                maker,
                TEST_BLOCK,
                &expected_hash,
                budget,
                Duration::from_secs(10),
            )
            .await;
        let primary_count = primary_calls.lock().unwrap().len();
        let secondary_count = secondary_calls.lock().unwrap().len();
        primary_server.abort();
        secondary_server.abort();
        (result, primary_count, secondary_count)
    }

    #[tokio::test]
    async fn rooted_controls_accept_current_and_prior_source_versions_with_exact_send_count() {
        for (version, case, words, expected_active) in [
            (
                FifthExchangeImplementationVersion::Current641b,
                "current-pending-wide",
                [U256::ZERO, U256::MAX, U256::ONE, U256::from(TEST_BLOCK + 1)],
                false,
            ),
            (
                FifthExchangeImplementationVersion::Current641b,
                "current-active-global",
                [
                    U256::ONE,
                    U256::from(7),
                    U256::from(3),
                    U256::from(TEST_BLOCK),
                ],
                true,
            ),
            (
                FifthExchangeImplementationVersion::Prior7345,
                "prior-pending-wide",
                [U256::ZERO, U256::MAX, U256::from(2), U256::MAX],
                false,
            ),
            (
                FifthExchangeImplementationVersion::Prior7345,
                "prior-zero-activation",
                [U256::ZERO, U256::ZERO, U256::ZERO, U256::ZERO],
                false,
            ),
        ] {
            let values = rooted_values(SUBMITTER, MAKER, words);
            let (
                verifier,
                primary_server,
                secondary_server,
                primary_calls,
                secondary_calls,
                _,
                expected_hash,
            ) = rooted_exchange_controls_pair(version, &values, false, None).await;
            let observation = verifier
                .verify_fifth_exchange_controls_bounded(
                    SUBMITTER,
                    MAKER,
                    TEST_BLOCK,
                    &expected_hash,
                    16,
                    Duration::from_secs(10),
                )
                .await
                .unwrap();
            assert_eq!(
                observation.code_context().exchange_implementation_version(),
                version
            );
            assert_eq!(observation.global_pause_word(), words[0]);
            assert_eq!(observation.global_paused(), words[0] == U256::ONE);
            assert_eq!(observation.user_pause_block_interval(), words[1]);
            assert_eq!(observation.submitter_role_bitmap(), words[2]);
            assert_eq!(
                observation.submitter_has_operator_role(),
                !(words[2] & OPERATOR_ROLE).is_zero()
            );
            assert_eq!(observation.maker_pause_activation_block(), words[3]);
            assert_eq!(observation.maker_pause_active(), expected_active);
            assert_eq!(observation.submitter().to_string(), SUBMITTER);
            assert_eq!(observation.maker().to_string(), MAKER);
            assert_eq!(primary_calls.lock().unwrap().len(), 8);
            assert_eq!(secondary_calls.lock().unwrap().len(), 8);
            capture_fixture(case, &observation, &primary_calls, &secondary_calls);
            primary_server.abort();
            secondary_server.abort();
        }
    }

    #[test]
    fn pinned_source_vector_matches_control_storage_keys_and_masks() {
        let vectors: Value = serde_json::from_str(include_str!(
            "artifacts/fifth-exchange-controls-source-vectors.json"
        ))
        .unwrap();
        assert_eq!(
            vectors["source_policy_version"],
            FIFTH_EXCHANGE_CONTROLS_POLICY_VERSION
        );
        assert_eq!(vectors["operator_role_mask"], "0x2");
        assert_eq!(vectors["admin_role_mask"], "0x1");
        assert_eq!(
            vectors["maker_pause_predicate"],
            "activation > 0 && U256(block_number) >= activation"
        );
        assert_eq!(vectors["interval_is_raw_observation"], true);
        for packet in vectors["packets"].as_array().unwrap() {
            let layout = &packet["control_storage_layout"];
            assert_eq!(layout["paused"][0], "0");
            assert_eq!(layout["userPauseBlockInterval"][0], "1");
            assert_eq!(layout["userPausedBlockAt"][0], "3");
        }
        let submitter =
            Address::parse_checksummed(vectors["vector"]["submitter"].as_str().unwrap(), None)
                .unwrap();
        let maker =
            Address::parse_checksummed(vectors["vector"]["maker"].as_str().unwrap(), None).unwrap();
        let actual_keys = exchange_control_storage_keys(submitter, maker)
            .into_iter()
            .map(|key| format!("{key:#x}"))
            .collect::<Vec<_>>();
        let expected_keys = vectors["vector"]["storage_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(actual_keys, expected_keys);
    }

    #[tokio::test]
    async fn rooted_controls_use_full_role_bitmap_and_root_block_for_pause_activation() {
        for (submitter, maker, roles, activation, expected_active) in [
            (SUBMITTER, MAKER, U256::from(1), U256::ZERO, false),
            (
                SUBMITTER,
                MAKER,
                U256::from(2),
                U256::from(TEST_BLOCK - 1),
                true,
            ),
            (
                SUBMITTER,
                MAKER,
                U256::from(1),
                U256::from(TEST_BLOCK),
                true,
            ),
            (
                SUBMITTER,
                MAKER,
                U256::from(2),
                U256::from(TEST_BLOCK + 1),
                false,
            ),
            (SUBMITTER, MAKER, U256::from(3), U256::MAX, false),
            (
                SUBMITTER,
                MAKER,
                (U256::ONE << 255) | U256::from(2),
                U256::from(TEST_BLOCK),
                true,
            ),
            (
                SUBMITTER,
                MAKER,
                (U256::ONE << 255) | U256::ONE,
                U256::ZERO,
                false,
            ),
            (
                SUBMITTER,
                SUBMITTER,
                U256::from(2),
                U256::from(TEST_BLOCK),
                true,
            ),
        ] {
            let (result, _, _) = run(
                FifthExchangeImplementationVersion::Current641b,
                submitter,
                maker,
                [U256::ONE, U256::MAX, roles, activation],
                16,
                false,
                None,
            )
            .await;
            let observation = result.unwrap();
            assert!(observation.global_paused());
            assert_eq!(observation.submitter_role_bitmap(), roles);
            assert_eq!(
                observation.submitter_has_operator_role(),
                !(roles & OPERATOR_ROLE).is_zero()
            );
            assert_eq!(observation.maker_pause_active(), expected_active);
            assert_eq!(observation.user_pause_block_interval(), U256::MAX);
        }
    }

    #[tokio::test]
    async fn rooted_controls_reject_noncanonical_pause_words_and_unproved_storage_shapes() {
        for global_pause_word in [
            U256::from(2),
            U256::from(256),
            (U256::ONE << 255) | U256::ONE,
        ] {
            let invalid_words = rooted_values(
                SUBMITTER,
                MAKER,
                [global_pause_word, U256::ZERO, U256::from(2), U256::ZERO],
            );
            let (verifier, primary_server, secondary_server, _, _, _, expected_hash) =
                rooted_exchange_controls_pair(
                    FifthExchangeImplementationVersion::Current641b,
                    &invalid_words,
                    false,
                    None,
                )
                .await;
            assert_eq!(
                verifier
                    .verify_fifth_exchange_controls_bounded(
                        SUBMITTER,
                        MAKER,
                        TEST_BLOCK,
                        &expected_hash,
                        16,
                        Duration::from_secs(10),
                    )
                    .await,
                Err(BoundedFifthExchangeControlsError::Verification(
                    ChainLogAuditError::Unverified
                ))
            );
            primary_server.abort();
            secondary_server.abort();
        }

        for mutation in [
            "missing",
            "extra",
            "wrong_key",
            "wrong_value",
            "corrupt_storage_proof",
            "wrong_account",
            "wrong_code_hash",
        ] {
            let (result, _, _) = run(
                FifthExchangeImplementationVersion::Prior7345,
                SUBMITTER,
                MAKER,
                [U256::ZERO, U256::from(3), U256::from(2), U256::ZERO],
                16,
                false,
                Some(mutation),
            )
            .await;
            assert_eq!(
                result,
                Err(BoundedFifthExchangeControlsError::Verification(
                    ChainLogAuditError::Unverified
                )),
                "{mutation}"
            );
        }
    }

    #[tokio::test]
    async fn rooted_controls_reject_invalid_inputs_before_provider_io() {
        let values = rooted_values(
            SUBMITTER,
            MAKER,
            [U256::ZERO, U256::ZERO, U256::from(2), U256::ZERO],
        );
        let (
            verifier,
            primary_server,
            secondary_server,
            primary_calls,
            secondary_calls,
            _,
            expected_hash,
        ) = rooted_exchange_controls_pair(
            FifthExchangeImplementationVersion::Current641b,
            &values,
            false,
            None,
        )
        .await;
        let invalid_input = Err(BoundedFifthExchangeControlsError::Verification(
            ChainLogAuditError::InvalidInput,
        ));
        for result in [
            verifier
                .verify_fifth_exchange_controls_bounded(
                    "0x0000000000000000000000000000000000000000",
                    MAKER,
                    TEST_BLOCK,
                    &expected_hash,
                    16,
                    Duration::from_secs(10),
                )
                .await,
            verifier
                .verify_fifth_exchange_controls_bounded(
                    SUBMITTER,
                    "malformed",
                    TEST_BLOCK,
                    &expected_hash,
                    16,
                    Duration::from_secs(10),
                )
                .await,
            verifier
                .verify_fifth_exchange_controls_bounded(
                    SUBMITTER,
                    MAKER,
                    TEST_BLOCK,
                    "0x01",
                    16,
                    Duration::from_secs(10),
                )
                .await,
            verifier
                .verify_fifth_exchange_controls_bounded(
                    SUBMITTER,
                    MAKER,
                    0,
                    &expected_hash,
                    16,
                    Duration::from_secs(10),
                )
                .await,
            verifier
                .verify_fifth_exchange_controls_bounded(
                    SUBMITTER,
                    MAKER,
                    TEST_BLOCK,
                    &expected_hash,
                    0,
                    Duration::from_secs(10),
                )
                .await,
            verifier
                .verify_fifth_exchange_controls_bounded(
                    SUBMITTER,
                    MAKER,
                    TEST_BLOCK,
                    &expected_hash,
                    16,
                    Duration::ZERO,
                )
                .await,
        ] {
            assert_eq!(result, invalid_input);
        }
        assert!(primary_calls.lock().unwrap().is_empty());
        assert!(secondary_calls.lock().unwrap().is_empty());
        primary_server.abort();
        secondary_server.abort();
    }

    #[tokio::test]
    async fn rooted_controls_reuse_sealed_code_context_with_one_budget_and_deadline() {
        let values = rooted_values(
            SUBMITTER,
            MAKER,
            [U256::ZERO, U256::MAX, U256::from(2), U256::ZERO],
        );
        let (
            verifier,
            primary_server,
            secondary_server,
            primary_calls,
            secondary_calls,
            _,
            expected_hash,
        ) = rooted_exchange_controls_pair(
            FifthExchangeImplementationVersion::Current641b,
            &values,
            false,
            None,
        )
        .await;
        let budget = TransactionRequestBudget::new(16);
        let scoped = verifier.with_request_budget(budget.inner());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let context = scoped
            .verify_fifth_code_context_inner(TEST_BLOCK, &expected_hash, deadline)
            .await
            .unwrap();
        assert_eq!(budget.reserved_requests(), 14);
        let observation = scoped
            .verify_fifth_exchange_controls_from_code_context_inner(
                context,
                Address::parse_checksummed(SUBMITTER, None).unwrap(),
                Address::parse_checksummed(MAKER, None).unwrap(),
                deadline,
            )
            .await
            .unwrap();
        assert_eq!(budget.reserved_requests(), 16);
        assert_eq!(primary_calls.lock().unwrap().len(), 8);
        assert_eq!(secondary_calls.lock().unwrap().len(), 8);
        assert_eq!(observation.user_pause_block_interval(), U256::MAX);
        primary_server.abort();
        secondary_server.abort();
    }

    #[tokio::test]
    async fn rooted_controls_share_the_exact_budget_and_deadline_through_the_late_proof() {
        let values = rooted_values(
            SUBMITTER,
            MAKER,
            [U256::ZERO, U256::from(1), U256::from(2), U256::ZERO],
        );
        let (
            verifier,
            primary_server,
            secondary_server,
            primary_calls,
            secondary_calls,
            _,
            expected_hash,
        ) = rooted_exchange_controls_pair(
            FifthExchangeImplementationVersion::Current641b,
            &values,
            false,
            None,
        )
        .await;
        assert_eq!(
            verifier
                .verify_fifth_exchange_controls_bounded(
                    SUBMITTER,
                    MAKER,
                    TEST_BLOCK,
                    &expected_hash,
                    15,
                    Duration::from_secs(10),
                )
                .await,
            Err(BoundedFifthExchangeControlsError::RequestBudgetExceeded)
        );
        let sends = primary_calls.lock().unwrap().len() + secondary_calls.lock().unwrap().len();
        assert!(sends <= 15 && sends > 0);
        primary_server.abort();
        secondary_server.abort();

        let (verifier, primary_server, secondary_server, _, _, gate, expected_hash) =
            rooted_exchange_controls_pair(
                FifthExchangeImplementationVersion::Prior7345,
                &values,
                true,
                None,
            )
            .await;
        tokio::time::pause();
        let mut task = tokio::spawn(async move {
            verifier
                .verify_fifth_exchange_controls_bounded(
                    SUBMITTER,
                    MAKER,
                    TEST_BLOCK,
                    &expected_hash,
                    16,
                    Duration::from_secs(1),
                )
                .await
        });
        tokio::select! {
            _ = gate.wait_until_started(2) => {}
            result = &mut task => panic!("controls call finished before final storage proof: {result:?}"),
            _ = test_wall_timeout(Duration::from_secs(30)) => panic!("control storage proof was never reached"),
        }
        tokio::time::advance(Duration::from_millis(1_100)).await;
        let result = tokio::select! {
            result = &mut task => result.unwrap(),
            _ = test_wall_timeout(Duration::from_secs(30)) => panic!("shared deadline did not settle"),
        };
        assert_eq!(result, Err(BoundedFifthExchangeControlsError::Timeout));
        tokio::time::resume();
        gate.release();
        task.abort();
        primary_server.abort();
        secondary_server.abort();

        let values = rooted_values(
            SUBMITTER,
            MAKER,
            [U256::ZERO, U256::ZERO, U256::from(2), U256::ZERO],
        );
        let (
            verifier,
            primary_server,
            secondary_server,
            primary_calls,
            secondary_calls,
            gate,
            expected_hash,
        ) = rooted_exchange_controls_pair(
            FifthExchangeImplementationVersion::Current641b,
            &values,
            true,
            None,
        )
        .await;
        let mut task = tokio::spawn(async move {
            verifier
                .verify_fifth_exchange_controls_bounded(
                    SUBMITTER,
                    MAKER,
                    TEST_BLOCK,
                    &expected_hash,
                    16,
                    Duration::from_secs(10),
                )
                .await
        });
        tokio::select! {
            _ = gate.wait_until_started(2) => {}
            result = &mut task => panic!("cancelled call finished before gated proof: {result:?}"),
            _ = test_wall_timeout(Duration::from_secs(30)) => panic!("gated control proof was never reached"),
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        gate.release();
        test_wall_timeout(Duration::from_millis(50)).await;
        let stable_count =
            primary_calls.lock().unwrap().len() + secondary_calls.lock().unwrap().len();
        test_wall_timeout(Duration::from_millis(50)).await;
        assert_eq!(
            primary_calls.lock().unwrap().len() + secondary_calls.lock().unwrap().len(),
            stable_count,
            "caller cancellation must stop later provider sends"
        );
        primary_server.abort();
        secondary_server.abort();
    }
}
