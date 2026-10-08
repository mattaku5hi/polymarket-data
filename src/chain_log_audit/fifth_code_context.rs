//! One caller-anchored proof of the fifth Exchange proxy and known implementation code.
//! This does not establish proxy history, execution authority, or venue completeness.

use super::header_binding::bind_header;
use super::{
    CHAIN_ID, ChainLogAuditError, ChainLogVerifier, TransactionRequestBudget,
    exact_eip1186_storage_entries, field, parse_eip1186_storage_value, parse_fixed_b256,
    parse_hex_u64, rlp_u256, validate_hex, verify_eip1186_account_proof,
    verify_eip1186_storage_proof,
};
use serde_json::{Value, json};
use std::{fmt, time::Duration};
use thiserror::Error;

pub(super) const EXCHANGE_PROXY: &str = "0xe3333700ca9d93003f00f0f71f8515005f6c00aa";
pub(super) const POSITION_MANAGER_PROXY: &str = "0x006f54f7f9a22e0000cc2ab60031000000ae9fef";
pub(super) const ERC1967_PROXY_CODE_HASH: &str =
    "0xaaa52c8cc8a0e3fd27ce756cc6b4e70c51423e9b597b11f32d3e49f8b1fc890d";
pub(super) const ERC1967_IMPLEMENTATION_SLOT: &str =
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
pub(super) const PRIOR_EXCHANGE_IMPLEMENTATION: &str = "0x7345c6842b244926125ed4054905cac49620b5dc";
pub(super) const PRIOR_EXCHANGE_CODE_HASH: &str =
    "0x90209de686581e9c69d3a0454ee89e770652c51aa874a7edd0e9b4cdc3541f95";
pub(super) const CURRENT_EXCHANGE_IMPLEMENTATION: &str =
    "0x641b40ec414a076b9e79e703fc7bf4ebec248bb7";
pub(super) const CURRENT_EXCHANGE_CODE_HASH: &str =
    "0x42b8522e8b56d0587bc02e66a37e43614911580ded1c676a925f5373c7f2fcd6";
pub(super) const POSITION_MANAGER_IMPLEMENTATION: &str =
    "0xcc5de1e9d14a7ab75e872e23fc9d605518bac2d0";
pub(super) const POSITION_MANAGER_CODE_HASH: &str =
    "0x4f3ca1f933ee48546581d8ee28506e5c5b89d08e50900ff880603cedcde14c9e";

pub const FIFTH_CODE_CONTEXT_POLICY_VERSION: &str =
    "fifth-exchange-proxy-implementation-source-codehash-root-proof/1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedFifthCodeContextError {
    #[error("fifth code context RPC request budget exhausted")]
    RequestBudgetExceeded,
    #[error("fifth code context exceeded its total deadline")]
    Timeout,
    #[error(transparent)]
    Verification(#[from] ChainLogAuditError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthExchangeImplementationVersion {
    Prior7345,
    Current641b,
}

impl FifthExchangeImplementationVersion {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prior7345 => "prior_7345",
            Self::Current641b => "current_641b",
        }
    }
}

impl fmt::Display for FifthExchangeImplementationVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Verified code context at one caller-selected, locally bound Polygon state root.
/// Provider finality remains an attestation; this is not a proxy history or venue permit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthCodeContextObservation {
    block_number: u64,
    block_hash: String,
    state_root: String,
    primary_finalized_height: u64,
    secondary_finalized_height: u64,
    exchange_implementation_version: FifthExchangeImplementationVersion,
}

impl FifthCodeContextObservation {
    #[must_use]
    pub const fn chain_id(&self) -> u64 {
        CHAIN_ID
    }

    #[must_use]
    pub const fn block_number(&self) -> u64 {
        self.block_number
    }

    #[must_use]
    pub fn block_hash(&self) -> &str {
        &self.block_hash
    }

    #[must_use]
    pub fn state_root(&self) -> &str {
        &self.state_root
    }

    #[must_use]
    pub const fn primary_finalized_height(&self) -> u64 {
        self.primary_finalized_height
    }

    #[must_use]
    pub const fn secondary_finalized_height(&self) -> u64 {
        self.secondary_finalized_height
    }

    #[must_use]
    pub const fn exchange_implementation_version(&self) -> FifthExchangeImplementationVersion {
        self.exchange_implementation_version
    }

    #[must_use]
    pub const fn finality_attestation(&self) -> super::ProviderFinalityAttestation {
        super::ProviderFinalityAttestation::BothProvidersReportFinalized
    }

    #[must_use]
    pub const fn code_context_policy_version(&self) -> &'static str {
        FIFTH_CODE_CONTEXT_POLICY_VERSION
    }

    #[must_use]
    pub fn exchange_proxy(&self) -> &'static str {
        EXCHANGE_PROXY
    }

    #[must_use]
    pub fn exchange_proxy_code_hash(&self) -> &'static str {
        ERC1967_PROXY_CODE_HASH
    }

    #[must_use]
    pub fn exchange_implementation(&self) -> &'static str {
        match self.exchange_implementation_version {
            FifthExchangeImplementationVersion::Prior7345 => PRIOR_EXCHANGE_IMPLEMENTATION,
            FifthExchangeImplementationVersion::Current641b => CURRENT_EXCHANGE_IMPLEMENTATION,
        }
    }

    #[must_use]
    pub fn exchange_implementation_code_hash(&self) -> &'static str {
        match self.exchange_implementation_version {
            FifthExchangeImplementationVersion::Prior7345 => PRIOR_EXCHANGE_CODE_HASH,
            FifthExchangeImplementationVersion::Current641b => CURRENT_EXCHANGE_CODE_HASH,
        }
    }

    #[must_use]
    pub fn position_manager_proxy(&self) -> &'static str {
        POSITION_MANAGER_PROXY
    }

    #[must_use]
    pub fn position_manager_proxy_code_hash(&self) -> &'static str {
        ERC1967_PROXY_CODE_HASH
    }

    #[must_use]
    pub fn position_manager_implementation(&self) -> &'static str {
        POSITION_MANAGER_IMPLEMENTATION
    }

    #[must_use]
    pub fn position_manager_implementation_code_hash(&self) -> &'static str {
        POSITION_MANAGER_CODE_HASH
    }
}

struct ProviderCodeContext {
    requested_header_hash: String,
    state_root: String,
    finalized_height: u64,
    exchange_version: FifthExchangeImplementationVersion,
}

impl ChainLogVerifier {
    /// Verify the fifth Exchange and its fixed PositionManager proxy code at one
    /// caller-anchored root. The shared send budget and deadline span both providers.
    pub async fn verify_fifth_code_context_bounded(
        &self,
        block: u64,
        expected_hash: &str,
        max_requests: usize,
        total_timeout: Duration,
    ) -> Result<FifthCodeContextObservation, BoundedFifthCodeContextError> {
        let expected_hash = validate_hex(expected_hash, 32).map_err(|_| {
            BoundedFifthCodeContextError::Verification(ChainLogAuditError::InvalidInput)
        })?;
        if max_requests == 0 || total_timeout.is_zero() {
            return Err(BoundedFifthCodeContextError::Verification(
                ChainLogAuditError::InvalidInput,
            ));
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(total_timeout)
            .ok_or(BoundedFifthCodeContextError::Verification(
                ChainLogAuditError::InvalidInput,
            ))?;
        let budget = TransactionRequestBudget::new(max_requests);
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let scoped = self.with_request_budget(budget.inner());
        let verification = scoped.verify_fifth_code_context_inner(block, &expected_hash, deadline);
        tokio::pin!(verification);
        let deadline_wait = tokio::time::sleep_until(deadline);
        tokio::pin!(deadline_wait);
        tokio::select! {
            biased;
            _ = exhaustion.wait_for(|is_exhausted| *is_exhausted) => {
                Err(BoundedFifthCodeContextError::RequestBudgetExceeded)
            }
            () = &mut deadline_wait => {
                if budget.is_exhausted() {
                    Err(BoundedFifthCodeContextError::RequestBudgetExceeded)
                } else {
                    Err(BoundedFifthCodeContextError::Timeout)
                }
            }
            result = &mut verification => {
                if budget.is_exhausted() {
                    Err(BoundedFifthCodeContextError::RequestBudgetExceeded)
                } else {
                    result
                }
            }
        }
    }

    pub(super) async fn verify_fifth_code_context_inner(
        &self,
        block: u64,
        expected_hash: &str,
        deadline: tokio::time::Instant,
    ) -> Result<FifthCodeContextObservation, BoundedFifthCodeContextError> {
        if tokio::time::Instant::now() >= deadline {
            return Err(BoundedFifthCodeContextError::Timeout);
        }
        let (primary, secondary) = tokio::try_join!(
            self.fifth_code_context_provider(&self.primary, block, expected_hash),
            self.fifth_code_context_provider(&self.secondary, block, expected_hash),
        )?;
        if primary.requested_header_hash != secondary.requested_header_hash
            || primary.state_root != secondary.state_root
            || primary.exchange_version != secondary.exchange_version
        {
            return Err(BoundedFifthCodeContextError::Verification(
                ChainLogAuditError::Divergent,
            ));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(BoundedFifthCodeContextError::Timeout);
        }
        Ok(FifthCodeContextObservation {
            block_number: block,
            block_hash: primary.requested_header_hash,
            state_root: primary.state_root,
            primary_finalized_height: primary.finalized_height,
            secondary_finalized_height: secondary.finalized_height,
            exchange_implementation_version: primary.exchange_version,
        })
    }

    async fn fifth_code_context_provider(
        &self,
        endpoint: &str,
        block: u64,
        expected_hash: &str,
    ) -> Result<ProviderCodeContext, ChainLogAuditError> {
        let chain_id = self.rpc(endpoint, "eth_chainId", json!([])).await?;
        if parse_hex_u64(chain_id.as_str().ok_or(ChainLogAuditError::Unverified)?)? != CHAIN_ID {
            return Err(ChainLogAuditError::Unverified);
        }

        let finalized = self
            .rpc(
                endpoint,
                "eth_getBlockByNumber",
                json!(["finalized", false]),
            )
            .await?;
        let finalized = bind_header(&finalized)?;
        if finalized.number < block
            || (finalized.number == block && finalized.hash != expected_hash)
        {
            return Err(ChainLogAuditError::Unverified);
        }

        let requested = self
            .rpc(
                endpoint,
                "eth_getBlockByNumber",
                json!([format!("{block:#x}"), false]),
            )
            .await?;
        let requested = bind_header(&requested)?;
        if requested.number != block || requested.hash != expected_hash {
            return Err(ChainLogAuditError::Unverified);
        }

        let exchange_version = self
            .fifth_proxy_implementation(
                endpoint,
                block,
                &requested.state_root,
                EXCHANGE_PROXY,
                &[
                    FifthExchangeImplementationVersion::Prior7345,
                    FifthExchangeImplementationVersion::Current641b,
                ],
            )
            .await?
            .ok_or(ChainLogAuditError::Unverified)?;
        let (exchange_implementation, exchange_hash) = exchange_source_binding(exchange_version);
        self.fifth_implementation_account(
            endpoint,
            block,
            &requested.state_root,
            exchange_implementation,
            exchange_hash,
        )
        .await?;

        let position_version = self
            .fifth_proxy_implementation(
                endpoint,
                block,
                &requested.state_root,
                POSITION_MANAGER_PROXY,
                &[],
            )
            .await?;
        if position_version.is_some() {
            return Err(ChainLogAuditError::Unverified);
        }
        self.fifth_implementation_account(
            endpoint,
            block,
            &requested.state_root,
            POSITION_MANAGER_IMPLEMENTATION,
            POSITION_MANAGER_CODE_HASH,
        )
        .await?;

        Ok(ProviderCodeContext {
            requested_header_hash: requested.hash,
            state_root: requested.state_root,
            finalized_height: finalized.number,
            exchange_version,
        })
    }

    async fn fifth_proxy_implementation(
        &self,
        endpoint: &str,
        block: u64,
        state_root: &str,
        proxy: &str,
        allowed_exchange_versions: &[FifthExchangeImplementationVersion],
    ) -> Result<Option<FifthExchangeImplementationVersion>, ChainLogAuditError> {
        let slot = parse_fixed_b256(ERC1967_IMPLEMENTATION_SLOT)?;
        let proof = self
            .rpc(
                endpoint,
                "eth_getProof",
                json!([proxy, [format!("{slot:#x}")], format!("{block:#x}")]),
            )
            .await?;
        let account = verify_eip1186_account_proof(state_root, proxy, &proof)?;
        if account.code_hash != parse_fixed_b256(ERC1967_PROXY_CODE_HASH)? {
            return Err(ChainLogAuditError::Unverified);
        }
        let entries = exact_eip1186_storage_entries(&proof, &[slot])?;
        let entry = entries.first().ok_or(ChainLogAuditError::Unverified)?;
        let value = parse_eip1186_storage_value(field(entry, "value")?)?;
        if value.is_zero() {
            return Err(ChainLogAuditError::Unverified);
        }
        verify_eip1186_storage_proof(&account, slot, entry, Some(rlp_u256(value)), false)?;
        let word = value.to_be_bytes::<32>();
        if word[..12] != [0_u8; 12] {
            return Err(ChainLogAuditError::Unverified);
        }
        let implementation = format!("0x{}", hex::encode(&word[12..]));
        if proxy == POSITION_MANAGER_PROXY {
            return (implementation == POSITION_MANAGER_IMPLEMENTATION)
                .then_some(None)
                .ok_or(ChainLogAuditError::Unverified);
        }
        let version = match implementation.as_str() {
            PRIOR_EXCHANGE_IMPLEMENTATION => FifthExchangeImplementationVersion::Prior7345,
            CURRENT_EXCHANGE_IMPLEMENTATION => FifthExchangeImplementationVersion::Current641b,
            _ => return Err(ChainLogAuditError::Unverified),
        };
        if !allowed_exchange_versions.contains(&version) {
            return Err(ChainLogAuditError::Unverified);
        }
        Ok(Some(version))
    }

    async fn fifth_implementation_account(
        &self,
        endpoint: &str,
        block: u64,
        state_root: &str,
        implementation: &str,
        expected_code_hash: &str,
    ) -> Result<(), ChainLogAuditError> {
        let proof = self
            .rpc(
                endpoint,
                "eth_getProof",
                json!([implementation, [], format!("{block:#x}")]),
            )
            .await?;
        if proof
            .get("storageProof")
            .and_then(Value::as_array)
            .is_none_or(|entries| !entries.is_empty())
        {
            return Err(ChainLogAuditError::Unverified);
        }
        let account = verify_eip1186_account_proof(state_root, implementation, &proof)?;
        if account.code_hash != parse_fixed_b256(expected_code_hash)? {
            return Err(ChainLogAuditError::Unverified);
        }
        Ok(())
    }
}

fn exchange_source_binding(
    version: FifthExchangeImplementationVersion,
) -> (&'static str, &'static str) {
    match version {
        FifthExchangeImplementationVersion::Prior7345 => {
            (PRIOR_EXCHANGE_IMPLEMENTATION, PRIOR_EXCHANGE_CODE_HASH)
        }
        FifthExchangeImplementationVersion::Current641b => {
            (CURRENT_EXCHANGE_IMPLEMENTATION, CURRENT_EXCHANGE_CODE_HASH)
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use alloy_primitives::{B256, U256};
    use alloy_trie::{EMPTY_ROOT_HASH, HashBuilder, TrieAccount, proof::ProofRetainer};
    use axum::{Json, Router, extract::State, routing::post};
    use serde_json::Value;
    use sha3::Digest as _;
    use std::{
        collections::BTreeMap,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Instant,
    };
    use tokio::{
        sync::{Notify, watch},
        task::JoinHandle,
    };

    const TEST_BLOCK: u64 = 100;

    #[derive(Clone)]
    struct ProofOptions {
        exchange_proxy_code_hash: B256,
        exchange_slot_address: String,
        exchange_code_hash: B256,
        pm_proxy_code_hash: B256,
        pm_slot_address: String,
        pm_code_hash: B256,
    }

    impl ProofOptions {
        fn valid(version: FifthExchangeImplementationVersion) -> Self {
            let (_, exchange_hash) = exchange_source_binding(version);
            Self {
                exchange_proxy_code_hash: parse_fixed_b256(ERC1967_PROXY_CODE_HASH).unwrap(),
                exchange_slot_address: exchange_source_binding(version).0.to_owned(),
                exchange_code_hash: parse_fixed_b256(exchange_hash).unwrap(),
                pm_proxy_code_hash: parse_fixed_b256(ERC1967_PROXY_CODE_HASH).unwrap(),
                pm_slot_address: POSITION_MANAGER_IMPLEMENTATION.to_owned(),
                pm_code_hash: parse_fixed_b256(POSITION_MANAGER_CODE_HASH).unwrap(),
            }
        }
    }

    struct RootedFixture {
        block_header: Value,
        finalized_header: Value,
        proofs: BTreeMap<String, Value>,
        responses: Arc<Mutex<Vec<Value>>>,
        chain_id: &'static str,
        gate_pm_proof: bool,
        gate_control_proof: bool,
        gate: Arc<ProofGate>,
    }

    pub(in crate::chain_log_audit) struct ProofGate {
        started: AtomicUsize,
        started_notify: Notify,
        release: watch::Sender<bool>,
    }

    impl ProofGate {
        fn new() -> Arc<Self> {
            let (release, _) = watch::channel(false);
            Arc::new(Self {
                started: AtomicUsize::new(0),
                started_notify: Notify::new(),
                release,
            })
        }

        pub(in crate::chain_log_audit) async fn wait_until_started(&self, count: usize) {
            while self.started.load(Ordering::Acquire) < count {
                self.started_notify.notified().await;
            }
        }

        pub(in crate::chain_log_audit) fn release(&self) {
            self.release.send_replace(true);
        }

        async fn stop(&self) {
            let mut release = self.release.subscribe();
            if !*release.borrow() {
                self.started.fetch_add(1, Ordering::AcqRel);
                self.started_notify.notify_one();
                let _ = release.wait_for(|is_released| *is_released).await;
            }
        }
    }

    async fn fifth_rpc(
        State(fixture): State<Arc<RootedFixture>>,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        let method = request["method"].as_str().unwrap_or_default();
        let params = request["params"].clone();
        let response_index = {
            let mut responses = fixture.responses.lock().unwrap();
            responses.push(json!({
                "method": method,
                "params": params.clone(),
                "result": null,
            }));
            responses.len() - 1
        };
        let result = match method {
            "eth_chainId" => json!(fixture.chain_id),
            "eth_getBlockByNumber" if params[0] == "finalized" => fixture.finalized_header.clone(),
            "eth_getBlockByNumber" => fixture.block_header.clone(),
            "eth_getProof" => {
                let address = params[0].as_str().unwrap_or_default().to_ascii_lowercase();
                if fixture.gate_pm_proof && address == POSITION_MANAGER_IMPLEMENTATION {
                    fixture.gate.stop().await;
                }
                if fixture.gate_control_proof
                    && address == EXCHANGE_PROXY
                    && params[1].as_array().is_some_and(|keys| keys.len() == 4)
                {
                    fixture.gate.stop().await;
                }
                fixture
                    .proofs
                    .get(&address)
                    .cloned()
                    .map(|mut proof| {
                        if let Some(requested) = params[1].as_array() {
                            let requested = requested
                                .iter()
                                .filter_map(Value::as_str)
                                .map(str::to_ascii_lowercase)
                                .collect::<std::collections::BTreeSet<_>>();
                            if let Some(entries) = proof["storageProof"].as_array_mut() {
                                entries.retain(|entry| {
                                    entry["key"].as_str().is_some_and(|key| {
                                        requested.contains(&key.to_ascii_lowercase())
                                    })
                                });
                            }
                        }
                        proof
                    })
                    .unwrap_or(Value::Null)
            }
            _ => Value::Null,
        };
        fixture.responses.lock().unwrap()[response_index]["result"] = result.clone();
        Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
    }

    async fn serve(fixture: RootedFixture) -> (String, JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(fixture);
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/", post(fifth_rpc)).with_state(state),
            )
            .await
            .unwrap();
        });
        (endpoint, task)
    }

    pub(in crate::chain_log_audit) async fn test_wall_timeout(duration: Duration) {
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline {
            tokio::task::yield_now().await;
        }
    }

    fn rooted_fixture(
        version: FifthExchangeImplementationVersion,
        options: ProofOptions,
    ) -> RootedFixture {
        rooted_fixture_with_storage(version, options, &[])
    }

    fn rooted_fixture_with_storage(
        version: FifthExchangeImplementationVersion,
        options: ProofOptions,
        exchange_storage: &[(B256, U256)],
    ) -> RootedFixture {
        let slot = parse_fixed_b256(ERC1967_IMPLEMENTATION_SLOT).unwrap();
        let proxy_account = |address: &str,
                             implementation: &str,
                             code_hash: B256,
                             additional_storage: &[(B256, U256)]| {
            let implementation_bytes = hex::decode(&implementation[2..]).unwrap();
            let mut storage_values = vec![(slot, U256::from_be_slice(&implementation_bytes))];
            storage_values.extend_from_slice(additional_storage);
            storage_values.sort_by_key(|(key, _)| {
                alloy_trie::Nibbles::unpack(B256::from_slice(&sha3::Keccak256::digest(
                    key.as_slice(),
                )))
            });
            let storage_paths = storage_values
                .iter()
                .map(|(key, _)| {
                    alloy_trie::Nibbles::unpack(B256::from_slice(&sha3::Keccak256::digest(
                        key.as_slice(),
                    )))
                })
                .collect::<Vec<_>>();
            let mut storage = HashBuilder::default()
                .with_proof_retainer(ProofRetainer::from_iter(storage_paths.iter().copied()));
            for ((_, value), path) in storage_values.iter().zip(&storage_paths) {
                if !value.is_zero() {
                    storage.add_leaf(*path, &rlp_u256(*value));
                }
            }
            let storage_root = storage.root();
            let storage_nodes = storage.take_proof_nodes();
            let account = TrieAccount {
                nonce: 1,
                balance: U256::ZERO,
                storage_root,
                code_hash,
            };
            let slot_entries = storage_values
                .iter()
                .zip(&storage_paths)
                .map(|((key, value), path)| {
                    let proof = storage_nodes
                        .matching_nodes_sorted(path)
                        .into_iter()
                        .map(|(_, node)| format!("0x{}", hex::encode(node)))
                        .collect::<Vec<_>>();
                    json!({
                        "key": format!("{key:#x}"),
                        "value": format!("{value:#x}"),
                        "proof": proof,
                    })
                })
                .collect::<Vec<_>>();
            (address.to_owned(), account, Some(slot_entries))
        };
        let implementation_account = |address: &str, code_hash: B256| {
            (
                address.to_owned(),
                TrieAccount {
                    nonce: 1,
                    balance: U256::ZERO,
                    storage_root: EMPTY_ROOT_HASH,
                    code_hash,
                },
                None,
            )
        };

        let mut accounts = [
            proxy_account(
                EXCHANGE_PROXY,
                &options.exchange_slot_address,
                options.exchange_proxy_code_hash,
                exchange_storage,
            ),
            implementation_account(
                exchange_source_binding(version).0,
                options.exchange_code_hash,
            ),
            proxy_account(
                POSITION_MANAGER_PROXY,
                &options.pm_slot_address,
                options.pm_proxy_code_hash,
                &[],
            ),
            implementation_account(POSITION_MANAGER_IMPLEMENTATION, options.pm_code_hash),
        ];
        let mut account_paths = accounts
            .iter()
            .map(|(address, _, _)| {
                let address_bytes = hex::decode(&address[2..]).unwrap();
                alloy_trie::Nibbles::unpack(B256::from_slice(&sha3::Keccak256::digest(
                    address_bytes,
                )))
            })
            .collect::<Vec<_>>();
        account_paths.sort();
        let mut account_trie = HashBuilder::default()
            .with_proof_retainer(ProofRetainer::from_iter(account_paths.iter().copied()));
        let mut sorted = accounts
            .iter_mut()
            .map(|(address, account, slot)| {
                let address_bytes = hex::decode(&address[2..]).unwrap();
                let path = alloy_trie::Nibbles::unpack(B256::from_slice(&sha3::Keccak256::digest(
                    address_bytes,
                )));
                (path, address.clone(), *account, slot.clone())
            })
            .collect::<Vec<_>>();
        sorted.sort_by_key(|(path, _, _, _)| *path);
        for (path, _, account, _) in &sorted {
            account_trie.add_leaf(*path, &alloy_rlp::encode(*account));
        }
        let state_root = account_trie.root();
        let account_nodes = account_trie.take_proof_nodes();
        let proofs = sorted
            .into_iter()
            .map(|(path, address, account, slot)| {
                let account_proof = account_nodes
                    .matching_nodes_sorted(&path)
                    .into_iter()
                    .map(|(_, node)| format!("0x{}", hex::encode(node)))
                    .collect::<Vec<_>>();
                let proof = json!({
                    "address": address,
                    "nonce": format!("0x{:x}", account.nonce),
                    "balance": format!("{:#x}", account.balance),
                    "storageHash": format!("{:#x}", account.storage_root),
                    "codeHash": format!("{:#x}", account.code_hash),
                    "accountProof": account_proof,
                    "storageProof": slot.into_iter().flatten().collect::<Vec<_>>(),
                });
                (address, proof)
            })
            .collect::<BTreeMap<_, _>>();
        let state_root_text = format!("{state_root:#x}");
        let block_header = super::super::header_binding::fixture_header(
            TEST_BLOCK,
            &format!("0x{}", "11".repeat(32)),
            &state_root_text,
            &format!("0x{}", "00".repeat(32)),
            &format!("0x{}", "00".repeat(32)),
        );
        let finalized_header = super::super::header_binding::fixture_header(
            TEST_BLOCK + 1,
            block_header["hash"].as_str().unwrap(),
            &state_root_text,
            &format!("0x{}", "00".repeat(32)),
            &format!("0x{}", "00".repeat(32)),
        );
        RootedFixture {
            block_header,
            finalized_header,
            proofs,
            responses: Arc::new(Mutex::new(Vec::new())),
            chain_id: "0x89",
            gate_pm_proof: false,
            gate_control_proof: false,
            gate: ProofGate::new(),
        }
    }

    pub(in super::super) fn rooted_code_proof_packet(
        version: FifthExchangeImplementationVersion,
    ) -> (String, BTreeMap<String, Value>) {
        let fixture = rooted_fixture(version, ProofOptions::valid(version));
        (
            fixture.block_header["stateRoot"]
                .as_str()
                .expect("rooted fixture state root")
                .to_owned(),
            fixture.proofs,
        )
    }

    async fn verifier_pair(
        primary: RootedFixture,
        secondary: RootedFixture,
    ) -> (
        ChainLogVerifier,
        JoinHandle<()>,
        JoinHandle<()>,
        Arc<Mutex<Vec<Value>>>,
        Arc<Mutex<Vec<Value>>>,
    ) {
        let primary_responses = primary.responses.clone();
        let secondary_responses = secondary.responses.clone();
        let (primary_endpoint, primary_server) = serve(primary).await;
        let (secondary_endpoint, secondary_server) = serve(secondary).await;
        let verifier = ChainLogVerifier::new(&primary_endpoint, &secondary_endpoint).unwrap();
        (
            verifier,
            primary_server,
            secondary_server,
            primary_responses,
            secondary_responses,
        )
    }

    pub(in crate::chain_log_audit) async fn rooted_exchange_controls_pair(
        version: FifthExchangeImplementationVersion,
        keys_and_values: &[(B256, U256)],
        gate_control_proof: bool,
        mutation: Option<&str>,
    ) -> (
        ChainLogVerifier,
        JoinHandle<()>,
        JoinHandle<()>,
        Arc<Mutex<Vec<Value>>>,
        Arc<Mutex<Vec<Value>>>,
        Arc<ProofGate>,
        String,
    ) {
        let mut primary =
            rooted_fixture_with_storage(version, ProofOptions::valid(version), keys_and_values);
        if let Some(mutation) = mutation {
            mutate_exchange_storage_proof(&mut primary, mutation);
        }
        primary.gate_control_proof = gate_control_proof;
        let mut secondary =
            rooted_fixture_with_storage(version, ProofOptions::valid(version), keys_and_values);
        if let Some(mutation) = mutation {
            mutate_exchange_storage_proof(&mut secondary, mutation);
        }
        secondary.gate_control_proof = gate_control_proof;
        secondary.gate = primary.gate.clone();
        let gate = primary.gate.clone();
        let expected_hash = primary.block_header["hash"]
            .as_str()
            .expect("fixture hash")
            .to_owned();
        let (verifier, primary_server, secondary_server, primary_calls, secondary_calls) =
            verifier_pair(primary, secondary).await;
        (
            verifier,
            primary_server,
            secondary_server,
            primary_calls,
            secondary_calls,
            gate,
            expected_hash,
        )
    }

    fn mutate_exchange_storage_proof(fixture: &mut RootedFixture, mutation: &str) {
        let proof = fixture.proofs.get_mut(EXCHANGE_PROXY).unwrap();
        let implementation_slot = format!(
            "{:#x}",
            parse_fixed_b256(ERC1967_IMPLEMENTATION_SLOT).unwrap()
        );
        let target_index = proof["storageProof"]
            .as_array()
            .unwrap()
            .iter()
            .position(|entry| entry["key"] != implementation_slot)
            .unwrap();
        match mutation {
            "missing" => {
                proof["storageProof"]
                    .as_array_mut()
                    .unwrap()
                    .remove(target_index);
            }
            "extra" => {
                let entries = proof["storageProof"].as_array_mut().unwrap();
                let duplicate = entries[target_index].clone();
                entries.push(duplicate);
            }
            "wrong_key" => {
                proof["storageProof"][target_index]["key"] =
                    json!(format!("0x{}", "77".repeat(32)));
            }
            "wrong_value" => proof["storageProof"][target_index]["value"] = json!("0x1"),
            "corrupt_storage_proof" => proof["storageProof"][target_index]["proof"] = json!([]),
            "wrong_account" => proof["address"] = json!(POSITION_MANAGER_PROXY),
            "wrong_code_hash" => proof["codeHash"] = json!(format!("0x{}", "77".repeat(32))),
            _ => unreachable!(),
        };
    }

    pub(in crate::chain_log_audit) fn rpc_rows(responses: &[Value]) -> Vec<Value> {
        let mut unique = BTreeMap::new();
        for response in responses {
            let key =
                serde_json::to_string(&json!([response["method"], response["params"]])).unwrap();
            if let Some(previous) = unique.insert(key, response.clone()) {
                assert_eq!(
                    previous["result"], response["result"],
                    "providers returned different results for an identical request"
                );
            }
        }
        unique.into_values().collect()
    }

    fn capture_fixture(case: &str, observation: &FifthCodeContextObservation, rows: Vec<Value>) {
        let Ok(directory) = std::env::var("PDH_CAPTURE_FIFTH_CODE_CONTEXT_DIRECTORY") else {
            return;
        };
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../")
            .join(directory)
            .join(format!("fifth-code-context-{case}-rpc.json"));
        let bytes = serde_json::to_vec(&json!({
                "provenance": "Deterministic loopback responses from root-bound fifth code context proof test; no provider or chain retrieval.",
                "case": case,
                "block_number": observation.block_number(),
                "block_hash": observation.block_hash(),
                "state_root": observation.state_root(),
                "rpc_responses": rows,
            }))
            .unwrap();
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
    }

    #[tokio::test]
    async fn fifth_code_context_current_and_prior_variants_are_rooted_and_exactly_bounded() {
        for (version, case) in [
            (
                FifthExchangeImplementationVersion::Current641b,
                "current-641b",
            ),
            (FifthExchangeImplementationVersion::Prior7345, "prior-7345"),
        ] {
            let primary = rooted_fixture(version, ProofOptions::valid(version));
            let secondary = rooted_fixture(version, ProofOptions::valid(version));
            let expected_hash = primary.block_header["hash"].as_str().unwrap().to_owned();
            let expected_root = primary.block_header["stateRoot"]
                .as_str()
                .unwrap()
                .to_owned();
            let (verifier, primary_server, secondary_server, primary_calls, secondary_calls) =
                verifier_pair(primary, secondary).await;
            let observation = verifier
                .verify_fifth_code_context_bounded(
                    TEST_BLOCK,
                    &expected_hash,
                    14,
                    Duration::from_secs(10),
                )
                .await
                .unwrap();
            assert_eq!(observation.block_hash(), expected_hash);
            assert_eq!(observation.state_root(), expected_root);
            assert_eq!(observation.chain_id(), CHAIN_ID);
            assert_eq!(observation.exchange_implementation_version(), version);
            let (expected_implementation, expected_code_hash) = exchange_source_binding(version);
            assert_eq!(observation.exchange_proxy(), EXCHANGE_PROXY);
            assert_eq!(
                observation.exchange_proxy_code_hash(),
                ERC1967_PROXY_CODE_HASH
            );
            assert_eq!(
                observation.exchange_implementation(),
                expected_implementation
            );
            assert_eq!(
                observation.exchange_implementation_code_hash(),
                expected_code_hash
            );
            assert_eq!(observation.position_manager_proxy(), POSITION_MANAGER_PROXY);
            assert_eq!(
                observation.position_manager_proxy_code_hash(),
                ERC1967_PROXY_CODE_HASH
            );
            assert_eq!(
                observation.position_manager_implementation(),
                POSITION_MANAGER_IMPLEMENTATION
            );
            assert_eq!(
                observation.position_manager_implementation_code_hash(),
                POSITION_MANAGER_CODE_HASH
            );
            assert_eq!(
                observation.code_context_policy_version(),
                FIFTH_CODE_CONTEXT_POLICY_VERSION
            );
            assert_eq!(observation.primary_finalized_height(), TEST_BLOCK + 1);
            assert_eq!(observation.secondary_finalized_height(), TEST_BLOCK + 1);
            assert_eq!(
                observation.finality_attestation(),
                super::super::ProviderFinalityAttestation::BothProvidersReportFinalized
            );
            assert_eq!(primary_calls.lock().unwrap().len(), 7);
            assert_eq!(secondary_calls.lock().unwrap().len(), 7);
            for calls in [&primary_calls, &secondary_calls] {
                let calls = calls.lock().unwrap();
                assert_eq!(
                    calls
                        .iter()
                        .filter(|call| call["method"] == "eth_getProof")
                        .count(),
                    4
                );
                assert_eq!(
                    calls
                        .iter()
                        .filter(|call| call["method"] == "eth_chainId")
                        .count(),
                    1
                );
                assert_eq!(
                    calls
                        .iter()
                        .filter(|call| call["method"] == "eth_getBlockByNumber")
                        .count(),
                    2
                );
                assert!(calls.iter().all(|call| !matches!(
                    call["method"].as_str(),
                    Some("eth_getCode" | "eth_call")
                )));
            }
            let mut responses = primary_calls.lock().unwrap().clone();
            responses.extend(secondary_calls.lock().unwrap().iter().cloned());
            assert_eq!(rpc_rows(&responses).len(), 7);
            capture_fixture(case, &observation, rpc_rows(&responses));
            primary_server.abort();
            secondary_server.abort();
        }
    }

    #[tokio::test]
    async fn fifth_code_context_refuses_unknown_or_unbound_code_before_partial_success() {
        let version = FifthExchangeImplementationVersion::Current641b;
        let unknown = "0x1111111111111111111111111111111111111111";
        let mut unknown_exchange = ProofOptions::valid(version);
        unknown_exchange.exchange_slot_address = unknown.to_owned();
        let primary = rooted_fixture(version, unknown_exchange.clone());
        let secondary = rooted_fixture(version, unknown_exchange);
        let expected_hash = primary.block_header["hash"].as_str().unwrap().to_owned();
        let (verifier, primary_server, secondary_server, primary_calls, secondary_calls) =
            verifier_pair(primary, secondary).await;
        assert_eq!(
            verifier
                .verify_fifth_code_context_bounded(
                    TEST_BLOCK,
                    &expected_hash,
                    14,
                    Duration::from_secs(10),
                )
                .await,
            Err(BoundedFifthCodeContextError::Verification(
                ChainLogAuditError::Unverified
            ))
        );
        for calls in [&primary_calls, &secondary_calls] {
            let calls = calls.lock().unwrap();
            assert_eq!(
                calls.len(),
                4,
                "unknown slot must refuse before implementation lookup"
            );
            assert!(calls.iter().all(|call| {
                call["method"] != "eth_getProof" || call["params"][0] == EXCHANGE_PROXY
            }));
        }
        primary_server.abort();
        secondary_server.abort();

        let mut mismatched_hash = ProofOptions::valid(version);
        mismatched_hash.exchange_code_hash = B256::repeat_byte(0x12);
        let primary = rooted_fixture(version, mismatched_hash.clone());
        let secondary = rooted_fixture(version, mismatched_hash);
        let expected_hash = primary.block_header["hash"].as_str().unwrap().to_owned();
        let (verifier, primary_server, secondary_server, _, _) =
            verifier_pair(primary, secondary).await;
        assert_eq!(
            verifier
                .verify_fifth_code_context_bounded(
                    TEST_BLOCK,
                    &expected_hash,
                    14,
                    Duration::from_secs(10),
                )
                .await,
            Err(BoundedFifthCodeContextError::Verification(
                ChainLogAuditError::Unverified
            ))
        );
        primary_server.abort();
        secondary_server.abort();

        let mut bad_pm_code = ProofOptions::valid(version);
        bad_pm_code.pm_code_hash = B256::repeat_byte(0x34);
        let primary = rooted_fixture(version, bad_pm_code.clone());
        let secondary = rooted_fixture(version, bad_pm_code);
        let expected_hash = primary.block_header["hash"].as_str().unwrap().to_owned();
        let (verifier, primary_server, secondary_server, _, _) =
            verifier_pair(primary, secondary).await;
        assert_eq!(
            verifier
                .verify_fifth_code_context_bounded(
                    TEST_BLOCK,
                    &expected_hash,
                    14,
                    Duration::from_secs(10),
                )
                .await,
            Err(BoundedFifthCodeContextError::Verification(
                ChainLogAuditError::Unverified
            ))
        );
        primary_server.abort();
        secondary_server.abort();

        let mut bad_pm_proxy_code = ProofOptions::valid(version);
        bad_pm_proxy_code.pm_proxy_code_hash = B256::repeat_byte(0x56);
        let primary = rooted_fixture(version, bad_pm_proxy_code.clone());
        let secondary = rooted_fixture(version, bad_pm_proxy_code);
        let expected_hash = primary.block_header["hash"].as_str().unwrap().to_owned();
        let (verifier, primary_server, secondary_server, primary_calls, secondary_calls) =
            verifier_pair(primary, secondary).await;
        assert_eq!(
            verifier
                .verify_fifth_code_context_bounded(
                    TEST_BLOCK,
                    &expected_hash,
                    14,
                    Duration::from_secs(10),
                )
                .await,
            Err(BoundedFifthCodeContextError::Verification(
                ChainLogAuditError::Unverified
            ))
        );
        for calls in [&primary_calls, &secondary_calls] {
            assert!(
                calls
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|call| call["params"][0] != POSITION_MANAGER_IMPLEMENTATION)
            );
        }
        primary_server.abort();
        secondary_server.abort();

        let mut unknown_pm_slot = ProofOptions::valid(version);
        unknown_pm_slot.pm_slot_address = unknown.to_owned();
        let primary = rooted_fixture(version, unknown_pm_slot.clone());
        let secondary = rooted_fixture(version, unknown_pm_slot);
        let expected_hash = primary.block_header["hash"].as_str().unwrap().to_owned();
        let (verifier, primary_server, secondary_server, primary_calls, secondary_calls) =
            verifier_pair(primary, secondary).await;
        assert_eq!(
            verifier
                .verify_fifth_code_context_bounded(
                    TEST_BLOCK,
                    &expected_hash,
                    14,
                    Duration::from_secs(10),
                )
                .await,
            Err(BoundedFifthCodeContextError::Verification(
                ChainLogAuditError::Unverified
            ))
        );
        for calls in [&primary_calls, &secondary_calls] {
            assert!(
                calls
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|call| call["params"][0] != POSITION_MANAGER_IMPLEMENTATION)
            );
        }
        primary_server.abort();
        secondary_server.abort();
    }

    #[tokio::test]
    async fn fifth_code_context_refuses_bad_proxy_storage_and_account_entries() {
        let version = FifthExchangeImplementationVersion::Prior7345;
        for mutation in ["missing", "extra", "wrong_key", "zero", "padded", "address"] {
            let mut primary = rooted_fixture(version, ProofOptions::valid(version));
            let mut secondary = rooted_fixture(version, ProofOptions::valid(version));
            for fixture in [&mut primary, &mut secondary] {
                let proof = fixture.proofs.get_mut(EXCHANGE_PROXY).unwrap();
                match mutation {
                    "missing" => proof["storageProof"] = json!([]),
                    "extra" => {
                        let entry = proof["storageProof"][0].clone();
                        proof["storageProof"] = json!([entry.clone(), entry]);
                    }
                    "wrong_key" => {
                        proof["storageProof"][0]["key"] = json!(format!("0x{}", "77".repeat(32)));
                    }
                    "zero" => proof["storageProof"][0]["value"] = json!("0x0"),
                    "padded" => {
                        let current = proof["storageProof"][0]["value"]
                            .as_str()
                            .unwrap()
                            .to_owned();
                        proof["storageProof"][0]["value"] = json!(format!("0x00{}", &current[2..]));
                    }
                    "address" => proof["address"] = json!(POSITION_MANAGER_PROXY),
                    _ => unreachable!(),
                }
            }
            let expected_hash = primary.block_header["hash"].as_str().unwrap().to_owned();
            let (verifier, primary_server, secondary_server, _, _) =
                verifier_pair(primary, secondary).await;
            assert_eq!(
                verifier
                    .verify_fifth_code_context_bounded(
                        TEST_BLOCK,
                        &expected_hash,
                        14,
                        Duration::from_secs(10),
                    )
                    .await,
                Err(BoundedFifthCodeContextError::Verification(
                    ChainLogAuditError::Unverified
                )),
                "{mutation}"
            );
            primary_server.abort();
            secondary_server.abort();
        }
    }

    #[tokio::test]
    async fn fifth_code_context_validates_inputs_and_uses_one_shared_send_budget() {
        let version = FifthExchangeImplementationVersion::Current641b;
        let primary = rooted_fixture(version, ProofOptions::valid(version));
        let secondary = rooted_fixture(version, ProofOptions::valid(version));
        let expected_hash = primary.block_header["hash"].as_str().unwrap().to_owned();
        let (verifier, primary_server, secondary_server, primary_calls, secondary_calls) =
            verifier_pair(primary, secondary).await;
        assert_eq!(
            verifier
                .verify_fifth_code_context_bounded(TEST_BLOCK, "0x01", 14, Duration::from_secs(10),)
                .await,
            Err(BoundedFifthCodeContextError::Verification(
                ChainLogAuditError::InvalidInput
            ))
        );
        assert_eq!(
            verifier
                .verify_fifth_code_context_bounded(
                    TEST_BLOCK,
                    &expected_hash,
                    0,
                    Duration::from_secs(10),
                )
                .await,
            Err(BoundedFifthCodeContextError::Verification(
                ChainLogAuditError::InvalidInput
            ))
        );
        assert_eq!(
            verifier
                .verify_fifth_code_context_bounded(TEST_BLOCK, &expected_hash, 14, Duration::ZERO,)
                .await,
            Err(BoundedFifthCodeContextError::Verification(
                ChainLogAuditError::InvalidInput
            ))
        );
        assert!(primary_calls.lock().unwrap().is_empty());
        assert!(secondary_calls.lock().unwrap().is_empty());
        assert_eq!(
            verifier
                .verify_fifth_code_context_bounded(
                    TEST_BLOCK,
                    &expected_hash,
                    13,
                    Duration::from_secs(10),
                )
                .await,
            Err(BoundedFifthCodeContextError::RequestBudgetExceeded)
        );
        let total_calls =
            primary_calls.lock().unwrap().len() + secondary_calls.lock().unwrap().len();
        assert!(
            total_calls > 0 && total_calls <= 13,
            "the failed 14th reservation must not send"
        );
        primary_server.abort();
        secondary_server.abort();
    }

    #[tokio::test]
    async fn fifth_code_context_refuses_wrong_header_root_finality_chain_and_provider() {
        let version = FifthExchangeImplementationVersion::Current641b;
        for case in [
            "wrong_root",
            "not_finalized",
            "wrong_chain",
            "provider_disagreement",
        ] {
            let mut primary = rooted_fixture(version, ProofOptions::valid(version));
            let mut secondary = rooted_fixture(version, ProofOptions::valid(version));
            match case {
                "wrong_root" => {
                    primary.block_header["stateRoot"] = json!(format!("0x{}", "ab".repeat(32)));
                }
                "not_finalized" => {
                    primary.finalized_header = super::super::header_binding::fixture_header(
                        TEST_BLOCK - 1,
                        primary.block_header["parentHash"].as_str().unwrap(),
                        primary.block_header["stateRoot"].as_str().unwrap(),
                        &format!("0x{}", "00".repeat(32)),
                        &format!("0x{}", "00".repeat(32)),
                    );
                }
                "wrong_chain" => secondary.chain_id = "0x1",
                "provider_disagreement" => {
                    secondary = rooted_fixture(
                        FifthExchangeImplementationVersion::Prior7345,
                        ProofOptions::valid(FifthExchangeImplementationVersion::Prior7345),
                    );
                }
                _ => unreachable!(),
            }
            let expected_hash = primary.block_header["hash"].as_str().unwrap().to_owned();
            let (verifier, primary_server, secondary_server, _, _) =
                verifier_pair(primary, secondary).await;
            assert!(
                matches!(
                    verifier
                        .verify_fifth_code_context_bounded(
                            TEST_BLOCK,
                            &expected_hash,
                            14,
                            Duration::from_secs(10),
                        )
                        .await,
                    Err(BoundedFifthCodeContextError::Verification(
                        ChainLogAuditError::Unverified | ChainLogAuditError::Divergent
                    )),
                ),
                "{case}"
            );
            primary_server.abort();
            secondary_server.abort();
        }
    }

    #[tokio::test]
    async fn fifth_code_context_deadline_and_cancellation_reach_late_position_manager_proof() {
        let version = FifthExchangeImplementationVersion::Prior7345;
        let mut primary = rooted_fixture(version, ProofOptions::valid(version));
        primary.gate_pm_proof = true;
        let gate = primary.gate.clone();
        let secondary = rooted_fixture(version, ProofOptions::valid(version));
        let expected_hash = primary.block_header["hash"].as_str().unwrap().to_owned();
        let (verifier, primary_server, secondary_server, _, _) =
            verifier_pair(primary, secondary).await;
        tokio::time::pause();
        let mut task = tokio::spawn(async move {
            verifier
                .verify_fifth_code_context_bounded(
                    TEST_BLOCK,
                    &expected_hash,
                    14,
                    Duration::from_secs(1),
                )
                .await
        });
        tokio::select! {
            _ = gate.wait_until_started(1) => {}
            result = &mut task => panic!("deadline call finished before the late proof gate: {result:?}"),
            _ = test_wall_timeout(Duration::from_secs(30)) => panic!("late PositionManager proof was never reached"),
        }
        tokio::time::advance(Duration::from_millis(1_100)).await;
        let result = tokio::select! {
            result = &mut task => result.unwrap(),
            _ = test_wall_timeout(Duration::from_secs(30)) => panic!("deadline did not settle after the shared deadline"),
        };
        assert_eq!(result, Err(BoundedFifthCodeContextError::Timeout));
        tokio::time::resume();
        gate.release.send_replace(true);
        task.abort();
        primary_server.abort();
        secondary_server.abort();

        let mut primary = rooted_fixture(version, ProofOptions::valid(version));
        primary.gate_pm_proof = true;
        let gate = primary.gate.clone();
        let secondary = rooted_fixture(version, ProofOptions::valid(version));
        let expected_hash = primary.block_header["hash"].as_str().unwrap().to_owned();
        let (verifier, primary_server, secondary_server, primary_calls, _) =
            verifier_pair(primary, secondary).await;
        let mut task = tokio::spawn(async move {
            verifier
                .verify_fifth_code_context_bounded(
                    TEST_BLOCK,
                    &expected_hash,
                    14,
                    Duration::from_secs(10),
                )
                .await
        });
        tokio::select! {
            _ = gate.wait_until_started(1) => {}
            result = &mut task => panic!("cancellation call finished before the late proof gate: {result:?}"),
            _ = test_wall_timeout(Duration::from_secs(30)) => panic!("cancel gate was never reached"),
        }
        task.abort();
        let _ = task.await;
        let calls_at_abort = primary_calls.lock().unwrap().len();
        gate.release.send_replace(true);
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(100)) => {}
            _ = test_wall_timeout(Duration::from_secs(5)) => panic!("cancellation cleanup wall wait failed"),
        }
        assert_eq!(primary_calls.lock().unwrap().len(), calls_at_abort);
        primary_server.abort();
        secondary_server.abort();
    }
}
