//! Bounded rooted observations of opaque ERC-1155 balances in the two known ledgers.
//! This proves point balances only; it does not establish a complete token universe.

use super::fifth_code_context::{
    BoundedFifthCodeContextError, FifthCodeContextObservation, POSITION_MANAGER_PROXY,
};
use super::{
    CHAIN_ID, ChainLogAuditError, ChainLogVerifier, ProviderFinalityAttestation,
    TransactionRequestBudget, ctf_erc1155_balance_storage_key, exact_eip1186_storage_entries,
    field, parse_eip1186_storage_value, parse_fixed_b256, rlp_u256, validate_hex,
    verify_eip1186_account_proof, verify_eip1186_storage_proof,
};
use alloy_primitives::{Address, B256, U256};
use serde_json::json;
use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use thiserror::Error;

const CTF_ADDRESS: &str = "0x4d97dcd97ec945f40cf65f87097ace5ea0476045";
const CTF_CODE_HASH_CANDIDATE: [u8; 32] = super::CTF_CONDITIONAL_TOKENS_CODE_HASH_CANDIDATE;
const MAX_IDS: usize = 2_048;
// Local deterministic batch policy; this is not a provider-advertised key limit.
const MAX_KEYS_PER_PROOF: usize = 64;
// Bounded normalized balance proof result JSON; excludes context RPC proofs/framing.
const MAX_BALANCE_PROOF_JSON_BYTES: usize = 64 * 1024 * 1024;
const CTF_LAYOUT_POLICY_VERSION: &str = "conditional-tokens-solc-0.5.10-balances-slot-1/1";

pub const KNOWN_POSITION_BALANCES_POLICY_VERSION: &str =
    "ctf-position-manager-opaque-id-rooted-balances-two-provider/1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedKnownPositionBalancesError {
    #[error("known position balances RPC request budget exhausted")]
    RequestBudgetExceeded,
    #[error("known position balances exceeded its total deadline")]
    Timeout,
    #[error(transparent)]
    Verification(#[from] ChainLogAuditError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KnownPositionBalanceNamespace {
    Ctf,
    PositionManager,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownPositionBalanceId {
    pub namespace: KnownPositionBalanceNamespace,
    pub id: B256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownPositionBalanceRow {
    namespace: KnownPositionBalanceNamespace,
    id: B256,
    storage_key: B256,
    balance: U256,
    account_code_hash: B256,
}

impl KnownPositionBalanceRow {
    #[must_use]
    pub const fn namespace(&self) -> KnownPositionBalanceNamespace {
        self.namespace
    }

    #[must_use]
    pub const fn id(&self) -> B256 {
        self.id
    }

    #[must_use]
    pub const fn storage_key(&self) -> B256 {
        self.storage_key
    }

    #[must_use]
    pub const fn balance(&self) -> U256 {
        self.balance
    }

    #[must_use]
    pub const fn account_code_hash(&self) -> B256 {
        self.account_code_hash
    }
}

/// Sealed point-in-time balance evidence for the caller's exact opaque ID set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownPositionBalancesObservation {
    code_context: FifthCodeContextObservation,
    owner: String,
    rows: Vec<KnownPositionBalanceRow>,
    // Serialized `eth_getProof` result objects only; excludes context proofs and RPC framing.
    balance_proof_json_bytes: usize,
    request_count: usize,
}

impl KnownPositionBalancesObservation {
    #[must_use]
    pub const fn chain_id(&self) -> u64 {
        CHAIN_ID
    }

    #[must_use]
    pub const fn block_number(&self) -> u64 {
        self.code_context.block_number()
    }

    #[must_use]
    pub fn block_hash(&self) -> &str {
        self.code_context.block_hash()
    }

    #[must_use]
    pub fn state_root(&self) -> &str {
        self.code_context.state_root()
    }

    #[must_use]
    pub const fn code_context(&self) -> &FifthCodeContextObservation {
        &self.code_context
    }

    #[must_use]
    pub const fn finality_attestation(&self) -> ProviderFinalityAttestation {
        self.code_context.finality_attestation()
    }

    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    #[must_use]
    pub fn rows(&self) -> &[KnownPositionBalanceRow] {
        &self.rows
    }

    #[must_use]
    pub const fn balance_proof_json_bytes(&self) -> usize {
        self.balance_proof_json_bytes
    }

    #[must_use]
    pub const fn request_count(&self) -> usize {
        self.request_count
    }

    #[must_use]
    pub const fn source_policy_version(&self) -> &'static str {
        KNOWN_POSITION_BALANCES_POLICY_VERSION
    }

    #[must_use]
    pub const fn ctf_layout_policy_version(&self) -> &'static str {
        CTF_LAYOUT_POLICY_VERSION
    }

    #[must_use]
    pub fn ctf_code_hash_candidate(&self) -> B256 {
        B256::from(CTF_CODE_HASH_CANDIDATE)
    }
}

struct ProviderRows(Vec<KnownPositionBalanceRow>);

impl ChainLogVerifier {
    /// Prove every supplied opaque ID at one caller-selected, provider-agreed root.
    #[allow(clippy::too_many_arguments)]
    pub async fn verify_known_position_balances_bounded(
        &self,
        owner: &str,
        ids: &[KnownPositionBalanceId],
        block: u64,
        expected_hash: &str,
        max_requests: usize,
        total_timeout: Duration,
    ) -> Result<KnownPositionBalancesObservation, BoundedKnownPositionBalancesError> {
        let owner = validate_hex(owner, 20).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let owner_bytes = hex::decode(&owner[2..]).map_err(|_| ChainLogAuditError::InvalidInput)?;
        if owner_bytes.iter().all(|byte| *byte == 0)
            || ids.is_empty()
            || ids.len() > MAX_IDS
            || max_requests == 0
            || total_timeout.is_zero()
        {
            return Err(ChainLogAuditError::InvalidInput.into());
        }
        let mut seen = HashSet::with_capacity(ids.len());
        if ids
            .iter()
            .any(|asset| !seen.insert((asset.namespace, asset.id)))
        {
            return Err(ChainLogAuditError::InvalidInput.into());
        }
        let expected_hash =
            validate_hex(expected_hash, 32).map_err(|_| ChainLogAuditError::InvalidInput)?;
        let owner_address = Address::from_slice(&owner_bytes);
        let deadline = tokio::time::Instant::now()
            .checked_add(total_timeout)
            .ok_or(ChainLogAuditError::InvalidInput)?;
        let budget = TransactionRequestBudget::new(max_requests);
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let scoped = self.with_request_budget(budget.inner());
        let verification = scoped.verify_known_position_balances_inner(
            owner,
            owner_address,
            ids,
            block,
            &expected_hash,
            deadline,
            budget.clone(),
        );
        tokio::pin!(verification);
        let deadline_wait = tokio::time::sleep_until(deadline);
        tokio::pin!(deadline_wait);
        tokio::select! {
            biased;
            _ = exhaustion.wait_for(|is_exhausted| *is_exhausted) => {
                Err(BoundedKnownPositionBalancesError::RequestBudgetExceeded)
            }
            () = &mut deadline_wait => {
                if budget.is_exhausted() {
                    Err(BoundedKnownPositionBalancesError::RequestBudgetExceeded)
                } else {
                    Err(BoundedKnownPositionBalancesError::Timeout)
                }
            }
            result = &mut verification => {
                if budget.is_exhausted() {
                    Err(BoundedKnownPositionBalancesError::RequestBudgetExceeded)
                } else {
                    result
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn verify_known_position_balances_inner(
        &self,
        owner: String,
        owner_address: Address,
        ids: &[KnownPositionBalanceId],
        block: u64,
        expected_hash: &str,
        deadline: tokio::time::Instant,
        budget: TransactionRequestBudget,
    ) -> Result<KnownPositionBalancesObservation, BoundedKnownPositionBalancesError> {
        ensure_before_deadline(deadline)?;
        let context = self
            .verify_fifth_code_context_inner(block, expected_hash, deadline)
            .await
            .map_err(map_context_error)?;
        if context.block_hash() != expected_hash {
            return Err(ChainLogAuditError::Unverified.into());
        }
        let capture_bytes = Arc::new(AtomicUsize::new(0));
        let (primary, secondary) = tokio::try_join!(
            self.known_position_balances_provider(
                &self.primary,
                block,
                context.state_root(),
                owner_address,
                ids,
                &capture_bytes,
            ),
            self.known_position_balances_provider(
                &self.secondary,
                block,
                context.state_root(),
                owner_address,
                ids,
                &capture_bytes,
            ),
        )?;
        ensure_before_deadline(deadline)?;
        if primary.0 != secondary.0 {
            return Err(ChainLogAuditError::Divergent.into());
        }
        ensure_before_deadline(deadline)?;
        Ok(KnownPositionBalancesObservation {
            code_context: context,
            owner,
            rows: primary.0,
            balance_proof_json_bytes: capture_bytes.load(Ordering::Acquire),
            request_count: budget.reserved_requests(),
        })
    }

    async fn known_position_balances_provider(
        &self,
        endpoint: &str,
        block: u64,
        state_root: &str,
        owner: Address,
        ids: &[KnownPositionBalanceId],
        capture_bytes: &AtomicUsize,
    ) -> Result<ProviderRows, ChainLogAuditError> {
        let mut rows = Vec::with_capacity(ids.len());
        for namespace in [
            KnownPositionBalanceNamespace::Ctf,
            KnownPositionBalanceNamespace::PositionManager,
        ] {
            let selected = ids
                .iter()
                .filter(|asset| asset.namespace == namespace)
                .collect::<Vec<_>>();
            let contract = match namespace {
                KnownPositionBalanceNamespace::Ctf => CTF_ADDRESS,
                KnownPositionBalanceNamespace::PositionManager => POSITION_MANAGER_PROXY,
            };
            let expected_code_hash = match namespace {
                KnownPositionBalanceNamespace::Ctf => B256::from(CTF_CODE_HASH_CANDIDATE),
                KnownPositionBalanceNamespace::PositionManager => {
                    parse_fixed_b256(super::fifth_code_context::ERC1967_PROXY_CODE_HASH)?
                }
            };
            for batch in selected.chunks(MAX_KEYS_PER_PROOF) {
                let keys = batch
                    .iter()
                    .map(|asset| balance_key(owner, **asset))
                    .collect::<Vec<_>>();
                let proof = self
                    .rpc(
                        endpoint,
                        "eth_getProof",
                        json!([
                            contract,
                            keys.iter()
                                .map(|key| format!("{key:#x}"))
                                .collect::<Vec<_>>(),
                            format!("{block:#x}")
                        ]),
                    )
                    .await?;
                let size = serde_json::to_vec(&proof)
                    .map_err(|_| ChainLogAuditError::Unverified)?
                    .len();
                reserve_proof_json_bytes(capture_bytes, size)?;
                let account = verify_eip1186_account_proof(state_root, contract, &proof)?;
                if account.code_hash != expected_code_hash {
                    return Err(ChainLogAuditError::Unverified);
                }
                let entries = exact_eip1186_storage_entries(&proof, &keys)?;
                for ((asset, key), entry) in batch.iter().zip(keys).zip(entries) {
                    let balance = parse_eip1186_storage_value(field(entry, "value")?)?;
                    verify_eip1186_storage_proof(
                        &account,
                        key,
                        entry,
                        (!balance.is_zero()).then(|| rlp_u256(balance)),
                        balance.is_zero(),
                    )?;
                    rows.push(KnownPositionBalanceRow {
                        namespace,
                        id: asset.id,
                        storage_key: key,
                        balance,
                        account_code_hash: account.code_hash,
                    });
                }
            }
        }
        // Match the caller's order, retaining namespace as part of every identity.
        rows.sort_by_key(|row| {
            ids.iter()
                .position(|asset| asset.namespace == row.namespace && asset.id == row.id)
                .unwrap_or(usize::MAX)
        });
        Ok(ProviderRows(rows))
    }
}

fn balance_key(owner: Address, asset: KnownPositionBalanceId) -> B256 {
    match asset.namespace {
        KnownPositionBalanceNamespace::Ctf => {
            ctf_erc1155_balance_storage_key(owner, U256::from_be_slice(asset.id.as_slice()))
        }
        KnownPositionBalanceNamespace::PositionManager => {
            super::fifth_selected_balances::position_manager_balance_key(owner, asset.id)
        }
    }
}

fn reserve_proof_json_bytes(total: &AtomicUsize, size: usize) -> Result<(), ChainLogAuditError> {
    let mut current = total.load(Ordering::Acquire);
    loop {
        let next = current
            .checked_add(size)
            .ok_or(ChainLogAuditError::Unverified)?;
        if next > MAX_BALANCE_PROOF_JSON_BYTES {
            return Err(ChainLogAuditError::Unverified);
        }
        match total.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(()),
            Err(actual) => current = actual,
        }
    }
}

fn ensure_before_deadline(
    deadline: tokio::time::Instant,
) -> Result<(), BoundedKnownPositionBalancesError> {
    if tokio::time::Instant::now() >= deadline {
        Err(BoundedKnownPositionBalancesError::Timeout)
    } else {
        Ok(())
    }
}

fn map_context_error(error: BoundedFifthCodeContextError) -> BoundedKnownPositionBalancesError {
    match error {
        BoundedFifthCodeContextError::RequestBudgetExceeded => {
            BoundedKnownPositionBalancesError::RequestBudgetExceeded
        }
        BoundedFifthCodeContextError::Timeout => BoundedKnownPositionBalancesError::Timeout,
        BoundedFifthCodeContextError::Verification(error) => {
            BoundedKnownPositionBalancesError::Verification(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_trie::{EMPTY_ROOT_HASH, HashBuilder, Nibbles, TrieAccount, proof::ProofRetainer};
    use axum::{Json, Router, extract::State, routing::post};
    use serde_json::Value;
    use sha3::{Digest, Keccak256};
    use std::{
        collections::BTreeMap,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::task::JoinHandle;

    use super::super::fifth_code_context::{
        CURRENT_EXCHANGE_CODE_HASH, CURRENT_EXCHANGE_IMPLEMENTATION, EXCHANGE_PROXY,
        POSITION_MANAGER_CODE_HASH, POSITION_MANAGER_IMPLEMENTATION,
    };

    const BLOCK: u64 = 100;
    const OWNER: &str = "0x1111111111111111111111111111111111111111";
    type StorageProofFixture = (B256, U256, Vec<String>);
    type AccountFixture = (String, TrieAccount, Vec<StorageProofFixture>);

    struct Fixture {
        header: Value,
        finalized: Value,
        proofs: BTreeMap<String, Value>,
        requests: Arc<AtomicUsize>,
        mutation: ProofMutation,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ProofMutation {
        None,
        MissingEntry,
        ExtraEntry,
        DuplicateEntry,
        WrongCtfCodeHash,
        WrongPositionManagerSlot,
        WrongRoot,
        OversizedBody,
        DelayChainId,
    }

    async fn rpc(State(fixture): State<Arc<Fixture>>, Json(request): Json<Value>) -> Json<Value> {
        fixture.requests.fetch_add(1, Ordering::Relaxed);
        let method = request["method"].as_str().unwrap_or_default();
        let params = &request["params"];
        let result = match method {
            "eth_chainId" => {
                if fixture.mutation == ProofMutation::DelayChainId {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                json!("0x89")
            }
            "eth_getBlockByNumber" if params[0] == "finalized" => fixture.finalized.clone(),
            "eth_getBlockByNumber" => {
                let mut header = fixture.header.clone();
                if fixture.mutation == ProofMutation::WrongRoot {
                    header["stateRoot"] = json!(format!("0x{}", "77".repeat(32)));
                }
                header
            }
            "eth_getProof" => {
                let address = params[0].as_str().unwrap_or_default().to_ascii_lowercase();
                let Some(mut proof) = fixture.proofs.get(&address).cloned() else {
                    return Json(json!({"jsonrpc":"2.0","id":request["id"],"result":null}));
                };
                let requested = params[1].as_array().cloned().unwrap_or_default();
                let all = proof["storageProof"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                let mut entries = requested
                    .iter()
                    .filter_map(|key| all.iter().find(|entry| entry["key"] == *key).cloned())
                    .collect::<Vec<_>>();
                match fixture.mutation {
                    ProofMutation::MissingEntry if address == CTF_ADDRESS => {
                        entries.pop();
                    }
                    ProofMutation::ExtraEntry if address == CTF_ADDRESS => {
                        entries.push(json!({"key":format!("0x{}", "77".repeat(32)),"value":"0x0","proof":[]}));
                    }
                    ProofMutation::DuplicateEntry if address == CTF_ADDRESS => {
                        if let Some(entry) = entries.first().cloned() {
                            entries.push(entry);
                        }
                    }
                    ProofMutation::WrongPositionManagerSlot
                        if address == POSITION_MANAGER_PROXY && requested.len() == 1 =>
                    {
                        if let Some(entry) = entries.first_mut() {
                            entry["value"] = json!("0x1");
                        }
                    }
                    _ => {}
                }
                proof["storageProof"] = json!(entries);
                if fixture.mutation == ProofMutation::WrongCtfCodeHash && address == CTF_ADDRESS {
                    proof["codeHash"] = json!(format!("0x{}", "77".repeat(32)));
                }
                if fixture.mutation == ProofMutation::OversizedBody && address == CTF_ADDRESS {
                    proof["padding"] = json!("x".repeat(8 * 1024 * 1024));
                }
                proof
            }
            _ => Value::Null,
        };
        Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
    }

    async fn serve(fixture: Fixture) -> (String, JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/", post(rpc))
                    .with_state(Arc::new(fixture)),
            )
            .await
            .unwrap();
        });
        (endpoint, task)
    }

    async fn verifier_pair(
        mutation: ProofMutation,
    ) -> (
        ChainLogVerifier,
        String,
        Arc<AtomicUsize>,
        JoinHandle<()>,
        JoinHandle<()>,
    ) {
        let owner = Address::from_slice(&hex::decode(&OWNER[2..]).unwrap());
        let id_a = B256::from([0x11; 32]);
        let id_b = B256::from([0x22; 32]);
        let proxy_slot =
            parse_fixed_b256(super::super::fifth_code_context::ERC1967_IMPLEMENTATION_SLOT)
                .unwrap();
        let ctf_hash = B256::from(CTF_CODE_HASH_CANDIDATE);
        let pm_hash =
            parse_fixed_b256(super::super::fifth_code_context::ERC1967_PROXY_CODE_HASH).unwrap();
        let exchange_impl_hash = parse_fixed_b256(CURRENT_EXCHANGE_CODE_HASH).unwrap();
        let mut ctf_entries = vec![
            (
                ctf_erc1155_balance_storage_key(owner, U256::from_be_slice(id_a.as_slice())),
                U256::from_be_slice(&[0x80; 32]),
            ),
            (
                ctf_erc1155_balance_storage_key(owner, U256::from_be_slice(id_b.as_slice())),
                U256::ZERO,
            ),
        ];
        for byte in 0..=64_u8 {
            let mut word = [0_u8; 32];
            word[31] = byte;
            let id = B256::new(word);
            ctf_entries.push((
                ctf_erc1155_balance_storage_key(owner, U256::from_be_slice(id.as_slice())),
                U256::from(byte),
            ));
        }
        let specs = vec![
            account_with_storage(
                EXCHANGE_PROXY,
                pm_hash,
                vec![(proxy_slot, address_word(CURRENT_EXCHANGE_IMPLEMENTATION))],
            ),
            account_without_storage(CURRENT_EXCHANGE_IMPLEMENTATION, exchange_impl_hash),
            account_with_storage(
                POSITION_MANAGER_PROXY,
                pm_hash,
                vec![
                    (proxy_slot, address_word(POSITION_MANAGER_IMPLEMENTATION)),
                    (
                        super::super::fifth_selected_balances::position_manager_balance_key(
                            owner, id_a,
                        ),
                        U256::ZERO,
                    ),
                    (
                        super::super::fifth_selected_balances::position_manager_balance_key(
                            owner, id_b,
                        ),
                        U256::from(42),
                    ),
                ],
            ),
            account_without_storage(
                POSITION_MANAGER_IMPLEMENTATION,
                parse_fixed_b256(POSITION_MANAGER_CODE_HASH).unwrap(),
            ),
            account_with_storage(CTF_ADDRESS, ctf_hash, ctf_entries),
        ];
        let (proofs, state_root) = state_proofs(specs);
        let header = super::super::header_binding::fixture_header(
            BLOCK,
            &format!("0x{}", "11".repeat(32)),
            &format!("{state_root:#x}"),
            &format!("0x{}", "00".repeat(32)),
            &format!("0x{}", "00".repeat(32)),
        );
        let finalized = super::super::header_binding::fixture_header(
            BLOCK + 1,
            header["hash"].as_str().unwrap(),
            &format!("{state_root:#x}"),
            &format!("0x{}", "00".repeat(32)),
            &format!("0x{}", "00".repeat(32)),
        );
        let requests = Arc::new(AtomicUsize::new(0));
        let primary_fixture = Fixture {
            header: header.clone(),
            finalized: finalized.clone(),
            proofs: proofs.clone(),
            requests: requests.clone(),
            mutation,
        };
        let secondary_requests = Arc::new(AtomicUsize::new(0));
        let secondary_fixture = Fixture {
            header,
            finalized,
            proofs,
            requests: secondary_requests,
            mutation,
        };
        let expected_hash = primary_fixture.header["hash"].as_str().unwrap().to_owned();
        let (primary, primary_task) = serve(primary_fixture).await;
        let (secondary, secondary_task) = serve(secondary_fixture).await;
        (
            ChainLogVerifier::new(&primary, &secondary).unwrap(),
            expected_hash,
            requests,
            primary_task,
            secondary_task,
        )
    }

    fn state_proofs(specs: Vec<AccountFixture>) -> (BTreeMap<String, Value>, B256) {
        let mut account_trie = HashBuilder::default().with_proof_retainer(
            ProofRetainer::from_iter(specs.iter().map(|(address, _, _)| account_path(address))),
        );
        let mut sorted = specs
            .into_iter()
            .map(|(address, account, storage)| (account_path(&address), address, account, storage))
            .collect::<Vec<_>>();
        sorted.sort_by_key(|(path, _, _, _)| *path);
        for (path, _, account, _) in &sorted {
            account_trie.add_leaf(*path, &alloy_rlp::encode(*account));
        }
        let root = account_trie.root();
        let account_nodes = account_trie.take_proof_nodes();
        let proofs = sorted.into_iter().map(|(path, address, account, storage)| {
            let account_proof = account_nodes.matching_nodes_sorted(&path).into_iter().map(|(_, node)| format!("0x{}", hex::encode(node))).collect::<Vec<_>>();
            let storage_proof = storage.into_iter().map(|(key, value, proof)| json!({"key":format!("{key:#x}"),"value":format!("{value:#x}"),"proof":proof})).collect::<Vec<_>>();
            (address.clone(), json!({"address":address,"nonce":format!("0x{:x}",account.nonce),"balance":format!("{:#x}",account.balance),"storageHash":format!("{:#x}",account.storage_root),"codeHash":format!("{:#x}",account.code_hash),"accountProof":account_proof,"storageProof":storage_proof}))
        }).collect();
        (proofs, root)
    }

    fn account_with_storage(
        address: &str,
        code_hash: B256,
        entries: Vec<(B256, U256)>,
    ) -> AccountFixture {
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
        let root = trie.root();
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
                storage_root: root,
                code_hash,
            },
            proofs,
        )
    }

    fn account_without_storage(address: &str, code_hash: B256) -> AccountFixture {
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

    fn address_word(address: &str) -> U256 {
        U256::from_be_slice(&hex::decode(&address[2..]).unwrap())
    }

    #[tokio::test]
    async fn proves_full_width_namespace_qualified_ids_at_one_root() {
        let (verifier, hash, requests, primary, secondary) =
            verifier_pair(ProofMutation::None).await;
        let repeated_word = B256::from([0x11; 32]);
        let ids = [
            KnownPositionBalanceId {
                namespace: KnownPositionBalanceNamespace::Ctf,
                id: repeated_word,
            },
            KnownPositionBalanceId {
                namespace: KnownPositionBalanceNamespace::PositionManager,
                id: repeated_word,
            },
            KnownPositionBalanceId {
                namespace: KnownPositionBalanceNamespace::Ctf,
                id: B256::from([0x22; 32]),
            },
        ];
        let observation = verifier
            .verify_known_position_balances_bounded(
                OWNER,
                &ids,
                BLOCK,
                &hash,
                18,
                Duration::from_secs(10),
            )
            .await
            .unwrap();
        assert_eq!(observation.rows().len(), 3);
        assert_eq!(
            observation.rows()[0].namespace(),
            KnownPositionBalanceNamespace::Ctf
        );
        assert_eq!(observation.rows()[0].id(), repeated_word);
        assert_eq!(
            observation.rows()[0].balance(),
            U256::from_be_slice(&[0x80; 32])
        );
        assert_eq!(
            observation.rows()[1].namespace(),
            KnownPositionBalanceNamespace::PositionManager
        );
        assert_eq!(observation.rows()[1].id(), repeated_word);
        assert_eq!(observation.rows()[1].balance(), U256::ZERO);
        assert_eq!(observation.rows()[2].balance(), U256::ZERO);
        assert_eq!(observation.request_count(), 18);
        assert_eq!(requests.load(Ordering::Relaxed), 9);
        assert_eq!(
            verifier
                .verify_known_position_balances_bounded(
                    OWNER,
                    &ids,
                    BLOCK,
                    &hash,
                    17,
                    Duration::from_secs(10),
                )
                .await
                .unwrap_err(),
            BoundedKnownPositionBalancesError::RequestBudgetExceeded
        );
        primary.abort();
        secondary.abort();
    }

    #[tokio::test]
    async fn rejects_duplicate_class_and_missing_proof_entry_without_prefix() {
        let (verifier, hash, _, primary, secondary) =
            verifier_pair(ProofMutation::MissingEntry).await;
        let asset = KnownPositionBalanceId {
            namespace: KnownPositionBalanceNamespace::Ctf,
            id: B256::from([0x11; 32]),
        };
        let duplicate = [asset, asset];
        assert_eq!(
            verifier
                .verify_known_position_balances_bounded(
                    OWNER,
                    &duplicate,
                    BLOCK,
                    &hash,
                    18,
                    Duration::from_secs(10)
                )
                .await
                .unwrap_err(),
            BoundedKnownPositionBalancesError::Verification(ChainLogAuditError::InvalidInput)
        );
        let single = [asset];
        assert!(
            verifier
                .verify_known_position_balances_bounded(
                    OWNER,
                    &single,
                    BLOCK,
                    &hash,
                    18,
                    Duration::from_secs(10)
                )
                .await
                .is_err()
        );
        primary.abort();
        secondary.abort();
    }

    #[tokio::test]
    async fn refuses_later_batch_budget_exhaustion_for_more_than_sixty_four_ids() {
        let (verifier, hash, _, primary, secondary) = verifier_pair(ProofMutation::None).await;
        let ids = (0..=64_u8)
            .map(|byte| {
                let mut word = [0_u8; 32];
                word[31] = byte;
                KnownPositionBalanceId {
                    namespace: KnownPositionBalanceNamespace::Ctf,
                    id: B256::new(word),
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(
            verifier
                .verify_known_position_balances_bounded(
                    OWNER,
                    &ids,
                    BLOCK,
                    &hash,
                    17,
                    Duration::from_secs(10),
                )
                .await
                .unwrap_err(),
            BoundedKnownPositionBalancesError::RequestBudgetExceeded
        );
        primary.abort();
        secondary.abort();
    }

    #[tokio::test]
    async fn rejects_wrong_roots_code_implementation_and_proof_key_shapes() {
        for mutation in [
            ProofMutation::ExtraEntry,
            ProofMutation::DuplicateEntry,
            ProofMutation::WrongCtfCodeHash,
            ProofMutation::WrongPositionManagerSlot,
            ProofMutation::WrongRoot,
        ] {
            let (verifier, hash, _, primary, secondary) = verifier_pair(mutation).await;
            let ids = [KnownPositionBalanceId {
                namespace: KnownPositionBalanceNamespace::Ctf,
                id: B256::from([0x11; 32]),
            }];
            assert!(
                verifier
                    .verify_known_position_balances_bounded(
                        OWNER,
                        &ids,
                        BLOCK,
                        &hash,
                        18,
                        Duration::from_secs(10),
                    )
                    .await
                    .is_err(),
                "mutation: {mutation:?}"
            );
            primary.abort();
            secondary.abort();
        }
    }

    #[tokio::test]
    async fn refuses_response_size_limit_and_normalized_json_aggregate_limit() {
        let (verifier, hash, _, primary, secondary) =
            verifier_pair(ProofMutation::OversizedBody).await;
        let ids = [KnownPositionBalanceId {
            namespace: KnownPositionBalanceNamespace::Ctf,
            id: B256::from([0x11; 32]),
        }];
        assert!(
            verifier
                .verify_known_position_balances_bounded(
                    OWNER,
                    &ids,
                    BLOCK,
                    &hash,
                    16,
                    Duration::from_secs(10),
                )
                .await
                .is_err()
        );
        primary.abort();
        secondary.abort();
        let total = AtomicUsize::new(0);
        assert!(reserve_proof_json_bytes(&total, MAX_BALANCE_PROOF_JSON_BYTES).is_ok());
        assert_eq!(
            reserve_proof_json_bytes(&total, 1),
            Err(ChainLogAuditError::Unverified)
        );
    }

    #[tokio::test]
    async fn enforces_one_deadline_across_the_shared_context_and_balance_reads() {
        let (verifier, hash, _, primary, secondary) =
            verifier_pair(ProofMutation::DelayChainId).await;
        let ids = [KnownPositionBalanceId {
            namespace: KnownPositionBalanceNamespace::Ctf,
            id: B256::from([0x11; 32]),
        }];
        assert_eq!(
            verifier
                .verify_known_position_balances_bounded(
                    OWNER,
                    &ids,
                    BLOCK,
                    &hash,
                    16,
                    Duration::from_millis(1),
                )
                .await
                .unwrap_err(),
            BoundedKnownPositionBalancesError::Timeout
        );
        primary.abort();
        secondary.abort();
    }

    #[tokio::test]
    async fn caller_cancellation_drops_the_incomplete_observation() {
        let (verifier, hash, requests, primary, secondary) =
            verifier_pair(ProofMutation::DelayChainId).await;
        let ids = [KnownPositionBalanceId {
            namespace: KnownPositionBalanceNamespace::Ctf,
            id: B256::from([0x11; 32]),
        }];
        let task = tokio::spawn(async move {
            verifier
                .verify_known_position_balances_bounded(
                    OWNER,
                    &ids,
                    BLOCK,
                    &hash,
                    16,
                    Duration::from_secs(2),
                )
                .await
        });
        for _ in 0..100 {
            if requests.load(Ordering::Relaxed) > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(requests.load(Ordering::Relaxed) > 0);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        primary.abort();
        secondary.abort();
    }
}
