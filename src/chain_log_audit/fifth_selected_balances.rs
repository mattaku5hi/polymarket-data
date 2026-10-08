//! One caller-selected owner's two PositionManager balances and pUSD balance.
//! The result is point-in-time evidence only; IDs remain opaque full-width words.

use super::fifth_code_context::{
    BoundedFifthCodeContextError, ERC1967_IMPLEMENTATION_SLOT, ERC1967_PROXY_CODE_HASH,
    FifthCodeContextObservation, POSITION_MANAGER_CODE_HASH, POSITION_MANAGER_IMPLEMENTATION,
    POSITION_MANAGER_PROXY,
};
use super::{
    CHAIN_ID, ChainLogAuditError, ChainLogVerifier, ProviderFinalityAttestation,
    TransactionRequestBudget, exact_eip1186_storage_entries, field, parse_eip1186_storage_value,
    parse_fixed_b256, rlp_u256, validate_hex, verify_eip1186_account_proof,
    verify_eip1186_storage_proof,
};
use alloy_primitives::{Address, B256, U256};
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};
use std::time::Duration;
use thiserror::Error;

const PUSD_PROXY: &str = "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb";
const PUSD_IMPLEMENTATION: &str = "0xce84e053301a82937f90ee2c2c1889cab1db25de";
const PUSD_PROXY_CODE_HASH_CANDIDATE: &str =
    "0xaaa52c8cc8a0e3fd27ce756cc6b4e70c51423e9b597b11f32d3e49f8b1fc890d";
const PUSD_IMPLEMENTATION_CODE_HASH: &str =
    "0x740b9ebbb47b33a28e47c999b330fe79f878b7e0f1f7e7e09b8a0928ef4e1cb0";
const PUSD_BALANCE_SLOT_SEED: [u8; 4] = [0x87, 0xa2, 0x11, 0xa2];
const POSITION_MANAGER_BALANCE_SEED: u64 = 0x9a31110384e0b0c9;

pub const FIFTH_SELECTED_BALANCES_POLICY_VERSION: &str =
    "fifth-selected-position-and-pusd-rooted-balances/1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedFifthSelectedBalancesError {
    #[error("fifth selected balances RPC request budget exhausted")]
    RequestBudgetExceeded,
    #[error("fifth selected balances exceeded its total deadline")]
    Timeout,
    #[error(transparent)]
    Verification(#[from] ChainLogAuditError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthSelectedBalancesObservation {
    code_context: FifthCodeContextObservation,
    owner: String,
    position_id_a: B256,
    position_id_b: B256,
    position_balance_a: U256,
    position_balance_b: U256,
    pusd_balance: U256,
}

impl FifthSelectedBalancesObservation {
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
    pub const fn position_id_a(&self) -> B256 {
        self.position_id_a
    }

    #[must_use]
    pub const fn position_id_b(&self) -> B256 {
        self.position_id_b
    }

    #[must_use]
    pub const fn position_balance_a(&self) -> U256 {
        self.position_balance_a
    }

    #[must_use]
    pub const fn position_balance_b(&self) -> U256 {
        self.position_balance_b
    }

    #[must_use]
    pub const fn pusd_balance(&self) -> U256 {
        self.pusd_balance
    }

    #[must_use]
    pub const fn pusd_decimals(&self) -> u8 {
        6
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

    #[must_use]
    pub fn pusd_proxy(&self) -> &'static str {
        PUSD_PROXY
    }

    #[must_use]
    pub fn pusd_proxy_code_hash(&self) -> &'static str {
        PUSD_PROXY_CODE_HASH_CANDIDATE
    }

    #[must_use]
    pub fn pusd_implementation(&self) -> &'static str {
        PUSD_IMPLEMENTATION
    }

    #[must_use]
    pub fn pusd_implementation_code_hash(&self) -> &'static str {
        PUSD_IMPLEMENTATION_CODE_HASH
    }

    #[must_use]
    pub const fn source_policy_version(&self) -> &'static str {
        FIFTH_SELECTED_BALANCES_POLICY_VERSION
    }
}

struct ProviderBalances {
    position_a: U256,
    position_b: U256,
    pusd: U256,
}

impl ChainLogVerifier {
    /// Verify two caller-selected full-width PositionIds and one pUSD balance
    /// at a single caller-anchored, provider-agreed state root.
    #[allow(clippy::too_many_arguments)]
    pub async fn verify_fifth_selected_balances_bounded(
        &self,
        owner: &str,
        id_a: &str,
        id_b: &str,
        block: u64,
        expected_hash: &str,
        max_requests: usize,
        total_timeout: Duration,
    ) -> Result<FifthSelectedBalancesObservation, BoundedFifthSelectedBalancesError> {
        let owner = validate_hex(owner, 20).map_err(|_| {
            BoundedFifthSelectedBalancesError::Verification(ChainLogAuditError::InvalidInput)
        })?;
        let owner_bytes = hex::decode(&owner[2..]).map_err(|_| {
            BoundedFifthSelectedBalancesError::Verification(ChainLogAuditError::InvalidInput)
        })?;
        if owner_bytes.iter().all(|byte| *byte == 0) {
            return Err(ChainLogAuditError::InvalidInput.into());
        }
        let id_a = parse_fixed_b256(id_a).map_err(|_| {
            BoundedFifthSelectedBalancesError::Verification(ChainLogAuditError::InvalidInput)
        })?;
        let id_b = parse_fixed_b256(id_b).map_err(|_| {
            BoundedFifthSelectedBalancesError::Verification(ChainLogAuditError::InvalidInput)
        })?;
        if id_a == id_b || max_requests == 0 || total_timeout.is_zero() {
            return Err(ChainLogAuditError::InvalidInput.into());
        }
        let expected_hash = validate_hex(expected_hash, 32).map_err(|_| {
            BoundedFifthSelectedBalancesError::Verification(ChainLogAuditError::InvalidInput)
        })?;
        let owner_address = Address::from_slice(&owner_bytes);
        let deadline = tokio::time::Instant::now()
            .checked_add(total_timeout)
            .ok_or(BoundedFifthSelectedBalancesError::Verification(
                ChainLogAuditError::InvalidInput,
            ))?;
        let budget = TransactionRequestBudget::new(max_requests);
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let scoped = self.with_request_budget(budget.inner());
        let verification = scoped.verify_fifth_selected_balances_inner(
            owner,
            owner_address,
            id_a,
            id_b,
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
                Err(BoundedFifthSelectedBalancesError::RequestBudgetExceeded)
            }
            () = &mut deadline_wait => {
                if budget.is_exhausted() {
                    Err(BoundedFifthSelectedBalancesError::RequestBudgetExceeded)
                } else {
                    Err(BoundedFifthSelectedBalancesError::Timeout)
                }
            }
            result = &mut verification => {
                if budget.is_exhausted() {
                    Err(BoundedFifthSelectedBalancesError::RequestBudgetExceeded)
                } else {
                    result
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn verify_fifth_selected_balances_inner(
        &self,
        owner: String,
        owner_address: Address,
        id_a: B256,
        id_b: B256,
        block: u64,
        expected_hash: &str,
        deadline: tokio::time::Instant,
    ) -> Result<FifthSelectedBalancesObservation, BoundedFifthSelectedBalancesError> {
        ensure_before_deadline(deadline)?;
        let code_context = self
            .verify_fifth_code_context_inner(block, expected_hash, deadline)
            .await
            .map_err(map_code_context_error)?;
        if code_context.block_hash() != expected_hash {
            return Err(ChainLogAuditError::Unverified.into());
        }

        let (primary, secondary) = tokio::try_join!(
            self.selected_balances_provider(
                &self.primary,
                block,
                code_context.state_root(),
                owner_address,
                id_a,
                id_b,
                &code_context,
            ),
            self.selected_balances_provider(
                &self.secondary,
                block,
                code_context.state_root(),
                owner_address,
                id_a,
                id_b,
                &code_context,
            ),
        )?;
        ensure_before_deadline(deadline)?;
        if primary.position_a != secondary.position_a
            || primary.position_b != secondary.position_b
            || primary.pusd != secondary.pusd
        {
            return Err(ChainLogAuditError::Divergent.into());
        }
        ensure_before_deadline(deadline)?;
        Ok(FifthSelectedBalancesObservation {
            code_context,
            owner,
            position_id_a: id_a,
            position_id_b: id_b,
            position_balance_a: primary.position_a,
            position_balance_b: primary.position_b,
            pusd_balance: primary.pusd,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn selected_balances_provider(
        &self,
        endpoint: &str,
        block: u64,
        state_root: &str,
        owner: Address,
        id_a: B256,
        id_b: B256,
        code_context: &FifthCodeContextObservation,
    ) -> Result<ProviderBalances, ChainLogAuditError> {
        let position_keys = [
            position_manager_balance_key(owner, id_a),
            position_manager_balance_key(owner, id_b),
        ];
        let position_proof = self
            .rpc(
                endpoint,
                "eth_getProof",
                json!([
                    POSITION_MANAGER_PROXY,
                    position_keys
                        .iter()
                        .map(|key| format!("{key:#x}"))
                        .collect::<Vec<_>>(),
                    format!("{block:#x}")
                ]),
            )
            .await?;
        let position_account =
            verify_eip1186_account_proof(state_root, POSITION_MANAGER_PROXY, &position_proof)?;
        if position_account.code_hash
            != parse_fixed_b256(code_context.position_manager_proxy_code_hash())?
        {
            return Err(ChainLogAuditError::Unverified);
        }
        let position_entries = exact_eip1186_storage_entries(&position_proof, &position_keys)?;
        let position_a =
            verify_balance_entry(&position_account, position_keys[0], position_entries[0])?;
        let position_b =
            verify_balance_entry(&position_account, position_keys[1], position_entries[1])?;

        let proxy_slot = parse_fixed_b256(ERC1967_IMPLEMENTATION_SLOT)?;
        let pusd_balance_key = pusd_balance_key(owner);
        let pusd_keys = [proxy_slot, pusd_balance_key];
        let pusd_proxy_proof = self
            .rpc(
                endpoint,
                "eth_getProof",
                json!([
                    PUSD_PROXY,
                    pusd_keys
                        .iter()
                        .map(|key| format!("{key:#x}"))
                        .collect::<Vec<_>>(),
                    format!("{block:#x}")
                ]),
            )
            .await?;
        let pusd_proxy_account =
            verify_eip1186_account_proof(state_root, PUSD_PROXY, &pusd_proxy_proof)?;
        if pusd_proxy_account.code_hash != parse_fixed_b256(PUSD_PROXY_CODE_HASH_CANDIDATE)? {
            return Err(ChainLogAuditError::Unverified);
        }
        let pusd_entries = exact_eip1186_storage_entries(&pusd_proxy_proof, &pusd_keys)?;
        let implementation_value = parse_eip1186_storage_value(field(pusd_entries[0], "value")?)?;
        let implementation_word = address_word(PUSD_IMPLEMENTATION)?;
        if implementation_value != implementation_word {
            return Err(ChainLogAuditError::Unverified);
        }
        verify_eip1186_storage_proof(
            &pusd_proxy_account,
            proxy_slot,
            pusd_entries[0],
            Some(rlp_u256(implementation_word)),
            false,
        )?;
        let pusd_balance =
            verify_balance_entry(&pusd_proxy_account, pusd_balance_key, pusd_entries[1])?;

        let implementation_proof = self
            .rpc(
                endpoint,
                "eth_getProof",
                json!([PUSD_IMPLEMENTATION, [], format!("{block:#x}")]),
            )
            .await?;
        if implementation_proof
            .get("storageProof")
            .and_then(Value::as_array)
            .is_none_or(|entries| !entries.is_empty())
        {
            return Err(ChainLogAuditError::Unverified);
        }
        let implementation_account =
            verify_eip1186_account_proof(state_root, PUSD_IMPLEMENTATION, &implementation_proof)?;
        if implementation_account.code_hash != parse_fixed_b256(PUSD_IMPLEMENTATION_CODE_HASH)? {
            return Err(ChainLogAuditError::Unverified);
        }
        Ok(ProviderBalances {
            position_a,
            position_b,
            pusd: pusd_balance,
        })
    }
}

fn ensure_before_deadline(
    deadline: tokio::time::Instant,
) -> Result<(), BoundedFifthSelectedBalancesError> {
    if tokio::time::Instant::now() >= deadline {
        Err(BoundedFifthSelectedBalancesError::Timeout)
    } else {
        Ok(())
    }
}

fn map_code_context_error(
    error: BoundedFifthCodeContextError,
) -> BoundedFifthSelectedBalancesError {
    match error {
        BoundedFifthCodeContextError::RequestBudgetExceeded => {
            BoundedFifthSelectedBalancesError::RequestBudgetExceeded
        }
        BoundedFifthCodeContextError::Timeout => BoundedFifthSelectedBalancesError::Timeout,
        BoundedFifthCodeContextError::Verification(error) => {
            BoundedFifthSelectedBalancesError::Verification(error)
        }
    }
}

fn verify_balance_entry(
    account: &alloy_trie::TrieAccount,
    key: B256,
    entry: &Value,
) -> Result<U256, ChainLogAuditError> {
    let value = parse_eip1186_storage_value(field(entry, "value")?)?;
    verify_eip1186_storage_proof(
        account,
        key,
        entry,
        (!value.is_zero()).then(|| rlp_u256(value)),
        value.is_zero(),
    )?;
    Ok(value)
}

fn address_word(address: &str) -> Result<U256, ChainLogAuditError> {
    let address = validate_hex(address, 20)?;
    let bytes = hex::decode(&address[2..]).map_err(|_| ChainLogAuditError::Unverified)?;
    Ok(U256::from_be_slice(&bytes))
}

fn pusd_balance_key(owner: Address) -> B256 {
    let mut preimage = [0_u8; 32];
    preimage[..20].copy_from_slice(owner.as_slice());
    preimage[28..].copy_from_slice(&PUSD_BALANCE_SLOT_SEED);
    B256::from_slice(&Keccak256::digest(preimage))
}

fn position_manager_balance_key(owner: Address, id: B256) -> B256 {
    let owner_value = U256::from_be_slice(owner.as_slice());
    let seed: U256 = (owner_value << 96_u32) | U256::from(POSITION_MANAGER_BALANCE_SEED);
    let mut preimage = [0_u8; 64];
    preimage[..32].copy_from_slice(id.as_slice());
    preimage[32..].copy_from_slice(&seed.to_be_bytes::<32>());
    B256::from_slice(&Keccak256::digest(preimage))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_trie::{EMPTY_ROOT_HASH, HashBuilder, Nibbles, TrieAccount, proof::ProofRetainer};
    use axum::{Json, Router, extract::State, routing::post};
    use serde_json::Value;
    use std::{
        collections::BTreeMap,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Instant as StdInstant,
    };
    use tokio::{
        sync::{Notify, watch},
        task::JoinHandle,
    };

    use super::super::fifth_code_context::{
        CURRENT_EXCHANGE_CODE_HASH, CURRENT_EXCHANGE_IMPLEMENTATION, EXCHANGE_PROXY,
        FifthExchangeImplementationVersion, PRIOR_EXCHANGE_CODE_HASH,
        PRIOR_EXCHANGE_IMPLEMENTATION,
    };

    const BLOCK: u64 = 100;
    const OWNER: &str = "0x1111111111111111111111111111111111111111";
    const ID_A: &str = "0x010123456789abcdef0123456789abcdef000000000000000000000000000000";
    const ID_B: &str = "0x010123456789abcdef0123456789abcdef000000000000000000000000000001";
    type RootedAccountProof = (String, TrieAccount, Vec<(B256, U256, Vec<String>)>);

    #[derive(Debug, Clone, Copy)]
    enum ProofShape {
        Valid,
        MissingEntry,
        ExtraEntry,
        DuplicateEntry,
        ChangedValue,
        WrongCodeHash,
        WrongAddress,
        UnknownImplementation,
        WrongHeader,
    }

    struct Fixture {
        block_header: Value,
        finalized_header: Value,
        proofs: BTreeMap<String, Value>,
        responses: Arc<Mutex<Vec<Value>>>,
        requests: Arc<AtomicUsize>,
        shape: ProofShape,
        initial_advance: Option<Duration>,
        initial_advance_once: Arc<AtomicBool>,
        gate_address: Option<String>,
        gate: Arc<ProofGate>,
    }

    struct ProofGate {
        started: AtomicUsize,
        notify: Notify,
        release: watch::Sender<bool>,
    }

    impl ProofGate {
        fn new() -> Arc<Self> {
            let (release, _) = watch::channel(false);
            Arc::new(Self {
                started: AtomicUsize::new(0),
                notify: Notify::new(),
                release,
            })
        }

        async fn wait_until_started(&self, count: usize) {
            loop {
                let notified = self.notify.notified();
                if self.started.load(Ordering::Acquire) >= count {
                    return;
                }
                notified.await;
            }
        }

        async fn stop(&self) {
            let mut release = self.release.subscribe();
            if !*release.borrow() {
                self.started.fetch_add(1, Ordering::AcqRel);
                self.notify.notify_waiters();
                let _ = release.wait_for(|is_released| *is_released).await;
            }
        }

        fn release(&self) {
            let _ = self.release.send(true);
        }
    }

    async fn rpc(State(fixture): State<Arc<Fixture>>, Json(request): Json<Value>) -> Json<Value> {
        fixture.requests.fetch_add(1, Ordering::Relaxed);
        let method = request["method"].as_str().unwrap_or_default();
        let params = request["params"].clone();
        let result = match method {
            "eth_chainId" => {
                if fixture
                    .initial_advance
                    .is_some_and(|_| !fixture.initial_advance_once.swap(true, Ordering::AcqRel))
                {
                    tokio::time::advance(fixture.initial_advance.unwrap()).await;
                }
                json!("0x89")
            }
            "eth_getBlockByNumber" if params[0] == "finalized" => {
                if matches!(fixture.shape, ProofShape::WrongHeader) {
                    let mut header = fixture.finalized_header.clone();
                    header["stateRoot"] = json!(format!("0x{}", "77".repeat(32)));
                    header
                } else {
                    fixture.finalized_header.clone()
                }
            }
            "eth_getBlockByNumber" => {
                if matches!(fixture.shape, ProofShape::WrongHeader) {
                    let mut header = fixture.block_header.clone();
                    header["stateRoot"] = json!(format!("0x{}", "77".repeat(32)));
                    header
                } else {
                    fixture.block_header.clone()
                }
            }
            "eth_getProof" => {
                let address = params[0].as_str().unwrap_or_default().to_ascii_lowercase();
                if fixture.gate_address.as_deref() == Some(address.as_str()) {
                    fixture.gate.stop().await;
                }
                proof_response(&fixture, &address, &params[1])
            }
            _ => Value::Null,
        };
        fixture.responses.lock().unwrap().push(json!({
            "method":method,
            "params":params,
            "result":result.clone(),
        }));
        Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
    }

    fn proof_response(fixture: &Fixture, address: &str, requested_keys: &Value) -> Value {
        let Some(mut proof) = fixture.proofs.get(address).cloned() else {
            return Value::Null;
        };
        let requested = requested_keys
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        let all_entries = proof["storageProof"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mut entries = requested
            .iter()
            .filter_map(|key| {
                all_entries
                    .iter()
                    .find(|entry| entry["key"].as_str() == Some(*key))
                    .cloned()
            })
            .collect::<Vec<_>>();
        match fixture.shape {
            ProofShape::MissingEntry
                if address == POSITION_MANAGER_PROXY && requested.len() == 2 =>
            {
                entries.pop();
            }
            ProofShape::ExtraEntry if address == POSITION_MANAGER_PROXY && requested.len() == 2 => {
                entries
                    .push(json!({"key":format!("0x{}", "77".repeat(32)),"value":"0x0","proof":[]}));
            }
            ProofShape::DuplicateEntry
                if address == POSITION_MANAGER_PROXY && requested.len() == 2 =>
            {
                if let Some(entry) = entries.first().cloned() {
                    entries.push(entry);
                }
            }
            ProofShape::ChangedValue
                if address == POSITION_MANAGER_PROXY && requested.len() == 2 =>
            {
                if let Some(entry) = entries.first_mut() {
                    entry["value"] = json!("0x7");
                }
            }
            ProofShape::WrongCodeHash
                if address == POSITION_MANAGER_PROXY && requested.len() == 2 =>
            {
                proof["codeHash"] = json!(format!("0x{}", "77".repeat(32)));
            }
            ProofShape::WrongAddress
                if address == POSITION_MANAGER_PROXY && requested.len() == 2 =>
            {
                proof["address"] = json!(format!("0x{}", "77".repeat(20)));
            }
            ProofShape::UnknownImplementation if address == PUSD_PROXY => {
                if let Some(entry) = entries.first_mut() {
                    entry["value"] = json!(format!("0x{}", "77".repeat(20)));
                }
            }
            ProofShape::Valid
            | ProofShape::MissingEntry
            | ProofShape::ExtraEntry
            | ProofShape::DuplicateEntry
            | ProofShape::ChangedValue
            | ProofShape::WrongCodeHash
            | ProofShape::WrongAddress
            | ProofShape::UnknownImplementation
            | ProofShape::WrongHeader => {}
        }
        proof["storageProof"] = json!(entries);
        proof
    }

    async fn serve(fixture: Fixture) -> (String, JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(fixture);
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/", post(rpc)).with_state(state),
            )
            .await
            .unwrap();
        });
        (endpoint, task)
    }

    struct Pair {
        verifier: ChainLogVerifier,
        expected_hash: String,
        state_root: String,
        primary_server: JoinHandle<()>,
        secondary_server: JoinHandle<()>,
        primary_requests: Arc<AtomicUsize>,
        secondary_requests: Arc<AtomicUsize>,
        primary_responses: Arc<Mutex<Vec<Value>>>,
        secondary_responses: Arc<Mutex<Vec<Value>>>,
        gate: Arc<ProofGate>,
    }

    async fn verifier_pair(
        version: FifthExchangeImplementationVersion,
        balances: [U256; 2],
        cash: U256,
        shape: ProofShape,
        gate: bool,
    ) -> Pair {
        verifier_pair_with_initial_advance(version, balances, cash, shape, gate, None).await
    }

    async fn verifier_pair_with_initial_advance(
        version: FifthExchangeImplementationVersion,
        balances: [U256; 2],
        cash: U256,
        shape: ProofShape,
        gate: bool,
        initial_advance: Option<Duration>,
    ) -> Pair {
        let initial_advance_once = Arc::new(AtomicBool::new(false));
        let primary = rooted_fixture(
            version,
            balances,
            cash,
            shape,
            gate,
            initial_advance,
            initial_advance_once.clone(),
        );
        let secondary = rooted_fixture(
            version,
            balances,
            cash,
            shape,
            gate,
            initial_advance,
            initial_advance_once,
        );
        let expected_hash = primary.block_header["hash"].as_str().unwrap().to_owned();
        let state_root = primary.block_header["stateRoot"]
            .as_str()
            .unwrap()
            .to_owned();
        let gate = primary.gate.clone();
        let primary_requests = primary.requests.clone();
        let secondary_requests = secondary.requests.clone();
        let primary_responses = primary.responses.clone();
        let secondary_responses = secondary.responses.clone();
        let (primary_endpoint, primary_server) = serve(primary).await;
        let (secondary_endpoint, secondary_server) = serve(secondary).await;
        Pair {
            verifier: ChainLogVerifier::new(&primary_endpoint, &secondary_endpoint).unwrap(),
            expected_hash,
            state_root,
            primary_server,
            secondary_server,
            primary_requests,
            secondary_requests,
            primary_responses,
            secondary_responses,
            gate,
        }
    }

    fn rooted_fixture(
        version: FifthExchangeImplementationVersion,
        balances: [U256; 2],
        cash: U256,
        shape: ProofShape,
        gate: bool,
        initial_advance: Option<Duration>,
        initial_advance_once: Arc<AtomicBool>,
    ) -> Fixture {
        let owner = Address::from_slice(&hex::decode(&OWNER[2..]).unwrap());
        let id_a = parse_fixed_b256(ID_A).unwrap();
        let id_b = parse_fixed_b256(ID_B).unwrap();
        let slot = parse_fixed_b256(ERC1967_IMPLEMENTATION_SLOT).unwrap();
        let (exchange_implementation, exchange_hash) = match version {
            FifthExchangeImplementationVersion::Prior7345 => {
                (PRIOR_EXCHANGE_IMPLEMENTATION, PRIOR_EXCHANGE_CODE_HASH)
            }
            FifthExchangeImplementationVersion::Current641b => {
                (CURRENT_EXCHANGE_IMPLEMENTATION, CURRENT_EXCHANGE_CODE_HASH)
            }
        };
        let mut accounts = [
            account_with_storage(
                EXCHANGE_PROXY,
                parse_fixed_b256(ERC1967_PROXY_CODE_HASH).unwrap(),
                vec![(slot, address_word(exchange_implementation).unwrap())],
            ),
            account_without_storage(
                exchange_implementation,
                parse_fixed_b256(exchange_hash).unwrap(),
            ),
            account_with_storage(
                POSITION_MANAGER_PROXY,
                parse_fixed_b256(ERC1967_PROXY_CODE_HASH).unwrap(),
                vec![
                    (slot, address_word(POSITION_MANAGER_IMPLEMENTATION).unwrap()),
                    (position_manager_balance_key(owner, id_a), balances[0]),
                    (position_manager_balance_key(owner, id_b), balances[1]),
                ],
            ),
            account_without_storage(
                POSITION_MANAGER_IMPLEMENTATION,
                parse_fixed_b256(POSITION_MANAGER_CODE_HASH).unwrap(),
            ),
            account_with_storage(
                PUSD_PROXY,
                parse_fixed_b256(PUSD_PROXY_CODE_HASH_CANDIDATE).unwrap(),
                vec![
                    (slot, address_word(PUSD_IMPLEMENTATION).unwrap()),
                    (pusd_balance_key(owner), cash),
                ],
            ),
            account_without_storage(
                PUSD_IMPLEMENTATION,
                parse_fixed_b256(PUSD_IMPLEMENTATION_CODE_HASH).unwrap(),
            ),
        ];
        let mut account_trie = HashBuilder::default().with_proof_retainer(
            ProofRetainer::from_iter(accounts.iter().map(|(address, _, _)| account_path(address))),
        );
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
            account_trie.add_leaf(*path, &alloy_rlp::encode(*account));
        }
        let state_root = account_trie.root();
        let account_nodes = account_trie.take_proof_nodes();
        let proofs = sorted
            .into_iter()
            .map(|(path, address, account, entries)| {
                let account_proof = account_nodes
                    .matching_nodes_sorted(&path)
                    .into_iter()
                    .map(|(_, node)| format!("0x{}", hex::encode(node)))
                    .collect::<Vec<_>>();
                let storage_proof = entries
                    .into_iter()
                    .map(|(key, value, nodes)| {
                        json!({"key":format!("{key:#x}"),"value":format!("{value:#x}"),"proof":nodes})
                    })
                    .collect::<Vec<_>>();
                (
                    address.clone(),
                    json!({
                        "address":address,
                        "nonce":format!("0x{:x}",account.nonce),
                        "balance":format!("{:#x}",account.balance),
                        "storageHash":format!("{:#x}",account.storage_root),
                        "codeHash":format!("{:#x}",account.code_hash),
                        "accountProof":account_proof,
                        "storageProof":storage_proof,
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
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
        Fixture {
            block_header,
            finalized_header,
            proofs,
            responses: Arc::new(Mutex::new(Vec::new())),
            requests: Arc::new(AtomicUsize::new(0)),
            shape,
            initial_advance,
            initial_advance_once,
            gate_address: gate.then(|| PUSD_IMPLEMENTATION.to_owned()),
            gate: ProofGate::new(),
        }
    }

    fn account_with_storage(
        address: &str,
        code_hash: B256,
        entries: Vec<(B256, U256)>,
    ) -> RootedAccountProof {
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

    fn account_without_storage(address: &str, code_hash: B256) -> RootedAccountProof {
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

    fn rpc_rows(rows: &[Value]) -> Vec<Value> {
        let mut unique = BTreeMap::new();
        for row in rows {
            let key = serde_json::to_string(&json!([row["method"], row["params"]])).unwrap();
            if let Some(previous) = unique.insert(key, row.clone()) {
                assert_eq!(previous["result"], row["result"]);
            }
        }
        unique.into_values().collect()
    }

    fn capture(case: &str, observation: &FifthSelectedBalancesObservation, rows: Vec<Value>) {
        let Ok(directory) = std::env::var("PDH_CAPTURE_FIFTH_SELECTED_BALANCES_DIRECTORY") else {
            return;
        };
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../")
            .join(directory)
            .join(format!("fifth-selected-balances-{case}-rpc.json"));
        let bytes = serde_json::to_vec(&json!({
            "provenance":"Deterministic rooted loopback proof fixture; no provider or chain retrieval.",
            "case":case,
            "owner":observation.owner(),
            "position_id_a":format!("{:#x}",observation.position_id_a()),
            "position_id_b":format!("{:#x}",observation.position_id_b()),
            "block_number":observation.block_number(),
            "block_hash":observation.block_hash(),
            "state_root":observation.state_root(),
            "rpc_responses":rows,
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

    async fn wall_guard(duration: Duration) {
        let end = StdInstant::now() + duration;
        while StdInstant::now() < end {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn fifth_selected_balances_current_root_proves_nonzero_and_zero_quantities() {
        let high_position = U256::from_be_slice(&[0x80; 32]);
        let high_cash = U256::from_be_slice(&[0x91; 32]);
        for (case, balances, cash) in [
            ("nonzero", [high_position, U256::from(42_u8)], high_cash),
            ("zero", [U256::ZERO, U256::ZERO], U256::ZERO),
        ] {
            let pair = verifier_pair(
                FifthExchangeImplementationVersion::Current641b,
                balances,
                cash,
                ProofShape::Valid,
                false,
            )
            .await;
            let observation = pair
                .verifier
                .verify_fifth_selected_balances_bounded(
                    OWNER,
                    ID_A,
                    ID_B,
                    BLOCK,
                    &pair.expected_hash,
                    20,
                    Duration::from_secs(10),
                )
                .await
                .unwrap();
            assert_eq!(observation.owner(), OWNER);
            assert_eq!(observation.position_id_a(), parse_fixed_b256(ID_A).unwrap());
            assert_eq!(observation.position_id_b(), parse_fixed_b256(ID_B).unwrap());
            assert_eq!(observation.position_balance_a(), balances[0]);
            assert_eq!(observation.position_balance_b(), balances[1]);
            assert_eq!(observation.pusd_balance(), cash);
            assert_eq!(observation.pusd_decimals(), 6);
            assert_eq!(observation.block_hash(), pair.expected_hash);
            assert_eq!(observation.state_root(), pair.state_root);
            assert_eq!(pair.primary_requests.load(Ordering::Relaxed), 10);
            assert_eq!(pair.secondary_requests.load(Ordering::Relaxed), 10);
            assert_eq!(observation.position_manager_proxy(), POSITION_MANAGER_PROXY);
            assert_eq!(
                observation.position_manager_implementation(),
                POSITION_MANAGER_IMPLEMENTATION
            );
            assert_eq!(observation.pusd_proxy(), PUSD_PROXY);
            assert_eq!(observation.pusd_implementation(), PUSD_IMPLEMENTATION);
            let mut rows = pair.primary_responses.lock().unwrap().clone();
            rows.extend(pair.secondary_responses.lock().unwrap().clone());
            capture(case, &observation, rpc_rows(&rows));
            pair.primary_server.abort();
            pair.secondary_server.abort();
        }
    }

    #[tokio::test]
    async fn fifth_selected_balances_reject_bad_inputs_and_rooted_proof_shapes() {
        let pair = verifier_pair(
            FifthExchangeImplementationVersion::Current641b,
            [U256::from(1_u8), U256::from(2_u8)],
            U256::from(3_u8),
            ProofShape::Valid,
            false,
        )
        .await;
        for (owner, id_a, id_b, hash) in [
            (
                "0x0000000000000000000000000000000000000000",
                ID_A,
                ID_B,
                pair.expected_hash.as_str(),
            ),
            ("0x1111", ID_A, ID_B, pair.expected_hash.as_str()),
            (OWNER, ID_A, ID_A, pair.expected_hash.as_str()),
            (OWNER, "0x01", ID_B, pair.expected_hash.as_str()),
            (OWNER, ID_A, ID_B, "0x01"),
        ] {
            assert!(
                pair.verifier
                    .verify_fifth_selected_balances_bounded(
                        owner,
                        id_a,
                        id_b,
                        BLOCK,
                        hash,
                        20,
                        Duration::from_secs(10),
                    )
                    .await
                    .is_err()
            );
        }
        assert!(
            pair.verifier
                .verify_fifth_selected_balances_bounded(
                    OWNER,
                    ID_A,
                    ID_B,
                    BLOCK,
                    &pair.expected_hash,
                    0,
                    Duration::from_secs(10),
                )
                .await
                .is_err()
        );
        assert!(
            pair.verifier
                .verify_fifth_selected_balances_bounded(
                    OWNER,
                    ID_A,
                    ID_B,
                    BLOCK,
                    &pair.expected_hash,
                    20,
                    Duration::ZERO,
                )
                .await
                .is_err()
        );
        assert_eq!(pair.primary_requests.load(Ordering::Relaxed), 0);
        assert_eq!(pair.secondary_requests.load(Ordering::Relaxed), 0);
        pair.primary_server.abort();
        pair.secondary_server.abort();

        for shape in [
            ProofShape::MissingEntry,
            ProofShape::ExtraEntry,
            ProofShape::DuplicateEntry,
            ProofShape::ChangedValue,
            ProofShape::WrongCodeHash,
            ProofShape::WrongAddress,
            ProofShape::UnknownImplementation,
            ProofShape::WrongHeader,
        ] {
            let pair = verifier_pair(
                FifthExchangeImplementationVersion::Current641b,
                [U256::from(1_u8), U256::from(2_u8)],
                U256::from(3_u8),
                shape,
                false,
            )
            .await;
            let result = pair
                .verifier
                .verify_fifth_selected_balances_bounded(
                    OWNER,
                    ID_A,
                    ID_B,
                    BLOCK,
                    &pair.expected_hash,
                    20,
                    Duration::from_secs(10),
                )
                .await;
            assert!(result.is_err(), "proof shape should refuse: {shape:?}");
            if matches!(shape, ProofShape::UnknownImplementation) {
                let requests = pair.primary_responses.lock().unwrap();
                assert!(!requests.iter().any(|row| {
                    row["method"] == "eth_getProof" && row["params"][0] == PUSD_IMPLEMENTATION
                }));
            }
            pair.primary_server.abort();
            pair.secondary_server.abort();
        }

        let pair = verifier_pair(
            FifthExchangeImplementationVersion::Current641b,
            [U256::from(1_u8), U256::from(2_u8)],
            U256::from(3_u8),
            ProofShape::Valid,
            false,
        )
        .await;
        assert!(
            pair.verifier
                .verify_fifth_selected_balances_bounded(
                    "0x2222222222222222222222222222222222222222",
                    ID_A,
                    ID_B,
                    BLOCK,
                    &pair.expected_hash,
                    20,
                    Duration::from_secs(10),
                )
                .await
                .is_err()
        );
        pair.primary_server.abort();
        pair.secondary_server.abort();

        let pair = verifier_pair(
            FifthExchangeImplementationVersion::Current641b,
            [U256::from(1_u8), U256::from(2_u8)],
            U256::from(3_u8),
            ProofShape::Valid,
            false,
        )
        .await;
        let wrong_hash = format!("0x{}", "77".repeat(32));
        assert!(
            pair.verifier
                .verify_fifth_selected_balances_bounded(
                    OWNER,
                    ID_A,
                    ID_B,
                    BLOCK,
                    &wrong_hash,
                    20,
                    Duration::from_secs(10),
                )
                .await
                .is_err()
        );
        assert_eq!(pair.primary_requests.load(Ordering::Relaxed), 3);
        assert_eq!(pair.secondary_requests.load(Ordering::Relaxed), 3);
        pair.primary_server.abort();
        pair.secondary_server.abort();
    }

    #[tokio::test]
    async fn fifth_selected_balances_share_late_budget_deadline_and_cancellation() {
        let pair = verifier_pair(
            FifthExchangeImplementationVersion::Current641b,
            [U256::from(4_u8), U256::from(9_u8)],
            U256::from(18_u8),
            ProofShape::Valid,
            false,
        )
        .await;
        assert_eq!(
            pair.verifier
                .verify_fifth_selected_balances_bounded(
                    OWNER,
                    ID_A,
                    ID_B,
                    BLOCK,
                    &pair.expected_hash,
                    19,
                    Duration::from_secs(10),
                )
                .await,
            Err(BoundedFifthSelectedBalancesError::RequestBudgetExceeded)
        );
        let received_requests = pair.primary_requests.load(Ordering::Relaxed)
            + pair.secondary_requests.load(Ordering::Relaxed);
        assert!((18..=19).contains(&received_requests));
        {
            let rows = pair.primary_responses.lock().unwrap();
            assert_eq!(
                rows.iter()
                    .filter(|row| {
                        row["method"] == "eth_getProof" && row["params"][0] == PUSD_PROXY
                    })
                    .count(),
                1
            );
        }
        {
            let rows = pair.secondary_responses.lock().unwrap();
            assert_eq!(
                rows.iter()
                    .filter(|row| {
                        row["method"] == "eth_getProof" && row["params"][0] == PUSD_PROXY
                    })
                    .count(),
                1
            );
        }
        // A send reservation can be rejected and cancel a peer request before
        // that HTTP request reaches the loopback server, so arrivals may trail
        // the shared budget's reserved-send count by one.
        pair.primary_server.abort();
        pair.secondary_server.abort();
        tokio::time::pause();
        let pair = verifier_pair_with_initial_advance(
            FifthExchangeImplementationVersion::Current641b,
            [U256::from(4_u8), U256::from(9_u8)],
            U256::from(18_u8),
            ProofShape::Valid,
            true,
            Some(Duration::from_millis(500)),
        )
        .await;
        let future = pair.verifier.verify_fifth_selected_balances_bounded(
            OWNER,
            ID_A,
            ID_B,
            BLOCK,
            &pair.expected_hash,
            20,
            Duration::from_secs(1),
        );
        tokio::pin!(future);
        let mut guard = tokio::spawn(wall_guard(Duration::from_secs(30)));
        tokio::select! {
            _ = pair.gate.wait_until_started(1) => {}
            result = &mut future => panic!("verification ended before late proof gate: {result:?}"),
            _ = &mut guard => panic!("late proof gate did not start"),
        }
        tokio::time::advance(Duration::from_millis(600)).await;
        let result = tokio::select! {
            result = &mut future => result,
            _ = &mut guard => panic!("deadline result did not arrive within wall bound"),
        };
        assert_eq!(result, Err(BoundedFifthSelectedBalancesError::Timeout));
        pair.gate.release();
        guard.abort();
        pair.primary_server.abort();
        pair.secondary_server.abort();
        tokio::time::resume();

        let pair = verifier_pair(
            FifthExchangeImplementationVersion::Current641b,
            [U256::from(4_u8), U256::from(9_u8)],
            U256::from(18_u8),
            ProofShape::Valid,
            true,
        )
        .await;
        let verifier = pair.verifier;
        let expected_hash = pair.expected_hash.clone();
        let mut task = tokio::spawn(async move {
            verifier
                .verify_fifth_selected_balances_bounded(
                    OWNER,
                    ID_A,
                    ID_B,
                    BLOCK,
                    &expected_hash,
                    20,
                    Duration::from_secs(10),
                )
                .await
        });
        let mut guard = tokio::spawn(wall_guard(Duration::from_secs(30)));
        tokio::select! {
            _ = pair.gate.wait_until_started(1) => {}
            result = &mut task => panic!("verification ended before cancellation gate: {result:?}"),
            _ = &mut guard => panic!("cancellation proof gate did not start"),
        }
        task.abort();
        let _ = task.await;
        let requests_at_abort = pair.primary_requests.load(Ordering::Relaxed)
            + pair.secondary_requests.load(Ordering::Relaxed);
        pair.gate.release();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            pair.primary_requests.load(Ordering::Relaxed)
                + pair.secondary_requests.load(Ordering::Relaxed),
            requests_at_abort
        );
        guard.abort();
        pair.primary_server.abort();
        pair.secondary_server.abort();
    }

    #[test]
    fn fifth_selected_balance_slot_formulas_match_parent_vectors() {
        let owner = Address::from_slice(&hex::decode(&OWNER[2..]).unwrap());
        assert_eq!(
            format!("{:#x}", pusd_balance_key(owner)),
            "0x9997d51b74a3fde17e56becb3912f358d0629006aafa83c01147270cff8b2254"
        );
        assert_eq!(
            format!(
                "{:#x}",
                position_manager_balance_key(owner, parse_fixed_b256(ID_A).unwrap())
            ),
            "0xc4d1ba415d232cd72285b21a5944d9ea20533d8a54406a245a09bc23039c3727"
        );
        assert_eq!(
            format!(
                "{:#x}",
                position_manager_balance_key(owner, parse_fixed_b256(ID_B).unwrap())
            ),
            "0x8db1ed9f7262844c9956f53fe26d5b6232d77d3ccfaa27e6ea95fb742f347e50"
        );
    }
}
