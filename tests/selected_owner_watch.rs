use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicUsize, Ordering},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{Json, Router, extract::State, routing::post};
use polymarket_data::chain_log_audit::{
    BoundedSelectedCtfV2OwnerWatchError, BoundedSelectedCtfV2OwnerWindowError, ChainLogAuditError,
    ChainLogVerifier, SelectedCtfV2OwnerWatchWindow,
    SourceAttestedSelectedCtfV2OwnerWatchObservation, TransactionRequestBudget,
};
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};
use tokio::task::JoinHandle;

const MAKER_ONE: &str = "0x1111111111111111111111111111111111111111";
const MAKER_TWO: &str = "0x2222222222222222222222222222222222222222";
const COUNTERPARTY: &str = "0x3333333333333333333333333333333333333333";
const BLOCK_HASH: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TX_HASH_ONE: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const TX_HASH_TWO: &str = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const V2_EXCHANGE_ONE: &str = "0xe111180000d2663c0091e4f400237545b87b996b";
const V2_EXCHANGE_TWO: &str = "0xe2222d279d744050d28e00520010520000310f59";

fn uppercase_hex_digits(value: &str) -> String {
    format!("0x{}", value[2..].to_ascii_uppercase())
}

#[derive(Clone)]
struct ProviderState {
    logs: Vec<Value>,
    requests: Arc<Mutex<Vec<Value>>>,
    delay: Duration,
}

struct Provider {
    url: String,
    requests: Arc<Mutex<Vec<Value>>>,
    task: JoinHandle<()>,
}

impl Drop for Provider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct ProviderPair {
    verifier: ChainLogVerifier,
    primary: Provider,
    secondary: Provider,
}

#[derive(Clone)]
struct WindowProviderState {
    finalized: Value,
    requests: Arc<Mutex<Vec<Value>>>,
    log_requests: Arc<AtomicUsize>,
    logs_by_maker_topic: Arc<BTreeMap<String, Value>>,
    delay: Duration,
}

impl ProviderPair {
    fn request_count(&self) -> usize {
        self.primary.requests.lock().unwrap().len() + self.secondary.requests.lock().unwrap().len()
    }
}

async fn rpc(State(state): State<ProviderState>, Json(request): Json<Value>) -> Json<Value> {
    state.requests.lock().unwrap().push(request.clone());
    tokio::time::sleep(state.delay).await;
    Json(json!({
        "jsonrpc":"2.0",
        "id":request.get("id").cloned().unwrap_or(Value::Null),
        "result":state.logs,
    }))
}

async fn start_provider(logs: Vec<Value>) -> Provider {
    start_provider_with_delay(logs, Duration::ZERO).await
}

async fn start_provider_with_delay(logs: Vec<Value>, delay: Duration) -> Provider {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback provider listener");
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let state = ProviderState {
        logs,
        requests: Arc::clone(&requests),
        delay,
    };
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/", post(rpc)).with_state(state),
        )
        .await
        .expect("loopback provider server");
    });
    Provider {
        url,
        requests,
        task,
    }
}

async fn window_rpc(
    State(state): State<WindowProviderState>,
    Json(request): Json<Value>,
) -> Json<Value> {
    state.requests.lock().unwrap().push(request.clone());
    tokio::time::sleep(state.delay).await;
    let result = match request["method"].as_str() {
        Some("eth_getBlockByNumber") => state.finalized.clone(),
        Some("eth_getLogs") => {
            state.log_requests.fetch_add(1, Ordering::Relaxed);
            let selected = request["params"][0]["topics"][2]
                .as_array()
                .expect("selected maker topic list")
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>();
            state
                .logs_by_maker_topic
                .iter()
                .filter(|(topic, _)| selected.contains(topic.as_str()))
                .map(|(_, log)| log.clone())
                .collect::<Vec<_>>()
                .into()
        }
        _ => Value::Null,
    };
    Json(json!({
        "jsonrpc":"2.0",
        "id":request.get("id").cloned().unwrap_or(Value::Null),
        "result":result,
    }))
}

async fn start_window_provider(
    finalized: Value,
    logs_by_maker_topic: BTreeMap<String, Value>,
    delay: Duration,
) -> Provider {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback finalized-window listener");
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let state = WindowProviderState {
        finalized,
        requests: Arc::clone(&requests),
        log_requests: Arc::new(AtomicUsize::new(0)),
        logs_by_maker_topic: Arc::new(logs_by_maker_topic),
        delay,
    };
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/", post(window_rpc)).with_state(state),
        )
        .await
        .expect("loopback finalized-window RPC server");
    });
    Provider {
        url,
        requests,
        task,
    }
}

async fn window_providers(
    primary_finalized: Value,
    secondary_finalized: Value,
    primary_logs: BTreeMap<String, Value>,
    secondary_logs: BTreeMap<String, Value>,
    delay: Duration,
) -> ProviderPair {
    let primary = start_window_provider(primary_finalized, primary_logs, delay).await;
    let secondary = start_window_provider(secondary_finalized, secondary_logs, delay).await;
    let verifier = ChainLogVerifier::new(&primary.url, &secondary.url)
        .expect("two loopback finalized-window providers");
    ProviderPair {
        verifier,
        primary,
        secondary,
    }
}

async fn providers(primary: Vec<Value>, secondary: Vec<Value>) -> ProviderPair {
    let primary = start_provider(primary).await;
    let secondary = start_provider(secondary).await;
    let verifier = ChainLogVerifier::new(&primary.url, &secondary.url).expect("two loopback RPCs");
    ProviderPair {
        verifier,
        primary,
        secondary,
    }
}

fn selected_makers() -> Vec<String> {
    vec![MAKER_ONE.to_owned(), MAKER_TWO.to_owned()]
}

fn maker(value: u64) -> String {
    format!("0x{value:040x}")
}

fn maker_topic(maker: &str) -> String {
    format!("0x{}{}", "00".repeat(12), &maker[2..])
}

fn finalized_header(number: u64, parent_hash: &str, timestamp: u64) -> Value {
    let mut header = json!({
        "parentHash": parent_hash,
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "miner": "0x0000000000000000000000000000000000000001",
        "stateRoot": format!("0x{}", "11".repeat(32)),
        "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "logsBloom": format!("0x{}", "00".repeat(256)),
        "difficulty": "0x1",
        "number": format!("0x{number:x}"),
        "gasLimit": "0x100000",
        "gasUsed": "0x5208",
        "timestamp": format!("0x{timestamp:x}"),
        "extraData": "0x",
        "mixHash": format!("0x{}", "22".repeat(32)),
        "nonce": "0x0000000000000000",
        "transactions": [],
    });
    header["hash"] = json!(header_hash(&header));
    header
}

fn header_hash(header: &Value) -> String {
    let bytes = |key: &str| {
        alloy_rlp::encode(
            hex::decode(header[key].as_str().unwrap().trim_start_matches("0x"))
                .unwrap()
                .as_slice(),
        )
    };
    let quantity = |key: &str| {
        let digits = header[key].as_str().unwrap().trim_start_matches("0x");
        let padded = if digits.len() % 2 == 1 {
            format!("0{digits}")
        } else {
            digits.to_owned()
        };
        let mut value = hex::decode(padded).unwrap();
        let first_nonzero = value
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(value.len());
        value.drain(..first_nonzero);
        alloy_rlp::encode(value.as_slice())
    };
    let fields = [
        bytes("parentHash"),
        bytes("sha3Uncles"),
        bytes("miner"),
        bytes("stateRoot"),
        bytes("transactionsRoot"),
        bytes("receiptsRoot"),
        bytes("logsBloom"),
        quantity("difficulty"),
        quantity("number"),
        quantity("gasLimit"),
        quantity("gasUsed"),
        quantity("timestamp"),
        alloy_rlp::encode(&[][..]),
        bytes("mixHash"),
        bytes("nonce"),
    ];
    let mut encoded = Vec::new();
    alloy_rlp::Header {
        list: true,
        payload_length: fields.iter().map(Vec::len).sum(),
    }
    .encode(&mut encoded);
    for field in fields {
        encoded.extend_from_slice(&field);
    }
    format!("0x{}", hex::encode(Keccak256::digest(encoded)))
}

fn event_topic() -> String {
    format!(
        "0x{}",
        hex::encode(Keccak256::digest(
            b"OrderFilled(bytes32,address,address,uint8,uint256,uint256,uint256,uint256,bytes32,bytes32)"
        ))
    )
}

fn address_topic(address: &str) -> String {
    format!("0x{}{}", "00".repeat(12), &address[2..])
}

fn word(value: u128) -> String {
    format!("{value:064x}")
}

fn event_data() -> String {
    format!(
        "0x{}",
        [
            word(0),
            word(1),
            word(1_000),
            word(2_000),
            word(10),
            word(0),
            word(0)
        ]
        .join("")
    )
}

fn event_log(block: u64, log_index: u64, maker: &str, tx_hash: &str) -> Value {
    json!({
        "address": V2_EXCHANGE_ONE,
        "blockNumber": format!("0x{block:x}"),
        "blockHash": BLOCK_HASH,
        "transactionHash": tx_hash,
        "logIndex": format!("0x{log_index:x}"),
        "topics": [
            event_topic(),
            format!("0x{}", "44".repeat(32)),
            address_topic(maker),
            address_topic(COUNTERPARTY),
        ],
        "data": event_data(),
        "removed": false,
    })
}

async fn observe(
    pair: &ProviderPair,
    makers: &[String],
    request_limit: usize,
    response_limit: usize,
) -> Result<SourceAttestedSelectedCtfV2OwnerWatchObservation, BoundedSelectedCtfV2OwnerWatchError> {
    pair.verifier
        .observe_selected_ctf_v2_owner_logs_bounded(
            100,
            101,
            makers,
            &TransactionRequestBudget::new(request_limit),
            response_limit,
            Duration::from_secs(5),
        )
        .await
}

async fn observe_window(
    pair: &ProviderPair,
    from_block: u64,
    makers: &[String],
    request_limit: usize,
    response_limit: usize,
    timeout: Duration,
) -> Result<SelectedCtfV2OwnerWatchWindow, BoundedSelectedCtfV2OwnerWindowError> {
    pair.verifier
        .observe_selected_ctf_v2_owner_window_bounded(
            from_block,
            makers,
            &TransactionRequestBudget::new(request_limit),
            response_limit,
            timeout,
        )
        .await
}

fn log_with_header(block_hash: &str, log_index: u64, maker: &str) -> Value {
    let mut log = event_log(100, log_index, maker, TX_HASH_ONE);
    log["blockHash"] = json!(block_hash);
    log
}

#[tokio::test]
async fn wire_filter_uses_selected_maker_topic2_and_normalizes_provider_order() {
    let first = event_log(100, 2, MAKER_ONE, TX_HASH_ONE);
    let mut second = event_log(101, 1, MAKER_TWO, TX_HASH_TWO);
    second["address"] = json!(V2_EXCHANGE_TWO);
    let mut second_provider_first = second.clone();
    let mut second_provider_second = first.clone();
    second_provider_first["address"] = json!(uppercase_hex_digits(V2_EXCHANGE_TWO));
    second_provider_first["blockHash"] = json!(uppercase_hex_digits(BLOCK_HASH));
    second_provider_second["transactionHash"] = json!(uppercase_hex_digits(TX_HASH_ONE));
    let pair = providers(
        vec![first.clone(), second.clone()],
        vec![second_provider_first, second_provider_second],
    )
    .await;
    let makers = selected_makers();
    let observation = observe(&pair, &makers, 2, 1024 * 1024)
        .await
        .expect("both source responses agree after normalization");

    assert_eq!(pair.request_count(), 2);
    assert_eq!(observation.request_count(), 2);
    assert_eq!(observation.from_block(), 100);
    assert_eq!(observation.through_block(), 101);
    assert!(observation.response_bytes() > 0);
    assert_eq!(observation.logs().len(), 2);
    assert_eq!(observation.logs()[0].maker(), MAKER_ONE);
    assert_eq!(observation.logs()[1].maker(), MAKER_TWO);
    assert_eq!(observation.logs()[0].block_number(), 100);
    assert_eq!(observation.logs()[1].block_number(), 101);
    assert_eq!(
        observation.policy_version(),
        "ctf-v2-selected-maker-two-provider-source-attested-watch/1"
    );

    for provider in [&pair.primary, &pair.secondary] {
        let requests = provider.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["method"], "eth_getLogs");
        let filter = &requests[0]["params"][0];
        assert_eq!(filter["fromBlock"], "0x64");
        assert_eq!(filter["toBlock"], "0x65");
        assert_eq!(filter["address"], json!([V2_EXCHANGE_ONE, V2_EXCHANGE_TWO]));
        assert_eq!(filter["topics"][0], event_topic());
        assert!(filter["topics"][1].is_null());
        assert_eq!(
            filter["topics"][2],
            json!([address_topic(MAKER_ONE), address_topic(MAKER_TWO)])
        );
        assert!(filter["topics"].get(3).is_none());
    }
}

#[tokio::test]
async fn unequal_and_out_of_scope_provider_results_are_refused() {
    let row = event_log(100, 1, MAKER_ONE, TX_HASH_ONE);
    let unequal = providers(vec![row.clone()], vec![]).await;
    assert!(matches!(
        observe(&unequal, &selected_makers(), 2, 1024 * 1024).await,
        Err(BoundedSelectedCtfV2OwnerWatchError::Verification(
            ChainLogAuditError::Divergent
        ))
    ));

    let mut out_of_scope = row;
    out_of_scope["address"] = json!("0xe3333700ca9d93003f00f0f71f8515005f6c00aa");
    let escaped = providers(vec![out_of_scope.clone()], vec![out_of_scope]).await;
    assert!(matches!(
        observe(&escaped, &selected_makers(), 2, 1024 * 1024).await,
        Err(BoundedSelectedCtfV2OwnerWatchError::Verification(
            ChainLogAuditError::Unverified
        ))
    ));

    let mut different_payload = event_log(100, 1, MAKER_ONE, TX_HASH_ONE);
    different_payload["data"] = json!(format!(
        "0x{}",
        [
            word(0),
            word(1),
            word(1_000),
            word(2_000),
            word(11),
            word(0),
            word(0)
        ]
        .join("")
    ));
    let payload_divergence = providers(
        vec![event_log(100, 1, MAKER_ONE, TX_HASH_ONE)],
        vec![different_payload],
    )
    .await;
    assert!(matches!(
        observe(&payload_divergence, &selected_makers(), 2, 1024 * 1024).await,
        Err(BoundedSelectedCtfV2OwnerWatchError::Verification(
            ChainLogAuditError::Divergent
        ))
    ));
}

#[tokio::test]
async fn empty_equal_results_are_a_bounded_source_observation_only() {
    let pair = providers(vec![], vec![]).await;
    let observation = observe(&pair, &selected_makers(), 2, 1024 * 1024)
        .await
        .expect("empty provider result agreement");
    assert!(observation.logs().is_empty());
    assert_eq!(observation.request_count(), 2);
    assert!(observation.response_bytes() > 0);
}

#[tokio::test]
async fn removed_off_range_and_malformed_logs_are_refused() {
    let valid = event_log(100, 1, MAKER_ONE, TX_HASH_ONE);
    let mutations: [fn(&mut Value); 4] = [
        |row: &mut Value| row["removed"] = json!(true),
        |row: &mut Value| row["blockNumber"] = json!("0x66"),
        |row: &mut Value| row["topics"] = json!([event_topic()]),
        |row: &mut Value| {
            row["topics"].as_array_mut().unwrap().push(json!(
                "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            ));
        },
    ];
    for mutate in mutations {
        let mut invalid = valid.clone();
        mutate(&mut invalid);
        let pair = providers(vec![invalid.clone()], vec![invalid]).await;
        assert!(matches!(
            observe(&pair, &selected_makers(), 2, 1024 * 1024).await,
            Err(BoundedSelectedCtfV2OwnerWatchError::Verification(
                ChainLogAuditError::Unverified
            ))
        ));
    }
}

#[tokio::test]
async fn response_byte_and_actual_send_budgets_are_enforced() {
    let row = event_log(100, 1, MAKER_ONE, TX_HASH_ONE);
    let response_limited = providers(vec![row.clone()], vec![row.clone()]).await;
    assert!(matches!(
        observe(&response_limited, &selected_makers(), 2, 1).await,
        Err(BoundedSelectedCtfV2OwnerWatchError::Verification(_))
    ));
    assert!(response_limited.request_count() > 0);
    assert!(response_limited.request_count() <= 2);

    let send_limited = providers(vec![row.clone()], vec![row]).await;
    assert!(matches!(
        observe(&send_limited, &selected_makers(), 1, 1024 * 1024).await,
        Err(BoundedSelectedCtfV2OwnerWatchError::RequestBudgetExceeded)
    ));
    assert!(send_limited.request_count() <= 1);
}

#[tokio::test]
async fn invalid_ranges_and_noncanonical_or_duplicate_makers_fail_before_rpc() {
    let pair = providers(vec![], vec![]).await;
    let budget = TransactionRequestBudget::new(2);
    for (from_block, through_block, makers) in [
        (0, 1, selected_makers()),
        (102, 101, selected_makers()),
        (100, 116, selected_makers()),
        (100, 101, vec![]),
        (100, 101, vec![MAKER_ONE.to_owned(), MAKER_ONE.to_owned()]),
        (
            100,
            101,
            vec!["0x111111111111111111111111111111111111111A".to_owned()],
        ),
    ] {
        assert!(matches!(
            pair.verifier
                .observe_selected_ctf_v2_owner_logs_bounded(
                    from_block,
                    through_block,
                    &makers,
                    &budget,
                    1024 * 1024,
                    Duration::from_secs(5),
                )
                .await,
            Err(BoundedSelectedCtfV2OwnerWatchError::Verification(
                ChainLogAuditError::InvalidInput
            ))
        ));
    }

    let too_many_makers = (1_u64..=100)
        .map(|value| format!("0x{value:040x}"))
        .collect::<Vec<_>>();
    assert!(matches!(
        pair.verifier
            .observe_selected_ctf_v2_owner_logs_bounded(
                100,
                101,
                &too_many_makers,
                &budget,
                1024 * 1024,
                Duration::from_secs(5),
            )
            .await,
        Err(BoundedSelectedCtfV2OwnerWatchError::Verification(
            ChainLogAuditError::InvalidInput
        ))
    ));
    assert_eq!(pair.request_count(), 0);
}

#[tokio::test]
async fn total_deadline_cancels_inflight_provider_queries() {
    let primary = start_provider_with_delay(vec![], Duration::from_secs(30)).await;
    let secondary = start_provider_with_delay(vec![], Duration::from_secs(30)).await;
    let verifier = ChainLogVerifier::new(&primary.url, &secondary.url).unwrap();
    let budget = TransactionRequestBudget::new(2);
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        verifier.observe_selected_ctf_v2_owner_logs_bounded(
            100,
            101,
            &selected_makers(),
            &budget,
            1024 * 1024,
            Duration::from_millis(100),
        ),
    )
    .await
    .expect("whole watch deadline bounds slow providers");
    assert_eq!(result, Err(BoundedSelectedCtfV2OwnerWatchError::Timeout));
    assert!(!budget.is_exhausted());
}

#[tokio::test]
async fn finalized_window_partitions_full_1024_maker_cohort_by_actual_wire_size() {
    let makers = (1..=1_024).map(maker).collect::<Vec<_>>();
    let header = finalized_header(100, &format!("0x{}", "33".repeat(32)), 1_000);
    let matching_rows = BTreeMap::from([
        (
            maker_topic(&makers[0]),
            log_with_header(header["hash"].as_str().unwrap(), 2, &makers[0]),
        ),
        (
            maker_topic(makers.last().unwrap()),
            log_with_header(header["hash"].as_str().unwrap(), 9, makers.last().unwrap()),
        ),
    ]);
    let pair = window_providers(
        header.clone(),
        header.clone(),
        matching_rows.clone(),
        matching_rows,
        Duration::ZERO,
    )
    .await;
    let observation = observe_window(
        &pair,
        100,
        &makers,
        128,
        8 * 1024 * 1024,
        Duration::from_secs(5),
    )
    .await
    .expect("bounded partitions cover all declared makers");
    let SelectedCtfV2OwnerWatchWindow::SourceAttested(observation) = observation else {
        panic!("a finalized starting block yields a source-attested window");
    };
    assert_eq!(observation.from_block(), 100);
    assert_eq!(observation.through_block(), 100);
    assert_eq!(observation.primary_finalized().block_number(), 100);
    assert_eq!(observation.secondary_finalized().block_number(), 100);
    assert_eq!(
        observation.primary_finalized().block_hash(),
        observation.secondary_finalized().block_hash()
    );
    assert_eq!(observation.cohort().selected_makers().len(), 1_024);
    assert_eq!(observation.cohort().selected_makers(), makers.as_slice());
    assert!(observation.cohort().sha256().starts_with("sha256:"));
    assert!(observation.partition_count() > 1);
    assert_eq!(
        observation.request_count(),
        2 + observation.partition_count() * 2
    );
    assert!(observation.response_bytes() > 0);
    assert_eq!(observation.logs().len(), 2);
    assert_eq!(observation.logs()[0].maker(), makers.first().unwrap());
    assert_eq!(observation.logs()[1].maker(), makers.last().unwrap());
    assert_eq!(
        observation.policy_version(),
        "ctf-v2-selected-maker-finalized-watch-window/1"
    );

    let requests = pair.primary.requests.lock().unwrap();
    let filters = requests
        .iter()
        .filter(|request| request["method"] == "eth_getLogs")
        .collect::<Vec<_>>();
    assert_eq!(filters.len(), observation.partition_count());
    let mut observed_topics = BTreeSet::new();
    for request in filters {
        let body = serde_json::to_vec(request).unwrap();
        assert!(
            body.len() <= 4_096,
            "serialized filter stays within RPC cap"
        );
        let filter = &request["params"][0];
        assert_eq!(filter["fromBlock"], "0x64");
        assert_eq!(filter["toBlock"], "0x64");
        assert_eq!(filter["address"], json!([V2_EXCHANGE_ONE, V2_EXCHANGE_TWO]));
        assert_eq!(filter["topics"][0], event_topic());
        assert!(filter["topics"][1].is_null());
        for topic in filter["topics"][2].as_array().unwrap() {
            observed_topics.insert(topic.as_str().unwrap().to_owned());
        }
    }
    let expected_topics = makers
        .iter()
        .map(|maker| maker_topic(maker))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        observed_topics, expected_topics,
        "partitions have no holes or duplicates"
    );
    drop(requests);
    assert_eq!(
        pair.request_count(),
        observation.request_count(),
        "two finalized-head reads plus two provider reads for every partition"
    );
}

#[tokio::test]
async fn finalized_window_waits_without_logs_and_rejects_same_height_forks() {
    let makers = selected_makers();
    let parent = format!("0x{}", "33".repeat(32));
    let primary_head = finalized_header(100, &parent, 1_000);
    let lagging_head = finalized_header(99, &parent, 999);
    let waiting = window_providers(
        primary_head.clone(),
        lagging_head,
        BTreeMap::new(),
        BTreeMap::new(),
        Duration::ZERO,
    )
    .await;
    let result = observe_window(
        &waiting,
        100,
        &makers,
        8,
        1024 * 1024,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let SelectedCtfV2OwnerWatchWindow::Waiting(waiting_observation) = result else {
        panic!("a lagging common finalized height must wait");
    };
    assert_eq!(waiting_observation.from_block(), 100);
    assert_eq!(waiting_observation.request_count(), 2);
    assert!(waiting_observation.response_bytes() > 0);
    assert_eq!(waiting.request_count(), 2);
    assert!(
        waiting
            .primary
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request["method"] == "eth_getBlockByNumber")
    );

    let same_height_other_hash = finalized_header(100, &parent, 1_001);
    let fork = window_providers(
        primary_head,
        same_height_other_hash,
        BTreeMap::new(),
        BTreeMap::new(),
        Duration::ZERO,
    )
    .await;
    assert_eq!(
        observe_window(&fork, 100, &makers, 8, 1024 * 1024, Duration::from_secs(5)).await,
        Err(BoundedSelectedCtfV2OwnerWindowError::FinalizedFork)
    );
    assert_eq!(fork.request_count(), 2);
}

#[tokio::test]
async fn finalized_window_rejects_overflowing_start_before_rpc() {
    let header = finalized_header(100, &format!("0x{}", "33".repeat(32)), 1_000);
    let pair = window_providers(
        header.clone(),
        header,
        BTreeMap::new(),
        BTreeMap::new(),
        Duration::ZERO,
    )
    .await;

    assert_eq!(
        observe_window(
            &pair,
            u64::MAX - 14,
            &selected_makers(),
            8,
            1024 * 1024,
            Duration::from_secs(5),
        )
        .await,
        Err(BoundedSelectedCtfV2OwnerWindowError::Verification(
            ChainLogAuditError::InvalidInput
        ))
    );
    assert_eq!(pair.request_count(), 0);

    let boundary = observe_window(
        &pair,
        u64::MAX - 15,
        &selected_makers(),
        8,
        1024 * 1024,
        Duration::from_secs(5),
    )
    .await
    .expect("the highest valid 16-block start remains representable");
    let SelectedCtfV2OwnerWatchWindow::Waiting(boundary) = boundary else {
        panic!("the lower finalized head leaves the boundary window waiting");
    };
    assert_eq!(boundary.from_block(), u64::MAX - 15);
    assert_eq!(pair.request_count(), 2);
}

#[tokio::test]
async fn finalized_window_budgets_headers_and_all_partitions_under_one_deadline() {
    let makers = (1..=1_024).map(maker).collect::<Vec<_>>();
    let parent = format!("0x{}", "33".repeat(32));
    let header = finalized_header(100, &parent, 1_000);
    let head_probe = window_providers(
        header.clone(),
        header.clone(),
        BTreeMap::new(),
        BTreeMap::new(),
        Duration::ZERO,
    )
    .await;
    let waiting = observe_window(
        &head_probe,
        101,
        &makers,
        2,
        1024 * 1024,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let SelectedCtfV2OwnerWatchWindow::Waiting(waiting) = waiting else {
        panic!("head-only probe waits at the next block");
    };
    let header_bytes = waiting.response_bytes();

    let byte_limited = window_providers(
        header.clone(),
        header.clone(),
        BTreeMap::new(),
        BTreeMap::new(),
        Duration::ZERO,
    )
    .await;
    assert!(matches!(
        observe_window(
            &byte_limited,
            100,
            &makers[..1],
            4,
            header_bytes + 1,
            Duration::from_secs(5),
        )
        .await,
        Err(BoundedSelectedCtfV2OwnerWindowError::Verification(_))
    ));
    assert_eq!(byte_limited.request_count(), 4);

    let request_limited = window_providers(
        header.clone(),
        header.clone(),
        BTreeMap::new(),
        BTreeMap::new(),
        Duration::ZERO,
    )
    .await;
    assert_eq!(
        observe_window(
            &request_limited,
            100,
            &makers,
            2,
            8 * 1024 * 1024,
            Duration::from_secs(5)
        )
        .await,
        Err(BoundedSelectedCtfV2OwnerWindowError::RequestBudgetExceeded)
    );
    assert_eq!(
        request_limited.request_count(),
        2,
        "no partition sends after preflight fails"
    );

    let timed = window_providers(
        header.clone(),
        header,
        BTreeMap::new(),
        BTreeMap::new(),
        Duration::from_millis(25),
    )
    .await;
    assert_eq!(
        observe_window(
            &timed,
            100,
            &makers,
            128,
            8 * 1024 * 1024,
            Duration::from_millis(40),
        )
        .await,
        Err(BoundedSelectedCtfV2OwnerWindowError::Timeout)
    );
    assert!(
        timed.request_count() >= 2,
        "deadline includes actual head reads"
    );
}

#[tokio::test]
async fn finalized_window_refuses_duplicate_cross_partition_identity_and_late_divergence() {
    let makers = (1..=1_024).map(maker).collect::<Vec<_>>();
    let first = makers.first().unwrap();
    let last = makers.last().unwrap();
    let header = finalized_header(100, &format!("0x{}", "33".repeat(32)), 1_000);
    let duplicate_rows = BTreeMap::from([
        (
            maker_topic(first),
            log_with_header(header["hash"].as_str().unwrap(), 7, first),
        ),
        (
            maker_topic(last),
            log_with_header(header["hash"].as_str().unwrap(), 7, last),
        ),
    ]);
    let duplicate = window_providers(
        header.clone(),
        header.clone(),
        duplicate_rows.clone(),
        duplicate_rows,
        Duration::ZERO,
    )
    .await;
    assert_eq!(
        observe_window(
            &duplicate,
            100,
            &makers,
            128,
            8 * 1024 * 1024,
            Duration::from_secs(5)
        )
        .await,
        Err(BoundedSelectedCtfV2OwnerWindowError::Verification(
            ChainLogAuditError::Unverified
        ))
    );

    let late_row = log_with_header(header["hash"].as_str().unwrap(), 8, last);
    let divergent = window_providers(
        header.clone(),
        header,
        BTreeMap::from([(maker_topic(last), late_row)]),
        BTreeMap::new(),
        Duration::ZERO,
    )
    .await;
    assert_eq!(
        observe_window(
            &divergent,
            100,
            &makers,
            128,
            8 * 1024 * 1024,
            Duration::from_secs(5)
        )
        .await,
        Err(BoundedSelectedCtfV2OwnerWindowError::Verification(
            ChainLogAuditError::Divergent
        ))
    );
    let log_calls = divergent
        .primary
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|request| request["method"] == "eth_getLogs")
        .count();
    assert!(
        log_calls > 1,
        "the divergence is only returned by a later partition"
    );
}
