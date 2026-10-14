use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{Json, Router, extract::State, routing::post};
use polymarket_data::chain_log_audit::{
    BoundedSelectedCtfV2OwnerWatchError, ChainLogAuditError, ChainLogVerifier,
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
