use super::*;
use axum::{body::Body, response::Response};

mod rpc_http_timeout_tests {
    include!("rpc_http_timeout_tests.rs");
}

async fn receipt_transcript_rpc(
    State(fixture): State<CtfInventoryFixture>,
    Json(request): Json<Value>,
) -> Json<Value> {
    if request["method"] == "eth_getTransactionReceipt" {
        let (_, header, _) = ctf_inventory_headers(&fixture);
        let transaction_hash = format!(
            "{:#x}",
            encode_signed_transaction(&fixture.rooted_gas_block.as_ref().unwrap().transactions[0])
                .unwrap()
                .hash
        );
        return Json(json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {
                "transactionHash": transaction_hash,
                "blockNumber": "0x64",
                "blockHash": header["hash"],
                "transactionIndex": "0x0",
                "status": "0x1"
            }
        }));
    }
    ctf_inventory_rpc(State(fixture), Json(request)).await
}

async fn receipt_transcript_provider(fixture: CtfInventoryFixture) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/", post(receipt_transcript_rpc))
                .with_state(fixture),
        )
        .await
        .unwrap();
    });
    url
}

async fn chunked_aggregate_cap_rpc(
    State(fixture): State<CtfInventoryFixture>,
    Json(request): Json<Value>,
) -> Response {
    if request["method"] == "eth_chainId" {
        let body = json!({
            "jsonrpc":"2.0", "id":request["id"], "result":"0x89",
            "padding":"x".repeat(256)
        })
        .to_string();
        let chunks = body
            .as_bytes()
            .chunks(17)
            .map(|chunk| Ok::<_, std::io::Error>(axum::body::Bytes::copy_from_slice(chunk)))
            .collect::<Vec<_>>();
        return Response::builder()
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(Body::from_stream(futures_util::stream::iter(chunks)))
            .unwrap();
    }
    let Json(response) = ctf_inventory_rpc(State(fixture), Json(request)).await;
    Response::builder()
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(Body::from(response.to_string()))
        .unwrap()
}

async fn late_failure_rpc(
    State((fixture, fail_late)): State<(CtfInventoryFixture, bool)>,
    Json(request): Json<Value>,
) -> Json<Value> {
    let is_late_full_block = request["method"] == "eth_getBlockByNumber"
        && request["params"]
            .as_array()
            .is_some_and(|params| params.get(1) == Some(&json!(true)));
    let mut response = ctf_inventory_rpc(State(fixture), Json(request)).await.0;
    if fail_late && is_late_full_block {
        response["result"]["receiptsRoot"] = json!(format!("0x{}", "cc".repeat(32)));
    }
    Json(response)
}

async fn chunked_aggregate_cap_provider(fixture: CtfInventoryFixture) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/", post(chunked_aggregate_cap_rpc))
                .with_state(fixture),
        )
        .await
        .unwrap();
    });
    url
}

async fn late_failure_provider(fixture: CtfInventoryFixture, fail_late: bool) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/", post(late_failure_rpc))
                .with_state((fixture, fail_late)),
        )
        .await
        .unwrap();
    });
    url
}

#[derive(Clone)]
struct HashLookupRpcState {
    fixture: CtfInventoryFixture,
    requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    refuse_hash: bool,
}

async fn hash_lookup_rpc(
    State(state): State<HashLookupRpcState>,
    Json(request): Json<Value>,
) -> Json<Value> {
    if request["method"] == "eth_getBlockByHash" {
        state
            .requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let result = if state.refuse_hash {
            Value::Null
        } else {
            let (opening, header, _) = ctf_inventory_headers(&state.fixture);
            let full =
                ctf_inventory_header(100, opening["hash"].as_str().unwrap(), &state.fixture, true);
            if request["params"][0] == header["hash"] {
                full
            } else {
                Value::Null
            }
        };
        return Json(json!({"jsonrpc":"2.0", "id":request["id"], "result":result}));
    }
    receipt_transcript_rpc(State(state.fixture), Json(request)).await
}

async fn hash_lookup_provider(
    fixture: CtfInventoryFixture,
    requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    refuse_hash: bool,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/", post(hash_lookup_rpc))
                .with_state(HashLookupRpcState {
                    fixture,
                    requests,
                    refuse_hash,
                }),
        )
        .await
        .unwrap();
    });
    url
}

fn receipt_transcript_fixture() -> (CtfInventoryFixture, String) {
    let (transaction, _) = signed_polygon_native_gas_transaction(
        0,
        0x47,
        0,
        21_000,
        U256::ZERO,
        U256::ZERO,
        U256::ZERO,
    );
    let transaction_hash = format!(
        "{:#x}",
        encode_signed_transaction(&transaction).unwrap().hash
    );
    let mut fixture = ctf_inventory_fixture(U256::ZERO, 0);
    fixture.rooted_gas_block = Some(RootedGasBlockFixture {
        transactions: vec![transaction],
        receipt_logs: vec![Vec::new()],
        receipt_statuses: vec![1],
        cumulative_gas_used: vec![21_000],
        receipt_types: vec![0],
        gas_limit: 1_000_000,
        base_fee_per_gas: U256::ZERO,
        header_gas_used_override: None,
        tamper_header_gas_used: false,
        tamper_cumulative_index: None,
    });
    (fixture, transaction_hash)
}

fn replay_transcript(value: Value) -> RecordedChainTransactionReceiptRpcTranscript {
    serde_json::from_value(value).unwrap()
}

fn page_for_method(value: &Value, method: &str) -> usize {
    value["pages"]
        .as_array()
        .unwrap()
        .iter()
        .position(|page| {
            serde_json::from_str::<Value>(page["request_json"].as_str().unwrap()).unwrap()["method"]
                == method
        })
        .unwrap()
}

fn mutate_response(value: &mut Value, method: &str, mutate: impl FnOnce(&mut Value)) {
    let index = page_for_method(value, method);
    let raw = value["pages"][index]["response_json"].as_str().unwrap();
    let mut response: Value = serde_json::from_str(raw).unwrap();
    mutate(&mut response);
    value["pages"][index]["response_json"] = json!(response.to_string());
}

#[tokio::test]
async fn captured_receipt_replays_offline_with_identical_rooted_content() {
    let (fixture, transaction_hash) = receipt_transcript_fixture();
    let primary = receipt_transcript_provider(fixture.clone()).await;
    let secondary = receipt_transcript_provider(fixture.clone()).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    let budget = TransactionRequestBudget::new(16);
    let captured = verifier
        .capture_transaction_receipt_observation_bounded(
            &transaction_hash,
            &budget,
            MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

    assert!(captured.transcript().request_count() > 0);
    assert_eq!(
        captured.transcript().request_count(),
        MAX_RECORDED_RECEIPT_REQUESTS
    );
    assert_eq!(
        budget.reserved_requests(),
        captured.transcript().request_count()
    );
    assert_eq!(
        fixture
            .full_block_requests
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );
    assert_eq!(
        captured.transcript().policy_version(),
        RECORDED_RECEIPT_REVERIFICATION_POLICY_VERSION
    );
    let replayed = reverify_recorded_transaction_receipt_observation_bounded(
        &transaction_hash,
        captured.transcript(),
        MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
        Duration::from_secs(30),
    )
    .await
    .unwrap();
    let live = captured.evidence();
    assert_eq!(replayed.chain_id(), live.chain_id());
    assert_eq!(replayed.transaction_hash(), live.transaction_hash());
    assert_eq!(replayed.block_number(), live.block_number());
    assert_eq!(replayed.block_hash(), live.block_hash());
    assert_eq!(replayed.block_timestamp(), live.block_timestamp());
    assert_eq!(replayed.transaction_index(), live.transaction_index());
    assert_eq!(replayed.receipt_status(), live.receipt_status());
    assert_eq!(replayed.receipt_evidence(), live.receipt_evidence());
    assert_eq!(replayed.transactions_root(), live.transactions_root());
    assert_eq!(replayed.receipt_logs(), live.receipt_logs());
    assert_eq!(
        replayed.movement_observations(),
        live.movement_observations()
    );
    assert_eq!(
        replayed.reverified_policy_version(),
        RECORDED_RECEIPT_REVERIFICATION_POLICY_VERSION
    );
}

#[tokio::test]
async fn recorded_receipt_replay_rejects_frame_mutations_and_bounds() {
    let (fixture, transaction_hash) = receipt_transcript_fixture();
    let primary = receipt_transcript_provider(fixture.clone()).await;
    let secondary = receipt_transcript_provider(fixture).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    let captured = verifier
        .capture_transaction_receipt_observation_bounded(
            &transaction_hash,
            &TransactionRequestBudget::new(16),
            MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let captured_value = serde_json::to_value(captured.transcript()).unwrap();

    let mut missing = captured_value.clone();
    missing["pages"].as_array_mut().unwrap().pop();
    let missing = replay_transcript(missing);
    assert!(
        reverify_recorded_transaction_receipt_observation_bounded(
            &transaction_hash,
            &missing,
            MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
            Duration::from_secs(30),
        )
        .await
        .is_err()
    );

    let mut wrong_request = captured_value.clone();
    let request = wrong_request["pages"][0]["request_json"].as_str().unwrap();
    wrong_request["pages"][0]["request_json"] = json!(request.replace("\"id\":1", "\"id\":2"));
    let wrong_request = replay_transcript(wrong_request);
    assert!(
        reverify_recorded_transaction_receipt_observation_bounded(
            &transaction_hash,
            &wrong_request,
            MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
            Duration::from_secs(30),
        )
        .await
        .is_err()
    );

    let transcript = captured.transcript();
    assert!(
        reverify_recorded_transaction_receipt_observation_bounded(
            &transaction_hash,
            transcript,
            transcript.response_bytes().saturating_sub(1),
            Duration::from_secs(30),
        )
        .await
        .is_err()
    );
    assert!(matches!(
        verifier
            .capture_transaction_receipt_observation_bounded(
                &transaction_hash,
                &TransactionRequestBudget::new(1),
                MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
                Duration::from_secs(30),
            )
            .await,
        Err(BoundedRecordedReceiptVerificationError::RequestBudgetExceeded)
    ));
    assert!(matches!(
        verifier
            .capture_transaction_receipt_observation_bounded(
                &transaction_hash,
                &TransactionRequestBudget::new(MAX_RECORDED_RECEIPT_REQUESTS - 1),
                MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
                Duration::from_secs(30),
            )
            .await,
        Err(BoundedRecordedReceiptVerificationError::RequestBudgetExceeded)
    ));
}

#[tokio::test]
async fn recorded_receipt_replay_rejects_source_order_envelope_header_and_signed_tx_mutations() {
    let (fixture, transaction_hash) = receipt_transcript_fixture();
    let primary = receipt_transcript_provider(fixture.clone()).await;
    let secondary = receipt_transcript_provider(fixture).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    let captured = verifier
        .capture_transaction_receipt_observation_bounded(
            &transaction_hash,
            &TransactionRequestBudget::new(16),
            MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let original = serde_json::to_value(captured.transcript()).unwrap();
    let pages = original["pages"].as_array().unwrap();
    let mut mutations = Vec::new();

    let first_source = pages[0]["source"].clone();
    let mut wrong_source = original.clone();
    wrong_source["pages"][0]["source"] = if first_source == "primary" {
        json!("secondary")
    } else {
        json!("primary")
    };
    mutations.push(wrong_source);

    let mut extra_call = original.clone();
    let duplicate = extra_call["pages"][0].clone();
    extra_call["pages"].as_array_mut().unwrap().push(duplicate);
    mutations.push(extra_call);

    let mut same_source_order = original.clone();
    let pages = same_source_order["pages"].as_array_mut().unwrap();
    let first_role = pages[0]["source"].clone();
    let indices = pages
        .iter()
        .enumerate()
        .filter_map(|(index, page)| (page["source"] == first_role).then_some(index))
        .take(2)
        .collect::<Vec<_>>();
    assert_eq!(indices.len(), 2);
    pages.swap(indices[0], indices[1]);
    mutations.push(same_source_order);

    let request_index = page_for_method(&original, "eth_getBlockByNumber");
    let mut wrong_method = original.clone();
    let request = wrong_method["pages"][request_index]["request_json"]
        .as_str()
        .unwrap();
    let mut request: Value = serde_json::from_str(request).unwrap();
    request["method"] = json!("eth_getBlockByHash");
    wrong_method["pages"][request_index]["request_json"] = json!(request.to_string());
    mutations.push(wrong_method);

    let mut wrong_params = original.clone();
    let request = wrong_params["pages"][request_index]["request_json"]
        .as_str()
        .unwrap();
    let mut request: Value = serde_json::from_str(request).unwrap();
    request["params"] = json!(["0xdead", false]);
    wrong_params["pages"][request_index]["request_json"] = json!(request.to_string());
    mutations.push(wrong_params);

    let mut bad_response_id = original.clone();
    mutate_response(&mut bad_response_id, "eth_chainId", |response| {
        response["id"] = json!(2);
    });
    mutations.push(bad_response_id);

    let mut bad_jsonrpc = original.clone();
    mutate_response(&mut bad_jsonrpc, "eth_chainId", |response| {
        response["jsonrpc"] = json!("1.0");
    });
    mutations.push(bad_jsonrpc);

    let mut rpc_error = original.clone();
    mutate_response(&mut rpc_error, "eth_chainId", |response| {
        response["error"] = json!({"code": -32000, "message": "unavailable"});
    });
    mutations.push(rpc_error);

    let mut altered_receipt_root = original.clone();
    mutate_response(
        &mut altered_receipt_root,
        "eth_getBlockByNumber",
        |response| response["result"]["receiptsRoot"] = json!(format!("0x{}", "aa".repeat(32))),
    );
    mutations.push(altered_receipt_root);

    let mut altered_transactions_root = original.clone();
    mutate_response(
        &mut altered_transactions_root,
        "eth_getBlockByNumber",
        |response| {
            response["result"]["transactionsRoot"] = json!(format!("0x{}", "bb".repeat(32)));
        },
    );
    mutations.push(altered_transactions_root);

    let mut altered_receipt_body = original.clone();
    mutate_response(
        &mut altered_receipt_body,
        "eth_getBlockReceipts",
        |response| response["result"][0]["cumulativeGasUsed"] = json!("0x5209"),
    );
    mutations.push(altered_receipt_body);

    let mut altered_signed_transaction = original;
    let signed_block_index = altered_signed_transaction["pages"]
        .as_array()
        .unwrap()
        .iter()
        .position(|page| {
            let response: Value =
                serde_json::from_str(page["response_json"].as_str().unwrap()).unwrap();
            response["result"]["transactions"]
                .as_array()
                .and_then(|transactions| transactions.first())
                .is_some_and(Value::is_object)
        })
        .unwrap();
    let response = altered_signed_transaction["pages"][signed_block_index]["response_json"]
        .as_str()
        .unwrap();
    let mut response: Value = serde_json::from_str(response).unwrap();
    response["result"]["transactions"][0]["r"] = json!("0x01");
    altered_signed_transaction["pages"][signed_block_index]["response_json"] =
        json!(response.to_string());
    mutations.push(altered_signed_transaction);

    for (index, mutation) in mutations.into_iter().enumerate() {
        let transcript = replay_transcript(mutation);
        assert!(
            reverify_recorded_transaction_receipt_observation_bounded(
                &transaction_hash,
                &transcript,
                MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
                Duration::from_secs(30),
            )
            .await
            .is_err(),
            "accepted transcript mutation {index}"
        );
    }
}

#[tokio::test]
async fn capture_enforces_declared_and_streamed_aggregate_caps_and_returns_no_partial_result() {
    let (fixture, transaction_hash) = receipt_transcript_fixture();
    let primary = receipt_transcript_provider(fixture.clone()).await;
    let secondary = receipt_transcript_provider(fixture).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    let declared = verifier
        .capture_transaction_receipt_observation_bounded(
            &transaction_hash,
            &TransactionRequestBudget::new(16),
            1,
            Duration::from_secs(30),
        )
        .await;
    assert!(declared.is_err());

    let (fixture, transaction_hash) = receipt_transcript_fixture();
    let primary = chunked_aggregate_cap_provider(fixture.clone()).await;
    let secondary = chunked_aggregate_cap_provider(fixture).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    let chunked = verifier
        .capture_transaction_receipt_observation_bounded(
            &transaction_hash,
            &TransactionRequestBudget::new(16),
            32,
            Duration::from_secs(30),
        )
        .await;
    assert!(chunked.is_err());
}

#[tokio::test]
async fn capture_deadline_cancellation_and_late_validation_failure_return_no_success() {
    let (mut fixture, transaction_hash) = receipt_transcript_fixture();
    fixture.delay_ms = 50;
    let primary = receipt_transcript_provider(fixture.clone()).await;
    let secondary = receipt_transcript_provider(fixture).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    assert!(matches!(
        verifier
            .capture_transaction_receipt_observation_bounded(
                &transaction_hash,
                &TransactionRequestBudget::new(16),
                MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
                Duration::from_millis(5),
            )
            .await,
        Err(BoundedRecordedReceiptVerificationError::Timeout)
    ));

    let capture_primary = primary.clone();
    let capture_secondary = secondary.clone();
    let capture_hash = transaction_hash.clone();
    let cancelled = tokio::spawn(async move {
        let capture_verifier = ChainLogVerifier::new(&capture_primary, &capture_secondary).unwrap();
        capture_verifier
            .capture_transaction_receipt_observation_bounded(
                &capture_hash,
                &TransactionRequestBudget::new(16),
                MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
                Duration::from_secs(30),
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(5)).await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());

    let (fixture, transaction_hash) = receipt_transcript_fixture();
    let primary = late_failure_provider(fixture.clone(), true).await;
    let secondary = late_failure_provider(fixture, false).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    let late_failure = verifier
        .capture_transaction_receipt_observation_bounded(
            &transaction_hash,
            &TransactionRequestBudget::new(16),
            MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
            Duration::from_secs(30),
        )
        .await;
    assert!(late_failure.is_err());
}

#[tokio::test]
async fn explicit_hash_lookup_captures_sixteen_sends_and_replays_same_content() {
    let (fixture, transaction_hash) = receipt_transcript_fixture();
    let primary_requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let secondary_requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let primary = hash_lookup_provider(fixture.clone(), primary_requests.clone(), false).await;
    let secondary = hash_lookup_provider(fixture.clone(), secondary_requests.clone(), false).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .with_full_block_hash_lookup();
    let budget = TransactionRequestBudget::new(MAX_RECORDED_RECEIPT_REQUESTS);
    let captured = verifier
        .capture_transaction_receipt_observation_bounded(
            &transaction_hash,
            &budget,
            MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

    let full_block_requests = captured
        .transcript()
        .pages()
        .iter()
        .filter(|page| {
            serde_json::from_str::<Value>(page.request_json()).unwrap()["method"]
                == "eth_getBlockByHash"
        })
        .count();
    assert_eq!(captured.transcript().request_count(), 16);
    assert_eq!(budget.reserved_requests(), 16);
    assert_eq!(
        primary_requests.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(
        secondary_requests.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(full_block_requests, 2);
    assert_eq!(
        fixture
            .full_block_requests
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );

    let replayed = reverify_recorded_transaction_receipt_observation_bounded(
        &transaction_hash,
        captured.transcript(),
        MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
        Duration::from_secs(30),
    )
    .await
    .unwrap();
    assert_eq!(replayed.chain_id(), captured.evidence().chain_id());
    assert_eq!(
        replayed.transaction_hash(),
        captured.evidence().transaction_hash()
    );
    assert_eq!(replayed.block_hash(), captured.evidence().block_hash());
    assert_eq!(
        replayed.receipt_evidence(),
        captured.evidence().receipt_evidence()
    );
    assert_eq!(
        replayed.transactions_root(),
        captured.evidence().transactions_root()
    );
    assert_eq!(replayed.receipt_logs(), captured.evidence().receipt_logs());
    assert_eq!(
        replayed.movement_observations(),
        captured.evidence().movement_observations()
    );
    assert_eq!(
        replayed.reverified_policy_version(),
        RECORDED_RECEIPT_REVERIFICATION_POLICY_VERSION
    );
}

#[tokio::test]
async fn hash_lookup_refusal_does_not_fall_back_to_block_number() {
    let (fixture, transaction_hash) = receipt_transcript_fixture();
    let hash_requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let primary = hash_lookup_provider(fixture.clone(), hash_requests.clone(), true).await;
    let secondary = hash_lookup_provider(fixture.clone(), hash_requests.clone(), true).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .with_full_block_hash_lookup();

    assert!(
        verifier
            .capture_transaction_receipt_observation_bounded(
                &transaction_hash,
                &TransactionRequestBudget::new(MAX_RECORDED_RECEIPT_REQUESTS),
                MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
                Duration::from_secs(30),
            )
            .await
            .is_err()
    );
    assert_eq!(hash_requests.load(std::sync::atomic::Ordering::Relaxed), 2);
    assert_eq!(
        fixture
            .full_block_requests
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn hash_lookup_replay_rejects_wrong_context_and_rooted_content_mutations() {
    let (fixture, transaction_hash) = receipt_transcript_fixture();
    let primary = hash_lookup_provider(
        fixture.clone(),
        std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        false,
    )
    .await;
    let secondary = hash_lookup_provider(
        fixture,
        std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        false,
    )
    .await;
    let verifier = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .with_full_block_hash_lookup();
    let captured = verifier
        .capture_transaction_receipt_observation_bounded(
            &transaction_hash,
            &TransactionRequestBudget::new(MAX_RECORDED_RECEIPT_REQUESTS),
            MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let original = serde_json::to_value(captured.transcript()).unwrap();
    let hash_page = page_for_method(&original, "eth_getBlockByHash");
    let mut mutations = Vec::new();

    let mut wrong_requested_hash = original.clone();
    let request = wrong_requested_hash["pages"][hash_page]["request_json"]
        .as_str()
        .unwrap();
    let mut request: Value = serde_json::from_str(request).unwrap();
    request["params"][0] = json!(format!("0x{}", "dd".repeat(32)));
    wrong_requested_hash["pages"][hash_page]["request_json"] = json!(request.to_string());
    mutations.push(wrong_requested_hash);

    let mut inconsistent_modes = original.clone();
    let request = inconsistent_modes["pages"][hash_page]["request_json"]
        .as_str()
        .unwrap();
    let mut request: Value = serde_json::from_str(request).unwrap();
    request["method"] = json!("eth_getBlockByNumber");
    request["params"] = json!(["0x64", true]);
    inconsistent_modes["pages"][hash_page]["request_json"] = json!(request.to_string());
    mutations.push(inconsistent_modes);

    let mut wrong_hash_flag = original.clone();
    let request = wrong_hash_flag["pages"][hash_page]["request_json"]
        .as_str()
        .unwrap();
    let mut request: Value = serde_json::from_str(request).unwrap();
    request["params"][1] = json!(false);
    wrong_hash_flag["pages"][hash_page]["request_json"] = json!(request.to_string());
    mutations.push(wrong_hash_flag);

    for (field, value) in [
        ("hash", json!(format!("0x{}", "ee".repeat(32)))),
        ("number", json!("0x65")),
        ("receiptsRoot", json!(format!("0x{}", "aa".repeat(32)))),
        ("transactionsRoot", json!(format!("0x{}", "bb".repeat(32)))),
    ] {
        let mut mutation = original.clone();
        mutate_response(&mut mutation, "eth_getBlockByHash", |response| {
            response["result"][field] = value;
        });
        mutations.push(mutation);
    }

    let mut altered_transaction = original;
    mutate_response(&mut altered_transaction, "eth_getBlockByHash", |response| {
        response["result"]["transactions"][0]["r"] = json!("0x01")
    });
    mutations.push(altered_transaction);

    for mutation in mutations {
        let transcript = replay_transcript(mutation);
        assert!(
            reverify_recorded_transaction_receipt_observation_bounded(
                &transaction_hash,
                &transcript,
                MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
                Duration::from_secs(30),
            )
            .await
            .is_err()
        );
    }
}
