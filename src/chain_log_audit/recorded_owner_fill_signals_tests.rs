use super::*;

fn event_word(value: u64) -> String {
    format!("{value:064x}")
}

fn owner_fill_log(order_byte: &str, counterparty: &str) -> Value {
    let topic_address = |address: &str| format!("0x{}{}", "00".repeat(12), &address[2..]);
    json!({
        "address": EXCHANGES[2],
        "topics": [
            V2_ORDER_FILLED,
            format!("0x{}", order_byte.repeat(32)),
            topic_address(&format!("0x{}", "11".repeat(20))),
            topic_address(counterparty),
        ],
        "data": format!(
            "0x{}",
            [
                event_word(0),
                event_word(1),
                event_word(1_000_000),
                event_word(2_000_000),
                event_word(5_000),
                event_word(0xb017),
                event_word(0xcafe),
            ]
            .concat()
        ),
    })
}

fn fixture_with_owner_fills() -> (CtfInventoryFixture, String, String, String) {
    let (mut fixture, transaction_hash) = receipt_transcript_fixture();
    fixture.rooted_gas_block.as_mut().unwrap().receipt_logs[0] = vec![
        owner_fill_log("44", &format!("0x{}", "66".repeat(20))),
        owner_fill_log("77", EXCHANGES[2]),
    ];
    let (opening, closing, _) = ctf_inventory_headers(&fixture);
    (
        fixture,
        transaction_hash,
        opening["hash"].as_str().unwrap().to_owned(),
        closing["hash"].as_str().unwrap().to_owned(),
    )
}

fn assert_same_fill_fields(online: &V2OwnerFillSignal, recorded: &V2OwnerFillSignal) {
    assert_eq!(online.chain_id(), recorded.chain_id());
    assert_eq!(online.block_number(), recorded.block_number());
    assert_eq!(online.block_hash(), recorded.block_hash());
    assert_eq!(online.parent_hash(), recorded.parent_hash());
    assert_eq!(online.block_timestamp(), recorded.block_timestamp());
    assert_eq!(online.transaction_hash(), recorded.transaction_hash());
    assert_eq!(online.transaction_index(), recorded.transaction_index());
    assert_eq!(
        online.transaction_local_log_ordinal(),
        recorded.transaction_local_log_ordinal()
    );
    assert_eq!(online.global_log_index(), recorded.global_log_index());
    assert_eq!(online.exchange(), recorded.exchange());
    assert_eq!(online.order_hash(), recorded.order_hash());
    assert_eq!(online.wallet(), recorded.wallet());
    assert_eq!(online.raw_counterparty(), recorded.raw_counterparty());
    assert_eq!(online.role(), recorded.role());
    assert_eq!(online.decoder_version(), recorded.decoder_version());
    assert_eq!(online.token_id(), recorded.token_id());
    assert_eq!(online.side(), recorded.side());
    assert_eq!(online.share_base_units(), recorded.share_base_units());
    assert_eq!(
        online.collateral_base_units(),
        recorded.collateral_base_units()
    );
    assert_eq!(online.fee_asset(), recorded.fee_asset());
    assert_eq!(online.fee_base_units(), recorded.fee_base_units());
    assert_eq!(online.builder(), recorded.builder());
    assert_eq!(online.metadata(), recorded.metadata());
}

#[tokio::test]
async fn captured_owner_signals_replay_without_claiming_current_finality() {
    // The signed transaction and receipt trie are loopback fixtures; this
    // checks deterministic verification/replay, not EVM execution.
    let (fixture, transaction_hash, parent_hash, end_hash) = fixture_with_owner_fills();
    let primary = receipt_transcript_provider(fixture.clone()).await;
    let secondary = receipt_transcript_provider(fixture).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    let budget = TransactionRequestBudget::new(MAX_RECORDED_RECEIPT_REQUESTS);
    let captured = verifier
        .capture_v2_owner_fill_signals_bounded(
            100,
            &parent_hash,
            &end_hash,
            &budget,
            MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

    assert_eq!(captured.interval().from_block(), 100);
    assert_eq!(captured.interval().through_block(), 100);
    assert_eq!(captured.interval().expected_parent_hash(), parent_hash);
    assert_eq!(captured.interval().expected_end_hash(), end_hash);
    assert_eq!(
        captured.signals().len(),
        2,
        "equal-valued owner rows at different local log ordinals both survive"
    );
    assert_eq!(captured.signals()[0].transaction_hash(), transaction_hash);
    assert_eq!(
        captured.signals()[0].provenance(),
        V2OwnerFillSignalProvenance::OnlineProvidersReportFinalized
    );
    assert_eq!(
        captured.signals()[1].provenance(),
        V2OwnerFillSignalProvenance::OnlineProvidersReportFinalized
    );
    assert_eq!(
        captured.packet().request_count(),
        budget.reserved_requests()
    );
    assert!(captured.packet().request_count() <= MAX_RECORDED_RECEIPT_REQUESTS);
    assert!(captured.packet().response_bytes() > 0);
    assert!(captured.packet().response_bytes() <= MAX_RECORDED_RECEIPT_RESPONSE_BYTES);
    assert_eq!(
        captured.packet().packet_schema_version(),
        RECORDED_V2_OWNER_FILL_PACKET_SCHEMA_VERSION
    );
    assert_eq!(
        captured.packet().capture_policy_version(),
        V2_OWNER_FILL_CAPTURE_POLICY_VERSION
    );
    assert_eq!(
        captured.packet().signal_policy_version(),
        CTF_V2_OWNER_FILL_SIGNAL_POLICY_VERSION
    );
    assert_eq!(captured.signals()[0].role(), V2OwnerFillRole::OrdinaryMaker);
    assert_eq!(
        captured.signals()[1].role(),
        V2OwnerFillRole::ExchangeAggregateOwner
    );
    assert_eq!(captured.signals()[0].share_base_units(), 2_000_000);
    assert_eq!(captured.signals()[0].collateral_base_units(), 1_000_000);
    assert_eq!(captured.signals()[0].fee_base_units(), 5_000);
    assert_eq!(
        captured.signals()[0].builder(),
        &format!("0x{}", event_word(0xb017))
    );
    assert_eq!(
        captured.signals()[0].metadata(),
        &format!("0x{}", event_word(0xcafe))
    );

    let packet_json = serde_json::to_vec(captured.packet()).unwrap();
    let packet: RecordedV2OwnerFillSignalsPacket = serde_json::from_slice(&packet_json).unwrap();
    let replayed = reverify_recorded_v2_owner_fill_signals_bounded(
        &packet,
        MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
        Duration::from_secs(30),
    )
    .await
    .unwrap();
    assert_eq!(replayed.block_number(), 100);
    assert_eq!(replayed.expected_parent_hash(), parent_hash);
    assert_eq!(replayed.expected_end_hash(), end_hash);
    assert_eq!(
        replayed.policy_version(),
        V2_OWNER_FILL_RECORDED_REVERIFICATION_POLICY_VERSION
    );
    assert_eq!(replayed.signals().len(), captured.signals().len());
    for (online, recorded) in captured.signals().iter().zip(replayed.signals()) {
        assert_same_fill_fields(online, recorded);
        assert_eq!(
            recorded.provenance(),
            V2OwnerFillSignalProvenance::RecordedProvidersReportedFinalized
        );
    }
    assert_eq!(
        packet.transcript().request_count(),
        packet.transcript().pages().len()
    );
    let serialized = String::from_utf8(packet_json).unwrap();
    assert!(!serialized.contains(&primary));
    assert!(!serialized.contains(&secondary));
    assert!(!serialized.contains("captured_at"));
}

#[tokio::test]
async fn recorded_owner_signal_replay_rejects_versions_frames_and_byte_caps() {
    let (fixture, _transaction_hash, parent_hash, end_hash) = fixture_with_owner_fills();
    let primary = receipt_transcript_provider(fixture.clone()).await;
    let secondary = receipt_transcript_provider(fixture).await;
    let captured = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .capture_v2_owner_fill_signals_bounded(
            100,
            &parent_hash,
            &end_hash,
            &TransactionRequestBudget::new(MAX_RECORDED_RECEIPT_REQUESTS),
            MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let valid_value = serde_json::to_value(captured.packet()).unwrap();

    let mut wrong_schema = valid_value.clone();
    wrong_schema["packet_schema_version"] = json!("unknown");
    let wrong_schema: RecordedV2OwnerFillSignalsPacket =
        serde_json::from_value(wrong_schema).unwrap();
    assert!(matches!(
        reverify_recorded_v2_owner_fill_signals_bounded(
            &wrong_schema,
            MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
            Duration::from_secs(30)
        )
        .await,
        Err(BoundedRecordedOwnerFillSignalsError::Verification(
            ChainLogAuditError::Unverified
        ))
    ));

    let mut missing_page = valid_value.clone();
    missing_page["transcript"]["pages"]
        .as_array_mut()
        .unwrap()
        .pop();
    let missing_page: RecordedV2OwnerFillSignalsPacket =
        serde_json::from_value(missing_page).unwrap();
    assert!(
        reverify_recorded_v2_owner_fill_signals_bounded(
            &missing_page,
            MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
            Duration::from_secs(30)
        )
        .await
        .is_err()
    );

    let mut extra_page = valid_value.clone();
    let duplicate = extra_page["transcript"]["pages"][0].clone();
    extra_page["transcript"]["pages"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    let extra_page: RecordedV2OwnerFillSignalsPacket = serde_json::from_value(extra_page).unwrap();
    assert!(
        reverify_recorded_v2_owner_fill_signals_bounded(
            &extra_page,
            MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
            Duration::from_secs(30)
        )
        .await
        .is_err()
    );

    let mut bad_envelope = valid_value.clone();
    bad_envelope["transcript"]["pages"][0]["response_json"] = json!("{}");
    let bad_envelope: RecordedV2OwnerFillSignalsPacket =
        serde_json::from_value(bad_envelope).unwrap();
    assert!(
        reverify_recorded_v2_owner_fill_signals_bounded(
            &bad_envelope,
            MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
            Duration::from_secs(30)
        )
        .await
        .is_err()
    );

    let packet: RecordedV2OwnerFillSignalsPacket = serde_json::from_value(valid_value).unwrap();
    assert!(
        reverify_recorded_v2_owner_fill_signals_bounded(
            &packet,
            packet.response_bytes() - 1,
            Duration::from_secs(30)
        )
        .await
        .is_err()
    );
    assert!(matches!(
        reverify_recorded_v2_owner_fill_signals_bounded(
            &packet,
            MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
            Duration::ZERO
        )
        .await,
        Err(BoundedRecordedOwnerFillSignalsError::Verification(
            ChainLogAuditError::InvalidInput
        ))
    ));
}

#[tokio::test]
async fn owner_signal_capture_enforces_budget_timeout_and_cancellation() {
    let (fixture, _transaction_hash, parent_hash, end_hash) = fixture_with_owner_fills();
    let provider = receipt_transcript_provider(fixture.clone()).await;
    let secondary = receipt_transcript_provider(fixture.clone()).await;
    let verifier = ChainLogVerifier::new(&provider, &secondary).unwrap();
    let short_budget = TransactionRequestBudget::new(1);
    assert!(matches!(
        verifier
            .capture_v2_owner_fill_signals_bounded(
                100,
                &parent_hash,
                &end_hash,
                &short_budget,
                MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
                Duration::from_secs(30),
            )
            .await,
        Err(BoundedRecordedOwnerFillSignalsError::RequestBudgetExceeded)
    ));
    assert_eq!(short_budget.reserved_requests(), 1);

    let byte_budget = TransactionRequestBudget::new(MAX_RECORDED_RECEIPT_REQUESTS);
    assert!(matches!(
        verifier
            .capture_v2_owner_fill_signals_bounded(
                100,
                &parent_hash,
                &end_hash,
                &byte_budget,
                1,
                Duration::from_secs(30),
            )
            .await,
        Err(BoundedRecordedOwnerFillSignalsError::Verification(
            ChainLogAuditError::Unverified
        ))
    ));
    assert!(byte_budget.reserved_requests() > 0);

    let (mut slow_fixture, transaction_hash, parent_hash, end_hash) = fixture_with_owner_fills();
    slow_fixture.delay_ms = 100;
    let primary = receipt_transcript_provider(slow_fixture.clone()).await;
    let secondary = receipt_transcript_provider(slow_fixture.clone()).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    assert!(matches!(
        verifier
            .capture_v2_owner_fill_signals_bounded(
                100,
                &parent_hash,
                &end_hash,
                &TransactionRequestBudget::new(MAX_RECORDED_RECEIPT_REQUESTS),
                MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
                Duration::from_millis(1),
            )
            .await,
        Err(BoundedRecordedOwnerFillSignalsError::Timeout)
    ));

    let cancellation_fixture = slow_fixture.clone();
    let cancellation_primary = receipt_transcript_provider(cancellation_fixture.clone()).await;
    let cancellation_secondary = receipt_transcript_provider(cancellation_fixture.clone()).await;
    let verifier = ChainLogVerifier::new(&cancellation_primary, &cancellation_secondary).unwrap();
    let task = tokio::spawn(async move {
        verifier
            .capture_v2_owner_fill_signals_bounded(
                100,
                &parent_hash,
                &end_hash,
                &TransactionRequestBudget::new(MAX_RECORDED_RECEIPT_REQUESTS),
                MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
                Duration::from_secs(30),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while slow_fixture
            .requests
            .load(std::sync::atomic::Ordering::Relaxed)
            == 0
        {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let sent = slow_fixture
        .requests
        .load(std::sync::atomic::Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        slow_fixture
            .requests
            .load(std::sync::atomic::Ordering::Relaxed),
        sent
    );
    assert_eq!(transaction_hash.len(), 66);
}

#[derive(Clone)]
struct BlockAnchorFixture {
    header: Value,
    padding_bytes: usize,
    delay: Duration,
    requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

struct BlockAnchorProvider {
    url: String,
    requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for BlockAnchorProvider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn block_anchor_rpc(
    State(fixture): State<BlockAnchorFixture>,
    Json(request): Json<Value>,
) -> Json<Value> {
    use std::sync::atomic::Ordering;

    assert_eq!(request["method"], "eth_getBlockByNumber");
    assert_eq!(request["params"], json!(["0x64", false]));
    fixture.requests.fetch_add(1, Ordering::Relaxed);
    if !fixture.delay.is_zero() {
        tokio::time::sleep(fixture.delay).await;
    }
    let mut response = json!({
        "jsonrpc":"2.0",
        "id":request["id"],
        "result":fixture.header,
    });
    if fixture.padding_bytes > 0 {
        response["padding"] = json!("x".repeat(fixture.padding_bytes));
    }
    Json(response)
}

async fn block_anchor_provider(
    header: Value,
    padding_bytes: usize,
    delay: Duration,
) -> BlockAnchorProvider {
    use std::sync::atomic::AtomicUsize;

    let requests = std::sync::Arc::new(AtomicUsize::new(0));
    let fixture = BlockAnchorFixture {
        header,
        padding_bytes,
        delay,
        requests: requests.clone(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/", post(block_anchor_rpc))
                .with_state(fixture),
        )
        .await
        .unwrap();
    });
    BlockAnchorProvider {
        url,
        requests,
        task,
    }
}

fn block_anchor_header(number: u64) -> Value {
    let parent = format!("0x{}", "11".repeat(32));
    let zero = format!("0x{}", "00".repeat(32));
    super::super::super::header_binding::fixture_header(number, &parent, &zero, &zero, &zero)
}

fn block_anchor_verifier(primary_url: &str) -> ChainLogVerifier {
    ChainLogVerifier::new(primary_url, "http://127.0.0.1:1").unwrap()
}

#[tokio::test]
async fn block_anchor_observation_is_one_primary_rpc_and_returns_content_bound_hashes() {
    use std::sync::atomic::Ordering;

    let header = block_anchor_header(100);
    let expected_hash = header["hash"].as_str().unwrap().to_owned();
    let expected_parent = header["parentHash"].as_str().unwrap().to_owned();
    let provider = block_anchor_provider(header, 0, Duration::ZERO).await;
    let budget = TransactionRequestBudget::new(1);
    let observed = block_anchor_verifier(&provider.url)
        .observe_block_anchor_bounded(100, &budget, 4096, Duration::from_secs(1))
        .await
        .unwrap();

    assert_eq!(observed.block_number(), 100);
    assert_eq!(observed.block_hash(), expected_hash);
    assert_eq!(observed.parent_hash(), expected_parent);
    assert!(observed.response_bytes() > 0);
    assert!(observed.response_bytes() <= 4096);
    assert_eq!(budget.reserved_requests(), 1);
    assert_eq!(provider.requests.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn block_anchor_observation_rejects_wrong_height_and_malformed_header() {
    for header in [block_anchor_header(101), {
        let mut header = block_anchor_header(100);
        header["hash"] = json!(format!("0x{}", "ff".repeat(32)));
        header
    }] {
        let provider = block_anchor_provider(header, 0, Duration::ZERO).await;
        let result = block_anchor_verifier(&provider.url)
            .observe_block_anchor_bounded(
                100,
                &TransactionRequestBudget::new(1),
                4096,
                Duration::from_secs(1),
            )
            .await;
        assert!(matches!(
            result,
            Err(BoundedRecordedOwnerFillSignalsError::Verification(
                ChainLogAuditError::Unverified
            ))
        ));
    }
}

#[tokio::test]
async fn block_anchor_observation_enforces_response_and_request_budgets() {
    use std::sync::atomic::Ordering;

    let provider = block_anchor_provider(block_anchor_header(100), 1024, Duration::ZERO).await;
    let byte_result = block_anchor_verifier(&provider.url)
        .observe_block_anchor_bounded(
            100,
            &TransactionRequestBudget::new(1),
            64,
            Duration::from_secs(1),
        )
        .await;
    assert!(matches!(
        byte_result,
        Err(BoundedRecordedOwnerFillSignalsError::Verification(
            ChainLogAuditError::Unverified
        ))
    ));
    assert_eq!(provider.requests.load(Ordering::Relaxed), 1);

    let budget = TransactionRequestBudget::new(0);
    let budget_result = block_anchor_verifier(&provider.url)
        .observe_block_anchor_bounded(100, &budget, 4096, Duration::from_secs(1))
        .await;
    assert!(matches!(
        budget_result,
        Err(BoundedRecordedOwnerFillSignalsError::RequestBudgetExceeded)
    ));
    assert_eq!(budget.reserved_requests(), 0);
    assert_eq!(provider.requests.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn block_anchor_observation_timeout_returns_no_anchor() {
    let provider =
        block_anchor_provider(block_anchor_header(100), 0, Duration::from_millis(100)).await;
    let result = block_anchor_verifier(&provider.url)
        .observe_block_anchor_bounded(
            100,
            &TransactionRequestBudget::new(1),
            4096,
            Duration::from_millis(1),
        )
        .await;
    assert!(matches!(
        result,
        Err(BoundedRecordedOwnerFillSignalsError::Timeout)
    ));
}
