use super::*;
use axum::{Json, Router, extract::State, routing::post};
use std::time::Duration;
use tokio::sync::{Notify, watch};

struct RequestGate {
    received: std::sync::atomic::AtomicUsize,
    request_received: Notify,
    release: watch::Sender<bool>,
}

async fn gated_receipt_fixture_rpc(
    State((fixture, gate)): State<(CtfInventoryFixture, Arc<RequestGate>)>,
    Json(request): Json<Value>,
) -> Json<Value> {
    if request["method"] == "eth_chainId" {
        gate.received
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        gate.request_received.notify_one();
        let mut release = gate.release.subscribe();
        if !*release.borrow() {
            let _ = release.changed().await;
        }
        return Json(json!({"jsonrpc":"2.0", "id":request["id"], "result":"0x89"}));
    }
    receipt_transcript_rpc(State(fixture), Json(request)).await
}

async fn gated_receipt_fixture_endpoint(
    fixture: CtfInventoryFixture,
    gate: Arc<RequestGate>,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback fixture endpoint");
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/", post(gated_receipt_fixture_rpc))
                .with_state((fixture, gate)),
        )
        .await
        .unwrap();
    });
    url
}

impl RequestGate {
    fn new() -> Self {
        let (release, _) = watch::channel(false);
        Self {
            received: std::sync::atomic::AtomicUsize::new(0),
            request_received: Notify::new(),
            release,
        }
    }

    async fn wait_for_pair(&self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.received.load(std::sync::atomic::Ordering::SeqCst) < 2 {
                self.request_received.notified().await;
            }
        })
        .await
        .expect("both provider RPCs reach their loopback gates");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_http_timeout_can_outlive_default_while_operation_deadline_remains_bounded() {
    let (fixture, transaction_hash) = receipt_transcript_fixture();
    let default_gate = Arc::new(RequestGate::new());
    let primary = gated_receipt_fixture_endpoint(fixture.clone(), default_gate.clone()).await;
    let secondary = gated_receipt_fixture_endpoint(fixture.clone(), default_gate.clone()).await;
    let default_verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    let default_hash = transaction_hash.clone();
    let default_call = tokio::spawn(async move {
        default_verifier
            .verify_transaction_receipt_observation_bounded(
                &default_hash,
                16,
                Duration::from_secs(60),
            )
            .await
    });
    default_gate.wait_for_pair().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(21)).await;
    assert!(matches!(
        default_call.await.expect("default SDK call task"),
        Err(BoundedTransactionVerificationError::Verification(
            ChainLogAuditError::Unavailable
        ))
    ));
    tokio::time::resume();

    let extended_gate = Arc::new(RequestGate::new());
    let primary = gated_receipt_fixture_endpoint(fixture.clone(), extended_gate.clone()).await;
    let secondary = gated_receipt_fixture_endpoint(fixture, extended_gate.clone()).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .with_rpc_http_timeout(Duration::from_secs(60))
        .unwrap();
    let budget = TransactionRequestBudget::new(16);
    let capture_hash = transaction_hash.clone();
    let capture_budget = budget.clone();
    let extended_call = tokio::spawn(async move {
        verifier
            .capture_transaction_receipt_observation_bounded(
                &capture_hash,
                &capture_budget,
                MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
                Duration::from_secs(60),
            )
            .await
    });
    extended_gate.wait_for_pair().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(21)).await;
    assert!(
        !extended_call.is_finished(),
        "the explicit HTTP timeout must not preempt the still-live operation deadline"
    );
    tokio::time::resume();
    extended_gate.release.send_replace(true);
    let captured = extended_call
        .await
        .expect("extended SDK call task")
        .expect("rooted fixture completes after the explicit HTTP timeout");
    assert_eq!(captured.transcript().request_count(), 16);
    assert_eq!(budget.reserved_requests(), 16);
    assert_eq!(captured.evidence().transaction_hash(), transaction_hash);

    let (fixture, transaction_hash) = receipt_transcript_fixture();
    let short_gate = Arc::new(RequestGate::new());
    let primary = gated_receipt_fixture_endpoint(fixture.clone(), short_gate.clone()).await;
    let secondary = gated_receipt_fixture_endpoint(fixture, short_gate.clone()).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .with_rpc_http_timeout(Duration::from_secs(60))
        .unwrap();
    let timed_out = tokio::spawn(async move {
        verifier
            .capture_transaction_receipt_observation_bounded(
                &transaction_hash,
                &TransactionRequestBudget::new(16),
                MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
                Duration::from_secs(10),
            )
            .await
    });
    short_gate.wait_for_pair().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    assert!(matches!(
        timed_out.await.expect("bounded operation task"),
        Err(BoundedRecordedReceiptVerificationError::Timeout)
    ));
    tokio::time::resume();
}

#[test]
fn explicit_http_timeout_rejects_zero_and_values_over_sixty_seconds() {
    for timeout in [Duration::ZERO, Duration::from_secs(61)] {
        assert!(matches!(
            ChainLogVerifier::new("http://127.0.0.1:1", "http://127.0.0.1:2")
                .unwrap()
                .with_rpc_http_timeout(timeout),
            Err(ChainLogAuditError::InvalidInput)
        ));
    }
}
