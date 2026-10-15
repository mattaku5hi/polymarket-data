use super::*;
use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
    routing::{any, post},
};
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

const PRIMARY_AUTH_SENTINEL: &str = "fixture-primary-auth-sentinel";
const SECONDARY_AUTH_SENTINEL: &str = "fixture-secondary-auth-sentinel";

#[derive(Clone)]
struct ProviderAuthState {
    fixture: CtfInventoryFixture,
    provider: &'static str,
    requests: Arc<std::sync::Mutex<Vec<(&'static str, HeaderMap)>>>,
}

async fn provider_auth_receipt_rpc(
    State(state): State<ProviderAuthState>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Json<Value> {
    state
        .requests
        .lock()
        .unwrap()
        .push((state.provider, headers));
    if request["method"] == "eth_chainId" {
        return Json(json!({"jsonrpc":"2.0", "id":request["id"], "result":"0x89"}));
    }
    receipt_transcript_rpc(State(state.fixture), Json(request)).await
}

async fn provider_auth_endpoint(
    fixture: CtfInventoryFixture,
    provider: &'static str,
    requests: Arc<std::sync::Mutex<Vec<(&'static str, HeaderMap)>>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind provider auth fixture endpoint");
    let url = format!("http://{}", listener.local_addr().unwrap());
    let state = ProviderAuthState {
        fixture,
        provider,
        requests,
    };
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/", post(provider_auth_receipt_rpc))
                .with_state(state),
        )
        .await
        .unwrap();
    });
    (url, server)
}

fn provider_auth_headers(value: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static(value));
    headers
}

async fn redirect_rpc(
    State((location, requests)): State<(String, Arc<AtomicUsize>)>,
    _headers: HeaderMap,
) -> Response<Body> {
    requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header(header::LOCATION, location)
        .body(Body::empty())
        .unwrap()
}

async fn count_redirect_target(State(requests): State<Arc<AtomicUsize>>) -> Json<Value> {
    requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Json(json!({"jsonrpc":"2.0", "id":1, "result":"0x89"}))
}

async fn count_retry_target(
    State(requests): State<Arc<AtomicUsize>>,
    _headers: HeaderMap,
    _body: axum::body::Bytes,
) -> StatusCode {
    requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    StatusCode::SERVICE_UNAVAILABLE
}

async fn redirect_endpoint(location: String, requests: Arc<AtomicUsize>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind redirect fixture endpoint");
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/", any(redirect_rpc))
                .with_state((location, requests)),
        )
        .await
        .unwrap();
    });
    url
}

async fn counted_target_endpoint(requests: Arc<AtomicUsize>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind redirect target fixture endpoint");
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/", any(count_redirect_target))
                .with_state(requests),
        )
        .await
        .unwrap();
    });
    url
}

async fn counted_unavailable_endpoint(requests: Arc<AtomicUsize>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind retry-count fixture endpoint");
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/", post(count_retry_target))
                .with_state(requests),
        )
        .await
        .unwrap();
    });
    url
}

#[tokio::test]
async fn provider_auth_headers_stay_scoped_through_budget_timeout_clone_and_offline_replay() {
    let (fixture, transaction_hash) = receipt_transcript_fixture();
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (primary, primary_server) =
        provider_auth_endpoint(fixture.clone(), "primary", requests.clone()).await;
    let (secondary, secondary_server) =
        provider_auth_endpoint(fixture, "secondary", requests.clone()).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .with_rpc_provider_headers(
            provider_auth_headers(PRIMARY_AUTH_SENTINEL),
            provider_auth_headers(SECONDARY_AUTH_SENTINEL),
        )
        .unwrap()
        .with_rpc_http_timeout(Duration::from_secs(30))
        .unwrap();
    assert!(!format!("{:?}", verifier.primary_rpc_headers).contains(PRIMARY_AUTH_SENTINEL));
    assert!(!format!("{:?}", verifier.secondary_rpc_headers).contains(SECONDARY_AUTH_SENTINEL));

    // Both existing call-local clones must preserve their own provider headers.
    let module_scoped = verifier.with_fifth_module_call_targets(Address::ZERO);
    let budget_scoped = module_scoped.with_request_budget(Arc::new(OperationRequestBudget::new(2)));
    budget_scoped
        .rpc(&primary, "eth_chainId", json!([]))
        .await
        .unwrap();
    budget_scoped
        .rpc(&secondary, "eth_chainId", json!([]))
        .await
        .unwrap();
    assert!(matches!(
        budget_scoped.rpc(&primary, "eth_chainId", json!([])).await,
        Err(ChainLogAuditError::Unavailable)
    ));
    assert!(matches!(
        budget_scoped.rpc(&primary, "eth_chainId", json!([])).await,
        Err(ChainLogAuditError::Unavailable)
    ));

    let captured = verifier
        .capture_transaction_receipt_observation_bounded(
            &transaction_hash,
            &TransactionRequestBudget::new(16),
            MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let request_count_before_replay = requests.lock().unwrap().len();
    let captured_text = serde_json::to_string(captured.transcript()).unwrap();
    assert!(!captured_text.contains(PRIMARY_AUTH_SENTINEL));
    assert!(!captured_text.contains(SECONDARY_AUTH_SENTINEL));

    {
        let recorded_requests = requests.lock().unwrap();
        assert!(recorded_requests.iter().any(|(provider, headers)| {
            *provider == "primary"
                && headers
                    .get("x-api-key")
                    .is_some_and(|value| value == PRIMARY_AUTH_SENTINEL)
                && headers
                    .get(header::CONTENT_TYPE)
                    .is_some_and(|value| value == "application/json")
        }));
        assert!(recorded_requests.iter().any(|(provider, headers)| {
            *provider == "secondary"
                && headers
                    .get("x-api-key")
                    .is_some_and(|value| value == SECONDARY_AUTH_SENTINEL)
                && headers
                    .get(header::CONTENT_TYPE)
                    .is_some_and(|value| value == "application/json")
        }));
        assert!(
            recorded_requests
                .iter()
                .all(|(provider, headers)| match *provider {
                    "primary" => {
                        headers
                            .get("x-api-key")
                            .is_some_and(|value| value == PRIMARY_AUTH_SENTINEL)
                            && !headers
                                .get("x-api-key")
                                .is_some_and(|value| value == SECONDARY_AUTH_SENTINEL)
                    }
                    "secondary" => {
                        headers
                            .get("x-api-key")
                            .is_some_and(|value| value == SECONDARY_AUTH_SENTINEL)
                            && !headers
                                .get("x-api-key")
                                .is_some_and(|value| value == PRIMARY_AUTH_SENTINEL)
                    }
                    _ => false,
                })
        );
    }

    reverify_recorded_transaction_receipt_observation_bounded(
        &transaction_hash,
        captured.transcript(),
        MAX_RECORDED_RECEIPT_RESPONSE_BYTES,
        Duration::from_secs(30),
    )
    .await
    .unwrap();
    assert_eq!(requests.lock().unwrap().len(), request_count_before_replay);

    primary_server.abort();
    secondary_server.abort();
}

#[test]
fn provider_auth_headers_reject_transport_fields_and_keep_errors_redacted() {
    for forbidden in [
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "content-type",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(forbidden, HeaderValue::from_static(PRIMARY_AUTH_SENTINEL));
        let result = ChainLogVerifier::new("http://127.0.0.1:1", "http://127.0.0.1:2")
            .unwrap()
            .with_rpc_provider_headers(headers, HeaderMap::new());
        assert!(matches!(&result, Err(ChainLogAuditError::InvalidInput)));
        assert!(!format!("{:?}", result.err().unwrap()).contains(PRIMARY_AUTH_SENTINEL));
    }

    assert!(ChainLogVerifier::new("http://example.com", "https://rpc.example").is_err());
    assert!(
        ChainLogVerifier::new("https://same.example/rpc-a", "https://same.example/rpc-b").is_err()
    );
}

#[tokio::test]
async fn provider_auth_is_not_forwarded_through_redirects() {
    let target_requests = Arc::new(AtomicUsize::new(0));
    let target = counted_target_endpoint(target_requests.clone()).await;
    let source_requests = Arc::new(AtomicUsize::new(0));
    let source = redirect_endpoint(target, source_requests.clone()).await;
    let verifier = ChainLogVerifier::new(&source, "http://127.0.0.1:1")
        .unwrap()
        .with_rpc_provider_headers(
            provider_auth_headers(PRIMARY_AUTH_SENTINEL),
            provider_auth_headers(SECONDARY_AUTH_SENTINEL),
        )
        .unwrap();

    assert!(matches!(
        verifier.rpc(&source, "eth_chainId", json!([])).await,
        Err(ChainLogAuditError::Unavailable)
    ));
    assert_eq!(source_requests.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(target_requests.load(std::sync::atomic::Ordering::SeqCst), 0);

    let unavailable_requests = Arc::new(AtomicUsize::new(0));
    let unavailable = counted_unavailable_endpoint(unavailable_requests.clone()).await;
    let verifier = ChainLogVerifier::new(&unavailable, "http://127.0.0.1:1")
        .unwrap()
        .with_rpc_provider_headers(
            provider_auth_headers(PRIMARY_AUTH_SENTINEL),
            provider_auth_headers(SECONDARY_AUTH_SENTINEL),
        )
        .unwrap();
    assert!(matches!(
        verifier.rpc(&unavailable, "eth_chainId", json!([])).await,
        Err(ChainLogAuditError::Unavailable)
    ));
    assert_eq!(
        unavailable_requests.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "provider HTTP responses are not retried"
    );
}
