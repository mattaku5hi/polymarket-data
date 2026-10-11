use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router, body::Body, extract::State, http::Request, response::IntoResponse, routing::post,
};
use polymarket_data::rpc_position_history::{
    RpcPositionHistoryError, RpcPositionHistoryReader, RpcPositionHistoryRequest,
};
use serde_json::{Value, json};
use tokio::{sync::Notify, time::Instant};

const HOLDER: &str = "0x1111111111111111111111111111111111111111";
const TERMINAL_HASH: &str = "0x000000000000000000000000000000000000000000000000000000000000000f";

#[derive(Clone)]
struct Replay {
    count: Arc<AtomicUsize>,
    arrivals: Arc<Mutex<Vec<Instant>>>,
    first_request: Arc<Notify>,
}

async fn reader() -> (String, Replay) {
    let replay = Replay {
        count: Arc::new(AtomicUsize::new(0)),
        arrivals: Arc::new(Mutex::new(Vec::new())),
        first_request: Arc::new(Notify::new()),
    };
    let app = Router::new()
        .route("/rpc", post(handler))
        .with_state(replay.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}/rpc"), replay)
}

async fn handler(State(replay): State<Replay>, request: Request<Body>) -> impl IntoResponse {
    replay.arrivals.lock().unwrap().push(Instant::now());
    let n = replay.count.fetch_add(1, Ordering::SeqCst);
    if n == 0 {
        replay.first_request.notify_one();
    }
    let bytes = axum::body::to_bytes(request.into_body(), 64 * 1024)
        .await
        .unwrap();
    let request: Value = serde_json::from_slice(&bytes).unwrap();
    let result = match request["method"].as_str().unwrap() {
        "eth_chainId" => json!("0x89"),
        "eth_getBlockByNumber" if request["params"][0] == "finalized" => header(1_000, hash(1_000)),
        "eth_getBlockByNumber" => header(15, TERMINAL_HASH),
        "eth_getLogs" => json!([]),
        _ => unreachable!(),
    };
    (
        axum::http::StatusCode::OK,
        json!({"jsonrpc":"2.0", "id":request["id"], "result":result}).to_string(),
    )
}

fn hash(number: u64) -> String {
    format!("0x{number:064x}")
}

fn header(number: u64, hash_value: impl AsRef<str>) -> Value {
    json!({
        "number": format!("0x{number:x}"),
        "hash": hash_value.as_ref(),
        "parentHash": hash(number.saturating_sub(1)),
        "stateRoot": hash(number.saturating_add(1)),
        "transactionsRoot": hash(number.saturating_add(2)),
        "receiptsRoot": hash(number.saturating_add(3)),
        "logsBloom": format!("0x{}", "00".repeat(256)),
    })
}

fn request() -> RpcPositionHistoryRequest {
    RpcPositionHistoryRequest {
        holder_address: HOLDER.into(),
        from_block: 0,
        through_block: 15,
        expected_through_hash: TERMINAL_HASH.into(),
        max_requests: 8,
        max_total_response_bytes: 8 * 1024 * 1024,
        total_timeout: Duration::from_secs(5),
    }
}

#[tokio::test]
async fn configured_interval_spaces_actual_sends_and_carries_across_reads() {
    let (endpoint, replay) = reader().await;
    let interval = Duration::from_millis(25);
    let client = RpcPositionHistoryReader::new_with_request_interval(
        reqwest::Client::builder(),
        &endpoint,
        interval,
    )
    .unwrap();

    let start = Instant::now();
    assert_eq!(
        client
            .read_history(&request())
            .await
            .unwrap()
            .request_count(),
        6
    );
    let first_read_elapsed = start.elapsed();
    assert!(first_read_elapsed >= interval * 4);
    assert_eq!(replay.count.load(Ordering::SeqCst), 6);

    assert_eq!(
        client
            .read_history(&request())
            .await
            .unwrap()
            .request_count(),
        6
    );
    let arrivals = replay.arrivals.lock().unwrap();
    assert_eq!(arrivals.len(), 12);
    for pair in arrivals.windows(2) {
        assert!(pair[1].duration_since(pair[0]) >= interval - Duration::from_millis(5));
    }
}

#[tokio::test]
async fn deadline_and_cancellation_while_waiting_do_not_start_extra_requests() {
    let (endpoint, replay) = reader().await;
    let interval = Duration::from_millis(250);
    let client = Arc::new(
        RpcPositionHistoryReader::new_with_request_interval(
            reqwest::Client::builder(),
            &endpoint,
            interval,
        )
        .unwrap(),
    );
    let mut short = request();
    short.total_timeout = Duration::from_millis(100);
    assert_eq!(
        client.read_history(&short).await.unwrap_err(),
        RpcPositionHistoryError::Timeout
    );
    assert_eq!(replay.count.load(Ordering::SeqCst), 1);

    let (endpoint, replay) = reader().await;
    let client = Arc::new(
        RpcPositionHistoryReader::new_with_request_interval(
            reqwest::Client::builder(),
            &endpoint,
            Duration::from_millis(250),
        )
        .unwrap(),
    );
    let task_client = Arc::clone(&client);
    let task = tokio::spawn(async move { task_client.read_history(&request()).await });
    tokio::time::timeout(Duration::from_secs(1), replay.first_request.notified())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(replay.count.load(Ordering::SeqCst), 1);

    let mut still_paced = request();
    still_paced.total_timeout = Duration::from_millis(30);
    assert_eq!(
        client.read_history(&still_paced).await.unwrap_err(),
        RpcPositionHistoryError::Timeout
    );
    assert_eq!(replay.count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn concurrent_reads_share_one_request_start_gate() {
    let (endpoint, replay) = reader().await;
    let interval = Duration::from_millis(20);
    let client = Arc::new(
        RpcPositionHistoryReader::new_with_request_interval(
            reqwest::Client::builder(),
            &endpoint,
            interval,
        )
        .unwrap(),
    );
    let first_client = Arc::clone(&client);
    let first = tokio::spawn(async move { first_client.read_history(&request()).await });
    let second_client = Arc::clone(&client);
    let second = tokio::spawn(async move { second_client.read_history(&request()).await });
    assert_eq!(first.await.unwrap().unwrap().request_count(), 6);
    assert_eq!(second.await.unwrap().unwrap().request_count(), 6);

    let arrivals = replay.arrivals.lock().unwrap();
    assert_eq!(arrivals.len(), 12);
    for pair in arrivals.windows(2) {
        assert!(pair[1].duration_since(pair[0]) >= interval - Duration::from_millis(5));
    }
}

#[tokio::test]
async fn rejects_interval_that_overflows_instant_arithmetic() {
    let (endpoint, replay) = reader().await;
    assert!(matches!(
        RpcPositionHistoryReader::new_with_request_interval(
            reqwest::Client::builder(),
            &endpoint,
            Duration::MAX,
        ),
        Err(RpcPositionHistoryError::InvalidInput)
    ));
    assert_eq!(replay.count.load(Ordering::SeqCst), 0);
}
