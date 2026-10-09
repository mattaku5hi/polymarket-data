use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use polymarket_data::{
    position_history::{CTF_EMITTER, TRANSFER_BATCH_TOPIC, TRANSFER_SINGLE_TOPIC},
    rpc_position_history::{
        RpcPositionHistoryError, RpcPositionHistoryReader, RpcPositionHistoryRequest,
    },
};
use serde_json::{Value, json};

const HOLDER: &str = "0x1111111111111111111111111111111111111111";
const HASH15: &str = "0x000000000000000000000000000000000000000000000000000000000000000f";
const TX: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Clone)]
struct ServerState {
    mode: &'static str,
    count: Arc<AtomicUsize>,
}

async fn server(mode: &'static str) -> (String, ServerState) {
    let state = ServerState {
        mode,
        count: Arc::new(AtomicUsize::new(0)),
    };
    let app = Router::new()
        .route("/rpc", post(handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}/rpc"), state)
}

async fn handler(State(state): State<ServerState>, request: Request<Body>) -> Response {
    let n = state.count.fetch_add(1, Ordering::SeqCst);
    let bytes = to_bytes(request.into_body(), 64 * 1024).await.unwrap();
    let request: Value = serde_json::from_slice(&bytes).unwrap();
    if state.mode == "delayed" {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if state.mode == "rate_limited" {
        return Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("retry-after", "7")
            .body(Body::empty())
            .unwrap();
    }
    if state.mode == "redirect" {
        return Response::builder()
            .status(StatusCode::TEMPORARY_REDIRECT)
            .header("location", "/other")
            .body(Body::empty())
            .unwrap();
    }
    if state.mode == "oversize" {
        return (StatusCode::OK, " ".repeat(2 * 1024 * 1024 + 1)).into_response();
    }
    let id = if state.mode == "bad_id" {
        json!(request["id"].as_u64().unwrap() + 1)
    } else {
        request["id"].clone()
    };
    let method = request["method"].as_str().unwrap();
    let result = match method {
        "eth_chainId" => json!(if state.mode == "wrong_chain" {
            "0x1"
        } else {
            "0x89"
        }),
        "eth_getBlockByNumber" if request["params"][0] == "finalized" => header(
            if state.mode == "not_final" { 14 } else { 20 },
            &hash_for(20),
        ),
        "eth_getBlockByNumber" => {
            let mut h = header(15, HASH15);
            if state.mode == "anchor_change" && n == 5 {
                h["hash"] = json!(hash_for(16));
            }
            if state.mode == "before_wrong" && n == 2 {
                h["hash"] = json!(hash_for(16));
            }
            h
        }
        "eth_getLogs" => {
            if state.mode == "out_of_range" {
                json!([log(16)])
            } else if state.mode == "removed" {
                let mut l = log(15);
                l["removed"] = json!(true);
                json!([l])
            } else if state.mode == "wrong_filter" {
                let mut l = log(15);
                l["topics"][2] = json!(hash_for(0));
                json!([l])
            } else if state.mode == "conflict" && request["params"][0]["topics"][2].is_null() {
                let mut l = log(15);
                l["transactionHash"] = json!(hash_for(10));
                json!([l])
            } else if state.mode == "transaction_conflict"
                && request["params"][0]["topics"][2].is_null()
            {
                let mut l = log(15);
                l["transactionHash"] = json!(hash_for(10));
                l["logIndex"] = json!("0x4");
                json!([l])
            } else if state.mode == "block_hash_conflict"
                && request["params"][0]["topics"][2].is_null()
            {
                let mut l = log(15);
                l["blockHash"] = json!(hash_for(14));
                json!([l])
            } else {
                json!([log(15)])
            }
        }
        _ => unreachable!(),
    };
    let envelope = if state.mode == "rpc_error" {
        json!({"jsonrpc":"2.0", "id":id, "error":{"code":-32000,"message":"sensitive-provider-detail"}})
    } else {
        json!({"jsonrpc":"2.0", "id":id, "result":result})
    };
    (StatusCode::OK, envelope.to_string()).into_response()
}

fn hash_for(number: u64) -> String {
    format!("0x{number:064x}")
}
fn header(number: u64, hash: &str) -> Value {
    json!({"number":format!("0x{number:x}"), "hash":hash, "parentHash":hash_for(number.saturating_sub(1)),
        "stateRoot":hash_for(number + 1), "transactionsRoot":hash_for(number + 2), "receiptsRoot":hash_for(number + 3),
        "logsBloom":format!("0x{}", "00".repeat(256))})
}
fn log(number: u64) -> Value {
    let holder = format!("0x{:0>64}", &HOLDER[2..]);
    json!({"address":CTF_EMITTER, "topics":[TRANSFER_SINGLE_TOPIC, hash_for(0), holder, holder], "data":"0x01",
        "blockNumber":format!("0x{number:x}"), "blockHash":HASH15, "transactionHash":TX,
        "transactionIndex":"0x2", "logIndex":"0x3", "removed":false})
}
fn request() -> RpcPositionHistoryRequest {
    RpcPositionHistoryRequest {
        holder_address: HOLDER.into(),
        from_block: 0,
        through_block: 15,
        expected_through_hash: HASH15.into(),
        max_requests: 8,
        max_total_response_bytes: 8 * 1024 * 1024,
        total_timeout: Duration::from_secs(3),
    }
}
async fn make_reader(mode: &'static str) -> (RpcPositionHistoryReader, ServerState) {
    let (url, state) = server(mode).await;
    (
        RpcPositionHistoryReader::new(reqwest::Client::builder(), &url).unwrap(),
        state,
    )
}

#[tokio::test]
async fn sends_six_sequential_exact_scope_calls_and_collapses_self_transfer() {
    let (reader, state) = make_reader("ok").await;
    let observation = reader.read_history(&request()).await.unwrap();
    assert_eq!(observation.request_count(), 6);
    assert_eq!(observation.pages().len(), 6);
    assert_eq!(observation.logs().len(), 1);
    assert_eq!(observation.terminal_hash(), HASH15);
    assert_eq!(state.count.load(Ordering::SeqCst), 6);
    let from: Value = serde_json::from_str(observation.pages()[3].request_json()).unwrap();
    let filter = &from["params"][0];
    assert_eq!(filter["fromBlock"], "0x0");
    assert_eq!(filter["toBlock"], "0xf");
    assert_eq!(
        filter["address"],
        json!([CTF_EMITTER, "0x006f54f7f9a22e0000cc2ab60031000000ae9fef"])
    );
    assert_eq!(
        filter["topics"][0],
        json!([TRANSFER_SINGLE_TOPIC, TRANSFER_BATCH_TOPIC])
    );
    assert_eq!(filter["topics"][2], format!("0x{:0>64}", &HOLDER[2..]));
    let to: Value = serde_json::from_str(observation.pages()[4].request_json()).unwrap();
    assert!(to["params"][0]["topics"][2].is_null());
    assert_eq!(
        to["params"][0]["topics"][3],
        format!("0x{:0>64}", &HOLDER[2..])
    );
}

#[tokio::test]
async fn rejects_chain_finality_anchor_jsonrpc_and_log_scope_errors() {
    for (mode, expected) in [
        ("wrong_chain", RpcPositionHistoryError::WrongChain),
        ("not_final", RpcPositionHistoryError::NotFinalized),
        ("anchor_change", RpcPositionHistoryError::AnchorMismatch),
        ("before_wrong", RpcPositionHistoryError::AnchorMismatch),
        ("bad_id", RpcPositionHistoryError::MalformedResponse),
        (
            "rpc_error",
            RpcPositionHistoryError::RpcError { code: -32000 },
        ),
        ("removed", RpcPositionHistoryError::MalformedResponse),
        ("out_of_range", RpcPositionHistoryError::MalformedResponse),
        ("wrong_filter", RpcPositionHistoryError::MalformedResponse),
        ("conflict", RpcPositionHistoryError::ConflictingLocator),
        (
            "transaction_conflict",
            RpcPositionHistoryError::ConflictingLocator,
        ),
        (
            "block_hash_conflict",
            RpcPositionHistoryError::ConflictingHeader,
        ),
    ] {
        let (reader, _) = make_reader(mode).await;
        let error = reader.read_history(&request()).await.unwrap_err();
        assert_eq!(error, expected, "mode={mode}");
        assert!(!error.to_string().contains("sensitive-provider-detail"));
    }
}

#[tokio::test]
async fn enforces_request_body_and_deadline_bounds_without_partial_success() {
    let (reader, state) = make_reader("ok").await;
    let mut insufficient = request();
    insufficient.max_requests = 5;
    assert_eq!(
        reader.read_history(&insufficient).await.unwrap_err(),
        RpcPositionHistoryError::RequestBudgetExceeded
    );
    assert_eq!(state.count.load(Ordering::SeqCst), 0);

    let (reader, _) = make_reader("oversize").await;
    assert_eq!(
        reader.read_history(&request()).await.unwrap_err(),
        RpcPositionHistoryError::BodyBudgetExceeded
    );

    let (reader, _) = make_reader("ok").await;
    let mut invalid = request();
    invalid.total_timeout = Duration::ZERO;
    assert_eq!(
        reader.read_history(&invalid).await.unwrap_err(),
        RpcPositionHistoryError::InvalidInput
    );

    let (reader, _) = make_reader("ok").await;
    let mut tiny_total = request();
    tiny_total.max_total_response_bytes = 1;
    assert_eq!(
        reader.read_history(&tiny_total).await.unwrap_err(),
        RpcPositionHistoryError::BodyBudgetExceeded
    );

    let (reader, _) = make_reader("delayed").await;
    let mut short = request();
    short.total_timeout = Duration::from_millis(5);
    assert_eq!(
        reader.read_history(&short).await.unwrap_err(),
        RpcPositionHistoryError::Timeout
    );
}

#[tokio::test]
async fn does_not_follow_redirects_or_retry_http_failures() {
    let (reader, state) = make_reader("redirect").await;
    assert_eq!(
        reader.read_history(&request()).await.unwrap_err(),
        RpcPositionHistoryError::HttpStatus {
            status: 307,
            retry_after_seconds: None
        }
    );
    assert_eq!(state.count.load(Ordering::SeqCst), 1);

    let (reader, state) = make_reader("rate_limited").await;
    assert_eq!(
        reader.read_history(&request()).await.unwrap_err(),
        RpcPositionHistoryError::HttpStatus {
            status: 429,
            retry_after_seconds: Some(7),
        }
    );
    assert_eq!(state.count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancellation_yields_no_observation() {
    let (url, state) = server("delayed").await;
    let reader = Arc::new(RpcPositionHistoryReader::new(reqwest::Client::builder(), &url).unwrap());
    let task_reader = reader.clone();
    let task = tokio::spawn(async move { task_reader.read_history(&request()).await });
    while state.count.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
}
