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
use polymarket_data::position_history::{
    CTF_EMITTER, MAX_HISTORY_RESPONSE_BYTES, POSITION_MANAGER_EMITTER, PositionHistoryDirection,
    PositionHistoryError, PositionLedger, SqdPositionHistoryReader, SqdPositionHistoryRequest,
    TRANSFER_SINGLE_TOPIC,
};
use serde_json::{Value, json};
use tokio::net::TcpListener;

const HOLDER: &str = "0x1111111111111111111111111111111111111111";
const HASH15: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TX: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[derive(Clone)]
struct ServerState {
    requests: Arc<AtomicUsize>,
    mode: &'static str,
}

async fn server(mode: &'static str) -> (String, ServerState) {
    let state = ServerState {
        requests: Arc::new(AtomicUsize::new(0)),
        mode,
    };
    let app = Router::new()
        .route("/dataset/finalized-stream", post(handler))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}/dataset"), state)
}

async fn handler(State(state): State<ServerState>, request: Request<Body>) -> Response {
    let number = state.requests.fetch_add(1, Ordering::SeqCst);
    if request
        .headers()
        .get("accept")
        .and_then(|value| value.to_str().ok())
        != Some("application/x-ndjson")
    {
        return (StatusCode::BAD_REQUEST, "wrong accept".to_owned()).into_response();
    }
    let bytes = to_bytes(request.into_body(), 128 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let from = body["fromBlock"].as_u64().unwrap();
    let direction = if body["logs"][0].get("topic2").is_some() {
        "from"
    } else {
        "to"
    };
    if state.mode == "status_529" {
        return Response::builder()
            .status(StatusCode::from_u16(529).unwrap())
            .header("retry-after", "10")
            .body(Body::empty())
            .unwrap();
    }
    if state.mode == "invalid_json" {
        return (StatusCode::OK, "{".to_owned()).into_response();
    }
    if state.mode == "delayed" {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if state.mode == "oversize" {
        return (StatusCode::OK, " ".repeat(MAX_HISTORY_RESPONSE_BYTES + 1)).into_response();
    }

    let (blocks, data) = match state.mode {
        "wrong_hash" => (vec![10, 15], None),
        "early_cursor" => (vec![from + 1, 15], None),
        "wrong_holder" => (vec![from, 15], Some("wrong_holder")),
        "wrong_emitter" => (vec![from, 15], Some("wrong_emitter")),
        "wrong_topic" => (vec![from, 15], Some("wrong_topic")),
        "conflict" => (vec![from, 15], Some("conflict")),
        _ if direction == "from" && from == 10 => (vec![10, 12], None),
        _ if direction == "from" => (vec![from, 15], None),
        _ => (vec![10, 15], None),
    };
    let mut records = Vec::new();
    for block_number in blocks {
        let is_terminal = block_number == 15;
        let hash = if is_terminal && state.mode != "wrong_hash" {
            HASH15.to_owned()
        } else {
            hash_for(block_number)
        };
        let mut header_value = header(block_number, &hash);
        if state.mode == "header_conflict" && direction == "to" && is_terminal {
            header_value["stateRoot"] = json!(hash_for(100));
        }
        if state.mode == "bad_parent" && direction == "from" && block_number == 13 {
            header_value["parentHash"] = json!(hash_for(999));
        }
        let mut record = json!({
            "header": header_value,
            "logs": []
        });
        if (state.mode != "wrong_hash" && state.mode != "early_cursor") && block_number == 15 {
            let mut entry = log(
                direction,
                data,
                if state.mode == "conflict" && direction == "to" {
                    "0xdead"
                } else {
                    "0x01"
                },
            );
            if let Some(log) = entry.as_object_mut() {
                if state.mode == "conflict" && direction == "to" {
                    log.insert(
                        "transactionHash".into(),
                        json!("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
                    );
                }
                if data == Some("wrong_holder") {
                    log.insert(
                        "topics".into(),
                        json!([TRANSFER_SINGLE_TOPIC, zero_hash(), zero_hash(), zero_hash()]),
                    );
                }
                if data == Some("wrong_emitter") {
                    log.insert(
                        "address".into(),
                        json!("0x2222222222222222222222222222222222222222"),
                    );
                }
                if data == Some("wrong_topic") {
                    log.insert(
                        "topics".into(),
                        json!([zero_hash(), zero_hash(), holder_topic(), holder_topic()]),
                    );
                }
            }
            record["logs"] = json!([entry]);
        }
        records.push(record);
    }
    let _ = number;
    (
        StatusCode::OK,
        records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )
        .into_response()
}

fn zero_hash() -> String {
    format!("0x{}", "00".repeat(32))
}
fn holder_topic() -> String {
    format!("0x{:0>64}", &HOLDER[2..])
}
fn hash_for(block: u64) -> String {
    format!("0x{block:064x}")
}
fn header(number: u64, hash: &str) -> Value {
    json!({"number": number, "hash": hash, "parentHash": hash_for(number.saturating_sub(1)),
        "stateRoot": hash_for(number + 1), "transactionsRoot": hash_for(number + 2),
        "receiptsRoot": hash_for(number + 3), "logsBloom": format!("0x{}", "00".repeat(256))})
}
fn log(direction: &str, mutate: Option<&str>, data: &str) -> Value {
    let _ = direction;
    let topics = vec![
        TRANSFER_SINGLE_TOPIC.to_owned(),
        zero_hash(),
        holder_topic(),
        holder_topic(),
    ];
    let mut entry = json!({"address": CTF_EMITTER, "topics": topics, "data": data,
        "transactionHash": TX, "transactionIndex": "0x2", "logIndex": "0x3"});
    if mutate == Some("wrong_holder") {
        entry["topics"][2] = json!(zero_hash());
    }
    entry
}
fn request() -> SqdPositionHistoryRequest {
    SqdPositionHistoryRequest {
        holder_address: HOLDER.into(),
        from_block: 10,
        through_block: 15,
        expected_through_hash: HASH15.into(),
        max_requests: 8,
        max_total_response_bytes: 8 * 1024 * 1024,
        total_timeout: Duration::from_secs(3),
    }
}
async fn make_reader(mode: &'static str) -> (SqdPositionHistoryReader, ServerState) {
    let (base, state) = server(mode).await;
    let reader = SqdPositionHistoryReader::new(reqwest::Client::builder(), &base).unwrap();
    (reader, state)
}

#[tokio::test]
async fn paginates_sparse_pages_keeps_filter_evidence_and_deduplicates_self_transfer() {
    let (reader, state) = make_reader("ok").await;
    let observation = reader.read_history(&request()).await.unwrap();
    assert_eq!(observation.request_count(), 3);
    assert_eq!(observation.pages().len(), 3);
    assert_eq!(observation.logs().len(), 1); // exact self-transfer appears in both directions once
    assert_eq!(observation.logs()[0].ledger(), PositionLedger::Ctf);
    assert_eq!(observation.pages()[0].last_block(), 12); // sparse interior blocks are valid
    let first: Value = serde_json::from_str(observation.pages()[0].request_body()).unwrap();
    assert_eq!(first["fromBlock"], 10);
    assert_eq!(first["toBlock"], 15);
    assert_eq!(
        first["logs"][0]["address"],
        json!([CTF_EMITTER, POSITION_MANAGER_EMITTER])
    );
    assert_eq!(first["logs"].as_array().unwrap().len(), 2);
    assert_eq!(first["logs"][0]["topic0"].as_array().unwrap().len(), 1);
    assert_eq!(first["logs"][1]["topic0"].as_array().unwrap().len(), 1);
    for field in [
        "number",
        "hash",
        "parentHash",
        "stateRoot",
        "transactionsRoot",
        "receiptsRoot",
        "logsBloom",
    ] {
        assert_eq!(first["fields"]["block"][field], true);
    }
    for field in [
        "address",
        "topics",
        "data",
        "transactionHash",
        "transactionIndex",
        "logIndex",
    ] {
        assert_eq!(first["fields"]["log"][field], true);
    }
    assert_eq!(first["logs"][0]["topic0"][0], TRANSFER_SINGLE_TOPIC);
    assert_eq!(
        first["logs"][1]["topic0"][0],
        polymarket_data::position_history::TRANSFER_BATCH_TOPIC
    );
    assert!(first["logs"][0].get("topic2").is_some());
    let to: Value = serde_json::from_str(observation.pages()[2].request_body()).unwrap();
    assert!(to["logs"][0].get("topic3").is_some());
    assert!(to["logs"][0].get("topic2").is_none());
    assert_eq!(observation.from_terminal().hash(), HASH15);
    assert_eq!(state.requests.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn rejects_conflicts_wrong_identity_topics_early_cursor_and_anchor_mismatch() {
    for (mode, expected) in [
        ("conflict", PositionHistoryError::ConflictingLocator),
        (
            "wrong_holder",
            PositionHistoryError::FilterMismatch(PositionHistoryDirection::From),
        ),
        (
            "wrong_emitter",
            PositionHistoryError::FilterMismatch(PositionHistoryDirection::From),
        ),
        (
            "wrong_topic",
            PositionHistoryError::FilterMismatch(PositionHistoryDirection::From),
        ),
        (
            "early_cursor",
            PositionHistoryError::InvalidPageCursor(PositionHistoryDirection::From),
        ),
        ("wrong_hash", PositionHistoryError::AnchorMismatch),
        ("header_conflict", PositionHistoryError::ConflictingHeader),
        ("bad_parent", PositionHistoryError::ConflictingHeader),
    ] {
        let (reader, _) = make_reader(mode).await;
        assert_eq!(
            reader.read_history(&request()).await.unwrap_err(),
            expected,
            "mode={mode}"
        );
    }
}

#[tokio::test]
async fn reports_sqd_backpressure_status_and_retry_after_without_retrying() {
    let (reader, state) = make_reader("status_529").await;
    assert_eq!(
        reader.read_history(&request()).await.unwrap_err(),
        PositionHistoryError::RateLimited {
            direction: PositionHistoryDirection::From,
            status: 529,
            retry_after_seconds: Some(10),
        }
    );
    assert_eq!(state.requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn rejects_malformed_body_request_exhaustion_and_deadline_without_observation() {
    let (invalid_reader, _) = make_reader("invalid_json").await;
    assert_eq!(
        invalid_reader.read_history(&request()).await.unwrap_err(),
        PositionHistoryError::MalformedResponse(PositionHistoryDirection::From)
    );

    let (reader, state) = make_reader("ok").await;
    let mut bounded = request();
    bounded.max_requests = 2;
    assert_eq!(
        reader.read_history(&bounded).await.unwrap_err(),
        PositionHistoryError::RequestBudgetExceeded
    );
    assert_eq!(state.requests.load(Ordering::SeqCst), 2);

    let (reader, _) = make_reader("delayed").await;
    let mut short = request();
    short.total_timeout = Duration::from_millis(5);
    assert_eq!(
        reader.read_history(&short).await.unwrap_err(),
        PositionHistoryError::Timeout(PositionHistoryDirection::From)
    );
}

#[tokio::test]
async fn enforces_response_limit_and_caller_input_bounds() {
    let (oversize_reader, _) = make_reader("oversize").await;
    assert_eq!(
        oversize_reader.read_history(&request()).await.unwrap_err(),
        PositionHistoryError::BodyBudgetExceeded
    );
    let (reader, _) = make_reader("ok").await;
    let mut invalid = request();
    invalid.holder_address = "0x0000000000000000000000000000000000000000".into();
    assert_eq!(
        reader.read_history(&invalid).await.unwrap_err(),
        PositionHistoryError::InvalidInput
    );
}

#[tokio::test]
async fn cancellation_returns_no_prefix_observation() {
    let (base, _) = server("delayed").await;
    let reader =
        Arc::new(SqdPositionHistoryReader::new(reqwest::Client::builder(), &base).unwrap());
    let task_reader = reader.clone();
    let task = tokio::spawn(async move { task_reader.read_history(&request()).await });
    tokio::time::sleep(Duration::from_millis(5)).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
}
