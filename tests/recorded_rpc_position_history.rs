#![cfg(feature = "chain-audit")]

use std::{sync::Arc, time::Duration};

use axum::{
    Router, body::Body, extract::State, http::Request, response::IntoResponse, routing::post,
};
use polymarket_data::{
    position_history::{
        CTF_EMITTER, POSITION_MANAGER_EMITTER, RecordedSqdPositionHistoryPage,
        SqdPositionHistoryReader, SqdPositionHistoryRequest, TRANSFER_BATCH_TOPIC,
        TRANSFER_SINGLE_TOPIC, reverify_recorded_sqd_position_history_segment,
    },
    rpc_position_history::{
        RecordedRpcPositionHistoryPage, RpcPositionHistoryError, RpcPositionHistoryReader,
        RpcPositionHistoryRequest, reverify_recorded_rpc_position_history_segment,
        validate_recorded_position_history_segment_source_agreement,
        validate_recorded_rpc_sqd_position_history_segment_source_agreement,
    },
};
use serde_json::{Value, json};
use tokio::sync::Mutex;

const HOLDER: &str = "0x1111111111111111111111111111111111111111";
const OTHER: &str = "0x2222222222222222222222222222222222222222";

#[derive(Clone)]
struct Replay {
    event: Option<Value>,
    calls: Arc<Mutex<Vec<String>>>,
}

async fn reader(event: Option<Value>) -> (RpcPositionHistoryReader, Replay) {
    let replay = Replay {
        event,
        calls: Arc::new(Mutex::new(Vec::new())),
    };
    let app = Router::new()
        .route("/rpc", post(handler))
        .with_state(replay.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let reader =
        RpcPositionHistoryReader::new(reqwest::Client::builder(), &format!("http://{address}/rpc"))
            .unwrap();
    (reader, replay)
}

async fn sqd_transcript() -> (
    polymarket_data::position_history::SqdPositionHistoryObservation,
    Vec<RecordedSqdPositionHistoryPage>,
) {
    let app = Router::new().route("/dataset/finalized-stream", post(sqd_handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let reader = SqdPositionHistoryReader::new(
        reqwest::Client::builder(),
        &format!("http://{address}/dataset"),
    )
    .unwrap();
    let observation = reader.read_history(&sqd_request()).await.unwrap();
    let pages = observation
        .pages()
        .iter()
        .map(|page| RecordedSqdPositionHistoryPage {
            direction: page.direction(),
            cursor: page.cursor(),
            last_block: page.last_block(),
            request_body: page.request_body().to_owned(),
            response_body: page.response_body().to_owned(),
        })
        .collect();
    (observation, pages)
}

async fn sqd_handler(request: Request<Body>) -> impl IntoResponse {
    let bytes = axum::body::to_bytes(request.into_body(), 64 * 1024)
        .await
        .unwrap();
    let query: Value = serde_json::from_slice(&bytes).unwrap();
    let direction = if query["logs"][0].get("topic2").is_some() {
        "from"
    } else {
        "to"
    };
    let event = transfer(
        POSITION_MANAGER_EMITTER,
        TRANSFER_BATCH_TOPIC,
        HOLDER,
        HOLDER,
    );
    let mut records = Vec::new();
    for n in 10..=15 {
        let block_hash = hash(n);
        let header = json!({
            "number":n, "hash":block_hash, "parentHash":hash(n.saturating_sub(1)),
            "stateRoot":hash(n.saturating_add(1)), "transactionsRoot":hash(n.saturating_add(2)),
            "receiptsRoot":hash(n.saturating_add(3)), "logsBloom":format!("0x{}", "00".repeat(256)),
        });
        let logs = if n == 12 {
            let rpc_log = event.clone();
            json!([{
                "address":rpc_log["address"], "topics":rpc_log["topics"], "data":rpc_log["data"],
                "transactionHash":rpc_log["transactionHash"], "transactionIndex":rpc_log["transactionIndex"],
                "logIndex":rpc_log["logIndex"],
            }])
        } else {
            json!([])
        };
        records.push(json!({"header":header,"logs":logs}));
    }
    let _ = direction;
    (
        axum::http::StatusCode::OK,
        records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )
}

fn sqd_request() -> SqdPositionHistoryRequest {
    SqdPositionHistoryRequest {
        holder_address: HOLDER.to_owned(),
        from_block: 10,
        through_block: 15,
        expected_through_hash: hash(15),
        max_requests: 16,
        max_total_response_bytes: 8 * 1024 * 1024,
        total_timeout: Duration::from_secs(3),
    }
}

async fn handler(State(replay): State<Replay>, request: Request<Body>) -> impl IntoResponse {
    let bytes = axum::body::to_bytes(request.into_body(), 64 * 1024)
        .await
        .unwrap();
    let request: Value = serde_json::from_slice(&bytes).unwrap();
    replay
        .calls
        .lock()
        .await
        .push(request["method"].as_str().unwrap().to_owned());
    let result = match request["method"].as_str().unwrap() {
        "eth_chainId" => json!("0x89"),
        "eth_getBlockByNumber" if request["params"][0] == "finalized" => {
            header(1_000, &hash(1_000))
        }
        "eth_getBlockByNumber" => {
            let number = parse_quantity(&request["params"][0]);
            header(number, &hash(number))
        }
        "eth_getLogs" => {
            let filter = &request["params"][0];
            let event = replay.event.as_ref().filter(|event| {
                let number = parse_quantity(&event["blockNumber"]);
                let topics = event["topics"].as_array().unwrap();
                let filter_topics = filter["topics"].as_array().unwrap();
                number >= parse_quantity(&filter["fromBlock"])
                    && number <= parse_quantity(&filter["toBlock"])
                    && filter["address"]
                        .as_array()
                        .unwrap()
                        .contains(&event["address"])
                    && topic_matches(&filter_topics[0], &topics[0])
                    && topic_matches(&filter_topics[2], &topics[2])
                    && topic_matches(&filter_topics[3], &topics[3])
            });
            event.map_or_else(|| json!([]), |event| json!([event]))
        }
        _ => unreachable!(),
    };
    (
        axum::http::StatusCode::OK,
        json!({"jsonrpc":"2.0", "id":request["id"], "result":result}).to_string(),
    )
}

fn topic_matches(filter: &Value, actual: &Value) -> bool {
    filter.is_null()
        || filter == actual
        || filter
            .as_array()
            .is_some_and(|topics| topics.iter().any(|topic| topic == actual))
}

fn parse_quantity(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn hash(number: u64) -> String {
    format!("0x{number:064x}")
}

fn header(number: u64, block_hash: &str) -> Value {
    json!({
        "number": format!("0x{number:x}"),
        "hash": block_hash,
        "parentHash": hash(number.saturating_sub(1)),
        "stateRoot": hash(number.saturating_add(1)),
        "transactionsRoot": hash(number.saturating_add(2)),
        "receiptsRoot": hash(number.saturating_add(3)),
        "logsBloom": format!("0x{}", "00".repeat(256)),
    })
}

fn transfer(emitter: &str, topic: &str, from: &str, to: &str) -> Value {
    json!({
        "address": emitter,
        "topics": [topic, hash(7), format!("0x{:0>64}", &from[2..]), format!("0x{:0>64}", &to[2..])],
        "data": "0x01",
        "blockNumber": "0xc",
        "blockHash": hash(12),
        "transactionHash": hash(20),
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": false,
    })
}

fn request() -> RpcPositionHistoryRequest {
    RpcPositionHistoryRequest {
        holder_address: HOLDER.to_owned(),
        from_block: 10,
        through_block: 15,
        expected_through_hash: hash(15),
        max_requests: 512,
        max_total_response_bytes: 32 * 1024 * 1024,
        total_timeout: Duration::from_secs(3),
    }
}

async fn online_capture(
    event: Option<Value>,
    width: u64,
) -> (
    polymarket_data::rpc_position_history::RpcPositionHistorySegmentObservation,
    Vec<RecordedRpcPositionHistoryPage>,
) {
    let (reader, _) = reader(event).await;
    let observation = reader
        .read_history_segment_paginated(&request(), width)
        .await
        .unwrap();
    let pages = observation
        .history()
        .pages()
        .iter()
        .map(|page| RecordedRpcPositionHistoryPage {
            request_json: page.request_json().to_owned(),
            response_json: page.response_json().to_owned(),
        })
        .collect();
    (observation, pages)
}

#[tokio::test]
async fn recorded_replay_matches_empty_and_both_ledger_transfer_directions() {
    let cases = [
        (None, 2),
        (
            Some(transfer(CTF_EMITTER, TRANSFER_SINGLE_TOPIC, HOLDER, OTHER)),
            2,
        ),
        (
            Some(transfer(
                POSITION_MANAGER_EMITTER,
                TRANSFER_BATCH_TOPIC,
                OTHER,
                HOLDER,
            )),
            3,
        ),
        (
            Some(transfer(CTF_EMITTER, TRANSFER_SINGLE_TOPIC, HOLDER, HOLDER)),
            3,
        ),
    ];
    for (event, width) in cases {
        let (online, pages) = online_capture(event, width).await;
        let recorded = reverify_recorded_rpc_position_history_segment(&request(), width, &pages)
            .await
            .unwrap();
        assert_eq!(recorded.holder_address(), online.history().holder_address());
        assert_eq!(recorded.from_block(), online.history().from_block());
        assert_eq!(recorded.through_block(), online.history().through_block());
        assert_eq!(
            recorded.expected_through_hash(),
            online.history().expected_through_hash()
        );
        assert_eq!(recorded.start_block_number(), online.start_block_number());
        assert_eq!(recorded.start_block_hash(), online.start_block_hash());
        assert_eq!(recorded.start_parent_hash(), online.start_parent_hash());
        assert_eq!(recorded.terminal_hash(), online.history().terminal_hash());
        assert_eq!(
            recorded.terminal_state_root(),
            online.history().terminal_state_root()
        );
        assert_eq!(
            recorded.terminal_transactions_root(),
            online.history().terminal_transactions_root()
        );
        assert_eq!(
            recorded.terminal_receipts_root(),
            online.history().terminal_receipts_root()
        );
        assert_eq!(recorded.logs(), online.history().logs());
        assert_eq!(recorded.pages().len(), pages.len());
        assert_eq!(recorded.request_count(), online.history().request_count());
        assert_eq!(recorded.response_bytes(), online.history().response_bytes());
    }
}

#[tokio::test]
async fn recorded_transcript_rejects_sequence_identity_filter_and_size_mutations() {
    let (_, original) = online_capture(
        Some(transfer(
            POSITION_MANAGER_EMITTER,
            TRANSFER_SINGLE_TOPIC,
            HOLDER,
            OTHER,
        )),
        2,
    )
    .await;

    let mut reordered = original.clone();
    reordered.swap(0, 1);
    assert!(
        reverify_recorded_rpc_position_history_segment(&request(), 2, &reordered)
            .await
            .is_err()
    );
    assert!(
        reverify_recorded_rpc_position_history_segment(
            &request(),
            2,
            &original[..original.len() - 1]
        )
        .await
        .is_err()
    );
    let mut extra = original.clone();
    extra.push(original[0].clone());
    assert!(
        reverify_recorded_rpc_position_history_segment(&request(), 2, &extra)
            .await
            .is_err()
    );

    for mutate in ["id", "method", "filter"] {
        let mut changed = original.clone();
        let index = if mutate == "filter" {
            changed
                .iter()
                .position(|page| {
                    serde_json::from_str::<Value>(&page.request_json)
                        .is_ok_and(|request| request["method"] == "eth_getLogs")
                })
                .unwrap()
        } else {
            0
        };
        let value = &mut changed[index].request_json;
        let mut json: Value = serde_json::from_str(value).unwrap();
        match mutate {
            "id" => json["id"] = json!(999),
            "method" => json["method"] = json!("eth_getBlockByHash"),
            _ => json["params"][0]["fromBlock"] = json!("0xb"),
        }
        *value = json.to_string();
        assert!(
            reverify_recorded_rpc_position_history_segment(&request(), 2, &changed)
                .await
                .is_err()
        );
    }
    let mut oversized = original.clone();
    oversized[0].request_json = format!("{}{}", oversized[0].request_json, " ".repeat(4096));
    assert_eq!(
        reverify_recorded_rpc_position_history_segment(&request(), 2, &oversized)
            .await
            .unwrap_err(),
        RpcPositionHistoryError::BodyBudgetExceeded
    );
}

#[tokio::test]
async fn recorded_response_and_boundary_mutations_refuse_the_whole_transcript() {
    let (_, original) = online_capture(
        Some(transfer(CTF_EMITTER, TRANSFER_SINGLE_TOPIC, OTHER, HOLDER)),
        3,
    )
    .await;
    for mutate in [
        "id",
        "header",
        "start_header",
        "log",
        "emitter",
        "holder",
        "removed",
        "conflict",
    ] {
        let mut changed = original.clone();
        let index = match mutate {
            "header" => 2,
            "start_header" => 3,
            "log" | "emitter" | "holder" | "removed" | "conflict" => 5,
            _ => 0,
        };
        let mut response: Value = serde_json::from_str(&changed[index].response_json).unwrap();
        match mutate {
            "id" => response["id"] = json!(444),
            "header" => response["result"]["parentHash"] = json!(hash(77)),
            "start_header" => response["result"]["number"] = json!("0xb"),
            "log" => {
                response["result"][0]["blockNumber"] = json!("0xa");
                response["result"][0]["blockHash"] = json!(hash(77));
            }
            "emitter" => response["result"][0]["address"] = json!(OTHER),
            "holder" => {
                response["result"][0]["topics"][3] = json!(format!("0x{:0>64}", &OTHER[2..]));
            }
            "removed" => response["result"][0]["removed"] = json!(true),
            _ => {
                let mut duplicate = response["result"][0].clone();
                duplicate["data"] = json!("0x02");
                response["result"].as_array_mut().unwrap().push(duplicate);
            }
        }
        changed[index].response_json = response.to_string();
        assert!(
            reverify_recorded_rpc_position_history_segment(&request(), 3, &changed)
                .await
                .is_err()
        );
    }

    let mut rpc_error = original.clone();
    let last_page = rpc_error.len() - 1;
    let mut response: Value = serde_json::from_str(&rpc_error[last_page].response_json).unwrap();
    response.as_object_mut().unwrap().remove("result");
    response["error"] = json!({"code": -32000, "message": "fixture error"});
    rpc_error[last_page].response_json = response.to_string();
    assert!(
        reverify_recorded_rpc_position_history_segment(&request(), 3, &rpc_error)
            .await
            .is_err()
    );

    let mut low_budget = request();
    low_budget.max_total_response_bytes = 1;
    assert_eq!(
        reverify_recorded_rpc_position_history_segment(&low_budget, 3, &original)
            .await
            .unwrap_err(),
        RpcPositionHistoryError::BodyBudgetExceeded
    );

    let mut too_many_bytes = original.clone();
    too_many_bytes[0].response_json = format!(
        "{}{}",
        too_many_bytes[0].response_json,
        " ".repeat(2 * 1024 * 1024)
    );
    assert_eq!(
        reverify_recorded_rpc_position_history_segment(&request(), 3, &too_many_bytes)
            .await
            .unwrap_err(),
        RpcPositionHistoryError::BodyBudgetExceeded
    );

    let mut insufficient = request();
    insufficient.max_requests = 8;
    assert_eq!(
        reverify_recorded_rpc_position_history_segment(&insufficient, 2, &original)
            .await
            .unwrap_err(),
        RpcPositionHistoryError::RequestBudgetExceeded
    );
}

#[tokio::test]
async fn paired_recorded_segments_agree_across_chunk_widths_and_refuse_changed_logs() {
    let event = Some(transfer(
        POSITION_MANAGER_EMITTER,
        TRANSFER_BATCH_TOPIC,
        HOLDER,
        HOLDER,
    ));
    let (_, pages_a) = online_capture(event.clone(), 2).await;
    let (_, pages_b) = online_capture(event, 3).await;
    let first = reverify_recorded_rpc_position_history_segment(&request(), 2, &pages_a)
        .await
        .unwrap();
    let second = reverify_recorded_rpc_position_history_segment(&request(), 3, &pages_b)
        .await
        .unwrap();
    validate_recorded_position_history_segment_source_agreement(&first, &second).unwrap();

    let mut changed_start_pages = pages_b.clone();
    let mut start_header_response: Value =
        serde_json::from_str(&changed_start_pages[3].response_json).unwrap();
    start_header_response["result"]["parentHash"] = json!(hash(77));
    changed_start_pages[3].response_json = start_header_response.to_string();
    let changed_start =
        reverify_recorded_rpc_position_history_segment(&request(), 3, &changed_start_pages)
            .await
            .unwrap();
    assert!(
        validate_recorded_position_history_segment_source_agreement(&first, &changed_start)
            .is_err()
    );

    let (_, empty_pages) = online_capture(None, 3).await;
    let empty = reverify_recorded_rpc_position_history_segment(&request(), 3, &empty_pages)
        .await
        .unwrap();
    assert!(validate_recorded_position_history_segment_source_agreement(&first, &empty).is_err());
}

#[tokio::test]
async fn recorded_rpc_and_sqd_segments_require_matching_scope_headers_and_physical_logs() {
    let event = Some(transfer(
        POSITION_MANAGER_EMITTER,
        TRANSFER_BATCH_TOPIC,
        HOLDER,
        HOLDER,
    ));
    let (_, rpc_pages) = online_capture(event, 2).await;
    let rpc = reverify_recorded_rpc_position_history_segment(&request(), 2, &rpc_pages)
        .await
        .unwrap();
    let (sqd_live, sqd_pages) = sqd_transcript().await;
    let (rpc_live, _) = online_capture(
        Some(transfer(
            POSITION_MANAGER_EMITTER,
            TRANSFER_BATCH_TOPIC,
            HOLDER,
            HOLDER,
        )),
        2,
    )
    .await;
    polymarket_data::rpc_position_history::validate_rpc_sqd_position_history_segment_source_agreement(
        &rpc_live, &sqd_live,
    ).unwrap();
    let sqd = reverify_recorded_sqd_position_history_segment(&sqd_request(), &sqd_pages)
        .await
        .unwrap();
    validate_recorded_rpc_sqd_position_history_segment_source_agreement(&rpc, &sqd).unwrap();

    let mut changed_logs = sqd_pages.clone();
    for page in &mut changed_logs {
        page.response_body = page.response_body.replace("0x01", "0x02");
    }
    let changed = reverify_recorded_sqd_position_history_segment(&sqd_request(), &changed_logs)
        .await
        .unwrap();
    assert!(
        validate_recorded_rpc_sqd_position_history_segment_source_agreement(&rpc, &changed)
            .is_err()
    );

    let mut changed_header = sqd_pages.clone();
    for page in &mut changed_header {
        page.response_body = page.response_body.replace(
            &format!("\"stateRoot\":\"{}\"", hash(11)),
            &format!("\"stateRoot\":\"{}\"", hash(90)),
        );
    }
    let changed = reverify_recorded_sqd_position_history_segment(&sqd_request(), &changed_header)
        .await
        .unwrap();
    assert!(
        validate_recorded_rpc_sqd_position_history_segment_source_agreement(&rpc, &changed)
            .is_err()
    );
}

#[tokio::test]
async fn recorded_replay_uses_one_deadline_for_all_pages() {
    let (_, pages) = online_capture(None, 2).await;
    let mut request = request();
    request.total_timeout = Duration::from_nanos(1);
    assert_eq!(
        reverify_recorded_rpc_position_history_segment(&request, 2, &pages)
            .await
            .unwrap_err(),
        RpcPositionHistoryError::Timeout
    );
}
