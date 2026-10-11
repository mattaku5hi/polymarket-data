#![cfg(feature = "chain-audit")]

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router, body::Body, extract::State, http::Request, response::IntoResponse, routing::post,
};
use polymarket_data::{
    position_history::{CTF_EMITTER, TRANSFER_SINGLE_TOPIC},
    position_history_receipts::PositionHistoryReceiptJoinError,
    rpc_position_history::{
        RpcPositionHistoryError, RpcPositionHistoryReader, RpcPositionHistoryRequest,
        validate_position_history_segment_source_agreement,
    },
};
use serde_json::{Value, json};
use tokio::sync::Notify;

const HOLDER: &str = "0x1111111111111111111111111111111111111111";

#[derive(Clone)]
struct Replay {
    count: Arc<AtomicUsize>,
    mode: &'static str,
    start_entered: Arc<Notify>,
    release_start: Arc<Notify>,
}

async fn reader(mode: &'static str) -> (RpcPositionHistoryReader, Replay) {
    let replay = Replay {
        count: Arc::new(AtomicUsize::new(0)),
        mode,
        start_entered: Arc::new(Notify::new()),
        release_start: Arc::new(Notify::new()),
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

async fn handler(State(replay): State<Replay>, request: Request<Body>) -> impl IntoResponse {
    let call = replay.count.fetch_add(1, Ordering::SeqCst);
    let bytes = axum::body::to_bytes(request.into_body(), 64 * 1024)
        .await
        .unwrap();
    let request: Value = serde_json::from_slice(&bytes).unwrap();
    if replay.mode == "blocked_start" && call == 3 {
        replay.start_entered.notify_one();
        replay.release_start.notified().await;
    }
    let method = request["method"].as_str().unwrap();
    let result = match method {
        "eth_chainId" => json!("0x89"),
        "eth_getBlockByNumber" if request["params"][0] == "finalized" => {
            header(1_000, &hash(1_000))
        }
        "eth_getBlockByNumber" => {
            let number = u64::from_str_radix(
                request["params"][0]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
                16,
            )
            .unwrap();
            if replay.mode == "wrong_start_number" && number == 10 {
                header(11, &hash(11))
            } else if (replay.mode == "same_block_start_differs" && call == 3)
                || (matches!(replay.mode, "changed_start_parent" | "changed_start_root")
                    && number == 10)
            {
                let mut h = header(number, &hash(number));
                if replay.mode == "changed_start_root" {
                    h["stateRoot"] = json!(hash(99));
                } else {
                    h["parentHash"] = json!(hash(99));
                }
                h
            } else {
                header(number, &hash(number))
            }
        }
        "eth_getLogs" => {
            let filter = &request["params"][0];
            let from = u64::from_str_radix(
                filter["fromBlock"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
                16,
            )
            .unwrap();
            let through = u64::from_str_radix(
                filter["toBlock"].as_str().unwrap().trim_start_matches("0x"),
                16,
            )
            .unwrap();
            if replay.mode == "wrong_start_log_hash" {
                json!([log(10, &hash(9))])
            } else if replay.mode == "wrong_terminal_log_hash" {
                json!([log(15, &hash(14))])
            } else if replay.mode == "one_event" && from <= 12 && 12 <= through {
                json!([log(12, &hash(12))])
            } else {
                json!([])
            }
        }
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

fn header(number: u64, hash_value: &str) -> Value {
    json!({
        "number": format!("0x{number:x}"),
        "hash": hash_value,
        "parentHash": hash(number.saturating_sub(1)),
        "stateRoot": hash(number.saturating_add(1)),
        "transactionsRoot": hash(number.saturating_add(2)),
        "receiptsRoot": hash(number.saturating_add(3)),
        "logsBloom": format!("0x{}", "00".repeat(256)),
    })
}

fn log(number: u64, block_hash: &str) -> Value {
    let holder = format!("0x{:0>64}", &HOLDER[2..]);
    json!({
        "address": CTF_EMITTER,
        "topics": [
            TRANSFER_SINGLE_TOPIC,
            hash(0), holder, holder
        ],
        "data": "0x01",
        "blockNumber": format!("0x{number:x}"),
        "blockHash": block_hash,
        "transactionHash": hash(20),
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": false,
    })
}

fn request(from_block: u64, through_block: u64) -> RpcPositionHistoryRequest {
    RpcPositionHistoryRequest {
        holder_address: HOLDER.into(),
        from_block,
        through_block,
        expected_through_hash: hash(through_block),
        max_requests: 512,
        max_total_response_bytes: 32 * 1024 * 1024,
        total_timeout: Duration::from_secs(3),
    }
}

#[tokio::test]
async fn segment_adds_start_header_context_and_accepts_different_chunk_widths() {
    let (first, first_replay) = reader("one_event").await;
    let (second, second_replay) = reader("one_event").await;
    let request = request(10, 15);
    let first = first
        .read_history_segment_paginated(&request, 2)
        .await
        .unwrap();
    let second = second
        .read_history_segment_paginated(&request, 3)
        .await
        .unwrap();
    assert_eq!(first.start_block_number(), 10);
    assert_eq!(first.start_block_hash(), hash(10));
    assert_eq!(first.start_parent_hash(), hash(9));
    assert_eq!(first.history().logs().len(), 1);
    assert_eq!(first.history().logs()[0].block_number(), 12);
    assert_eq!(second.history().logs(), first.history().logs());
    assert_eq!(first.history().request_count(), 11);
    assert_eq!(first_replay.count.load(Ordering::SeqCst), 11);
    assert_eq!(second.history().request_count(), 9);
    assert_eq!(second_replay.count.load(Ordering::SeqCst), 9);
    validate_position_history_segment_source_agreement(&first, &second).unwrap();
}

#[tokio::test]
async fn segment_preflights_five_contexts_and_checks_start_header_number_and_single_block_equality()
{
    let (r, replay) = reader("ok").await;
    let mut insufficient = request(10, 10);
    insufficient.max_requests = 6;
    assert_eq!(
        r.read_history_segment_paginated(&insufficient, 1)
            .await
            .unwrap_err(),
        RpcPositionHistoryError::RequestBudgetExceeded
    );
    assert_eq!(replay.count.load(Ordering::SeqCst), 0);

    let (r, replay) = reader("wrong_start_number").await;
    assert_eq!(
        r.read_history_segment_paginated(&request(10, 15), 20)
            .await
            .unwrap_err(),
        RpcPositionHistoryError::ConflictingHeader
    );
    assert_eq!(replay.count.load(Ordering::SeqCst), 4);

    let (r, _) = reader("same_block_start_differs").await;
    assert_eq!(
        r.read_history_segment_paginated(&request(15, 15), 1)
            .await
            .unwrap_err(),
        RpcPositionHistoryError::ConflictingHeader
    );
}

#[tokio::test]
async fn segment_checks_log_hashes_at_both_boundary_blocks() {
    let (r, replay) = reader("wrong_start_log_hash").await;
    assert_eq!(
        r.read_history_segment_paginated(&request(10, 15), 20)
            .await
            .unwrap_err(),
        RpcPositionHistoryError::ConflictingHeader
    );
    assert_eq!(replay.count.load(Ordering::SeqCst), 5);

    let (r, _) = reader("wrong_terminal_log_hash").await;
    assert_eq!(
        r.read_history_segment_paginated(&request(10, 15), 20)
            .await
            .unwrap_err(),
        RpcPositionHistoryError::ConflictingHeader
    );
}

#[tokio::test]
async fn segment_source_agreement_includes_all_start_header_fields() {
    let (first, _) = reader("ok").await;
    let (second, _) = reader("ok").await;
    let request = request(10, 15);
    let first = first
        .read_history_segment_paginated(&request, 2)
        .await
        .unwrap();
    let second = second
        .read_history_segment_paginated(&request, 2)
        .await
        .unwrap();
    validate_position_history_segment_source_agreement(&first, &second).unwrap();

    let (changed_parent, _) = reader("changed_start_parent").await;
    let changed_parent = changed_parent
        .read_history_segment_paginated(&request, 2)
        .await
        .unwrap();
    assert_eq!(
        validate_position_history_segment_source_agreement(&first, &changed_parent),
        Err(PositionHistoryReceiptJoinError::SourceMismatch)
    );

    let (changed_root, _) = reader("changed_start_root").await;
    let changed_root = changed_root
        .read_history_segment_paginated(&request, 2)
        .await
        .unwrap();
    assert_eq!(
        validate_position_history_segment_source_agreement(&first, &changed_root),
        Err(PositionHistoryReceiptJoinError::SourceMismatch)
    );
}

#[tokio::test]
async fn segment_start_read_shares_response_budget_deadline_and_cancellation() {
    let (baseline_reader, _) = reader("ok").await;
    let baseline = baseline_reader
        .read_history_segment_paginated(&request(10, 15), 10)
        .await
        .unwrap();
    let pages = baseline.history().pages();
    let before_start_bytes = pages[..3]
        .iter()
        .map(|page| page.response_json().len())
        .sum::<usize>();
    let start_header_bytes = pages[3].response_json().len();

    let (r, replay) = reader("ok").await;
    let mut byte_limited = request(10, 15);
    byte_limited.max_total_response_bytes = before_start_bytes + start_header_bytes - 1;
    assert_eq!(
        r.read_history_segment_paginated(&byte_limited, 10)
            .await
            .unwrap_err(),
        RpcPositionHistoryError::BodyBudgetExceeded
    );
    assert_eq!(replay.count.load(Ordering::SeqCst), 4);

    let (r, replay) = reader("blocked_start").await;
    let task =
        tokio::spawn(async move { r.read_history_segment_paginated(&request(10, 15), 10).await });
    tokio::time::timeout(Duration::from_secs(2), replay.start_entered.notified())
        .await
        .expect("start-header RPC is in flight before advancing the clock");
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(4)).await;
    assert_eq!(
        task.await.unwrap().unwrap_err(),
        RpcPositionHistoryError::Timeout
    );
    assert_eq!(replay.count.load(Ordering::SeqCst), 4);
    replay.release_start.notify_one();
    tokio::time::resume();

    let (reader, replay) = reader("blocked_start").await;
    let task = tokio::spawn(async move {
        reader
            .read_history_segment_paginated(&request(10, 15), 10)
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), replay.start_entered.notified())
        .await
        .expect("start-header request begins after the terminal anchor");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(replay.count.load(Ordering::SeqCst), 4);
    replay.release_start.notify_one();
}
