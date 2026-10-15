#![cfg(feature = "chain-audit")]

use std::{sync::Arc, time::Duration};

use axum::{
    Router, body::Body, extract::State, http::Request, response::IntoResponse, routing::post,
};
use polymarket_data::{
    position_history::PositionHistoryDirection,
    rpc_position_history::{
        RpcPositionHistoryError, RpcPositionHistoryFailure, RpcPositionHistoryReader,
        RpcPositionHistoryRequest, RpcPositionHistoryRequestMethod, RpcPositionHistoryRequestPhase,
    },
};
use serde_json::{Value, json};
use tokio::sync::Mutex;

const HOLDER_A: &str = "0x1111111111111111111111111111111111111111";
const HOLDER_B: &str = "0x3333333333333333333333333333333333333333";
const SENSITIVE_MESSAGE: &str = "provider response must remain private";

#[derive(Clone)]
struct ServerState {
    failures: Arc<Vec<FailureRule>>,
    fail_ordinal: Option<u64>,
    calls: Arc<Mutex<Vec<(u64, String)>>>,
}

#[derive(Clone)]
struct FailureRule {
    holder: String,
    direction: PositionHistoryDirection,
}

async fn reader(failures: Vec<FailureRule>) -> (RpcPositionHistoryReader, ServerState) {
    reader_with_ordinal(failures, None).await
}

async fn reader_with_ordinal(
    failures: Vec<FailureRule>,
    fail_ordinal: Option<u64>,
) -> (RpcPositionHistoryReader, ServerState) {
    let state = ServerState {
        failures: Arc::new(failures),
        fail_ordinal,
        calls: Arc::new(Mutex::new(Vec::new())),
    };
    let app = Router::new()
        .route("/rpc", post(handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let reader =
        RpcPositionHistoryReader::new(reqwest::Client::builder(), &format!("http://{address}/rpc"))
            .unwrap();
    (reader, state)
}

async fn handler(State(state): State<ServerState>, request: Request<Body>) -> impl IntoResponse {
    let bytes = axum::body::to_bytes(request.into_body(), 64 * 1024)
        .await
        .unwrap();
    let request: Value = serde_json::from_slice(&bytes).unwrap();
    let ordinal = request["id"].as_u64().unwrap();
    let method = request["method"].as_str().unwrap().to_owned();
    state.calls.lock().await.push((ordinal, method.clone()));
    if state.fail_ordinal == Some(ordinal) || fails(&state.failures, &request) {
        return (
            axum::http::StatusCode::OK,
            json!({
                "jsonrpc": "2.0",
                "id": ordinal,
                "error": {"code": -32603, "message": SENSITIVE_MESSAGE}
            })
            .to_string(),
        );
    }
    let result = match method.as_str() {
        "eth_chainId" => json!("0x89"),
        "eth_getBlockByNumber" if request["params"][0] == "finalized" => header(1_000),
        "eth_getBlockByNumber" => header(parse_quantity(&request["params"][0])),
        "eth_getLogs" => json!([]),
        _ => unreachable!(),
    };
    (
        axum::http::StatusCode::OK,
        json!({"jsonrpc":"2.0", "id":ordinal, "result":result}).to_string(),
    )
}

fn fails(rules: &[FailureRule], request: &Value) -> bool {
    if request["method"] != "eth_getLogs" {
        return false;
    }
    let topics = &request["params"][0]["topics"];
    rules.iter().any(|rule| match rule.direction {
        PositionHistoryDirection::From => topics[2] == holder_topic(&rule.holder),
        PositionHistoryDirection::To => topics[3] == holder_topic(&rule.holder),
    })
}

fn holder_topic(holder: &str) -> String {
    format!("0x{:0>64}", &holder[2..])
}

fn request(holder: &str) -> RpcPositionHistoryRequest {
    RpcPositionHistoryRequest {
        holder_address: holder.to_owned(),
        from_block: 10,
        through_block: 15,
        expected_through_hash: hash(15),
        max_requests: 32,
        max_total_response_bytes: 2 * 1024 * 1024,
        total_timeout: Duration::from_secs(3),
    }
}

fn parse_quantity(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn hash(number: u64) -> String {
    format!("0x{number:064x}")
}

fn header(number: u64) -> Value {
    json!({
        "number": format!("0x{number:x}"),
        "hash": hash(number),
        "parentHash": hash(number.saturating_sub(1)),
        "stateRoot": hash(number.saturating_add(1)),
        "transactionsRoot": hash(number.saturating_add(2)),
        "receiptsRoot": hash(number.saturating_add(3)),
        "logsBloom": format!("0x{}", "00".repeat(256)),
    })
}

fn expected_locator(
    ordinal: u64,
) -> (
    RpcPositionHistoryRequestMethod,
    RpcPositionHistoryRequestPhase,
) {
    match ordinal {
        1 => (
            RpcPositionHistoryRequestMethod::ChainId,
            RpcPositionHistoryRequestPhase::Chain,
        ),
        2 => (
            RpcPositionHistoryRequestMethod::GetBlockByNumber,
            RpcPositionHistoryRequestPhase::Finalized,
        ),
        3 => (
            RpcPositionHistoryRequestMethod::GetBlockByNumber,
            RpcPositionHistoryRequestPhase::TerminalBefore,
        ),
        4 => (
            RpcPositionHistoryRequestMethod::GetBlockByNumber,
            RpcPositionHistoryRequestPhase::StartHeader,
        ),
        5 => (
            RpcPositionHistoryRequestMethod::GetLogs,
            RpcPositionHistoryRequestPhase::Logs {
                direction: PositionHistoryDirection::From,
                from_block: 10,
                through_block: 15,
            },
        ),
        6 => (
            RpcPositionHistoryRequestMethod::GetLogs,
            RpcPositionHistoryRequestPhase::Logs {
                direction: PositionHistoryDirection::To,
                from_block: 10,
                through_block: 15,
            },
        ),
        7 => (
            RpcPositionHistoryRequestMethod::GetBlockByNumber,
            RpcPositionHistoryRequestPhase::TerminalAfter,
        ),
        _ => unreachable!(),
    }
}

fn assert_failure_context(error: RpcPositionHistoryFailure, ordinal: u64) {
    assert_eq!(
        error.error(),
        RpcPositionHistoryError::RpcError { code: -32603 }
    );
    let locator = error.request().expect("RPC failure has a locator");
    let (method, phase) = expected_locator(ordinal);
    assert_eq!(locator.request_ordinal(), ordinal);
    assert_eq!(locator.method(), method);
    assert_eq!(locator.phase(), phase);
    let display = error.to_string();
    assert!(!display.contains(SENSITIVE_MESSAGE));
    assert!(!display.contains("127.0.0.1"));
    assert!(!display.contains(HOLDER_A));
}

#[tokio::test]
async fn failure_locator_covers_each_rpc_phase_and_stops_without_partial_result() {
    for fail_at in 1..=7 {
        let (reader, server) = reader_with_ordinal(vec![], Some(fail_at)).await;
        let result = reader
            .read_history_segment_paginated_with_failure_context(&request(HOLDER_A), 10)
            .await;
        let Err(error) = result else {
            panic!("expected RPC failure at ordinal {fail_at}");
        };
        assert_failure_context(error, fail_at);
        let calls = server.calls.lock().await;
        assert_eq!(calls.len(), fail_at as usize);
        assert_eq!(calls.last().unwrap().0, fail_at);
    }
}

#[tokio::test]
async fn failure_locator_tracks_late_pages_in_the_bounded_65_call_plan() {
    for fail_at in [42, 64, 65] {
        let (reader, server) = reader_with_ordinal(vec![], Some(fail_at)).await;
        let mut long_request = request(HOLDER_A);
        long_request.through_block = 69;
        long_request.expected_through_hash = hash(69);
        long_request.max_requests = 65;
        let error = reader
            .read_history_segment_paginated_with_failure_context(&long_request, 2)
            .await
            .unwrap_err();
        assert_eq!(
            error.error(),
            RpcPositionHistoryError::RpcError { code: -32603 }
        );
        let locator = error.request().expect("RPC error has a locator");
        assert_eq!(locator.request_ordinal(), fail_at);
        assert_eq!(locator.method(), expected_long_method(fail_at));
        assert_eq!(locator.phase(), expected_long_phase(fail_at));
        assert_eq!(server.calls.lock().await.len(), fail_at as usize);
    }
}

fn expected_long_method(ordinal: u64) -> RpcPositionHistoryRequestMethod {
    if ordinal == 1 {
        RpcPositionHistoryRequestMethod::ChainId
    } else if (2..=4).contains(&ordinal) || ordinal == 65 {
        RpcPositionHistoryRequestMethod::GetBlockByNumber
    } else {
        RpcPositionHistoryRequestMethod::GetLogs
    }
}

fn expected_long_phase(ordinal: u64) -> RpcPositionHistoryRequestPhase {
    match ordinal {
        1 => RpcPositionHistoryRequestPhase::Chain,
        2 => RpcPositionHistoryRequestPhase::Finalized,
        3 => RpcPositionHistoryRequestPhase::TerminalBefore,
        4 => RpcPositionHistoryRequestPhase::StartHeader,
        65 => RpcPositionHistoryRequestPhase::TerminalAfter,
        5..=64 => {
            let log_ordinal = ordinal - 5;
            let chunk_start = 10 + (log_ordinal / 2) * 2;
            RpcPositionHistoryRequestPhase::Logs {
                direction: if log_ordinal % 2 == 0 {
                    PositionHistoryDirection::From
                } else {
                    PositionHistoryDirection::To
                },
                from_block: chunk_start,
                through_block: (chunk_start + 1).min(69),
            }
        }
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn successful_rpc_with_semantic_failure_has_no_request_locator() {
    let (reader, server) = reader(vec![]).await;
    let mut request = request(HOLDER_A);
    request.from_block = 1_001;
    request.through_block = 1_001;
    request.expected_through_hash = hash(1_001);
    let error = reader
        .read_history_segment_paginated_with_failure_context(&request, 1)
        .await
        .unwrap_err();
    assert_eq!(error.error(), RpcPositionHistoryError::NotFinalized);
    assert_eq!(error.request(), None);
    assert_eq!(server.calls.lock().await.len(), 2);
}

#[tokio::test]
async fn successful_context_reader_matches_legacy_observation_content() {
    let (reader, _) = reader(vec![]).await;
    let request = request(HOLDER_A);
    let contextual = reader
        .read_history_segment_paginated_with_failure_context(&request, 2)
        .await
        .unwrap();
    let legacy = reader
        .read_history_segment_paginated(&request, 2)
        .await
        .unwrap();

    assert_eq!(contextual.start_block_number(), legacy.start_block_number());
    assert_eq!(contextual.start_block_hash(), legacy.start_block_hash());
    assert_eq!(contextual.start_parent_hash(), legacy.start_parent_hash());
    let contextual = contextual.history();
    let legacy = legacy.history();
    assert_eq!(contextual.holder_address(), legacy.holder_address());
    assert_eq!(contextual.from_block(), legacy.from_block());
    assert_eq!(contextual.through_block(), legacy.through_block());
    assert_eq!(
        contextual.expected_through_hash(),
        legacy.expected_through_hash()
    );
    assert_eq!(contextual.terminal_number(), legacy.terminal_number());
    assert_eq!(contextual.terminal_hash(), legacy.terminal_hash());
    assert_eq!(
        contextual.terminal_state_root(),
        legacy.terminal_state_root()
    );
    assert_eq!(
        contextual.terminal_transactions_root(),
        legacy.terminal_transactions_root()
    );
    assert_eq!(
        contextual.terminal_receipts_root(),
        legacy.terminal_receipts_root()
    );
    assert_eq!(contextual.logs(), legacy.logs());
    assert_eq!(contextual.pages(), legacy.pages());
    assert_eq!(contextual.request_count(), legacy.request_count());
    assert_eq!(contextual.response_bytes(), legacy.response_bytes());
}

#[tokio::test]
async fn legacy_reader_error_is_unchanged_and_context_is_opt_in() {
    let rules = vec![FailureRule {
        holder: HOLDER_A.to_owned(),
        direction: PositionHistoryDirection::From,
    }];
    let (reader, server) = reader(rules).await;
    let error = reader
        .read_history_segment_paginated(&request(HOLDER_A), 10)
        .await
        .unwrap_err();
    assert_eq!(error, RpcPositionHistoryError::RpcError { code: -32603 });
    assert_eq!(server.calls.lock().await.len(), 5);
}

#[tokio::test]
async fn concurrent_reads_keep_failure_locators_per_call() {
    let rules = vec![
        FailureRule {
            holder: HOLDER_A.to_owned(),
            direction: PositionHistoryDirection::From,
        },
        FailureRule {
            holder: HOLDER_B.to_owned(),
            direction: PositionHistoryDirection::To,
        },
    ];
    let (reader, _) = reader(rules).await;
    let request_a = request(HOLDER_A);
    let request_b = request(HOLDER_B);
    let (a, b) = tokio::join!(
        reader.read_history_segment_paginated_with_failure_context(&request_a, 10),
        reader.read_history_segment_paginated_with_failure_context(&request_b, 10),
    );
    assert_failure_context(a.unwrap_err(), 5);
    assert_failure_context(b.unwrap_err(), 6);
}

#[tokio::test]
async fn preflight_failures_have_no_locator_and_make_no_rpc_calls() {
    let (reader, server) = reader(vec![]).await;
    let invalid_width = reader
        .read_history_segment_paginated_with_failure_context(&request(HOLDER_A), 0)
        .await
        .unwrap_err();
    assert_eq!(invalid_width.error(), RpcPositionHistoryError::InvalidInput);
    assert_eq!(invalid_width.request(), None);

    let mut malformed_input = request(HOLDER_A);
    malformed_input.holder_address = "not-an-address".to_owned();
    let input_error = reader
        .read_history_segment_paginated_with_failure_context(&malformed_input, 10)
        .await
        .unwrap_err();
    assert_eq!(input_error.error(), RpcPositionHistoryError::InvalidInput);
    assert_eq!(input_error.request(), None);

    let mut insufficient_budget = request(HOLDER_A);
    insufficient_budget.max_requests = 6;
    let budget_error = reader
        .read_history_segment_paginated_with_failure_context(&insufficient_budget, 10)
        .await
        .unwrap_err();
    assert_eq!(
        budget_error.error(),
        RpcPositionHistoryError::RequestBudgetExceeded
    );
    assert_eq!(budget_error.request(), None);
    assert!(server.calls.lock().await.is_empty());
}
