#![cfg(feature = "chain-audit")]

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{Json, Router, extract::State, routing::post};
use polymarket_data::chain_log_audit::{
    BoundedFifthNativeBinaryActivityError, ChainLogVerifier, FifthNativeBinaryActivityStatus,
};
use serde_json::{Value, json};
use tokio::net::TcpListener;

#[derive(Clone)]
struct Replay {
    fixture: Arc<Value>,
    sends: Arc<AtomicUsize>,
}

async fn rpc(State(replay): State<Replay>, Json(request): Json<Value>) -> Json<Value> {
    replay.sends.fetch_add(1, Ordering::SeqCst);
    let result = replay.fixture["rpc_responses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["method"] == request["method"] && row["params"] == request["params"])
        .map(|row| row["result"].clone());
    match result {
        Some(value) => Json(json!({"jsonrpc":"2.0","id":request["id"],"result":value})),
        None => Json(
            json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32601,"message":"unmatched replay request"}}),
        ),
    }
}

async fn serve(fixture: &Value) -> (String, Replay, tokio::task::JoinHandle<()>) {
    let replay = Replay {
        fixture: Arc::new(fixture.clone()),
        sends: Arc::new(AtomicUsize::new(0)),
    };
    let state = replay.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/", post(rpc)).with_state(state),
        )
        .await
        .unwrap();
    });
    (endpoint, replay, task)
}

fn cases() -> [Value; 3] {
    [
        include_str!("fixtures/fifth-native-binary-activity-fund-split-buy-sell-rpc.json"),
        include_str!("fixtures/fifth-native-binary-activity-partial-redemption-rpc.json"),
        include_str!("fixtures/fifth-native-binary-activity-mint-multi-refund-rpc.json"),
    ]
    .map(|blob| serde_json::from_str(blob).unwrap())
}

#[tokio::test]
async fn immutable_native_accounting_sources_preserve_receipt_locators_and_shared_limits() {
    for fixture in cases() {
        let budget = usize::try_from(fixture["actual_request_count"].as_u64().unwrap()).unwrap();
        for limit in [budget, budget - 1] {
            let (primary, primary_state, primary_task) = serve(&fixture).await;
            let (secondary, secondary_state, secondary_task) = serve(&fixture).await;
            let result = ChainLogVerifier::new(&primary, &secondary)
                .unwrap()
                .verify_fifth_native_binary_activity_interval_bounded(
                    fixture["owner"].as_str().unwrap(),
                    fixture["condition_id"].as_str().unwrap(),
                    fixture["from_block"].as_u64().unwrap(),
                    fixture["through_block"].as_u64().unwrap(),
                    fixture["parent_hash"].as_str().unwrap(),
                    fixture["end_hash"].as_str().unwrap(),
                    limit,
                    Duration::from_secs(10),
                )
                .await;
            let sends = primary_state.sends.load(Ordering::SeqCst)
                + secondary_state.sends.load(Ordering::SeqCst);
            if limit == budget {
                let report = result.unwrap();
                assert_eq!(report.status(), &FifthNativeBinaryActivityStatus::Matched);
                assert_eq!(sends, budget);
                let actual = report
                    .transactions()
                    .iter()
                    .flat_map(|tx| tx.order_fills().iter().map(|fill| fill.log_index()))
                    .collect::<Vec<_>>();
                let expected = fixture["trades"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|tx| {
                        tx["order_fills"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|fill| fill["log_index"].as_u64().unwrap())
                    })
                    .collect::<Vec<_>>();
                assert_eq!(actual, expected);
                for operation in report.module_operations() {
                    let locator = operation.operation_transaction();
                    let block = report
                        .evidence()
                        .blocks()
                        .iter()
                        .find(|b| b.block_number() == locator.block_number())
                        .unwrap();
                    let tx = block
                        .transactions()
                        .iter()
                        .find(|tx| tx.transaction_hash() == locator.transaction_hash())
                        .unwrap();
                    assert_eq!(
                        locator.log_index(),
                        tx.logs().last().unwrap().block_log_index()
                    );
                }
            } else {
                assert_eq!(
                    result,
                    Err(BoundedFifthNativeBinaryActivityError::RequestBudgetExceeded)
                );
                assert!((1..=limit).contains(&sends));
            }
            primary_task.abort();
            secondary_task.abort();
        }
    }
}
