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

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "fixtures/fifth-native-binary-activity-fund-trade-split-rpc.json"
    ))
    .unwrap()
}

#[tokio::test]
async fn immutable_mixed_activity_is_atomic_under_exact_and_short_budgets() {
    for budget in [130, 129] {
        let fixture = fixture();
        let (primary, primary_state, primary_task) = serve(&fixture).await;
        let (secondary, secondary_state, secondary_task) = serve(&fixture).await;
        let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
        let result = verifier
            .verify_fifth_native_binary_activity_interval_bounded(
                fixture["owner"].as_str().unwrap(),
                fixture["condition_id"].as_str().unwrap(),
                fixture["from_block"].as_u64().unwrap(),
                fixture["through_block"].as_u64().unwrap(),
                fixture["parent_hash"].as_str().unwrap(),
                fixture["end_hash"].as_str().unwrap(),
                budget,
                Duration::from_secs(10),
            )
            .await;
        let sends = primary_state.sends.load(Ordering::SeqCst)
            + secondary_state.sends.load(Ordering::SeqCst);
        if budget == 130 {
            let report = result.unwrap();
            assert_eq!(report.status(), &FifthNativeBinaryActivityStatus::Matched);
            assert_eq!(report.transactions().len(), 1);
            assert_eq!(report.module_operations().len(), 1);
            assert_eq!(report.controls().len(), 6);
            assert_eq!(
                report.module_operations()[0].funding_transactions().len(),
                1
            );
            assert_eq!(
                report.module_operations()[0].funding_transactions()[0]
                    .transaction()
                    .block_number(),
                100
            );
            assert_eq!(
                report.module_operations()[0]
                    .operation_transaction()
                    .block_number(),
                101
            );
            let middle = &report.block_observations()[0];
            assert_eq!(format!("{:#x}", middle.module_pusd_balance()), "0xa");
            let closing = report.block_observations().last().unwrap();
            assert_eq!(format!("{:#x}", closing.module_pusd_balance()), "0x0");
            let owner = closing.native_context().selected_balances();
            assert_eq!(format!("{:#x}", owner.position_balance_a()), "0x6e");
            assert_eq!(format!("{:#x}", owner.position_balance_b()), "0xa");
            assert_eq!(format!("{:#x}", owner.pusd_balance()), "0x3ab");
            assert_eq!(sends, 130);
        } else {
            assert_eq!(
                result,
                Err(BoundedFifthNativeBinaryActivityError::RequestBudgetExceeded)
            );
            assert!((1..=129).contains(&sends));
        }
        primary_task.abort();
        secondary_task.abort();
    }
}
