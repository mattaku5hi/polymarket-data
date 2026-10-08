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
    BoundedFifthNativeBinaryTradeError, ChainLogVerifier, FifthNativeBinaryTradeStatus,
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
        include_str!("fixtures/fifth-native-binary-trades-normal-buy-rpc.json"),
        include_str!("fixtures/fifth-native-binary-trades-mint-rpc.json"),
        include_str!("fixtures/fifth-native-binary-trades-merge-rpc.json"),
    ]
    .map(|blob| serde_json::from_str(blob).unwrap())
}

#[tokio::test]
async fn immutable_native_trade_receipts_replay_with_one_shared_exact_budget() {
    for fixture in cases() {
        let (primary, primary_state, primary_task) = serve(&fixture).await;
        let (secondary, secondary_state, secondary_task) = serve(&fixture).await;
        let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
        let observation = verifier
            .verify_fifth_native_binary_trade_interval_bounded(
                fixture["owner"].as_str().unwrap(),
                fixture["condition_id"].as_str().unwrap(),
                fixture["from_block"].as_u64().unwrap(),
                fixture["through_block"].as_u64().unwrap(),
                fixture["parent_hash"].as_str().unwrap(),
                fixture["end_hash"].as_str().unwrap(),
                130,
                Duration::from_secs(10),
            )
            .await
            .unwrap();
        assert_eq!(observation.status(), &FifthNativeBinaryTradeStatus::Matched);
        assert_eq!(observation.transactions().len(), 1);
        assert_eq!(observation.controls().len(), 6);
        assert_eq!(
            format!("{:?}", observation.transactions()[0].branch()),
            fixture["transactions"][0]["branch"].as_str().unwrap()
        );
        let closing = observation
            .block_observations()
            .last()
            .unwrap()
            .native_context()
            .selected_balances();
        assert_eq!(
            json!([
                format!("{:#x}", closing.position_balance_a()),
                format!("{:#x}", closing.position_balance_b())
            ]),
            fixture["expected_owner_closing"]["position_balances"]
        );
        assert_eq!(
            format!("{:#x}", closing.pusd_balance()),
            fixture["expected_owner_closing"]["pusd_balance"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            primary_state.sends.load(Ordering::SeqCst)
                + secondary_state.sends.load(Ordering::SeqCst),
            130
        );
        primary_task.abort();
        secondary_task.abort();
    }
}

#[tokio::test]
async fn immutable_native_trade_receipts_refuse_a_one_short_budget() {
    let fixture = cases().into_iter().next().unwrap();
    let (primary, primary_state, primary_task) = serve(&fixture).await;
    let (secondary, secondary_state, secondary_task) = serve(&fixture).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    assert_eq!(
        verifier
            .verify_fifth_native_binary_trade_interval_bounded(
                fixture["owner"].as_str().unwrap(),
                fixture["condition_id"].as_str().unwrap(),
                100,
                101,
                fixture["parent_hash"].as_str().unwrap(),
                fixture["end_hash"].as_str().unwrap(),
                129,
                Duration::from_secs(10),
            )
            .await,
        Err(BoundedFifthNativeBinaryTradeError::RequestBudgetExceeded)
    );
    let sends =
        primary_state.sends.load(Ordering::SeqCst) + secondary_state.sends.load(Ordering::SeqCst);
    assert!((1..=129).contains(&sends));
    primary_task.abort();
    secondary_task.abort();
}
