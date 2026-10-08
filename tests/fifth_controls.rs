#![cfg(feature = "chain-audit")]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{Json, Router, extract::State, routing::post};
use polymarket_data::chain_log_audit::{BoundedFifthExchangeControlsError, ChainLogVerifier};
use serde_json::{Value, json};
use tokio::net::TcpListener;

#[derive(Clone)]
struct RpcReplay {
    fixture: Arc<Value>,
    requests: Arc<AtomicUsize>,
}

impl RpcReplay {
    fn new(fixture: Value) -> Self {
        Self {
            fixture: Arc::new(fixture),
            requests: Arc::new(AtomicUsize::new(0)),
        }
    }
}

async fn rpc(State(replay): State<RpcReplay>, Json(request): Json<Value>) -> Json<Value> {
    replay.requests.fetch_add(1, Ordering::SeqCst);
    let method = request["method"].as_str().unwrap_or_default();
    let params = &request["params"];
    let result = replay.fixture["rpc_responses"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|row| row["method"] == method && row["params"] == *params)
        })
        .and_then(|row| row.get("result"))
        .cloned();
    match result {
        Some(result) => Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result})),
        None => Json(
            json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32601,"message":"unmatched replay request"}}),
        ),
    }
}

async fn serve(fixture: Value) -> (String, RpcReplay, tokio::task::JoinHandle<()>) {
    let replay = RpcReplay::new(fixture);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let state = replay.clone();
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/", post(rpc)).with_state(state),
        )
        .await
        .unwrap();
    });
    (url, replay, task)
}

fn fixture_cases() -> [Value; 4] {
    [
        serde_json::from_str(include_str!(
            "fixtures/fifth-exchange-controls-current-active-global-rpc.json"
        ))
        .unwrap(),
        serde_json::from_str(include_str!(
            "fixtures/fifth-exchange-controls-current-pending-wide-rpc.json"
        ))
        .unwrap(),
        serde_json::from_str(include_str!(
            "fixtures/fifth-exchange-controls-prior-pending-wide-rpc.json"
        ))
        .unwrap(),
        serde_json::from_str(include_str!(
            "fixtures/fifth-exchange-controls-prior-zero-activation-rpc.json"
        ))
        .unwrap(),
    ]
}

#[tokio::test]
async fn rooted_controls_fixtures_replay_all_observed_fields_at_exact_budget() {
    for fixture in fixture_cases() {
        let (primary, primary_replay, primary_server) = serve(fixture.clone()).await;
        let (secondary, secondary_replay, secondary_server) = serve(fixture.clone()).await;
        let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
        let observation = verifier
            .verify_fifth_exchange_controls_bounded(
                fixture["submitter"].as_str().unwrap(),
                fixture["maker"].as_str().unwrap(),
                fixture["block_number"].as_u64().unwrap(),
                fixture["block_hash"].as_str().unwrap(),
                16,
                std::time::Duration::from_secs(10),
            )
            .await
            .unwrap();

        assert_eq!(
            format!("{:#x}", observation.submitter()),
            fixture["submitter"].as_str().unwrap()
        );
        assert_eq!(
            format!("{:#x}", observation.maker()),
            fixture["maker"].as_str().unwrap()
        );
        assert_eq!(
            observation.code_context().block_number(),
            fixture["block_number"].as_u64().unwrap()
        );
        assert_eq!(
            observation.code_context().block_hash(),
            fixture["block_hash"].as_str().unwrap()
        );
        assert_eq!(
            observation
                .code_context()
                .exchange_implementation_version()
                .as_str(),
            fixture["exchange_implementation_version"].as_str().unwrap()
        );
        assert_eq!(
            format!("{:#x}", observation.global_pause_word()),
            fixture["global_pause_word"].as_str().unwrap()
        );
        assert_eq!(
            observation.global_paused(),
            fixture["global_paused"].as_bool().unwrap()
        );
        assert_eq!(
            format!("{:#x}", observation.user_pause_block_interval()),
            fixture["user_pause_block_interval"].as_str().unwrap()
        );
        assert_eq!(
            format!("{:#x}", observation.submitter_role_bitmap()),
            fixture["submitter_role_bitmap"].as_str().unwrap()
        );
        assert_eq!(
            observation.submitter_has_operator_role(),
            fixture["submitter_has_operator_role"].as_bool().unwrap()
        );
        assert_eq!(
            format!("{:#x}", observation.maker_pause_activation_block()),
            fixture["maker_pause_activation_block"].as_str().unwrap()
        );
        assert_eq!(
            observation.maker_pause_active(),
            fixture["maker_pause_active"].as_bool().unwrap()
        );
        let expected_keys = fixture["storage_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            observation
                .storage_keys()
                .map(|key| format!("{key:#x}"))
                .to_vec(),
            expected_keys
        );
        assert_eq!(
            observation.source_policy_version(),
            fixture["source_policy_version"].as_str().unwrap()
        );
        assert_eq!(
            primary_replay.requests.load(Ordering::SeqCst)
                + secondary_replay.requests.load(Ordering::SeqCst),
            usize::try_from(fixture["actual_request_count"].as_u64().unwrap()).unwrap()
        );
        primary_server.abort();
        secondary_server.abort();
    }
}

#[tokio::test]
async fn rooted_controls_one_short_budget_cancels_after_fifteen_or_fewer_sends() {
    let fixture = fixture_cases().into_iter().next().unwrap();
    let (primary, primary_replay, primary_server) = serve(fixture.clone()).await;
    let (secondary, secondary_replay, secondary_server) = serve(fixture.clone()).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    assert_eq!(
        verifier
            .verify_fifth_exchange_controls_bounded(
                fixture["submitter"].as_str().unwrap(),
                fixture["maker"].as_str().unwrap(),
                fixture["block_number"].as_u64().unwrap(),
                fixture["block_hash"].as_str().unwrap(),
                15,
                std::time::Duration::from_secs(10),
            )
            .await,
        Err(BoundedFifthExchangeControlsError::RequestBudgetExceeded)
    );
    let sends = primary_replay.requests.load(Ordering::SeqCst)
        + secondary_replay.requests.load(Ordering::SeqCst);
    assert!((14..=15).contains(&sends));
    primary_server.abort();
    secondary_server.abort();
}
