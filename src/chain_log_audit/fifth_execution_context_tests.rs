use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{Router, extract::Query, routing::get};
use serde_json::json;

use crate::clob::execution_context::{ClobExecutionContextReader, ExecutionContextRequest};

use super::super::{
    FIFTH_NATIVE_EXECUTION_ASSET_BINDING_POLICY_VERSION, FifthNativeExecutionAssetBindingError,
    bind_fifth_native_execution_assets,
};

const API_CONDITION: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

async fn context_server(
    version: &str,
    ids: [&str; 2],
    selected: &str,
) -> (String, tokio::task::JoinHandle<()>, Arc<AtomicUsize>) {
    let sends = Arc::new(AtomicUsize::new(0));
    let gamma_ids = ids.map(str::to_owned);
    let market_ids = gamma_ids.clone();
    let expected_selected = selected.to_owned();
    let gamma_sends = sends.clone();
    let market_sends = sends.clone();
    let book_sends = sends.clone();
    let market_condition = API_CONDITION.to_owned();
    let book_condition = API_CONDITION.to_owned();
    let gamma_version = version.to_owned();
    let app = Router::new()
        .route(
            "/markets",
            get(move || {
                let sends = gamma_sends.clone();
                let ids = gamma_ids.clone();
                let version = gamma_version.clone();
                async move {
                    sends.fetch_add(1, Ordering::Relaxed);
                    axum::Json(json!([{
                        "conditionId":API_CONDITION,
                        "version":version,
                        "outcomes":"[\"Affirmative\",\"Negative\"]",
                        "clobTokenIds":ids,
                        "positionIds":ids,
                        "active":true,
                        "closed":false,
                        "acceptingOrders":true,
                        "enableOrderBook":true,
                        "orderMinSize":"5",
                        "orderPriceMinTickSize":"0.01"
                    }]))
                }
            }),
        )
        .route(
            "/clob-markets/{condition}",
            get(
                move |axum::extract::Path(condition): axum::extract::Path<String>| {
                    let sends = market_sends.clone();
                    let ids = market_ids.clone();
                    let expected_condition = market_condition.clone();
                    async move {
                        sends.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(condition, expected_condition);
                        axum::Json(json!({
                            "t":[{"t":ids[1],"o":"Negative"},{"t":ids[0],"o":"Affirmative"}],
                            "mos":"5",
                            "mts":"0.01"
                        }))
                    }
                },
            ),
        )
        .route(
            "/book",
            get(
                move |Query(query): Query<std::collections::HashMap<String, String>>| {
                    let sends = book_sends.clone();
                    let expected_asset = expected_selected.clone();
                    let condition = book_condition.clone();
                    async move {
                        sends.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(query.get("token_id"), Some(&expected_asset));
                        axum::Json(json!({
                            "market":condition,
                            "asset_id":expected_asset,
                            "hash":"binding-book",
                            "timestamp":"1700000000123",
                            "bids":[],
                            "asks":[]
                        }))
                    }
                },
            ),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, task, sends)
}

async fn read_context(
    version: &str,
    ids: [&str; 2],
    selected_index: usize,
) -> (
    crate::clob::execution_context::ExecutionContextObservation,
    tokio::task::JoinHandle<()>,
    Arc<AtomicUsize>,
) {
    let (base, task, sends) = context_server(version, ids, ids[selected_index]).await;
    let reader =
        ClobExecutionContextReader::with_client_builder(reqwest::Client::builder(), &base, &base)
            .unwrap();
    let context = reader
        .read_context(&ExecutionContextRequest {
            api_condition_id: API_CONDITION.to_owned(),
            selected_asset_id: ids[selected_index].to_owned(),
            max_requests: 3,
            total_timeout: std::time::Duration::from_secs(5),
        })
        .await
        .unwrap();
    (context, task, sends)
}

#[tokio::test]
async fn binds_rooted_native_pair_to_real_v2_context_for_either_selection_without_io() {
    let (fixture, condition_id, owner) = super::native_contiguous_fund_quiet_sell_fixture();
    let (_, _, _, closing_header) = super::ctf_inventory_headers_with_102(&fixture);
    let primary = super::ctf_inventory_provider(fixture.clone()).await;
    let secondary = super::ctf_inventory_provider(fixture.clone()).await;
    let native = super::super::await_loopback_without_virtual_time_advance(
        super::ChainLogVerifier::new(&primary, &secondary)
            .unwrap()
            .verify_fifth_native_binary_bounded(
                &owner,
                &format!("{condition_id:#x}"),
                102,
                closing_header["hash"].as_str().unwrap(),
                26,
                std::time::Duration::from_secs(10),
            ),
    )
    .await
    .unwrap();
    assert_eq!(fixture.requests.load(Ordering::Relaxed), 26);

    let native_ids = native.position_ids();
    let provider_ids =
        native_ids.map(|id| alloy_primitives::U256::from_be_slice(id.as_slice()).to_string());
    assert!(
        alloy_primitives::U256::from_str_radix(&provider_ids[0], 10).unwrap()
            > alloy_primitives::U256::from(u128::MAX)
    );
    assert_ne!(native.condition_id().to_string(), API_CONDITION);

    for (selected_index, native_id) in native_ids.iter().enumerate() {
        let (context, task, sends) =
            read_context("v2", [&provider_ids[0], &provider_ids[1]], selected_index).await;
        assert_eq!(context.request_count(), 3);
        assert_eq!(sends.load(Ordering::Relaxed), 3);
        assert_ne!(
            context.api_condition_id(),
            &format!("{:#x}", native.condition_id())
        );

        let before = fixture.requests.load(Ordering::Relaxed);
        let binding = bind_fifth_native_execution_assets(&native, &context).unwrap();
        assert_eq!(fixture.requests.load(Ordering::Relaxed), before);
        assert_eq!(sends.load(Ordering::Relaxed), 3);
        assert_eq!(binding.native_context().condition_id(), condition_id);
        assert_eq!(
            binding.execution_context().api_condition_id(),
            API_CONDITION
        );
        assert_eq!(binding.selected_native_outcome_index(), selected_index);
        assert_eq!(binding.selected_native_position_id(), *native_id);
        assert_eq!(
            binding.source_policy_version(),
            FIFTH_NATIVE_EXECUTION_ASSET_BINDING_POLICY_VERSION
        );
        task.abort();
    }
}

#[tokio::test]
async fn refuses_unsupported_protocol_malformed_and_nonmatching_ordered_pairs() {
    let (fixture, condition_id, owner) = super::native_contiguous_fund_quiet_sell_fixture();
    let (_, _, _, closing_header) = super::ctf_inventory_headers_with_102(&fixture);
    let primary = super::ctf_inventory_provider(fixture.clone()).await;
    let secondary = super::ctf_inventory_provider(fixture.clone()).await;
    let native = super::super::await_loopback_without_virtual_time_advance(
        super::ChainLogVerifier::new(&primary, &secondary)
            .unwrap()
            .verify_fifth_native_binary_bounded(
                &owner,
                &format!("{condition_id:#x}"),
                102,
                closing_header["hash"].as_str().unwrap(),
                26,
                std::time::Duration::from_secs(10),
            ),
    )
    .await
    .unwrap();
    let ids = native
        .position_ids()
        .map(|id| alloy_primitives::U256::from_be_slice(id.as_slice()).to_string());
    let foreign = "987654321";
    let overflow = "115792089237316195423570985008687907853269984665640564039457584007913129639936";

    let cases = vec![
        (
            "v1",
            [ids[0].clone(), ids[1].clone()],
            0,
            FifthNativeExecutionAssetBindingError::UnsupportedProtocol,
        ),
        (
            "v2",
            [ids[1].clone(), ids[0].clone()],
            1,
            FifthNativeExecutionAssetBindingError::AssetMismatch,
        ),
        (
            "v2",
            [ids[0].clone(), foreign.to_owned()],
            0,
            FifthNativeExecutionAssetBindingError::AssetMismatch,
        ),
        (
            "v2",
            [format!("0{}", ids[0]), ids[1].clone()],
            0,
            FifthNativeExecutionAssetBindingError::InvalidAssetId,
        ),
        (
            "v2",
            [overflow.to_owned(), ids[1].clone()],
            0,
            FifthNativeExecutionAssetBindingError::InvalidAssetId,
        ),
    ];

    for (version, pair, selected_index, expected) in cases {
        let (context, task, sends) =
            read_context(version, [&pair[0], &pair[1]], selected_index).await;
        assert_eq!(sends.load(Ordering::Relaxed), 3);
        let rpc_before = fixture.requests.load(Ordering::Relaxed);
        assert!(matches!(
            bind_fifth_native_execution_assets(&native, &context),
            Err(error) if error == expected
        ));
        assert_eq!(fixture.requests.load(Ordering::Relaxed), rpc_before);
        assert_eq!(sends.load(Ordering::Relaxed), 3);
        task.abort();
    }
}
