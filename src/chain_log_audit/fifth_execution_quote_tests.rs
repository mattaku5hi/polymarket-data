use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use crate::{
    chain_log_audit::{
        FifthExchangeImplementationVersion, FifthNativeExecutionQuoteBindingError,
        FifthNativeQuoteCashUnit, bind_fifth_native_execution_assets,
        bind_fifth_native_execution_quote,
    },
    clob::{
        execution_context::{ClobExecutionContextReader, ExecutionContextRequest},
        execution_quote::{
            ExecutionQuote, ExecutionQuoteError, ExecutionQuoteFeeCurrency, ExecutionQuoteFeeKind,
            ExecutionQuoteSide, estimate_execution_quote,
        },
    },
};
use axum::{Router, extract::Query, routing::get};
use serde_json::json;

const API_CONDITION: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

async fn context_server(
    version: &str,
    ids: [&str; 2],
    selected_index: usize,
    api_condition: &str,
    book_hash: &str,
    timestamp: &str,
) -> (
    crate::clob::execution_context::ExecutionContextObservation,
    tokio::task::JoinHandle<()>,
    Arc<AtomicUsize>,
) {
    let sends = Arc::new(AtomicUsize::new(0));
    let gamma_ids = ids.map(str::to_owned);
    let market_ids = gamma_ids.clone();
    let expected_selected = ids[selected_index].to_owned();
    let api_condition = api_condition.to_owned();
    let book_hash = book_hash.to_owned();
    let timestamp = timestamp.to_owned();
    let gamma_sends = sends.clone();
    let market_sends = sends.clone();
    let book_sends = sends.clone();
    let gamma_version = version.to_owned();
    let gamma_condition = api_condition.clone();
    let market_condition = api_condition.clone();
    let book_condition = api_condition.clone();
    let app = Router::new()
        .route(
            "/markets",
            get(move || {
                let sends = gamma_sends.clone();
                let ids = gamma_ids.clone();
                let version = gamma_version.clone();
                let condition = gamma_condition.clone();
                async move {
                    sends.fetch_add(1, Ordering::Relaxed);
                    axum::Json(json!([{
                        "conditionId":condition,
                        "version":version,
                        "outcomes":"[\"Affirmative\",\"Negative\"]",
                        "clobTokenIds":ids,
                        "positionIds":ids,
                        "active":true,
                        "closed":false,
                        "acceptingOrders":true,
                        "enableOrderBook":true,
                        "orderMinSize":"5",
                        "orderPriceMinTickSize":"0.01",
                        "feesEnabled":true,
                        "feeSchedule":{"rate":0.02,"exponent":2,"takerOnly":true,"rebateRate":null}
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
                            "mts":"0.01",
                            "fd":{"r":0.02,"e":2,"to":true}
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
                    let hash = book_hash.clone();
                    let timestamp = timestamp.clone();
                    async move {
                        sends.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(query.get("token_id"), Some(&expected_asset));
                        axum::Json(json!({
                            "market":condition,
                            "asset_id":expected_asset,
                            "hash":hash,
                            "timestamp":timestamp,
                            "bids":[{"price":"0.4","size":"2"}],
                            "asks":[{"price":"0.5","size":"10"}]
                        }))
                    }
                },
            ),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let reader =
        ClobExecutionContextReader::with_client_builder(reqwest::Client::builder(), &base, &base)
            .unwrap();
    let context = reader
        .read_context(&ExecutionContextRequest {
            api_condition_id: api_condition,
            selected_asset_id: ids[selected_index].to_owned(),
            max_requests: 3,
            total_timeout: std::time::Duration::from_secs(5),
        })
        .await
        .unwrap();
    (context, task, sends)
}

fn quote(
    context: &crate::clob::execution_context::ExecutionContextObservation,
    max_age: std::time::Duration,
) -> Result<ExecutionQuote, ExecutionQuoteError> {
    estimate_execution_quote(
        context,
        ExecutionQuoteSide::Buy,
        rust_decimal::Decimal::ONE,
        max_age,
    )
}

async fn rooted_native() -> (
    Arc<AtomicUsize>,
    crate::chain_log_audit::FifthNativeBinaryObservation,
) {
    let (fixture, condition_id, owner) = super::super::native_contiguous_fund_quiet_sell_fixture();
    let (_, _, _, closing_header) = super::super::ctf_inventory_headers_with_102(&fixture);
    let primary = super::super::ctf_inventory_provider(fixture.clone()).await;
    let secondary = super::super::ctf_inventory_provider(fixture.clone()).await;
    let requests = fixture.requests.clone();
    let native = super::super::super::await_loopback_without_virtual_time_advance(
        crate::chain_log_audit::ChainLogVerifier::new(&primary, &secondary)
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
    (requests, native)
}

fn provider_ids(native: &crate::chain_log_audit::FifthNativeBinaryObservation) -> [String; 2] {
    native
        .position_ids()
        .map(|id| alloy_primitives::U256::from_be_slice(id.as_slice()).to_string())
}

#[tokio::test]
async fn binds_both_selected_assets_to_current_rooted_pusd_profile_without_io() {
    let (fixture_requests, native) = rooted_native().await;
    let ids = provider_ids(&native);
    let initial_requests = fixture_requests.load(Ordering::Relaxed);
    for selected_index in 0..2 {
        let (context, task, sends) = context_server(
            "v2",
            [&ids[0], &ids[1]],
            selected_index,
            API_CONDITION,
            "binding-book",
            "1700000000123",
        )
        .await;
        let before_bind = fixture_requests.load(Ordering::Relaxed);
        let asset_binding = bind_fifth_native_execution_assets(&native, &context).unwrap();
        let quote = quote(&context, std::time::Duration::from_secs(10)).unwrap();
        assert_eq!(quote.fee_kind(), ExecutionQuoteFeeKind::ModeledEstimate);
        assert!(quote.estimated_platform_fee() > rust_decimal::Decimal::ZERO);
        assert_eq!(
            quote.fee_currency(),
            ExecutionQuoteFeeCurrency::ClobUsdNotional
        );
        let profile = bind_fifth_native_execution_quote(&asset_binding, &quote).unwrap();
        assert_eq!(fixture_requests.load(Ordering::Relaxed), before_bind);
        assert_eq!(sends.load(Ordering::Relaxed), 3);
        assert_eq!(profile.quote_cash_unit(), FifthNativeQuoteCashUnit::Pusd);
        assert_eq!(profile.quote_cash_decimals(), 6);
        assert_eq!(profile.selected_native_outcome_index(), selected_index);
        assert_eq!(
            profile.selected_native_position_id(),
            native.position_ids()[selected_index]
        );
        assert_eq!(profile.chain_id(), 137);
        assert_eq!(profile.root_block_number(), 102);
        assert_eq!(
            profile.root_block_hash(),
            native.selected_balances().block_hash()
        );
        assert_eq!(
            profile.root_state_root(),
            native.selected_balances().state_root()
        );
        assert_eq!(profile.collateral_symbol(), "pUSD");
        assert_eq!(
            profile.collateral_proxy(),
            "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb"
        );
        assert_eq!(
            profile.collateral_proxy_code_hash(),
            "0xaaa52c8cc8a0e3fd27ce756cc6b4e70c51423e9b597b11f32d3e49f8b1fc890d"
        );
        assert_eq!(
            profile.collateral_implementation(),
            "0xce84e053301a82937f90ee2c2c1889cab1db25de"
        );
        assert_eq!(
            profile.collateral_implementation_code_hash(),
            "0x740b9ebbb47b33a28e47c999b330fe79f878b7e0f1f7e7e09b8a0928ef4e1cb0"
        );
        assert_eq!(
            profile.position_manager_proxy(),
            "0x006f54f7f9a22e0000cc2ab60031000000ae9fef"
        );
        assert_eq!(
            profile.position_manager_implementation(),
            "0xcc5de1e9d14a7ab75e872e23fc9d605518bac2d0"
        );
        assert_eq!(
            profile.position_manager_implementation_code_hash(),
            "0x4f3ca1f933ee48546581d8ee28506e5c5b89d08e50900ff880603cedcde14c9e"
        );
        assert_eq!(profile.exchange_fee_cap_bps(), 1_000);
        assert_eq!(
            profile.exchange_implementation_version(),
            FifthExchangeImplementationVersion::Current641b
        );
        assert!(
            profile
                .exchange_fee_cap_source_provenance()
                .contains("741f8bbe")
        );
        assert_eq!(
            profile.code_context_source_policy_version(),
            "fifth-exchange-proxy-implementation-source-codehash-root-proof/1"
        );
        assert_eq!(
            profile.native_balance_source_policy_version(),
            "fifth-selected-position-and-pusd-rooted-balances/1"
        );
        assert_eq!(
            profile.quote().fee_kind(),
            ExecutionQuoteFeeKind::ModeledEstimate
        );
        assert_eq!(profile.valid_until(), quote.valid_until());
        assert_eq!(
            profile.quote_binding_policy_version(),
            "fifth-native-v2-rooted-pusd-modeled-quote-binding/1"
        );
        task.abort();
    }
    assert_eq!(fixture_requests.load(Ordering::Relaxed), initial_requests);
}

#[tokio::test]
async fn refuses_foreign_asset_book_selector_and_acquisition_timing() {
    let (fixture_requests, native) = rooted_native().await;
    let ids = provider_ids(&native);
    let (context, task, _) = context_server(
        "v2",
        [&ids[0], &ids[1]],
        0,
        API_CONDITION,
        "binding-book",
        "1700000000123",
    )
    .await;
    let assets = bind_fifth_native_execution_assets(&native, &context).unwrap();
    let before = fixture_requests.load(Ordering::Relaxed);

    let (other_asset_context, task_asset, _) = context_server(
        "v2",
        [&ids[0], &ids[1]],
        1,
        API_CONDITION,
        "binding-book",
        "1700000000123",
    )
    .await;
    assert!(matches!(
        bind_fifth_native_execution_quote(
            &assets,
            &quote(&other_asset_context, std::time::Duration::from_secs(10)).unwrap()
        ),
        Err(FifthNativeExecutionQuoteBindingError::ContextMismatch)
    ));

    let (other_book_context, task_book, _) = context_server(
        "v2",
        [&ids[0], &ids[1]],
        0,
        API_CONDITION,
        "foreign-book",
        "1700000000123",
    )
    .await;
    assert!(matches!(
        bind_fifth_native_execution_quote(
            &assets,
            &quote(&other_book_context, std::time::Duration::from_secs(10)).unwrap()
        ),
        Err(FifthNativeExecutionQuoteBindingError::ContextMismatch)
    ));

    let (other_selector_context, task_selector, _) = context_server(
        "v2",
        [&ids[0], &ids[1]],
        0,
        "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "binding-book",
        "1700000000123",
    )
    .await;
    assert!(matches!(
        bind_fifth_native_execution_quote(
            &assets,
            &quote(&other_selector_context, std::time::Duration::from_secs(10)).unwrap()
        ),
        Err(FifthNativeExecutionQuoteBindingError::ContextMismatch)
    ));

    let (same_identity_context, task_timing, _) = context_server(
        "v2",
        [&ids[0], &ids[1]],
        0,
        API_CONDITION,
        "binding-book",
        "1700000000123",
    )
    .await;
    assert_ne!(context.started_at(), same_identity_context.started_at());
    assert!(matches!(
        bind_fifth_native_execution_quote(
            &assets,
            &quote(&same_identity_context, std::time::Duration::from_secs(10)).unwrap()
        ),
        Err(FifthNativeExecutionQuoteBindingError::ContextMismatch)
    ));
    assert_eq!(fixture_requests.load(Ordering::Relaxed), before);
    task.abort();
    task_asset.abort();
    task_book.abort();
    task_selector.abort();
    task_timing.abort();
}

#[tokio::test]
async fn expired_quote_refuses_without_renewing_its_deadline() {
    let (fixture_requests, native) = rooted_native().await;
    let ids = provider_ids(&native);
    let (context, task, _) = context_server(
        "v2",
        [&ids[0], &ids[1]],
        0,
        API_CONDITION,
        "binding-book",
        "1700000000123",
    )
    .await;
    let assets = bind_fifth_native_execution_assets(&native, &context).unwrap();
    let quote = quote(&context, std::time::Duration::from_millis(250)).unwrap();
    let deadline = quote.valid_until();
    tokio::time::sleep(std::time::Duration::from_millis(260)).await;
    assert!(tokio::time::Instant::now() >= deadline);
    let before = fixture_requests.load(Ordering::Relaxed);
    assert!(matches!(
        bind_fifth_native_execution_quote(&assets, &quote),
        Err(FifthNativeExecutionQuoteBindingError::QuoteExpired)
    ));
    assert_eq!(fixture_requests.load(Ordering::Relaxed), before);
    task.abort();
}
