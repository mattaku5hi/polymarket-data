use std::time::Duration;

use axum::{
    Router,
    extract::{Path, Query},
    routing::get,
};
use polymarket_data::clob::{
    execution_context::{ClobExecutionContextReader, ExecutionContextRequest},
    execution_quote::{
        ExecutionQuoteBuilderPolicy, ExecutionQuoteError, ExecutionQuoteFeeKind,
        ExecutionQuoteRole, ExecutionQuoteSide, estimate_execution_quote,
    },
};
use rust_decimal::Decimal;
use serde_json::{Value, json};

const CONDITION: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn gamma(enabled: Value, rate: Value, exponent: Value, taker: Value, version: &str) -> Value {
    json!([{
        "conditionId": CONDITION, "version": version, "outcomes": ["Yes", "No"],
        "clobTokenIds": ["123", "456"], "positionIds": ["123", "456"],
        "active": true, "closed": false, "acceptingOrders": true, "enableOrderBook": true,
        "orderMinSize": "1", "orderPriceMinTickSize": "0.01", "feesEnabled": enabled,
        "feeSchedule": {"rate": rate, "exponent": exponent, "takerOnly": taker, "rebateRate": null}
    }])
}

fn clob(rate: Value, exponent: Value, taker: Value) -> Value {
    json!({"t":[{"t":"123","o":"Yes"},{"t":"456","o":"No"}],"mos":"1","mts":"0.01","fd":{"r":rate,"e":exponent,"to":taker}})
}

fn book(bids: Value, asks: Value) -> Value {
    json!({"market":CONDITION,"asset_id":"123","hash":"book-hash","timestamp":"1234567890","min_order_size":"1","tick_size":"0.01","bids":bids,"asks":asks})
}

async fn context(
    gamma_body: Value,
    clob_body: Value,
    book_body: Value,
) -> polymarket_data::clob::execution_context::ExecutionContextObservation {
    let app = Router::new()
        .route(
            "/markets",
            get({
                let body = gamma_body.clone();
                move || {
                    let body = body.clone();
                    async move { axum::Json(body) }
                }
            }),
        )
        .route(
            "/clob-markets/{condition}",
            get({
                let body = clob_body.clone();
                move |Path(_): Path<String>| {
                    let body = body.clone();
                    async move { axum::Json(body) }
                }
            }),
        )
        .route(
            "/book",
            get({
                let body = book_body.clone();
                move |Query(_): Query<std::collections::HashMap<String, String>>| {
                    let body = body.clone();
                    async move { axum::Json(body) }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let reader =
        ClobExecutionContextReader::with_client_builder(reqwest::Client::builder(), &base, &base)
            .unwrap();
    reader
        .read_context(&ExecutionContextRequest {
            api_condition_id: CONDITION.to_owned(),
            selected_asset_id: "123".to_owned(),
            max_requests: 3,
            total_timeout: Duration::from_secs(3),
        })
        .await
        .unwrap()
}

fn positive_gamma() -> Value {
    gamma(json!(true), json!(0.02), json!(2), json!(true), "v2")
}
fn positive_clob() -> Value {
    clob(json!(0.02), json!(2), json!(true))
}
fn depth() -> Value {
    book(
        json!([{"price":"0.4","size":"3"},{"price":"0.3","size":"2"}]),
        json!([{"price":"0.6","size":"2"},{"price":"0.8","size":"3"}]),
    )
}

#[tokio::test]
async fn buy_and_sell_quote_full_depth_with_conservative_price_level_fees() {
    let ctx = context(positive_gamma(), positive_clob(), depth()).await;
    let buy = estimate_execution_quote(
        &ctx,
        ExecutionQuoteSide::Buy,
        Decimal::new(28, 1),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(buy.gross_shares(), Decimal::from(4));
    assert_eq!(buy.gross_notional(), Decimal::new(28, 1));
    assert_eq!(buy.estimated_platform_fee(), Decimal::new(334, 5));
    assert_eq!(buy.total_buy_cash(), Some(Decimal::new(280334, 5)));
    assert_eq!(buy.fee_kind(), ExecutionQuoteFeeKind::ModeledEstimate);
    assert_eq!(buy.fee_rate(), Decimal::new(2, 2));
    assert_eq!(buy.fee_exponent(), 2);
    assert_eq!(
        buy.fee_rounding_policy(),
        "ceil-per-consumed-price-level-to-5-decimals"
    );
    assert_eq!(buy.role(), ExecutionQuoteRole::Taker);
    assert_eq!(buy.builder_policy(), ExecutionQuoteBuilderPolicy::Disabled);
    assert_eq!(buy.book_hash(), "book-hash");
    assert_eq!(buy.unspent_buy_budget(), Some(Decimal::ZERO));
    assert_eq!(
        buy.fee_currency(),
        polymarket_data::clob::execution_quote::ExecutionQuoteFeeCurrency::ClobUsdNotional
    );
    let sell = estimate_execution_quote(
        &ctx,
        ExecutionQuoteSide::Sell,
        Decimal::from(4),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(sell.gross_notional(), Decimal::new(15, 1));
    assert_eq!(sell.estimated_platform_fee(), Decimal::new(435, 5));
    assert_eq!(sell.net_sell_proceeds(), Some(Decimal::new(149565, 5)));
}

#[tokio::test]
async fn recurring_buy_quantity_is_floored_without_exceeding_budget_and_prices_are_merged() {
    let book_body = book(
        json!([{"price":"0.4","size":"1"}]),
        json!([
            {"price":"0.8","size":"1"},
            {"price":"0.6","size":"1"},
            {"price":"0.6","size":"1"}
        ]),
    );
    let ctx = context(positive_gamma(), positive_clob(), book_body).await;
    let merged = estimate_execution_quote(
        &ctx,
        ExecutionQuoteSide::Buy,
        Decimal::new(12, 1),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(merged.gross_shares(), Decimal::from(2));
    assert_eq!(merged.estimated_platform_fee(), Decimal::new(231, 5));

    let book_body = book(
        json!([{"price":"0.4","size":"1"}]),
        json!([{"price":"0.3","size":"10"}]),
    );
    let ctx = context(positive_gamma(), positive_clob(), book_body).await;
    let recurring = estimate_execution_quote(
        &ctx,
        ExecutionQuoteSide::Buy,
        Decimal::ONE,
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(
        recurring.gross_shares(),
        Decimal::from_str_exact("3.333333333333333333").unwrap()
    );
    assert!(recurring.gross_notional() <= Decimal::ONE);
    assert_eq!(
        recurring.unspent_buy_budget(),
        Some(Decimal::ONE - recurring.gross_notional())
    );
}

#[tokio::test]
async fn explicit_disabled_fee_profile_is_exact_zero_and_fine_amounts_are_supported() {
    let ctx = context(
        gamma(json!(false), json!(0), json!(2), json!(true), "v2"),
        clob(json!(0), json!(2), json!(true)),
        depth(),
    )
    .await;
    let quote = estimate_execution_quote(
        &ctx,
        ExecutionQuoteSide::Sell,
        Decimal::new(1234567, 6),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(quote.estimated_platform_fee(), Decimal::ZERO);
    assert_eq!(quote.fee_kind(), ExecutionQuoteFeeKind::ExactZero);
    assert_eq!(quote.gross_shares(), Decimal::new(1234567, 6));
    let ctx = context(
        gamma(json!(false), json!(0), json!(0), json!(true), "v2"),
        clob(json!(0), json!(0), json!(false)),
        depth(),
    )
    .await;
    assert_eq!(
        estimate_execution_quote(
            &ctx,
            ExecutionQuoteSide::Buy,
            Decimal::ONE,
            Duration::from_secs(10)
        ),
        Err(ExecutionQuoteError::UnsupportedFeeMetadata)
    );
}

#[tokio::test]
async fn contradictory_missing_and_unsupported_fee_metadata_refuse() {
    let ctx = context(
        positive_gamma(),
        clob(json!(0.03), json!(2), json!(true)),
        depth(),
    )
    .await;
    assert_eq!(
        estimate_execution_quote(
            &ctx,
            ExecutionQuoteSide::Buy,
            Decimal::ONE,
            Duration::from_secs(10)
        ),
        Err(ExecutionQuoteError::UnsupportedFeeMetadata)
    );
    let ctx = context(
        gamma(Value::Null, json!(0), json!(0), json!(true), "v2"),
        clob(json!(0), json!(0), json!(true)),
        depth(),
    )
    .await;
    assert_eq!(
        estimate_execution_quote(
            &ctx,
            ExecutionQuoteSide::Buy,
            Decimal::ONE,
            Duration::from_secs(10)
        ),
        Err(ExecutionQuoteError::UnsupportedFeeMetadata)
    );
    let ctx = context(
        gamma(json!(true), json!(0.02), json!(2), json!(true), "v1"),
        positive_clob(),
        depth(),
    )
    .await;
    let v1_quote = estimate_execution_quote(
        &ctx,
        ExecutionQuoteSide::Sell,
        Decimal::ONE,
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(
        v1_quote.protocol_version(),
        polymarket_data::clob::execution_context::ObservedMarketVersion::V1
    );
    assert_eq!(v1_quote.selected_asset_id(), "123");
    let ctx = context(
        gamma(json!(true), json!(0.02), json!(9), json!(true), "v2"),
        clob(json!(0.02), json!(9), json!(true)),
        depth(),
    )
    .await;
    assert_eq!(
        estimate_execution_quote(
            &ctx,
            ExecutionQuoteSide::Buy,
            Decimal::ONE,
            Duration::from_secs(10)
        ),
        Err(ExecutionQuoteError::UnsupportedFeeMetadata)
    );
}

#[tokio::test]
async fn partial_depth_and_checked_overflow_are_refused() {
    let ctx = context(positive_gamma(), positive_clob(), depth()).await;
    assert_eq!(
        estimate_execution_quote(
            &ctx,
            ExecutionQuoteSide::Buy,
            Decimal::from(100),
            Duration::from_secs(10)
        ),
        Err(ExecutionQuoteError::InsufficientDepth)
    );
    let huge = Decimal::MAX.to_string();
    let giant_book = book(
        json!([{"price":"0.123456789123456789","size":huge}]),
        json!([{"price":"0.6","size":"1"}]),
    );
    let ctx = context(positive_gamma(), positive_clob(), giant_book).await;
    assert_eq!(
        estimate_execution_quote(
            &ctx,
            ExecutionQuoteSide::Sell,
            Decimal::MAX,
            Duration::from_secs(10)
        ),
        Err(ExecutionQuoteError::ArithmeticOverflow)
    );
}

#[tokio::test]
async fn quote_ttl_is_anchored_to_original_context_start() {
    let ctx = context(positive_gamma(), positive_clob(), depth()).await;
    let clone = ctx.clone();
    let first = estimate_execution_quote(
        &ctx,
        ExecutionQuoteSide::Sell,
        Decimal::ONE,
        Duration::from_secs(1),
    )
    .unwrap();
    let second = estimate_execution_quote(
        &clone,
        ExecutionQuoteSide::Sell,
        Decimal::ONE,
        Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(first.valid_until(), second.valid_until());
    tokio::time::sleep_until(first.valid_until()).await;
    assert_eq!(first.check_validity(), Err(ExecutionQuoteError::Expired));
    assert_eq!(
        estimate_execution_quote(
            &clone,
            ExecutionQuoteSide::Sell,
            Decimal::ONE,
            Duration::from_secs(1)
        ),
        Err(ExecutionQuoteError::Expired)
    );
}
