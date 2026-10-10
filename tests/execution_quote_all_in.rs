use std::time::Duration;

use axum::{
    Router,
    extract::{Path, Query},
    routing::get,
};
use polymarket_data::clob::execution_context::{
    ClobExecutionContextReader, ExecutionContextRequest,
};
use polymarket_data::clob::execution_quote::{
    ExecutionQuoteAmountKind, ExecutionQuoteError, ExecutionQuoteFeeKind, ExecutionQuoteSide,
    estimate_all_in_buy_execution_quote, estimate_execution_quote,
};
use rust_decimal::Decimal;
use serde_json::{Value, json};

const CONDITION: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn gamma(enabled: bool, rate: Value, exponent: Value) -> Value {
    json!([{
        "conditionId": CONDITION, "version": "v2", "outcomes": ["Yes", "No"],
        "clobTokenIds": ["123", "456"], "positionIds": ["123", "456"],
        "active": true, "closed": false, "acceptingOrders": true, "enableOrderBook": true,
        "orderMinSize": "1", "orderPriceMinTickSize": "0.01", "feesEnabled": enabled,
        "feeSchedule": {"rate": rate, "exponent": exponent, "takerOnly": true, "rebateRate": null}
    }])
}

fn clob(rate: Value, exponent: Value) -> Value {
    json!({"t":[{"t":"123","o":"Yes"},{"t":"456","o":"No"}],"mos":"1","mts":"0.01","fd":{"r":rate,"e":exponent,"to":true}})
}

fn book(asks: Value) -> Value {
    json!({"market":CONDITION,"asset_id":"123","hash":"book-hash","timestamp":"1234567890","min_order_size":"1","tick_size":"0.01","bids":[{"price":"0.4","size":"2"}],"asks":asks})
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

fn positive_fees() -> (Value, Value) {
    (
        gamma(true, json!(0.02), json!(2)),
        clob(json!(0.02), json!(2)),
    )
}

fn no_fees() -> (Value, Value) {
    (gamma(false, json!(0), json!(2)), clob(json!(0), json!(2)))
}

#[tokio::test]
async fn five_cash_budget_includes_positive_fees_and_maximizes_grid_quantity() {
    let (gamma_body, clob_body) = positive_fees();
    let ctx = context(
        gamma_body,
        clob_body,
        book(json!([{"price":"0.5","size":"20"}])),
    )
    .await;
    let quote =
        estimate_all_in_buy_execution_quote(&ctx, Decimal::from(5), Duration::from_secs(10))
            .unwrap();

    // At 0.5 and rate 0.02/exponent 2, fee is ceil(0.00125 * shares, 5dp).
    // 9.97506 shares cost 4.98753 gross + 0.01247 fee = exactly 5.
    assert_eq!(
        quote.gross_shares(),
        Decimal::from_str_exact("9.97506").unwrap()
    );
    assert_eq!(
        quote.gross_notional(),
        Decimal::from_str_exact("4.98753").unwrap()
    );
    assert_eq!(
        quote.estimated_platform_fee(),
        Decimal::from_str_exact("0.01247").unwrap()
    );
    assert_eq!(quote.total_buy_cash(), Some(Decimal::from(5)));
    assert_eq!(quote.unspent_buy_budget(), Some(Decimal::ZERO));
    assert_eq!(quote.amount_kind(), ExecutionQuoteAmountKind::BuyAllInCash);
    assert_eq!(quote.fee_kind(), ExecutionQuoteFeeKind::ModeledEstimate);

    let next = quote.gross_shares() + Decimal::from_str_exact("0.000000000000000001").unwrap();
    // The fee stays 0.01247 at the next share grid point, so gross + fee exceeds 5.
    assert!(
        next * Decimal::new(5, 1) + Decimal::from_str_exact("0.01247").unwrap() > Decimal::from(5)
    );
}

#[tokio::test]
async fn positive_fee_rounding_jump_limits_quantity_at_five_decimal_boundary() {
    let (gamma_body, clob_body) = positive_fees();
    let ctx = context(
        gamma_body,
        clob_body,
        book(json!([{"price":"0.5","size":"3"}])),
    )
    .await;
    let quote =
        estimate_all_in_buy_execution_quote(&ctx, Decimal::ONE, Duration::from_secs(10)).unwrap();
    assert_eq!(
        quote.gross_shares(),
        Decimal::from_str_exact("1.995").unwrap()
    );
    assert_eq!(
        quote.gross_notional(),
        Decimal::from_str_exact("0.9975").unwrap()
    );
    assert_eq!(
        quote.estimated_platform_fee(),
        Decimal::from_str_exact("0.0025").unwrap()
    );
    assert_eq!(quote.total_buy_cash(), Some(Decimal::ONE));
}

#[tokio::test]
async fn zero_fees_and_unordered_duplicate_levels_use_merged_ask_order() {
    let (gamma_body, clob_body) = no_fees();
    let ctx = context(
        gamma_body,
        clob_body,
        book(json!([
            {"price":"0.6","size":"2"},
            {"price":"0.5","size":"4"},
            {"price":"0.5","size":"6"}
        ])),
    )
    .await;
    let quote = estimate_all_in_buy_execution_quote(
        &ctx,
        Decimal::from_str_exact("6.2").unwrap(),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(quote.gross_shares(), Decimal::from_str_exact("12").unwrap());
    assert_eq!(
        quote.gross_notional(),
        Decimal::from_str_exact("6.2").unwrap()
    );
    assert_eq!(quote.estimated_platform_fee(), Decimal::ZERO);
    assert_eq!(quote.fee_kind(), ExecutionQuoteFeeKind::ExactZero);
    assert_eq!(quote.amount_kind(), ExecutionQuoteAmountKind::BuyAllInCash);
    assert_eq!(
        quote.total_buy_cash(),
        Some(Decimal::from_str_exact("6.2").unwrap())
    );
}

#[tokio::test]
async fn full_valid_decimal_quantity_is_not_limited_by_share_unit_mantissa() {
    let (gamma_body, clob_body) = no_fees();
    let ctx = context(
        gamma_body,
        clob_body,
        book(json!([{"price":"0.5","size":"10000000000000000000000000000"}])),
    )
    .await;
    let quote = estimate_all_in_buy_execution_quote(
        &ctx,
        Decimal::from_str_exact("5000000000000000000000000000").unwrap(),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(
        quote.gross_shares(),
        Decimal::from_str_exact("10000000000000000000000000000").unwrap()
    );
    assert_eq!(
        quote.gross_notional(),
        Decimal::from_str_exact("5000000000000000000000000000").unwrap()
    );
    assert_eq!(quote.total_buy_cash(), Some(quote.gross_notional()));
}

#[tokio::test]
async fn tiny_positive_fees_round_up_and_quantity_dust_is_reported() {
    let rate = json!(0.02);
    let ctx = context(
        gamma(true, rate.clone(), json!(8)),
        clob(rate, json!(8)),
        book(json!([{"price":"0.5","size":"0.01"}])),
    )
    .await;
    let quote = estimate_all_in_buy_execution_quote(
        &ctx,
        Decimal::from_str_exact("0.00501").unwrap(),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(
        quote.gross_shares(),
        Decimal::from_str_exact("0.01").unwrap()
    );
    assert_eq!(
        quote.gross_notional(),
        Decimal::from_str_exact("0.005").unwrap()
    );
    assert_eq!(
        quote.estimated_platform_fee(),
        Decimal::from_str_exact("0.00001").unwrap()
    );
    assert_eq!(
        quote.total_buy_cash(),
        Some(Decimal::from_str_exact("0.00501").unwrap())
    );

    let (gamma_body, clob_body) = no_fees();
    let ctx = context(
        gamma_body,
        clob_body,
        book(json!([{"price":"0.3","size":"10"}])),
    )
    .await;
    let quote =
        estimate_all_in_buy_execution_quote(&ctx, Decimal::ONE, Duration::from_secs(10)).unwrap();
    assert_eq!(
        quote.gross_shares(),
        Decimal::from_str_exact("3.333333333333333333").unwrap()
    );
    assert_eq!(
        quote.gross_notional(),
        Decimal::from_str_exact("0.9999999999999999999").unwrap()
    );
    assert_eq!(
        quote.unspent_buy_budget(),
        Some(Decimal::from_str_exact("0.0000000000000000001").unwrap())
    );
    assert_eq!(quote.total_buy_cash(), Some(quote.gross_notional()));
}

#[tokio::test]
async fn insufficient_displayed_depth_is_not_returned_as_a_partial_quote() {
    let (gamma_body, clob_body) = no_fees();
    let ctx = context(
        gamma_body,
        clob_body,
        book(json!([{"price":"0.5","size":"2"}])),
    )
    .await;
    assert_eq!(
        estimate_all_in_buy_execution_quote(
            &ctx,
            Decimal::from_str_exact("2.000000000000000001").unwrap(),
            Duration::from_secs(10),
        ),
        Err(ExecutionQuoteError::InsufficientDepth)
    );
}

#[tokio::test]
async fn original_context_deadline_is_preserved_and_below_precision_budget_refuses() {
    let (gamma_body, clob_body) = no_fees();
    let ctx = context(
        gamma_body,
        clob_body,
        book(json!([{"price":"0.5","size":"2"}])),
    )
    .await;
    assert_eq!(
        estimate_all_in_buy_execution_quote(
            &ctx,
            Decimal::from_str_exact("0.0000000000000000001").unwrap(),
            Duration::from_secs(10),
        ),
        Err(ExecutionQuoteError::BuyQuantityPrecision)
    );
    assert!(
        estimate_all_in_buy_execution_quote(&ctx, Decimal::ONE, Duration::from_millis(10),).is_ok()
    );
    tokio::time::sleep(Duration::from_millis(15)).await;
    assert_eq!(
        estimate_all_in_buy_execution_quote(&ctx, Decimal::ONE, Duration::from_millis(10),),
        Err(ExecutionQuoteError::Expired)
    );
}

#[tokio::test]
async fn existing_gross_buy_and_sell_inputs_have_explicit_amount_kinds() {
    let (gamma_body, clob_body) = no_fees();
    let ctx = context(
        gamma_body,
        clob_body,
        book(json!([{"price":"0.5","size":"4"}])),
    )
    .await;
    let gross_buy = estimate_execution_quote(
        &ctx,
        ExecutionQuoteSide::Buy,
        Decimal::ONE,
        Duration::from_secs(10),
    )
    .unwrap();
    let sell = estimate_execution_quote(
        &ctx,
        ExecutionQuoteSide::Sell,
        Decimal::ONE,
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(
        gross_buy.amount_kind(),
        ExecutionQuoteAmountKind::BuyGrossNotional
    );
    assert_eq!(sell.amount_kind(), ExecutionQuoteAmountKind::SellShares);
}

#[tokio::test]
async fn fractional_depth_below_share_grid_does_not_hide_insufficient_depth() {
    for asks in [
        json!([{"price":"0.5","size":"2.0000000000000000001"}]),
        json!([
            {"price":"0.5","size":"2"},
            {"price":"0.6","size":"0.0000000000000000001"}
        ]),
    ] {
        let (gamma_body, clob_body) = no_fees();
        let ctx = context(gamma_body, clob_body, book(asks)).await;
        assert_eq!(
            estimate_all_in_buy_execution_quote(&ctx, Decimal::from(2), Duration::from_secs(10)),
            Err(ExecutionQuoteError::InsufficientDepth)
        );
    }
}

#[tokio::test]
async fn all_in_budget_crosses_positive_fee_levels_with_exact_residual() {
    let (gamma_body, clob_body) = positive_fees();
    let ctx = context(
        gamma_body,
        clob_body,
        book(json!([
            {"price":"0.6","size":"20"},
            {"price":"0.4","size":"1"},
            {"price":"0.4","size":"1"}
        ])),
    )
    .await;
    let quote =
        estimate_all_in_buy_execution_quote(&ctx, Decimal::from(5), Duration::from_secs(10))
            .unwrap();
    // Independent Fraction arithmetic: consume2 at0.4, then6.982733333333333333 at0.6.
    assert_eq!(
        quote.gross_shares(),
        Decimal::from_str_exact("8.982733333333333333").unwrap()
    );
    assert_eq!(
        quote.gross_notional(),
        Decimal::from_str_exact("4.9896399999999999998").unwrap()
    );
    assert_eq!(
        quote.estimated_platform_fee(),
        Decimal::from_str_exact("0.01036").unwrap()
    );
    assert_eq!(
        quote.unspent_buy_budget(),
        Some(Decimal::from_str_exact("0.0000000000000000002").unwrap())
    );
    assert_eq!(
        quote.total_buy_cash(),
        Some(Decimal::from_str_exact("4.9999999999999999998").unwrap())
    );
}
