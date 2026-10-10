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
    ExecutionQuoteError, ExecutionQuoteSide, MarketBuyBudget, estimate_all_in_buy_execution_quote,
    estimate_execution_quote, estimate_normalized_market_buy_quote,
};
use rust_decimal::Decimal;
use serde_json::{Value, json};

const CONDITION: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn gamma(fees_enabled: bool, rate: Value) -> Value {
    json!([{
        "conditionId": CONDITION, "version": "v2", "outcomes": ["Yes", "No"],
        "clobTokenIds": ["123", "456"], "positionIds": ["123", "456"],
        "active": true, "closed": false, "acceptingOrders": true, "enableOrderBook": true,
        "orderMinSize": "5", "orderPriceMinTickSize": "0.01", "feesEnabled": fees_enabled,
        "feeSchedule": {"rate": rate, "exponent": 2, "takerOnly": true, "rebateRate": null}
    }])
}

fn clob(rate: Value) -> Value {
    json!({"t":[{"t":"123","o":"Yes"},{"t":"456","o":"No"}],
        "mos":"5","mts":"0.01","fd":{"r":rate,"e":2,"to":true}})
}

fn book(asks: Value) -> Value {
    json!({"market":CONDITION,"asset_id":"123","hash":"normalized-buy-book-hash",
        "timestamp":"1234567890","min_order_size":"5","tick_size":"0.01",
        "bids":[{"price":"0.06","size":"20"}],"asks":asks})
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

#[tokio::test]
async fn normalized_gross_budget_keeps_one_dollar_maker_at_low_price() {
    let ctx = context(
        gamma(false, json!(0)),
        clob(json!(0)),
        book(json!([{"price":"0.07","size":"20"}])),
    )
    .await;
    for budget in [
        MarketBuyBudget::GrossNotional(Decimal::ONE),
        MarketBuyBudget::AllInCash(Decimal::ONE),
    ] {
        let quote =
            estimate_normalized_market_buy_quote(&ctx, budget, Duration::from_secs(10)).unwrap();
        assert_eq!(quote.normalized_maker_notional(), Decimal::ONE);
        assert_eq!(quote.reserved_buy_cash(), Decimal::ONE);
        assert_eq!(
            quote.quote().gross_notional(),
            Decimal::from_str_exact("0.99999999999999999998").unwrap()
        );
        assert_eq!(
            quote.quote().unspent_buy_budget(),
            Some(Decimal::from_str_exact("0.00000000000000000002").unwrap())
        );
        assert_eq!(quote.required_maker_minimum(), Decimal::ONE);
        assert_eq!(
            quote.maker_amount_policy_version(),
            "polymarket-market-buy-maker-cent-floor-minimum/1"
        );
        assert_eq!(
            quote.maker_amount_source_commit(),
            "24e346374acef3e3a3da4e3c08a8981e0122ea81"
        );
        assert_eq!(
            quote.maker_amount_source_sha256(),
            "1e373ee5207426201cff4687c7dbaf4b2094483c4fda094da4c20065b0cd9fe0"
        );
    }
}

#[tokio::test]
async fn subminimum_normalized_gross_budget_is_rejected() {
    let ctx = context(
        gamma(false, json!(0)),
        clob(json!(0)),
        book(json!([{"price":"0.5","size":"20"}])),
    )
    .await;
    assert_eq!(
        estimate_normalized_market_buy_quote(
            &ctx,
            MarketBuyBudget::GrossNotional(Decimal::new(999, 3)),
            Duration::from_secs(10),
        )
        .unwrap_err(),
        ExecutionQuoteError::BelowMarketBuyCashMinimum,
    );
}

#[tokio::test]
async fn gross_budget_truncates_to_cents_and_preserves_original_request() {
    let ctx = context(
        gamma(false, json!(0)),
        clob(json!(0)),
        book(json!([{"price":"0.5","size":"20"}])),
    )
    .await;
    for (requested, maker, unspent) in [
        ("0.99", "0.99", "0"),
        ("1", "1", "0"),
        ("1.009", "1", "0.009"),
    ] {
        if requested == "0.99" {
            assert_eq!(
                estimate_normalized_market_buy_quote(
                    &ctx,
                    MarketBuyBudget::GrossNotional(Decimal::from_str_exact(requested).unwrap()),
                    Duration::from_secs(10),
                )
                .unwrap_err(),
                ExecutionQuoteError::BelowMarketBuyCashMinimum
            );
            continue;
        }
        let quote = estimate_normalized_market_buy_quote(
            &ctx,
            MarketBuyBudget::GrossNotional(Decimal::from_str_exact(requested).unwrap()),
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(
            quote.normalized_maker_notional(),
            Decimal::from_str_exact(maker).unwrap()
        );
        assert_eq!(
            quote.quote().requested_amount(),
            Decimal::from_str_exact(requested).unwrap()
        );
        assert_eq!(
            quote.quote().unspent_buy_budget(),
            Some(Decimal::from_str_exact(unspent).unwrap())
        );
    }
    let old = estimate_execution_quote(
        &ctx,
        ExecutionQuoteSide::Buy,
        Decimal::ONE,
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(old.requested_amount(), Decimal::ONE);
    assert_eq!(old.gross_notional(), Decimal::ONE);
}

#[tokio::test]
async fn all_in_fee_cap_uses_normalized_maker_minimum_and_reports_reserve_separately() {
    let ctx = context(
        gamma(true, json!(0.02)),
        clob(json!(0.02)),
        book(json!([{"price":"0.5","size":"20"}])),
    )
    .await;
    assert_eq!(
        estimate_normalized_market_buy_quote(
            &ctx,
            MarketBuyBudget::AllInCash(Decimal::ONE),
            Duration::from_secs(10),
        )
        .unwrap_err(),
        ExecutionQuoteError::BelowMarketBuyCashMinimum
    );

    let cap = Decimal::from_str_exact("1.0025").unwrap();
    let quote = estimate_normalized_market_buy_quote(
        &ctx,
        MarketBuyBudget::AllInCash(cap),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(quote.normalized_maker_notional(), Decimal::ONE);
    assert_eq!(
        quote.quote().estimated_platform_fee(),
        Decimal::from_str_exact("0.0025").unwrap()
    );
    assert_eq!(quote.reserved_buy_cash(), cap);
    assert_eq!(quote.quote().requested_amount(), cap);
    assert_eq!(quote.quote().total_buy_cash(), Some(cap));
    assert_eq!(quote.quote().unspent_buy_budget(), Some(Decimal::ZERO));
    assert_eq!(
        estimate_normalized_market_buy_quote(
            &ctx,
            MarketBuyBudget::AllInCash(Decimal::from_str_exact("1.00249").unwrap()),
            Duration::from_secs(10),
        )
        .unwrap_err(),
        ExecutionQuoteError::BelowMarketBuyCashMinimum
    );
    for (cap, maker, reserve) in [("1.01252", "1", "1.0025"), ("1.01253", "1.01", "1.01253")] {
        let boundary = estimate_normalized_market_buy_quote(
            &ctx,
            MarketBuyBudget::AllInCash(Decimal::from_str_exact(cap).unwrap()),
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(
            boundary.normalized_maker_notional(),
            Decimal::from_str_exact(maker).unwrap()
        );
        assert_eq!(
            boundary.reserved_buy_cash(),
            Decimal::from_str_exact(reserve).unwrap()
        );
    }

    let dust_context = context(
        gamma(false, json!(0)),
        clob(json!(0)),
        book(json!([{"price":"0.07","size":"20"}])),
    )
    .await;
    let dust_quote = estimate_normalized_market_buy_quote(
        &dust_context,
        MarketBuyBudget::GrossNotional(Decimal::ONE),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(dust_quote.reserved_buy_cash(), Decimal::ONE);
    assert!(dust_quote.quote().total_buy_cash().unwrap() < dust_quote.reserved_buy_cash());
}

#[tokio::test]
async fn all_in_chooses_largest_feasible_cent_across_merged_fee_levels() {
    let ctx = context(
        gamma(true, json!(0.02)),
        clob(json!(0.02)),
        book(json!([
            {"price":"0.6","size":"20"},
            {"price":"0.5","size":"2"},
            {"price":"0.5","size":"4"}
        ])),
    )
    .await;
    let quote = estimate_normalized_market_buy_quote(
        &ctx,
        MarketBuyBudget::AllInCash(Decimal::from(5)),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(
        quote.normalized_maker_notional(),
        Decimal::from_str_exact("4.98").unwrap()
    );
    assert_eq!(
        quote.quote().estimated_platform_fee(),
        Decimal::from_str_exact("0.01131").unwrap()
    );
    assert_eq!(
        quote.reserved_buy_cash(),
        Decimal::from_str_exact("4.99131").unwrap()
    );
    assert!(quote.reserved_buy_cash() <= Decimal::from(5));
    let next = estimate_execution_quote(
        &ctx,
        ExecutionQuoteSide::Buy,
        Decimal::from_str_exact("4.99").unwrap(),
        Duration::from_secs(10),
    )
    .unwrap();
    assert!(
        Decimal::from_str_exact("4.99").unwrap() + next.estimated_platform_fee() > Decimal::from(5)
    );
}

#[tokio::test]
async fn normalized_buy_retains_context_gates_and_rejects_conflicting_fee_metadata() {
    let ctx = context(
        gamma(false, json!(0)),
        clob(json!(0)),
        book(json!([{"price":"0.5","size":"20"}])),
    )
    .await;
    assert_eq!(ctx.request_count(), 3);
    let deadline = ctx.local_valid_until(Duration::from_secs(10)).unwrap();
    assert_eq!(
        estimate_normalized_market_buy_quote(
            &ctx,
            MarketBuyBudget::GrossNotional(Decimal::ONE),
            Duration::ZERO,
        )
        .unwrap_err(),
        ExecutionQuoteError::InvalidInput
    );
    assert_eq!(
        ctx.local_valid_until(Duration::from_secs(10)).unwrap(),
        deadline
    );
    tokio::time::sleep(Duration::from_millis(15)).await;
    let expired_clone = ctx.clone();
    assert_eq!(
        estimate_normalized_market_buy_quote(
            &expired_clone,
            MarketBuyBudget::GrossNotional(Decimal::ONE),
            Duration::from_millis(1),
        )
        .unwrap_err(),
        ExecutionQuoteError::Expired
    );
    assert_eq!(ctx.request_count(), 3);

    let conflicting = context(
        gamma(true, json!(0.02)),
        clob(json!(0.03)),
        book(json!([{"price":"0.5","size":"20"}])),
    )
    .await;
    assert_eq!(
        estimate_normalized_market_buy_quote(
            &conflicting,
            MarketBuyBudget::GrossNotional(Decimal::ONE),
            Duration::from_secs(10),
        )
        .unwrap_err(),
        ExecutionQuoteError::UnsupportedFeeMetadata
    );

    let mut missing_fee_body = gamma(true, json!(0.02));
    missing_fee_body[0]["feeSchedule"] = Value::Null;
    let missing_fee_clob = json!({"t":[{"t":"123","o":"Yes"},{"t":"456","o":"No"}],
        "mos":"5","mts":"0.01","fd":null});
    let malformed = context(
        missing_fee_body,
        missing_fee_clob,
        book(json!([{"price":"0.5","size":"20"}])),
    )
    .await;
    assert_eq!(
        estimate_normalized_market_buy_quote(
            &malformed,
            MarketBuyBudget::GrossNotional(Decimal::ONE),
            Duration::from_secs(10),
        )
        .unwrap_err(),
        ExecutionQuoteError::UnsupportedFeeMetadata
    );
}

#[tokio::test]
async fn insufficient_full_budget_depth_is_not_hidden_by_smaller_cent_choice() {
    let ctx = context(
        gamma(false, json!(0)),
        clob(json!(0)),
        book(json!([{"price":"0.5","size":"2"}])),
    )
    .await;
    assert_eq!(
        estimate_normalized_market_buy_quote(
            &ctx,
            MarketBuyBudget::AllInCash(Decimal::from(5)),
            Duration::from_secs(10),
        )
        .unwrap_err(),
        ExecutionQuoteError::InsufficientDepth
    );
    assert_eq!(
        estimate_all_in_buy_execution_quote(&ctx, Decimal::from(5), Duration::from_secs(10))
            .unwrap_err(),
        ExecutionQuoteError::InsufficientDepth
    );
}
