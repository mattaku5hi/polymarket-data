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
    ExecutionQuoteAmountKind, ExecutionQuoteError, ExecutionQuoteVenueMinimumStatus,
    MarketBuyBudget, ProtectedMarketBuyQuote, estimate_protected_market_buy_quote,
};
use rust_decimal::Decimal;
use serde_json::{Value, json};

const CONDITION: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn gamma(tick: &str, enabled: bool, rate: Value) -> Value {
    gamma_with_exponent(tick, enabled, rate, 2)
}

fn gamma_with_exponent(tick: &str, enabled: bool, rate: Value, exponent: u32) -> Value {
    json!([{
        "conditionId": CONDITION, "version": "v2", "outcomes": ["Yes", "No"],
        "clobTokenIds": ["123", "456"], "positionIds": ["123", "456"],
        "active": true, "closed": false, "acceptingOrders": true, "enableOrderBook": true,
        "orderMinSize": "5", "orderPriceMinTickSize": tick, "feesEnabled": enabled,
        "feeSchedule": {"rate": rate, "exponent": exponent, "takerOnly": true, "rebateRate": null}
    }])
}

fn clob(tick: &str, rate: Value) -> Value {
    clob_with_exponent(tick, rate, 2)
}

fn clob_with_exponent(tick: &str, rate: Value, exponent: u32) -> Value {
    json!({"t":[{"t":"123","o":"Yes"},{"t":"456","o":"No"}],
        "mos":"5","mts":tick,"fd":{"r":rate,"e":exponent,"to":true}})
}

fn book(tick: &str, asks: Value) -> Value {
    json!({"market":CONDITION,"asset_id":"123","hash":"protected-buy-book-hash",
        "timestamp":"1234567890","min_order_size":"5","tick_size":tick,
        "bids":[{"price":"0.5","size":"20"}],"asks":asks})
}

async fn context(
    tick: &str,
    gamma_body: Value,
    clob_body: Value,
    asks: Value,
) -> polymarket_data::clob::execution_context::ExecutionContextObservation {
    let book_body = book(tick, asks);
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

fn gross_quote(
    context: &polymarket_data::clob::execution_context::ExecutionContextObservation,
    maker_budget: Decimal,
    max_price: Decimal,
    max_age: Duration,
) -> Result<ProtectedMarketBuyQuote, ExecutionQuoteError> {
    estimate_protected_market_buy_quote(
        context,
        MarketBuyBudget::GrossNotional(maker_budget),
        max_price,
        max_age,
    )
}

#[tokio::test]
async fn one_dollar_protected_buy_exposes_exact_six_decimal_order_legs() {
    let asks = json!([{"price":"0.07","size":"14.2857"}]);
    let ctx = context(
        "0.01",
        gamma("0.01", false, json!(0)),
        clob("0.01", json!(0)),
        asks,
    )
    .await;
    let max_age = Duration::from_secs(10);
    let quote = gross_quote(
        &ctx,
        Decimal::ONE,
        Decimal::from_str_exact("0.07").unwrap(),
        max_age,
    )
    .unwrap();

    assert_eq!(quote.normalized_maker_notional(), Decimal::ONE);
    assert_eq!(quote.required_maker_minimum(), Decimal::ONE);
    assert_eq!(quote.maker_cash_base_units(), 1_000_000);
    assert_eq!(quote.taker_share_base_units(), 14_285_700);
    assert_eq!(quote.order_amount_decimals(), 6);
    assert_eq!(quote.max_price(), Decimal::from_str_exact("0.07").unwrap());
    assert_eq!(quote.quote().requested_amount(), Decimal::ONE);
    assert_eq!(
        quote.quote().gross_shares(),
        Decimal::from_str_exact("14.2857").unwrap()
    );
    assert_eq!(
        quote.quote().gross_notional(),
        Decimal::from_str_exact("0.999999").unwrap()
    );
    assert_eq!(
        quote.quote().unspent_buy_budget(),
        Some(Decimal::from_str_exact("0.000001").unwrap())
    );
    assert_eq!(quote.quote().estimated_platform_fee(), Decimal::ZERO);
    assert_eq!(quote.reserved_buy_cash(), Decimal::ONE);
    assert_eq!(
        quote.quote().venue_minimum_status(),
        ExecutionQuoteVenueMinimumStatus::Unverified
    );
    assert_eq!(quote.quote().request_count(), 3);
    assert_eq!(
        quote.order_amount_policy_version(),
        "polymarket-protected-buy-tick-share-six-decimal-guard/1"
    );
    assert_eq!(
        quote.order_amount_source_commit(),
        "24e346374acef3e3a3da4e3c08a8981e0122ea81"
    );
    assert_eq!(
        quote.order_amount_source_sha256(),
        "1e373ee5207426201cff4687c7dbaf4b2094483c4fda094da4c20065b0cd9fe0"
    );
    assert_eq!(
        quote.quote().valid_until(),
        ctx.local_valid_until(max_age).unwrap()
    );
}

#[tokio::test]
async fn protected_quote_reports_typed_price_and_depth_failures() {
    let ctx = context(
        "0.01",
        gamma("0.01", false, json!(0)),
        clob("0.01", json!(0)),
        json!([{"price":"0.07","size":"20"}]),
    )
    .await;
    assert_eq!(
        gross_quote(
            &ctx,
            Decimal::ONE,
            Decimal::from_str_exact("0.071").unwrap(),
            Duration::from_secs(10),
        )
        .unwrap_err(),
        ExecutionQuoteError::InvalidProtectedMarketBuyPrice
    );
    let shallow = context(
        "0.01",
        gamma("0.01", false, json!(0)),
        clob("0.01", json!(0)),
        json!([{"price":"0.07","size":"5"}]),
    )
    .await;
    assert_eq!(
        gross_quote(
            &shallow,
            Decimal::ONE,
            Decimal::from_str_exact("0.07").unwrap(),
            Duration::from_secs(10),
        )
        .unwrap_err(),
        ExecutionQuoteError::InsufficientDepth
    );
}

#[tokio::test]
async fn protected_walk_caps_shares_and_preserves_unspent_cash_at_better_prices() {
    let ctx = context(
        "0.01",
        gamma("0.01", true, json!(0.02)),
        clob("0.01", json!(0.02)),
        json!([
            {"price":"0.07","size":"20"},
            {"price":"0.06","size":"5"}
        ]),
    )
    .await;
    let quote = gross_quote(
        &ctx,
        Decimal::from_str_exact("1.009").unwrap(),
        Decimal::from_str_exact("0.07").unwrap(),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(quote.normalized_maker_notional(), Decimal::ONE);
    assert_eq!(quote.maker_cash_base_units(), 1_000_000);
    assert_eq!(quote.taker_share_base_units(), 14_285_700);
    assert_eq!(
        quote.quote().requested_amount(),
        Decimal::from_str_exact("1.009").unwrap()
    );
    assert_eq!(
        quote.quote().gross_shares(),
        Decimal::from_str_exact("14.2857").unwrap()
    );
    assert_eq!(
        quote.quote().gross_notional(),
        Decimal::from_str_exact("0.949999").unwrap()
    );
    assert_eq!(
        quote.quote().unspent_buy_budget(),
        Some(Decimal::from_str_exact("0.059001").unwrap())
    );
    assert_eq!(
        quote.quote().estimated_platform_fee(),
        Decimal::from_str_exact("0.00111").unwrap()
    );
    assert_eq!(
        quote.quote().total_buy_cash(),
        Some(Decimal::from_str_exact("0.951109").unwrap())
    );
    assert_eq!(
        quote.reserved_buy_cash(),
        Decimal::from_str_exact("1.00111").unwrap()
    );

    let exact_cent = gross_quote(
        &ctx,
        Decimal::ONE,
        Decimal::from_str_exact("0.07").unwrap(),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(
        exact_cent.quote().gross_notional(),
        Decimal::from_str_exact("0.949999").unwrap()
    );
    assert_eq!(
        exact_cent.quote().unspent_buy_budget(),
        Some(Decimal::from_str_exact("0.050001").unwrap())
    );
}

#[tokio::test]
async fn asks_above_unchanged_cap_do_not_complete_target_shares() {
    let ctx = context(
        "0.01",
        gamma("0.01", false, json!(0)),
        clob("0.01", json!(0)),
        json!([
            {"price":"0.07","size":"4"},
            {"price":"0.071","size":"20"}
        ]),
    )
    .await;
    assert_eq!(
        gross_quote(
            &ctx,
            Decimal::ONE,
            Decimal::from_str_exact("0.07").unwrap(),
            Duration::from_secs(10),
        )
        .unwrap_err(),
        ExecutionQuoteError::InsufficientDepth
    );
}

#[tokio::test]
async fn protected_price_uses_supported_tick_grid_without_snapping() {
    let cases = [
        ("0.1", "0.5"),
        ("0.01", "0.5"),
        ("0.005", "0.5"),
        ("0.0025", "0.5"),
        ("0.001", "0.5"),
        ("0.0001", "0.5"),
    ];
    for (tick, cap) in cases {
        let ctx = context(
            tick,
            gamma(tick, false, json!(0)),
            clob(tick, json!(0)),
            json!([{"price":"0.5","size":"20"}]),
        )
        .await;
        let quote = gross_quote(
            &ctx,
            Decimal::ONE,
            Decimal::from_str_exact(cap).unwrap(),
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(quote.order_amount_decimals(), 6);
        assert_eq!(quote.taker_share_base_units(), 2_000_000);
        assert_eq!(quote.max_price(), Decimal::from_str_exact(cap).unwrap());
    }

    let nontrivial_amounts = [
        ("0.1", "0.9", 1_111_000),
        ("0.01", "0.45", 2_222_200),
        ("0.005", "0.335", 2_985_070),
        ("0.0025", "0.4325", 2_312_138),
        ("0.001", "0.962", 1_039_500),
        ("0.0001", "0.4275", 2_339_181),
    ];
    for (tick, cap, expected_units) in nontrivial_amounts {
        let ctx = context(
            tick,
            gamma(tick, false, json!(0)),
            clob(tick, json!(0)),
            json!([{"price":cap,"size":"20"}]),
        )
        .await;
        let quote = gross_quote(
            &ctx,
            Decimal::ONE,
            Decimal::from_str_exact(cap).unwrap(),
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(quote.taker_share_base_units(), expected_units);
    }

    let coarse = context(
        "0.1",
        gamma("0.1", false, json!(0)),
        clob("0.1", json!(0)),
        json!([{"price":"0.6","size":"5"}]),
    )
    .await;
    assert_eq!(
        gross_quote(
            &coarse,
            Decimal::ONE,
            Decimal::from_str_exact("0.6").unwrap(),
            Duration::from_secs(10),
        )
        .unwrap_err(),
        ExecutionQuoteError::ProtectedPricePrecision
    );

    let safe = context(
        "0.1",
        gamma("0.1", false, json!(0)),
        clob("0.1", json!(0)),
        json!([{"price":"0.9","size":"5"}]),
    )
    .await;
    let quote = gross_quote(
        &safe,
        Decimal::ONE,
        Decimal::from_str_exact("0.9").unwrap(),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(quote.taker_share_base_units(), 1_111_000);
}

#[tokio::test]
async fn malformed_caps_and_unsupported_ticks_refuse_instead_of_rounding() {
    let ctx = context(
        "0.01",
        gamma("0.01", false, json!(0)),
        clob("0.01", json!(0)),
        json!([{"price":"0.5","size":"20"}]),
    )
    .await;
    for cap in ["0", "1", "0.071"] {
        assert_eq!(
            gross_quote(
                &ctx,
                Decimal::ONE,
                Decimal::from_str_exact(cap).unwrap(),
                Duration::from_secs(10),
            )
            .unwrap_err(),
            ExecutionQuoteError::InvalidProtectedMarketBuyPrice
        );
    }
    let unsupported = context(
        "0.0005",
        gamma("0.0005", false, json!(0)),
        clob("0.0005", json!(0)),
        json!([{"price":"0.5","size":"20"}]),
    )
    .await;
    assert_eq!(
        gross_quote(
            &unsupported,
            Decimal::ONE,
            Decimal::from_str_exact("0.5").unwrap(),
            Duration::from_secs(10),
        )
        .unwrap_err(),
        ExecutionQuoteError::UnsupportedProtectedMarketBuyTick
    );
}

#[tokio::test]
async fn positive_fee_model_and_expiry_provenance_are_preserved() {
    let ctx = context(
        "0.01",
        gamma("0.01", true, json!(0.02)),
        clob("0.01", json!(0.02)),
        json!([{"price":"0.5","size":"20"}]),
    )
    .await;
    let max_age = Duration::from_secs(10);
    let quote = gross_quote(
        &ctx,
        Decimal::ONE,
        Decimal::from_str_exact("0.5").unwrap(),
        max_age,
    )
    .unwrap();
    assert_eq!(
        quote.quote().estimated_platform_fee(),
        Decimal::from_str_exact("0.0025").unwrap()
    );
    assert_eq!(
        quote.quote().total_buy_cash(),
        Some(Decimal::from_str_exact("1.0025").unwrap())
    );
    assert_eq!(
        quote.reserved_buy_cash(),
        Decimal::from_str_exact("1.0025").unwrap()
    );
    assert_eq!(
        quote.quote().fee_model_version(),
        "clob-api-fee-curve-price-level-ceil-5dp-estimate/1"
    );
    assert_eq!(
        quote.quote().fee_rounding_policy(),
        "ceil-per-consumed-price-level-to-5-decimals"
    );
    assert_eq!(
        quote.quote().fee_aggregation_policy(),
        "sum-rounded-displayed-price-level-estimates"
    );
    assert_eq!(
        quote.quote().fee_currency(),
        polymarket_data::clob::execution_quote::ExecutionQuoteFeeCurrency::ClobUsdNotional
    );
    assert_eq!(
        quote.quote().valid_until(),
        ctx.local_valid_until(max_age).unwrap()
    );

    assert_eq!(
        gross_quote(
            &ctx,
            Decimal::ONE,
            Decimal::from_str_exact("0.5").unwrap(),
            Duration::ZERO,
        )
        .unwrap_err(),
        ExecutionQuoteError::InvalidInput
    );
    assert_eq!(
        estimate_protected_market_buy_quote(
            &ctx,
            MarketBuyBudget::AllInCash(Decimal::from_str_exact("1.0025").unwrap()),
            Decimal::from_str_exact("0.5").unwrap(),
            Duration::ZERO,
        )
        .unwrap_err(),
        ExecutionQuoteError::InvalidInput
    );
    tokio::time::sleep(Duration::from_millis(15)).await;
    let cloned = ctx.clone();
    assert_eq!(
        gross_quote(
            &cloned,
            Decimal::ONE,
            Decimal::from_str_exact("0.5").unwrap(),
            Duration::from_millis(1),
        )
        .unwrap_err(),
        ExecutionQuoteError::Expired
    );
    assert_eq!(
        estimate_protected_market_buy_quote(
            &cloned,
            MarketBuyBudget::AllInCash(Decimal::from_str_exact("1.0025").unwrap()),
            Decimal::from_str_exact("0.5").unwrap(),
            Duration::from_millis(1),
        )
        .unwrap_err(),
        ExecutionQuoteError::Expired
    );
    assert_eq!(ctx.request_count(), 3);
}

#[tokio::test]
async fn missing_or_conflicting_fee_metadata_is_refused() {
    let mut gamma_body = gamma("0.01", true, json!(0.02));
    gamma_body[0]["feeSchedule"] = Value::Null;
    let missing = context(
        "0.01",
        gamma_body,
        json!({"t":[{"t":"123","o":"Yes"},{"t":"456","o":"No"}],
            "mos":"5","mts":"0.01","fd":null}),
        json!([{"price":"0.5","size":"20"}]),
    )
    .await;
    assert_eq!(
        gross_quote(
            &missing,
            Decimal::ONE,
            Decimal::from_str_exact("0.5").unwrap(),
            Duration::from_secs(10),
        )
        .unwrap_err(),
        ExecutionQuoteError::UnsupportedFeeMetadata
    );
    assert_eq!(
        estimate_protected_market_buy_quote(
            &missing,
            MarketBuyBudget::AllInCash(Decimal::from_str_exact("1.01").unwrap()),
            Decimal::from_str_exact("0.5").unwrap(),
            Duration::from_secs(10),
        )
        .unwrap_err(),
        ExecutionQuoteError::UnsupportedFeeMetadata
    );

    let conflicting = context(
        "0.01",
        gamma("0.01", true, json!(0.02)),
        clob("0.01", json!(0.03)),
        json!([{"price":"0.5","size":"20"}]),
    )
    .await;
    assert_eq!(
        gross_quote(
            &conflicting,
            Decimal::ONE,
            Decimal::from_str_exact("0.5").unwrap(),
            Duration::from_secs(10),
        )
        .unwrap_err(),
        ExecutionQuoteError::UnsupportedFeeMetadata
    );
    assert_eq!(
        estimate_protected_market_buy_quote(
            &conflicting,
            MarketBuyBudget::AllInCash(Decimal::from_str_exact("1.01").unwrap()),
            Decimal::from_str_exact("0.5").unwrap(),
            Duration::from_secs(10),
        )
        .unwrap_err(),
        ExecutionQuoteError::UnsupportedFeeMetadata
    );
}

#[tokio::test]
async fn protected_all_in_search_selects_greatest_guard_safe_cent() {
    let ctx = context(
        "0.1",
        gamma("0.1", false, json!(0)),
        clob("0.1", json!(0)),
        json!([{"price":"0.6","size":"3"}]),
    )
    .await;
    let quote = estimate_protected_market_buy_quote(
        &ctx,
        MarketBuyBudget::AllInCash(Decimal::from_str_exact("1.04").unwrap()),
        Decimal::from_str_exact("0.6").unwrap(),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(
        quote.normalized_maker_notional(),
        Decimal::from_str_exact("1.02").unwrap()
    );
    assert_eq!(quote.maker_cash_base_units(), 1_020_000);
    assert_eq!(quote.taker_share_base_units(), 1_700_000);
    assert_eq!(
        quote.reserved_buy_cash(),
        Decimal::from_str_exact("1.02").unwrap()
    );
    assert_eq!(
        quote.quote().requested_amount(),
        Decimal::from_str_exact("1.04").unwrap()
    );
    assert_eq!(
        quote.quote().gross_notional(),
        Decimal::from_str_exact("1.02").unwrap()
    );
    assert_eq!(
        quote.quote().unspent_buy_budget(),
        Some(Decimal::from_str_exact("0.02").unwrap())
    );
    assert_eq!(
        quote.quote().amount_kind(),
        ExecutionQuoteAmountKind::BuyAllInCash
    );
    assert_eq!(quote.quote().request_count(), 3);
}

#[tokio::test]
async fn protected_all_in_fee_reserve_selects_maximum_feasible_cent() {
    let ctx = context(
        "0.1",
        gamma_with_exponent("0.1", true, json!(0.01), 1),
        clob_with_exponent("0.1", json!(0.01), 1),
        json!([{"price":"0.5","size":"3"}]),
    )
    .await;
    let quote = estimate_protected_market_buy_quote(
        &ctx,
        MarketBuyBudget::AllInCash(Decimal::from_str_exact("1.04").unwrap()),
        Decimal::from_str_exact("0.5").unwrap(),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(
        quote.normalized_maker_notional(),
        Decimal::from_str_exact("1.03").unwrap()
    );
    assert_eq!(quote.maker_cash_base_units(), 1_030_000);
    assert_eq!(quote.taker_share_base_units(), 2_060_000);
    assert_eq!(
        quote.quote().estimated_platform_fee(),
        Decimal::from_str_exact("0.00515").unwrap()
    );
    assert_eq!(
        quote.reserved_buy_cash(),
        Decimal::from_str_exact("1.03515").unwrap()
    );
    assert_eq!(
        quote.quote().unspent_buy_budget(),
        Some(Decimal::from_str_exact("0.00485").unwrap())
    );
}

#[tokio::test]
async fn protected_all_in_minimum_and_better_price_residual_are_cash_cap_aware() {
    let min_ctx = context(
        "0.01",
        gamma("0.01", true, json!(0.02)),
        clob("0.01", json!(0.02)),
        json!([{"price":"0.5","size":"20"}]),
    )
    .await;
    assert_eq!(
        estimate_protected_market_buy_quote(
            &min_ctx,
            MarketBuyBudget::AllInCash(Decimal::ONE),
            Decimal::from_str_exact("0.5").unwrap(),
            Duration::from_secs(10),
        )
        .unwrap_err(),
        ExecutionQuoteError::BelowMarketBuyCashMinimum
    );
    let exact_fee_cash = estimate_protected_market_buy_quote(
        &min_ctx,
        MarketBuyBudget::AllInCash(Decimal::from_str_exact("1.0025").unwrap()),
        Decimal::from_str_exact("0.5").unwrap(),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(exact_fee_cash.normalized_maker_notional(), Decimal::ONE);
    assert_eq!(exact_fee_cash.taker_share_base_units(), 2_000_000);
    assert_eq!(
        exact_fee_cash.quote().estimated_platform_fee(),
        Decimal::from_str_exact("0.0025").unwrap()
    );
    assert_eq!(
        exact_fee_cash.reserved_buy_cash(),
        Decimal::from_str_exact("1.0025").unwrap()
    );
    assert_eq!(
        exact_fee_cash.quote().unspent_buy_budget(),
        Some(Decimal::ZERO)
    );

    let residual_ctx = context(
        "0.01",
        gamma("0.01", true, json!(0.02)),
        clob("0.01", json!(0.02)),
        json!([
            {"price":"0.07","size":"20"},
            {"price":"0.06","size":"2"},
            {"price":"0.06","size":"3"}
        ]),
    )
    .await;
    let residual = estimate_protected_market_buy_quote(
        &residual_ctx,
        MarketBuyBudget::AllInCash(Decimal::from_str_exact("1.00111").unwrap()),
        Decimal::from_str_exact("0.07").unwrap(),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(residual.normalized_maker_notional(), Decimal::ONE);
    assert_eq!(
        residual.quote().gross_notional(),
        Decimal::from_str_exact("0.949999").unwrap()
    );
    assert_eq!(
        residual.quote().estimated_platform_fee(),
        Decimal::from_str_exact("0.00111").unwrap()
    );
    assert_eq!(
        residual.quote().unspent_buy_budget(),
        Some(Decimal::from_str_exact("0.050001").unwrap())
    );
    assert_eq!(
        residual.reserved_buy_cash(),
        Decimal::from_str_exact("1.00111").unwrap()
    );
}

#[tokio::test]
async fn protected_all_in_refuses_incomplete_cap_depth_and_no_safe_amount() {
    let shallow = context(
        "0.1",
        gamma("0.1", false, json!(0)),
        clob("0.1", json!(0)),
        json!([
            {"price":"0.5","size":"1"},
            {"price":"0.6","size":"20"}
        ]),
    )
    .await;
    assert_eq!(
        estimate_protected_market_buy_quote(
            &shallow,
            MarketBuyBudget::AllInCash(Decimal::from(2)),
            Decimal::from_str_exact("0.5").unwrap(),
            Duration::from_secs(10),
        )
        .unwrap_err(),
        ExecutionQuoteError::InsufficientDepth
    );

    let no_safe = context(
        "0.1",
        gamma("0.1", false, json!(0)),
        clob("0.1", json!(0)),
        json!([{"price":"0.6","size":"5"}]),
    )
    .await;
    assert_eq!(
        estimate_protected_market_buy_quote(
            &no_safe,
            MarketBuyBudget::AllInCash(Decimal::ONE),
            Decimal::from_str_exact("0.6").unwrap(),
            Duration::from_secs(10),
        )
        .unwrap_err(),
        ExecutionQuoteError::ProtectedPricePrecision
    );
}

#[tokio::test]
async fn coarse_tick_all_in_search_matches_exhaustive_integer_guard_oracle() {
    let ctx = context(
        "0.1",
        gamma("0.1", false, json!(0)),
        clob("0.1", json!(0)),
        json!([{"price":"0.6","size":"20"}]),
    )
    .await;
    for cap_cents in 100i64..=130 {
        let cap = Decimal::new(cap_cents, 2);
        let max_maker_cents = cap_cents;
        let expected = (100i64..=max_maker_cents).rev().find(|maker_cents| {
            let taker_millis = 100 * maker_cents / 6;
            let maker_units = maker_cents * 10_000;
            let taker_units = taker_millis * 1_000;
            maker_units * 10 >= taker_units * 6 && maker_units * 10_000 < taker_units * 6_001
        });
        let result = estimate_protected_market_buy_quote(
            &ctx,
            MarketBuyBudget::AllInCash(cap),
            Decimal::from_str_exact("0.6").unwrap(),
            Duration::from_secs(10),
        );
        match expected {
            Some(maker_cents) => assert_eq!(
                result.unwrap().normalized_maker_notional(),
                Decimal::new(maker_cents, 2),
                "cash cap {cap}"
            ),
            None => assert_eq!(
                result.unwrap_err(),
                ExecutionQuoteError::ProtectedPricePrecision
            ),
        }
    }
}
