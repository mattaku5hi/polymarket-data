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
    ExecutionQuoteError, ExecutionQuoteMarketMinimumBasis, ExecutionQuoteMarketMinimumStatus,
    ExecutionQuoteSide, ExecutionQuoteVenueMinimumStatus, estimate_all_in_buy_execution_quote,
    estimate_execution_quote,
};
use rust_decimal::Decimal;
use serde_json::{Value, json};

const CONDITION: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn gamma(fees_enabled: bool, rate: Value, order_min_size: &str) -> Value {
    json!([{
        "conditionId": CONDITION, "version": "v2", "outcomes": ["Yes", "No"],
        "clobTokenIds": ["123", "456"], "positionIds": ["123", "456"],
        "active": true, "closed": false, "acceptingOrders": true, "enableOrderBook": true,
        "orderMinSize": order_min_size, "orderPriceMinTickSize": "0.01",
        "feesEnabled": fees_enabled,
        "feeSchedule": {"rate": rate, "exponent": 2, "takerOnly": true, "rebateRate": null}
    }])
}

fn clob(rate: Value, mos: &str) -> Value {
    json!({"t":[{"t":"123","o":"Yes"},{"t":"456","o":"No"}],
        "mos":mos,"mts":"0.01","fd":{"r":rate,"e":2,"to":true}})
}

fn book() -> Value {
    json!({"market":CONDITION,"asset_id":"123","hash":"minimum-profile-book-hash",
        "timestamp":"1234567890","min_order_size":"5","tick_size":"0.01",
        "bids":[{"price":"0.5","size":"20"}],
        "asks":[{"price":"0.5","size":"20"}]})
}

async fn context(
    gamma_body: Value,
    clob_body: Value,
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
                let body = book();
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
async fn buy_gross_minimum_uses_requested_input_at_the_one_dollar_boundary() {
    let ctx = context(gamma(false, json!(0), "5"), clob(json!(0), "5")).await;
    let max_age = Duration::from_secs(10);
    for (amount, expected) in [
        (
            "0.99",
            ExecutionQuoteMarketMinimumStatus::BelowClientBuyMinimum,
        ),
        (
            "1",
            ExecutionQuoteMarketMinimumStatus::MeetsClientBuyMinimum,
        ),
        (
            "1.01",
            ExecutionQuoteMarketMinimumStatus::MeetsClientBuyMinimum,
        ),
    ] {
        let quote = estimate_execution_quote(
            &ctx,
            ExecutionQuoteSide::Buy,
            Decimal::from_str_exact(amount).unwrap(),
            max_age,
        )
        .unwrap();
        assert_eq!(
            quote.market_minimum_check_amount(),
            quote.requested_amount()
        );
        assert_eq!(
            quote.market_minimum_basis(),
            ExecutionQuoteMarketMinimumBasis::RequestedBuyGrossNotional
        );
        assert_eq!(quote.market_minimum_status(), expected);
        assert_eq!(
            quote.venue_minimum_status(),
            ExecutionQuoteVenueMinimumStatus::Unverified
        );
        assert_eq!(
            quote.required_market_buy_notional_minimum(),
            Some(Decimal::ONE)
        );
        assert_eq!(
            quote.gross_shares(),
            quote.requested_amount() / Decimal::new(5, 1)
        );
        assert!(quote.gross_shares() < Decimal::from(5));
        assert_eq!(quote.vwap_share_denominator(), quote.gross_shares());
        assert_eq!(
            quote.gross_notional() / quote.vwap_share_denominator(),
            quote.vwap()
        );
        assert_eq!(quote.request_count(), 3);
        assert_eq!(quote.book_hash(), "minimum-profile-book-hash");
        assert_eq!(
            quote.market_minimum_policy_version(),
            "polymarket-frontend-market-input-minimum/2026-10-11"
        );
        assert_eq!(
            quote.market_minimum_source_sha256(),
            "bf1323dcfbfdae3ae3c78c6bc9283ec8a57d8d8e26f0bcc3ed3001150e5ecc60"
        );
        let original_expiry = quote.valid_until();
        assert!(quote.check_validity().is_ok());
        let _ = (
            quote.market_minimum_check_amount(),
            quote.market_minimum_basis(),
            quote.market_minimum_status(),
            quote.required_market_buy_notional_minimum(),
            quote.market_minimum_policy_version(),
            quote.market_minimum_source_sha256(),
        );
        assert_eq!(quote.valid_until(), original_expiry);
    }
}

#[tokio::test]
async fn all_in_buy_checks_modeled_gross_and_sell_has_no_client_floor() {
    let ctx = context(gamma(true, json!(0.02), "5"), clob(json!(0.02), "5")).await;
    let one_cash =
        estimate_all_in_buy_execution_quote(&ctx, Decimal::ONE, Duration::from_secs(10)).unwrap();
    assert_eq!(
        one_cash.market_minimum_basis(),
        ExecutionQuoteMarketMinimumBasis::EstimatedBuyGrossNotional
    );
    assert_eq!(
        one_cash.market_minimum_check_amount(),
        one_cash.gross_notional()
    );
    assert_eq!(
        one_cash.gross_notional(),
        Decimal::from_str_exact("0.9975").unwrap()
    );
    assert_eq!(one_cash.total_buy_cash(), Some(Decimal::ONE));
    assert_eq!(
        one_cash.market_minimum_status(),
        ExecutionQuoteMarketMinimumStatus::BelowClientBuyMinimum
    );
    assert_eq!(
        one_cash.required_market_buy_notional_minimum(),
        Some(Decimal::ONE)
    );

    let five_cash =
        estimate_all_in_buy_execution_quote(&ctx, Decimal::from(5), Duration::from_secs(10))
            .unwrap();
    assert_eq!(
        five_cash.market_minimum_status(),
        ExecutionQuoteMarketMinimumStatus::MeetsClientBuyMinimum
    );
    assert!(five_cash.market_minimum_check_amount() >= Decimal::ONE);

    let sell = estimate_execution_quote(
        &ctx,
        ExecutionQuoteSide::Sell,
        Decimal::from_str_exact("0.1").unwrap(),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(
        sell.market_minimum_basis(),
        ExecutionQuoteMarketMinimumBasis::RequestedSellShares
    );
    assert_eq!(
        sell.market_minimum_check_amount(),
        Decimal::from_str_exact("0.1").unwrap()
    );
    assert_eq!(
        sell.market_minimum_status(),
        ExecutionQuoteMarketMinimumStatus::NoClientSellFloor
    );
    assert_eq!(sell.required_market_buy_notional_minimum(), None);
}

#[tokio::test]
async fn meeting_client_minimum_does_not_renew_an_expired_quote() {
    let ctx = context(gamma(false, json!(0), "5"), clob(json!(0), "5")).await;
    let quote = estimate_execution_quote(
        &ctx,
        ExecutionQuoteSide::Buy,
        Decimal::ONE,
        Duration::from_secs(10),
    )
    .unwrap();
    let deadline = quote.valid_until();
    let cloned = quote.clone();
    tokio::time::pause();
    tokio::time::advance(deadline.saturating_duration_since(tokio::time::Instant::now())).await;
    for snapshot in [quote, cloned] {
        assert_eq!(
            snapshot.market_minimum_status(),
            ExecutionQuoteMarketMinimumStatus::MeetsClientBuyMinimum
        );
        assert_eq!(snapshot.check_validity(), Err(ExecutionQuoteError::Expired));
        assert_eq!(snapshot.valid_until(), deadline);
    }
}
