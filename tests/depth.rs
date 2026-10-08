use axum::{Json, Router, routing::get};
use polymarket_data::clob::{
    BookError,
    depth::{DepthQuoteError, best_bid, quote_buy, quote_sell},
    fetch_book,
};
use rust_decimal::Decimal;
use serde_json::{Value, json};

fn book() -> Value {
    json!({
        "asset_id":"123",
        "hash":"book-hash",
        "timestamp":"1700000000123",
        "bids":[
            {"price":"0.40","size":"1"},
            {"price":"0.60","size":"2"},
            {"price":"0.50","size":"10"}
        ],
        "asks":[
            {"price":"0.70","size":"10"},
            {"price":"0.50","size":"10"}
        ]
    })
}

async fn serve(reply: Value) -> (reqwest::Client, String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/book",
        get(move || {
            let reply = reply.clone();
            async move { Json(reply) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (reqwest::Client::new(), base_url, server)
}

#[tokio::test]
async fn best_bid_and_buy_walk_validated_levels_with_book_provenance() {
    let (client, base_url, server) = serve(book()).await;
    let book = fetch_book(&client, &base_url, "123").await.unwrap();

    assert_eq!(best_bid(&book), Ok(Decimal::new(60, 2)));

    let buy = quote_buy(&book, Decimal::new(5, 0)).unwrap();
    assert_eq!(buy.requested_notional, Decimal::new(5, 0));
    assert_eq!(buy.filled_notional, Decimal::new(5, 0));
    assert_eq!(buy.filled_quantity, Decimal::new(10, 0));
    assert_eq!(buy.vwap_price, Decimal::new(50, 2));
    assert_eq!(buy.asset_id, "123");
    assert_eq!(buy.book_hash, "book-hash");
    assert_eq!(buy.book_timestamp, "1700000000123");

    let deeper_buy = quote_buy(&book, Decimal::new(10, 0)).unwrap();
    assert_eq!(deeper_buy.filled_notional, Decimal::new(10, 0));
    assert_eq!(deeper_buy.vwap_price.round_dp(6), Decimal::new(583333, 6));
    server.abort();
}

#[tokio::test]
async fn buy_returns_actual_partial_depth() {
    let mut raw = book();
    raw["asks"] = json!([{"price":"0.5", "size":"2"}]);
    let (client, base_url, server) = serve(raw).await;
    let book = fetch_book(&client, &base_url, "123").await.unwrap();

    let quote = quote_buy(&book, Decimal::new(5, 0)).unwrap();
    assert_eq!(quote.requested_notional, Decimal::new(5, 0));
    assert_eq!(quote.filled_notional, Decimal::ONE);
    assert_eq!(quote.filled_quantity, Decimal::new(2, 0));
    assert_eq!(quote.vwap_price, Decimal::new(50, 2));
    server.abort();
}

#[tokio::test]
async fn sell_walks_bids_and_returns_partial_depth() {
    let (client, base_url, server) = serve(book()).await;
    let book = fetch_book(&client, &base_url, "123").await.unwrap();

    let quote = quote_sell(&book, Decimal::new(5, 0)).unwrap();
    assert_eq!(quote.requested_quantity, Decimal::new(5, 0));
    assert_eq!(quote.filled_quantity, Decimal::new(5, 0));
    assert_eq!(quote.gross_proceeds, Decimal::new(27, 1));
    assert_eq!(quote.vwap_price, Decimal::new(54, 2));
    assert_eq!(quote.asset_id, "123");
    assert_eq!(quote.book_hash, "book-hash");
    assert_eq!(quote.book_timestamp, "1700000000123");

    let partial = quote_sell(&book, Decimal::new(20, 0)).unwrap();
    assert_eq!(partial.requested_quantity, Decimal::new(20, 0));
    assert_eq!(partial.filled_quantity, Decimal::new(13, 0));
    assert_eq!(partial.gross_proceeds, Decimal::new(66, 1));
    server.abort();
}

#[tokio::test]
async fn empty_and_invalid_requests_fail_closed() {
    let mut raw = book();
    raw["bids"] = json!([]);
    raw["asks"] = json!([]);
    let (client, base_url, server) = serve(raw).await;
    let book = fetch_book(&client, &base_url, "123").await.unwrap();
    assert_eq!(best_bid(&book), Err(DepthQuoteError::EmptyDepth));
    assert_eq!(
        quote_buy(&book, Decimal::ONE),
        Err(DepthQuoteError::EmptyDepth)
    );
    assert_eq!(
        quote_sell(&book, Decimal::ONE),
        Err(DepthQuoteError::EmptyDepth)
    );
    assert_eq!(
        quote_buy(&book, Decimal::ZERO),
        Err(DepthQuoteError::InvalidRequest)
    );
    assert_eq!(
        quote_sell(&book, Decimal::ZERO),
        Err(DepthQuoteError::InvalidRequest)
    );
    server.abort();
}

#[tokio::test]
async fn fetch_rejects_identity_and_provenance_before_quotes() {
    for raw in [
        {
            let mut raw = book();
            raw["asset_id"] = json!("wrong-token");
            raw
        },
        {
            let mut raw = book();
            raw["timestamp"] = json!("170000000000000000000");
            raw
        },
    ] {
        let (client, base_url, server) = serve(raw).await;
        assert_eq!(
            fetch_book(&client, &base_url, "123").await.unwrap_err(),
            BookError::MalformedBook
        );
        server.abort();
    }
}

#[tokio::test]
async fn decimal_overflow_does_not_return_a_partial_arithmetic_result() {
    let mut raw = book();
    let expensive_quantity = Decimal::MAX.to_string();
    raw["asks"] = json!([
        {"price":"0.0000000000000000000000000001", "size":expensive_quantity},
        {"price":"0.0000000000000000000000000001", "size":Decimal::MAX.to_string()}
    ]);
    let (client, base_url, server) = serve(raw).await;
    let book = fetch_book(&client, &base_url, "123").await.unwrap();
    assert_eq!(
        quote_buy(&book, Decimal::MAX),
        Err(DepthQuoteError::Arithmetic)
    );
    server.abort();
}
