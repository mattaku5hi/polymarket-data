use axum::{Router, extract::Query, http::StatusCode, routing::get};
use polymarket_data::clob::{BookError, fetch_book};
use serde_json::{Value, json};
use std::collections::HashMap;

fn book() -> Value {
    json!({"asset_id":"123", "hash":"book-hash", "timestamp":"1700000000123",
        "bids":[{"price":"0.4","size":"10"}],
        "asks":[{"price":"0.6","size":"20"}]})
}

async fn serve(reply: Value) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/book",
        get(move |Query(q): Query<HashMap<String, String>>| {
            let reply = reply.clone();
            async move {
                assert_eq!(q.get("token_id").map(String::as_str), Some("123"));
                axum::Json(reply)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, task)
}

#[tokio::test]
async fn book_preserves_decimal_text_order_and_identity() {
    let mut raw = book();
    raw["bids"]
        .as_array_mut()
        .unwrap()
        .push(json!({"price":"0.3", "size":"2.00"}));
    let (base, task) = serve(raw.clone()).await;
    let observed = fetch_book(&reqwest::Client::new(), &base, "123")
        .await
        .unwrap();
    assert_eq!(observed.asset_id, "123");
    assert_eq!(observed.hash, "book-hash");
    assert_eq!(observed.timestamp, "1700000000123");
    assert_eq!(observed.bids[1].size, "2.00");
    assert_eq!(observed.vendor_book(), &raw);
    task.abort();
}

#[tokio::test]
async fn rejects_wrong_token_and_malformed_levels_without_partial_book() {
    for raw in [
        {
            let mut b = book();
            b["asset_id"] = json!("456");
            b
        },
        {
            let mut b = book();
            b["bids"][0]["size"] = json!("not-a-number");
            b
        },
        {
            let mut b = book();
            b["asks"][0]["price"] = json!("1.1");
            b
        },
        {
            let mut b = book();
            b["asks"][0]["size"] = json!("0");
            b
        },
        {
            let mut b = book();
            b["timestamp"] = json!("unknown");
            b
        },
        {
            let mut b = book();
            b["bids"][0]["price"] = json!("0.123456789012345678901234567891");
            b
        },
    ] {
        let (base, task) = serve(raw).await;
        assert_eq!(
            fetch_book(&reqwest::Client::new(), &base, "123")
                .await
                .unwrap_err(),
            BookError::MalformedBook
        );
        task.abort();
    }
}

#[tokio::test]
async fn empty_book_is_an_observation_not_a_price_or_fill() {
    let mut raw = book();
    raw["bids"] = json!([]);
    raw["asks"] = json!([]);
    let (base, task) = serve(raw).await;
    let b = fetch_book(&reqwest::Client::new(), &base, "123")
        .await
        .unwrap();
    assert!(b.bids.is_empty() && b.asks.is_empty());
    task.abort();
}

#[tokio::test]
async fn rate_limit_and_oversize_are_explicit_and_redacted() {
    let app = Router::new().route(
        "/book",
        get(|| async {
            (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", "9")],
                "private body",
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    assert_eq!(
        fetch_book(&reqwest::Client::new(), &base, "123")
            .await
            .unwrap_err(),
        BookError::RateLimited {
            retry_after_seconds: Some(9)
        }
    );
    task.abort();
    let mut raw = book();
    raw["padding"] = json!("x".repeat(2 * 1024 * 1024));
    let (base, task) = serve(raw).await;
    assert_eq!(
        fetch_book(&reqwest::Client::new(), &base, "123")
            .await
            .unwrap_err(),
        BookError::ResponseTooLarge
    );
    task.abort();
}

#[tokio::test]
async fn chunked_body_cannot_bypass_the_limit() {
    let app = Router::new().route(
        "/book",
        get(|| async {
            let stream = tokio_stream::iter(
                (0..3).map(|_| Ok::<_, std::io::Error>("x".repeat(1024 * 1024))),
            );
            axum::body::Body::from_stream(stream)
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    assert_eq!(
        fetch_book(&reqwest::Client::new(), &base, "123")
            .await
            .unwrap_err(),
        BookError::ResponseTooLarge
    );
    task.abort();
}

#[tokio::test]
async fn rejects_remote_plaintext_before_request() {
    assert_eq!(
        fetch_book(&reqwest::Client::new(), "http://example.com/secret", "123")
            .await
            .unwrap_err(),
        BookError::InvalidEndpoint
    );
}
