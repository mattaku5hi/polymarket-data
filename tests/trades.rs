use axum::{Router, body::Body, http::StatusCode, routing::get};
use polymarket_data::{
    PageError, TradeRowError, TradeSide, fetch_v2_global_trades_page,
    fetch_v2_global_trades_page_with_min_size, fetch_v2_trades_page, parse_v2_trade,
};
use serde_json::{Value, json};
use tokio::net::TcpListener;

const WALLET: &str = "0x1111111111111111111111111111111111111111";
const TX: &str = "0xdeadbeef00000000000000000000000000000000000000000000000000000001";
const TOKEN: &str = "71321045679252212594626385532706912750332728571942532289631379312455583992563";

fn row() -> Value {
    json!({
        "proxy_wallet": WALLET,
        "side": "BUY",
        "token_id": TOKEN,
        "condition_id": "0xabcdef0000000000000000000000000000000000000000000000000000000001",
        "size": 125.5,
        "price": 0.75,
        "timestamp": 1731489409,
        "title": "Will it rain?",
        "outcome": "Yes",
        "transaction_hash": TX
    })
}

async fn serve(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, task)
}

#[test]
fn parser_matches_polydoghound_public_observation_fixture_without_project_identity() {
    let vendor = row();
    let parsed = parse_v2_trade(&vendor).unwrap();
    assert_eq!(parsed.proxy_wallet, WALLET);
    assert_eq!(parsed.token_id, TOKEN);
    assert_eq!(parsed.transaction_hash, TX);
    assert_eq!(parsed.side, TradeSide::Buy);
    assert_eq!(parsed.price, "0.75");
    assert_eq!(parsed.size, "125.5");
    assert_eq!(parsed.observed_at.to_rfc3339(), "2024-11-13T09:16:49+00:00");
    assert_eq!(parsed.vendor_row(), &vendor);
    let mut milliseconds = row();
    milliseconds["timestamp"] = json!(1_782_752_879_000_i64);
    assert_eq!(
        parse_v2_trade(&milliseconds)
            .unwrap()
            .observed_at
            .to_rfc3339(),
        "2026-06-29T17:07:59+00:00"
    );
    let mut bad = row();
    bad["side"] = json!("HOLD");
    assert!(matches!(
        parse_v2_trade(&bad),
        Err(TradeRowError::UnknownSide { .. })
    ));
}

#[tokio::test]
async fn bounded_read_keeps_cursor_and_exact_evidence_without_project_conversion() {
    let vendor = row();
    let reply = json!({"data":[vendor.clone()],"pagination":{"next_cursor":"opaque-next"}});
    let app = Router::new().route("/v2/trades", get(move || async move { axum::Json(reply) }));
    let (base, server) = serve(app).await;
    let page = fetch_v2_trades_page(&reqwest::Client::new(), &base, WALLET, 7, None)
        .await
        .unwrap();
    assert_eq!(page.observations[0].vendor_row(), &vendor);
    assert_eq!(page.next_cursor.as_deref(), Some("opaque-next"));
    server.abort();
}

#[tokio::test]
async fn global_feed_omits_user_and_bounds_and_preserves_mixed_rows_and_multiplicity() {
    let mut unenriched = row();
    unenriched["condition_id"] = json!("");
    unenriched["outcome"] = json!("");
    let rows = vec![row(), row(), unenriched];
    let expected = rows.clone();
    let app = Router::new().route(
        "/v2/trades",
        get(
            move |axum::extract::Query(query): axum::extract::Query<
                std::collections::HashMap<String, String>,
            >| {
                let rows = rows.clone();
                async move {
                    assert_eq!(query.get("taker_only").map(String::as_str), Some("false"));
                    assert!(!query.contains_key("user"));
                    assert!(!query.contains_key("start"));
                    assert!(!query.contains_key("end"));
                    if query.contains_key("cursor") {
                        assert_eq!(query["cursor"], "opaque+/=cursor");
                        assert!(!query.contains_key("limit"));
                    } else {
                        assert_eq!(query["limit"], "3");
                    }
                    axum::Json(json!({"data":rows,"pagination":{"next_cursor":"opaque+/=cursor"}}))
                }
            },
        ),
    );
    let (base, server) = serve(app).await;
    let client = reqwest::Client::new();
    let first = fetch_v2_global_trades_page(&client, &base, 3, None)
        .await
        .unwrap();
    assert_eq!(first.rows, expected);
    let next = fetch_v2_global_trades_page(&client, &base, 3, first.next_cursor.as_deref())
        .await
        .unwrap();
    assert_eq!(next.rows, expected);
    server.abort();
}

#[tokio::test]
async fn wallet_query_remains_explicit_and_global_transport_errors_are_typed() {
    let app = Router::new().route(
        "/v2/trades",
        get(
            |axum::extract::Query(query): axum::extract::Query<
                std::collections::HashMap<String, String>,
            >| async move {
                assert_eq!(query["user"], WALLET);
                assert_eq!(query["taker_only"], "false");
                assert_eq!(query["cursor"], "saved-cursor");
                assert!(!query.contains_key("limit"));
                axum::Json(json!({"data":[row()],"pagination":{"next_cursor":null}}))
            },
        ),
    );
    let (base, server) = serve(app).await;
    fetch_v2_trades_page(
        &reqwest::Client::new(),
        &base,
        WALLET,
        3,
        Some("saved-cursor"),
    )
    .await
    .unwrap();
    server.abort();
    let app = Router::new().route(
        "/v2/trades",
        get(|| async {
            (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", "7")],
                "private vendor body",
            )
        }),
    );
    let (base, server) = serve(app).await;
    assert_eq!(
        fetch_v2_global_trades_page(&reqwest::Client::new(), &base, 3, None)
            .await
            .unwrap_err(),
        PageError::RateLimitedWithDelay(7)
    );
    assert_eq!(
        fetch_v2_global_trades_page(&reqwest::Client::new(), &base, 0, None)
            .await
            .unwrap_err(),
        PageError::InvalidLimit(0)
    );
    server.abort();
}

#[tokio::test]
async fn global_feed_rejects_malformed_data_or_pagination_instead_of_false_exhaustion() {
    for reply in [
        json!({"pagination":{"next_cursor":null}}),
        json!({"data":null,"pagination":{"next_cursor":null}}),
        json!({"data":[],"pagination":null}),
        json!({"data":[],"pagination":{}}),
        json!({"data":[],"pagination":{"next_cursor":" "}}),
        json!({"data":[],"pagination":{"next_cursor":42}}),
        json!({"data":[],"pagination":{"next_cursor":null,"has_more":true}}),
        json!({"data":[],"pagination":{"next_cursor":"next","has_more":false}}),
    ] {
        let app = Router::new().route("/v2/trades", get(move || async move { axum::Json(reply) }));
        let (base, server) = serve(app).await;
        assert_eq!(
            fetch_v2_global_trades_page(&reqwest::Client::new(), &base, 3, None)
                .await
                .unwrap_err(),
            PageError::InvalidEnvelope
        );
        server.abort();
    }
}

#[tokio::test]
async fn explicit_nonzero_token_filter_includes_micro_fills_and_survives_cursor_paging() {
    let app = Router::new().route(
        "/v2/trades",
        get(
            |axum::extract::Query(query): axum::extract::Query<
                std::collections::HashMap<String, String>,
            >| async move {
                assert!(!query.contains_key("user"));
                assert_eq!(query["taker_only"], "false");
                assert_eq!(query["filter_type"], "TOKENS");
                assert_eq!(query["filter_amount"], "0.000001");
                if query.contains_key("cursor") {
                    assert!(!query.contains_key("limit"));
                }
                let mut tiny = row();
                tiny["size"] = json!("0.000001");
                axum::Json(json!({"data":[tiny],"pagination":{"next_cursor":"next"}}))
            },
        ),
    );
    let (base, server) = serve(app).await;
    let client = reqwest::Client::new();
    let first = fetch_v2_global_trades_page_with_min_size(&client, &base, "0.000001", 1000, None)
        .await
        .unwrap();
    assert_eq!(first.rows[0]["size"], "0.000001");
    fetch_v2_global_trades_page_with_min_size(
        &client,
        &base,
        "0.000001",
        1000,
        first.next_cursor.as_deref(),
    )
    .await
    .unwrap();
    for invalid in [
        "0",
        "-1",
        "NaN",
        "private-invalid-value",
        "0.00000000000000000000000000001",
    ] {
        let error = fetch_v2_global_trades_page_with_min_size(&client, &base, invalid, 1000, None)
            .await
            .unwrap_err();
        assert_eq!(error, PageError::InvalidMinimumSize);
        assert!(!error.to_string().contains(invalid));
    }
    server.abort();
}

#[tokio::test]
async fn global_feed_surfaces_cache_age_without_inventing_freshness() {
    for (age, expected) in [("103", Some(103)), ("not-an-age", None)] {
        let app = Router::new().route(
            "/v2/trades",
            get(move || async move {
                (
                    [("age", age)],
                    axum::Json(json!({"data":[],"pagination":{"next_cursor":null}})),
                )
            }),
        );
        let (base, server) = serve(app).await;
        let page = fetch_v2_global_trades_page(&reqwest::Client::new(), &base, 3, None)
            .await
            .unwrap();
        assert_eq!(page.cache_age_seconds, expected);
        server.abort();
    }
}

#[tokio::test]
async fn global_feed_accepts_explicit_terminal_empty_page() {
    let app = Router::new().route(
        "/v2/trades",
        get(|| async {
            axum::Json(json!({"data":[],"pagination":{"next_cursor":null,"has_more":false}}))
        }),
    );
    let (base, server) = serve(app).await;
    let page = fetch_v2_global_trades_page(&reqwest::Client::new(), &base, 3, None)
        .await
        .unwrap();
    assert!(page.rows.is_empty());
    assert!(page.next_cursor.is_none());
    assert!(page.cache_age_seconds.is_none());
    server.abort();
}

#[tokio::test]
async fn malformed_page_is_atomic_and_transport_errors_hide_endpoint_credentials() {
    let mut broken = row();
    broken.as_object_mut().unwrap().remove("token_id");
    let reply = json!({"data":[row(),broken],"pagination":{"next_cursor":null}});
    let app = Router::new().route("/v2/trades", get(move || async move { axum::Json(reply) }));
    let (base, server) = serve(app).await;
    assert!(matches!(
        fetch_v2_trades_page(&reqwest::Client::new(), &base, WALLET, 1, None).await,
        Err(PageError::InvalidTrade(TradeRowError::InvalidField {
            field: "token_id"
        }))
    ));
    server.abort();
    let error = fetch_v2_trades_page(
        &reqwest::Client::new(),
        "http://user:secret@127.0.0.1:1",
        WALLET,
        1,
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(error, PageError::RequestFailed);
    assert!(!error.to_string().contains("secret"));
}

#[tokio::test]
async fn rejects_http_non_loopback_and_oversized_declared_or_streaming_body() {
    assert_eq!(
        fetch_v2_trades_page(
            &reqwest::Client::new(),
            "http://example.com",
            WALLET,
            1,
            None
        )
        .await
        .unwrap_err(),
        PageError::InvalidEndpoint
    );
    for chunked in [false, true] {
        let app = Router::new().route(
            "/v2/trades",
            get(move || async move {
                let oversized = vec![b'x'; 8 * 1024 * 1024 + 1];
                if chunked {
                    let mid = 4 * 1024 * 1024;
                    let chunks = vec![
                        Ok::<_, std::io::Error>(oversized[..mid].to_vec()),
                        Ok(oversized[mid..].to_vec()),
                    ];
                    Body::from_stream(tokio_stream::iter(chunks))
                } else {
                    Body::from(oversized)
                }
            }),
        );
        let (base, server) = serve(app).await;
        assert_eq!(
            fetch_v2_trades_page(&reqwest::Client::new(), &base, WALLET, 1, None)
                .await
                .unwrap_err(),
            PageError::ResponseTooLarge
        );
        server.abort();
    }
}

#[tokio::test]
async fn http_error_and_invalid_local_limit_are_typed() {
    let app = Router::new().route(
        "/v2/trades",
        get(|| async { (StatusCode::BAD_REQUEST, "bad") }),
    );
    let (base, server) = serve(app).await;
    let client = reqwest::Client::new();
    assert_eq!(
        fetch_v2_trades_page(&client, &base, WALLET, 0, None)
            .await
            .unwrap_err(),
        PageError::InvalidLimit(0)
    );
    assert_eq!(
        fetch_v2_trades_page(&client, &base, WALLET, 1, None)
            .await
            .unwrap_err(),
        PageError::HttpStatus(400)
    );
    server.abort();
}
