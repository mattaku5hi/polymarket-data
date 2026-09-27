use axum::{Router, body::Body, http::StatusCode, routing::get};
use polymarket_data::{PageError, TradeRowError, TradeSide, fetch_v2_trades_page, parse_v2_trade};
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
