use axum::{Router, body::Body, http::StatusCode, routing::get};
use polymarket_data::resolutions::{
    MAX_CONDITION_SELECTORS, ResolutionReadError, fetch_v2_resolution_rows,
};
use serde_json::json;
use tokio::net::TcpListener;

async fn serve(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, task)
}

#[tokio::test]
async fn fetches_raw_rows_with_one_condition_selector_and_accepts_null_miss() {
    let app = Router::new().route(
        "/v2/resolutions",
        get(
            |axum::extract::Query(query): axum::extract::Query<
                std::collections::HashMap<String, String>,
            >| async move {
                assert_eq!(query.get("condition").map(String::as_str), Some("a,b"));
                axum::Json(json!({"data":[{"condition_id":"a","extra":{"kept":true}}]}))
            },
        ),
    );
    let (base, server) = serve(app).await;
    let rows = fetch_v2_resolution_rows(
        &reqwest::Client::new(),
        &base,
        &["a".to_owned(), "b".to_owned()],
    )
    .await
    .unwrap();
    assert_eq!(
        rows,
        vec![json!({"condition_id":"a","extra":{"kept":true}})]
    );
    server.abort();

    let app = Router::new().route(
        "/v2/resolutions",
        get(|| async { axum::Json(json!({"data":null})) }),
    );
    let (base, server) = serve(app).await;
    assert!(
        fetch_v2_resolution_rows(&reqwest::Client::new(), &base, &["x".to_owned()])
            .await
            .unwrap()
            .is_empty()
    );
    server.abort();
}

#[tokio::test]
async fn invalid_selectors_are_rejected_before_http() {
    let client = reqwest::Client::new();
    for selectors in [
        Vec::new(),
        vec![" ".to_owned()],
        (0..=MAX_CONDITION_SELECTORS)
            .map(|index| index.to_string())
            .collect(),
    ] {
        assert_eq!(
            fetch_v2_resolution_rows(&client, "http://127.0.0.1:1", &selectors).await,
            Err(ResolutionReadError::InvalidSelector)
        );
    }
}

#[tokio::test]
async fn status_envelope_and_both_size_limits_are_checked() {
    let app = Router::new().route(
        "/v2/resolutions",
        get(|| async {
            (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", "9")],
                "secret",
            )
        }),
    );
    let (base, server) = serve(app).await;
    assert_eq!(
        fetch_v2_resolution_rows(&reqwest::Client::new(), &base, &["x".to_owned()]).await,
        Err(ResolutionReadError::RateLimitedWithDelay(9))
    );
    server.abort();

    let app = Router::new().route("/v2/resolutions", get(|| async { "not-json" }));
    let (base, server) = serve(app).await;
    assert_eq!(
        fetch_v2_resolution_rows(&reqwest::Client::new(), &base, &["x".to_owned()]).await,
        Err(ResolutionReadError::InvalidEnvelope)
    );
    server.abort();

    let app = Router::new().route(
        "/v2/resolutions",
        get(|| async {
            let oversized = vec![b' '; 8 * 1024 * 1024 + 1];
            let body = Body::from_stream(tokio_stream::iter([Ok::<_, std::io::Error>(oversized)]));
            axum::response::Response::builder()
                .status(StatusCode::OK)
                .body(body)
                .unwrap()
        }),
    );
    let (base, server) = serve(app).await;
    assert_eq!(
        fetch_v2_resolution_rows(&reqwest::Client::new(), &base, &["x".to_owned()]).await,
        Err(ResolutionReadError::ResponseTooLarge)
    );
    server.abort();
}
