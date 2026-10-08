#![cfg(feature = "gamma")]

use std::time::Duration;

use axum::{
    Router,
    body::Body,
    http::{StatusCode, Uri},
    routing::get,
};
use polymarket_data::{
    gamma_index::{GammaIndexError, GammaNegRiskGroupLookup, GammaOutcomeTokenIndex},
    gamma_market_metadata::{GammaMarketMetadataLookup, GammaTokenMarketLookup},
};
use rust_decimal::Decimal;
use serde_json::json;
use tokio::net::TcpListener;

async fn serve(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, task)
}

fn market() -> serde_json::Value {
    json!({
        "conditionId":"condition-a",
        "outcomes":"[\"No\",\"Yes\"]",
        "clobTokenIds":"[\"token-0\",\"token-1\"]",
        "negRisk":true,
        "negRiskMarketID":"group-a",
        "slug":"market-a",
        "events":[{"slug":"event-a"}],
        "volumeNum":"1250.5",
        "liquidityNum":250,
        "endDate":"2030-01-02T03:04:05Z",
        "category":"crypto"
    })
}

#[tokio::test]
async fn outcome_index_hydrates_repeatable_selectors_and_maps_by_position() {
    let app = Router::new().route(
        "/markets",
        get(|uri: Uri| async move {
            let query = uri.query().unwrap_or_default();
            assert!(query.contains("condition_ids=condition-a&condition_ids=condition-b"));
            assert!(query.contains("closed=true"));
            axum::Json(vec![market()])
        }),
    );
    let (base, server) = serve(app).await;
    let index = GammaOutcomeTokenIndex::with_base_url(base);
    index
        .hydrate(&["condition-a".to_owned(), "condition-b".to_owned()])
        .await
        .unwrap();
    assert_eq!(
        index.token_id_for_outcome("condition-a", 0).as_deref(),
        Some("token-0")
    );
    assert_eq!(
        index.token_id_for_outcome("condition-a", 1).as_deref(),
        Some("token-1")
    );
    assert_eq!(index.token_id_for_outcome("condition-b", 0), None);
    assert_eq!(index.token_id_for_outcome("condition-a", 2), None);
    assert_eq!(index.cache_len(), 2);
    server.abort();
}

#[tokio::test]
async fn neg_risk_lookup_returns_only_the_exact_positive_group() {
    let app = Router::new().route(
        "/markets",
        get(|uri: Uri| async move {
            let query = uri.query().unwrap_or_default();
            if query.contains("condition_ids=condition-a") {
                axum::Json(vec![market()])
            } else {
                axum::Json(vec![json!({"conditionId":"condition-b","negRisk":false})])
            }
        }),
    );
    let (base, server) = serve(app).await;
    let lookup = GammaNegRiskGroupLookup::with_base_url(base);
    assert_eq!(
        lookup.lookup("condition-a").await.unwrap().as_deref(),
        Some("group-a")
    );
    assert_eq!(lookup.lookup("condition-b").await.unwrap(), None);
    server.abort();
}

#[tokio::test]
async fn token_market_and_market_metadata_lookups_map_gamma_fields() {
    let app = Router::new().route(
        "/markets",
        get(|uri: Uri| async move {
            let query = uri.query().unwrap_or_default();
            if query.contains("clob_token_ids=token-1") {
                let mut row = market();
                row["events"] = json!([{"slug":"event-a"}]);
                axum::Json(vec![row])
            } else {
                axum::Json(vec![market()])
            }
        }),
    );
    let (base, server) = serve(app).await;
    let client = reqwest::Client::new();
    let token =
        GammaTokenMarketLookup::with_client(client.clone(), base.clone(), Duration::from_secs(60));
    let token_market = token.market_for_token("token-1").await.unwrap();
    assert_eq!(token_market.condition_id, "condition-a");
    assert_eq!(token_market.slug, "market-a");
    assert_eq!(token_market.event_slug, "event-a");
    assert_eq!(token_market.outcome, "Yes");

    let metadata = GammaMarketMetadataLookup::with_client(client, base, Duration::from_secs(60));
    let row = metadata.market_metadata("condition-a").await.unwrap();
    assert_eq!(row.volume_usd, Decimal::new(12505, 1));
    assert_eq!(row.liquidity_usd, Decimal::new(250, 0));
    assert_eq!(row.end_date.to_rfc3339(), "2030-01-02T03:04:05+00:00");
    assert_eq!(row.category.as_deref(), Some("crypto"));
    server.abort();
}

#[tokio::test]
async fn gamma_index_and_neg_risk_readers_enforce_declared_and_chunked_limits() {
    let app = Router::new().route(
        "/markets",
        get(|| async {
            let body = vec![b' '; 2 * 1024 * 1024 + 1];
            axum::response::Response::builder()
                .status(StatusCode::OK)
                .header("content-length", body.len().to_string())
                .body(Body::from(body))
                .unwrap()
        }),
    );
    let (base, server) = serve(app).await;
    let index = GammaOutcomeTokenIndex::with_base_url(base);
    assert_eq!(
        index.hydrate(&["condition-a".to_owned()]).await,
        Err(GammaIndexError::ResponseTooLarge)
    );
    server.abort();

    let app = Router::new().route(
        "/markets",
        get(|| async {
            let parts = [vec![b' '; 1024 * 1024], vec![b' '; 1024 * 1024 + 1]]
                .into_iter()
                .map(Ok::<_, std::io::Error>);
            let body = Body::from_stream(tokio_stream::iter(parts));
            axum::response::Response::builder()
                .status(StatusCode::OK)
                .body(body)
                .unwrap()
        }),
    );
    let (base, server) = serve(app).await;
    let lookup = GammaNegRiskGroupLookup::with_base_url(base);
    assert_eq!(
        lookup.lookup("condition-a").await,
        Err(GammaIndexError::ResponseTooLarge)
    );
    server.abort();
}

#[tokio::test]
async fn gamma_reader_errors_do_not_disclose_request_or_response_contents() {
    let app = Router::new().route(
        "/markets",
        get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "private-response-marker") }),
    );
    let (base, server) = serve(app).await;
    let index = GammaOutcomeTokenIndex::with_base_url(base.clone());
    let error = index
        .hydrate(&["private-condition-marker".to_owned()])
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("http 500"));
    assert!(!error.contains("private-response-marker"));
    assert!(!error.contains("private-condition-marker"));

    let metadata = GammaMarketMetadataLookup::with_client(
        reqwest::Client::new(),
        base,
        Duration::from_secs(0),
    );
    let error = metadata
        .market_metadata("private-condition-marker")
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("500"));
    assert!(!error.contains("private-response-marker"));
    assert!(!error.contains("private-condition-marker"));
    server.abort();

    let index =
        GammaOutcomeTokenIndex::with_base_url("http://private-user:private-password@127.0.0.1:1");
    let error = index
        .hydrate(&["private-condition-marker".to_owned()])
        .await
        .unwrap_err()
        .to_string();
    assert!(!error.contains("private-user"));
    assert!(!error.contains("private-password"));
    assert!(!error.contains("private-condition-marker"));
}
