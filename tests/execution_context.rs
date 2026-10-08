use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Path, Query},
    http::{Response, StatusCode, header},
    routing::get,
};
use polymarket_data::clob::execution_context::{
    ClobExecutionContextReader, ExecutionContextError, ExecutionContextRequest,
    ExecutionContextStage, ObservedMarketVersion,
};
use serde_json::{Value, json};
use tokio::sync::{Notify, mpsc, watch};

const CONDITION: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const YES_V1: &str = "123";

async fn wall_timeout(duration: Duration) {
    let deadline = std::time::Instant::now() + duration;
    while std::time::Instant::now() < deadline {
        tokio::task::yield_now().await;
    }
}

fn gamma(version: &str, selected_ids: bool) -> Value {
    let mut row = json!({
        "id":"market-id",
        "conditionId":CONDITION,
        "version":version,
        "outcomes":"[\"Yes\",\"No\"]",
        "clobTokenIds":["123","456"],
        "positionIds":"[\"789\",\"890\"]",
        "active":true,
        "closed":false,
        "acceptingOrders":true,
        "enableOrderBook":true,
        "orderMinSize":"5",
        "orderPriceMinTickSize":"0.01",
        "feesEnabled":null,
        "feeSchedule":{"rate":0.125,"exponent":2,"takerOnly":true,"rebateRate":null},
    });
    if !selected_ids {
        row["positionIds"] = json!(["123", "456"]);
    }
    json!([row])
}

fn clob_market() -> Value {
    json!({
        "t":[{"t":"456","o":"No"},{"t":"123","o":"Yes"}],
        "mos":"5.00",
        "mts":"0.0100",
        "mbf":0,
        "tbf":100,
        "fd":{"r":0.0200,"e":2,"to":true}
    })
}

fn book(asset_id: &str, timestamp: &str) -> Value {
    json!({
        "market":CONDITION,
        "asset_id":asset_id,
        "hash":"book-hash",
        "timestamp":timestamp,
        "min_order_size":"5.0",
        "tick_size":"0.010",
        "bids":[{"price":"0.4","size":"10"}],
        "asks":[{"price":"0.6","size":"20"}]
    })
}

async fn serve(
    gamma_body: Value,
    clob_body: Value,
    book_body: Value,
) -> (String, tokio::task::JoinHandle<()>, Arc<AtomicUsize>) {
    let sends = Arc::new(AtomicUsize::new(0));
    let expected_asset = book_body["asset_id"].as_str().unwrap().to_owned();
    let gamma_sends = sends.clone();
    let clob_sends = sends.clone();
    let book_sends = sends.clone();
    let app = Router::new()
        .route(
            "/markets",
            get(
                move |Query(query): Query<std::collections::HashMap<String, String>>| {
                    let body = gamma_body.clone();
                    let sends = gamma_sends.clone();
                    async move {
                        sends.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(
                            query.get("condition_ids").map(String::as_str),
                            Some(CONDITION)
                        );
                        axum::Json(body)
                    }
                },
            ),
        )
        .route(
            "/clob-markets/{condition}",
            get(move |Path(condition): Path<String>| {
                let body = clob_body.clone();
                let sends = clob_sends.clone();
                async move {
                    sends.fetch_add(1, Ordering::Relaxed);
                    assert_eq!(condition, CONDITION);
                    axum::Json(body)
                }
            }),
        )
        .route(
            "/book",
            get(
                move |Query(query): Query<std::collections::HashMap<String, String>>| {
                    let body = book_body.clone();
                    let sends = book_sends.clone();
                    let expected_asset = expected_asset.clone();
                    async move {
                        sends.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(query.get("token_id"), Some(&expected_asset));
                        axum::Json(body)
                    }
                },
            ),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, task, sends)
}

fn request(asset_id: &str, max_requests: usize, timeout: Duration) -> ExecutionContextRequest {
    ExecutionContextRequest {
        api_condition_id: CONDITION.to_owned(),
        selected_asset_id: asset_id.to_owned(),
        max_requests,
        total_timeout: timeout,
    }
}

fn reader(base: &str) -> ClobExecutionContextReader {
    ClobExecutionContextReader::with_client_builder(reqwest::Client::builder(), base, base).unwrap()
}

#[tokio::test]
async fn reads_v1_context_and_preserves_raw_numeric_fee_lexemes() {
    let (base, task, sends) =
        serve(gamma("v1", true), clob_market(), book(YES_V1, "1700000000")).await;
    let observed = reader(&base)
        .read_context(&request(YES_V1, 3, Duration::from_secs(2)))
        .await
        .unwrap();
    assert_eq!(observed.protocol_version(), ObservedMarketVersion::V1);
    assert_eq!(observed.selected_outcome_index(), 0);
    assert_eq!(observed.outcomes()[1].label(), "No");
    assert_eq!(observed.min_order_size(), "5.00");
    assert_eq!(observed.min_tick_size(), "0.0100");
    assert_eq!(observed.book_min_order_size(), Some("5.0"));
    assert_eq!(observed.fee_curve_rate_lexeme(), Some("0.02"));
    assert_eq!(observed.fee_curve_exponent_lexeme(), Some("2"));
    assert_eq!(observed.fee_curve_taker_only(), Some(true));
    assert_eq!(observed.book().timestamp, "1700000000");
    assert_eq!(
        observed.book_raw_body(),
        serde_json::to_string(&book(YES_V1, "1700000000"))
            .unwrap()
            .as_str()
    );
    assert_eq!(observed.request_count(), 3);
    assert_eq!(sends.load(Ordering::Relaxed), 3);
    assert!(observed.completed_at() >= observed.started_at());
    task.abort();
}

#[tokio::test]
async fn explicit_v2_version_selects_position_ids_when_both_arrays_exist() {
    let mut clob = clob_market();
    clob["t"] = json!([{"t":"890","o":"No"},{"t":"789","o":"Yes"}]);
    let (base, task, _) = serve(gamma("v2", true), clob, book("789", "1700000000123")).await;
    let observed = reader(&base)
        .read_context(&request("789", 3, Duration::from_secs(2)))
        .await
        .unwrap();
    assert_eq!(observed.protocol_version(), ObservedMarketVersion::V2);
    assert_eq!(observed.selected_asset_id(), "789");
    assert_eq!(observed.selected_outcome_index(), 0);
    task.abort();
}

#[tokio::test]
async fn two_request_budget_refuses_before_any_send() {
    let (base, task, sends) =
        serve(gamma("v1", true), clob_market(), book(YES_V1, "1700000000")).await;
    let error = reader(&base)
        .read_context(&request(YES_V1, 2, Duration::from_secs(2)))
        .await
        .unwrap_err();
    assert_eq!(error, ExecutionContextError::RequestBudgetExceeded);
    assert_eq!(sends.load(Ordering::Relaxed), 0);
    task.abort();
}

#[tokio::test]
async fn zero_budget_and_malformed_selectors_are_invalid_before_io() {
    let (base, task, sends) =
        serve(gamma("v1", true), clob_market(), book(YES_V1, "1700000000")).await;
    assert_eq!(
        reader(&base)
            .read_context(&request(YES_V1, 0, Duration::from_secs(2)))
            .await
            .unwrap_err(),
        ExecutionContextError::InvalidInput
    );
    let mut malformed = request(YES_V1, 3, Duration::from_secs(2));
    malformed.api_condition_id.push('/');
    assert_eq!(
        reader(&base).read_context(&malformed).await.unwrap_err(),
        ExecutionContextError::InvalidInput
    );
    assert_eq!(sends.load(Ordering::Relaxed), 0);
    task.abort();
}

#[tokio::test]
async fn refuses_unknown_state_and_identity_or_constraint_disagreement() {
    let mut bad_gamma = gamma("v1", true);
    bad_gamma[0]["closed"] = Value::Null;
    let (base, task, _) = serve(bad_gamma, clob_market(), book(YES_V1, "1700000000")).await;
    assert_eq!(
        reader(&base)
            .read_context(&request(YES_V1, 3, Duration::from_secs(2)))
            .await
            .unwrap_err(),
        ExecutionContextError::MarketUnavailable
    );
    task.abort();

    let mut bad_clob = clob_market();
    bad_clob["t"][1]["o"] = json!("No");
    let (base, task, _) = serve(gamma("v1", true), bad_clob, book(YES_V1, "1700000000")).await;
    assert_eq!(
        reader(&base)
            .read_context(&request(YES_V1, 3, Duration::from_secs(2)))
            .await
            .unwrap_err(),
        ExecutionContextError::IdentityMismatch(ExecutionContextStage::ClobMarket)
    );
    task.abort();

    let (base, task, _) = serve(gamma("v1", true), clob_market(), book(YES_V1, "1700000000")).await;
    let mut mismatched = request("999", 3, Duration::from_secs(2));
    mismatched.selected_asset_id = "999".to_owned();
    assert!(matches!(
        reader(&base).read_context(&mismatched).await,
        Err(ExecutionContextError::IdentityMismatch(
            ExecutionContextStage::GammaMarket
        ))
    ));
    task.abort();
}

#[tokio::test]
async fn optional_clob_condition_identifiers_are_checked_when_present() {
    let mut contradictory = clob_market();
    contradictory["c"] =
        json!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    let (base, task, _) = serve(gamma("v1", true), contradictory, book(YES_V1, "1700000000")).await;
    assert_eq!(
        reader(&base)
            .read_context(&request(YES_V1, 3, Duration::from_secs(2)))
            .await
            .unwrap_err(),
        ExecutionContextError::IdentityMismatch(ExecutionContextStage::ClobMarket)
    );
    task.abort();
}

#[tokio::test]
async fn malformed_fee_curve_refuses_context_without_defaulting_fields() {
    let mut bad = clob_market();
    bad["fd"]["r"] = json!(-0.01);
    let (base, task, _) = serve(gamma("v1", true), bad, book(YES_V1, "1700000000")).await;
    assert!(matches!(
        reader(&base)
            .read_context(&request(YES_V1, 3, Duration::from_secs(2)))
            .await,
        Err(ExecutionContextError::MalformedResponse(
            ExecutionContextStage::ClobMarket
        ))
    ));
    task.abort();
}

#[tokio::test]
async fn absent_curve_fields_remain_unknown() {
    let mut market = clob_market();
    market["fd"] = json!({"r":0.02});
    let (base, task, _) = serve(gamma("v1", true), market, book(YES_V1, "1700000000")).await;
    let observed = reader(&base)
        .read_context(&request(YES_V1, 3, Duration::from_secs(2)))
        .await
        .unwrap();
    assert_eq!(observed.fee_curve_rate_lexeme(), Some("0.02"));
    assert_eq!(observed.fee_curve_exponent_lexeme(), None);
    assert_eq!(observed.fee_curve_taker_only(), None);
    task.abort();
}

#[tokio::test]
async fn malformed_or_contradictory_constraint_metadata_refuses_the_complete_context() {
    let mut malformed = clob_market();
    malformed["mos"] = json!("five shares");
    let (base, task, _) = serve(gamma("v1", true), malformed, book(YES_V1, "1700000000")).await;
    assert!(matches!(
        reader(&base)
            .read_context(&request(YES_V1, 3, Duration::from_secs(2)))
            .await,
        Err(ExecutionContextError::MalformedResponse(
            ExecutionContextStage::ClobMarket
        ))
    ));
    task.abort();

    let mut mismatched_book = book(YES_V1, "1700000000");
    mismatched_book["tick_size"] = json!("0.02");
    let (base, task, _) = serve(gamma("v1", true), clob_market(), mismatched_book).await;
    assert_eq!(
        reader(&base)
            .read_context(&request(YES_V1, 3, Duration::from_secs(2)))
            .await
            .unwrap_err(),
        ExecutionContextError::IdentityMismatch(ExecutionContextStage::Book)
    );
    task.abort();
}

#[tokio::test]
async fn redirect_is_not_followed_and_error_does_not_expose_location() {
    let app = Router::new().route(
        "/markets",
        get(|| async {
            (
                StatusCode::FOUND,
                [(header::LOCATION, "http://127.0.0.1:9/private?secret=value")],
                "redirect",
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let error = reader(&base)
        .read_context(&request(YES_V1, 3, Duration::from_secs(2)))
        .await
        .unwrap_err();
    assert_eq!(
        error,
        ExecutionContextError::HttpStatus {
            stage: ExecutionContextStage::GammaMarket,
            status: 302
        }
    );
    assert!(!error.to_string().contains("secret"));
    task.abort();
}

#[tokio::test]
async fn rate_limit_retry_hint_is_typed_and_private_response_text_is_redacted() {
    let app = Router::new().route(
        "/markets",
        get(|| async {
            (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, "17")],
                "private body content",
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let error = reader(&base)
        .read_context(&request(YES_V1, 3, Duration::from_secs(2)))
        .await
        .unwrap_err();
    assert_eq!(
        error,
        ExecutionContextError::RateLimited {
            stage: ExecutionContextStage::GammaMarket,
            retry_after_seconds: Some(17)
        }
    );
    assert!(!error.to_string().contains("private"));
    task.abort();
}

#[tokio::test]
async fn chunked_response_cannot_bypass_body_limit() {
    let app = Router::new().route(
        "/markets",
        get(|| async {
            let chunks = tokio_stream::iter(
                (0..3).map(|_| Ok::<_, std::io::Error>(vec![b'x'; 1024 * 1024])),
            );
            Response::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from_stream(chunks))
                .unwrap()
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let error = reader(&base)
        .read_context(&request(YES_V1, 3, Duration::from_secs(2)))
        .await
        .unwrap_err();
    assert_eq!(
        error,
        ExecutionContextError::ResponseTooLarge(ExecutionContextStage::GammaMarket)
    );
    task.abort();
}

#[tokio::test]
async fn declared_oversize_is_rejected_before_body_read() {
    let app = Router::new().route(
        "/markets",
        get(|| async {
            Response::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CONTENT_LENGTH, (2 * 1024 * 1024 + 1).to_string())
                .body(Body::from_stream(tokio_stream::pending::<
                    Result<Bytes, Infallible>,
                >()))
                .unwrap()
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let error = reader(&base)
        .read_context(&request(YES_V1, 3, Duration::from_secs(2)))
        .await
        .unwrap_err();
    assert_eq!(
        error,
        ExecutionContextError::ResponseTooLarge(ExecutionContextStage::GammaMarket)
    );
    task.abort();
}

#[tokio::test]
async fn stalled_body_read_is_reported_as_deadline_timeout() {
    let app = Router::new().route(
        "/markets",
        get(|| async {
            let (sender, receiver) = mpsc::channel(1);
            tokio::spawn(async move {
                let _ = sender.send(Ok::<_, std::io::Error>(b"[".to_vec())).await;
                tokio::time::sleep(Duration::from_secs(5)).await;
            });
            Response::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from_stream(
                    tokio_stream::wrappers::ReceiverStream::new(receiver),
                ))
                .unwrap()
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let error = reader(&base)
        .read_context(&request(YES_V1, 3, Duration::from_millis(100)))
        .await
        .unwrap_err();
    assert_eq!(
        error,
        ExecutionContextError::Timeout(ExecutionContextStage::GammaMarket)
    );
    task.abort();
}

#[tokio::test]
async fn raw_fee_number_lexemes_survive_parsing_without_float_rounding() {
    let gamma_body = format!(
        r#"[{{"conditionId":"{CONDITION}","version":"v1","outcomes":["Yes","No"],"clobTokenIds":["123","456"],"positionIds":["789","890"],"active":true,"closed":false,"acceptingOrders":true,"enableOrderBook":true,"feeSchedule":{{"rate":0.1234567890123456789012345678,"exponent":2,"takerOnly":true}}}}]"#
    );
    let clob_body = r#"{"t":[{"t":"123","o":"Yes"},{"t":"456","o":"No"}],"mos":"5","mts":"0.01","fd":{"r":0.0200,"e":2,"to":true}}"#.to_owned();
    let book_body = serde_json::to_string(&book(YES_V1, "1700000000")).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let gamma_count = count.clone();
    let clob_count = count.clone();
    let book_count = count.clone();
    let app = Router::new()
        .route(
            "/markets",
            get(move || {
                let body = gamma_body.clone();
                let count = gamma_count.clone();
                async move {
                    count.fetch_add(1, Ordering::Relaxed);
                    raw_json(body)
                }
            }),
        )
        .route(
            "/clob-markets/{condition}",
            get(move || {
                let body = clob_body.clone();
                let count = clob_count.clone();
                async move {
                    count.fetch_add(1, Ordering::Relaxed);
                    raw_json(body)
                }
            }),
        )
        .route(
            "/book",
            get(move || {
                let body = book_body.clone();
                let count = book_count.clone();
                async move {
                    count.fetch_add(1, Ordering::Relaxed);
                    raw_json(body)
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let observed = reader(&base)
        .read_context(&request(YES_V1, 3, Duration::from_secs(2)))
        .await
        .unwrap();
    assert_eq!(observed.fee_curve_rate_lexeme(), Some("0.0200"));
    assert!(
        observed
            .gamma_raw_body()
            .contains("0.1234567890123456789012345678")
    );
    assert_eq!(count.load(Ordering::Relaxed), 3);
    task.abort();
}

#[tokio::test]
async fn one_absolute_deadline_spans_metadata_stages() {
    tokio::time::pause();
    let gamma_started = Arc::new(Notify::new());
    let clob_started = Arc::new(Notify::new());
    let (gamma_release, gamma_release_rx) = watch::channel(false);
    let requests = Arc::new(AtomicUsize::new(0));
    let gamma_gate = gamma_started.clone();
    let gamma_requests = requests.clone();
    let clob_gate = clob_started.clone();
    let clob_requests = requests.clone();
    let book_requests = requests.clone();
    let app = Router::new()
        .route(
            "/markets",
            get(move || {
                let gate = gamma_gate.clone();
                let requests = gamma_requests.clone();
                let mut release = gamma_release_rx.clone();
                async move {
                    requests.fetch_add(1, Ordering::Relaxed);
                    gate.notify_one();
                    let mut released = *release.borrow_and_update();
                    while !released {
                        if release.changed().await.is_err() {
                            break;
                        }
                        released = *release.borrow_and_update();
                    }
                    axum::Json(gamma("v1", true))
                }
            }),
        )
        .route(
            "/clob-markets/{condition}",
            get(move || {
                let gate = clob_gate.clone();
                let requests = clob_requests.clone();
                async move {
                    requests.fetch_add(1, Ordering::Relaxed);
                    gate.notify_one();
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    axum::Json(clob_market())
                }
            }),
        )
        .route(
            "/book",
            get(move || {
                let requests = book_requests.clone();
                async move {
                    requests.fetch_add(1, Ordering::Relaxed);
                    axum::Json(book(YES_V1, "1700000000"))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let started = tokio::time::Instant::now();
    let mut read = tokio::spawn(async move {
        reader(&base)
            .read_context(&request(YES_V1, 3, Duration::from_secs(1)))
            .await
    });
    tokio::select! {
        _ = gamma_started.notified() => {}
        result = &mut read => panic!("reader ended before the Gamma gate: {result:?}"),
        _ = wall_timeout(Duration::from_secs(30)) => panic!("Gamma gate was not reached"),
    }
    tokio::time::advance(Duration::from_millis(500)).await;
    gamma_release.send_replace(true);
    tokio::select! {
        _ = clob_started.notified() => {}
        result = &mut read => panic!("reader ended before the CLOB gate: {result:?}"),
        _ = wall_timeout(Duration::from_secs(30)) => panic!("CLOB gate was not reached"),
    }
    tokio::time::advance(Duration::from_millis(600)).await;
    let result = tokio::select! {
        result = &mut read => result.unwrap(),
        _ = wall_timeout(Duration::from_secs(30)) => panic!("reader did not enforce the shared deadline"),
    };
    assert_eq!(
        result.unwrap_err(),
        ExecutionContextError::Timeout(ExecutionContextStage::ClobMarket)
    );
    assert_eq!(started.elapsed(), Duration::from_millis(1_100));
    assert_eq!(requests.load(Ordering::Relaxed), 2);
    server.abort();
    tokio::time::resume();
}

#[tokio::test]
async fn caller_abort_stops_after_the_in_flight_metadata_request() {
    tokio::time::pause();
    let gamma_started = Arc::new(Notify::new());
    let requests = Arc::new(AtomicUsize::new(0));
    let gamma_gate = gamma_started.clone();
    let gamma_requests = requests.clone();
    let clob_requests = requests.clone();
    let book_requests = requests.clone();
    let app = Router::new()
        .route(
            "/markets",
            get(move || {
                let gate = gamma_gate.clone();
                let requests = gamma_requests.clone();
                async move {
                    requests.fetch_add(1, Ordering::Relaxed);
                    gate.notify_one();
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    axum::Json(gamma("v1", true))
                }
            }),
        )
        .route(
            "/clob-markets/{condition}",
            get(move || {
                let requests = clob_requests.clone();
                async move {
                    requests.fetch_add(1, Ordering::Relaxed);
                    axum::Json(clob_market())
                }
            }),
        )
        .route(
            "/book",
            get(move || {
                let requests = book_requests.clone();
                async move {
                    requests.fetch_add(1, Ordering::Relaxed);
                    axum::Json(book(YES_V1, "1700000000"))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut read = tokio::spawn(async move {
        reader(&base)
            .read_context(&request(YES_V1, 3, Duration::from_secs(60)))
            .await
    });
    tokio::select! {
        _ = gamma_started.notified() => {}
        result = &mut read => panic!("reader ended before the Gamma gate: {result:?}"),
        _ = wall_timeout(Duration::from_secs(30)) => panic!("Gamma gate was not reached"),
    }
    read.abort();
    assert!(read.await.unwrap_err().is_cancelled());
    assert_eq!(requests.load(Ordering::Relaxed), 1);
    server.abort();
    tokio::time::resume();
}

#[tokio::test]
async fn endpoint_credentials_and_non_loopback_http_are_rejected() {
    assert!(matches!(
        ClobExecutionContextReader::with_client_builder(
            reqwest::Client::builder(),
            "http://example.com",
            "https://gamma.example"
        ),
        Err(ExecutionContextError::InvalidInput)
    ));
    assert!(matches!(
        ClobExecutionContextReader::with_client_builder(
            reqwest::Client::builder(),
            "https://user:pass@clob.example",
            "https://gamma.example"
        ),
        Err(ExecutionContextError::InvalidInput)
    ));
    assert!(
        ClobExecutionContextReader::with_client_builder(
            reqwest::Client::builder(),
            "http://[::1]:8080",
            "http://[::1]:8081"
        )
        .is_ok()
    );
}

fn raw_json(body: String) -> Response<Body> {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn full_gamma_response_is_preserved_and_unknown_row_identity_refuses_context() {
    let mut observed_gamma = gamma("v1", true);
    observed_gamma
        .as_array_mut()
        .unwrap()
        .push(json!({"conditionId":"other-market","unknown_field":"retained"}));
    let expected_raw = serde_json::to_string(&observed_gamma).unwrap();
    let (base, task, _) = serve(observed_gamma, clob_market(), book(YES_V1, "1700000000")).await;
    let observed = reader(&base)
        .read_context(&request(YES_V1, 3, Duration::from_secs(2)))
        .await
        .unwrap();
    assert_eq!(observed.gamma_raw_body(), expected_raw);
    task.abort();
    for malformed in [Value::Null, json!({"version":"v1"})] {
        let mut rows = gamma("v1", true);
        rows.as_array_mut().unwrap().push(malformed);
        let (base, task, sends) = serve(rows, clob_market(), book(YES_V1, "1700000000")).await;
        assert_eq!(
            reader(&base)
                .read_context(&request(YES_V1, 3, Duration::from_secs(2)))
                .await
                .unwrap_err(),
            ExecutionContextError::MalformedResponse(ExecutionContextStage::GammaMarket)
        );
        assert_eq!(sends.load(Ordering::Relaxed), 1);
        task.abort();
    }
}
