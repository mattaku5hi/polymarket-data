# polymarket-data (initial slice)

Standalone, **read-only** Rust library for Polymarket public data. Currently only Data API v2 `GET /v2/trades` **one page** is implemented. It accepts an injected `reqwest::Client`, a base URL and a proxy wallet; no signing keys, global runtime, storage, trading actions or hidden retries. The caller owns pagination, cancellation, rate budgets and coverage policy.

```rust,ignore
let page = polymarket_data::fetch_v2_trades_page(
    &client,
    polymarket_data::DEFAULT_BASE_URL,
    proxy_wallet,
    100,
    None,
).await?;
for observation in page.observations {
    // Public observations, not unique fills or P&L.
    println!("{}", observation.observed_at);
}
// A non-null page.next_cursor means the walk is incomplete.
```

The response is capped at 8 MiB before decoding (including chunked responses), rejects any invalid row atomically and returns typed status/transport/body errors without embedding request URLs or response bodies. Numeric `Retry-After` is surfaced as seconds; no retry is performed. HTTPS is required except loopback HTTP for local fixtures. The vendor JSON remains available via `vendor_row()`. The API returns decimal **text** as supplied by JSON representation; it does not calculate fees or fill economics.

**Provenance and limits:** Data API v2 provides no per-fill ID. Equal wallet/transaction/token/side/time/price/size rows may represent distinct fills; this package neither deduplicates them nor claims historical completeness. An opaque cursor is not an independently verified source of coverage. The 8 MiB cap is a safety limit, not a throughput measurement. Polymarket CLOB, Gamma, RTDS, Polygon receipts, resolution semantics and the dashboard are **not** exported by this initial slice. No production consumer has switched to this library yet.

Run `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`. Tests use only loopback fixture servers. This directory is an independent Cargo project inside `crypto-tools`; it does not import Polydoghound or modify `trader-scout/`. The package is currently `UNLICENSED`; licensing, versioned distribution and rollback need owner approval. Do not publish or wire a production consumer without parity tests and an approved dependency/rollback path.
