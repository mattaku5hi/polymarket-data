# polymarket-data (read-only slices)

Standalone, **read-only** Rust library for Polymarket public data. Implements Data API v2 `GET /v2/trades` **one page** and CLOB `GET /book` **one snapshot**. It accepts an injected `reqwest::Client` and a base URL, with either a wallet-filtered trade page or an explicit global raw page; no signing keys, global runtime, storage, trading actions or hidden retries. The caller owns pagination, cancellation, rate budgets and coverage policy.

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

The response is capped at 8 MiB before decoding (including chunked responses); the wallet reader rejects any invalid row atomically. Both readers return typed status/transport/body errors without embedding request URLs or response bodies. Numeric `Retry-After` is surfaced as seconds; no retry is performed. HTTPS is required except loopback HTTP for local fixtures. The vendor JSON remains available via `vendor_row()`. The API returns decimal **text** as supplied by JSON representation; it does not calculate fees or fill economics.

## Global trade page (raw evidence)

```rust,ignore
let page = polymarket_data::fetch_v2_global_trades_page(
    &client, polymarket_data::DEFAULT_BASE_URL, 1_000, saved_cursor,
).await?;
// Persist page.rows in vendor order, before product mapping or deduplication.
// Repeated equal rows remain repeated; page.next_cursor is opaque.
```

This sends **no `user`**, with `taker_only=false`. The existing wallet signature is unchanged. Global rows are raw JSON, **not validated `TradeObservation`s**: unenriched/other-product rows must not disappear because the ordinary-market parser rejects them. The caller must validate and quarantine unsupported products before using their economics. Neither reader deduplicates. Missing/null `data`, missing/blank/ill-typed `next_cursor`, and contradictory `has_more` when supplied are rejected instead of implying exhaustion. An explicit empty `data` array and null cursor is valid.

Only first-page requests send `limit`; cursor requests use the provider's encoded size. No global `start/end` parameters are exposed: the provider ignores them outside the wallet-shaped feed. The global feed retains the current-plus-previous calendar month, not full history. A short walk is not proof of end-to-end completeness, and following an old cursor only walks older rows—it does not poll new arrivals.

A bounded 2026-09-30 public probe found CloudFront `Cache-Control: public, max-age=300`; request `Cache-Control: no-cache` still returned an aged head. It also found enrichment changing between reads (`event_slug`/`outcome_index`). Thus an identical cached head is not a liveness guarantee and a whole-row JSON hash is not stable overlap identity. `RawTradesPage.cache_age_seconds` exposes a parsed HTTP `Age` header; missing or invalid means unknown, never an invented zero/cache miss. The library does not bypass caching, infer a freshness SLA or recover coverage gaps.

## CLOB book snapshot

```rust,ignore
let book = polymarket_data::clob::fetch_book(
    &client, polymarket_data::clob::DEFAULT_BASE_URL, token_id,
).await?;
// Ordered vendor levels; not a quote guarantee or a simulated execution.
assert_eq!(book.asset_id, token_id);
```

The book reader checks token identity, nonblank hash, 13-digit millisecond timestamp and all bid/ask levels atomically, preserving decimal text and vendor order. Decimal values outside the exact supported representation are rejected rather than rounded. The response is capped at 2 MiB, including chunked bodies. Empty sides are valid observations, not executable prices. Numeric `Retry-After` is surfaced; the caller owns timeout/retry/cancellation policy via its injected client. No fee, freshness, depth-execution or coverage claim is derived. This new CLOB slice is local and not yet wired into the pinned Polydoghound consumer; its paper depth calculations remain project-owned.

**Provenance and limits:** Data API v2 provides no per-fill ID. Equal wallet/transaction/token/side/time/price/size rows may represent distinct fills; this package neither deduplicates them nor claims historical completeness. An opaque cursor is not an independently verified source of coverage. The 8 MiB cap is a safety limit, not a throughput measurement. CLOB market/user WebSockets, account/auth/order submission, Gamma, RTDS, Polygon receipts, resolution semantics and the dashboard are **not** exported by these slices. This is not a full CLOB client wrapper. The new global/CLOB slices are not wired into the pinned Polydoghound consumer.

Run `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`. Tests use only loopback fixture servers. This directory is an independent Cargo project inside `crypto-tools`; it does not import Polydoghound or modify `trader-scout/`. The package is currently `UNLICENSED`; licensing, versioned distribution and rollback need owner approval. Do not publish or wire a production consumer without parity tests and an approved dependency/rollback path.
