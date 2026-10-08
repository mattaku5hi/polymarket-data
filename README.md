# polymarket-data

Standalone, **read-only** Rust library shared by Polymarket applications. Default APIs acquire Data API v2 pages and CLOB snapshots and calculate exact gross depth. Optional modules provide market/RTDS streams, Gamma metadata and bounded rooted chain evidence. Page readers accept an injected `reqwest::Client` and a base URL; callers own pagination, cancellation, rate budgets and coverage policy. Stream reconnect behavior and chain request budgets are explicit module contracts.

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

For an explicit smaller **positive** TOKENS floor, use `fetch_v2_global_trades_page_with_min_size(&client, base, "0.000001", limit, cursor)`. Zero is rejected: the provider treats zero as its default 0.01, not an unfiltered request. The same selected minimum is sent on cursor requests. A bounded public probe with 0.000001 returned a 0.00868-share row; this verifies sampled sub-0.01 visibility, not all-fill completeness or the precision of every product.

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

The book reader checks token identity, nonblank hash, 13-digit millisecond timestamp and all bid/ask levels atomically, preserving decimal text and vendor order. Decimal values outside the exact supported representation are rejected rather than rounded. The response is capped at 2 MiB, including chunked bodies. Empty sides are valid observations, not executable prices. Numeric `Retry-After` is surfaced; the caller owns timeout/retry/cancellation policy via its injected client. No fee, freshness, depth-execution or coverage claim is derived. The shared gross-depth calculations described below are used by the Polydoghound adapter; its full-position SELL requirement and paper fee policy remain project-owned.

## Shared adapter capabilities

Default features expose trade pages, raw resolution pages, bounded HTTP defaults,
candidate overlap observations and exact Decimal CLOB depth calculations:

```rust,ignore
let buy = polymarket_data::clob::quote_buy(&book, requested_notional)?;
let sell = polymarket_data::clob::quote_sell(&book, requested_quantity)?;
// Reports retain asset_id, book_hash, book_timestamp and permit partial depth.
// Gross notional/proceeds exclude fees and do not establish executable quotes.
```

Optional features keep a single reusable implementation:

| Feature | Public modules | Scope |
|---|---|---|
| `streams` | `market_stream`, `trade_firehose` | CLOB bid cache and RTDS observations; reconnect clears stale market state |
| `gamma` | `gamma_index`, `gamma_market_metadata`, `ttl_cache` | Bounded Gamma acquisition, neutral metadata and cache; no strategy/risk traits |
| `chain-audit` | `chain_log_audit`, `activity_hints` | Budgeted independent-provider rooted evidence, signed transaction/receipt binding, source-specific CTF/fifth contracts |

Core, `streams` and `gamma` support Rust 1.85. `chain-audit` requires Rust 1.88.
All modules are read-only. No private keys, submitted orders, wallet spending,
complete ExecutionQuote, fee discovery, FX conversion, history completeness or
qualification is supplied. Chain observations retain their narrow source policy
and mismatch/unavailable states; a proof for one contract/path does not validate
unsupported products. The fifth Exchange control observer proves current role and pause words under
a shared budget and deadline. Its sealed context can be reused internally;
rooted current/prior fixtures cover exact limits, cancellation and malformed
proofs. Current point state does not establish control state at a trade call.

The sealed fifth Exchange code-context observation also binds the source/build
`MAX_FEE_RATE` immutable for the exact Current641b and Prior7345 runtime hashes.
Both verified source packets bind the constructor value to 1,000 basis points;
the prior implementation is from a captured explorer source snapshot, while
Current641b matches its pinned source commit. This is the contract's operator-
supplied per-order fee cap, not a market commission, expected fee, builder fee,
all-in execution cost, or wallet-net ceiling. Unknown runtime hashes are not
mapped to a cap. This source binding proves neither chain inclusion nor proxy
activation history; see `src/chain_log_audit/artifacts/fifth-exchange-immutable-fee-cap-binding.json`.

`ChainLogVerifier::verify_fifth_native_binary_trade_interval_bounded` attributes
direct native Binary `matchOrders` receipts to the selected owner and reconciles
both position balances and pUSD at every block boundary. One request budget and
deadline cover native context, receipts and every recovered submitter/order-maker
control proof. Control transitions and unsupported activity refuse the entire
interval and clear transaction facts. Successful observations establish bounded
source correspondence; they do not independently validate order signatures,
execute an EVM trace or establish native creation, opening cost basis or P&L.

`verify_fifth_native_binary_activity_interval_bounded` combines those trade
facts with exact owner-funded native module operations in one rooted replay.
Pending module funds can cross block boundaries, including a trade before their
consumption; every owner/module balance checkpoint must reconcile, and pending
funds and module balances must be empty at the end. It returns its own sealed
activity observation without opening cost basis or collateral conversion.
`verify_fifth_native_binary_activity_intervals_bounded` acquires1–16 adjacent
intervals under one actual-send budget and one absolute deadline. It validates
all anchors before I/O, requires complete matched segments and identical rooted
shared boundaries, and returns no report prefix on failure. Module funding must
be consumed within each segment; pending funding across segment boundaries is
unsupported. Quiet segments retain authenticated nonzero owner inventory without
adding economic facts. This evidence establishes no cost basis, collateral FX,
complete wallet history or qualification.


Source trade fills and direct module transaction locators expose their exact
receipt log indices. Repeated owner order hashes retain distinct occurrences;
consumers can order economic actions without reparsing vendor event ABIs.

Polydoghound consumes these modules through thin local trait/domain adapters.
Polyazimuth can consume gross-depth acquisition through its observation consumer
seam; its reconstructed book views are not silently upgraded to executable quotes.
The library has no dependency on either application's domain, persistence or risk.

**Provenance and limits:** Data API v2 provides no per-fill ID. Equal
wallet/transaction/token/side/time/price/size rows may represent distinct fills;
observed overlap and opaque cursors do not establish historical completeness.
Raw vendor data is preserved separately from derived observations. Bounds are
safety limits, not capacity measurements. Caller-selected budgets, cancellation
and coverage policy remain explicit. Book provenance supplies no freshness SLA,
fee/currency evidence or order validity guarantee.

Run `cargo fmt --all -- --check`,
`cargo clippy --locked --all-targets --all-features -- -D warnings`,
`cargo test --locked --all-features` and
`cargo +1.85.0 check --locked --no-default-features --features streams,gamma`.
Tests use offline deterministic artifacts and loopback fixture servers.
This is an independent Cargo project inside `crypto-tools`; it does not modify
`trader-scout/`. The package remains `UNLICENSED` and is distributed through
explicit reviewed Git revisions, not a package-registry release.

`observe_native_binary_gas_for_owner` consumes one or more sealed native activity
reports without additional RPCs. It shares the V1 signed-envelope/receipt gas
accumulator, includes failed receipts and excludes other recovered payers. Gas
availability is independent of trade attribution; missing gas evidence refuses
the whole observation. Amounts are Polygon native base units, with no collateral
conversion, wallet-wide gas-history or net-P&L claim.

`clob::execution_context::ClobExecutionContextReader` acquires Gamma market
metadata, compact CLOB market info and a selected book as three bounded reads.
Explicit Gamma version selects outcome asset IDs; token/label/condition and
known market-state/constraint disagreement refuse the complete context. It
preserves exact raw responses, fee-number lexemes and local acquisition timing,
with unknown fees left unknown. Its caller-configured client builder has redirects
and retries disabled, and one request budget/deadline covers all bodies. This is
quote input provenance; it provides no canonical native-ID binding, fee/currency
calculation, exchange-guaranteed freshness/expiry or order interface. Raw book
timestamps have no inferred seconds/milliseconds unit. Core supports Rust1.85.

Context minimum sizes retain endpoint-specific units: Gamma `orderMinSize` is
labelled USDC notional by its documentation, book `min_order_size` is shares,
and compact CLOB `mos` has an unspecified unit. Typed unit getters describe those
source claims; these separate numbers are never compared as one constraint or
converted to collateral. Tick-size disagreement still refuses context.
