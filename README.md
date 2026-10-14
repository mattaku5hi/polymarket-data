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

For explicit wallet full-history reads, use `fetch_v2_trades_page_full_history`; it sends `start=1` on the initial request and every cursor request while keeping the same wallet and `taker_only=false` filters. For a bounded historical walk, use `fetch_v2_trades_page_full_history_until` with a positive inclusive Unix-second `end`:

```rust,ignore
let page = polymarket_data::fetch_v2_trades_page_full_history_until(
    &client,
    polymarket_data::DEFAULT_BASE_URL,
    proxy_wallet,
    100,
    saved_cursor,
    end_unix_seconds,
).await?;
```

Both `start=1` and the same `end` are sent on every cursor request. The upper event-time bound does not provide snapshot isolation or prove that data through that instant is available; callers must retain page/capture coverage and source freshness evidence. These functions select request modes, not completeness. The existing `fetch_v2_trades_page` leaves `start` and `end` unset and keeps its prior behavior.

## Venue-reported wallet economics

```rust,ignore
use polymarket_data::economics::{EconomicsReader, PositionsRequest, UserPnlRequest};

let reader = EconomicsReader::new(client.clone(), polymarket_data::DEFAULT_BASE_URL)?;
let mut request = PositionsRequest::new(proxy_wallet, 100);
request.status = Some("CLOSED".to_owned());
let positions = reader.positions(&request).await?;
let stats = reader.user_stats(proxy_wallet).await?;
let pnl = reader.user_pnl(&UserPnlRequest::new(proxy_wallet)).await?;
// Follow positions.next_cursor using request.with_cursor(cursor).
// The caller owns full-walk coverage, rate budgets and durable storage.
```

Each response retains exact raw bytes, query parameters, request/retrieval times
and HTTP freshness headers. Each request, including its body, has a 30-second
deadline and an 8 MiB body cap; no automatic retry is performed. Structured
HTTP errors retain status, Retry-After and the venue error payload. Successful
DTOs support serde captures, preserving absent versus explicitly null economic
atoms. Projected JSON numbers remain unvalidated provider values; use raw bytes
when exact decimal spelling matters. The source is explicitly `venue_reported`.
These readers do not calculate qualification, historical cost basis or ROI.

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

## API-only wallet activity hints

With the existing `chain-audit` feature, `activity_hints::PolymarketActivityHintClient::acquire_wallet_activity_hints` walks the default activity filter and explicit `TIP` filter using HTTP-only `WalletActivityHintLimits`. It keeps raw activity rows and per-pass/page/row occurrence positions without constructing a receipt verifier or sending RPC requests. Both filters retain `start`/`end` and other request parameters on cursor pages. Even two exhausted passes are hints, not proof of complete wallet history, balances, or ROI; callers must inspect `is_complete()` and keep venue-reported source semantics explicit.

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
Signed transaction binding supports legacy, EIP-2930, EIP-1559 and EIP-7702
envelopes. Type-4 authorization tuples stay in the signed payload; binding them
does not establish authorization validity or expand supported contract targets.
Failed Polygon receipts may contain one shape- and bloom-checked native Bor
`LogFeeTransfer` event, retained in the receipt root; other failed-receipt logs
are rejected. Native gas uses the signed fee terms and receipt gas delta, rather
than the deprecated fee-event payload. Receipt, interval and native-gas policy
versions are `/2`; fill and asset-movement decoder policies are unchanged.
All modules are read-only. Execution quotes below expose modeled API fees and
cash totals with local expiry. No submitted orders, wallet spending, guaranteed
settlement, FX conversion, history completeness or qualification is supplied.
Chain observations retain their narrow source policy
and mismatch/unavailable states; a proof for one contract/path does not validate
unsupported products. The fifth Exchange control observer proves current role and pause words under
a shared budget and deadline. Its sealed context can be reused internally;
rooted current/prior fixtures cover exact limits, cancellation and malformed
proofs. Current point state does not establish control state at a trade call.

`chain_log_audit::polygon_genesis_position_opening()` verifies an embedded
offline account-trie non-inclusion proof for the fixed CTF and PositionManager
emitters at Polygon block zero. The sealed result establishes only zero ledger
balance namespaces at genesis; it does not establish wallet history completeness
or later balances. Its reference header and proofs use Bor revision
[`9c445ef603e71469e1c176d8e57e7cf94864ade7`](https://github.com/0xPolygon/bor/tree/9c445ef603e71469e1c176d8e57e7cf94864ade7), including the pinned
[genesis allocation](https://github.com/0xPolygon/bor/blob/9c445ef603e71469e1c176d8e57e7cf94864ade7/builder/files/genesis-mainnet-v1.json)
and Bor's [`Genesis.ToBlock` implementation](https://github.com/0xPolygon/bor/blob/9c445ef603e71469e1c176d8e57e7cf94864ade7/core/genesis.go) and
[`BorMainnetGenesisHash`](https://github.com/0xPolygon/bor/blob/9c445ef603e71469e1c176d8e57e7cf94864ade7/params/config.go).
The pinned allocation, header-construction source and expected-hash source SHA-256 values are
`2b2c67557d703ec1eae81785c9521e214a464d1416469caae952de67cca2f8fa`,
`0ccd5413a1e12a8c89736cdaec58720487da81c789c24c50a6ebac2fb96fa4ab`, and
`322153f97a16990b37bfc34b03c2d535942cc736caf9d254275b690fbd2ddb57`, respectively.
The allocation reconstructs state root `0x654f28d19b44239d1012f27038f1f71b3d4465dc415a382fb2b7009cba1527c8`,
and the resulting header hash matches Bor's pinned mainnet genesis hash
`0xa9c28ce2141b56c474f1dc504bee9b01eb1bd7d1a507580d5519d4437a97de1b`.
The SDK rechecks both anchors and both fixed-address proofs before returning
the sealed result. The `chain-audit` dependency floor is Alloy Trie 0.9.7 because
0.9.0 accepts a truncated version of the pinned CTF absence proof.

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

`verify_fifth_native_binary_two_condition_trades_bounded` verifies two distinct
canonical native conditions at the same authenticated opening and per-block
roots. It acquires the receipt interval once, tags each source trade with its
condition index, and replays four owner position balances against one shared
pUSD balance stream under one actual-send budget and absolute deadline. Every
successful Exchange match must route wholly to one selected pair; mixed or
unselected pairs and direct module/funding activity refuse the complete result.
The immutable loopback packet at
`tests/fixtures/fifth-native-two-condition-trade-rpc.json` exercises two buys
across both pairs in one block and a later sale with shared cash checkpoints.
This source evidence does not establish complete wallet history, cost basis or
P&L.

`verify_fifth_native_binary_two_condition_splits_bounded` verifies one owner
deposit followed by one source-matched split for each of two canonical native
conditions, using one receipt interval and shared owner/module cash replay.
The funding transaction is reported once with the two split facts tagged by
condition index; every anchored root checks all four selected positions and
the shared module cash, including intermediate residual cash. It refuses
additional cash effects, other module operations, Exchange calls, unknown
owner/module movements and control or code transitions. The immutable loopback
packet at `tests/fixtures/fifth-native-two-condition-splits-rpc.json` covers a
10-unit deposit split as 4 and 6. It does not infer opening basis or make a
complete-history claim.

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

`chain_log_audit::extract_ctf_v2_owner_fill_signals` extracts owner rows only
from a sealed `ChainReceiptIntervalEvidence`, and only for the e111/e222 CTF V2
exchanges. It ignores unrelated events, but a malformed scoped `OrderFilled`
rejects the full extraction. It enforces all seven non-indexed words in the
pinned V2 event ABI and preserves the final `builder` and `metadata` bytes32
words through getters. Its policy version is
`ctf-v2-rooted-receipt-owner-fill-signals-e111-e222/2`. Each row preserves
block/parent/time, transaction index/hash, global log index, and the log's
ordinal among **all** receipt logs in that transaction. `OrdinaryMaker` versus
`ExchangeAggregateOwner` is the observable source event shape; equal-valued
logs remain separate rows. Share, collateral, and fee amounts are gross V2
event base units (the V2 fee is collateral-denominated); they are not wallet-net
accounting or RTDS matches. This CTF extractor does not cover the separate fifth
Exchange.

`FifthReceiptMakerWindow::aggregate_fills()` separately returns fifth-Exchange
aggregate owner rows only after their `OrderFilled`/`OrdersMatched` pair passes
the existing source-pinned checks. `maker_fills()` and `aggregate_count()` keep
their prior meanings. Fifth rows also expose the transaction-local ordinal and
global receipt log index. Neither API claims complete wallet history or
qualifies an economic trade.

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
Callers may supply a positive maximum age to `local_valid_until`; the returned
monotonic deadline is anchored to the original acquisition start and expires at
the exact boundary. It does not infer upstream freshness or a venue TTL.

`clob::execution_quote::estimate_execution_quote` calculates a read-only,
full-depth BUY estimate by gross notional or SELL estimate by shares. It requires
explicit `feesEnabled` and matching Gamma `feeSchedule` / CLOB `fd` fields for
positive API fee curves on supported V1 and V2 contexts; disabled fees require
a consistent explicit zero profile. It uses the market API curve fields and
does not infer fees from the legacy signed-order `feeRateBps` field.
The modeled platform fee applies `shares × rate × (price × (1-price))^exponent`
to each consumed displayed price level and rounds each merged price level upward
to five decimal places with checked integer-rational arithmetic. This selected
estimate policy does not claim exchange settlement exactness; the book does not
expose maker grouping. Builder fees are disabled, the role is Taker, and
unsupported models refuse. All cash values are labeled `ClobUsdNotional`,
without a collateral token/address binding or native pUSD claim. BUY quantity is
floored to 18 decimal places so gross spend stays within budget; the remaining
budget is returned. Returned total BUY cash and net SELL proceeds are modeled
estimates and do not relax caller safety gates. `ExecutionQuote::check_validity`
checks the original local deadline and does not renew it.

The read-only example acquires Gamma/market/book under a three-request budget:
`cargo run --locked --example execution_quote -- CONDITION_ID ASSET_ID buy 10`.
BUY input is gross notional before fees; use `sell` for a share quantity. Output
names modeled cash units and remaining local TTL. It submits no orders.

For a total cash cap that includes modeled fees, use
`execution_quote::estimate_all_in_buy_execution_quote(context, max_cash_budget, max_age)`.
Its `requested_amount()` is identified by `amount_kind() == BuyAllInCash`; the
existing `estimate_execution_quote` BUY remains gross notional before fees
(`BuyGrossNotional`), and SELL remains shares (`SellShares`). The all-in result
maximizes displayed shares on the 18-decimal quantity grid, reports budget dust
in `unspent_buy_budget()`, and uses the same ceil-per-merged-price-level fee
estimate. It does not guarantee matching or settlement and does not bind cash
to a collateral token or native unit.

For a cent-normalized market BUY budget, use
`execution_quote::estimate_normalized_market_buy_quote(context, MarketBuyBudget::GrossNotional(amount), max_age)`
or `MarketBuyBudget::AllInCash(cap)`. The sealed result reports
`normalized_maker_notional()` and `reserved_buy_cash()`, and `quote()` exposes
the same depth/fee/identity/expiry contract for existing consumers and native
binding. Gross input is floored to whole cents. All-in input selects the largest
whole-cent maker budget whose entire maker reserve plus modeled fees fits the
cash cap, after the existing full-budget depth check. Both paths refuse maker
cash below1 with `BelowMarketBuyCashMinimum`. For example, all-in1 with positive
fees may fail while1.0025 can reserve maker1 plus modeled fee.0025.

The maker rule is pinned to [official py-sdk PR292](https://github.com/Polymarket/py-sdk/pull/292)
and its merge24e34637; policy/source getters identify the inspected amount
implementation. Maker cash and modeled executed gross stay separate: budget1
at price.07 retains maker1 even when modeled share dust leaves gross slightly
below1. Original requested input and all remaining dust stay observable. The
all-in reserve calculation is this SDK's exact displayed-depth estimate, not
a reproduction of the official floating-point `maxSpend` helper or a proven
operator fee ceiling. Shares retain the18-decimal estimate grid; no signed
taker normalization or protected-price order is constructed. Complete venue
eligibility remains unverified. Existing estimators/getters keep their behavior.

For a cent-normalized BUY with a caller-supplied maximum price, use
`execution_quote::estimate_protected_market_buy_quote(context, MarketBuyBudget::AllInCash(cap), max_price, max_age)`
or `GrossNotional(amount)`. The sealed result exposes normalized maker cash,
six-decimal `maker_cash_base_units()` / `taker_share_base_units()`, unchanged
`max_price()`, `reserved_buy_cash()` and the underlying modeled `quote()`.
The cap must lie on the observed supported tick grid. Taker amounts use the
pinned py-sdk tick-dependent precision; an exact integer guard refuses a ratio
at or above cap + .0001. No price snapping, signing or submission occurs.
`required_maker_minimum()` reports the source-backed maker cash floor1. The
underlying quote's legacy client-minimum getters retain their conservative
estimate semantics and may check modeled gross below1; they do not replace the
protected result's normalized maker check or certify full venue eligibility.

Only asks at or below the original cap can cover the fixed taker share target.
Better prices leave modeled cash unspent rather than enlarge that target.
The all-in path selects the greatest depth/reserve-feasible, encoding-safe whole
cent maker amount, reserving the entire maker leg plus modeled fees. It uses a
bounded binary search and at most nine coarse-tick guard checks. This path can
return a smaller valid target when the entire cash ceiling lacks eligible depth;
it still requires complete coverage of the selected target and maker cash at
least1. The legacy normalized estimator keeps its full-budget depth behavior.
All-in residual is cash ceiling minus modeled executed gross and fee; gross
residual excludes fee. Full maker reserve is distinct from modeled executed cash.

For maker1/cap.07, the amount legs are `(1,000,000 / 14,285,700)`;
14.2857 displayed shares at.07 model gross.999999. The source/policy getters
identify py-sdk merge24e34637. Fee aggregation remains the documented merged
price-level model, not a venue fee ceiling or fill guarantee. The native quote
binder accepts `protected.quote()` under its existing asset/identity/unit checks;
neither binding nor amount normalization promotes whole venue eligibility.
Use example mode `buy-protected AMOUNT MAX_PRICE` or
`buy-all-in-protected CASH_CAP MAX_PRICE` for this read-only path.

`position_history::SqdPositionHistoryReader` captures both ERC-1155 holder
directions from the Polygon finalized stream, retaining sparse-page cursors and
raw bodies until the fixed caller anchor is reached. `rpc_position_history::`
`RpcPositionHistoryReader` uses a caller-configured Polygon RPC endpoint: chain,
finality and before/after anchor checks surround the two full-range log queries.
Both readers validate CTF/PositionManager filters, preserve separate ledgers,
reject conflicts and return source observations with literal request, byte and
deadline budgets. They establish no receipt proof, complete wallet inventory,
basis, P&L or qualification; unsupported server ranges and backpressure return
errors with no partial observation. Production provider selection stays with
the caller. The `position_history` example reads its endpoint from
`POLYGON_HISTORY_RPC_URL` and prints only source counts, never that endpoint.

For endpoints with finite log-range limits, call
`read_history_paginated(request, max_blocks_per_log_query)` with a positive
caller-selected inclusive span. Both directions are read for every contiguous
chunk. One global request/byte/deadline budget and before/after terminal header
cover the complete requested interval; any failed chunk returns no observation.
Planned calls are checked before sending. The512-call limit permits at most254
chunks. The example accepts an optional fifth span argument and then uses the
same30-second/32MiB limits with512 calls. This enables bounded windows, not an
automatic full-genesis scan or a claim of provider/source completeness.

For caller-managed backward capture, the additive
`read_history_segment_paginated(request, max_blocks_per_log_query)` also reads
the provider-reported header at the interval's start. Its sealed result exposes
`history()` and start number/hash/parent-hash getters. The same request, byte and
deadline limits cover all calls: five context calls plus two per log chunk,
so at most253 chunks fit the512-call cap. Start/terminal boundary log hashes
must match those headers; existing methods keep their four-context-call behavior.
With `chain-audit`, `rpc_position_history::validate_position_history_segment_source_agreement`
compares complete start-header fields and reuses the existing source agreement
check. The caller can use the agreed start parent as the next lower interval's
terminal anchor. This is source-reported boundary continuity; headers remain
structurally parsed and neither interior ancestry nor omission completeness is
proved. Durable progress, cumulative budgets and saved-capture validation remain
caller-owned. `reverify_recorded_rpc_position_history_segment` validates an
ordered list of saved request/response JSON pages against the same generated
methods, filters, IDs, bounds and response checks without making network calls.
Its distinct sealed result has no acquisition-clock data or network conversion;
it verifies transcript consistency, not provider identity, that calls occurred,
or source completeness.

`RpcPositionHistoryReader::new_with_request_interval(builder, endpoint, interval)`
adds explicit pacing between request launches on the same reader, including
successive or concurrent reads. Waiting uses each operation's existing deadline;
cancellation or expiry starts no later request. It adds no retry or extra call.
The ordinary `new` constructor retains zero spacing. Provider method costs,
other clients' traffic and account-wide quotas remain caller-owned.

With `chain-audit`, `position_history_receipts::validate_position_history_source_agreement`
checks two sealed RPC observations for the same holder, interval, terminal roots
and canonical event set before a caller starts receipt I/O. Different page widths
or JSON-RPC IDs do not change agreement. The caller chooses the sources; this
check does not establish their independence or consensus finality.
`bind_position_history_receipts(first, second, receipts)` repeats that shared
check and joins every source event to its exact root-derived transaction/log
locator and raw bytes in an existing sealed receipt observation. It requires
exactly one receipt per hinted transaction, with no extras or duplicates, and
uses the existing strict ERC1155 decoder. Within those verified receipts, the
reverse check refuses any holder transfer omitted by both source scans.

`ChainLogVerifier::capture_transaction_receipt_observation_bounded` returns the
ordinary live receipt observation together with exact ordered request/response
JSON bodies tagged by primary or secondary source. The raw transcript is
untrusted portable data. `reverify_recorded_transaction_receipt_observation_bounded`
replays it offline through the same receipt-root, signed-transaction and
movement checks and returns `RecordedChainTransactionReceiptEvidence`, which
does not claim current provider finality. Capture and replay cap each operation
at 16 requests, 128 MiB of response bodies, 4 KiB per request and 8 MiB per
response, with a caller deadline no longer than 30 minutes.
Call `ChainLogVerifier::with_full_block_hash_lookup()` to request the full
transaction objects by the already checked block hash. Number lookup remains
the default; recorded replay accepts either exact lookup shape and never falls
back between them.

`bind_recorded_position_history_receipts(first, second, receipts)` applies the
same join to two offline-reverified recorded history segments. Its result reports
`PositionHistoryReceiptSourceKind::RecordedTranscript`; the live binder reports
`NetworkObservation`. Recorded re-verification checks saved transcript content,
not whether an RPC occurred or who supplied it.

`bind_recorded_position_history_recorded_receipts(first, second, receipts)` also
accepts two recorded history segments and offline-reverified recorded receipt
evidence. Its `rooted_receipt_source_kind()` getter reports
`PositionHistoryReceiptSourceKind::RecordedTranscript`; this records the
evidence path, not the identity or independence of the transcript supplier.

The sealed result exposes sorted candidate IDs with ledger and original event
locators. Equal raw integers in CTF and PositionManager remain different
candidates. It is an observation of a partial interval: opening inventory is
unknown, and `complete_wallet_history()` / `qualification()` remain false,
including an empty interval. Matching hints cannot detect transfers in unhinted
transactions, certify token/market authority, or create balances, basis or P&L.
Acquisition budgets, one overall deadline and raw capture persistence remain
caller-owned; the shared agreement/binding functions perform no I/O.

With `chain-audit`, `verify_known_position_balances_bounded` proves an explicit
set of up to 2,048 full-width CTF/PositionManager IDs at one caller block/hash.
The same integer in both ledgers remains two assets. It shares code/header
verification, request budget and deadline across both providers and 64-key proof
batches; missing keys, bad proofs or disagreement refuse the whole result.
These are point balances, not a complete wallet universe or accounting report.
The `known_position_balances` example uses private input/output JSON files and
`POLYGON_BALANCE_RPC_PRIMARY` / `POLYGON_BALANCE_RPC_SECONDARY`; stdout contains
counts only. Historical proof retention is a separate endpoint capability from
historical log availability.

`chain_log_audit::bind_fifth_native_execution_assets` joins a sealed rooted
native Binary observation with a sealed HTTP V2 execution context only when the
ordered full-width provider asset IDs exactly equal the native pair. It keeps
the API condition selector separate from native condition identity and makes no
claim about outcome semantics, fees, currency, freshness, or execution safety.

`verify_fifth_native_binary_two_condition_activity_bounded` verifies one
rooted interval containing a direct pUSD funding call, one exact native split
for each selected condition, and supported Exchange trades across the shared
owner/module cash and position state. It acquires one receipt interval and
applies one request budget and deadline; the sealed report is complete-or-error
and does not combine independently verified per-condition reports.

`verify_fifth_native_binary_two_condition_activity_intervals_bounded` applies
the same single source scan and shared owner/module replay across 1–16 adjacent
rooted chunks (up to 256 blocks total). Module pUSD may carry between chunk
boundaries; funding, both splits, trade cash, and final residue are verified once
over the complete interval set with one request budget and deadline.

Context minimum sizes retain endpoint-specific units: Gamma `orderMinSize` is
labelled USDC notional by its documentation, book `min_order_size` is shares,
and compact CLOB `mos` has an unspecified unit. Typed unit getters describe those
source claims; these separate numbers are never compared as one constraint or
converted to collateral. Tick-size disagreement still refuses context.


With `chain-audit`, `bind_fifth_native_execution_quote` binds a quote to the
existing sealed V2 native asset context without additional RPC calls. It checks
market/asset/index, book provenance, acquisition timing and the original expiry.
The borrowed binding exposes the rooted pUSD collateral identity (six decimals)
and the separate source-bound Exchange fee cap. The original quote retains its
modeled fee classification and neutral CLOB cash notation; this is no FX
conversion or assertion of settled fee amounts. Source-tagged minimum fields
remain separate observations: market FAK/FOK applicability is unresolved, so
this binding does not establish venue-minimum validity or trading eligibility.

The quote also exposes the versioned published-client market minimum model via
`market_minimum_status()`, `market_minimum_basis()` and
`market_minimum_check_amount()`. Gross-BUY checks its requested gross input;
all-in BUY checks the resulting modeled gross notional, rather than its cash
ceiling. BUY requires at least1 in CLOB notional; SELL has `NoClientSellFloor`.
The all-in mapping is this estimate model's conservative input mapping, not an
official `maxSpend` or normalized signed-order contract. The inspected frontend
source SHA-256 is available from `market_minimum_source_sha256()`.
Endpoint-specific Gamma/book/compact minimum observations remain unchanged and
are not substituted for this market profile. `venue_minimum_status()` remains
`Unverified`: a client minimum result does not satisfy a caller's verified
venue-eligibility gate. Callers must also check the original expiry; below-floor
quotes remain readable estimates for compatibility.

The rooted native binding adds `quote_share_unit()`, `quote_share_decimals()`
and `share_unit_policy_version()`. Normalized native position shares use six
decimals, established by source-bound BinaryModule/BaseModule split/merge
amount parity and the official native order encoder. This applies to the sealed
native condition, not legacy migration or generic V1 shares.
`estimated_buy_received_shares()` returns the modeled BUY quantity without
subtracting cash-side native fees; SELL returns `None`. It is an estimate of
received shares at full modeled execution, not a current redeemability or
future-fill guarantee. `exact_modeled_share_base_units()` returns native units
only for exactly representable six-decimal quantities; otherwise it returns
`None` and leaves the 18-decimal estimate untouched. Exact unit conversion is
separate from tick-dependent signing precision. `vwap_share_denominator()`
explicitly supplies the gross-share denominator of the fee-exclusive VWAP.

For a consumer handoff, keep the quote condition/asset/index, execution side,
amount kind, gross values, modeled fees/totals, original times/expiry, book
identity, model versions and the native binding's units/source identities in one
immutable record. The application supplies its own quote ID, market/UP-DOWN and
forecast mapping, selector availability, qualified-clock deadline, latency
scenario and risk/trading status. Native BUY received shares can serve as a
modeled full-win payout quantity; other profiles do not inherit that meaning.
Missing or unverified eligibility stays explicit. No order API is introduced.
