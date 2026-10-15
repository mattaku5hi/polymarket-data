# Provider-reported current portfolio flows

`rpc_position_history::current_interval_census` adds bounded current collateral
and position transfer scans over `(start_block, through_block]`, anchored by
caller-selected block hashes. The additive `*_chunked` network and recorded
replay methods accept widths1..=128; existing methods retain128. One global
budget covers every chunk and event header. The owner-fill scan adds maker-topic
observations from the first four Exchange addresses without a taker duplicate
filter. It does not itself establish net trade cash or complete wallet history.

`current_interval_transactions` reads at most32 explicitly selected census
transactions and receipts, two calls each,16MiB and120seconds. Raw movement
locators must agree with the census; failures return no partial observation.
Recorded replay validates the same methods, filters, order and bounds offline.
Capture times retained by a caller remain reported metadata.

With `chain-audit`, `fifth_binary_context` reads PositionManager moduleById(1)
at a census event block using four ordinary RPC calls, at most256KiB and30seconds.
The before/after header must agree. This is provider-reported, implementation
Unbound context; no historical state proof or authenticated code identity.
`chain_log_audit::decode_provider_reported_fifth_binary_settlement` derives a
binary pair from owner order token IDs and applies the shared complete settlement
model to signed transaction/receipt data. Exact owner cash/position legs retain
both endpoints; gross fills and separate fees remain separate observations.
The raw fifth event parser also exposes unpaired OrdersMatched without promoting
it to an owner fill. Existing rooted verification APIs retain their guards.

`current_interval_census::portfolio_flow` reduces a bounded default+TIP Activity
window and a movement census. The additive fifth-settlement overload consumes
only exact matched pUSD/PositionManager legs. Legacy support is limited to
exact zero-fee V1 USDC.e/CTF matches. Deposits and withdrawals become signed
six-decimal capital flows identified by chain:transaction:log-index. Matched
income remains return; fee/refund metadata is not counted as another flow.
Unknown lifecycle, in-kind, wrap, ambiguous, unmatched or incomplete evidence
keeps coverage Unknown. KnownForDeclaredScope describes only the declared
current source window, never historical completeness, canonical identity,
qualification, NAV, high-water state or an execution guarantee.

## Bounded acquisition and offline artifact replay

With `chain-audit`, `current_wallet_flow::capture_current_wallet_flow_observation`
acquires one wallet's declared block/hash interval, derives Activity bounds from
its headers, reads32-block log chunks and selected transactions/receipts, and
resolves fifth BinaryModule context where needed. Defaults cap the entire
capture at8 Activity requests,256 RPC calls,32MiB raw response bodies,120seconds
and32 candidate transactions. Each subsequent phase receives only the remaining
global budget; there are no automatic retries. Unsupported or omitted candidate
semantics keep coverage Unknown. Endpoint-free `to_artifact` retains ordered RPC
frames, original capture windows/counts, raw Activity row occurrences and pass
summaries. Activity HTTP response envelopes are not retained by the existing
hint reader; these remain venue-reported rows and completion flags.

`CurrentWalletFlowObservation::from_artifact` replays the SDK components without
network calls, binds their scopes and recomputes the reduction before comparing
it with the saved report. Original times stay reported capture metadata; local
replay does not establish that calls occurred or authenticate the provider.
Use `request()`, `reduction()` and capture/count getters for caller provenance.
Maximum serialized artifact size is64MiB. No DB, risk, HWM or order path is added.

## V2 event ABI correction

Known V1 OrderFilled logs require exactly five data words. Known V2 logs require
exactly seven, matching the official [ITrading.sol event](https://github.com/Polymarket/ctf-exchange-v2/blob/ccc0596074f4dfd62c944fbca4de252893b82b4b/src/exchange/interfaces/ITrading.sol)
and [Events.sol emitter](https://github.com/Polymarket/ctf-exchange-v2/blob/ccc0596074f4dfd62c944fbca4de252893b82b4b/src/exchange/mixins/Events.sol).
The extra builder/metadata words remain in the raw RPC frame and are not another
fee or cash flow. Five/six/eight-word V2 payloads are rejected; the full payload
is passed to the existing gross-plus-fee decoder. A bounded real capture exposed
the previous five-word V2 limit; corrected full-width golden fixtures now cover
this mismatch. Parsing a V2 event does not enable its still-unsupported complete
CTF V2 settlement attribution in the current flow reducer.
