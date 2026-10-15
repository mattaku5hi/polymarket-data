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

The combined acquisition/artifact facade is not part of this publication;
callers currently compose these APIs and preserve their raw evidence.
