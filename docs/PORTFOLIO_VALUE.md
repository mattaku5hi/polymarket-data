# Current wallet positions value

`economics::EconomicsReader::portfolio_value(user)` reads the whole-wallet
`GET /v2/value?user=...` route. It preserves raw response bytes, request times,
freshness headers, query parameters, the returned wallet identity and full data
object. The projected value remains an unvalidated JSON atom; read exact decimal
spelling from `ResponseEvidence::raw_body`, and validate it before money math.
Explicit null remains unknown. Missing value or malformed/mismatched wallet
identity is rejected.

The [official contract](https://data-api.polymarket.com/v2/openapi.json) describes
marked market holdings plus unresolved combos at cost basis. It excludes free
collateral cash and has no venue as-of timestamp. It is not a cash-inclusive
portfolio NAV or historical equity endpoint. Combining it with other sources
requires an explicit account/asset scope and observation window; this reader
performs no sum, historical reconstruction or risk decision.

The method uses the existing bounded HTTP reader with no credentials, retries,
new dependencies or alternate endpoints. Local mock tests cover raw spelling,
evidence, null/missing values, malformed data and wrong-wallet responses.

## Collateral cash observation artifacts

`collateral_cash::fetch_collateral_cash_snapshot(&client, rpc_url, &wallets)`
reads pUSD and USDC.e for1–100 distinct canonical Polygon wallets. It checks
chain137 and token decimals6, pins calls to one provider-reported finalized
block and rechecks that block's header. One capture uses exactly `5 + 2*N`
sequential RPC calls, with a30-second total deadline,10 seconds per call,
64 KiB per response and1 MiB aggregate response bytes. Balances remain raw
uint256 words; consumers perform their own checked monetary conversion.

`collateral_cash::CollateralCashSnapshot::to_artifact()` writes a versioned
endpoint-free JSON artifact, and `from_artifact()` replays its saved JSON-RPC
frames offline. The 4 MiB artifact cap allows the 1 MiB aggregate RPC-response
budget, request frames, metadata, and JSON escaping of exact raw-frame strings.
Frames remain strings so JSON parsing does not normalize their original bytes.

Offline replay rebuilds the Polygon block, fixed token decimals, and raw balance
words from the recorded calls, then checks them against the stored projections,
call order, request parameters, IDs, timestamps, and byte bounds. This checks
internal consistency only: a coordinated rewrite of frames and projections can
still pass because the provider transcript has no signature or state-root
proof. The result remains `PROVIDER_REPORTED` and supplies no NAV or historical
equity claim.

## Current interval transfer census

`rpc_position_history::RpcPositionHistoryReader::read_current_interval_census`
accepts `current_interval_census::RpcCurrentIntervalCensusRequest`:1–100 distinct
wallets, previous cash block number/hash, new finalized block number/hash, and
request/response/deadline budgets. It scans `(start_block, through_block]` for
pUSD/USDC.e Transfer and CTF/Position Manager TransferSingle/TransferBatch events.
Four topic-OR filters per128-block chunk cover the whole wallet group; this is
not four requests per wallet. The method shares the existing RPC transport.

Limits:2,048 blocks,20,000 unique logs,384 event blocks,512 requests,2 MiB per
response,32 MiB aggregate response bytes and120 seconds total. With `C` chunks
and `H` event blocks, calls are at most `5 + 4*C + H`; headers already available
at interval boundaries are reused. Actual caller budgets can stop it earlier.
Each returned event block has a timestamp-bearing header checked against its
logs; the previous anchor and ending-header recheck bind the interval.

Stable event IDs use chain/transaction hash/log index; block hash remains a
separate binding. Conflicting duplicates, wrong filter families, removed logs,
malformed ABI, inconsistent headers or exhausted limits return an error. The
same strict ERC-1155 byte decoder serves default builds and optional receipt
inspection. The result retains ordered endpoint-free raw RPC frames and remains
provider-reported; it is not an authenticated transcript or state proof.

The census does not classify capital flows, value in-kind transfers, or publish
NAV. Consumers must attribute each wallet separately: a transfer between two
tracked wallets is outgoing for one portfolio and incoming for the other.
Do not net that transfer away across the wallet group or count its API activity
row and token log twice.
