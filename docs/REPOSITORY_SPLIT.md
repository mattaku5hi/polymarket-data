# Standalone repository split

Owner requested the independent polymarket-data GitHub repository on October15.
The subtree's committed history is retained. A double-inventoried frozen snapshot
also carries all115nonignored source files from the existing working tree,
including pending SDK modules; it does not discard them in favor of old HEAD.
Original monorepo sources and other projects are left untouched for rollback.

Added only standalone artifact profiles/budgeting, lock resolution, CI and this
handoff. No application policy, trading, credentials or deployment was added.
The library remains general; Polyazimuth's FOK cash/selection policy stays local.
License remains UNLICENSED; MIT was selected only for the new market-data crate.

Stable all-feature/all-target compiler and strict Clippy pass. Rust1.88covers
chain-audit; Rust1.85covers default and streams/gamma. Existing source tests were
preserved with history and compiler-checked, not executed. Behavioral QA remains
with each consumer's established acceptance gate. The initial public CI passed at9827774; the consumer-history merge requires
its own compiler checks and CI result.

Consumers use the new GitHub source with an exact reviewed revision. Preserve
existing independent local edits and gates in Polydoghound. Pending integration
must not be called a deployed paper/live release. Further shared SDK development
should use this repository; the old working tree is a retained migration source,
not an automatically synchronized second authority.

## Consumer history reconciliation

The initial source snapshot and Polydoghound's existing95907ff pin were on
different monorepo branches. A true merge of the consumer's subtree history
d63d1cd retains its activity-hint, full-history pagination, economics, selected
owner-watch and recorded RPC/SQD APIs alongside the initial SDK additions.
Duplicated identical timeout/block-hash helpers were retained once. The imported
selected-owner integration target now explicitly requires chain-audit; its test
cases are unchanged. Conditional SQD imports follow the same feature gate.

This corrects API compatibility; compiler checks cannot establish behavioral
equivalence. See CONSUMER_HISTORY_MERGE.json for branch identities and source
hashes. Consumers must pin the merge commit after their compiler checks.
