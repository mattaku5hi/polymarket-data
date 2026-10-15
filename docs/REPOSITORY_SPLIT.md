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
with each consumer's established acceptance gate. CI is prepared, not verified
by a local compiler run.

Consumers use the new GitHub source with an exact reviewed revision. Preserve
existing independent local edits and gates in Polydoghound. Pending integration
must not be called a deployed paper/live release. Further shared SDK development
should use this repository; the old working tree is a retained migration source,
not an automatically synchronized second authority.
