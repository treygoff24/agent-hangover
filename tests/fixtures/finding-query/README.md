Captured with the pinned Fallow 3.31.0 binary from `project/`:

`fallow --root project dead-code --no-type-aware --format json --quiet --finding-id dc1:unused-file:c6a0c011cc0e7ed3`

`found.json` keeps src/dead.js. `missing.json` removes it before the same query.
`inconclusive.json` keeps it and adds `--file src/index.js`; the missing ID is
filtered and the query is explicitly inconclusive. The raw outputs are retained,
including the fingerprint nested in `finding_id_query`.

`production.json` and `entry-exports.json` query the missing ID with `--production`
and `--include-entry-exports`, respectively. Both are query-wide limits.

Regenerate with `python3 tests/fixtures/finding-query/capture.py /path/to/fallow`.
