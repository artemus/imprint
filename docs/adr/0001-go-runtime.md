# ADR 0001: Replace the Python runtime with one Go executable

- Status: accepted
- Date: 2026-08-14

## Decision

Imprint will move to a statically linked Go executable while preserving the
3.1 data, configuration, hook, CLI, authority, and portability contracts. The
existing Python runtime remains a behavioral oracle during migration and is
removed only after the parity suite passes on macOS, Linux, and Windows.

The target architecture has five internal packages: `config`, `capture`,
`store`, `authority`, and `cli`. Projections, ingest, retrieval, migrations,
backup, and purge are thin operations over `store`; hook actions invoke the same
application services as CLI actions. SQLite remains canonical and the existing
schema is opened in place—there is no destructive store conversion.

## Why Go

One binary removes Python, venv, pip, wheels, interpreter probing, and hook
wrapper scripts from installation. Go supplies cross-platform processes,
deadlines, cryptography, JSON, filesystem APIs, and strong types without a
runtime installation. SQLite is the only non-standard build dependency and is
compiled into release binaries.

## Compatibility gates

1. Existing 3.1 stores produce byte-equivalent JSON-LD and Markdown exports.
2. Capture envelopes and canonical JSON hashes match the current implementation.
3. Every existing CLI command and exit/failure policy has a parity test.
4. Hooks preserve deadlines, fail-open retrieval, and fail-closed undurable Stop
   capture behavior.
5. Authority signatures, recovery bundles, checkpoints, and import receipts
   verify across implementations.
6. Install, upgrade, and uninstall acceptance tests pass on all three platforms.

No Python file, lock, wheelhouse, or interpreter check is removed before these
gates pass. This keeps every shipped feature available throughout the rewrite.
