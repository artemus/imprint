# ADR 0001: Replace the Python runtime with one Go executable

- Status: accepted
- Date: 2026-08-14

## Decision

Imprint will move to a statically linked Go executable while preserving the
3.1 data, configuration, hook, CLI, authority, and portability contracts. The
existing Python runtime remains a behavioral oracle during migration and is
removed only after the parity suite passes on macOS, Linux, and Windows.

Package boundaries follow stable contracts rather than a fixed package count.
Small validation and rendering packages may sit beside `config`, `capture`,
`store`, `authority`, and `cli`, while orchestration stays thin and shared by
hooks and CLI actions. SQLite remains canonical and the existing schema is
opened in place—there is no destructive store conversion.

## Migration method

This is an incremental replacement, not a blanket rewrite.

1. Port one bounded workflow only after its public inputs, outputs, side effects,
   and failure policy are covered by compatibility tests.
2. Keep the Python implementation as the reference and fallback until that
   workflow passes cross-platform parity; do not redesign adjacent subsystems as
   part of the port.
3. Preserve existing schemas and durable artifacts. Prefer adapters around the
   canonical store to parallel models or conversion layers.
4. Extract shared orchestration only after repetition exists, and keep security
   checks close to the boundary they protect.
5. Remove Python surfaces only in the final packaging checkpoint, after every
   compatibility gate below passes.

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
