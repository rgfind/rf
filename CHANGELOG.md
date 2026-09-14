# Changelog

## 0.0.7 — ignore provenance and query modes

- Added `ignore_source` to `rf why` results for a file hidden by an active
  ignore rule. It gives the source file, source class, rule pattern, and an
  unambiguous line number when available.
- Added `--fixed-strings`, `--word`, `--ignore-case`, and `--case-sensitive`
  to `content`, `find`, and `why`. Successful results now state the active
  query mode in `meta.query`.
- `find --word` reports `GIT_SCRUB_WORD_UNAVAILABLE` when Git pickaxe evidence
  cannot preserve whole-word semantics.

## 0.0.6 — why per-file forensic verdict

- Added `rf why <pattern> <file> [--root <dir>]` for one-file match verdicts and
  normal search-filter attribution.
- Added `INVALID_TARGET` for missing, unreadable, non-file, out-of-root, and
  repository-internal why targets.

## 0.0.5 — contract version 2

This release changes the machine contract.

- The JSON envelope has seven top-level keys. Failed requests use `data: null`.
- Exit code 5 means a paged result snapshot changed. Restart with the emitted command.
- `content` and `find` return at most 100 rows by default and 1000 rows at most.
- `find` reports Git history coverage and does not hide unavailable history as an empty result.
- `rf robot-docs guide` emits ready-to-run agent workflow recipes. Capabilities lists all released commands.
