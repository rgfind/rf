# Contract fixture

`capabilities.rc.json` is the output of `rf capabilities --json` from a fresh
build of the source tree. `plumb capture` writes it. Do not edit it by hand.
The crate documents (README, CHANGELOG) and the claims in `plumbline.json` are
checked against it. The site has its own fixture, made from the published
crate.

## Capture procedure

1. `plumb capture --yes`. It builds `rf` (`cargo build --quiet --bin rf`),
   runs `rf capabilities --json` with `SOURCE_DATE_EPOCH=0`, and writes this
   fixture. It also refreshes the generated blocks in `README.md`.
2. `plumb check`. It stops if a claim in `plumbline.json` does not agree with
   the fixture. `plumb capture` does not change the claims; change them by
   hand.

`plumb preflight` has the gate `fixture-fresh`. It makes a fresh capture and
compares it with the committed fixture. The comparison is on the contract
content, not byte for byte (see `RELEASING.md`, gate 2).

## Current capture

- Package version: `rf 0.1.0` (contract version `0.1`).
- Captured at source commit `9692a39` with plumbline 0.0.4. The release
  commit `ec79e2a` changed only the release workflow file.
- Fixture file (sha256):
  `e5549de41ca3b7d5031787613a2521204a4ee498564642b1d1375b1433d67156`.
- `fixture-fresh` passed in the release run for the release commit:
  <https://github.com/rgfind/rf/actions/runs/43963625334>.
- Conformance of the release binary in that run: profile
  `release-self-check`, 262 pass, 28 not applicable, 0 fail.
- Published archive checksum (crates.io index):
  `04e465e1b639d580e53156ada63a69837e636738271739033912f7c6642e2862`.

## Capture after the release

- Re-captured with plumbline 0.0.4 after two unreleased registry changes:
  `a50de03` registers `PARTIAL_RESULT` for `why` and changes its summary;
  the next commit adds the warning code `GIT_SCRUB_UNAVAILABLE`. The
  fixture differs from the 0.1.0 capture in those two registry entries and
  in the per-run fields. The hashes in "Current capture" are for the 0.1.0
  release capture, not for this file.
- Re-captured for the 0.1.1 release preparation. Added differences:
  `tool_version` `0.1.1`, `release_record` `release-records/0.1.1.md`,
  `release_classification` `additive-pending-release-verification`. Replace
  "Current capture" with the 0.1.1 release evidence after the release.

## Validity

Prose edits (README, CHANGELOG) keep this fixture valid, because they do not
change the output of the binary. A code or contract change makes the fixture
stale. Then capture and check again before a release.

## History

The entries below are for rf 0.0.5. At that time the fixture was captured
from a packaged and installed release candidate (`cargo package`, then
`cargo install --path <extracted>/rf-0.0.5`). That procedure is not in use
now.

- Captured at `aa10addf` (rf-guy.9) — first RC capture.
- Re-captured at `aa6b9b7` (rf-guy.12, final pre-publish) — re-anchored provenance
  after the pre-publish code and packaging changes:
  - `75d34bb` (rf-guy.13) — fixed the top-level `--help` workflow-guide line (CLI
    help text only).
  - `1af9de1` + `aa6b9b7` — restricted the published archive to a root-anchored
    `include` allowlist (drops `.beads/`, `bench/`, internal contract-QA files).
  Verified the machine contract is unchanged across the re-capture: normalized
  `capabilities --json` (dropping per-run `request_id`, `ts_iso`, `data_hash`,
  `elapsed_ms`) is byte-identical to the prior fixture. Conformance green
  (28/0/5). None of these changes touch the compiled binary's contract; the
  re-capture re-anchors source commit, capture hash, and archive hash only.
