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

- Package version: `rf 0.1.1` (contract version `0.1`).
- Captured at source commit `4279ad4` (the release commit) with plumbline
  0.0.4.
- Fixture file (sha256):
  `19e00e91fd1cdb973ac6584f7db6b1171834c0a851002c0e15e36abe2d4cd67e`.
- `fixture-fresh` passed in the release run for the release commit:
  <https://github.com/rgfind/rf/actions/runs/44035300025>.
- Conformance of the release binary in that run: profile
  `release-self-check`, 262 pass, 28 not applicable, 0 fail.
- Published archive checksum (crates.io index):
  `74cc4680594cc304cce06930dbd271a554fad9407d2cd82e188d5ca23d4be5ec`.
- Difference from the 0.1.0 capture: the `PARTIAL_RESULT` entry (`why`
  added, new summary), the new warning `GIT_SCRUB_UNAVAILABLE`,
  `tool_version`, `release_record`, `release_classification`, and the
  per-run fields. The 0.1.0 capture fixture sha256 was
  `e5549de41ca3b7d5031787613a2521204a4ee498564642b1d1375b1433d67156`.

- After the 0.1.1 release, the fixture was captured again from the source
  tree for an unreleased change: `limits.scrub_log` added, and the
  `GIT_SCRUB_UNAVAILABLE` summary now also names the time limit. Fixture
  sha256 after this change:
  `e209d7fd49d81961894728392a40a719365f035dfa5bfbde57857b5ae9138131`.
  The release hashes above are for the 0.1.1 release capture.

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
