# rf contract policy

## Contract version 2

This policy applies to contract version 2. The installed binary reports its
contract version with `rf capabilities --json`. The policy URL in that output
identifies this version of the policy.

## Compatibility

Contract versions are monotonic positive integers. A binary supports exactly
the versions listed in its capabilities output. An optional output field, an
optional flag, or a new warning code is additive when existing valid requests
keep the same meanings, defaults, cursor identity, exit codes, and output mode.

A removed or renamed field, flag, warning code, exit-code meaning, default, or
output-mode meaning is breaking. A renamed item must keep its old spelling for
one released contract version, mark it deprecated in capabilities, and state a
removal version. A breaking change needs a new contract version and an explicit
compatibility statement in the release record.

## Stable behavior

The JSON envelope has the seven top-level keys in capabilities. `--json` is the
machine output. `--human` is the human output. Success is exit 0, input error
is exit 1, environment error is exit 3, snapshot conflict is exit 5, and an
internal defect is exit 6.

Defaults are part of the contract. A cursor binds the complete sorted result
snapshot and every option that can change rows or their evidence. A request
with a changed cursor identity fails with `INVALID_INPUT`; a changed snapshot
fails with `CONFLICT` and has a restart command.

Each verb schema has a version in capabilities. Fixed limits are also in
capabilities. Clients must read them instead of assuming unbounded output.

## Release review

Before release, update the version-specific record in `release-records/`.
Classify every contract change as additive or breaking. A breaking change stops
release until the version, compatibility statement, capabilities fixture, and
generated documents agree.
