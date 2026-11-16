# rf contract policy

## Contract version 0.1

This policy applies to contract version `0.1`. The installed binary reports its
contract version with `rf capabilities --json`, in `data.contract_version` and
in `meta.contract_version` of every envelope. The policy URL in that output
identifies this version of the policy.

## Compatibility

A contract version is a `major.minor` string. A binary supports exactly the
versions listed in its capabilities output. Clients must compare the string and
must not read it as a number.

Before `1.0`, a minor bump may break. Each breaking change has a compatibility
statement in the release record. From `1.0`, a breaking change needs a major
bump.

An optional output field, an optional flag, or a new code is additive when
existing valid requests keep the same meanings, defaults, cursor identity, exit
codes, and output mode. A removed or renamed field, flag, code, exit-code
meaning, default, or output-mode meaning is breaking. A changed exit meaning
needs a new contract version and a compatibility statement in the release
record.

## Stable behavior

The JSON envelope has seven top-level keys: `ok`, `data`, `meta`, `warnings`,
`errors`, `commands`, `tool_version`. `data` is an object or `null`. A verb
that returns rows puts them in `data.items`. A request that fails before the
verb runs has `data: null`. A verb that fails after it has a result can keep
that result in `data`, with `ok: false`.

Each error has eight keys: `code`, `message`, `exit_code`, `remediation`,
`arg`, `path`, `did_you_mean`, `details`. Each warning has three keys: `code`,
`message`, `details`. Errors and warnings use one code registry, in
`data.error_codes` of the capabilities output.

`--json` selects the machine output. It is the only selector. Without it, rf
writes the human output, also to a pipe.

| Exit | Meaning | Use in rf |
|---|---|---|
| 0 | success | The verb ran. An empty result is success. |
| 1 | user-input error | Bad argv, bad pattern, a named path that does not exist. |
| 2 | safety block | Reserved. rf does not return it. |
| 3 | tool-environment error | An unreadable path, an absent program, a failed history scan. |
| 4 | transient failure | Reserved. rf does not return it. |
| 5 | conflict | The snapshot of a paged result changed. Use the restart command. |
| 6 | findings present | `doctor` found a faulty tool. `conformance` found a failed case. |
| 7 | internal error | A defect in rf. |
| 129, 130, 143 | ended by SIGHUP, SIGINT, SIGTERM | |
| 141 | reader closed the pipe | |

Defaults are part of the contract. A cursor binds the complete sorted result
snapshot and every option that can change rows or their evidence. A request
with a changed cursor identity fails with `INVALID_INPUT`; a changed snapshot
fails with `CONFLICT` and has a restart command.

Each verb with a result publishes its output schema as JSON Schema in
capabilities. Fixed limits are also in capabilities. Clients must read them
instead of assuming unbounded output.

## Release review

Before release, update the version-specific record in `release-records/`.
Classify every contract change as additive or breaking. A breaking change stops
release until the version, compatibility statement, capabilities fixture, and
generated documents agree.
