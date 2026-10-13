# Contracts and compatibility

## Implemented v1 offline campaign

The authoritative executable validator is `src/democratize_security/contracts.py`; `campaigns/development.example.json` demonstrates every required field. Unknown/missing fields and duplicate JSON keys are rejected rather than silently ignored.

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer 1; incompatible formats require a new version |
| `name`, `hypothesis` | Human campaign identity and proposed effect |
| `source_revision` | Full 40-character Git commit SHA; syntax checked, existence not checked |
| `scoring_version` | Frozen protocol/scorer identifier, not an executable evaluator |
| `model` | Provider, identifier and finite JSON settings; no credentials |
| `conditions` | Unique subset of four declared comparison conditions |
| `repetitions` | 1–100 repetitions per task/condition |
| `tasks` | Unique task ID, family, split and 64-character SHA-256 task manifest revision |
| `limits` | Max logical trials, budget in integer USD cents, timeout, retries, repairs and concurrency |
| `stopping_rule` | Human statement of stopping policy; execution enforcement not implemented |

Task families cannot cross splits in a campaign. `max_trials` bounds the Cartesian product. Concurrency is fixed to one; infrastructure retries at most one. Cost can be zero to support offline planning. Limits are configuration constraints, not yet enforced runtime reservations.

Canonical JSON uses sorted keys, compact separators, finite values and SHA-256. The entire campaign determines `campaign_id`; each campaign/task/condition/repetition tuple determines a stable `trial_id`. Ordering of lists is intentional and part of the campaign identity. Formatting and object-key ordering are not. Plan output embeds the campaign and sets `execution_enabled: false`. Re-running a plan gives identical output; changing inputs creates a new identity.

Validation does not verify a task hash against external files, model availability, caller authority, isolation, actual costs or security. Real execution must resolve those before dispatch. No `run`, `resume`, `report` or `confirm` command is exposed yet.

## Future contracts, not implemented

| Contract | Required fields/semantics |
| --- | --- |
| Candidate | ID, parent ID, patch/bundle hash, changed paths, rationale, proposer config/history |
| Trial execution | Campaign/candidate/task/family/split/condition/repetition, model/settings, tool permissions, image digests, deadlines, retry/repair limits |
| Result | Trial ID, artifact/verifier hashes, lifecycle, separate functional/security/coverage outcomes, failed check IDs, duration, usage, nullable cost, failure category, evidence paths |
| Event | Immutable event ID, trial/attempt, timestamp, from/to state, reason, provenance |
| Budget | Reservation identity, maximum charge, measured usage, estimate/actual marker, reconciliation state |

Adapters should implement project-owned prepare/run/extract/verify/report boundaries without exposing framework-specific record types throughout the codebase. Define narrow typed interfaces when integrating the first runner. Schema migration must preserve old records and prevent silent reinterpretation of scoring.
