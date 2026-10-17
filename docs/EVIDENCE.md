# Offline verifier evidence contract

Issue #38 adds validation and canonical serialization for synthetic verifier
reports. This is a prerequisite to result persistence, not an accepted-result
registry or proof that a verifier executed. Store v5 now links these offline
observations as described in [PERSISTENCE.md](PERSISTENCE.md); it grants no
accepted-result or execution authority.

## Report validation

`verification.report.validate_report(report)` checks the existing
`synthetic-reference-v3` report, schema version 1. Its exact fields are
`schema_version`, `protocol`, `coverage`, `outcome`, and `checks`. Each check has
exactly `id`, `outcome`, and `detail`; IDs must be unique members of the eight
required v3 checks. Outcomes are `pass`, `fail` or `not_evaluated`. Detail text is
bounded to 2,048 UTF-8 bytes per check. Extra fields, unknown/duplicate checks,
wrong types and inconsistent summaries are rejected.

A complete report contains every required check exactly once with a pass/fail
outcome. A complete report with any failure is failed. Missing checks, an empty
report or any `not_evaluated` outcome remain incomplete. Missing checks are not
silently filled with passes. This validator checks consistency; it does not run
checks, select retries, change denominators or calculate a new research metric.

The isolated tasks retain their existing standalone verifier copies. The
standard-library contract mirrors its `Check`, protocol, required IDs and
`summarize` behavior. A parity test compares all 3^8 check-outcome combinations
against the actual standalone verifier definitions without importing optional
HTTP/database packages. A future protocol change must update both contracts and
keep their consistency test; existing runtime scoring is unchanged.

## Bound envelope

Read the expected binding independently through `PlanStore.artifact_bindings()`
first, which revalidates the underlying artifact and ledger. Supply an expected
verification request ID from trusted controller state, not from incoming evidence:

```python
from democratize_security.evidence import bind_report, encode_evidence, decode_evidence

record = bind_report(expected_binding, expected_request_id, trusted_synthetic_report)
data = encode_evidence(record, expected_binding, expected_request_id)
same_record = decode_evidence(data, expected_binding, expected_request_id)
```

The envelope uses schema version 1 and kind `offline_verifier_evidence`. It includes
the binding digest, verification request ID, attempt/campaign/trial/task identities,
verifier hash, artifact payload hash, raw object hash, protocol, complete supplied
report and an evidence digest. It does not store secrets, usage or cost. Returned
records are detached from caller-owned dictionaries.

`validate_evidence(record, expected_binding, expected_request_id)` recomputes the
report summary and envelope against independently supplied expectations. A changed
attempt, artifact, verifier, protocol or request cannot be made acceptable merely
by recomputing the evidence hash. Both the expected binding and the report are
structurally checked. These functions do not reread artifact files themselves;
callers must obtain/revalidate their expected binding from the store.

Serialization is canonical compact sorted finite JSON, bounded to 64 KiB. Decode
rejects duplicate keys, nonfinite numbers, oversized or noncanonical bytes, invalid
UTF-8 and malformed envelopes. It takes bytes only and performs no filesystem or
network access. A larger or changed protocol requires an explicit compatible
contract; it must not silently truncate check details.

## Trust and remaining integration

A valid envelope is **not authenticated evidence**. Someone able to replace an
entire report and recompute hashes can produce a different internally consistent
report for the same identities. A dedicated test preserves this limitation.
Do not accept candidate-authored reports or choose expected identities from the
same untrusted report. Caller trust, independent verifier execution and private
runtime provenance still have to be established by the future adapter.

These APIs perform no object publication, SQLite write, accounting transition,
result acceptance, candidate promotion or execution. Incomplete/failed reports
can be represented without turning them into success. Separate evidence-object
publication (#40) and store v4 linkage (#42) add durable storage and revalidation.
V5 requires prior verification intent for new evidence bindings; historical
evidence retains its original schema and cannot acquire retrospective intent.
Runtime authentication, accepted-result semantics and recovery remain future work.
Persisted observations remain offline synthetic records only.
