# Harbor separate-verifier integration spike

Harbor **0.24.0** is locked in the optional `harbor` dependency group. Core runtime
imports remain independent of Harbor. This milestone exercises one public,
declarative PostgreSQL RLS policy task with two reviewed controls, not model calls.
It does **not** satisfy the M2 requirement for three application development tasks;
those are in [APPLICATION_TASKS.md](APPLICATION_TASKS.md).

## Reproduce

On a disposable Linux machine with Docker and Compose:

```bash
uv sync --locked --group harbor
uv run --locked --group harbor python scripts/harbor_spike.py
```

The command runs exactly one `oracle` and one `nop` trial, sequentially, with no
retries. Each Harbor subprocess has a 600-second deadline. Existing
`.research/harbor-spike` outputs cause refusal; preserve them and use a fresh
checkout for replay. CI job `harbor-spike` runs these controls on a hosted runner.

## Boundary and grading

1. Agent image contains an unsafe `policy.json` and public instructions. The
   oracle replaces it with a reviewed solution; nop preserves the unsafe policy.
2. Harbor collects `/candidate/policy.json` and transfers it into a **separate**
   verifier environment. The verifier image is built from `tests/`; its source
   is absent from the agent image (also checked by the oracle script).
3. The verifier parses a bounded regular JSON file, rejects duplicate fields and
   unknown options, and maps three fixed predicate choices to trusted SQL. No
   candidate Python, shell or SQL is executed.
4. A fresh PostgreSQL 17 cluster has two tenants and a non-owner, non-superuser,
   non-bypass runtime role. Checks require exact authorized rows for both tenants,
   no rows with missing context, and enabled RLS. Database errors emit no reward.
5. Host acceptance requires exactly one finished trial per control, no Harbor
   exception, separate mode, the expected reward and complete check evidence.
   It seals the collected file using the existing artifact module and checks
   its SHA-256 against the verifier's input hash. Evidence must carry an HMAC
   under a fresh per-run nonce that only the separate verifier receives, and
   any `reward.json` is rejected. Missing or mismatched evidence fails the job. The summary deliberately uses `security_verdict: not_evaluated`:
   it is infrastructure evidence, not an application security result.

Task configuration sets both environments to `no-network`, one CPU, bounded RAM
and storage requests, and agent/verifier timeouts. Reviewed compose files then
harden both containers: `network_mode: none`, non-root users, dropped
capabilities, `no-new-privileges`, PID and swap limits and read-only roots. The
verifier runs PostgreSQL as `postgres` without `runuser`. See
[HARBOR_AUDIT.md](HARBOR_AUDIT.md) for the configuration and its live audit.
Docker build stages need network access for images and apt; runtime network
policy is a separate setting.

## Limits and next task

This is a reviewed-data smoke test, **not approval for hostile candidates**.
Harbor's artifact collection and conventional `/logs/artifacts` transfer are not
our hardened allowlist boundary. Host sealing happens after Harbor verification;
the original spike alone does not enforce sealed-only replay. The follow-up
[sealed policy replay](SEALED_REPLAY.md) now verifies fresh tasks constructed from
those pre-existing bundles. Base images are now digest-pinned, but apt packages
remain mutable, even though Harbor/Python dependencies are locked. The
[boundary audit](HARBOR_AUDIT.md) found that Harbor's `no-network` still permitted
DNS and ICMP and that its containers ran as root. The task's reviewed compose
hardening now closes those gaps. Harbor's `storage_mb` requests are still not
enforced; container storage is instead bounded directly (audit v5), while the
trial directory still needs a bounded filesystem on the worker host.
The spike has no recovery controller, adversarial containment proof, private tests,
production identity, or independent application HTTP assessment. A killed host
process may require container cleanup; use disposable runners.

Next: retain the sealed policy replay regression and the v5 boundary audit. The
read/list/export application tasks now run under the hardened layout with the
independent HTTP/database verifier; see APPLICATION_TASKS.md for their
fresh-replay evidence. Every task now collects its artifact through a trusted
collector (HARBOR_AUDIT.md, Trusted artifact collection). Establish the
dedicated-host policy before model execution. Do not infer M2
completion from an oracle reward of 1.

Pinned upstream contracts:
- [Task configuration](https://github.com/harbor-framework/harbor/blob/v0.24.0/src/harbor/models/task/config.py)
- [Separate verification lifecycle](https://github.com/harbor-framework/harbor/blob/v0.24.0/src/harbor/trial/trial.py)
- [Artifact transfer](https://github.com/harbor-framework/harbor/blob/v0.24.0/src/harbor/trial/artifact_handler.py)

## Validation

Local Python 3.12 with optional dependencies: 81 passed, 19 infrastructure tests
skipped. Core-only locked environment: 74 passed, 20 skipped. Ruff checks and
package build passed. Harbor's pinned schema successfully loads the task.

[CI run 38577845657](https://github.com/dillaryclump/democratize-security/actions/runs/38577845657)
at code revision `df8eefcb4f1f6b0f157ca44553f41db0c49a6621` passed all five jobs:
Python 3.12/3.13, PostgreSQL (93 passed, 7 Docker-only skipped), worker probe
(all 7 container cases), and Harbor. Each Harbor control had one trial and zero
exceptions. Oracle passed all four policy checks; nop failed all four. Host
acceptance verified separate mode, complete evidence and matching artifact bytes.

| Control | Reward | Sealed bundle SHA-256 |
| --- | --- | --- |
| oracle | 1 | `6fb653ffa01b9d9a31bcfe1b3979c04ed77eb07f3086acd50fa63ce445207ae1` |
| nop | 0 | `34da710db241f00b4af2b93c64e6a1a3a4a06e04775695ed927e9b659bc8b574` |

These are public infrastructure control results, not benchmark measurements.
The checked summaries are in CI logs; raw trial directories are ephemeral on the
hosted runner. Durable campaign evidence storage remains M3 work.
