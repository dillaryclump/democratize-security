# Results: every model run so far

Updated 2026-11-15. This page records every run that sent a request to a model, with its counts, costs and deviations. It is a record of what was observed, not a claim that the security integration works.

## Summary

| Run | Date (UTC) | Source commit | Scheduled | Graded | Passed all checks | Settled cost (upper bound) |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| [Calibration](#calibration) | 2026-10-23 | `1f83ca6` | 6 | 6 | 6 | 27¢ |
| [Pilot](#pilot-interim-record-incomplete), incomplete | 2026-10-23 | `c05e58d` | 48 | 20 | 20 | 107¢ |

- **No difference between conditions has been observed.** Every graded pilot trial passed every check in all four conditions, including the `ordinary` baseline.
- **The pilot is incomplete.** One trial was interrupted and 27 never ran. It supports no comparison between conditions.
- **Total model spend recorded:** 134¢ settled, plus at most 13¢ committed to the interrupted trial. These are upper bounds and have not been reconciled against the provider bill.

## Terms

- **Graded:** the trial's sealed `app.py` was replayed in a fresh verifier and its report was admitted to the ledger through the authenticated path.
- **Joint success:** an admitted, complete report in which every required check passes. The checks cover both function (authorized requests work) and security (other tenants' data stays hidden and unchanged). Protocol `synthetic-reference-v3` has 8 checks and `synthetic-reference-v4` has 10.
- **Settled cost (upper bound):** each model request is priced with uncached input at the higher cache-write rate and rounded up to a whole cent. The real bill should be lower.
- **Condition:** what the agent was given. See [PILOT_PROTOCOL.md](PILOT_PROTOCOL.md).

## Model-free controls

Before any model run, the verifier itself is tested with reviewed controls. No model is involved.

Each of the 24 pilot variants runs three controls through the full container boundary: the reference solution (`oracle`), the unchanged starter (`nop`) and a reviewed vulnerable solution (`unsafe`). Each family's `full_tool` variant adds two controls that run the `check-isolation` self-check on the reference and on the unsafe solution. That makes 14 control trials per family and 84 in total. Each must produce exactly the per-check outcomes recorded in `src/democratize_security/pilot/controls/expected.json`, and each is audited against the host-observed container configuration.

All 84 were accepted and audited on the dedicated worker at `c05e58d` on 2026-10-23, directly before the pilot, after the full test suite passed there (1,429 tests, none skipped, with real PostgreSQL, Docker and Harbor). The same controls run in the CI job `pilot-controls` on every pull request and on every push to main.

**Not reproducible from source at present.** Some time between 2026-11-03 and 2026-11-15, Debian replaced the PostgreSQL package version that the `full_tool` agent image pins, and that image no longer builds. The `full_tool` controls last passed in CI on 2026-11-03 and fail as of 2026-11-15. The controls for the other three conditions still pass. See [#84](https://github.com/dillaryclump/democratize-security/issues/84).

This matters for reading the results below. The verifier does fail vulnerable code: every unsafe control fails at least one check, in the plain variants and in the variants protected by forced row-level security. A pass is therefore not an artifact of a verifier that passes everything.

## Calibration

**Purpose.** An engineering check that the metered transport, the two candidate models and the grading path work, and a measurement of real usage to size the pilot. It is not a comparison of conditions. All six trials used the same task setup, which ships security instructions and an RLS helper. Details are in [CALIBRATION.md](CALIBRATION.md).

**Setup.** Three public development tasks, once each with two models, medium reasoning, no retries and no repairs. Graded with protocol `synthetic-reference-v3`. The owner approved a $10 model-only cap for these six trials.

| Model | Task | Requests | Input tokens | Output tokens | Settled | Admitted result |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `gpt-6.1-sol` | invoice-read | 5 | 16,419 | 1,471 | 6¢ | pass, complete, 8 of 8 checks |
| `gpt-6.1-sol` | invoice-search | 4 | 11,835 | 1,426 | 5¢ | pass, complete, 8 of 8 checks |
| `gpt-6.1-sol` | invoice-export | 5 | 16,644 | 1,500 | 6¢ | pass, complete, 8 of 8 checks |
| `gpt-6-luna` | invoice-read | 3 | 6,639 | 868 | 3¢ | pass, complete, 8 of 8 checks |
| `gpt-6-luna` | invoice-search | 3 | 6,395 | 1,122 | 3¢ | pass, complete, 8 of 8 checks |
| `gpt-6-luna` | invoice-export | 4 | 10,617 | 1,143 | 4¢ | pass, complete, 8 of 8 checks |
| **Total** | | **24** | **68,549** | **7,530** | **27¢** | **6 of 6** |

- **Run time:** 10 minutes 30 seconds, from 15:47:11 to 15:57:41 UTC.
- **Unknown request outcomes:** none. Nothing is held in either campaign budget.
- **Earlier attempts:** two sessions stopped before sending any request, at 0¢. A job-naming rule was fixed in #71, and the worker helper correctly refused to reuse a dry-run job path.
- **Record:** the result was posted on [#57](https://github.com/dillaryclump/democratize-security/issues/57) the same day. The table above was regenerated from the ledger on 2026-11-15 and matches it.

**What it shows.** The pipeline ran six real agent trials end to end, and both models completed these three tasks. It shows nothing about whether the security integration helps, because every trial had the same setup.

## Pilot interim record (incomplete)

> **Status: interrupted and not resumed.** The pilot was pre-registered as 48 trials. The worker's virtual machine stopped 36 minutes into the batch. Twenty trials were graded, one was cut off mid-request and 27 never ran. This section reports all 48 scheduled trials as the protocol requires. Read it as a feasibility record, not as a result.

**Design.** Six scenario families × four conditions × two repetitions, on `gpt-6.1-sol` with medium reasoning, at most 12 model requests per trial, no retries and no repairs. Graded with protocol `synthetic-reference-v4`. The owner approved a $15 hard model-only cap. The protocol was frozen in [PILOT_PROTOCOL.md](PILOT_PROTOCOL.md) before the first request.

| Condition | Database | The agent gets |
| --- | --- | --- |
| `ordinary` | plain, no row-level security | the feature and the ownership requirement |
| `instructions` | plain | the same, plus explicit security guidance |
| `rls_starter` | protected by forced row-level security | the ownership requirement and an RLS-backed helper |
| `full_tool` | protected | the RLS helper, the security guidance and the `check-isolation` self-check |

### What happened

| Time (UTC, 2026-10-23) | Event |
| --- | --- |
| 18:14 to 19:11 | Pre-run gate on the worker at `c05e58d`, clean checkout: full suite passed, all 84 controls accepted, model-free dry run admitted a pass. |
| 19:11:23 | Live batch started. Trials ran one at a time in the pre-registered shuffled order. |
| 19:11 to 19:47 | Trials 1 to 20 graded and settled. All 20 passed all 10 checks. |
| 19:47:13 | Trial 21 (`invoice-create`, `instructions`) started. Three model requests settled at 1¢ each. |
| 19:47:43 | Trial 21's fourth model request was reserved (10¢). This is the last ledger event. Whether the request reached the provider is unknown. |
| after 19:47:43 | The worker's WSL2 virtual machine stopped. The cause was not recorded. The session never reached its report or cleanup steps. |

Nothing was written to the ledger afterwards. On 2026-11-15 the ledger was copied, and the report below was generated from the copy with the committed `scripts/pilot_report.py` at `c05e58d`. The original was not opened for writing; its SHA-256 was the same before and after.

The order in which the 21 trials were dispatched matches the order regenerated from the protocol's seed, `random.Random(20261023)`. The three trials of the first repetition that never started were the last three in that order.

### Report, as generated

```text
48 scheduled, 20 joint successes, 27 not run, 1 incomplete, 0 invalid; 107 cents settled (upper bound).
```

Joint success by family and condition (successes / scheduled):

| Family | ordinary | instructions | rls_starter | full_tool |
| --- | ---: | ---: | ---: | ---: |
| invoice-read | 1/2 | 1/2 | 1/2 | 1/2 |
| invoice-search | 1/2 | 1/2 | 0/2 | 1/2 |
| invoice-export | 0/2 | 1/2 | 1/2 | 1/2 |
| invoice-update | 1/2 | 1/2 | 1/2 | 1/2 |
| invoice-create | 1/2 | 0/2 | 1/2 | 1/2 |
| invoice-summary | 1/2 | 1/2 | 1/2 | 0/2 |

Every `0/2` cell is a trial that did not run or was interrupted. No graded trial failed.

By condition:

| Condition | Joint success | Isolation failures | Function failures | Incomplete | Invalid | Not run | Cents |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ordinary | 5/12 | 0 | 0 | 0 | 0 | 7 | 29 |
| instructions | 5/12 | 0 | 0 | 1 | 0 | 6 | 27 |
| rls_starter | 5/12 | 0 | 0 | 0 | 0 | 7 | 26 |
| full_tool | 5/12 | 0 | 0 | 0 | 0 | 7 | 25 |

Check pass counts by condition (graded trials, 5 per condition):

| Check | ordinary | instructions | rls_starter | full_tool |
| --- | ---: | ---: | ---: | ---: |
| fixture_configuration | 5 | 5 | 5 | 5 |
| authorized_reads | 5 | 5 | 5 | 5 |
| foreign_reads | 5 | 5 | 5 | 5 |
| list_search | 5 | 5 | 5 | 5 |
| exports | 5 | 5 | 5 | 5 |
| identity | 5 | 5 | 5 | 5 |
| spoofing | 5 | 5 | 5 | 5 |
| tenant_switching | 5 | 5 | 5 | 5 |
| aggregates | 5 | 5 | 5 | 5 |
| writes | 5 | 5 | 5 | 5 |

Usage by condition (graded trials):

| Condition | Trials | Requests | Input tokens | Output tokens | Settled |
| --- | ---: | ---: | ---: | ---: | ---: |
| ordinary | 5 | 24 | 86,280 | 6,934 | 29¢ |
| instructions | 5 | 23 | 85,061 | 7,568 | 27¢ |
| rls_starter | 5 | 22 | 73,365 | 5,681 | 26¢ |
| full_tool | 5 | 25 | 77,144 | 3,664 | 25¢ |
| **Total** | **20** | **94** | **321,850** | **23,847** | **107¢** |

### Every scheduled trial

First repetition, 24 trials. "Run" is the order in which the trial was dispatched.

| Family | Condition | Run | Status | Requests | Input tokens | Output tokens | Settled | Checks passed |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| invoice-read | ordinary | 17 | graded, pass | 5 | 17,900 | 1,345 | 6¢ | 10/10 |
| invoice-read | instructions | 15 | graded, pass | 4 | 14,307 | 1,511 | 5¢ | 10/10 |
| invoice-read | rls_starter | 6 | graded, pass | 4 | 11,213 | 646 | 4¢ | 10/10 |
| invoice-read | full_tool | 12 | graded, pass | 5 | 15,306 | 686 | 5¢ | 10/10 |
| invoice-search | ordinary | 11 | graded, pass | 5 | 18,729 | 1,498 | 6¢ | 10/10 |
| invoice-search | instructions | 10 | graded, pass | 5 | 16,858 | 1,464 | 5¢ | 10/10 |
| invoice-search | rls_starter | | not run | | | | | |
| invoice-search | full_tool | 19 | graded, pass | 5 | 15,076 | 713 | 5¢ | 10/10 |
| invoice-export | ordinary | | not run | | | | | |
| invoice-export | instructions | 2 | graded, pass | 4 | 13,563 | 1,335 | 5¢ | 10/10 |
| invoice-export | rls_starter | 9 | graded, pass | 5 | 20,027 | 1,911 | 7¢ | 10/10 |
| invoice-export | full_tool | 20 | graded, pass | 5 | 15,289 | 721 | 5¢ | 10/10 |
| invoice-update | ordinary | 3 | graded, pass | 5 | 17,706 | 1,276 | 6¢ | 10/10 |
| invoice-update | instructions | 16 | graded, pass | 5 | 20,957 | 1,807 | 6¢ | 10/10 |
| invoice-update | rls_starter | 1 | graded, pass | 5 | 17,930 | 1,390 | 6¢ | 10/10 |
| invoice-update | full_tool | 14 | graded, pass | 5 | 16,070 | 865 | 5¢ | 10/10 |
| invoice-create | ordinary | 5 | graded, pass | 5 | 19,070 | 1,566 | 6¢ | 10/10 |
| invoice-create | instructions | 21 | **interrupted** | 3 settled, 1 open | | | not settled | not graded |
| invoice-create | rls_starter | 7 | graded, pass | 4 | 12,905 | 1,143 | 5¢ | 10/10 |
| invoice-create | full_tool | 18 | graded, pass | 5 | 15,403 | 679 | 5¢ | 10/10 |
| invoice-summary | ordinary | 4 | graded, pass | 4 | 12,875 | 1,249 | 5¢ | 10/10 |
| invoice-summary | instructions | 13 | graded, pass | 5 | 19,376 | 1,451 | 6¢ | 10/10 |
| invoice-summary | rls_starter | 8 | graded, pass | 4 | 11,290 | 591 | 4¢ | 10/10 |
| invoice-summary | full_tool | | not run | | | | | |

Second repetition, 24 trials: **none ran.**

### Deviations from the pre-registered protocol

1. **The batch ended for a reason that is not a stop rule.** The protocol stops on an unknown model-request outcome, an integrity error or an exhausted budget. This batch ended because the worker's virtual machine stopped.
2. **One trial is still open in the ledger.** `pilot-invoice-create-instructions-r1` is in phase `running` with a request whose outcome is unknown. Its 101¢ trial reservation is still held. It has not been reconciled. The report counts it as incomplete, which is a non-success.
3. **The report was produced 23 days late, from a copy.** The protocol expects the report at the end of the batch.
4. **Costs are not reconciled.** The settled figures are upper bounds. They have not been compared with the provider bill, and the interrupted trial's fourth request may or may not have been billed.
5. **The second repetition did not run.** If it runs later, it will be separated from the first by weeks, and the model behind the `gpt-6.1-sol` name may have changed in between. Any such run must be reported as a deviation, not pooled silently.

### What can and cannot be concluded

**Supported by this record:**

- The pipeline works with a real model. Twenty trials went from task to sealed artifact to independent grade to settled cost, at about 5¢ and under two minutes each, with no unknown request outcome before the interruption.
- In the graded trials, `gpt-6.1-sol` produced an endpoint that passed all 10 checks every time, in every condition.

**Not supported:**

- **Any difference between conditions.** There is none in this data. All four conditions are at the ceiling.
- **That the integration helps.** The `ordinary` baseline matched the full integration on every graded trial.
- **That AI-written code is safe.** These are small, public, single-endpoint tasks on synthetic data with one model.
- **Any rate.** Five graded trials per condition, from one repetition, estimate nothing with useful precision.

**Observations that may explain the ceiling. None has been tested:**

- Each starter already contains the five sibling endpoints, written correctly for its condition. An agent can add the sixth by analogy.
- Every condition states the ownership requirement, as the research protocol requires of the baseline.
- The tasks are small, and one capable model was used.
- In three of the five families where both protected conditions were graded (`invoice-read`, `invoice-create` and `invoice-export`), the `rls_starter` and `full_tool` trials produced byte-identical `app.py` files. The 20 graded trials yielded 17 distinct sealed artifacts. Whether the agent ran the self-check in the `full_tool` trials has not been analysed.

The [roadmap](ROADMAP.md) anticipated a weaker form of this case: if a correctly configured RLS starter matches the full tool, investigate simpler packaging, diagnostics or maintenance value before broadening scope. Here the plain baseline matched as well. A neutral or negative experiment is a valid result.

### What remains before this pilot can be closed

These are owner decisions, and none has been taken:

1. Reconcile the interrupted trial in the ledger. Its open request must be resolved as unknown, which blocks the campaign budget until a human releases it.
2. Either close the pilot as reported here, or run the remaining 27 trials as a declared deviation. The $15 cap covers the remainder.
3. Reconcile the settled costs against the provider bill.
4. Decide whether the task set needs harder scenarios before another comparison is worth its cost.
5. If the pilot is resumed, first make the `full_tool` agent image buildable again ([#84](https://github.com/dillaryclump/democratize-security/issues/84)). Any fix changes the digests of the six `full_tool` task trees, which the campaign froze, so the remaining `full_tool` trials would run a task that differs from the one already graded. That is a further deviation and must be reported as one.

## Provenance

| Item | Value |
| --- | --- |
| Worker | Dedicated WSL2 distribution `ds-worker`, Ubuntu 24.04, Docker Engine 29.9.1, cgroup v2, one 64 MiB filesystem per Harbor job ([WORKER_HOST.md](WORKER_HOST.md)) |
| Calibration ledger | SHA-256 `6708f8336675171e2df46bfc44378c53597a319117598c4641538f5fdc7e4fe8`, source `1f83ca6` |
| Pilot ledger | SHA-256 `dc9e8f6cf079056af277cb6ec5230b7022c90bb9e266be2f9fd0cfc7083d19c4`, source `c05e58d`, one controller generation, no restore fence |
| Pilot campaign | `campaigns/pilot.v1.json`, 48 trials, cap 1500¢, hold 101¢ per trial |
| Sealed artifacts | 17 distinct `app.py` bundles for the 20 graded pilot trials, in the worker's object store |
| Report script | `scripts/pilot_report.py` at `c05e58d`, run on a copy of the ledger on 2026-11-15 |

The ledgers and sealed artifacts are kept on the worker. They are not published in this repository. The per-trial Harbor job directories from the live pilot session were not archived, because the session ended before its cleanup step, and their state has not been inspected.

To regenerate the pilot tables from a ledger:

```bash
uv run --locked python scripts/pilot_report.py LEDGER_DIR OUTPUT.md
```

Run it on a copy. Opening a ledger registers a controller generation, which is a write.

## Limitations stated before the pilot

These were written into the protocol before the first trial and still apply:

- All tasks and the verifier are public. There is no protected holdout, and results cannot speak for unseen task families.
- The tasks, instructions and verifier come from the same author, and the self-check reuses the verifier's probes on different data.
- One model with fixed settings. Provider-side variation is not controlled.
- Settled costs are upper bounds.
