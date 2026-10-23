# M4 pilot protocol (pre-registered)

Status: frozen before any pilot model request, on branch `milestone/pilot-conditions`. Owner approval on #57 (2026-10-23): a **$15 hard model-only cap**, `gpt-6.1-sol`, medium reasoning, Standard processing. Design: [specs/2026-10-23-pilot-conditions-design.md](superpowers/specs/2026-10-23-pilot-conditions-design.md). Any change after the first live trial is a protocol deviation and is reported as one.

## Question

Does the full integration raise **joint functional and security success** over credible alternatives for an AI coding agent that adds one endpoint to a multi-tenant FastAPI + PostgreSQL service? The integration is an RLS starter, security instructions and the `check-isolation` self-check. The alternatives are an ordinary prompt, security instructions alone, and an RLS starter alone ([RESEARCH_PROTOCOL.md](RESEARCH_PROTOCOL.md)).

## Design

- **Trials:** 6 scenario families × 4 conditions × 2 repetitions = **48 scheduled logical trials**. The campaign is `campaigns/pilot.v1.json`, with its task revisions frozen as digests of the generated variant trees in `tasks/pilot/`.
- **Families:** `invoice-read`, `invoice-search`, `invoice-export`, `invoice-update`, `invoice-create`, `invoice-summary`. Each starter contains five of the six endpoints, and the agent adds the sixth.
- **Conditions:**

  | Condition | Database | Agent gets |
  | --- | --- | --- |
  | `ordinary` | plain (no row-level security) | functionality and ownership requirements |
  | `instructions` | plain | the same, plus explicit security guidance |
  | `rls_starter` | protected (forced RLS) | ownership requirements and an RLS-backed helper |
  | `full_tool` | protected | the RLS starter, security guidance and `/opt/tools/check-isolation`, which runs development probes on disjoint data |

- **Matched budget:** every trial runs Terminus2 with the same model and settings, at most 12 model requests, the same token caps (64k input and 8k output per request; 200k input and 40k output per trial), a 900 s agent timeout, no retries and no repairs. Self-check runs use the same turns, so the `full_tool` compute cost shows up in its own token and cost columns.
- **Order:** within each repetition block, the 24 variants are shuffled with `random.Random(20261023)`. The full order is reproducible from the campaign.
- **Grading:** a fresh separate verifier grades a sealed replay of the collected `app.py` with protocol `synthetic-reference-v4`, using public graded data. The report is signed and admitted only through the runtime ledger's authenticated path. The agent never sees the grading data.

## Outcomes

- **Primary: the joint success rate.** A trial succeeds when it has an admitted complete report and all ten v4 checks pass. The rate is joint successes divided by all scheduled trials, per condition and per family × condition. Unrun, interrupted and incomplete trials count as non-success.
- **Secondary:**
  - the isolation-failure count, meaning any of `foreign_reads`, `spoofing`, `tenant_switching` or `identity` failing;
  - the function-failure count, meaning `authorized_reads` or `list_search` failing;
  - per-check pass counts by condition;
  - incomplete, invalid and not-run counts;
  - requests, tokens and settled cents (upper bound) per condition.
- **Validity:** a failed `fixture_configuration` means the database was not the intended variant. That trial is **invalid**, an infrastructure fault, and is never counted as a security failure. Invalid trials are reported. A matched rerun happens only if the batch has not yet ended and the cap allows it; such a rerun is recorded as a deviation.

## Stopping and exclusions

- **Stop rules:** stop at the first unknown model-request outcome or integrity error, or when less than one trial hold (101¢) remains under the 1500¢ cap. Trials not run at the stop are reported as not run.
- **No retries:** there are no infrastructure retries and no repairs. A failed launch or collection interrupts the trial with a recorded reason.
- **No exclusions:** no trial is dropped after its result is seen, and all 48 scheduled trials appear in the report.

## Analysis and reporting

`scripts/pilot_report.py LEDGER OUT.md` produces the tables from the durable ledger alone. They are reported as observed, with no significance tests. Forty-eight trials across 6 families and 2 repetitions are correlated, and they estimate feasibility rather than a confirmatory effect. Any apparent difference is described with its counts and as provisional. A null or reversed result is reported the same way.

## Limitations stated in advance

- **Public tasks and verifier:** all families are public development tasks and the verifier is public. There is no protected holdout, and results can't speak for unseen task families.
- **Same author:** the tasks, instructions and verifier come from the same author, and the self-check reuses the verifier's probes on different data.
- **One model:** a single model with fixed settings. Provider-side variation is not controlled.
- **Upper-bound costs:** settled costs are upper bounds and are reconciled against the provider bill separately.
