# Research protocol

This is the planned protocol, not a record of executed experiments. Freeze a campaign-specific revision before measurements.

## Question and controls

Does the full integration increase joint functional/security success or provide a demonstrable maintenance/cost advantage over credible existing protection?

| Condition | Intervention |
| --- | --- |
| `ordinary` | Ordinary coding agent, with intended functionality and ownership requirements stated |
| `instructions` | Same task plus explicit security instructions |
| `rls_starter` | Correctly configured existing PostgreSQL RLS starter |
| `full_tool` | Full integration and verifier-feedback workflow |

Match model configuration, task families, generation/repair budgets and intended requirements. Record differing tools, prompts and templates. If full-tool feedback needs extra compute, report it and add a matched-budget analysis where feasible. Separate research-search spend from product-use spend.

## Sequence and splits

First validate three public development tasks end to end. Later run six scenario families, two repetitions and four conditions: 48 logical trials. The three example records currently committed are planning placeholders, not implemented benchmark tasks.

Partition at scenario-family level. Related variants stay in one split. Development feedback can guide changes; selection data chooses candidates but becomes development data under repeated feedback; final cases stay inaccessible until candidate and protocol freeze. If final failures guide edits, classify that evaluation as exploratory and use new final cases for a confirmatory claim.

The six-family pilot estimates feasibility. Repetitions do not create new independent scenario families. Report per-family outcomes and broad uncertainty. Predefine meaningful effect sizes and a later study design using observed variation; do not invent significance from 48 correlated trials.

## Measurements

Primary operational rate = scheduled logical trials with functionality pass, security pass and complete required coverage / all scheduled logical trials. Incomplete trials count as non-success in this rate and are reported separately. Distinguish checks `pass`, `fail`, `not_evaluated`. A run that never reaches security evaluation cannot be called secure.

Also report functionality, exposure, false blocking, coverage, setup effort, latency, manual interventions, token usage and cost. Unknown cost is null/unknown, never zero. Any completed-only analysis explicitly lists exclusions. Apply infrastructure exclusion rules before inspecting which condition benefits; rerun matched blocks or state insufficient evidence when failures change conclusions.

Official benchmark scores are separate metrics governed by the benchmark's own rules. Pin original task/scorer revisions, preserve provenance and log transformations. Modified tasks are adapted evaluations. Audit BaxBench task fit instead of assuming every task exercises tenant isolation. LSCBench and generated challenges are later additions.

## Integrity and stopping

- Keep every scheduled trial, failure, rejected candidate and retry, linked to immutable inputs.
- Infrastructure: at most one declared transient retry. Generation repairs consume the declared model budget; no hidden retries.
- Search: manually specified intervention first. GEPA comes after valid measurement; initial automated search at most five candidates, one active trial, development feedback only.
- Freeze editable paths and patch limits. Candidate code cannot rewrite scoring or authoritative tests.
- Reserve worst-case cost before dispatch, reconcile afterward and enforce external provider limits where available. Missing prices or unbounded calls block unattended dispatch.
- Stop for budget exhaustion, repeated infrastructure failure or integrity violation. A score increase only nominates a candidate; it cannot automatically promote it.

## Evidence and release

Retain campaign/trial/candidate IDs, source/task/scorer revisions, hashes of exact artifacts, model alias or pinned version and date, full settings, prompts, seeds where supported, image digests, resource budgets, all verdicts, sanitized traces and measured usage. Seeds alone do not ensure model reproducibility. Hashes bind evidence to bytes; they do not prove an evaluator is honest.

Promotion requires frozen security gates, no material functionality regression, a confirmed benefit or documented cost/usability advantage, and human review. Public claims include scope, denominators, uncertainty, costs, reproduction commands and known failures. Publish only sanitized approved evidence. Preserve a fresh protected evaluation pool for future work.
