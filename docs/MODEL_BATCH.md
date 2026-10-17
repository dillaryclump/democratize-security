# Model batch proposal and exact offline costs

Status: **unapproved proposal, execution disabled**, issue #57. Sources fetched
2026-10-17. No model, token-count, account or provider API request was made.
The implementation estimates costs and validates finite proposals; it does not
reserve funds, authenticate usage, dispatch agents or authorize execution.

## Recommendation

Use **`gpt-6.1-sol`, medium reasoning, Standard processing** as the default.
The [official current model guide](https://developers.openai.com/api/docs/guides/latest-model)
positions Sol for complex coding at lower cost than Astra. Include a small
`gpt-6-luna`, medium arm to find out whether the cheaper model is sufficient for
these focused tasks. This is a hypothesis to measure, not a performance claim.
Freeze one model/settings tuple before the four-condition study; do not switch
models or escalate reasoning selectively after observing failures.

The proposed first batch is **six development calibration trials**: read,
list/search and CSV once with each model, one active trial, zero repairs and zero
automatic retries. These three public tasks already provide an RLS helper and
security instructions. They establish transport/functionality and measured usage,
not the `ordinary` versus `instructions` versus `rls_starter` versus `full_tool`
comparison. If both arms reach the ceiling, build the prespecified scenario
families and meaningful matched interventions; do not weaken functionality or
select failures to manufacture an effect. If Luna hits a floor, inspect whether
the cause is model capability, the harness, or a binding token/time limit.

Sonnet 5.5 is a plausible later independent-provider replication at the same
listed input/output rates as Sol. That requires its own tested adapter and frozen
configuration. Astra and Opus are more expensive alternatives; no need to add
either to the first engineering batch. Account access and actual model
availability have not been checked. Official Sol documentation currently names
`gpt-6.1-sol`; no dated snapshot ID is invented. Record the requested and returned
model IDs, settings, date, exact prompts and provider request/response IDs.

## Verified public rates

USD per million tokens, Standard/global processing. The snapshot stores integer
micro-USD per million tokens; calculations use exact rational dollars.

| Model | Ordinary input | Cache read | Cache write | Output |
| --- | ---: | ---: | ---: | ---: |
| [GPT-6.1 Sol](https://developers.openai.com/api/docs/models/gpt-6.1-sol) | 2.00 | 0.10 | 2.50 | 10.00 |
| [GPT-6 Luna](https://developers.openai.com/api/docs/models/gpt-6-luna) | 0.10 | 0.01 | 0.125 | 0.50 |
| [GPT-6 Astra](https://developers.openai.com/api/docs/models/gpt-6-astra) | 10.00 | 1.00 | 12.50 | 50.00 |
| [Claude Sonnet 5.5](https://platform.claude.com/docs/en/models/sonnet-5-5/overview) | 2.00 | 0.10 | 2.50 | 10.00 |
| [Claude Opus 5.5](https://platform.claude.com/docs/en/models/opus-5-5/overview) | 4.00 | 0.20 | 5.00 | 20.00 |
| [Claude Haiku 5.5](https://platform.claude.com/docs/en/models/haiku-5-5/overview) | 0.10 | 0.01 | 0.125 | 0.50 |

OpenAI rows apply only through 272,000 input tokens per request. Haiku's row
applies only through 100,000. Claude cache writes above are the five-minute
option; its one-hour writes cost more and are not supported by this snapshot.
No long-context premium, regional processing, Fast/Ultrafast, Batch/Flex,
hosted tools, infrastructure, tax or negotiated pricing is included. Recheck
rates and account settings before freezing an execution authorization.

[OpenAI reasoning](https://developers.openai.com/api/docs/guides/reasoning) and
[Claude thinking](https://platform.claude.com/docs/en/build-with-claude/thinking-steering-and-cost)
consume billed output. Output limits and estimates here include those tokens and
non-visible formatting; do not add reasoning charges a second time. Input
totals include cached and cache-write tokens. Actual token cost is:

```text
ordinary = total_input - cache_read - cache_write
cost = (ordinary * input_rate + cache_read * read_rate
        + cache_write * write_rate + total_output * output_rate) / 1,000,000
```

Cache-write prices replace ordinary input prices for those tokens; the estimator
does not charge both. For pessimistic quotes, every input token uses the highest
of the verified input/read/write rates. No cache-hit savings are assumed.

## Six-trial proposal

The [proposal](../campaigns/proposals/calibration.v1.json) binds the exact canonical
[pricing snapshot](../campaigns/proposals/pricing.2026-10-17.v1.json).
Task names remain unresolved labels, with explicit unmet execution requirements.
This format is deliberately different from a resolved campaign; passing its
validation never creates a runnable campaign or clears a milestone gate.

| Per logical trial | Proposed ceiling |
| --- | ---: |
| Model-generation requests, including all retries/repairs/auxiliary model calls | 12 |
| Full actual input per request, including history/tool/formatting overhead | 64,000 tokens |
| Output per request, including reasoning | 25,000 tokens |
| Cumulative billed input across every request | 500,000 tokens |
| Cumulative output across every request | 100,000 tokens |
| Agent / verifier deadline | 900 / 300 seconds |
| Infrastructure retries / feedback repairs | 0 / 0 |

One token-count preflight per generation request permits at most 12 generation
plus 12 token-count API contacts. Both need the separately approved execution
context. Disable client retries for both; an extra model request always consumes
the generation count. A timeout does not prove that generation stopped. A
separate outer deadline must bound setup, collection and cleanup as well.

The agent plus verifier caps allow 20 minutes of phase time per trial: up to
two hours for six trials, or 16 hours for 48, before setup/build, collection and
cleanup. Those outer phases are not yet bounded by this estimator or measured
for model-generated runs. Recommend a future 30-minute whole-trial deadline and
three-hour/six-trial or 24-hour/48-trial batch deadline, subject to a tested
adapter. These are proposed limits, not current enforcement or throughput
predictions. Use the first batch to measure actual durations and re-estimate.

Illustrative cumulative usage assumptions, charging all input at the cache-write
rate rather than predicting cache hits:

| Per-trial assumption | Six-trial token cost |
| --- | ---: |
| 50,000 input + 10,000 output | $0.70875 |
| 150,000 input + 30,000 output | $2.12625 |
| Every per-trial cumulative ceiling | $7.0875 |

Propose a **$10 model-only cap**, unapproved. At the token ceilings, each Sol
trial costs at most $2.25 and each Luna trial $0.1125. A future cents-based
ledger must round each reservation/settlement upward, not truncate. For at most
12 calls, a safe per-trial allowance is `ceil(exact ceiling in cents) + 11`:
236 cents per Sol trial and 23 per Luna trial, or **$7.77** for six. This is
rounding headroom, not additional predicted provider charges. Future infrastructure
and any separately priced API operation require separate approved limits.
Local offline preparation incurs no model or cloud charges. Dedicated worker
provisioning is deferred; its actual infrastructure cost remains unknown and is
not covered by these model-only figures.

Run the offline estimator:

```bash
uv run --locked python -m democratize_security.model_budget \
  campaigns/proposals/calibration.v1.json \
  campaigns/proposals/pricing.2026-10-17.v1.json
```

Its result includes exact scenario totals, the conditional token ceiling,
cents-reservation allowance, snapshot/proposal hashes, unresolved requirements
and `execution_enabled: false`. `quote_next_request` also rejects an exact
full-payload preflight that exceeds the per-request, cumulative, request-count
or remaining-money bounds. It is a pure quotation, not a durable reservation.

## Later 48-trial pilot

The planned six families x two repetitions x four conditions still needs six
implemented families and distinct matched interventions. At the same cumulative
limits with Sol in all 48 trials, the light/working assumptions are **$10.80 /
$32.40**; the conditional token ceiling is **$108**, and a safe cents-based
per-call reserve allowance is **$113.28**. A **$125 model-only cap** is a proposal,
not approval or a performance forecast. One declared repair and at most one
infrastructure retry, if later approved, must consume the same cumulative tokens,
calls and money per logical trial; otherwise recompute the estimate. An unknown
request outcome halts dispatch and retains its hold.

Use calibration's measured usage and failure causes to re-estimate before
approving that pilot. A second complete 48-trial model comparison is another
batch with another budget; it is not included here.

## Concrete transport integration contract

The core module imports stdlib and project contracts only. Provider code belongs
in a narrow adapter. For an initial OpenAI transport, implement synchronous
Responses calls on Standard processing, with only text and reviewed local
terminal actions; no hosted tools, streaming/background jobs, fallback providers
or asynchronous extra generation. The
[official per-run spending-controller example](https://developers.openai.com/cookbook/articles/per_run_spending_controller_responses_api)
supports preflight/reserve/settle with retries disabled and unknown-charge holds.
Its example prices are fictional; use the versioned prices above instead.

1. Resolve approved source/task/scorer/prompt/image hashes and acquire current
   fenced controller ownership. A saved proposal cannot provide that authority.
2. Freeze the exact final request, model, tier and output cap. Use the
   [input-count endpoint](https://developers.openai.com/api/docs/guides/token-counting)
   on that complete payload, including history, instructions, tools, formatting
   and provider context. Local `characters / 4` estimates cannot enforce a cap.
   Rewriting the payload after preflight invalidates the quote.
3. Atomically persist stable request intent and a pessimistic reservation before
   submitting. Check cumulative money, model requests and tokens, including
   outstanding/ambiguous maxima. No process-local counter alone survives a crash.
4. Send once with all automatic retries disabled. Keep the provider credential
   in the trusted host transport. Harbor's candidate stays non-root,
   `network_mode: none`, without provider keys, controller paths or Docker socket.
5. Bind sanitized raw usage to that request; require the expected model/tier and
   all inclusive input, cached, cache-write and output counts. Missing/invalid
   data remains unknown. Settle exact costs or upward-rounded cents; never turn
   missing prices or usage into zero. Incomplete output is not a successful
   generation. A lost response retains its reservation and stops new dispatch.
6. Seal/verify through the existing trusted collector and fresh verifier, then
   admit only authenticated, fully bound results. Reconcile provider costs with
   retained usage separately; do not accept candidate-written costs or grades.

[Provider hard limits](https://developers.openai.com/api/docs/guides/spend-limits)
are an additional backstop; enforcement may lag. Alerts do not stop traffic.
The local durable reservation is what decides whether the next request fits.

## Pinned Harbor findings and remaining work

The Harbor 0.24.0 sdist was downloaded without installing or executing it and
verified against `uv.lock` SHA-256
`6c5185e6a76abc677ed3f95e688dc0dbf8597e4fa50847cb9a37a4448c91b1e5`.
The inspected source establishes:

- `agents/terminus_2/terminus_2.py`: `use_responses_api` exists; `max_turns`
  defaults to 1,000,000, summarization is enabled, and `_query_llm` retries three
  times. Auxiliary summaries can make additional model calls.
- `llms/lite_llm.py`: `call` also retries three times; Responses supports an
  explicit `max_output_tokens` via call kwargs. `_extract_cost` substitutes 0.0
  when unknown, and Responses extraction hardcodes cached tokens to zero.
  Those values cannot be authoritative cost reconciliation.
- `agents/terminus_2/tmux_session.py`: missing tmux/recording tools trigger root
  installation attempts. Current task images contain no tmux. Build reviewed
  tools into a versioned agent image; retain the read-only root and no-network
  candidate policy. Add a model-free stub-transport conformance trial and rerun
  the collector/storage/replay audits before any real request.

[GPT-6.1 Sol](https://developers.openai.com/api/docs/models/gpt-6.1-sol) requires
Responses for tool calling. `use_responses_api=true`, bounded turns and disabled
summarization are useful adapter settings, but flags alone cannot bound nested
retries or authenticate usage. The trusted metered transport must intercept every
forwarded generation request, or the adapter must call it directly. Do not widen
the candidate network to run an in-container authenticated coding CLI.

Still unimplemented here: live transport, durable per-model-request intent and
reservations, controller/runtime wiring, authenticated accepted-result lifecycle,
verified backup integration and worker acceptance. The offline estimator and
current public oracle are not independent final-study evidence.
