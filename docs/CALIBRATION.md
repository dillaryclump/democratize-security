# Metered development calibration

Status: implemented for issue #69. The owner approved a **$10 model-only cap**
for exactly these six trials on 2026-10-20 (#57). The 48-trial pilot is not
approved. The worker evidence was accepted in #19.

## Scope

The calibration runs each of the three public invoice tasks (read, list/search,
CSV export) once with each of two models:
- `gpt-6.1-sol`, campaign `campaigns/calibration-sol.v1.json`, 708 cents;
- `gpt-6-luna`, campaign `campaigns/calibration-luna.v1.json`, 69 cents.

Both use medium reasoning and Standard processing, with no retries and no
repairs. The tasks already ship security instructions and an RLS helper, so the
campaigns label their single condition `rls_starter`. This is engineering and
model calibration, not a condition comparison. Results describe transport and
model behavior on public fixtures only. `security_verdict` remains
`not_evaluated`.

Each trial's hold is the safe per-request cents allowance from
[MODEL_BATCH.md](MODEL_BATCH.md): 236 cents for Sol and 23 for Luna. The two
campaigns total 777 cents, under the approved 1000.

## How one trial runs

`scripts/calibration.py` drives each trial through the store v8 runtime
lifecycle ([PERSISTENCE.md](PERSISTENCE.md)):

1. **Prepare.** The trial's hold, task-tree digest, verifier digest and configuration digest are recorded.
2. **Dispatch intent.** It is recorded before Harbor starts.
3. **Launch and acknowledge.** `harbor run` starts with `MeteredTerminus`: 12 turns, no summarization, tmux baked into the image. The ledger then records the acknowledgement.
4. **Broker the model requests.** Every request goes through the controller's broker socket to `model_meter.Meter`:
   - an exact preflight count of the complete payload;
   - a durable `request_intent` reservation;
   - exactly one send;
   - then `request_settle` from explicit usage, or `request_unknown`.

   The provider key stays in the controller. The `harbor run` environment is stripped of every `*_API_KEY`, `*_TOKEN`, `OPENAI_*` and `ANTHROPIC_*` variable. The candidate container is unchanged: no network, non-root.
5. **Collect and seal.** The trusted collector gathers the app. Its bytes are published, and the seal records the stop observation.
6. **Verify intent.** It is recorded with a fresh `VerifierSession` challenge.
7. **Sealed replay.** The sealed app is replayed with Harbor's `nop` agent and a fresh separate verifier.
8. **Sign and admit.** The replay's Harbor-nonce-bound evidence is signed as a v3 report by a short-lived signer that receives the runtime nonce only on stdin. It is admitted only through `PlanStore.admit_result`.
9. **Settle.** The trial settles at the committed request costs.

## Cost basis and stop conditions

Settled costs are an **upper bound**. OpenAI does not report cache writes, so all
uncached input is priced at the higher cache-write rate, and each request is
rounded up to whole cents. Reconcile against the provider bill separately.

The batch stops at the first unknown request outcome, for example a lost response, a timeout, an incomplete response, missing usage or an unexpected model. That request keeps its full reservation, the trial is interrupted but not settled, and the campaign budget stays blocked until a human reconciles it.

A trial whose collection or verification fails is interrupted with a bounded reason and settles at its known metered cost. Rerunning live mode skips trials that already have an attempt.

## Commands

The model-free dry run needs Docker and the Harbor group, but no key or network. It is also the CI job `metered-dry-run`:

```bash
uv run --locked --group harbor python scripts/calibration.py --dry-run
```

It runs one Sol-shaped `invoice-read` trial with a scripted provider. It requires an admitted complete pass and a settled nonzero metered cost. Local evidence (Docker 29.9.1, 2026-10-20) admitted pass/complete after 3 requests, settled at 3 cents, with the attempt at revision 13.

The live run is only for the dedicated worker. It spends real money:

```bash
DS_WORKER_HOST_REQUIRED=1 uv run --locked --group harbor python scripts/calibration.py \
  --live --key-file /home/controller/.secrets/openai-api-key --ledger <existing ledger dir>
```

Live mode refuses to start if any of these fails:
- `DS_WORKER_HOST_REQUIRED=1` is set;
- the checkout is clean;
- every task tree still matches its frozen campaign digest;
- the campaign caps fit the approved 1000 cents;
- neither campaign budget is blocked.

Before running:
- Reinstall the worker helper so it allowlists `.research/calibration`.
- Recheck the cited prices.
- Set a provider-side hard limit of $10 or less.

## Limits

- **The signer is a bridge.** It does not sign inside the verifier's own container. The Harbor nonce authenticates the replay evidence before signing.
- **Harbor exceptions stop collection.** A trial whose agent raised, for example after `TransportHalted`, is interrupted rather than graded.
- **No live request has been made by this change.** Account access, the model IDs actually returned, and current prices are still unverified.
