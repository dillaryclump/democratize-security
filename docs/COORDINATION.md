# Coordinating concurrent agents

## Sources of truth

| Question | Authority |
| --- | --- |
| What is merged? | Current remote main and merged PRs |
| Who is working on what? | Live task issue plus linked open PR and branch |
| What capability exists and what is blocked? | STATUS.md, pinned to a revision |
| What is the long-term order? | ROADMAP.md |
| Why does the architecture work this way? | ARCHITECTURE.md, threat contract and decisions |
| What was actually tested? | Revision-specific CI/log evidence and historical handoff |

Chat history, an old checkout, a closed PR and an unchecked task box are not evidence of current implementation.

## Before editing

1. Read AGENTS.md and required orientation. Inspect local changes; preserve work from other sessions.
2. Fetch current remote main, open PRs, task issues and relevant branch heads. Inspect overlapping PR files and their latest activity, not only titles. Work on an isolated branch/worktree.
3. Choose one bounded issue. Record status, execution owner/session, UTC update time, baseline SHA, branch, planned paths, excluded work, dependencies and acceptance evidence. A GitHub assignee is a person; identify agent sessions in the body.
4. Re-read the issue and relevant PR heads after claiming. Claims are a coordination convention, not an atomic lock. If claims overlap, narrow your scope or leave the affected files to the existing active owner. Never overwrite another owner's claim or assume inactivity means abandonment.
5. Do not restart merged work from an older branch. Compare complementary changes and preserve useful follow-ups explicitly.

## During work and publication

- States: planned, ready, in progress, in review, blocked, done, or superseded. An open PR is in review, not done.
- Update the issue at scope changes, publication, blockers and session handoff. Name the exact next action and who can take it. Use timestamped evidence, not a perpetual claim with no handoff.
- Check remote main and your branch head again before publishing. Integrate intervening commits deliberately and rerun affected checks. Use expected-head checks for ref updates; never force-push over unknown work.
- Shared documentation needs the same care as code. If another PR changes STATUS.md or AGENTS.md, preserve its factual additions and resolve against the latest source.
- A green job, merged implementation and owner acceptance are separate facts. Record each separately. Never reuse an older run as evidence for newer code.
- Closing a superseded PR must identify its replacement, retain its history and file any distinct unfinished work. Do not delete another session's branch.

## Handoff and completion

Use HANDOFF_TEMPLATE.md. Link the PR, exact tested commit/run, unavailable checks, remaining risks and dependencies. Release an unfinished claim explicitly as ready or blocked with a clear next step. Close an implementation issue after its acceptance criteria are met and code is merged; keep owner-review gates open until the decision is actually recorded.

## Current integration hazard

As of 2026-10-16 UTC, integration #33 merged at `d6c2657` with all eight CI
jobs passing. It includes #22/#23/#25 and #26 -> #28 -> #30 alongside the merged
collector #17 and storage #31. Source commits and branches are retained; stacked
#28/#30 are closed with their integration disposition. Issue #34 owns the next
artifact-object publication slice on `milestone/artifact-objects`. Follow live
issue/PR state before editing overlapping persistence or status files.
