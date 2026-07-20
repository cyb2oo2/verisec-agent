# Task Tracker

Working state across sessions. Read at session start; update at session end.

**Scope boundary:** this file holds *what is in flight*. [DEVELOPMENT_LOG.md](DEVELOPMENT_LOG.md)
holds *why decisions were made*. [docs/ROADMAP.md](docs/ROADMAP.md) holds long-range direction —
do not duplicate roadmap items here until they become active work.

**Status vocabulary:** `active` · `blocked` · `review` · `done`

**Last updated:** 2026-07-21 · **Branch:** `cyb/release-hardening`

---

## Active

### T-001 — Land the release-hardening branch
**Status:** review

Branch `cyb/release-hardening` carries substantial unlanded work: 15 modified files, 15 untracked,
6 new modules, 4 new test suites. Per `CHANGELOG.md` `[Unreleased]` this covers the plugin spine,
the operator surface (`verisec init`, grouped CLI, `review` → `r` alias), the
`py-unicode-normalization-dos` detector, class-based ReDoS with pattern-delta hardening, full-file
AST analysis, SARIF export, and `CONTRIBUTING.md` / `SECURITY.md`.

State: 175 tests pass, ruff clean.

Next: split into reviewable commits — `CONTRIBUTING.md` asks for one detector family or one docs
surface per PR, and this is currently several of both in one working tree.

### T-002 — Unblock the two remaining candidate CVE cases
**Status:** blocked

`examples/candidate_cases.json` holds 9 audited cases; 7 are promoted, 2 are blocked from measured
promotion pending verification configs and evaluation evidence.

Blocked on: verification configs and `VERISEC_EVIDENCE` markers for the two cases. Promotion runs
through `case-audit` → `case-promote`; do not merge into
`examples/promoted_candidate_cases.json` until the plan reports eligible (`CLAUDE.md` invariant 3).

---

## Backlog

### T-003 — A genuinely blind holdout for the next measured claim
**Status:** blocked

The current holdout pair (Django CVE-2023-46695, mechanize 0.4.6) is burned for blind evaluation —
detectors were tuned after observing the failure (D-002). Any future blind recall claim needs a
newly frozen holdout selected at a stated detector commit and audited disjoint via
`partition-audit`.

Blocked on: candidate cases not yet used in any measured suite, and a decision on freeze commit.

### T-004 — Resolve the two stale worktrees
**Status:** active

`.claude/worktrees/universal-ai-workflow-1526c8/` and
`.claude/worktrees/workflow-system-architecture-c13b72/` are both at `fb8d569`, three commits
behind. The latter holds the prior workflow kit whose useful structure was harvested into
`.claude/skills/` (D-006). Both are git-excluded and local-only.

Next: confirm nothing else is worth harvesting, then `git worktree remove` both. Retained pending
that confirmation.

### T-005 — Roadmap Phase 2: agentic validation
**Status:** blocked

Per `docs/ROADMAP.md`: planner turning hypotheses into validation plans, patch synthesis behind
mandatory verification gates, multi-agent review roles.

Blocked on: Phase 1 fully landed (T-001). Note that this phase introduces the project's first
model-dependent behavior — it needs an explicit human decision about where that boundary sits, since
`CLAUDE.md` currently forbids adding LLM calls to `src/` without instruction, and the "no LLM
required" property is central to the project's positioning.

---

## Done

### T-000 — AI collaboration layer
**Completed:** 2026-07-21

Added `CLAUDE.md`, `AI_CONTEXT.md`, `DEVELOPMENT_LOG.md`, `TASK_TRACKER.md`, and five skills. Fixed
one `E501` in `src/verisec_agent/operator.py` that was failing `ruff` and therefore CI. Rationale
and rejected alternatives: D-006.

Then made the layer tool-neutral: skills moved to `.ai/skills/` as canonical, `.claude/skills/`
reduced to dispatch stubs, `.ai/prompts/` added for tools without skill auto-selection. See D-007.

---

## Conventions for this file

- One entry per unit of work, newest first within each section.
- `blocked` entries must name what they are blocked *on*. A blocker with no named dependency is not
  a blocker, it is a deferral — say so.
- Move to Done with a completion date and a pointer to the decision-log entry if one exists.
- Prune Done entries older than roughly two releases; `CHANGELOG.md` is the durable record.
