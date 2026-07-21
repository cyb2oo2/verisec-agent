# Task Tracker

Working state across sessions. Read at session start; update at session end.

**Scope boundary:** this file holds *what is in flight*. [DEVELOPMENT_LOG.md](DEVELOPMENT_LOG.md)
holds *why decisions were made*. [docs/ROADMAP.md](docs/ROADMAP.md) holds long-range direction —
do not duplicate roadmap items here until they become active work.

**Status vocabulary:** `active` · `blocked` · `review` · `done`

**Last updated:** 2026-07-21 · **Branch:** `cyb/demote-django-36053`

---

## Active

### T-002 — Unblock the two remaining candidate CVE cases
**Status:** blocked

`examples/candidate_cases.json` holds 9 audited cases; 7 are promoted, 2 are blocked from measured
promotion pending verification configs and evaluation evidence.

Blocked on: verification configs and `VERISEC_EVIDENCE` markers for the two cases. Promotion runs
through `case-audit` → `case-promote`; do not merge into
`examples/promoted_candidate_cases.json` until the plan reports eligible (`CLAUDE.md` invariant 3).

---

## Backlog

### T-007 — Generated claim-boundary counts and a regeneration-freshness check
**Status:** active

`claim_boundaries` in `verisec_portfolio.json` and `verisec_portfolio.nightly.json` is
hand-maintained prose embedding counts the system also computes. It has now needed manual
correction twice (D-010, then T-006). Invariant 2 forbids hand-editing benchmark numbers while the
architecture requires exactly that in this one string, and nothing in CI detects the drift — the
portfolio and attestation both passed with the prose already stale.

Two parts: derive the counts from computed metrics, and add a CI check asserting regeneration
produces no diff against the committed snapshot. Rationale and rejected alternatives: D-012.

Implementation note: the freshness check must normalize line endings or compare parsed JSON. Git
stores the snapshot LF-normalized while the generator emits CRLF on Windows, so a naive byte
comparison fails every run for reasons unrelated to drift. Verified this session.

Scope note: changes the output contract of `portfolio.py` and `dashboard.py`, so it belongs in its
own PR under the one-concern-per-PR rule. README's benchmark table is generated-*derived* but
hand-transcribed, so a check covering only `docs/*.json` would still miss drift there.

---

### T-003 — A genuinely blind holdout for the next measured claim
**Status:** blocked

The current holdout pair (Django CVE-2023-46695, mechanize 0.4.6) is burned for blind evaluation —
detectors were tuned after observing the failure (D-002). Any future blind recall claim needs a
newly frozen holdout selected at a stated detector commit and audited disjoint via
`partition-audit`.

Blocked on: candidate cases not yet used in any measured suite, and a decision on freeze commit.

**Priority note (2026-07-21):** a repository-level review ranked this the highest-value open item.
Re-reading the blocker, it is a *decision* rather than a dependency — `partition-audit` already
exists to prove disjointness, and nothing engineering-side is missing. Supporting evidence: the one
time VeriSec ran against unlabeled real code (its own PR, D-008) it produced 11 findings, all false
positives, while the curated benchmark reported 1.00 recall and zero unexpected findings. That gap
is currently invisible to CI. Recommended sequence was T-007 → real-world FP corpus → this.

### T-004 — Resolve the two stale worktrees
**Status:** active

`.claude/worktrees/universal-ai-workflow-1526c8/` and
`.claude/worktrees/workflow-system-architecture-c13b72/` are both at `fb8d569`, three commits
behind. The latter holds the prior workflow kit whose useful structure was harvested into
`.claude/skills/` (D-006). Both are git-excluded and local-only.

Next: confirm nothing else is worth harvesting, then `git worktree remove` both. Retained pending
that confirmation.

Also fold in the stale local branch `cyb/fix-python-text-masking`, a pointer at `d2c9c76` that is
fully contained in the current branch — safe to delete, verified 2026-07-21.

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

### T-006 — Cover `scan_mode=python-text` masking; regenerate the snapshot
**Completed:** 2026-07-21

An uncommitted `hypotheses.py` change routed `python-text` rules around the multi-line string mask.
Measured both ways: it recovered zero detection and reintroduced the embedded-sample false positive
D-008 removed. Reverted. Root cause of the confusion was D-008's own closing claim, which described
a `scan_mode` exemption its code never contained — corrected in D-011, which also records the
evidence table.

The mandated negative-control gate passed green over that regression, because the only
triple-quoted control exercises `shell=True`, a `python-code` rule. Added
`negative-redos-triple-quoted` plus paired unit tests (sample must not fire, real call site must
still fire). Negative controls 11 → 12; snapshot regenerated from a passed, attested run and
published verbatim. No measured metric moved — denominator only, not a detection improvement.

Two commits, `3c71670` and `ce8e573`, each verified green standalone. Rebased onto `origin/main`,
which dropped two already-landed duplicates; `git diff` against the pre-rebase tree is empty.
**Not pushed** — the remote branch still holds the pre-rebase history and needs
`git push --force-with-lease origin cyb/demote-django-36053`.

A repository-level review this session ranked the open development paths: T-007 (claim-boundary
drift) → a real-world false-positive corpus → T-003 (blind holdout) → detection breadth → T-005
(Phase 2 LLM boundary). The first three all target the same gap: measured performance is
established only on cases the detectors have already seen.

### T-001 — Land the release-hardening branch
**Completed:** 2026-07-21

Split the working tree into five focused commits (`f04b771`..`4a10153`): semantics primitives,
plugin spine, SARIF export, operator surface, documentation. Each verified `ruff`-clean and
green in an isolated worktree; branch tip is 175 passing.

Two impurities, deliberate and recorded in the commit messages: `hypotheses.py` lands whole in the
plugin-spine commit because its `rules_api` import and new detector `RULES` occupy interleaved
hunks in one file, and `tests/test_python_semantics.py` lands with the spine rather than the
primitives because it exercises them through the repo-aware `generate_hypotheses` signature.

`tests/test_plugins.py::test_installed_verisec_rules_entry_points_exist` requires
`pip install -e .` in the tree under test — it fails in a fresh worktree because `.egg-info` is
gitignored. Environmental, not a defect, but worth knowing before trusting a worktree test run.

Pushed to `origin/cyb/release-hardening`. No PR opened. Note that `origin/main` is 10 commits
behind this branch — `cd7518e`, `d9754d0`, and `5b48402` had also never been pushed, so a PR from
here to `main` will carry those three older commits in addition to the seven from this session.

**Correction (2026-07-21, later session):** the divergence above no longer holds. `origin/main` has
since advanced and now contains rebased copies of `3d31d4c` and `2be2297` under different SHAs
(`076982e`, `8c7dd82`) — confirmed by identical `git patch-id` and a `range-diff` marking both
pairs `=`. Whatever landed them did not come through this branch. See T-006.

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
