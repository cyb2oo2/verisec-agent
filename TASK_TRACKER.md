# Task Tracker

Working state across sessions. Read at session start; update at session end.

**Scope boundary:** this file holds *what is in flight*. [DEVELOPMENT_LOG.md](DEVELOPMENT_LOG.md)
holds *why decisions were made*. [docs/ROADMAP.md](docs/ROADMAP.md) holds long-range direction —
do not duplicate roadmap items here until they become active work.

**Status vocabulary:** `active` · `blocked` · `review` · `done`

**Last updated:** 2026-07-22 · **Branch:** `cyb/demote-django-36053`

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

### T-003 — A genuinely blind holdout for the next measured claim
**Status:** done

Holdout 2 was frozen and **run once** on 2026-07-22 at detector commit `0ca2df5`. Result:
**0 findings across all 8 cases, primary recall 0/2, zero false positives** (D-018). Both
primary ReDoS cases missed structurally — the rule keys on `re.<func>(<inline pattern>` and
real fixes use variables / `re.split` / lexer token tuples. Case set, configs, protocol, and
the populated Results table are committed (`docs/HOLDOUT_2.md`). Detectors must not be tuned
against these now-burned cases (Invariant 1). Follow-ups spun out as T-010 and T-011.

The old holdout pair (Django CVE-2023-46695, mechanize 0.4.6) stays burned and historical
(D-002).

### T-011 — Generalize detection rules beyond exact call-site syntax
**Status:** active · **highest-value detector work**

**Investigation finding (2026-07-22, D-019):** the original premise was largely wrong. Synthetic
probes showed the semantic layer *already* resolves variable-bound patterns and the full `re.*`
sink set including `re.split`. The Holdout 2 misses do not stem from call-site syntax.

**Shipped (D-019):** the greedy-polynomial ReDoS shape `.*.*`, previously missed by
`is_redos_prone`. Synthetic-validated, greedy-only (does not touch the burned transformers
pattern), with a registered negative control.

**Shipped, follow-up (D-019):** generic SQL injection detection — string concatenation with taint,
plus `.raw`/`.executescript` sinks — and a **real precision fix**: parameterized `%s` DB-API
placeholders no longer trip the regex fallback. Two registered negative controls. Synthetic-
validated; not Django-specific.

**Remaining scope:**
- **Bare regex literals in data structures with no `re.*` sink** (pygments class) — deliberately
  left unflagged; a redos-shaped string is not necessarily a compiled regex (FP hazard). Pinned by
  `negative-redos-literal-in-structure`. Safe closure needs a regex-context signal (dataflow to a
  sink, or framework marker). The variable-bound and class-attribute forms already fire.
- **`py-sql-*` identifier rules** (D-015): the Django-specific patch-literal rules still exist and
  still cannot fire on unseen SQL. The new generic concat/taint detection covers the common shapes;
  whether to retire or generalize the identifier rules is a separate decision.

Hard constraints unchanged: **validate on new, unseen cases only** (Holdout 2 and pilot are
burned — Invariant 1); **paired negative controls first** (Invariant 4). The honest test of
whether generalization improved is a future Holdout 3, not a re-run of Holdout 2.

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

### T-010 — Verification argv rendering crashes on braces in a command
**Completed:** 2026-07-22

`verification.py` rendered argv with `str.format`, so any non-placeholder `{...}` — a `{1,36}`
regex quantifier, JSON, an f-string in a `-c` script — crashed the whole run (the `KeyError`
escaped the `ValueError`-only render guard). Replaced with `_expand_placeholders`, a regex that
substitutes only the defined `{python}` / `{tool_dir}` tokens and leaves every other brace intact.
Regression test asserts a `{1,36}` argv renders and executes. The pygments Holdout-2 config that
triggered this (D-018) is fixed at the renderer and needs no change; it stays frozen (Invariant 1).
Decision and rejected alternatives: D-020.

### T-009 — `repo` materialization returned a checkout at the wrong revision
**Completed:** 2026-07-22

`_materialize_case`'s `git_existing_repo` branch computed `base_ref..head_ref` correctly but
returned the caller's working tree at `HEAD`, not a checkout at `head_ref`; for `head_ref != HEAD`,
multi-line string masking (which assumes the checkout is `head_ref`, D-008) consulted the wrong
lines. Fixed by routing through `_checkout_case_repo(ref=head_ref)` — the same isolated-clone path
the `repo_url` branch uses and T-008 proved works with a local source (D-014). Regression test
parks the working tree at `base_ref` and asserts the materialized checkout is `head_ref`. No
measured suite uses the `repo` + refs form, so nothing published moved (confirmed). Decision: D-020.

### T-008 — Real-world false-positive corpus from self-history
**Completed:** 2026-07-22

Commit `b8b415d`. `examples/self_history_cases.json` replays all 18 parented commits on
`origin/main` as benign changes with no expected findings. Measured 22 findings, 14 of 18
cases clean, concentrated in four commits and overwhelmingly in fixtures: 21 of 22 in
`tests/`, `examples/`, or `scripts/`, one in `src/`. Wired as the `self-history-noise`
portfolio suite, gated with a new `max_findings` threshold ratcheted at 22.

Read the figure as an upper bound, not an estimate — the concentration in fixtures is an
artifact of this being a security tool's own repository. Design, alternatives, and the
reason no detector changed alongside it: D-014.

Runs offline, so it avoids the network fragility noted under T-007. Costs roughly five
minutes of portfolio wall-clock, which keeps it off the pull-request path per D-013.

**Follow-ups:** T-009 (the `repo` materialization defect found while building this).
External-OSS commits as a second corpus remain deferred, not rejected — more representative,
but reintroduces network dependence.

### T-007 — Generated claim-boundary counts and benchmark drift protection
**Completed:** 2026-07-22

Three commits, `ed8d523` / `d99e631` / `a356aec`. `claim_boundaries` prose now takes
`{system label:metric}` references resolved from the computed rows, so the counts that needed
manual correction twice (D-010, T-006) can no longer disagree with the table they qualify. The
templated manifests reproduce the published snapshot byte-identically, so no republish was needed.

Output shape was unchanged — `claim_boundaries` is still a list of strings — so `replay.py`,
`integrity.py`, and `scanner_baseline.py` were untouched. The scope note predicting a
`portfolio.py` / `dashboard.py` contract change was wrong; `dashboard.py` needed no edit at all.

Protection is layered because the release-portfolio CI step is guarded by
`github.event_name != 'pull_request'`: cross-surface consistency runs in pytest on every PR,
regeneration freshness rides the portfolio step on push. Rationale and the condition under which
the tiers should merge: D-013.

Tests 182 → 194. Both new checks were verified by injecting drift and confirming failure, not
merely by observing them pass.

**Left open:** the release portfolio is network-fragile — a transient
`fatal: fetch-pack: invalid index-pack output` during upstream materialization killed one
verification run. Unrelated to this work, plausible source of flaky CI on `main`, no entry yet.

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
