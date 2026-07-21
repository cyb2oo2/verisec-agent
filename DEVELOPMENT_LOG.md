# Development Log

Append-only record of decisions and their rationale. **Never rewrite or delete an entry** — if a
decision is superseded, add a new entry that references the old one and mark the old one superseded.

**Scope boundary:** this file records *why* a choice was made. [CHANGELOG.md](CHANGELOG.md) records
*what changed for users*. A decision with no user-visible effect belongs only here. Never duplicate
content between the two.

**Format:** newest first.

```markdown
## D-NNN — Short title
**Date:** YYYY-MM-DD · **Status:** accepted | superseded by D-NNN
**Context:** what forced a choice
**Decision:** what was chosen
**Alternatives:** what was rejected and why
**Consequences:** what this constrains going forward
```

Append when you make a choice a future change could accidentally undo. Skip trivia that is obvious
from the code.

---

## D-010 — django-cve-2023-36053 demoted; benchmark snapshot regenerated
**Date:** 2026-07-21 · **Status:** accepted

**Context:** The release portfolio failed on `promoted-cves: primary finding recall 0.86
below 1.00`. Bisecting every commit where the case exists — `5b48402`, `d9754d0`,
`cd7518e`, and current — gave an identical 0.8571. The case was never detected; there is
no regression point. Meanwhile `docs/release_benchmark_matrix.json` published
`primary_recall: 1.0` over 7 cases with `status: measured`, and `README.md` mirrored it.
That figure did not reproduce from any commit in this repository, including the one where
the snapshot was written.

Root cause: the case expects `py-regex-redos-hardening`, a rule that fires on a regex
pattern delta. CVE-2023-36053's actual fix changes no regex — it adds length guards
(`max_length = 2048`, `len(value) > 320`). The label does not match the patch, so no
version of this detector could satisfy it. `CHANGELOG.md` separately records a deliberate
decision that bare length bounds are not ReDoS findings, which points the same way.

**Decision:** Remove the case from `examples/promoted_candidate_cases.json`. It remains in
`examples/candidate_cases.json` tagged `candidate`, so it stays visible in the audit-only
queue without counting as measured performance. Regenerate the benchmark snapshot from a
passed, attested portfolio run and publish the artifacts verbatim.

**Alternatives:** (a) Relabel the case to expect a length-guard hardening rule — rejected
for now; no such rule exists for validator length bounds, and adding one collides with the
recorded decision that bare length bounds are not ReDoS. Reasonable future work. (b)
Publish 0.857 with the case retained — rejected because `case-promote` requires full
expected-finding recall, so the case does not meet the project's own promotion criteria and
should not be in a measured suite at all. Running `case-promote` after removal confirms it:
6 promoted, 3 blocked, and this case is now correctly among the blocked.

**Consequences:** promoted CVEs row moves from 7 cases / 1.00 recall / 0.69 precision to
6 cases / 1.00 recall / 0.64 precision; findings 13 → 11. Negative controls 10 → 11 from
the triple-quoted control added in D-008. `claim_boundaries` prose in both portfolio
manifests is hand-maintained rather than derived, so it was corrected to match; a future
change should consider deriving those counts. `docs/HOLDOUT_PILOT.md` still records "7
promoted CVE cases" and was deliberately left alone — it describes the partition state at
the `d9754d0` freeze, and editing it would falsify a historical audit record.

The published snapshot was verified to reproduce byte-identically from an independent
portfolio run. Recall remained 1.00 because the removed case was never detected, so no
detection claim was weakened by this change — only its denominator corrected.

---

## D-008 — String-literal suppression resolves spans from the file, not the window
**Date:** 2026-07-21 · **Status:** accepted

**Context:** VeriSec's review of its own PR #1 produced 11 findings, all false
positives. Every one had `analysis_scope=None` and zero dataflow steps — regex fallback
only, semantic layer never engaged. Root cause: `_strip_python_comments` tokenized each
line independently, so a single-line literal was blanked correctly but any line of a
triple-quoted block raised `TokenError` and fell through verbatim, reading as bare code.
The negative-control suite missed this because `shell_true_docs.diff` only covered the
single-line form.

**Decision:** Resolve multi-line string spans from the checked-out file
(`_file_string_lines`) and mask window lines by patched-file line number. The checkout is
the patched revision, so added-line numbers index directly into it. Two window-local
fallbacks remain for when no checkout exists: whole-text tokenization, then an
opener-only heuristic that requires real code before the quote. Added
`negative-shell-triple-quoted` plus three unit tests, one of which asserts a real
`shell=True` call still fires.

**Alternatives:** (a) Delimiter state machine over the window — rejected, a window that
begins mid-string cannot distinguish an opener from a closer, and guessing "closer" would
mask preceding real code. (b) Excluding `tests/` from review — rejected, it hides a
detector defect affecting any repository containing code samples in strings, which
includes documentation tooling and security projects generally. (c) Lowering the gate
threshold — rejected outright; that is weakening a check to make it pass.

**Consequences:** Self-review dropped 11 → 5 findings. The masking is line-preserving so
evidence-window mapping is unaffected. Suppression only applies where a checkout exists;
`--diff` with no repo degrades to the window-local heuristics. Deleted lines are never
masked, since the old file's spans cannot be resolved from a patched checkout. Rules with
`scan_mode = "python-text"` (redos, unicode-dos) still scan string contents by design and
are untouched — masking them would delete ReDoS detection, since regex patterns live in
string literals.

---

## D-009 — Self-review evidence covers only what is actually verified
**Date:** 2026-07-21 · **Status:** accepted

**Context:** After D-008, five findings remained and validation coverage was 0.00, failing
the PR gate. Coverage had to rise without weakening the gate.

**Decision:** `scripts/self_review_evidence.py`, wired as a `custom` verification command
in `verisec.toml`, executes the real detectors and emits `VERISEC_EVIDENCE` markers only
for properties it verifies: unicode length-guard dominance (hardening vs introduces-risk)
and ReDoS classification of nested-quantifier patterns against bounded equivalents.
`py-tls-verify-disabled` recommends "integration test against expected certificate chain";
no such test exists here, so **no marker is emitted** and the check stays uncovered. The
script prints a `VERISEC_NOTE` naming the omission.

**Alternatives:** Emitting a marker for the TLS check anyway — rejected as exactly the
capability-over-evidence dishonesty D-001 exists to prevent. Coverage of 4/5 that is true
beats 5/5 that is not.

**Consequences:** Coverage 0.80, avg confidence 0.62 → 0.77, PR gate passes. The TLS
finding remains visible and uncovered, which is the intended reviewer signal. Under
`untrusted-fork-pr` the `custom` adapter is blocked, so coverage falls to 0.00 — that gate
already failed at baseline on policy-blocked tools, so fork review is no worse, but it is
not fixed either. Adding a real TLS integration test would be the way to close the last
check.

---

## D-007 — Skills are canonical in `.ai/`; `.claude/` holds dispatch stubs
**Date:** 2026-07-21 · **Status:** accepted

**Context:** The layer needed to serve Cursor and Grok Build alongside Claude Code. Claude Code
discovers skills only under `.claude/skills/*/SKILL.md` and dispatches on YAML frontmatter, so the
two tool families cannot read the same path by default.

**Decision:** `.ai/skills/<name>.md` holds the canonical instructions. `.claude/skills/<name>/SKILL.md`
retains only its frontmatter — which Claude Code needs to know *when* to trigger — with a body that
directs the agent to read the canonical file. Added `.ai/prompts/` for tools with no auto-dispatch,
and `.ai/README.md` describing per-tool wiring. No project knowledge lives in `.ai/`; it points at
`AI_CONTEXT.md` and `CLAUDE.md`.

**Alternatives:** (a) Copy the skills into both trees — rejected, two copies of the same checklist
drift, and the drift is silent because both remain individually valid. (b) Symlink `.claude/skills`
to `.ai/skills` — rejected, Windows symlinks need Developer Mode or elevation and git portability
is poor; this repo is developed on Windows. (c) Make `.claude/` canonical and have `.ai/` point back
— rejected, `.ai/` is the tool-neutral surface, so vendor-neutral content should not live under a
vendor directory. (d) Keep prompts out entirely — rejected, Cursor and Grok have no skill
auto-selection, so a pasted prompt *is* their dispatch mechanism.

**Consequences:** Skill edits must go to `.ai/skills/` only; a stub containing instructions means
someone forked the content. Claude Code pays one extra file read per skill invocation — accepted
as the cost of a single source. Adding a skill now requires two files: the canonical instructions
and a frontmatter stub. `.cursorrules` was deliberately not created; `.ai/README.md` documents it
as an opt-in for teams standardizing on Cursor.

---

## D-006 — AI collaboration layer added as documentation, not tooling
**Date:** 2026-07-21 · **Status:** accepted

**Context:** No AI collaboration layer existed in the main tree. Two abandoned worktrees under
`.claude/worktrees/` held prior attempts, one containing a complete Claude×Grok workflow kit branched
from `fb8d569` — three commits stale.

**Decision:** Add `CLAUDE.md`, `AI_CONTEXT.md`, `DEVELOPMENT_LOG.md`, `TASK_TRACKER.md`, and five
skills under `.claude/skills/`. Documentation only — no changes to `src/` behavior, no new
dependencies, no CI changes. Harvested the prior kit's Steps/Output/Guardrails skill structure and
its honesty guardrails; discarded its Grok-specific handoff mechanics as too narrow for a
multi-tool layer.

**Alternatives:** (a) Adopt the worktree kit wholesale — rejected, it assumes a two-model
Claude-plans/Grok-builds split that does not match this repo's actual work. (b) Root
`ARCHITECTURE.md` — rejected, `docs/ARCHITECTURE.md` already exists and is linked from `README.md`
and `CONTRIBUTING.md`; a duplicate would split the source of truth and drift within weeks.
(c) Generic skill names — kept the five requested directories but scoped each to a VeriSec-specific
surface, since generic skills duplicate what coding agents already do well.

**Consequences:** `.claude/skills/` is committed and shared (only `.claude/worktrees/` is
git-excluded). Constraints live in `CLAUDE.md`, understanding in `AI_CONTEXT.md`, with no content
overlap — both must be updated when the review loop or the invariants change. The two stale
worktrees are retained pending review; see TASK_TRACKER.md T-004.

---

## D-005 — Plugin spine via setuptools entry points
**Date:** 2026-06 (reconstructed from `CONTRIBUTING.md`, `pyproject.toml`, `rules_api.py`)
**Status:** accepted

**Context:** Rules and adapters were in-tree only, so extending VeriSec meant forking it.

**Decision:** `RuleProvider` registry with the `verisec.rules` setuptools entry point group, plus
`AdapterSpec` TOML adapters loaded from `[adapters].paths`. Third parties ship packs as installable
packages; VeriSec declares its own `builtin` and `django` packs through the same mechanism.

**Alternatives:** Config-file rule definitions — rejected, rules need real AST analysis, not
declarative patterns. In-tree-only extension — rejected, forces forks.

**Consequences:** Rule packs are dogfooded through the public interface, so it cannot silently rot.
New built-in packs must register in both `rules_api._builtin_pack_factories()` and `pyproject.toml`
entry points.

---

## D-004 — Runtime stays dependency-free
**Date:** 2026-05 (reconstructed from `pyproject.toml`, `docs/THREAT_MODEL.md`)
**Status:** accepted

**Context:** VeriSec executes inside CI, including on untrusted fork PRs.

**Decision:** `dependencies = []`. Everything optional lives in the `dev` and `scanners` extras.
Semgrep, CodeQL, Bandit, and pip-audit are discovered at runtime, never imported.

**Alternatives:** Depend on Semgrep directly for richer analysis — rejected, it would put a large
transitive tree inside the untrusted-PR execution path and couple release cadence to a third party.

**Consequences:** All Python analysis is stdlib `ast` (hence `python_semantics.py` at 1561 lines).
New runtime dependencies require explicit human approval.

---

## D-003 — Governed, shell-free verification execution
**Date:** 2026-06-08 (`5b48402`) · **Status:** accepted

**Context:** Review runs execute tools against attacker-controlled diffs. A naive runner is a remote
code execution path.

**Decision:** Commands render to argv and execute with `shell=False`. `policy.py` gates every
execution on adapter allowlist, executable allowlist, timeout cap, output cap, blocked patterns,
environment mode, and network posture. Three profiles: `trusted-local`, `trusted-ci`,
`untrusted-fork-pr`. The fork profile blocks `pytest`, `poc-script`, and `custom`, forcing a static
adapter intersection. Blocked commands are recorded as failed results with `policy_status =
"blocked"` rather than silently dropped.

**Alternatives:** Trusting configuration — rejected, config travels with the PR. Skipping
verification on fork PRs — rejected, it would leave the highest-risk reviews unverified.

**Consequences:** Adding an adapter requires a policy allowlist entry. The blocked-not-dropped rule
keeps policy decisions auditable in the trace. CI mirrors this with a two-job split so the
privileged comment job never touches PR code.

---

## D-002 — Post-fix holdout remeasure is not a new blind holdout
**Date:** 2026-06-10 (`cd7518e`) · **Status:** accepted

**Context:** The frozen holdout pilot (Django CVE-2023-46695, mechanize 0.4.6), selected blind at
detector commit `d9754d0`, failed its gate at 0.00 primary recall. Phase 1–2 detector work then
raised the same cases to 1.00 recall.

**Decision:** Report both, labeled distinctly. `README.md` states plainly that the post-fix run "is
engineering validation on already-observed cases, not a new blind holdout." The failed pilot result
is retained, not replaced.

**Alternatives:** Report only the 1.00 figure — rejected as measurement fraud. Discard the holdout
after failure — rejected; a holdout that survives only when it passes measures nothing.

**Consequences:** Any future blind claim needs a *newly* frozen holdout at a stated commit. These
two cases are permanently burned for blind evaluation. This precision is load-bearing — see
`CLAUDE.md` invariant 8 and `docs/HOLDOUT_POSTFIX.md`.

---

## D-001 — Validation coverage requires evidence, not capability
**Date:** 2026-06-08 (`5b48402`) · **Status:** accepted

**Context:** Marking a check covered because a tool with a matching capability tag ran would inflate
coverage without demonstrating anything. Running pytest does not prove pytest exercised the
vulnerable path.

**Decision:** Capability matching identifies a *candidate tool*. A check becomes `covered` only when
the tool emits a matching scanner finding or a `VERISEC_EVIDENCE:` JSON marker binding the check to
a finding, rule, file/line, payload, or assertion. Uncovered recommended checks surface as
validation gaps and lower reviewer-facing confidence.

**Alternatives:** Capability-based coverage — rejected as the central dishonesty this project
exists to avoid.

**Consequences:** Coverage numbers are lower but meaningful. Benchmark cases need real verification
markers, which is why `examples/validation_evidence_stub.py` and `docs/VALIDATION_EVIDENCE.md`
exist. Weakening this invalidates every published coverage metric.

---

*Entries D-001 through D-005 were reconstructed from repository evidence — code, commits, and
documentation — during the D-006 work, and were not written contemporaneously. The decisions are
evidenced; the reasoning attributed to them is inferred. Correct any entry that misstates intent.*
