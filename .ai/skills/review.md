# Review

**Applies to:** any AI coding tool (Cursor, Grok Build, Copilot, Claude Code).
**When:** Pre-PR gate for changes to VeriSec itself before requesting human review. Use when the user says "review my changes", "ready to commit", "check this before I push", "is this ready", or finishes a unit of work. This reviews the repository's own code — not to be confused with `verisec review`, which reviews a user's diff.

**Read [../../AI_CONTEXT.md](../../AI_CONTEXT.md) and [../../CLAUDE.md](../../CLAUDE.md) first** — this file assumes both.

---

Adversarial self-review before human review. Assume the change is plausible but unverified; the job
is to find where it is wrong. This repository's credibility rests on calibrated claims — hold your
own work to the standard its gates enforce.

## Steps

1. **Read the actual diff.** `git status` then `git diff`. Note that `cyb/release-hardening` carries
   substantial pre-existing uncommitted work — separate your changes from what was already there
   before reviewing.

2. **Run the required checks. Both, in full:**
   ```powershell
   python -m ruff check src tests
   python -m pytest
   ```
   The suite is 175 tests in ~10 seconds. There is no reason to run a subset.

3. **Check the invariants** (`CLAUDE.md` "Hard constraints"). Walk them explicitly:
   - Were any holdout cases or manifests touched?
   - Were benchmark numbers in `README.md` or `docs/*.md` hand-edited rather than regenerated?
   - Did a case enter a measured suite without `case-audit` → `case-promote`?
   - Did a detector change ship without a negative control?
   - Was evidence-backed coverage weakened toward capability-based coverage?
   - Was `shell=True` introduced, or `policy.py` bypassed, or the fork profile widened?
   - Was a runtime dependency added to `pyproject.toml`?

4. **Run the negative-control suite if any detector changed:**
   ```powershell
   python -m verisec_agent eval --cases examples/negative_control_cases.json --out verisec-runs/nc
   python -m verisec_agent gate --evaluation verisec-runs/nc/evaluation.json `
     --min-accepted-finding-rate 1.0 --max-unexpected-finding-rate 0.0 `
     --max-negative-control-violations 0
   ```

5. **Check test quality, not just presence.** Does each test actually assert the behavior? Could it
   pass if the feature were removed? Are there `tmp_path` real-file tests rather than mocks? A test
   that cannot fail is a finding.

6. **Check correctness on the changed path.** Trace the main path and the edge cases. Look for
   unhandled `None`, off-by-one in line ranges, mutated shared state, unbounded output, and paths
   that behave differently when no checkout is available (`source_context` unavailable is a real
   runtime state, not a corner case).

7. **Check scope.** `CONTRIBUTING.md` asks for one detector family or one documentation surface per
   PR. Flag scope creep — including your own.

8. **Check the documentation fanout** (`AI_CONTEXT.md` "Documentation surfaces"). A new detector
   touches `CHANGELOG.md` and often `docs/ROADMAP.md`. A new module touches `docs/ARCHITECTURE.md`.
   A new command touches `README.md`, `docs/OPERATOR.md`, and `cli.py` help.

9. **Rank findings** most-severe first: file:line, what is wrong, a concrete failing scenario, the
   fix. Separate blocking correctness bugs from style nits.

## Output

Findings ranked by severity with concrete failure scenarios, then a verdict:

- **READY** — checks pass, invariants hold, scope is tight. State what you ran.
- **NOT READY** — a blocking list. Be specific about what must change.

Report check results honestly, with output. If tests fail, show the failure. If you only ran part
of the verification, say which part.

## Guardrails

- Never report unmet criteria as met. Partial is a valid, honest outcome — this project rejects
  inflated claims about detection quality; do not make inflated claims about your own work.
- Verify against the spec and the invariants, not against what the code appears to intend. Re-derive;
  do not trust comments.
- Do not commit, push, or open a PR unless explicitly asked.
- A green suite is not sufficient. The invariant walk in step 3 catches what tests cannot.
