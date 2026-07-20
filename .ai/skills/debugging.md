# Debugging

**Applies to:** any AI coding tool (Cursor, Grok Build, Copilot, Claude Code).
**When:** Diagnose a VeriSec finding that behaved wrong — a false positive, a missed detection, unexpected confidence, a policy block, or a failing evaluation case. Use when the user says "this fired wrong", "why didn't it detect", "false positive", "the gate failed", "confidence is off", or pastes a report or trace.

**Read [../../AI_CONTEXT.md](../../AI_CONTEXT.md) and [../../CLAUDE.md](../../CLAUDE.md) first** — this file assumes both.

---

VeriSec is deterministic and every run writes a complete audit bundle. That means debugging here is
*reading evidence*, not forming theories. Read the bundle before hypothesizing — the answer is
almost always already recorded.

## Steps

1. **Get a bundle.** If the user has one, read it. Otherwise reproduce:
   ```powershell
   python -m verisec_agent review --diff <diff> --repo . --out verisec-runs/debug
   ```

2. **Read `trace.jsonl` first.** Append-only, ordered, one event per stage: `review.start`,
   `diff.parsed`, `evidence.localized`, `hypotheses.generated`, `context.expanded`,
   `validation.planned`, `confidence.calibrated`, `review.finish`. The counts localize the failure
   to a stage immediately — no guessing which one broke.

3. **Bisect by stage using the counts:**

   | Symptom in trace | Failing stage |
   |---|---|
   | `changed_lines` is 0 | Diff parsing — malformed patch or unsupported format |
   | Lines parsed, `windows` is 0 | Evidence localization — change not classed security-relevant |
   | Windows exist, `count` is 0 | Hypothesis generation — the rule did not match |
   | Hypotheses exist, no finding | Confidence below `min_confidence` (default 0.35) |
   | Finding exists, low confidence | Calibration — check validation gaps |

4. **For a false negative**, isolate rule vs. semantics. Does `python_semantics.py` resolve the
   import alias? Is the taint source recognized? Does the sink match? Is the file classified as
   Python — non-`.py` release artifacts are deliberately excluded from SQL-formatting rules. Check
   whether the pattern is inside a comment or string literal, which is excluded on purpose.

5. **For a false positive**, check whether the code is actually the *safe* form of the pattern —
   `shell=False`, `verify=True`, `SafeLoader`, parameterized SQL, a bounded regex. If so, this is
   exactly what the negative-control suite covers: add the case to
   `examples/negative_control_cases.json` as a reproduction *before* changing the rule.

6. **For confidence complaints**, read `report.json` `confidence_notes`. Calibration is explicit:
   matched tool evidence raises confidence, scanner coverage without a hit lowers it, missing
   recommended checks are called out as gaps. The note states which applied.

7. **For a policy block**, the command was never executed. Look for `policy_status = "blocked"` in
   the verification result and read the stderr artifact under `tools/` — it names the policy reason.
   Check the active profile: `untrusted-fork-pr` blocks `pytest`, `poc-script`, and `custom` by
   design. A block under that profile is usually correct behavior, not a bug.

8. **For an evaluation or gate failure**, run `failure-analysis` — it classifies misses into
   semantic rule confusion, rule/location mismatch, undetected labeled locations, unexpected
   findings, and execution errors, rather than leaving you to read raw case output.

9. **Write a failing test before fixing.** Reproduce in `tests/` with `tmp_path` and real files.
   A fix without a reproduction is unverified.

## Output

The failing stage identified from the trace, the evidence that localizes it, a failing test
reproducing it, and the minimal fix. If the fix touches a detector, hand off to `coding` for the
negative-control requirement.

## Guardrails

- Read the bundle before theorizing. Deterministic system, complete trace — the evidence exists.
- **Never fix a false negative by tuning against a holdout case.** Those are frozen; making them
  pass by rule changes invalidates the measurement.
- Never widen a rule to catch one case without checking the negative-control suite still passes.
  Fixing a miss by breaking precision is a net regression.
- A policy block under `untrusted-fork-pr` is usually the system working. Verify before "fixing" it.
- If the root cause is that a report claimed more than the evidence supports, that is the bug —
  fix the claim, not the evidence.
