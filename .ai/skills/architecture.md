# Architecture

**Applies to:** any AI coding tool (Cursor, Grok Build, Copilot, Claude Code).
**When:** Plan a structural change to VeriSec — altering the review loop, adding a module, changing the bundle contract, or adding a CLI command. Use before writing code for anything that changes how stages connect, when the user says "add a module", "change the loop", "restructure", or proposes a new command surface.

**Read [../../AI_CONTEXT.md](../../AI_CONTEXT.md) and [../../CLAUDE.md](../../CLAUDE.md) first** — this file assumes both.

---

Structural changes to VeriSec are constrained by two things most contributors underestimate: the
review loop's ordering is semantic, and the bundle is a public interface. Plan against both before
writing code.

## Steps

1. **Locate the change in the loop.** Read `src/verisec_agent/agent.py` — 211 lines that name every
   stage in order. State which stage you are modifying and which stages consume its output.

2. **Check the ordering constraint.** Evidence localization precedes hypothesis generation because
   VeriSec reviews what a patch *introduces*, not the whole repository. Policy evaluation precedes
   execution because config travels with untrusted PRs. Calibration follows validation because
   confidence is derived from coverage. If your change reorders stages, stop and explain why the
   evidence still means what the reports claim it means.

3. **Check the bundle contract.** If output shape changes, `replay.py`, `integrity.py`, and
   `scanner_baseline.py` may consume it. Frozen baselines under `examples/baselines/` and the
   attestation flow depend on stable shapes. Enumerate consumers before changing a field.

4. **Prefer the existing extension points.** Most "new module" ideas are actually a rule pack
   (`rules_api.py`), a TOML adapter (`adapters_api.py`), or a parser branch (`tool_output.py`).
   A new top-level module needs justification that none of these fit.

5. **Check policy implications.** Anything that executes, reads files, or touches the network must
   pass through `policy.py` and be safe under `untrusted-fork-pr`. Ask: what happens when the diff
   is attacker-controlled?

6. **Plan the documentation fanout.** A new module touches `docs/ARCHITECTURE.md` package map. A
   new command touches `README.md` command table, `docs/OPERATOR.md`, and `cli.py` help. A bundle
   change touches `docs/ARCHITECTURE.md` bundle contract and `README.md` bundle contents. List
   these before starting, not after.

7. **Write the plan** as observable acceptance criteria — what a reviewer can check, not "works
   correctly". If a criterion is not checkable, rewrite it.

## Output

The stage you are changing, its consumers, the policy posture under untrusted input, the
documentation fanout list, and acceptance criteria. Recommend `coding` next for implementation.

## Guardrails

- Never introduce an LLM call or model-provider dependency into `src/`. "No LLM required" is the
  product, not an implementation detail.
- Never add a runtime dependency without explicit human approval — `dependencies = []` is deliberate
  because VeriSec runs in untrusted CI.
- Never widen `untrusted-fork-pr` to allow `pytest`, `poc-script`, or `custom`.
- If the change makes reports claim more than the evidence supports, that is a blocking objection —
  raise it rather than implementing it.
