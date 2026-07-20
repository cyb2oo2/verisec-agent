# Coding

**Applies to:** any AI coding tool (Cursor, Grok Build, Copilot, Claude Code).
**When:** Add or modify a VeriSec detection rule or verification adapter. Use when the user asks to detect a new vulnerability class, fix a rule's behavior, add a scanner or linter integration, or says "add a rule", "detect X", "add an adapter", "integrate <tool>".

**Read [../../AI_CONTEXT.md](../../AI_CONTEXT.md) and [../../CLAUDE.md](../../CLAUDE.md) first** — this file assumes both.

---

The highest-frequency real task in this repository. Both paths have a required ordering that
prevents shipping a detector which raises recall by raising false positives.

---

## Adding a detection rule

### Steps

1. **Prefer semantics over regex.** Detection belongs in `python_semantics.py` — AST parsing,
   import-alias resolution, taint sources, dataflow to sinks. Regex in `hypotheses.py` is a
   *secondary* signal only. A regex-primary rule will fire on comments, docstrings, and string
   literals; the negative-control suite exists specifically because this happened.

2. **Study a neighbouring rule first.** Find the closest existing detector and match its structure —
   how it resolves aliases, where it records dataflow steps, how it sets `analysis_scope`. The
   codebase is internally consistent; imitation is usually correct.

3. **Add `Rule` metadata** in `hypotheses.py` (`RULES` / `BUILTIN_RULES`): id, title, severity, base
   confidence, risk, fix guidance, recommended validation, false-positive notes. Set family/mode
   tags (`redos`, `complexity-dos`, `adds-hardening`) — these keep distinct vulnerability classes
   from collapsing into each other in evaluation.

4. **Distinguish introduces-risk from adds-hardening.** A patch that *adds* a bound to a regex is
   hardening; a patch that adds an unbounded one introduces risk. Conflating them produces findings
   that fire on security fixes — precisely backwards.

5. **Write the positive test** in `tests/test_python_semantics.py`: real code, real diff, `tmp_path`,
   assert on the actual finding. No mocks.

6. **Write the negative control — this is not optional.** Add a near-miss diff under
   `examples/negative_controls/` and register it in `examples/negative_control_cases.json`. The
   near-miss should be the safe form of the same pattern: `shell=False` against `shell=True`,
   `yaml.SafeLoader` against `yaml.Loader`, parameterized SQL against interpolated. Also cover the
   pattern appearing only in a comment or string literal.

7. **Run both suites:**
   ```powershell
   python -m pytest
   python -m verisec_agent eval --cases examples/negative_control_cases.json --out verisec-runs/nc
   python -m verisec_agent gate --evaluation verisec-runs/nc/evaluation.json `
     --min-accepted-finding-rate 1.0 --max-unexpected-finding-rate 0.0 `
     --max-negative-control-violations 0
   ```

8. **Update `CHANGELOG.md`**, and `docs/ROADMAP.md` if the rule completes a listed item.

---

## Adding a verification adapter

**External CLI (preferred):** copy `adapters/bandit.toml`, edit `id` / `command` / `executable` /
`parser` / `capabilities`. Add a parser branch in `tool_output.py` if the output format is new.
Reference from `[adapters].paths`, enable under `[[verification.adapters]]`, allowlist the adapter
and executable under `[policy]`. Test in `tests/test_plugins.py`.

**In-tree built-in:** register in `tool_adapters.BUILTIN_ADAPTERS`, map the parser in
`adapters_api.builtin_adapter_specs()`. Test in `tests/test_tool_adapters.py` and
`tests/test_tool_output.py`.

Declare capabilities honestly. A capability makes the tool a *candidate* for a check — it does not
confer coverage. Coverage requires a matching scanner finding or a `VERISEC_EVIDENCE:` marker
(`docs/VALIDATION_EVIDENCE.md`). Overstating capabilities inflates candidate counts and misleads
reviewers about what was actually checked.

---

## Output

The detection mechanism used (AST/dataflow vs regex fallback and why), the rule metadata, the
positive test, the negative control, both suite results, and the documentation updated.

## Guardrails

- **Never tune a rule against holdout cases.** `examples/holdout_cases.json` and the Django
  CVE-2023-46695 / mechanize 0.4.6 pair are frozen. Making them pass by changing a rule is
  measurement fraud, not a fix.
- Never ship a rule change without a negative control. Recall bought with false positives is a
  regression here.
- Never weaken the evidence-backed coverage rule to make a check appear covered.
- If a rule cannot be expressed without heavy regex, say so — that is a real finding about the
  vulnerability class, not a reason to lower the bar.
