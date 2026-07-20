# AI_CONTEXT.md

Tool-neutral project context for AI coding assistants — Claude Code, Cursor, Grok Build, Copilot, or
any other. Nothing here is Claude-specific.

**Companion file:** [CLAUDE.md](CLAUDE.md) holds the hard constraints and commands. It is plain
Markdown; read it too regardless of which tool you are. This file explains *what the system is* so
you can make good decisions; that file states *what you must not do*.

**Task instructions:** [`.ai/skills/`](.ai/README.md) — step-by-step checklists for adding rules,
debugging findings, structural changes, pre-PR review, and documentation. Tool-neutral and
canonical; Claude Code reaches the same files through stubs in `.claude/skills/`. If your tool
cannot auto-select a skill, [`.ai/prompts/library.md`](.ai/prompts/library.md) has copy-paste
dispatch prompts.

---

## What VeriSec is

A deterministic security patch review system for Python diffs and pull requests. It ingests a
unified diff, localizes evidence, generates security hypotheses from AST and dataflow analysis, runs
governed verification tools, and emits a replayable audit bundle.

**It contains no LLM.** That is a product decision, not a gap. The value proposition is that every
finding is traceable to a rule, a line, and a captured tool invocation — reproducible byte-for-byte.
Introducing model-dependent behavior into the review path would destroy that property.

What it is not: a multi-language SAST suite, an automatic patch rewriter, or a claim of universal
recall on arbitrary repositories. The README states these boundaries deliberately; the project's
credibility rests on not overclaiming.

---

## The review loop

This ordering is the architecture. Steps cannot be reordered without changing what the evidence
means.

```
diff → changed lines → evidence windows → hypotheses → verification
                                                            ↓
   bundle ← calibrated findings ← validation plan ← parsed tool output
     ↓
   CI gate → PR comment
```

1. **Diff ingestion** (`diff_parser.py`) — parse the unified diff into changed files, hunks, lines.
2. **Evidence localization** — compact windows around security-relevant *additions*. VeriSec reviews
   what a patch introduces, not the whole repository. This is why scanner baselines are scored
   diff-aware.
3. **Context expansion** (`source_context.py`) — bounded source windows from the checkout, when one
   exists.
4. **Hypothesis generation** (`hypotheses.py` + `python_semantics.py`) — AST and dataflow first,
   regex fallback second.
5. **Policy evaluation** (`policy.py`) — before any execution: adapter allowlist, executable
   allowlist, timeouts, output caps, blocked patterns, environment mode, network posture.
6. **Verification** (`verification.py`) — render to argv, execute with `shell=False`, bound output.
7. **Tool output parsing** (`tool_output.py`) — normalize Semgrep JSON, CodeQL SARIF, Bandit,
   pip-audit.
8. **Validation planning** (`validation.py`) — link each finding to covered and missing checks.
9. **Confidence calibration** (`calibration.py`) — adjust reviewer-facing confidence from evidence.
10. **Reporting** (`reporting.py`, `sarif.py`, `bundle.py`) — the audit bundle.

`agent.py` orchestrates the whole loop and is the best single file to read first — 211 lines that
name every stage in order.

Full detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (27-step expansion, complete package map).

---

## Vocabulary

Precise meanings. Using these loosely produces subtly wrong code and misleading reports.

| Term | Meaning |
|---|---|
| **Evidence window** | Compact line range around a security-relevant change; the unit of review |
| **Hypothesis** | Candidate security risk from a rule + evidence, before verification |
| **Finding** | Reviewer-facing hypothesis with context, calibrated confidence, fix guidance |
| **Candidate tool** | A tool whose declared *capability* matches a check — not yet evidence |
| **Covered** | A check backed by an actual scanner finding or `VERISEC_EVIDENCE:` marker |
| **Validation gap** | A recommended check with no covering evidence; lowers confidence |
| **Primary / supporting / benign / negative-control** | Expected-finding roles separating real reviewer value from accepted noise |
| **Negative control** | A near-miss that must *not* fire (`shell=False`, `yaml.SafeLoader`, parameterized SQL) |
| **Promoted case** | A case that passed `case-audit` → `case-promote` into a measured suite |
| **Holdout** | Frozen blind-evaluation cases; permanently excluded from measured promotion |
| **Bundle** | The portable audit directory — the project's real output artifact |
| **Policy profile** | `trusted-local`, `trusted-ci`, or `untrusted-fork-pr` execution posture |

The candidate/covered distinction is the one most often gotten wrong. Capability makes a tool a
*candidate*; only matching evidence makes a check *covered*.

---

## Layout

```
src/verisec_agent/     35 modules, no runtime dependencies
  agent.py             loop orchestration — read this first
  hypotheses.py        rule definitions + pack-aware generation
  python_semantics.py  AST, taint, dataflow (largest module, 1561 lines)
  policy.py            execution governance
  validation.py        evidence-backed coverage planning
  rules_*.py           RuleProvider plugin spine (builtin, django)
  adapters_api.py      AdapterSpec registry + TOML adapter loading
  evaluation.py        batch case runner
  portfolio.py         release orchestration
  cli.py               operator / CI / lab command surfaces
tests/                 175 tests, real files via tmp_path, no mocks
examples/              demo diffs, case manifests, negative controls
adapters/              external TOML adapter specs (bandit, pip-audit)
docs/                  architecture, threat model, operator guide, holdout protocol
scripts/               scanner freezing and nightly promotion
```

`verisec-runs/` is generated output and gitignored — write run artifacts only there.

---

## Task recipes

Which files a given change actually touches. Following these prevents partial changes that pass
tests but drift the documentation.

**Add a detection rule**
1. `python_semantics.py` — AST/dataflow detection (preferred path)
2. `hypotheses.py` — `Rule` metadata in `RULES` / `BUILTIN_RULES`, family/mode tags
3. `tests/test_python_semantics.py` — positive case
4. `examples/negative_controls/*.diff` + `examples/negative_control_cases.json` — near-miss
5. `CHANGELOG.md`, and `docs/ROADMAP.md` if it completes a roadmap item

Regex in `hypotheses.py` is a secondary signal, never the primary mechanism for a new rule.

**Add a verification adapter**
- External CLI: copy `adapters/bandit.toml`, add a parser branch in `tool_output.py`, reference from
  `[adapters].paths`, allowlist under `[policy]`, test in `tests/test_plugins.py`
- In-tree: `tool_adapters.BUILTIN_ADAPTERS` + `adapters_api.builtin_adapter_specs()`, test in
  `tests/test_tool_adapters.py`

**Add a benchmark case**
`case-audit` → `case-promote` → merge into `examples/promoted_candidate_cases.json` only when the
plan reports eligible. Never skip the gate. Never touch holdout manifests.

**Change the bundle contract**
`bundle.py` + `reporting.py` + `docs/ARCHITECTURE.md` "Bundle contract" + `README.md` "Review bundle
contents". The bundle is a public interface — replay and attestation depend on its shape.

---

## Documentation surfaces

Six surfaces restate overlapping information. Know which one a change belongs in:

| File | Holds |
|---|---|
| `README.md` | Operator-first onboarding, measured results, command surfaces |
| `docs/ARCHITECTURE.md` | Full loop, package map, bundle contract |
| `docs/OPERATOR.md` | Day-to-day usage |
| `docs/ROADMAP.md` | Phase status and delivered capability |
| `CONTRIBUTING.md` | How to extend rules, adapters, packs |
| `CHANGELOG.md` | User-visible changes, Keep a Changelog |

A new detector typically touches `CHANGELOG.md` and `docs/ROADMAP.md`. A new module touches
`docs/ARCHITECTURE.md`. A new command touches `README.md`, `docs/OPERATOR.md`, and `cli.py` help.

**Generated content is never hand-edited.** Benchmark tables in `README.md` and
`docs/RELEASE_BENCHMARK.md` mirror `docs/release_benchmark_matrix.json`, produced by
`verisec portfolio`. Regenerate; do not retype.

---

## Conventions

Python 3.11+. `from __future__ import annotations` everywhere. Modern typing (`str | None`, not
`Optional[str]`). Keyword-only arguments beyond two parameters. Frozen dataclasses for data;
`tuple` not `list` for collections on models. Underscore-prefixed module-private helpers. Ruff,
line length 100, `E,F,I,UP,B,SIM`.

Tests use pytest with `tmp_path`, write real files, and assert on real outputs. No mocking. Match
this — it is why the suite catches real regressions in 10 seconds.

Verify before proposing: `python -m ruff check src tests` and `python -m pytest`.
