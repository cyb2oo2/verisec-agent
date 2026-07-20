# Documentation

**Applies to:** any AI coding tool (Cursor, Grok Build, Copilot, Claude Code).
**When:** Update VeriSec documentation and keep its six overlapping surfaces in sync. Use when the user says "update the docs", "document this", "write it up", after a feature lands, or when README, ARCHITECTURE, ROADMAP, CHANGELOG, OPERATOR, and CONTRIBUTING have drifted apart.

**Read [../../AI_CONTEXT.md](../../AI_CONTEXT.md) and [../../CLAUDE.md](../../CLAUDE.md) first** — this file assumes both.

---

VeriSec has six documentation surfaces that restate overlapping information. The failure mode is
updating one and drifting the rest. The second failure mode — far more serious — is hand-editing
generated measurements.

## Surface map

| File | Holds | Do not put here |
|---|---|---|
| `README.md` | Operator onboarding, measured results, command surfaces | Internal design detail |
| `docs/ARCHITECTURE.md` | Full loop, package map, bundle contract | Usage instructions |
| `docs/OPERATOR.md` | Day-to-day usage | Architecture |
| `docs/ROADMAP.md` | Phase status, delivered capability | Implementation detail |
| `CONTRIBUTING.md` | How to extend rules, adapters, packs | Product claims |
| `CHANGELOG.md` | User-visible changes, Keep a Changelog | Rationale — that goes in `DEVELOPMENT_LOG.md` |

Plus the AI layer: `CLAUDE.md` (constraints and commands), `AI_CONTEXT.md` (architecture and
vocabulary for all tools), `DEVELOPMENT_LOG.md` (decisions), `TASK_TRACKER.md` (in-flight work).

## Steps

1. **Identify every affected surface before writing.** Typical fanouts:
   - New detector → `CHANGELOG.md`, `docs/ROADMAP.md` if it completes a listed item
   - New module → `docs/ARCHITECTURE.md` package map
   - New CLI command → `README.md` command table, `docs/OPERATOR.md`, `cli.py` help text
   - Bundle change → `docs/ARCHITECTURE.md` bundle contract, `README.md` bundle contents
   - New extension point → `CONTRIBUTING.md`
   - Loop or invariant change → `AI_CONTEXT.md` and `CLAUDE.md`

2. **Never hand-edit generated measurements.** Benchmark tables in `README.md` and
   `docs/RELEASE_BENCHMARK.md` mirror `docs/release_benchmark_matrix.json`, produced by
   `verisec portfolio`. If a number is wrong, regenerate it:
   ```powershell
   python -m verisec_agent portfolio --manifest verisec_portfolio.json --out verisec-runs/release-portfolio
   ```
   Editing the Markdown so it matches an expectation is the worst possible change in this repo.

3. **Preserve claim precision.** This project's credibility comes from careful hedging. Specific
   phrasings that must survive editing:
   - Measurements are **curated-set**, not estimates of arbitrary-repository performance
   - The post-fix holdout run is **engineering validation on already-observed cases, not a new
     blind holdout**
   - Scanner-baseline zero recall means **those configs did not match labeled changed lines in this
     set** — not that the scanner is incapable
   - Validation coverage is **evidence-backed**, not capability-based

   Never smooth these into stronger claims. If a sentence sounds hedged, it is hedged deliberately.

4. **Record decisions separately.** If the change involved a choice a future change could
   accidentally undo, append to `DEVELOPMENT_LOG.md` — context, decision, alternatives,
   consequences. Do not put rationale in `CHANGELOG.md`; do not put user-facing change notes in the
   decision log.

5. **Match the register.** These docs are dense, table-heavy, and precise. Match that. Do not add
   marketing language, do not pad with restatement, and keep the description shorter than the thing
   described.

6. **Code comments state contracts, not narration.** Add a comment only where it captures a
   constraint the code cannot show. Match the file's existing comment density — which is low.

7. **Verify every command you document.** Run it. Documented commands that fail are worse than
   absent ones.

## Output

The surfaces updated and what changed in each, plus any `DEVELOPMENT_LOG.md` entry appended. State
explicitly whether any measurements were regenerated versus reused.

## Guardrails

- **Never hand-edit a generated benchmark number.** Regenerate or leave it.
- Never strengthen a hedged claim. The hedges are the product.
- Never duplicate content across surfaces — cross-link instead. Duplication is how these six files
  drift.
- Docs describe what shipped, not what was planned. If they diverged, the code is the truth.
- If documenting a change would require overstating what the evidence supports, stop and say so.
