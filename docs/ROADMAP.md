# Roadmap

## Phase 0: Foundation

- Local CLI that reviews a unified diff.
- Evidence windows and traceable findings.
- Verification command runner.
- JSON review bundle.
- Unit tests and CI.

## Phase 1: Real repository review

- GitHub PR ingestion through `gh` or app integration.
- Repository context expansion around evidence windows.
- Tool adapters for pytest, semgrep, CodeQL, sanitizer runs, fuzz targets, and
  proof-of-concept scripts.
- False-positive taxonomy and reviewer-facing confidence calibration.

## Phase 2: Agentic validation

- Planner that turns hypotheses into validation plans.
- Patch synthesis with mandatory verification gates.
- Repro bundle replay command.
- Multi-agent review mode: skeptic, fixer, validator, reporter.

## Phase 3: Deployable security infrastructure

- GitHub PR bot.
- Web UI for trace replay and evidence inspection.
- Policy engine for sandbox, approvals, secrets, and tool permissions.
- Metrics: precision@k, reviewer time saved, validation pass rate, and accepted
  upstream fixes.
