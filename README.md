# VeriSec Agent

Evidence-grounded security patch review for real repositories.

VeriSec Agent is a foundation for a deployable security code review agent. It
does not try to be another vulnerability classifier. It runs a review loop that
links each security finding to evidence windows, tool traces, validation
commands, confidence, and a reproducible review bundle.

## Initial scope

- Ingest unified diffs from PRs, patches, or CVE fixes.
- Localize changed evidence windows with file and line context.
- Seed security hypotheses from risky code patterns.
- Run configured verification commands such as tests, static analysis, or
  project-specific checks.
- Emit reviewer-facing JSON reports and reproducibility bundles.

## Quick start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m verisec_agent review --diff examples/demo.diff --repo . --out verisec-runs/demo
python -m verisec_agent review --pr 123 --github-repo owner/repo --repo . --out verisec-runs/pr-123
python -m pytest
```

The generated bundle contains:

- `report.json`: reviewer-facing findings and verification summary.
- `trace.jsonl`: append-only agent decision and tool events.
- `inputs/diff.patch`: the reviewed patch input.
- `inputs/source.json`: diff source metadata for audit and replay.
- `tools/*.txt`: captured command output for each verification tool.

## Architecture

```text
Patch / PR diff
    |
    v
Diff parser -> Evidence windows -> Hypothesis engine
    |                                  |
    v                                  v
Trace log <-------------------- Verification runner
    |
    v
Review report + reproducibility bundle
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[docs/ROADMAP.md](docs/ROADMAP.md) for the project direction.

## Design principles

- Evidence first: every finding points to concrete changed lines.
- Verification over vibes: reports include command traces and failure modes.
- Low noise by construction: findings carry confidence and a false-positive
  rationale field.
- Auditability: every major step is recorded in a portable bundle.
- Deployment path: the core loop is independent from GitHub bots, CLIs, and UIs.
