# VeriSec Operator Guide

Day-to-day guide for reviewing a patch or pull request with VeriSec.

For architecture, benchmarks, and holdout protocol, see
[ARCHITECTURE.md](ARCHITECTURE.md), [PORTFOLIO_PROFILES.md](PORTFOLIO_PROFILES.md),
and [HOLDOUT_PILOT.md](HOLDOUT_PILOT.md).

## What VeriSec is / is not

**VeriSec is**

- A **deterministic**, LLM-free CLI that reviews **unified diffs / PRs**
- Focused on **Python** security-relevant changes (AST + rules + optional tools)
- Built around **evidence**: findings link to code windows, tool traces, validation, and confidence
- Deployable in **local** and **CI** workflows with policy profiles and gates

**VeriSec is not**

- A full multi-language SAST replacement for Semgrep/CodeQL across an entire monorepo
- An LLM coding agent or auto-fixer
- A guarantee of zero false positives/negatives on arbitrary code
- A substitute for human security review on high-risk changes

## Install (once)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Optional scanners: `python -m pip install -e ".[scanners]"` or
`.\scripts\bootstrap_scanners.ps1`.

## Three-command happy path

```powershell
python -m verisec_agent init
python -m verisec_agent review --diff examples/demo.diff --repo . --out verisec-runs/demo
# Open verisec-runs/demo/report.md
```

`review` is the primary command. Alias: `python -m verisec_agent r ...`.

## Review a real change

**Local diff**

```powershell
git diff main...HEAD > change.diff
python -m verisec_agent review --diff change.diff --repo . --out verisec-runs/change
```

**GitHub PR** (requires `gh` + auth)

```powershell
python -m verisec_agent review --pr 123 --github-repo owner/repo --repo . --out verisec-runs/pr-123
```

**Patch URL**

```powershell
python -m verisec_agent review --diff-url https://example.com/fix.diff --repo . --out verisec-runs/url
```

### Terminal output

By default `review` prints:

- Finding count and verification pass rate
- Severity-sorted findings with location, confidence, fix hint, validation gaps
- Paths to the bundle and `report.md`
- Concrete next steps (open report, optional PR comment, replay)

Use `--json` for machine-readable output.

### Bundle layout (what to open)

| Path | Purpose |
| --- | --- |
| `report.md` | Human review report |
| `report.json` | Machine-readable findings |
| `report.sarif` | SARIF 2.1.0 for code-scanning UIs |
| `trace.jsonl` | Decision / tool event log |
| `inputs/diff.patch` | Exact reviewed patch |
| `tools/*.txt` | Captured verification stdout/stderr |

Raise validation coverage with `VERISEC_EVIDENCE` markers — see
[VALIDATION_EVIDENCE.md](VALIDATION_EVIDENCE.md) and
`examples/validation_evidence_stub.py`.

## Common operator commands

| Command | When to use |
| --- | --- |
| `init` | First time in a repo; write `verisec.toml` |
| `review` / `r` | Review a diff or PR |
| `tools` | See which adapters are available |
| `replay` | Re-run verification from a prior bundle |
| `pr-comment` | Render a sticky-ready Markdown comment |
| `github-comment` | Publish/update the comment (needs `GITHUB_TOKEN`) |
| `gate` | Enforce CI thresholds on a report/evaluation |
| `attest` | Verify release artifact hashes |

## Minimal CI sketch

```yaml
- run: python -m pip install -e ".[dev]"
- run: >
    python -m verisec_agent review
    --pr ${{ github.event.pull_request.number }}
    --github-repo ${{ github.repository }}
    --repo .
    --out verisec-runs/pr-review
    --policy-profile trusted-ci
- run: >
    python -m verisec_agent gate
    --report verisec-runs/pr-review/report.json
    --out verisec-runs/pr-gate
    --min-validation-coverage 0.5
    --max-policy-blocked 0
```

Policy profiles: `trusted-local`, `trusted-ci`, `untrusted-fork-pr`
(see [THREAT_MODEL.md](THREAT_MODEL.md)).

## Config tips

Default config is `verisec.toml` (`verisec init` writes a starter).

- Raise `min_confidence` to reduce low-signal noise
- Enable Semgrep/CodeQL adapters when installed
- Prefer `trusted-ci` in same-repo CI; `untrusted-fork-pr` for fork PRs
- Rule packs: `[rules] packs = ["builtin"]` (add `"django"` for the specialized pack).
  Third-party packs install via setuptools entry points (`verisec.rules`); see
  [CONTRIBUTING.md](../CONTRIBUTING.md)
- External adapters (examples under `adapters/`):
  ```toml
  [adapters]
  paths = ["adapters/bandit.toml", "adapters/pip-audit.toml"]
  [[verification.adapters]]
  id = "bandit"
  [[verification.adapters]]
  id = "pip-audit"
  ```
  Requires `bandit` / `pip-audit` on PATH (`pip install bandit pip-audit`).

## When you need the lab surface

Use lab commands only if you maintain benchmarks or release gates:

- `eval`, `portfolio`, `dashboard`, `case-audit`, `case-promote`
- `partition-audit`, `failure-analysis`
- `scanner-run`, `scanner-baseline`

Start from the root [README.md](../README.md) “Lab / maintainers” section and
[PORTFOLIO_PROFILES.md](PORTFOLIO_PROFILES.md).

## Troubleshooting

| Symptom | What to try |
| --- | --- |
| No findings | Diff may have no Python changes; try `examples/demo.diff`; check `min_confidence` |
| Tool missing | `python -m verisec_agent tools`; install scanner extra or bootstrap script |
| PR review fails | Ensure `gh` is authenticated; or pass a local `--diff` |
| Policy blocked | Check `[policy]` allowlists and profile (`trusted-local` vs `untrusted-fork-pr`) |
| Validation always missing | Emit `VERISEC_EVIDENCE` markers ([VALIDATION_EVIDENCE.md](VALIDATION_EVIDENCE.md)) |

## Contributing and security

- Contributing: [CONTRIBUTING.md](../CONTRIBUTING.md)
- Security disclosure: [SECURITY.md](../SECURITY.md)
- Changelog: [CHANGELOG.md](../CHANGELOG.md)
