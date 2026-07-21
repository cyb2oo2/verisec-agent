# VeriSec Agent

**Deterministic security patch review for Python PRs and diffs** — findings tied
to evidence, verification, and a replayable review bundle. No LLM required.

## What VeriSec is / is not

| VeriSec **is** | VeriSec **is not** |
| --- | --- |
| A review loop for **unified diffs / PRs** | A drop-in multi-language enterprise SAST suite |
| **Evidence-grounded** (code windows, tools, confidence) | An LLM agent or automatic patch rewriter |
| Python-focused rules + AST/dataflow | A claim of universal recall on arbitrary repos |
| Local + CI friendly with policy profiles | A replacement for human review on critical changes |

Day-to-day usage: **[docs/OPERATOR.md](docs/OPERATOR.md)**.  
Architecture and lab harness: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.  
Contributing: **[CONTRIBUTING.md](CONTRIBUTING.md)** · Security: **[SECURITY.md](SECURITY.md)** ·
Changelog: **[CHANGELOG.md](CHANGELOG.md)**.

## Quick start (3 commands)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"

python -m verisec_agent init
python -m verisec_agent review --diff examples/demo.diff --repo . --out verisec-runs/demo
# Open verisec-runs/demo/report.md
```

That is the full operator happy path. The terminal prints a severity-sorted
finding summary, validation gaps, and next steps. Alias: `verisec r` for
`review`.

**Review your own change**

```powershell
git diff main...HEAD > change.diff
python -m verisec_agent review --diff change.diff --repo . --out verisec-runs/change
```

**Command surfaces** (see `python -m verisec_agent -h`)

| Surface | Commands |
| --- | --- |
| **Operator** | `init`, `review` (`r`), `replay`, `tools`, `pr-comment`, `github-comment` |
| **CI** | `gate`, `attest` |
| **Lab** (benchmarks / release) | `eval`, `portfolio`, `dashboard`, `case-audit`, `case-promote`, `partition-audit`, `failure-analysis`, `scanner-run`, `scanner-baseline` |

## Scope (operator)

- Ingest unified diffs from PRs, patches, or CVE fixes.
- Localize evidence windows and expand repo context when a checkout exists.
- Seed security hypotheses (rules + Python AST / dataflow).
- Run configured verification (tests, linters, Semgrep/CodeQL when present).
- Emit reviewer JSON/Markdown bundles and optional PR comments.
- Apply execution policy profiles for local, CI, and untrusted fork PRs.

## Measured performance (curated sets)

These are **curated-set** measurements, not estimates of performance on arbitrary
repositories. Snapshot from
[docs/release_benchmark_matrix.json](docs/release_benchmark_matrix.json)
([Markdown](docs/RELEASE_BENCHMARK.md)):

| System | Positive Cases | Negative Controls | Primary Recall | Primary Precision | Findings | Raw Tool Findings | Out Scope | Validation | Tool Evidence | Neg Ctrl Violations |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| VeriSec Agent | 3 OSS CVE/PR cases | 12 adversarial controls | 1.00 | 0.50 | 8 | 8 | 0 | 1.00 | 1.00 | 0 |
| VeriSec Agent promoted CVEs | 6 promoted CVE cases | 12 adversarial controls | 1.00 | 0.64 | 11 | 11 | 0 | 1.00 | 1.00 | 0 |
| Semgrep baseline | 3 OSS CVE/PR cases | 10 isolated scanner controls | 0.00 | 0.00 | 0 | 2 | 2 | 1.00 | 0.00 | 0 |
| CodeQL baseline | 3 OSS CVE/PR cases | 10 isolated scanner controls | 0.00 | 0.00 | 0 | 10 | 10 | 1.00 | 0.00 | 0 |

Scanner rows use patch-overlap scoring for the recorded configurations; zero
recall means those configs did not match labeled changed lines in this set.

**Holdout protocol** (blind pilot vs later post-fix remeasure):

| Split | Cases | Partition Overlap | Primary Recall | Primary Precision | Verified Patches | Gate |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Holdout pilot at `d9754d0` (blind) | 2 | 0/10 reference cases | 0.00 | 0.00 | 2/2 | failed |
| Holdout post-fix remeasure (Phase 1–2) | 2 | 0/10 reference cases | 1.00 | 1.00 | 2/2 | passed |

Details: [docs/HOLDOUT_PILOT.md](docs/HOLDOUT_PILOT.md),
[docs/HOLDOUT_POSTFIX.md](docs/HOLDOUT_POSTFIX.md). The post-fix run is
engineering validation on already-observed cases, not a new blind holdout.

## Lab / maintainers (optional)

Full research and release harness (keep using when you maintain benchmarks):

```powershell
python -m verisec_agent tools
python -m verisec_agent eval --cases examples/eval_cases.json --out verisec-runs/demo-eval --config examples/demo_verisec.toml
python -m verisec_agent portfolio --manifest verisec_portfolio.json --out verisec-runs/release-portfolio
python -m verisec_agent portfolio --manifest verisec_portfolio.nightly.json --out verisec-runs/nightly-portfolio
python -m verisec_agent attest --index verisec-runs/release-portfolio/artifact_index.json --out verisec-runs/release-portfolio-attestation
python -m pytest
```

Optional live scanners:

```powershell
.\scripts\bootstrap_scanners.ps1
python -m verisec_agent scanner-run --adapter semgrep --cases examples/scanner_smoke_cases.json --out verisec-runs/semgrep-smoke
python -m verisec_agent scanner-run --adapter codeql --cases examples/scanner_smoke_cases.json --out verisec-runs/codeql-smoke
```

Scanner discovery uses PATH, `VERISEC_SEMGREP` / `VERISEC_CODEQL`, `.venv`, and
`tools/codeql*/codeql/`. Profiles:
[docs/PORTFOLIO_PROFILES.md](docs/PORTFOLIO_PROFILES.md).

Additional lab commands: `case-audit`, `case-promote`, `partition-audit`,
`failure-analysis`, `scanner-baseline`, `dashboard`, `gate`, `pr-comment`,
`github-comment`, `replay`. Run `python -m verisec_agent -h` for the full list.

## Review bundle contents

The generated bundle contains:

- `report.json`: reviewer-facing findings and verification summary.
- `report.md`: human-readable reviewer report with evidence, repository
  context, and validation coverage.
- `report.sarif`: SARIF 2.1.0 export for GitHub code scanning and other UIs.
- `trace.jsonl`: append-only agent decision and tool events.
- `inputs/diff.patch`: the reviewed patch input.
- `inputs/source.json`: diff source metadata for audit and replay.
- `tools/*.txt`: captured command output for each verification tool.
- `replay/replay.json`: verification replay summary when `verisec replay` is used.

Validation coverage is evidence-backed. See
[docs/VALIDATION_EVIDENCE.md](docs/VALIDATION_EVIDENCE.md) and
`examples/validation_evidence_stub.py` for `VERISEC_EVIDENCE` markers.

Batch evaluation writes:

- `evaluation.json`: aggregate metrics and per-case summaries.
- `evaluation.md`: reviewer-friendly evaluation summary.
- `cases/<case-id>/`: the full VeriSec bundle for each case.
- `_source-cache/repos/<hash>/`: per-run repository object caches shared across
  cases from the same upstream repository, while each case still receives an
  isolated checkout under `cases/<case-id>/_source/repo`.

`verisec eval --resume` reuses existing `cases/<case-id>/report.json` bundles
in the output directory and recomputes aggregate metrics from those reports.
This makes long real-repository CVE suites recoverable after network, checkout,
or verification interruptions without losing case-level auditability.

Case audits write:

- `case_audit.json`: per-case benchmark-readiness checks for source
  reproducibility, labels, security metadata, tags, and verification configs.
- `case_audit.md`: compact intake-review table for expanding CVE/PR datasets.

Case promotion plans write:

- `case_promotion.json`: machine-readable decision table for candidate cases,
  existing promoted cases, blockers, evidence metrics, and promotion thresholds.
- `case_promotion.md`: reviewer-facing promotion plan showing why each
  candidate is eligible, already promoted, or blocked.
- Optional promoted-case manifest: newly eligible cases with `candidate` tags
  replaced by `promoted`.

CI gates write:

- `gate.json`: machine-readable pass/fail result, thresholds, and metrics.
- `gate.md`: Markdown summary suitable for CI logs or GitHub step summaries.

Regression dashboards write:

- `dashboard.json`: release matrix across multiple evaluation suites, optional
  gate status, and baseline-regression findings.
- `dashboard.md`: Markdown release matrix suitable for CI summaries or release
  notes.

Portfolio release gates write:

- `portfolio.json`: one-command release result across configured suites, gates,
  dashboard summary, and failures.
- `portfolio.md`: compact release-gate summary for CI and release review.
- `benchmark_matrix.json` and `benchmark_matrix.md`: measured agent and scanner
  baseline rows plus explicit skipped/not-run rows for unavailable comparisons.
- `scanner-runs/<label>/scanner_results.json` and `scanner_results.md`: real
  scanner execution provenance when a portfolio baseline uses `run: true`.
- `scanner-baselines/<label>/baseline.json` and `baseline.md`: scanner artifact
  findings scored against the same expected-finding labels used by VeriSec.
- `artifact_index.json` and `artifact_index.md`: SHA-256, byte size, command,
  timestamp, Python/platform version, and git state for release artifacts.
- `evaluations/`, `gates/`, and `dashboard/`: the underlying artifacts created
  from the portfolio manifest.

Artifact attestation writes:

- `attestation.json`: machine-readable verification result for an
  `artifact_index.json`.
- `attestation.md`: Markdown summary listing each artifact and whether its
  byte size and SHA-256 still match the index.

PR comment rendering writes:

- `demo-pr-comment.md`: GitHub-comment-ready Markdown with a stable marker,
  gate status, deployment metrics, and finding or case tables.

## Verification adapters

`verisec tools` lists built-in adapters and their capability tags. The default
config uses:

- `pytest`: `unit-test`, `regression-test`, `python-test`
- `ruff`: `lint`, `static-analysis`, `python-static-analysis`

Optional adapters such as `semgrep`, `codeql`, and `poc-script` can be enabled
in `verisec.toml` when those tools or scripts exist for a repository.

Semgrep runs in JSON mode when enabled. VeriSec parses its results into tool
findings, matches them back to review findings by file and line range, and shows
the matched evidence in the validation plan.

`verisec scanner-run` executes a standalone scanner against evaluation cases,
captures stdout/stderr and JSON/SARIF artifacts, and records argv, executable
path, exit code, duration, timeout, command-step details, and materialization
provenance. If the tool is missing, it writes explicit skipped cases rather than
empty findings. The built-in CodeQL profile uses a two-step Python security SARIF flow:
`codeql database create` followed by `codeql database analyze`.

`verisec scanner-baseline` scores captured Semgrep JSON, CodeQL SARIF, or
`scanner-run` manifests as standalone baseline systems. This keeps scanner
comparisons auditable without pretending they are VeriSec validation runs.
Baseline scoring is diff-aware: precision and recall use only scanner findings
that overlap the changed evidence window for the case, while raw full-repository
findings are retained as `raw_tool_finding_count`, `out_of_scope_finding_count`,
and out-of-scope samples. This makes external scanner comparisons fairer for PR
review loops without hiding scanner noise.

CodeQL runs through SARIF output when enabled. The `{tool_dir}` command
placeholder points tools at the bundle's `tools/` directory so generated SARIF
artifacts are captured and replayable.

Finding confidence is calibrated after validation: matched structured tool
evidence raises reviewer-facing confidence, scanner coverage without a matching
hit lowers it, and missing recommended checks are called out as validation gaps.

## Case intake

`verisec case-audit` is the benchmark expansion gate. It audits raw case
manifests before running expensive repository materialization:

```powershell
python -m verisec_agent case-audit `
  --cases examples/oss_seed_cases.json `
  --out verisec-runs/oss-seed-audit `
  --require-verification `
  --fail-on-blocked
```

The current OSS seed audit is 3/3 ready with zero warnings. The negative-control
suite is 11/11 ready with zero warnings. The candidate CVE intake queue in
`examples/candidate_cases.json` is audit-only: 9 cases have reproducible source
metadata and advisory labels, 6 are already promoted, and the remaining 3 are
blocked from measured promotion until they receive verification configs and
evaluation evidence.

`verisec case-promote` is the measured-benchmark promotion gate. It combines the
candidate audit, optional evaluation evidence, and the existing promoted manifest
to produce a promotion plan:

```powershell
python -m verisec_agent case-promote `
  --candidates examples/candidate_cases.json `
  --existing-promoted examples/promoted_candidate_cases.json `
  --evaluation verisec-runs/candidate-eval/evaluation.json `
  --out verisec-runs/candidate-promotion-plan `
  --promoted-manifest verisec-runs/newly-promoted-cases.json
```

By default a case cannot enter the measured benchmark unless it has a
verification config, primary expected finding, CVE/GHSA/advisory metadata,
completed evaluation evidence, full expected-finding recall, full primary
finding recall, full validation coverage, full tool evidence, no validation
gaps, no policy blocks, and no unexpected findings. New CVE/PR cases should be
merged into `examples/promoted_candidate_cases.json` only after this plan marks
them eligible.

Validation coverage is evidence-backed. A matching tool capability is recorded
as a candidate, but a check is only marked covered when the tool emits a matching
scanner finding or a `VERISEC_EVIDENCE:` JSON marker from stdout/stderr. Markers
can bind a check to `finding_id`, `rule_id`, file/line evidence, payloads, and
assertions so reviewer-facing coverage is auditable instead of command-name
based.

## Verification policy

The `[policy]` section in `verisec.toml` is a lightweight governance layer for
deployable runs. It can allowlist adapters, cap command timeouts, block dangerous
shell patterns, allowlist executables, cap retained stdout/stderr bytes, choose a
minimal or inherited environment, and warn or block when configured tools are
unavailable.

Policy profiles make the deployment posture explicit:

- `trusted-local`: local development and curated experiments.
- `trusted-ci`: main-branch and same-repository CI.
- `untrusted-fork-pr`: fork PR review; blocks `custom`, `poc-script`, and
  `pytest`, forces minimal environment and disabled-network posture, and only
  allows the configured static adapter intersection.

Verification commands are rendered into argv and executed with `shell=False`.
The original command template stays in the report for replay, but the executed
argv is also stored so reviewers can audit the exact process boundary. Commands
may provide an explicit `argv = [...]` template; otherwise VeriSec parses the
rendered command line into argv before policy evaluation.

Policy decisions are written into the trace and report. A blocked verification
command is recorded as a failed tool result with `policy_status = "blocked"`;
the command is not executed, and the stderr artifact explains the policy reason.

## Batch evaluation

`verisec eval` runs a JSON manifest of patch cases and summarizes deployment
signals such as validation coverage, tool evidence rate, validation gap rate,
average confidence, expected-rule recall, expected-finding recall, and
expected-rule precision. Cases can point at a local diff, a `diff_url`, or a real
repository patch with `repo_url`, `base_ref`, and `head_ref`; VeriSec will
clone/materialize the checkout, write the audited diff into the case bundle, and
review the patched revision. For older PRs whose head commit is no longer
fetchable, a case can combine `repo_url`, `base_ref`, and `diff_url` so VeriSec
checks out the base tree and applies the PR diff in an isolated clone.

```json
{
  "cases": [
    {
      "id": "demo-shell-true",
      "diff": "demo.diff",
      "repo": "..",
      "expected_rules": ["py-shell-true"],
      "tags": ["demo", "python"]
    }
  ]
}
```

Real-repository cases can carry portfolio metadata and finding-level labels:

```json
{
  "cases": [
    {
      "id": "project-cve-or-pr-id",
      "repo_url": "https://github.com/owner/repo.git",
      "base_ref": "vulnerable-or-pre-fix-commit",
      "head_ref": "fixed-or-pr-head-commit",
      "metadata": {
        "project": "owner/repo",
        "language": "python",
        "cve": "CVE-YYYY-NNNN",
        "cwe": "CWE-78",
        "upstream_pr": "https://github.com/owner/repo/pull/123",
        "vulnerability_class": "command-injection"
      },
      "expected_findings": [
        {
          "rule_id": "py-shell-true",
          "file_path": "path/to/file.py",
          "severity": "high",
          "role": "primary"
        }
      ],
      "tags": ["oss", "cve", "python", "command-injection"]
    }
  ]
}
```

`expected_findings.role` separates reviewer value from raw detections:
`primary` marks the main security signal, `supporting` marks useful evidence such
as regression tests or secondary changed paths, `benign` marks accepted noise, and
`negative-control` marks findings that should not appear. Evaluation summaries
report accepted finding rate, primary precision, primary finding recall,
supporting evidence rate, negative-control violations, and unexpected taxonomy.

The adversarial negative-control suite in
[examples/negative_control_cases.json](examples/negative_control_cases.json)
covers near misses such as `shell=False`, `verify=True`, parameterized SQL,
strong hashes, bounded regexes, and dangerous patterns that appear only in
comments or string literals. It is intended to keep false positives visible as a
first-class CI signal.

See [examples/real_repo_cases.example.json](examples/real_repo_cases.example.json)
for a template to turn accepted OSS PRs or CVE patches into evaluation cases.
The first real seed case is tracked in
[examples/oss_seed_cases.json](examples/oss_seed_cases.json) and documented in
[docs/CASE_STUDIES.md](docs/CASE_STUDIES.md). The current seed portfolio covers
MkDocs GHSL-2023-208, PyYAML PR #74 / CVE-2017-18342, and sqlparse
GHSL-2021-107 / CVE-2021-32839.

`verisec gate` turns a single `report.json` or an `evaluation.json` into a CI
decision. It exits non-zero when thresholds are missed and can append Markdown to
`GITHUB_STEP_SUMMARY`.

```powershell
python -m verisec_agent gate `
  --evaluation verisec-runs/demo-eval/evaluation.json `
  --min-validation-coverage 0.5 `
  --min-avg-confidence 0.6 `
  --min-accepted-finding-rate 1.0 `
  --min-primary-precision 1.0 `
  --min-primary-finding-recall 1.0 `
  --max-unexpected-finding-rate 0.0 `
  --max-negative-control-violations 0 `
  --max-policy-blocked 0 `
  --max-validation-gap-rate 1.0 `
  --github-step-summary
```

Noise gates are most meaningful for evaluation manifests with
`expected_findings`; single unlabelled PR reviews still use the validation,
confidence, severity, and policy gates.

For false-positive regression checks, gate the negative-control suite directly:

```powershell
python -m verisec_agent gate `
  --evaluation verisec-runs/negative-controls/evaluation.json `
  --min-accepted-finding-rate 1.0 `
  --max-unexpected-finding-rate 0.0 `
  --max-negative-control-violations 0
```

`verisec dashboard` rolls multiple evaluations into one release matrix. It can
also compare the current matrix against a previous `dashboard.json`.

```powershell
python -m verisec_agent dashboard `
  --evaluation demo=verisec-runs/demo-eval/evaluation.json `
  --gate demo=verisec-runs/demo-gate/gate.json `
  --evaluation oss-seed=verisec-runs/oss-seed-3/evaluation.json `
  --gate oss-seed=verisec-runs/oss-seed-3-gate/gate.json `
  --evaluation negative-controls=verisec-runs/negative-controls/evaluation.json `
  --gate negative-controls=verisec-runs/negative-controls-gate/gate.json `
  --baseline verisec-runs/previous-dashboard/dashboard.json `
  --out verisec-runs/regression-dashboard `
  --fail-on-regression
```

`verisec portfolio` runs the whole release gate from a manifest: every suite can
first be case-audited, then evaluated, gated, and rolled into a dashboard. It can
also run audit-only candidate queues through `case_audit_suites` so future CVE/PR
cases are visible without being counted as measured benchmark performance. The
included [verisec_portfolio.json](verisec_portfolio.json) covers the demo smoke
test, the real OSS seed portfolio, the promoted CVE suite, the adversarial
negative-control suite, an audit-only candidate CVE queue, and a benchmark
matrix with a measured Semgrep artifact baseline and a live CodeQL security
SARIF baseline backed by frozen scanner artifacts. CodeQL can still rerun live
when the frozen artifact is removed or `reuse_results` is disabled. It is
measured on isolated real OSS checkouts and a scanner-specific negative-control
manifest whose source root contains only the negative-control fixture, not the
VeriSec project checkout. Each run also writes an artifact index with SHA-256
hashes for the manifest, portfolio, scanner baselines, optional scanner
executions or reused scanner artifacts, benchmark matrix, dashboard, case
audits, evaluation, and gate outputs.

The release profile uses portable frozen CodeQL artifacts for fast CI and demo
runs. [verisec_portfolio.nightly.json](verisec_portfolio.nightly.json) reruns
Semgrep and CodeQL live against the same positive and isolated negative-control
cases so scanner drift can be measured without destabilizing the release gate.
After a passed nightly run and passed attestation, `scripts/promote_nightly_artifacts.py`
freezes the live scanner outputs back into portable release baselines and can
copy a passed release benchmark snapshot into `docs/`.
`scripts/check_benchmark_freshness.py` then guards that snapshot in CI, failing
when the published figures no longer match a live run. See
[docs/PORTFOLIO_PROFILES.md](docs/PORTFOLIO_PROFILES.md).

Scanner baseline entries can either point at captured artifacts:

```json
{"label": "semgrep-oss", "adapter": "semgrep", "cases": "cases.json", "results": "semgrep.json"}
```

or run the scanner during the portfolio command:

```json
{"label": "semgrep-live", "adapter": "semgrep", "cases": "cases.json", "run": true}
```

Long-running scanners can opt into artifact reuse. With `reuse_results: true`,
portfolio first looks for `reuse_from`, then the configured `results` path, then
the previous `scanner-runs/<label>/scanner_results.json` under the same output
directory. If the artifact is present it is scored and indexed without rerunning
the scanner; if it is absent, the scanner executes normally and writes a fresh
result.

```json
{"label": "codeql-live", "adapter": "codeql", "cases": "cases.json", "run": true, "reuse_results": true, "reuse_from": "examples/baselines/codeql_frozen.json"}
```

For CodeQL, omit `command` to use the built-in Python SARIF sequence, or provide
custom `steps` for another language/query suite.

```powershell
python -m verisec_agent portfolio `
  --manifest verisec_portfolio.json `
  --out verisec-runs/release-portfolio `
  --github-step-summary
```

`verisec attest` verifies an artifact index by recomputing every recorded byte
size and SHA-256.

```powershell
python -m verisec_agent attest `
  --index verisec-runs/release-portfolio/artifact_index.json `
  --out verisec-runs/release-portfolio-attestation
```

`verisec pr-comment` turns a single review report or batch evaluation into a
stable Markdown body for a GitHub PR bot or workflow step.

```powershell
python -m verisec_agent pr-comment `
  --evaluation verisec-runs/demo-eval/evaluation.json `
  --gate verisec-runs/demo-gate/gate.json `
  --out verisec-runs/demo-pr-comment.md
```

`verisec github-comment` creates or updates the existing PR comment that carries
the VeriSec marker. It reads `GITHUB_REPOSITORY`, `GITHUB_TOKEN`,
`GITHUB_API_URL`, and `GITHUB_EVENT_PATH` in GitHub Actions, while still allowing
explicit `--repo` and `--pr` values for trusted local or bot runs.

```powershell
python -m verisec_agent github-comment `
  --body verisec-runs/demo-pr-comment.md `
  --repo owner/repo `
  --pr 123 `
  --dry-run
```

The included CI workflow uses a safer two-job pattern: the untrusted PR code only
generates and uploads the comment artifact, then a separate minimal-permission
job updates the sticky PR comment for same-repository pull requests. On PR
events, the workflow reviews the actual pull request diff via `gh pr diff`,
gates the resulting `report.json`, and renders the PR comment from that report.
On push events, it runs the release portfolio manifest as a one-command
regression gate across demo, OSS seed, and negative-control suites, then attests
the generated artifact index. Gate steps write JSON before failing, so failures
remain auditable.

The separate nightly scanner-drift workflow runs only on the default branch via
`schedule` or `workflow_dispatch`. It bootstraps Semgrep and CodeQL, runs the
live nightly profile, attests artifacts, promotes frozen scanner baselines, reruns
the fast release profile, and opens a `cyb/verisec-nightly-promotion-*` PR only
when baseline or benchmark files changed.

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
    |
    v
CI gate + PR comment
    |
    v
Sticky GitHub review comment
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the execution profile threat
model. See [docs/ROADMAP.md](docs/ROADMAP.md) for the project direction.

## Design principles

- Evidence first: every finding points to concrete changed lines.
- Context aware: findings include surrounding repository source when available.
- Verification over vibes: reports include command traces and failure modes.
- Tool-aware validation: declared capabilities identify candidate tools, while
  coverage requires matching structured evidence.
- Calibrated confidence: findings separate base rule confidence from
  verification-informed reviewer confidence.
- Governed execution: verification tools are checked against adapter, timeout,
  availability, and blocked-pattern policy before execution.
- Reviewer-facing by default: each finding links risk, evidence, fix guidance, and
  validation coverage.
- PR-ready by default: review and evaluation outputs can be rendered into a
  stable comment body for workflow integration.
- Bot-friendly deployment: the same marker lets GitHub workflows or trusted
  publishers update one sticky review comment instead of creating noise.
- Low noise by construction: findings carry confidence and a false-positive
  rationale field.
- Auditability: every major step is recorded in a portable bundle.
- Deployment path: the core loop is independent from GitHub bots, CLIs, and UIs.
