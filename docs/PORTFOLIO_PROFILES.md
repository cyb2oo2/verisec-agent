# VeriSec Portfolio Profiles

VeriSec uses two portfolio profiles so release checks stay fast while live
scanner drift remains measurable.

## Fast release profile

Manifest: `verisec_portfolio.json`

Use this profile for CI pushes, portfolio demos, and application review. It runs
the agent suites, gates, dashboard, benchmark matrix, and artifact index, then
scores scanner baselines from portable captured artifacts where possible.

The `self-history-noise` suite replays this repository's own `origin/main`
commits as benign changes and gates their total finding count, so reviewer noise
on real diffs cannot regress unnoticed. It materializes from the local checkout
rather than a remote, so it adds no network dependency — but it does add roughly
five minutes to the profile, which is why the profile stays off the pull-request
path (D-013).

```powershell
python -m verisec_agent portfolio `
  --manifest verisec_portfolio.json `
  --out verisec-runs/release-portfolio `
  --policy-profile trusted-ci

python -m verisec_agent attest `
  --index verisec-runs/release-portfolio/artifact_index.json `
  --out verisec-runs/release-portfolio-attestation
```

Expected scanner source modes:

| Baseline | Source |
| --- | --- |
| Semgrep OSS seed | `provided` captured Semgrep JSON |
| Semgrep negative controls | `provided` captured Semgrep JSON over isolated scanner controls |
| CodeQL OSS seed | `reused` frozen SARIF-derived scanner artifact |
| CodeQL negative controls | `reused` frozen SARIF-derived scanner artifact |

The current release benchmark snapshot is checked in at
`docs/release_benchmark_matrix.json` and `docs/RELEASE_BENCHMARK.md`.
Its metrics apply only to the curated cases named in the manifest. Scanner
comparisons are patch-overlap measurements for recorded configurations, not
claims of universal superiority or estimates of production recall.

CI verifies that snapshot against the run it just produced:

```powershell
python scripts/check_benchmark_freshness.py `
  --generated verisec-runs/release-portfolio/benchmark-matrix
```

It exits non-zero with a diff when the checked-in figures no longer match a live
run, so a suite composition change that was never republished fails rather than
publishing silently. Counts quoted in `claim_boundaries` prose are resolved from
the computed rows via `{system label:metric}` references, so the disclaimer
cannot contradict the table beside it.

## Live nightly profile

Manifest: `verisec_portfolio.nightly.json`

Use this profile for scheduled or manual drift checks. It reruns Semgrep and
CodeQL instead of using frozen scanner artifacts, then scores those live scanner
outputs with the same diff-aware evaluator and isolated scanner negative
controls.

```powershell
python -m verisec_agent portfolio `
  --manifest verisec_portfolio.nightly.json `
  --out verisec-runs/nightly-portfolio `
  --policy-profile trusted-ci

python -m verisec_agent attest `
  --index verisec-runs/nightly-portfolio/artifact_index.json `
  --out verisec-runs/nightly-portfolio-attestation
```

Expected scanner source modes:

| Baseline | Source |
| --- | --- |
| Semgrep live OSS seed | `executed` live scanner run |
| Semgrep live negative controls | `executed` live scanner run |
| CodeQL live OSS seed | `executed` live scanner run |
| CodeQL live negative controls | `executed` live scanner run |

Nightly output is allowed to be slower and more environment-sensitive. Its job
is to detect scanner drift, missing tools, query-pack changes, and upstream repo
materialization failures without destabilizing the fast release gate.

## Promotion rule

Refresh frozen scanner artifacts only from a successful live run whose
attestation passes. The portable frozen artifacts should not contain local
absolute paths; they should keep inline scanner payloads, inline diffs, and
enough command provenance to explain how they were produced.

```powershell
python scripts/promote_nightly_artifacts.py `
  --nightly-dir verisec-runs/nightly-portfolio `
  --attestation verisec-runs/nightly-portfolio-attestation `
  --release-dir verisec-runs/release-portfolio `
  --out verisec-runs/nightly-promotion
```

Promotion writes `promotion.json` and `promotion.md`, updates the portable
scanner baselines under `examples/baselines/`, and copies the release benchmark
snapshot into `docs/release_benchmark_matrix.json` and
`docs/RELEASE_BENCHMARK.md` only after the release portfolio also passed. The
fast release profile should then be rerun and attested before committing the
new baseline artifacts.

The scheduled GitHub Actions workflow follows this rule automatically: it runs
the live nightly profile, attests it, refreshes portable baselines, reruns the
fast release profile with those baselines, attests the release artifacts, and
opens a promotion PR only when checked-in baseline or benchmark files changed.
