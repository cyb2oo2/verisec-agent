# Case Studies

This document tracks real repository security-review cases used to pressure-test
VeriSec Agent beyond toy diffs.

## MkDocs GHSL-2023-208

- Project: `mkdocs/mkdocs`
- Source advisory: https://securitylab.github.com/advisories/GHSL-2023-208_MkDocs/
- Upstream patch: https://github.com/mkdocs/mkdocs/pull/3465
- Base ref: `dc45916aa1cc4b4d4796dd45656bd1ff60d4ce44`
- Head ref: `47e41a9a0ebc097fb45899ca57edc4d005b7b154`
- Vulnerability class: unsafe YAML deserialization / object construction
- Expected VeriSec signal: `py-yaml-safe-loader`
- Verification: `mkdocs-yaml-safeloader-property` checks that the patched tree
  constrains `mkdocs_theme.yml` parsing to `SafeLoader`.

Current local seed result:

- Findings: 1
- Primary findings: 1
- Supporting findings: 0
- Validation coverage: 1.00
- Expected rule recall: 1.00
- Expected rule precision: 1.00
- Expected finding recall: 1.00
- Gate: passed with zero policy-blocked tools and zero validation gaps.

## PyYAML PR #74 / CVE-2017-18342

- Project: `yaml/pyyaml`
- Source advisory: https://github.com/advisories/GHSA-rprw-h62v-c2w7
- Upstream patch: https://github.com/yaml/pyyaml/pull/74
- Base ref: `d856c206fd4bfd71254e0d69e9d5e31bef5d2c0f`
- Diff URL: https://github.com/yaml/pyyaml/pull/74.diff
- Vulnerability class: unsafe YAML deserialization / object construction
- Expected VeriSec signals: `py-yaml-safe-loader`, `py-unsafe-yaml`
- Verification: `pyyaml-safe-default-property` checks that the patched tree makes
  `load` safe by default and exposes the previous unsafe behavior separately as
  `danger_load`.

This case uses `diff_url` plus `base_ref`, because the historical PR head commit
is no longer reliably fetchable from a normal upstream clone. VeriSec checks out
the base tree, applies the PR diff into an isolated materialized clone, and then
reviews the patched tree. This mirrors a common real-world problem in older CVE
and PR corpora.

Current local seed result:

- Findings: 6
- Primary findings: 2
- Supporting findings: 4
- Validation coverage: 1.00
- Expected rule recall: 1.00
- Expected rule precision: 1.00
- Expected finding recall: 1.00
- Gate: passed with zero policy-blocked tools and zero validation gaps.

## sqlparse GHSL-2021-107 / CVE-2021-32839

- Project: `andialbrecht/sqlparse`
- Source advisory: https://securitylab.github.com/advisories/GHSL-2021-107-andialbrecht-sqlparse/
- Upstream patch: https://github.com/andialbrecht/sqlparse/commit/8238a9e450ed1524e40cb3a8b0b3c00606903aeb
- Base ref: `e66046785b816e5c2d22f101f36faefd19c4a771`
- Head ref: `8238a9e450ed1524e40cb3a8b0b3c00606903aeb`
- Vulnerability class: regular expression denial of service
- Expected VeriSec signal: `py-regex-redos-hardening`
- Verification: `sqlparse-redos-regex-property` checks that the patched tree uses
  the hardened line-break regex and no longer contains the vulnerable
  `(\r\n|\r|\n)+` alternative.

Current local seed result:

- Findings: 1
- Primary findings: 1
- Supporting findings: 0
- Validation coverage: 1.00
- Expected rule recall: 1.00
- Expected rule precision: 1.00
- Expected finding recall: 1.00
- Gate: passed with zero policy-blocked tools and zero validation gaps.

## Seed Portfolio

Current portfolio result across the three seed cases:

- Case audit: 3/3 ready, 0 blocked, 0 warnings, 3 verification-ready cases.
- Cases: 3
- Findings: 8
- Accepted finding rate: 1.00
- Primary precision: 0.50
- Primary finding recall: 1.00
- Supporting evidence rate: 0.50
- Unexpected finding rate: 0.00
- Negative-control violations: 0
- Validation coverage: 1.00
- Expected rule recall: 1.00
- Expected rule precision: 1.00
- Expected finding recall: 1.00
- CVE/advisory cases: 3
- Benchmark matrix: VeriSec Agent row is measured against these three positive
  cases and the 10-case negative-control suite. The Semgrep artifact baseline is
  also measured on the same labels: 2 raw findings, 2 out-of-scope findings,
  primary recall 0.00, primary precision 0.00, validation coverage 1.00, tool
  evidence rate 0.00, and zero negative-control violations. The fast CodeQL row
  uses reusable frozen SARIF-derived artifacts: 10 raw findings, 10 out-of-scope
  findings, primary recall 0.00, primary precision 0.00, validation coverage
  1.00, tool evidence rate 0.00, and zero negative-control violations. These
  scanner rows are patch-overlap measurements for recorded configurations, not
  claims that one scanner universally dominates another.

Run it with:

```powershell
python -m verisec_agent case-audit `
  --cases examples/oss_seed_cases.json `
  --out verisec-runs/oss-seed-audit `
  --require-verification `
  --fail-on-blocked

python -m verisec_agent eval `
  --cases examples/oss_seed_cases.json `
  --out verisec-runs/oss-seed-3 `
  --fail-fast

python -m verisec_agent gate `
  --evaluation verisec-runs/oss-seed-3/evaluation.json `
  --out verisec-runs/oss-seed-3-gate `
  --min-validation-coverage 1.0 `
  --min-avg-confidence 0.6 `
  --min-accepted-finding-rate 1.0 `
  --min-primary-precision 0.5 `
  --min-primary-finding-recall 1.0 `
  --min-supporting-evidence-rate 0.5 `
  --max-unexpected-finding-rate 0.0 `
  --max-negative-control-violations 0 `
  --max-policy-blocked 0 `
  --max-validation-gap-rate 0.0

python -m verisec_agent scanner-baseline `
  --cases examples/oss_seed_cases.json `
  --results examples/baselines/semgrep_oss_seed.json `
  --out verisec-runs/semgrep-oss

python -m verisec_agent scanner-run `
  --cases examples/oss_seed_cases.json `
  --out verisec-runs/semgrep-live

python -m verisec_agent scanner-run `
  --adapter codeql `
  --cases examples/oss_seed_cases.json `
  --out verisec-runs/codeql-live
```

## Negative-Control Suite

The adversarial negative-control suite tracks near misses that should not create
review noise: `shell=False`, `verify=True`, parameterized SQL, SHA-256, bounded
regexes, `ast.literal_eval`, explicit YAML `SafeLoader`, and dangerous patterns
that appear only in comments or string literals.

Current local result:

- Case audit: 10/10 ready, 0 blocked, 0 warnings.
- Cases: 10
- Findings: 1
- Benign findings: 1
- Accepted finding rate: 1.00
- Unexpected finding rate: 0.00
- Negative-control violations: 0
- Expected rule recall: 1.00
- Expected finding recall: 1.00
- Gate: passed with zero unexpected findings and zero negative-control
  violations.

Run it with:

```powershell
python -m verisec_agent case-audit `
  --cases examples/negative_control_cases.json `
  --out verisec-runs/negative-controls-audit `
  --fail-on-blocked

python -m verisec_agent eval `
  --cases examples/negative_control_cases.json `
  --out verisec-runs/negative-controls `
  --fail-fast

python -m verisec_agent gate `
  --evaluation verisec-runs/negative-controls/evaluation.json `
  --out verisec-runs/negative-controls-gate `
  --min-accepted-finding-rate 1.0 `
  --max-unexpected-finding-rate 0.0 `
  --max-negative-control-violations 0 `
  --max-errors 0 `
  --max-policy-blocked 0
```

## Release Matrix

The regression dashboard combines the demo smoke test, real OSS security seed
portfolio, promoted CVE suite, and adversarial negative-control suite into one
deployability view.

Current local dashboard result:

- Suites: 4
- Total cases: 21
- Total findings: 23
- Gates passed: 4/4
- Regressions: 0
- Artifact index: generated with SHA-256 hashes for manifest, portfolio, case
  audits, scanner baselines, dashboard, evaluation, and gate artifacts.
- Attestation: passed across the indexed release artifacts with zero failures.

Run it with:

```powershell
python -m verisec_agent dashboard `
  --evaluation demo=verisec-runs/demo-eval/evaluation.json `
  --gate demo=verisec-runs/demo-gate/gate.json `
  --evaluation oss-seed=verisec-runs/oss-seed-3/evaluation.json `
  --gate oss-seed=verisec-runs/oss-seed-3-gate/gate.json `
  --evaluation promoted-cves=verisec-runs/promoted-cves/evaluation.json `
  --gate promoted-cves=verisec-runs/promoted-cves-gate/gate.json `
  --evaluation negative-controls=verisec-runs/negative-controls/evaluation.json `
  --gate negative-controls=verisec-runs/negative-controls-gate/gate.json `
  --out verisec-runs/regression-dashboard
```

## One-Command Release Gate

The portfolio manifest runs the demo, OSS seed, promoted CVE, and
negative-control suites through case audit, eval, gate, and dashboard in one
command.

Current local portfolio result:

- Status: passed
- Suites: 4
- Total cases: 21
- Total findings: 23
- Gates passed: 4/4
- Regressions: 0
- Case audits: enabled for each measured suite; blocked cases fail the release
  gate while warnings remain visible in `portfolio.md`.
- Promoted CVEs: 7/7 completed with expected-rule recall, expected-finding
  recall, validation coverage, and tool evidence all at 1.00.
- Promoted CVE cache/resume check: the 7-case promoted suite reused 2 source
  cache repositories across Django and sqlparse, passed the strict gate, then
  reran with `--resume` from existing case bundles while preserving the same
  aggregate metrics.
- Candidate intake: 9 audit-only CVE/security-release candidates are tracked in
  `examples/candidate_cases.json` and reported by the portfolio without being
  counted as measured benchmark performance unless also present in
  `examples/promoted_candidate_cases.json`.
- Candidate promotion: `verisec case-promote` currently reports 0 newly
  eligible cases, 7 already promoted cases, and 2 blocked cases; the blockers are
  missing verification configs and evaluation evidence, not missing source or
  advisory metadata.
- Release attestation: 43/43 indexed artifacts passed SHA-256 and byte-size
  verification with zero failures.
- Scanner baselines: Semgrep artifact suites and frozen CodeQL SARIF-derived
  artifacts feed the fast release benchmark matrix.
- Release scanner mode: `verisec_portfolio.json` reuses portable frozen CodeQL
  artifacts and records source mode as `reused`, while keeping live rerun
  fallback on cache miss.
- Nightly scanner mode: `verisec_portfolio.nightly.json` reruns Semgrep and
  CodeQL live against the OSS seed suite and isolated scanner negative controls.

Run it with:

```powershell
python -m verisec_agent portfolio `
  --manifest verisec_portfolio.json `
  --out verisec-runs/release-portfolio

python -m verisec_agent portfolio `
  --manifest verisec_portfolio.nightly.json `
  --out verisec-runs/nightly-portfolio

python -m verisec_agent attest `
  --index verisec-runs/release-portfolio/artifact_index.json `
  --out verisec-runs/release-portfolio-attestation
```
