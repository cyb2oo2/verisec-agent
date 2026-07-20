# VeriSec Holdout Pilot

This is the first explicitly frozen holdout evaluation for VeriSec Agent. It is
designed to test the evaluation protocol and expose detector failures, not to
produce a stable estimate of real-world performance.

## Protocol

- Split: `holdout`
- Frozen: `2026-06-10`
- Detector freeze commit: `d9754d0`
- Cases: 2 real OSS security patches that were not in the measured OSS seed or
  promoted CVE suites at freeze time
- Reference partitions: 3 OSS seed cases and 7 promoted CVE cases
- Partition fingerprints: case ID, CVE/GHSA/advisory, repository base/head
  pair, diff URL, and upstream commit
- Detector changes after case selection: none

The partition audit passed with zero overlap pairs across 10 reference cases.
Both holdout cases passed their patch-specific property checks before detector
performance was interpreted.

## Cases

| Case | Class | Patch Verification | Detector Result |
| --- | --- | --- | --- |
| Django CVE-2023-46695 | Unicode normalization complexity DoS | passed | wrong rule at the correct file |
| mechanize 0.4.6 | WWW-Authenticate regex DoS | passed | no finding |

## Results

| Metric | Value |
| --- | ---: |
| Cases | 2 |
| Findings | 1 |
| Primary finding recall | 0.00 |
| Primary precision | 0.00 |
| Unexpected finding rate | 1.00 |
| Verification commands passed | 2/2 |
| Strict gate | failed |
| Attested artifacts | 17/17 |

The strict gate reported eight failures. These are retained in the portfolio
artifact rather than relaxed for the pilot.

## Failure Taxonomy

| Category | Count | Interpretation |
| --- | ---: | --- |
| `semantic-rule-confusion` | 1 | The Django patch location was found, but a broad ReDoS heuristic mislabeled Unicode normalization complexity hardening. |
| `undetected-labeled-location` | 1 | The mechanize patch and adversarial regression evidence were verified, but no finding was produced at the labeled file. |

This separates pipeline validity from detector quality: source materialization,
property verification, partition isolation, and artifact attestation passed,
while security-semantic generalization failed.

## Reproduction

```powershell
python -m verisec_agent partition-audit `
  --cases examples/holdout_cases.json `
  --against examples/oss_seed_cases.json `
  --against examples/promoted_candidate_cases.json `
  --out verisec-runs/holdout-partition-audit `
  --fail-on-overlap

python -m verisec_agent portfolio `
  --manifest verisec_portfolio.holdout.json `
  --out verisec-runs/holdout-pilot `
  --policy-profile trusted-ci

python -m verisec_agent attest `
  --index verisec-runs/holdout-pilot/artifact_index.json `
  --out verisec-runs/holdout-pilot-attestation
```

The portfolio command is expected to exit non-zero because the strict gate
fails.

## Claim Boundary

This two-case pilot is not a production recall estimate. The cases are now
observed and must not be reused to claim post-hoc detector improvement. Fixes
motivated by this analysis must be measured on a newly frozen, untouched
holdout partition.

## Post-fix remeasurement

Phase 1–2 detector work was later re-run against the **same** cases for
engineering validation only. That measurement is documented separately in
[HOLDOUT_POSTFIX.md](HOLDOUT_POSTFIX.md) and [holdout_postfix.json](holdout_postfix.json).
The pilot numbers above remain the blind protocol result at `d9754d0`.
