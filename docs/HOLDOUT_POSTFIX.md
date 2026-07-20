# VeriSec Holdout Post-Fix Measurement

This document records a **post-detector-change re-run** of the same frozen
holdout cases used in [HOLDOUT_PILOT.md](HOLDOUT_PILOT.md). It measures the
Phase 1 (Unicode normalization DoS) and Phase 2 (class-based ReDoS) detectors
against the original two-case partition.

It does **not** replace the pilot. The pilot at detector freeze `d9754d0`
remains the historical blind result. This note is an explicit post-fix
measurement on observed cases and must not be marketed as a new blind holdout.

## Protocol

| Field | Value |
| --- | --- |
| Split | `holdout` (same cases as pilot) |
| Pilot freeze | `2026-06-10` at detector commit `d9754d0` |
| Post-fix measurement date | `2026-07-21` |
| Base git commit (workspace) | `cd7518e` on branch `cyb/release-hardening` |
| Detector changes since pilot | Phase 1 Unicode complexity-dos + Phase 2 class-based ReDoS (local working tree at measurement time) |
| Manifest | `verisec_portfolio.holdout.json` |
| Output | `verisec-runs/holdout-postfix/` |
| Cases | Unchanged: Django CVE-2023-46695, mechanize 0.4.6 |

Reproduction:

```powershell
python -m verisec_agent portfolio `
  --manifest verisec_portfolio.holdout.json `
  --out verisec-runs/holdout-postfix `
  --policy-profile trusted-ci

python -m verisec_agent attest `
  --index verisec-runs/holdout-postfix/artifact_index.json `
  --out verisec-runs/holdout-postfix-attestation
```

## What changed in the detector

1. **`py-unicode-normalization-dos`** (Phase 1)  
   Full-file AST detection of `unicodedata.normalize` with length-guard
   dominance, family `complexity-dos`, modes `adds-hardening` /
   `introduces-risk`. Suppresses ReDoS confusion on the same window.

2. **Class-based ReDoS** (Phase 2)  
   `is_redos_prone`, pattern-delta hardening → `py-regex-redos-hardening`,
   introduces-risk → `py-regex-redos`, full-file pattern bindings, family
   `redos`.

## Results (post-fix)

| Metric | Pilot (`d9754d0`) | Post-fix (Phase 1–2) |
| --- | ---: | ---: |
| Cases | 2 | 2 |
| Findings | 1 | 2 |
| Primary finding recall | 0.00 | **1.00** |
| Primary precision | 0.00 | **1.00** |
| Unexpected finding rate | 1.00 | **0.00** |
| Validation coverage | (verified patches 2/2) | **1.00** |
| Tool evidence rate | — | **1.00** |
| Avg confidence | — | **0.88** |
| Verification commands passed | 2/2 | **2/2** |
| Strict gate | failed (8 failures) | **passed** |
| Partition overlap | 0/10 | **0/10** |
| Case audit blocked/warnings | — | **0 / 0** |
| Classified detector failures | 2 | **0** |

Machine-readable snapshot: [holdout_postfix.json](holdout_postfix.json).  
Artifacts: `verisec-runs/holdout-postfix/` (evaluation, gate, failure analysis,
benchmark matrix, artifact index).

## Per-case outcomes

| Case | Class | Pilot | Post-fix |
| --- | --- | --- | --- |
| Django CVE-2023-46695 | Unicode normalization complexity DoS | wrong rule (`semantic-rule-confusion`) | **`py-unicode-normalization-dos`** at `django/contrib/auth/forms.py` (mode `adds-hardening`, scope `file`, confidence 0.92) |
| mechanize 0.4.6 | WWW-Authenticate ReDoS | no finding (`undetected-labeled-location`) | **`py-regex-redos-hardening`** at `mechanize/_urllib2_fork.py` (mode `adds-hardening`, scope `window`, confidence 0.84) |

Both property checks still pass (patch verification independent of detector
quality).

## Failure taxonomy

| Category | Pilot | Post-fix |
| --- | ---: | ---: |
| `semantic-rule-confusion` | 1 | **0** |
| `undetected-labeled-location` | 1 | **0** |
| Cases with failures | 2 | **0** |

## Claim boundary

- The **pilot** is still the blind protocol result at `d9754d0`.
- This post-fix run **used cases that were already observed** after the pilot.
  It demonstrates that Phase 1–2 close the documented failure classes; it is
  **not** a new frozen blind holdout and must not be cited as unbiased
  generalization evidence.
- Production claims should still rely on measured OSS seed / promoted suites
  plus a **new untouched holdout partition** for future detector work.
- Claim text from the portfolio matrix about “blind evaluation at d9754d0”
  describes the case selection history, not the detector version used in this
  re-run.

## Next steps

1. Commit Phase 1–2 detector changes so post-fix measurements pin a clean SHA.
2. Freeze a **new** holdout partition before further detector tuning.
3. Optionally refresh README holdout snapshot to show pilot + post-fix side by
   side without overwriting the historical pilot failure.
