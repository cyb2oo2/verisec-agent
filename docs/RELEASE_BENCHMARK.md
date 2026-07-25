# VeriSec Benchmark Matrix

| System | Status | Positive Cases | Negative Controls | Primary Recall | Primary Precision | Findings | Raw | Out Scope | Validation | Tool Evidence | Neg Ctrl Violations | Notes |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| VeriSec Agent | measured | 3 | 15 | 1.00 | 0.50 | 8 | 8 | 0 | 1.00 | 1.00 | 0 | AST/dataflow hypotheses with evidence-backed validation bundles. |
| VeriSec Agent promoted CVEs | verification-only | 6 | 15 | n/a | 0.00 | 0 | 0 | 0 | 1.00 | 0.00 | 0 | Verification-only: the patch-literal signatures were retired (DEVELOPMENT_LOG.md D-022); VeriSec reports no generalizable detection here. Each fix is confirmed present by a property-check. Not a detection measurement. |
| Semgrep baseline | measured | 3 | 10 | 0.00 | 0.00 | 0 | 44 | 44 | 1.00 | 0.00 | 0 | Semgrep-compatible captured JSON artifacts scored with the same expected-finding labels. |
| CodeQL baseline | measured | 3 | 10 | 0.00 | 0.00 | 0 | 10 | 10 | 1.00 | 0.00 | 0 | CodeQL Python security SARIF profile scored from frozen reusable scanner artifacts; live CodeQL reruns on cache miss. |

## Claim Boundaries

- These metrics describe a curated benchmark of 3 OSS seed cases, 6 promoted CVE cases, and 15 negative controls; they are not estimates of recall or precision on arbitrary real-world repositories.
- Semgrep and CodeQL rows measure patch-overlap against this benchmark's labels for the recorded configurations. A zero recall here means those configurations did not match the labeled changed lines, not that VeriSec universally outperforms either scanner.
- The promoted-CVE row is verification-only: the patch-literal signatures that previously scored it were retired (DEVELOPMENT_LOG.md D-022, extending D-015/D-016), so VeriSec reports no generalizable detection on these cases. They are retained because each fix is independently confirmed present by a property-check (validation coverage 1.0). The row makes no detection-quality claim and is not comparable to the scanner rows.
- The fast release profile may score captured or reused scanner artifacts for reproducibility. The nightly profile reruns the scanners live to measure tool and query-pack drift.
