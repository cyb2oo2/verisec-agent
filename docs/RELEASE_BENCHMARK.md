# VeriSec Benchmark Matrix

| System | Status | Positive Cases | Negative Controls | Primary Recall | Primary Precision | Findings | Raw | Out Scope | Validation | Tool Evidence | Neg Ctrl Violations | Notes |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| VeriSec Agent | measured | 3 | 15 | 1.00 | 0.50 | 8 | 8 | 0 | 1.00 | 1.00 | 0 | AST/dataflow hypotheses with evidence-backed validation bundles. |
| VeriSec Agent promoted CVEs | illustrative | 6 | 15 | 1.00 | 0.64 | 11 | 11 | 0 | 1.00 | 1.00 | 0 | Illustrative, not a detection measurement: recall reflects regex signatures matching the scored patches' literal text (DEVELOPMENT_LOG.md D-015), not detection that generalizes. |
| Semgrep baseline | measured | 3 | 10 | 0.00 | 0.00 | 0 | 2 | 2 | 1.00 | 0.00 | 0 | Semgrep-compatible captured JSON artifacts scored with the same expected-finding labels. |
| CodeQL baseline | measured | 3 | 10 | 0.00 | 0.00 | 0 | 10 | 10 | 1.00 | 0.00 | 0 | CodeQL Python security SARIF profile scored from frozen reusable scanner artifacts; live CodeQL reruns on cache miss. |

## Claim Boundaries

- These metrics describe a curated benchmark of 3 OSS seed cases, 6 promoted CVE cases, and 15 negative controls; they are not estimates of recall or precision on arbitrary real-world repositories.
- Semgrep and CodeQL rows measure patch-overlap against this benchmark's labels for the recorded configurations. A zero recall here means those configurations did not match the labeled changed lines, not that VeriSec universally outperforms either scanner.
- The promoted-CVE row's primary recall is produced by regex rules whose patterns match identifiers, constants, or test names introduced by the specific patches being scored; the semantic AST/dataflow layer contributes no promoted finding. It measures signature coverage of these curated cases, not detection that generalizes to unseen patches, and should not be read as a like-for-like detection-quality comparison against the scanner rows. See DEVELOPMENT_LOG.md D-015.
- The fast release profile may score captured or reused scanner artifacts for reproducibility. The nightly profile reruns the scanners live to measure tool and query-pack drift.
