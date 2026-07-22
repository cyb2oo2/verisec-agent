# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Plugin spine: `RuleProvider` / `AdapterSpec` registries, `[rules].packs`,
  `[adapters].paths`, Django rule pack, Bandit + pip-audit TOML adapters
- setuptools entry points group `verisec.rules` for installable rule packs
- Operator surface: `verisec init`, human-friendly `review` summary, CLI command
  grouping (operator / CI / lab), alias `review` → `r`
- `docs/OPERATOR.md` day-to-day guide
- Phase 1 detector: `py-unicode-normalization-dos` with length-guard dominance
  and complexity-dos family separation from ReDoS
- Phase 2 class-based ReDoS: `is_redos_prone`, pattern-delta hardening
  (`py-regex-redos-hardening`), introduces-risk (`py-regex-redos`)
- Full-file AST analysis, same-file return taint, dataflow steps on findings
- SARIF 2.1.0 export as `report.sarif` in every review bundle
- `docs/VALIDATION_EVIDENCE.md` and `examples/validation_evidence_stub.py`
- Holdout post-fix measurement docs (`docs/HOLDOUT_POSTFIX.md`)
- `CONTRIBUTING.md`, `SECURITY.md`
- Negative control `negative-redos-triple-quoted` and paired unit tests covering
  `scan_mode = "python-text"` rules. The existing triple-quoted control exercises
  `shell=True`, a `python-code` rule, and could not reach them. The published
  negative-control count moves 11 → 12 in the regenerated benchmark snapshot. This is
  a coverage addition, not a detection improvement: no detector behavior changed, and
  primary recall, precision, findings, and validation coverage are unchanged — only
  the control denominator grew.

- Holdout 2 (`docs/HOLDOUT_2.md`, `examples/holdout_2_cases.json`): a second blind evaluation,
  8 verified upstream cases in three groups, frozen at detector commit `0ca2df5` and run once.
  Result: 0 findings across all 8 cases, primary recall 0/2, zero false positives. Both primary
  ReDoS cases missed structurally (the rule matches a narrow call-site syntax real fixes rarely
  use). Detectors are not tuned against these now-burned cases
- Self-history noise corpus (`examples/self_history_cases.json`): every parented commit on
  this repository's `origin/main` replayed as a benign change with no expected findings,
  wired into the release portfolio as the `self-history-noise` suite. Measures 22 findings
  across 18 commits, 14 of them clean; runs offline against the local checkout
- `max_findings` gate threshold, plus `verisec gate --max-total-findings`, for ratcheting a
  total finding count where rate thresholds saturate because nothing is expected
- Benchmark `claim_boundaries` accept `{system label:metric}` references, resolved from
  the computed matrix rows so quoted counts cannot contradict the table they qualify. An
  unknown system, unknown metric, or unmeasured metric fails the portfolio run
- `scripts/check_benchmark_freshness.py` compares a generated benchmark matrix against
  the snapshot in `docs/`, wired into CI after the release portfolio step
- Tests asserting the published benchmark surfaces agree: `docs/RELEASE_BENCHMARK.md`
  against `docs/release_benchmark_matrix.json`, and README's hand-transcribed table
  against both

### Changed

- ReDoS shape detection now recognizes the greedy adjacent-wildcard polynomial class
  (`.*.*`, the canonical `.*.*=.*` form), previously missed. Greedy-only by design, with a
  paired negative control (`.*foo.*` contains-forms stay linear/quiet)
- SQL injection detection generalized beyond patch-literal matching: string concatenation of a
  SQL literal with tainted data now fires, and the ORM raw-query sink (`.raw`, plus
  `.executescript`) is recognized — taint-gated, not Django-specific. Negative controls 12 → 15
- README restructured for operator-first onboarding; lab commands deferred
- ReDoS regex fallback no longer treats bare `max_length` / length bounds as ReDoS
- Benchmark claim boundaries now disclose that the promoted-CVE row's primary recall
  reflects regex signatures matching the scored patches' literal text, not detection that
  generalizes; it is not a like-for-like comparison with the scanner rows. No benchmark
  number changed
- Promoted-CVE benchmark row relabeled from `measured` to `illustrative`, so it no longer
  reads as a detection measurement; its metrics stay visible. Adds a `display_status`
  benchmark-manifest field that may only demote a computed-measured row, never inflate one.
  No benchmark number changed

### Removed

- `django-cve-2023-36053` demoted from the promoted CVE suite. Its expected finding
  is a regex pattern-delta rule, but the CVE's fix adds length guards and changes no
  regex, so it was never detected at any commit. It stays in the audit-only candidate
  queue. The published benchmark claimed 1.00 primary recall over 7 promoted cases;
  that figure did not reproduce. Regenerated from a passed, attested portfolio run:
  6 cases, 1.00 recall, 0.64 precision.

### Fixed

- Verification commands whose argv contains braces that are not VeriSec placeholders
  — a `{1,36}` regex quantifier, a JSON literal, an f-string inside a `-c` script — now
  render and run instead of aborting the review. Only the defined `{python}` / `{tool_dir}`
  placeholders are expanded; every other brace is preserved verbatim
- Evaluation cases materialized from a local `repo` plus `base_ref` / `head_ref` (no
  `repo_url`) now review an isolated checkout at `head_ref` instead of the caller's working
  tree at whatever `HEAD` happened to be. Multi-line string masking, which resolves spans by
  patched-file line number, no longer consults the wrong revision when `head_ref != HEAD`
- Parameterized SQL using `%s` / `%(name)s` DB-API placeholders
  (`execute("... = %s", params)`) is no longer flagged as SQL string formatting. The regex
  fallback matched any `SELECT ... %`; it now matches string-then-% formatting only, and real
  `%`-formatting injection is caught precisely and taint-gated by the semantic layer
- Regex fallback no longer reports code samples embedded in multi-line strings as
  real call sites. String spans are resolved from the checked-out file when
  available, so a triple-quoted sample cut short by an evidence window is still
  recognized as string data. Semantic (AST/dataflow) detection is unchanged.
- New negative control `negative-shell-triple-quoted` covering the triple-quoted
  case; the existing docs control only covered single-line literals.

## [0.1.0] - 2026-06-10

### Added

- Initial VeriSec Agent CLI: review, replay, tools, evaluation, gates, portfolio
- Evidence bundles, policy profiles, scanner baselines, holdout pilot protocol
- MIT license
