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

- Benchmark `claim_boundaries` accept `{system label:metric}` references, resolved from
  the computed matrix rows so quoted counts cannot contradict the table they qualify. An
  unknown system, unknown metric, or unmeasured metric fails the portfolio run
- `scripts/check_benchmark_freshness.py` compares a generated benchmark matrix against
  the snapshot in `docs/`, wired into CI after the release portfolio step
- Tests asserting the published benchmark surfaces agree: `docs/RELEASE_BENCHMARK.md`
  against `docs/release_benchmark_matrix.json`, and README's hand-transcribed table
  against both

### Changed

- README restructured for operator-first onboarding; lab commands deferred
- ReDoS regex fallback no longer treats bare `max_length` / length bounds as ReDoS

### Removed

- `django-cve-2023-36053` demoted from the promoted CVE suite. Its expected finding
  is a regex pattern-delta rule, but the CVE's fix adds length guards and changes no
  regex, so it was never detected at any commit. It stays in the audit-only candidate
  queue. The published benchmark claimed 1.00 primary recall over 7 promoted cases;
  that figure did not reproduce. Regenerated from a passed, attested portfolio run:
  6 cases, 1.00 recall, 0.64 precision.

### Fixed

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
