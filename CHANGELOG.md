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

### Changed

- README restructured for operator-first onboarding; lab commands deferred
- ReDoS regex fallback no longer treats bare `max_length` / length bounds as ReDoS

## [0.1.0] - 2026-06-10

### Added

- Initial VeriSec Agent CLI: review, replay, tools, evaluation, gates, portfolio
- Evidence bundles, policy profiles, scanner baselines, holdout pilot protocol
- MIT license
