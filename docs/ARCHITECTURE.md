# Architecture

VeriSec Agent is organized around an auditable review loop.

## Core loop

1. Diff ingestion extracts changed files, hunks, and changed lines.
2. Evidence localization creates compact windows around security-relevant
   additions.
3. Repository context expansion reads bounded source windows from the checkout.
4. Hypothesis generation maps evidence to concrete security risks.
5. Tool adapter resolution maps configured checks to commands and capabilities.
6. Verification policy checks allowed adapters, allowed executables, timeout and
   output limits, blocked command patterns, environment mode, network posture,
   execution profile, and unavailable tool warnings.
7. Verification renders commands to argv, executes them with `shell=False`, and
   captures bounded outputs.
8. Tool output parsers normalize scanner results such as Semgrep JSON and
   CodeQL SARIF artifacts.
9. Validation planning links each finding to covered and missing checks. Tool
   capabilities identify candidate tools, while covered status requires
   matching scanner findings or `VERISEC_EVIDENCE:` JSON markers from
   stdout/stderr.
10. Confidence calibration adjusts reviewer-facing confidence from validation
   coverage, missing checks, and matched tool evidence.
11. Reporting emits reviewer-facing findings and a reproducibility bundle.
12. Batch evaluation runs many local or real-repository cases, materializes git
    base/head patches when needed, and aggregates deployment metrics.
13. Case intake audit checks raw evaluation manifests for source
    reproducibility, expected-finding labels, security metadata, tags, duplicate
    IDs, and verification configs before cases enter measured suites.
14. Case promotion planning combines intake audit, existing promoted manifests,
    and optional evaluation evidence so candidate CVE/PR cases can only enter
    measured suites after explicit evidence thresholds pass. Frozen holdout
    cases are permanently blocked from measured promotion.
15. Partition auditing checks holdout case IDs, advisory identities, source
    pairs, diff URLs, and upstream commits against reference manifests.
16. Failure analysis classifies expected misses and unexpected findings into
    semantic rule confusion, rule/location mismatch, undetected labeled
    locations, unexpected findings, and execution errors.
17. CI gating compares report or evaluation metrics against deployment
    thresholds.
18. Regression dashboards compare multiple evaluation suites and optional gates
    into a release matrix, with baseline regression detection.
19. Portfolio release gates run the configured evaluation suites, gates, and
    dashboard from one manifest.
20. Scanner execution can run Semgrep or a custom scanner argv over evaluation
    cases, materialize real repositories, capture stdout/stderr and JSON/SARIF
    artifacts, and record executable/path/exit/duration provenance. Missing
    scanners produce explicit skipped cases.
21. Scanner baseline scoring reads captured Semgrep JSON, CodeQL SARIF, or
    scanner-run manifests and applies the same expected-finding and
    negative-control labels used by VeriSec evaluations.
22. Benchmark-matrix rendering aggregates measured OSS/negative-control suites,
    measured scanner baselines, frozen scanner artifacts, live nightly scanner
    runs, and explicit skipped/not-run rows when tools are unavailable.
23. Artifact integrity indexing records SHA-256 hashes, command metadata,
    runtime environment, and git state for release artifacts.
24. Artifact attestation recomputes recorded byte sizes and SHA-256 hashes to
    detect post-run mutation.
25. PR comment rendering turns the gated result into a stable reviewer-facing
    Markdown body.
26. GitHub Actions can review the actual PR diff, upload the rendered comment
    body as an artifact, and keep the privileged comment-update job isolated
    from untrusted PR code.
27. GitHub comment publishing creates or updates the existing marker-bearing PR
    comment in trusted bot contexts.

The first version uses deterministic rules plus Python AST and lightweight
dataflow analysis so the infrastructure can be tested without relying on an LLM
provider. LLM planning and code-context expansion can be added behind the same
interfaces.

## Package map

- `diff_parser.py`: unified diff parsing and evidence windows.
- `source_context.py`: repository source context expansion around findings.
- `hypotheses.py`: security hypothesis rules, regex fallback, and pack-aware
  `generate_hypotheses` orchestration.
- `rules_api.py` / `rules_builtin.py` / `rules_django.py`: `RuleProvider` plugin
  spine and pack registry (`[rules].packs`), including setuptools entry points
  under the group `verisec.rules`.
- `python_semantics.py`: Python AST parsing, import-alias resolution, parameter
  and web/env taint sources, same-file return-taint summaries, full-file analysis
  when a checkout is available, and sink matching with explicit dataflow steps
  for security hypotheses. Includes complexity-dos detection for Unicode
  normalization (`unicodedata.normalize`) with length-guard dominance, plus
  class-based ReDoS detection (`is_redos_prone`, pattern-delta hardening,
  `re.*` sinks with taint) so redos and complexity-dos families stay distinct.
- `tool_adapters.py`: built-in verification adapters and capability tags.
- `adapters_api.py`: `AdapterSpec` registry, TOML adapter loading
  (`[adapters].paths`), external scanners (Bandit, pip-audit) via
  `parser` fields in TOML.
- `policy.py`: verification governance for trusted and untrusted execution
  profiles, adapter and executable allowlists, timeout/output caps, unavailable
  tools, environment mode, network posture, and blocked command patterns.
- `tool_output.py`: parser for structured scanner output such as Semgrep JSON
  and SARIF.
- `verification.py`: shell-free argv command execution, minimal verification
  environments, output bounding, and trace capture.
- `validation.py`: finding-specific validation coverage planning with
  evidence-backed coverage, candidate tools, scanner finding matches, and
  stdout/stderr validation markers.
- `calibration.py`: verification-informed confidence calibration.
- `reporting.py`: reviewer-facing Markdown report rendering.
- `replay.py`: verification replay from an existing bundle.
- `evaluation.py`: JSON-manifest batch runner and aggregate metrics.
  It supports local diff cases plus real-repository `repo_url`/`base_ref`/
  `head_ref` cases with metadata, expected-finding labels, benign labels, and
  negative-control assertions.
- `case_audit.py`: benchmark-intake audit for source reproducibility,
  expected-finding labels, security metadata, tags, duplicate IDs, and
  verification config readiness.
- `case_promotion.py`: measured-benchmark promotion planner for candidate CVE/PR
  cases, combining audit status, existing promoted manifests, and per-case
  evaluation evidence thresholds, with frozen holdout cases permanently
  excluded from measured promotion.
- `partition_audit.py`: benchmark leakage audit across case identity, advisory,
  source-pair, diff URL, and upstream-commit fingerprints.
- `failure_analysis.py`: machine-readable taxonomy for expected misses,
  unexpected findings, semantic rule confusion, and execution failures.
- `gate.py`: CI-oriented threshold checks for validation, policy, severity, and
  reviewer-noise metrics, plus Markdown summaries.
- `dashboard.py`: release-matrix rendering across evaluation suites, optional
  gate status, and baseline-regression comparison.
- `portfolio.py`: manifest-driven release orchestration for partition audit,
  eval, gate, optional failure analysis, dashboard runs, optional scanner
  execution, and measured/not-run/skipped benchmark matrix rows.
- `scanner_execution.py`: live scanner baseline harness for Semgrep or custom
  argv commands, with per-case artifact capture and skipped-tool provenance.
- `scanner_baseline.py`: standalone scanner artifact evaluator for Semgrep JSON
  and CodeQL/SARIF baselines, scored against expected-finding labels.
- `integrity.py`: artifact index generation and attestation with SHA-256
  hashes, command metadata, runtime environment, and git state.
- `pr_comment.py`: PR-ready Markdown comment rendering for reports and
  evaluations.
- `github_comment.py`: GitHub issue-comment upsert client for sticky PR review
  comments.
- `bundle.py`: portable review bundle layout.
- `agent.py`: orchestration of the review loop.
- `cli.py`: command-line entry point with operator / CI / lab command surfaces.
- `operator.py`: first-run `init` helper and human-friendly review summaries for
  the primary `review` happy path.
- `sarif.py`: SARIF 2.1.0 export of review findings for code-scanning consumers.

## Script map

- `scripts/freeze_scanner_results.py`: converts scanner-run manifests into
  portable baseline JSON by inlining scanner payloads and diffs.
- `scripts/promote_nightly_artifacts.py`: verifies a passed live nightly
  portfolio plus attestation, refreshes frozen release scanner baselines, and
  optionally publishes the current release benchmark snapshot into `docs/`.

## Bundle contract

Every run writes:

- `inputs/diff.patch`: exact reviewed patch.
- `inputs/source.json`: local file, GitHub PR, or URL source metadata.
- `trace.jsonl`: ordered decision and tool events.
- `tools/*.txt`: stdout and stderr from verification commands.
- `report.json`: stable machine-readable review report.
- `report.md`: reviewer-facing report with evidence, fix guidance, calibrated
  confidence, tool capabilities, candidate tools, policy decisions, parsed tool
  findings, and evidence-backed validation coverage.
- `replay/replay.json`: verification replay result when replay is requested.
- `evaluation.json` and `evaluation.md`: batch-level metrics when `verisec eval`
  is used, including materialized case paths, metadata, tag counts, expected-rule
  recall, expected-finding recall, reviewer role labels, primary precision,
  supporting evidence rate, unexpected-finding taxonomy, and negative-control
  violations.
- `case_audit.json` and `case_audit.md`: benchmark-readiness audit outputs when
  `verisec case-audit` is used directly, `verisec portfolio` has
  `case_audits.enabled`, or a portfolio `case_audit_suites` entry tracks an
  audit-only candidate queue.
- `case_promotion.json` and `case_promotion.md`: measured-benchmark promotion
  plan when `verisec case-promote` is used, including each candidate's eligible,
  already-promoted, or blocked status and the evidence thresholds used.
- `partition_audit.json` and `partition_audit.md`: holdout leakage evidence
  generated directly or by a portfolio `partition_audits` entry.
- `failure_analysis.json` and `failure_analysis.md`: classified expected misses
  and unexpected findings when `verisec failure-analysis` is used or a
  portfolio suite enables `failure_analysis`.
- `gate.json` and `gate.md`: pass/fail gate result when `verisec gate` is used,
  including reviewer-noise thresholds such as accepted finding rate, primary
  precision, unexpected finding rate, and negative-control violations.
- `dashboard.json` and `dashboard.md`: regression dashboard across multiple
  suites when `verisec dashboard` is used, including gate status and changes
  against an optional baseline dashboard.
- `portfolio.json` and `portfolio.md`: manifest-level release-gate result when
  `verisec portfolio` is used, with links to generated case audits,
  audit-only candidate queues, evaluations, gates, and dashboard artifacts.
- `benchmark_matrix.json` and `benchmark_matrix.md`: system-level benchmark rows
  across measured VeriSec suites, measured scanner artifact baselines, and
  explicit not-run or skipped scanner baselines.
- `scanner-runs/<label>/scanner_results.json` and `scanner_results.md`: live
  scanner execution provenance when `verisec scanner-run` or a portfolio
  `run: true` baseline is used. Portfolio scanner baselines record whether the
  source was `executed`, `reused`, or `provided` so cached CodeQL/Semgrep
  artifacts remain explicit in review output.
- `scanner-baselines/<label>/baseline.json` and `baseline.md`: standalone
  scanner baseline scoring outputs when `verisec portfolio` includes scanner
  baselines.
- `artifact_index.json` and `artifact_index.md`: release artifact integrity
  index with hashes for the manifest, portfolio, partition and case audits,
  failure analysis, scanner baselines, benchmark matrix, dashboard, evaluation,
  and gate outputs.
- `attestation.json` and `attestation.md`: artifact-index verification results
  when `verisec attest` is used.
- `*-pr-comment.md`: PR-ready Markdown body when `verisec pr-comment` is used.

The bundle is the future handoff point for UI replay, reviewer audit, and
benchmark reproducibility.

See `docs/THREAT_MODEL.md` for the trusted-local, trusted-CI, and
untrusted-fork-PR execution profiles.
