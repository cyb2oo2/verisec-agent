# Roadmap

## Phase 0: Foundation

- Local CLI that reviews a unified diff.
- Evidence windows and traceable findings.
- Repository source context around findings.
- Verification command runner.
- Built-in verification adapter registry.
- JSON review bundle.
- Reviewer-facing Markdown report.
- Unit tests and CI.

## Phase 1: Real repository review

- GitHub PR ingestion through `gh` or app integration.
- Repository context expansion around evidence windows.
- Tool adapters for Semgrep, CodeQL, sanitizer runs, fuzz targets, and
  proof-of-concept scripts.
- Adapter capability mapping for candidate-tool selection and reviewer reporting.
- Semgrep JSON parsing and finding-to-evidence matching.
- CodeQL/SARIF parsing and artifact capture.
- Per-finding validation coverage that marks recommended checks as covered only
  when a scanner finding or `VERISEC_EVIDENCE:` marker matches the finding.
- Reviewer-facing confidence calibration from tool evidence, scanner misses, and
  validation gaps.
- False-positive taxonomy and calibration evaluation.
- Batch evaluation runner for real OSS patch sets and aggregate deployment
  metrics.
- Real-repository case harness for `repo_url`/`base_ref`/`head_ref` materialized
  patches, CVE/PR metadata, and finding-level labels.
- Case intake audit for benchmark expansion, covering source reproducibility,
  expected-finding roles, security metadata, tags, duplicate IDs, and
  verification config readiness.
- Case promotion planner that blocks candidate CVE/PR cases from measured
  benchmark suites until audit, verification config, evaluation evidence,
  validation coverage, expected-finding recall, and reviewer-noise thresholds
  pass.
- Audit-only candidate CVE queue with 9 real OSS security-release cases across
  Django, sqlparse, and mechanize; these are visible in the portfolio but do not
  count as measured benchmark performance until verification configs and
  expected-finding coverage are added.
- Frozen holdout pilot with Django CVE-2023-46695 and mechanize 0.4.6, selected
  at detector commit `d9754d0`, audited as disjoint from 10 measured positive
  cases, and retained as a failed strict gate with 0.00 primary recall.
- Partition leakage audit using case IDs, advisory identities, source pairs,
  diff URLs, and upstream commits.
- Machine-readable failure analysis that distinguishes semantic rule confusion,
  rule/location mismatch, undetected labeled locations, unexpected findings,
  and execution errors.
- Promoted candidate suite with Django CVE-2020-7471 StringAgg delimiter
  parameterization, Django CVE-2022-34265 SQL lookup hardening, Django
  CVE-2022-28346 alias SQL injection hardening, Django CVE-2022-28347 EXPLAIN
  option SQL injection hardening, Django CVE-2023-36053 validator ReDoS
  hardening, Django CVE-2021-45115 password similarity DoS hardening, and
  sqlparse CVE-2023-30608 lexer ReDoS hardening, all backed by property-check
  verification markers.
- First real OSS seed case: MkDocs GHSL-2023-208 YAML SafeLoader hardening with
  expected-finding recall and a property-check verification command.
- Cross-class OSS seed portfolio covering unsafe deserialization and ReDoS with
  MkDocs, PyYAML, and sqlparse cases.
- Python AST and lightweight dataflow layer for alias-aware shell execution,
  unsafe YAML loading, tainted SQL query construction, TLS verification, dynamic
  execution, and weak-hash hypotheses before regex fallback.
- Python-only hypothesis file boundaries that prevent translation catalogs and
  other non-code release artifacts from being misclassified as SQL formatting
  findings.
- Reviewer-noise taxonomy with `primary`, `supporting`, `benign`, and
  `negative-control` expected-finding roles.
- CI gate for enforcing validation, confidence, reviewer-noise, and
  negative-control thresholds.
- Adversarial negative-control suite for shell, TLS, YAML, SQL, crypto, dynamic
  execution, regex, comment-only, and string-only near misses.
- Regression dashboard that combines demo, OSS seed, and negative-control suites
  into a release matrix with optional baseline comparison.
- Portfolio manifest for one-command eval, gate, dashboard, and release status
  generation.
- Portfolio benchmark matrix with measured VeriSec rows, measured Semgrep
  artifact-baseline rows, and CodeQL rows sourced from frozen reusable SARIF
  artifacts in the fast release profile.
- Separate live nightly portfolio manifest that reruns Semgrep and CodeQL
  against the OSS seed suite and isolated scanner negative controls, so scanner
  drift can be measured without destabilizing release CI.
- Scanner baseline evaluator for captured Semgrep JSON and CodeQL/SARIF
  artifacts, scored with the same expected-finding and negative-control labels
  as the agent evaluation.
- Scanner execution harness for live Semgrep or custom scanner argv baselines,
  with stdout/stderr capture, JSON/SARIF artifact capture, skipped-tool
  provenance, and portfolio integration.
- Built-in multi-step CodeQL Python SARIF profile using database create/analyze,
  scored through the same scanner-baseline path as captured SARIF.
- Portable scanner-freezing script that inlines scanner payloads and diffs into
  frozen baseline JSON without local absolute paths.
- Nightly promotion script that requires a passed live portfolio and artifact
  attestation before refreshing frozen release scanner baselines and benchmark
  snapshots.
- Real-repository materialization with required-ref fetches, blobless shallow
  fetch first, UTF-8 git output capture on Windows, and git-diff fallback when
  a remote compare patch does not apply cleanly to the base checkout.
- Per-run source cache for real-repository evaluations, sharing fetched Git
  objects across cases from the same upstream repository while preserving
  isolated per-case checkouts.
- Case-level evaluation resume mode that reuses existing `report.json` bundles
  and recomputes aggregate metrics without rerunning source materialization or
  verification.
- Release artifact integrity index with SHA-256 hashes, command metadata,
  runtime environment, and git state.
- Artifact attestation command for recomputing release artifact hashes and
  detecting post-run mutation.
- PR-ready comment renderer for gated review and evaluation results.
- Sticky GitHub PR comment publishing from rendered review bodies.
- GitHub Actions path that reviews the actual PR diff and isolates the
  privileged sticky-comment update from untrusted PR code.
- Scheduled/default-branch nightly scanner-drift workflow that promotes
  attested live scanner baselines through an auditable pull request.
- Shell-free argv verification runner with adapter/executable allowlists,
  timeout/output caps, minimal environment mode, network posture metadata,
  blocked command patterns, and unavailable tool handling.
- Trusted-local, trusted-CI, and untrusted-fork-PR execution profiles with fork
  PR CI behavior documented in a threat model.

## Phase 2: Agentic validation

- Planner that turns hypotheses into validation plans.
- Patch synthesis with mandatory verification gates.
- Repro bundle replay command for verification traces.
- Multi-agent review mode: skeptic, fixer, validator, reporter.

## Phase 3: Deployable security infrastructure

- GitHub PR bot.
- Web UI for trace replay and evidence inspection.
- Policy engine for sandbox, approvals, secrets, and tool permissions.
- Metrics: precision@k, reviewer time saved, validation pass rate, and accepted
  upstream fixes.
