from __future__ import annotations

import json
import os
import re
import shlex
from dataclasses import fields
from pathlib import Path
from typing import Any

from verisec_agent.case_audit import run_case_audit
from verisec_agent.dashboard import LabeledPath, run_dashboard
from verisec_agent.evaluation import run_evaluation
from verisec_agent.failure_analysis import run_failure_analysis
from verisec_agent.gate import GateThresholds, run_gate
from verisec_agent.integrity import ArtifactSpec, write_artifact_index
from verisec_agent.partition_audit import run_partition_audit
from verisec_agent.scanner_baseline import run_scanner_baseline
from verisec_agent.scanner_execution import run_scanner_execution


class PortfolioError(RuntimeError):
    pass


CASE_AUDIT_CONFIG_KEYS = {
    "enabled",
    "out",
    "require_verification",
    "fail_on_blocked",
    "fail_on_warnings",
}
CASE_AUDIT_SUITE_KEYS = CASE_AUDIT_CONFIG_KEYS | {"label", "cases"}
PARTITION_AUDIT_KEYS = {"label", "cases", "against", "out", "fail_on_overlap"}


def run_portfolio(
    *,
    manifest_path: Path,
    output_dir: Path,
    baseline_path: Path | None = None,
    command_line: str | None = None,
    write_github_summary: bool = False,
    policy_profile: str | None = None,
) -> dict[str, Any]:
    if not manifest_path.exists():
        raise PortfolioError(f"Portfolio manifest does not exist: {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    base_dir = manifest_path.parent
    raw_suites = manifest.get("suites")
    if not isinstance(raw_suites, list) or not raw_suites:
        raise PortfolioError("Portfolio manifest must contain a non-empty suites list.")
    raw_case_audits = manifest.get("case_audits")
    raw_case_audit_suites = manifest.get("case_audit_suites", [])
    if not isinstance(raw_case_audit_suites, list):
        raise PortfolioError("Portfolio case_audit_suites must be a list when provided.")

    output_dir.mkdir(parents=True, exist_ok=True)
    suite_results = []
    standalone_case_audits: list[dict[str, Any]] = []
    partition_audits: list[dict[str, Any]] = []
    failures: list[str] = []

    raw_partition_audits = manifest.get("partition_audits", [])
    if not isinstance(raw_partition_audits, list):
        raise PortfolioError("Portfolio partition_audits must be a list when provided.")
    for raw_partition_audit in raw_partition_audits:
        audit = _run_partition_audit_suite(
            raw_partition_audit,
            base_dir=base_dir,
            output_dir=output_dir,
        )
        partition_audits.append(audit)
        if audit["fail_on_overlap"] and not audit["passed"]:
            failures.append(
                f"{audit['label']}: partition overlap detected "
                f"({audit['summary']['overlap_count']} pair(s))"
            )

    for raw_suite in raw_suites:
        suite_result = _run_suite(
            raw_suite,
            base_dir=base_dir,
            output_dir=output_dir,
            policy_profile=policy_profile,
            portfolio_case_audit_config=raw_case_audits,
        )
        suite_results.append(suite_result)
        failures.extend(
            f"{suite_result['label']}: {failure}"
            for failure in suite_result.get("case_audit_failures", ())
        )
        if not suite_result["gate_passed"]:
            failures.extend(
                f"{suite_result['label']}: {failure}"
                for failure in suite_result.get("gate_failures", ())
            )
    for raw_audit_suite in raw_case_audit_suites:
        audit, audit_failures = _run_standalone_case_audit_suite(
            raw_audit_suite,
            base_dir=base_dir,
            output_dir=output_dir,
        )
        if audit is None:
            continue
        standalone_case_audits.append(audit)
        failures.extend(f"{audit['label']}: {failure}" for failure in audit_failures)

    raw_scanner_baselines = manifest.get("scanner_baselines", [])
    if not isinstance(raw_scanner_baselines, list):
        raise PortfolioError("Portfolio scanner_baselines must be a list when provided.")
    scanner_baseline_results = [
        _run_scanner_baseline(
            raw_baseline,
            base_dir=base_dir,
            output_dir=output_dir,
        )
        for raw_baseline in raw_scanner_baselines
    ]

    dashboard_config = manifest.get("dashboard", {})
    if not isinstance(dashboard_config, dict):
        raise PortfolioError("Portfolio dashboard config must be an object when provided.")
    dashboard_baseline = baseline_path or _resolve_optional_path(
        base_dir,
        dashboard_config.get("baseline"),
    )
    dashboard_output = output_dir / str(dashboard_config.get("out", "dashboard"))
    try:
        dashboard = run_dashboard(
            evaluations=tuple(
                LabeledPath(suite["label"], Path(suite["evaluation_path"]))
                for suite in suite_results
            ),
            gates=tuple(
                LabeledPath(suite["label"], Path(suite["gate_path"]))
                for suite in suite_results
            ),
            baseline_path=dashboard_baseline,
            output_dir=dashboard_output,
        )
    except Exception as exc:
        raise PortfolioError(f"Portfolio dashboard failed: {exc}") from exc
    if dashboard["regressions"]:
        failures.extend(
            f"{item['suite']}: {item['metric']} regressed from "
            f"{item['baseline']} to {item['current']}"
            for item in dashboard["regressions"]
        )

    benchmark_config = manifest.get("benchmark_matrix", {})
    if benchmark_config is not None and not isinstance(benchmark_config, dict):
        raise PortfolioError("Portfolio benchmark_matrix config must be an object.")
    benchmark_output = output_dir / str(benchmark_config.get("out", "benchmark_matrix"))
    benchmark_matrix = _build_benchmark_matrix(
        benchmark_config=benchmark_config,
        output_dir=benchmark_output,
        suites=suite_results,
        scanner_baselines=scanner_baseline_results,
    )

    result = {
        "passed": not failures,
        "manifest_path": str(manifest_path),
        "output_dir": str(output_dir),
        "dashboard_path": str(dashboard_output / "dashboard.json"),
        "benchmark_matrix_path": (
            str(benchmark_output / "benchmark_matrix.json")
            if benchmark_matrix is not None
            else None
        ),
        "artifact_index_path": str(output_dir / "artifact_index.json"),
        "dashboard_summary": dashboard["summary"],
        "benchmark_matrix": benchmark_matrix,
        "suites": suite_results,
        "case_audits": [
            suite["case_audit"] for suite in suite_results if suite.get("case_audit")
        ]
        + standalone_case_audits,
        "case_audit_suites": standalone_case_audits,
        "partition_audits": partition_audits,
        "scanner_baselines": scanner_baseline_results,
        "failures": failures,
    }
    markdown = render_portfolio_markdown(result)
    (output_dir / "portfolio.json").write_text(
        json.dumps(result, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (output_dir / "portfolio.md").write_text(markdown, encoding="utf-8")
    try:
        write_artifact_index(
            output_dir=output_dir,
            root_dir=output_dir,
            artifacts=_portfolio_artifacts(
                manifest_path=manifest_path,
                output_dir=output_dir,
                dashboard_output=dashboard_output,
                benchmark_output=benchmark_output if benchmark_matrix is not None else None,
                suites=suite_results,
                case_audits=standalone_case_audits,
                partition_audits=partition_audits,
                scanner_baselines=scanner_baseline_results,
            ),
            manifest_path=manifest_path,
            command_line=command_line,
            repo_path=base_dir,
        )
    except Exception as exc:
        raise PortfolioError(f"Portfolio artifact indexing failed: {exc}") from exc

    if write_github_summary:
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            with Path(summary_path).open("a", encoding="utf-8") as handle:
                handle.write(markdown)
                handle.write("\n")

    return result


def render_portfolio_markdown(result: dict[str, Any]) -> str:
    dashboard = result["dashboard_summary"]
    status = "passed" if result["passed"] else "failed"
    case_audits = result.get("case_audits", ())
    audit_blocked_count = sum(
        int(audit["summary"].get("blocked_count", 0)) for audit in case_audits
    )
    audit_warning_count = sum(
        int(audit["summary"].get("warning_count", 0)) for audit in case_audits
    )
    partition_audits = result.get("partition_audits", ())
    partition_overlap_count = sum(
        int(audit["summary"].get("overlap_count", 0))
        for audit in partition_audits
    )
    lines = [
        f"# VeriSec Portfolio: {status}",
        "",
        f"- Manifest: `{result['manifest_path']}`",
        f"- Suites: {dashboard['suite_count']}",
        f"- Total cases: {dashboard['total_cases']}",
        f"- Total findings: {dashboard['total_findings']}",
        f"- Gates passed: {dashboard['gates_passed']}/{dashboard['gates_total']}",
        f"- Regressions: {dashboard['regression_count']}",
        (
            f"- Case audits: {len(case_audits)} "
            f"({audit_blocked_count} blocked, {audit_warning_count} warnings)"
        ),
        (
            f"- Partition audits: {len(partition_audits)} "
            f"({partition_overlap_count} overlap pairs)"
        ),
        f"- Scanner baselines: {len(result.get('scanner_baselines', ()))}",
        f"- Dashboard: `{result['dashboard_path']}`",
        f"- Benchmark matrix: `{result.get('benchmark_matrix_path') or 'n/a'}`",
        f"- Artifact index: `{result['artifact_index_path']}`",
        "",
    ]
    benchmark_matrix = result.get("benchmark_matrix")
    if benchmark_matrix:
        lines.extend(["## Benchmark Matrix", ""])
        lines.extend(_render_benchmark_matrix_table(benchmark_matrix))
        lines.extend(_render_benchmark_claim_boundaries(benchmark_matrix))
        lines.append("")
    if case_audits:
        lines.extend(
            [
                "## Case Audits",
                "",
                (
                    "| Suite | Status | Cases | Ready | Blocked | Warnings | "
                    "Verification Ready | Output |"
                ),
                "| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
            ]
        )
        for audit in case_audits:
            summary = audit["summary"]
            lines.append(
                "| "
                f"{audit['label']} | "
                f"{_case_audit_status(audit)} | "
                f"{summary.get('case_count', 0)} | "
                f"{summary.get('ready_count', 0)} | "
                f"{summary.get('blocked_count', 0)} | "
                f"{summary.get('warning_count', 0)} | "
                f"{summary.get('verification_ready_count', 0)} | "
                f"`{audit['path']}` |"
            )
    if partition_audits:
        lines.extend(
            [
                "",
                "## Partition Audits",
                "",
                "| Audit | Status | Cases | Reference Cases | Overlaps | Output |",
                "| --- | --- | ---: | ---: | ---: | --- |",
            ]
        )
        for audit in partition_audits:
            summary = audit["summary"]
            lines.append(
                "| "
                f"{audit['label']} | "
                f"{'passed' if audit['passed'] else 'failed'} | "
                f"{summary['case_count']} | "
                f"{summary['reference_case_count']} | "
                f"{summary['overlap_count']} | "
                f"`{audit['path']}` |"
            )
        lines.append("")
    if result.get("scanner_baselines"):
        lines.extend(
            [
                "## Scanner Baselines",
                "",
                (
                    "| Baseline | Status | Source | Adapter | Cases | Completed | Skipped | "
                    "Findings | Raw | Out Scope | Expected Recall | "
                    "Primary Precision | Tool Evidence | Output |"
                ),
                (
                    "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | "
                    "---: | ---: | ---: | --- |"
                ),
            ]
        )
        for baseline in result["scanner_baselines"]:
            metrics = baseline["metrics"]
            status = _benchmark_status(metrics)
            finding_count = metrics.get("finding_count") if status == "measured" else None
            raw_tool_findings = (
                metrics.get("raw_tool_finding_count") if status == "measured" else None
            )
            out_of_scope_findings = (
                metrics.get("out_of_scope_finding_count") if status == "measured" else None
            )
            expected_recall = (
                metrics.get("expected_finding_recall") if status == "measured" else None
            )
            primary_precision = (
                metrics.get("primary_precision") if status == "measured" else None
            )
            tool_evidence = (
                metrics.get("tool_evidence_rate") if status == "measured" else None
            )
            lines.append(
                "| "
                f"{baseline['label']} | "
                f"{status} | "
                f"{baseline.get('scanner_execution_mode', 'provided')} | "
                f"{baseline['adapter']} | "
                f"{metrics.get('case_count', 0)} | "
                f"{metrics.get('completed_count', 0)} | "
                f"{metrics.get('skipped_count', 0)} | "
                f"{_format_count(finding_count)} | "
                f"{_format_count(raw_tool_findings)} | "
                f"{_format_count(out_of_scope_findings)} | "
                f"{_format_rate(expected_recall)} | "
                f"{_format_rate(primary_precision)} | "
                f"{_format_rate(tool_evidence)} | "
                f"`{baseline['baseline_path']}` |"
            )
        lines.append("")
    lines.extend(
        [
            "## Suites",
            "",
            (
                "| Suite | Gate | Cases | Findings | Validation | Accepted | Unexpected | "
                "Neg Ctrl | Evaluation |"
            ),
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for suite in result["suites"]:
        metrics = suite["metrics"]
        lines.append(
            "| "
            f"{suite['label']} | "
            f"{'passed' if suite['gate_passed'] else 'failed'} | "
            f"{metrics.get('case_count', 0)} | "
            f"{metrics.get('finding_count', 0)} | "
            f"{_format_rate(metrics.get('validation_coverage_rate'))} | "
            f"{_format_rate(metrics.get('accepted_finding_rate'))} | "
            f"{_format_rate(metrics.get('unexpected_finding_rate'))} | "
            f"{metrics.get('negative_control_violation_count', 0)} | "
            f"`{suite['evaluation_path']}` |"
        )
    if result["failures"]:
        lines.extend(["", "## Failures", ""])
        lines.extend(f"- {failure}" for failure in result["failures"])
    return "\n".join(lines).rstrip() + "\n"


def _run_suite(
    raw_suite: dict[str, Any],
    *,
    base_dir: Path,
    output_dir: Path,
    policy_profile: str | None = None,
    portfolio_case_audit_config: Any = None,
) -> dict[str, Any]:
    if not isinstance(raw_suite, dict):
        raise PortfolioError("Each portfolio suite must be an object.")
    label = str(raw_suite.get("label") or "").strip()
    if not label:
        raise PortfolioError("Each portfolio suite needs a label.")
    cases_path = _resolve_required_path(base_dir, raw_suite, "cases")
    config_path = _resolve_optional_path(base_dir, raw_suite.get("config"))
    safe_label = _safe_label(label)
    evaluation_dir = output_dir / "evaluations" / safe_label
    gate_dir = output_dir / "gates" / safe_label
    thresholds = _thresholds_from_manifest(raw_suite.get("gate", {}))
    case_audit, case_audit_failures = _run_suite_case_audit(
        raw_suite,
        output_dir=output_dir,
        cases_path=cases_path,
        label=label,
        safe_label=safe_label,
        portfolio_case_audit_config=portfolio_case_audit_config,
    )

    try:
        evaluation = run_evaluation(
            cases_path=cases_path,
            output_dir=evaluation_dir,
            default_config_path=config_path,
            fail_fast=bool(raw_suite.get("fail_fast", False)),
            policy_profile=policy_profile,
        )
    except Exception as exc:
        raise PortfolioError(f"Suite {label} evaluation failed: {exc}") from exc
    try:
        gate = run_gate(
            evaluation_path=evaluation_dir / "evaluation.json",
            thresholds=thresholds,
            output_dir=gate_dir,
        )
    except Exception as exc:
        raise PortfolioError(f"Suite {label} gate failed: {exc}") from exc
    failure_analysis_path = None
    failure_analysis_summary = None
    if bool(raw_suite.get("failure_analysis", False)):
        failure_analysis_dir = output_dir / "failure-analysis" / safe_label
        try:
            failure_analysis = run_failure_analysis(
                evaluation_path=evaluation_dir / "evaluation.json",
                output_dir=failure_analysis_dir,
            )
        except Exception as exc:
            raise PortfolioError(
                f"Suite {label} failure analysis failed: {exc}"
            ) from exc
        failure_analysis_path = str(
            failure_analysis_dir / "failure_analysis.json"
        )
        failure_analysis_summary = failure_analysis["summary"]
    summary = evaluation["summary"]
    return {
        "label": label,
        "cases_path": str(cases_path),
        "evaluation_path": str(evaluation_dir / "evaluation.json"),
        "gate_path": str(gate_dir / "gate.json"),
        "gate_passed": bool(gate["passed"]),
        "gate_failures": gate["failures"],
        "case_audit": case_audit,
        "case_audit_failures": case_audit_failures,
        "failure_analysis_path": failure_analysis_path,
        "failure_analysis_summary": failure_analysis_summary,
        "metrics": {
            "case_count": summary.get("case_count", 0),
            "finding_count": summary.get("finding_count", 0),
            "validation_coverage_rate": summary.get("validation_coverage_rate"),
            "accepted_finding_rate": summary.get("accepted_finding_rate"),
            "primary_precision": summary.get("primary_precision"),
            "primary_finding_recall": summary.get("primary_finding_recall"),
            "supporting_evidence_rate": summary.get("supporting_evidence_rate"),
            "unexpected_finding_rate": summary.get("unexpected_finding_rate"),
            "negative_control_violation_count": summary.get(
                "negative_control_violation_count",
                0,
            ),
            "expected_rule_recall": summary.get("expected_rule_recall"),
            "expected_finding_recall": summary.get("expected_finding_recall"),
            "validation_gap_rate": summary.get("validation_gap_rate"),
            "tool_evidence_rate": summary.get("tool_evidence_rate"),
            "policy_blocked_count": summary.get("policy_blocked_count"),
        },
    }


def _run_suite_case_audit(
    raw_suite: dict[str, Any],
    *,
    output_dir: Path,
    cases_path: Path,
    label: str,
    safe_label: str,
    portfolio_case_audit_config: Any,
) -> tuple[dict[str, Any] | None, list[str]]:
    config = _case_audit_config_for_suite(
        portfolio_case_audit_config=portfolio_case_audit_config,
        suite_case_audit_config=raw_suite.get("audit"),
    )
    return _run_case_audit_with_config(
        cases_path=cases_path,
        output_dir=output_dir,
        label=label,
        safe_label=safe_label,
        config=config,
    )


def _run_standalone_case_audit_suite(
    raw_audit_suite: dict[str, Any],
    *,
    base_dir: Path,
    output_dir: Path,
) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(raw_audit_suite, dict):
        raise PortfolioError("Each portfolio case_audit_suites entry must be an object.")
    unknown = sorted(set(raw_audit_suite) - CASE_AUDIT_SUITE_KEYS)
    if unknown:
        raise PortfolioError(
            "Unknown case_audit_suites setting(s): "
            + ", ".join(str(item) for item in unknown)
        )
    label = str(raw_audit_suite.get("label") or "").strip()
    if not label:
        raise PortfolioError("Each portfolio case_audit_suites entry needs a label.")
    cases_path = _resolve_required_path(base_dir, raw_audit_suite, "cases")
    config_overrides = {
        key: raw_audit_suite[key]
        for key in CASE_AUDIT_CONFIG_KEYS
        if key in raw_audit_suite
    }
    config = _case_audit_config_for_suite(
        portfolio_case_audit_config={"enabled": True},
        suite_case_audit_config=config_overrides,
    )
    return _run_case_audit_with_config(
        cases_path=cases_path,
        output_dir=output_dir,
        label=label,
        safe_label=_safe_label(label),
        config=config,
    )


def _run_partition_audit_suite(
    raw_audit: dict[str, Any],
    *,
    base_dir: Path,
    output_dir: Path,
) -> dict[str, Any]:
    if not isinstance(raw_audit, dict):
        raise PortfolioError("Each portfolio partition_audits entry must be an object.")
    unknown = sorted(set(raw_audit) - PARTITION_AUDIT_KEYS)
    if unknown:
        raise PortfolioError(
            "Unknown partition_audits setting(s): "
            + ", ".join(str(item) for item in unknown)
        )
    label = str(raw_audit.get("label") or "").strip()
    if not label:
        raise PortfolioError("Each portfolio partition_audits entry needs a label.")
    cases_path = _resolve_required_path(base_dir, raw_audit, "cases")
    raw_against = raw_audit.get("against")
    if not isinstance(raw_against, list) or not raw_against:
        raise PortfolioError(
            f"Portfolio partition audit '{label}' needs a non-empty against list."
        )
    reference_paths = tuple(
        _resolve_required_value_path(base_dir, value, label=label)
        for value in raw_against
    )
    audit_root = Path(str(raw_audit.get("out") or "partition-audits"))
    if not audit_root.is_absolute():
        audit_root = output_dir / audit_root
    audit_dir = audit_root / _safe_label(label)
    try:
        audit = run_partition_audit(
            cases_path=cases_path,
            reference_paths=reference_paths,
            output_dir=audit_dir,
        )
    except Exception as exc:
        raise PortfolioError(f"Partition audit {label} failed: {exc}") from exc
    return {
        "label": label,
        "cases_path": str(cases_path),
        "reference_paths": tuple(str(path) for path in reference_paths),
        "path": str(audit_dir / "partition_audit.json"),
        "markdown_path": str(audit_dir / "partition_audit.md"),
        "passed": bool(audit["passed"]),
        "fail_on_overlap": bool(raw_audit.get("fail_on_overlap", True)),
        "summary": audit["summary"],
        "overlaps": audit["overlaps"],
    }


def _run_case_audit_with_config(
    *,
    cases_path: Path,
    output_dir: Path,
    label: str,
    safe_label: str,
    config: dict[str, Any],
) -> tuple[dict[str, Any] | None, list[str]]:
    if not bool(config["enabled"]):
        return None, []

    audit_root = Path(str(config.get("out") or "case-audits"))
    if not audit_root.is_absolute():
        audit_root = output_dir / audit_root
    audit_dir = audit_root / safe_label
    try:
        audit = run_case_audit(
            cases_path=cases_path,
            output_dir=audit_dir,
            require_verification=bool(config["require_verification"]),
        )
    except Exception as exc:
        raise PortfolioError(f"Suite {label} case audit failed: {exc}") from exc

    summary = audit["summary"]
    failures: list[str] = []
    blocked_count = int(summary.get("blocked_count", 0))
    warning_count = int(summary.get("warning_count", 0))
    loader_passed = bool(summary.get("loader_passed", False))
    if bool(config["fail_on_blocked"]) and (blocked_count or not loader_passed):
        details = [f"{blocked_count} blocked case(s)"]
        if not loader_passed:
            details.append("loader failed")
        failures.append(f"case audit readiness failed: {', '.join(details)}")
    if bool(config["fail_on_warnings"]) and warning_count:
        failures.append(f"case audit has {warning_count} warning(s)")

    return (
        {
            "label": label,
            "cases_path": str(cases_path),
            "path": str(audit_dir / "case_audit.json"),
            "markdown_path": str(audit_dir / "case_audit.md"),
            "summary": summary,
        },
        failures,
    )


def _case_audit_config_for_suite(
    *,
    portfolio_case_audit_config: Any,
    suite_case_audit_config: Any,
) -> dict[str, Any]:
    config: dict[str, Any] = {
        "enabled": False,
        "out": "case-audits",
        "require_verification": False,
        "fail_on_blocked": True,
        "fail_on_warnings": False,
    }
    for label, raw_config in (
        ("case_audits", portfolio_case_audit_config),
        ("suite.audit", suite_case_audit_config),
    ):
        if raw_config is None:
            continue
        if not isinstance(raw_config, dict):
            raise PortfolioError(f"Portfolio {label} config must be an object.")
        unknown = sorted(set(raw_config) - CASE_AUDIT_CONFIG_KEYS)
        if unknown:
            raise PortfolioError(
                f"Unknown {label} setting(s): {', '.join(str(item) for item in unknown)}"
            )
        config.update(raw_config)
    return config


def _run_scanner_baseline(
    raw_baseline: dict[str, Any],
    *,
    base_dir: Path,
    output_dir: Path,
) -> dict[str, Any]:
    if not isinstance(raw_baseline, dict):
        raise PortfolioError("Each portfolio scanner baseline must be an object.")
    label = str(raw_baseline.get("label") or "").strip()
    if not label:
        raise PortfolioError("Each portfolio scanner baseline needs a label.")
    cases_path = _resolve_required_path(base_dir, raw_baseline, "cases")
    safe_label = _safe_label(label)
    should_run = bool(raw_baseline.get("run", False)) or not raw_baseline.get("results")
    reuse_results = bool(raw_baseline.get("reuse_results", False))
    reuse_from_path = _resolve_optional_path(base_dir, raw_baseline.get("reuse_from"))
    configured_results_path = _resolve_optional_path(base_dir, raw_baseline.get("results"))
    scanner_results_path: Path | None = None
    scanner_execution_mode = "provided"
    if should_run:
        scanner_run_dir = output_dir / "scanner-runs" / safe_label
        reusable_results_path = (
            reuse_from_path
            or configured_results_path
            or (scanner_run_dir / "scanner_results.json")
        )
        if reuse_results and reusable_results_path.exists():
            scanner_results_path = reusable_results_path
            results_path = reusable_results_path
            scanner_execution_mode = "reused"
        else:
            try:
                run_scanner_execution(
                    cases_path=cases_path,
                    output_dir=scanner_run_dir,
                    adapter=str(raw_baseline.get("adapter") or "semgrep"),
                    label=label,
                    command_argv=_command_argv_from_manifest(
                        raw_baseline.get("argv"),
                        raw_baseline.get("command"),
                    ),
                    command_sequence=_command_sequence_from_manifest(raw_baseline.get("steps")),
                    timeout_seconds=int(raw_baseline.get("timeout_seconds", 300)),
                    fail_fast=bool(raw_baseline.get("fail_fast", True)),
                )
            except Exception as exc:
                raise PortfolioError(f"Scanner baseline {label} execution failed: {exc}") from exc
            scanner_results_path = scanner_run_dir / "scanner_results.json"
            results_path = scanner_results_path
            scanner_execution_mode = "executed"
    else:
        results_path = _resolve_required_path(base_dir, raw_baseline, "results")
    baseline_dir = output_dir / "scanner-baselines" / safe_label

    try:
        baseline = run_scanner_baseline(
            cases_path=cases_path,
            results_path=results_path,
            output_dir=baseline_dir,
            adapter=raw_baseline.get("adapter"),
            label=label,
            fail_fast=bool(raw_baseline.get("fail_fast", True)),
        )
    except Exception as exc:
        raise PortfolioError(f"Scanner baseline {label} failed: {exc}") from exc
    summary = baseline["summary"]
    return {
        "label": label,
        "adapter": baseline["adapter"],
        "cases_path": str(cases_path),
        "results_path": str(results_path),
        "scanner_results_path": str(scanner_results_path) if scanner_results_path else None,
        "reuse_from_path": str(reuse_from_path) if reuse_from_path else None,
        "scanner_execution_mode": scanner_execution_mode,
        "reuse_results": reuse_results,
        "baseline_path": str(baseline_dir / "baseline.json"),
        "metrics": _summary_metrics(summary),
    }


def _summary_metrics(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_count": summary.get("case_count", 0),
        "completed_count": summary.get("completed_count", 0),
        "skipped_count": summary.get("skipped_count", 0),
        "error_count": summary.get("error_count", 0),
        "finding_count": summary.get("finding_count", 0),
        "raw_tool_finding_count": summary.get(
            "raw_tool_finding_count",
            summary.get("tool_finding_count", summary.get("finding_count", 0)),
        ),
        "out_of_scope_finding_count": summary.get("out_of_scope_finding_count", 0),
        "validation_coverage_rate": summary.get("validation_coverage_rate"),
        "accepted_finding_rate": summary.get("accepted_finding_rate"),
        "primary_precision": summary.get("primary_precision"),
        "primary_finding_recall": summary.get("primary_finding_recall"),
        "supporting_evidence_rate": summary.get("supporting_evidence_rate"),
        "unexpected_finding_rate": summary.get("unexpected_finding_rate"),
        "negative_control_violation_count": summary.get(
            "negative_control_violation_count",
            0,
        ),
        "expected_rule_recall": summary.get("expected_rule_recall"),
        "expected_finding_recall": summary.get("expected_finding_recall"),
        "validation_gap_rate": summary.get("validation_gap_rate"),
        "tool_evidence_rate": summary.get("tool_evidence_rate"),
        "policy_blocked_count": summary.get("policy_blocked_count"),
    }


def _thresholds_from_manifest(value: Any) -> GateThresholds:
    if value is None:
        return GateThresholds()
    if not isinstance(value, dict):
        raise PortfolioError("suite.gate must be an object when provided.")
    allowed = {field.name for field in fields(GateThresholds)}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise PortfolioError(f"Unknown gate threshold(s): {', '.join(unknown)}")
    return GateThresholds(**value)


def _command_argv_from_manifest(argv: Any, command: Any = None) -> tuple[str, ...] | None:
    if argv is not None and command is not None:
        raise PortfolioError("scanner baseline can use argv or command, not both.")
    if command is not None:
        return tuple(shlex.split(str(command)))
    if argv is None:
        return None
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        raise PortfolioError("scanner_baselines[].argv must be a list of strings.")
    return tuple(argv)


def _command_sequence_from_manifest(value: Any) -> tuple[tuple[str, ...], ...] | None:
    if value is None:
        return None
    if not isinstance(value, list) or not value:
        raise PortfolioError("scanner_baselines[].steps must be a non-empty list.")
    steps: list[tuple[str, ...]] = []
    for index, raw_step in enumerate(value, start=1):
        if isinstance(raw_step, str):
            step = tuple(shlex.split(raw_step))
        elif isinstance(raw_step, list) and all(isinstance(item, str) for item in raw_step):
            step = tuple(raw_step)
        else:
            raise PortfolioError(
                f"scanner_baselines[].steps[{index}] must be a string or list of strings."
            )
        if not step:
            raise PortfolioError(f"scanner_baselines[].steps[{index}] cannot be empty.")
        steps.append(step)
    return tuple(steps)


def _portfolio_artifacts(
    *,
    manifest_path: Path,
    output_dir: Path,
    dashboard_output: Path,
    benchmark_output: Path | None,
    suites: list[dict[str, Any]],
    case_audits: list[dict[str, Any]],
    partition_audits: list[dict[str, Any]],
    scanner_baselines: list[dict[str, Any]],
) -> tuple[ArtifactSpec, ...]:
    artifacts = [
        ArtifactSpec("portfolio", "manifest", manifest_path),
        ArtifactSpec("portfolio", "portfolio-json", output_dir / "portfolio.json"),
        ArtifactSpec("portfolio", "portfolio-markdown", output_dir / "portfolio.md"),
        ArtifactSpec("portfolio", "dashboard-json", dashboard_output / "dashboard.json"),
        ArtifactSpec("portfolio", "dashboard-markdown", dashboard_output / "dashboard.md"),
    ]
    if benchmark_output is not None:
        artifacts.extend(
            [
                ArtifactSpec(
                    "portfolio",
                    "benchmark-matrix-json",
                    benchmark_output / "benchmark_matrix.json",
                ),
                ArtifactSpec(
                    "portfolio",
                    "benchmark-matrix-markdown",
                    benchmark_output / "benchmark_matrix.md",
                ),
            ]
        )
    for suite in suites:
        label = str(suite["label"])
        case_audit = suite.get("case_audit")
        if case_audit:
            artifacts.extend(_case_audit_artifacts(label=label, audit=case_audit))
        evaluation_path = Path(str(suite["evaluation_path"]))
        gate_path = Path(str(suite["gate_path"]))
        artifacts.extend(
            [
                ArtifactSpec(label, "evaluation-json", evaluation_path),
                ArtifactSpec(label, "evaluation-markdown", evaluation_path.with_suffix(".md")),
                ArtifactSpec(label, "gate-json", gate_path),
                ArtifactSpec(label, "gate-markdown", gate_path.with_suffix(".md")),
            ]
        )
        failure_analysis_path = suite.get("failure_analysis_path")
        if failure_analysis_path:
            analysis_path = Path(str(failure_analysis_path))
            artifacts.extend(
                [
                    ArtifactSpec(
                        label,
                        "failure-analysis-json",
                        analysis_path,
                    ),
                    ArtifactSpec(
                        label,
                        "failure-analysis-markdown",
                        analysis_path.with_suffix(".md"),
                    ),
                ]
            )
    for audit in case_audits:
        artifacts.extend(_case_audit_artifacts(label=str(audit["label"]), audit=audit))
    for audit in partition_audits:
        audit_path = Path(str(audit["path"]))
        artifacts.extend(
            [
                ArtifactSpec(
                    str(audit["label"]),
                    "partition-audit-json",
                    audit_path,
                ),
                ArtifactSpec(
                    str(audit["label"]),
                    "partition-audit-markdown",
                    audit_path.with_suffix(".md"),
                ),
            ]
        )
    for baseline in scanner_baselines:
        label = str(baseline["label"])
        baseline_path = Path(str(baseline["baseline_path"]))
        scanner_results_path = baseline.get("scanner_results_path")
        if scanner_results_path:
            results_path = Path(str(scanner_results_path))
            artifacts.append(ArtifactSpec(label, "scanner-results-json", results_path))
            results_markdown_path = results_path.with_suffix(".md")
            if results_markdown_path.exists():
                artifacts.append(
                    ArtifactSpec(
                        label,
                        "scanner-results-markdown",
                        results_markdown_path,
                    )
                )
        artifacts.extend(
            [
                ArtifactSpec(label, "scanner-baseline-json", baseline_path),
                ArtifactSpec(
                    label,
                    "scanner-baseline-markdown",
                    baseline_path.with_suffix(".md"),
                ),
            ]
        )
    return tuple(artifacts)


def _case_audit_artifacts(*, label: str, audit: dict[str, Any]) -> list[ArtifactSpec]:
    audit_path = Path(str(audit["path"]))
    return [
        ArtifactSpec(label, "case-audit-json", audit_path),
        ArtifactSpec(label, "case-audit-markdown", audit_path.with_suffix(".md")),
    ]


def _resolve_required_path(base_dir: Path, item: dict[str, Any], key: str) -> Path:
    value = item.get(key)
    if not value:
        raise PortfolioError(f"Portfolio suite is missing required field: {key}")
    path = _resolve_optional_path(base_dir, value)
    assert path is not None
    if not path.exists():
        raise PortfolioError(f"Portfolio path does not exist: {path}")
    return path


def _resolve_required_value_path(base_dir: Path, value: Any, *, label: str) -> Path:
    path = _resolve_optional_path(base_dir, value)
    if path is None or not path.exists():
        raise PortfolioError(
            f"Portfolio partition audit '{label}' path does not exist: {value}"
        )
    return path


def _resolve_optional_path(base_dir: Path, value: Any) -> Path | None:
    if value is None:
        return None
    path = Path(str(value))
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def _safe_label(label: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", label).strip("-")
    return safe or "suite"


def _format_rate(value: Any) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.2f}"


def _build_benchmark_matrix(
    *,
    benchmark_config: dict[str, Any],
    output_dir: Path,
    suites: list[dict[str, Any]],
    scanner_baselines: list[dict[str, Any]],
) -> dict[str, Any] | None:
    raw_systems = benchmark_config.get("systems")
    if raw_systems is None:
        return None
    if not isinstance(raw_systems, list):
        raise PortfolioError("benchmark_matrix.systems must be a list.")
    raw_claim_boundaries = benchmark_config.get("claim_boundaries", [])
    if not isinstance(raw_claim_boundaries, list) or not all(
        isinstance(item, str) and item.strip() for item in raw_claim_boundaries
    ):
        raise PortfolioError(
            "benchmark_matrix.claim_boundaries must be a list of non-empty strings."
        )

    suites_by_label = {suite["label"]: suite for suite in suites}
    scanner_baselines_by_label = {
        baseline["label"]: baseline for baseline in scanner_baselines
    }
    systems = tuple(
        _benchmark_row(item, suites_by_label, scanner_baselines_by_label)
        for item in raw_systems
    )
    claim_boundaries = tuple(
        _resolve_claim_boundary(item.strip(), systems) for item in raw_claim_boundaries
    )
    result = {
        "summary": {
            "system_count": len(systems),
            "measured_system_count": sum(
                1 for system in systems if system["status"] == "measured"
            ),
            "skipped_system_count": sum(
                1 for system in systems if system["status"] == "skipped"
            ),
            "error_system_count": sum(
                1 for system in systems if system["status"] == "error"
            ),
            "not_run_system_count": sum(
                1 for system in systems if system["status"] == "not-run"
            ),
        },
        "systems": systems,
        "claim_boundaries": claim_boundaries,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "benchmark_matrix.json").write_text(
        json.dumps(result, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (output_dir / "benchmark_matrix.md").write_text(
        render_benchmark_matrix_markdown(result),
        encoding="utf-8",
    )
    return result


_CLAIM_PLACEHOLDER = re.compile(r"\{([^{}:]+):([^{}:]+)\}")


def _resolve_claim_boundary(text: str, systems: tuple[dict[str, Any], ...]) -> str:
    """Substitute ``{system label:metric}`` in claim-boundary prose with computed values.

    Counts in a claim boundary describe the benchmark the surrounding metrics were
    measured on, so they are derived rather than hand-maintained. An unresolved
    reference raises instead of passing through: publishing a claims document
    containing a literal placeholder, or prose contradicting the table beside it, is
    the failure this substitution exists to prevent.
    """
    metrics_by_label = {system["label"]: system["metrics"] for system in systems}

    def _replace(match: re.Match[str]) -> str:
        label = match.group(1).strip()
        metric = match.group(2).strip()
        metrics = metrics_by_label.get(label)
        if metrics is None:
            raise PortfolioError(
                f"benchmark_matrix.claim_boundaries references unknown system '{label}'."
            )
        if metric not in metrics:
            raise PortfolioError(
                f"benchmark_matrix.claim_boundaries references unknown metric '{metric}' "
                f"on system '{label}'."
            )
        value = metrics[metric]
        if value is None:
            raise PortfolioError(
                f"benchmark_matrix.claim_boundaries references unmeasured metric '{metric}' "
                f"on system '{label}'."
            )
        return _format_rate(value) if isinstance(value, float) else _format_count(value)

    return _CLAIM_PLACEHOLDER.sub(_replace, text)


def _benchmark_row(
    item: dict[str, Any],
    suites_by_label: dict[str, dict[str, Any]],
    scanner_baselines_by_label: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise PortfolioError("benchmark_matrix.systems entries must be objects.")
    label = str(item.get("label") or item.get("system") or "").strip()
    if not label:
        raise PortfolioError("benchmark_matrix.systems entries need a label.")

    suite_label = item.get("suite")
    negative_suite_label = item.get("negative_suite")
    baseline_label = item.get("baseline")
    negative_baseline_label = item.get("negative_baseline")
    notes = str(item.get("notes", ""))
    if suite_label is not None and baseline_label is not None:
        raise PortfolioError(
            f"benchmark_matrix system '{label}' cannot reference both suite and baseline."
        )
    if suite_label is None and baseline_label is None:
        return {
            "label": label,
            "status": str(item.get("status", "not-run")),
            "suite": None,
            "negative_suite": str(negative_suite_label) if negative_suite_label else None,
            "baseline": None,
            "negative_baseline": (
                str(negative_baseline_label) if negative_baseline_label else None
            ),
            "metrics": _empty_benchmark_metrics(),
            "notes": notes,
        }

    if baseline_label is not None:
        baseline = scanner_baselines_by_label.get(str(baseline_label))
        if baseline is None:
            raise PortfolioError(
                f"benchmark_matrix system '{label}' references unknown scanner baseline."
            )
        negative_baseline = (
            scanner_baselines_by_label.get(str(negative_baseline_label))
            if negative_baseline_label is not None
            else None
        )
        if negative_baseline_label is not None and negative_baseline is None:
            raise PortfolioError(
                f"benchmark_matrix system '{label}' references unknown negative_baseline."
            )
        return _measured_benchmark_row(
            label=label,
            suite=None,
            negative_suite=None,
            baseline=baseline,
            negative_baseline=negative_baseline,
            notes=notes,
        )

    suite = suites_by_label.get(str(suite_label))
    if suite is None:
        raise PortfolioError(f"benchmark_matrix system '{label}' references unknown suite.")
    negative_suite = (
        suites_by_label.get(str(negative_suite_label))
        if negative_suite_label is not None
        else None
    )
    if negative_suite_label is not None and negative_suite is None:
        raise PortfolioError(
            f"benchmark_matrix system '{label}' references unknown negative_suite."
        )

    return _measured_benchmark_row(
        label=label,
        suite=suite,
        negative_suite=negative_suite,
        baseline=None,
        negative_baseline=None,
        notes=notes,
    )


def _measured_benchmark_row(
    *,
    label: str,
    suite: dict[str, Any] | None,
    negative_suite: dict[str, Any] | None,
    baseline: dict[str, Any] | None,
    negative_baseline: dict[str, Any] | None,
    notes: str,
) -> dict[str, Any]:
    source = suite or baseline
    if source is None:
        raise PortfolioError(f"benchmark_matrix system '{label}' has no measured source.")
    negative_source = negative_suite or negative_baseline
    metrics = source["metrics"]
    negative_metrics = negative_source["metrics"] if negative_source is not None else {}
    status = _benchmark_status(metrics)
    if status != "measured":
        benchmark_metrics = _empty_benchmark_metrics()
        benchmark_metrics["positive_cases"] = metrics.get("case_count")
        benchmark_metrics["negative_controls"] = negative_metrics.get("case_count")
    else:
        benchmark_metrics = {
            "positive_cases": metrics.get("case_count"),
            "negative_controls": negative_metrics.get("case_count"),
            "findings": metrics.get("finding_count"),
            "raw_tool_findings": metrics.get(
                "raw_tool_finding_count",
                metrics.get("finding_count"),
            ),
            "out_of_scope_findings": metrics.get("out_of_scope_finding_count", 0),
            "expected_finding_recall": metrics.get("expected_finding_recall"),
            "primary_recall": metrics.get("primary_finding_recall"),
            "primary_precision": metrics.get("primary_precision"),
            "validation_coverage": metrics.get("validation_coverage_rate"),
            "tool_evidence_rate": metrics.get("tool_evidence_rate"),
            "validation_gap_rate": metrics.get("validation_gap_rate"),
            "unexpected_rate": metrics.get("unexpected_finding_rate"),
            "negative_control_violations": negative_metrics.get(
                "negative_control_violation_count"
            ),
            "policy_blocked_count": metrics.get("policy_blocked_count"),
        }
    return {
        "label": label,
        "status": status,
        "suite": suite["label"] if suite is not None else None,
        "negative_suite": negative_suite["label"] if negative_suite is not None else None,
        "baseline": baseline["label"] if baseline is not None else None,
        "negative_baseline": (
            negative_baseline["label"] if negative_baseline is not None else None
        ),
        "metrics": benchmark_metrics,
        "notes": notes,
    }


def _empty_benchmark_metrics() -> dict[str, Any]:
    return {
        "positive_cases": None,
        "negative_controls": None,
        "findings": None,
        "raw_tool_findings": None,
        "out_of_scope_findings": None,
        "expected_finding_recall": None,
        "primary_recall": None,
        "primary_precision": None,
        "validation_coverage": None,
        "tool_evidence_rate": None,
        "validation_gap_rate": None,
        "unexpected_rate": None,
        "negative_control_violations": None,
        "policy_blocked_count": None,
    }


def _benchmark_status(metrics: dict[str, Any]) -> str:
    case_count = int(metrics.get("case_count") or 0)
    completed_count = int(metrics.get("completed_count", case_count))
    skipped_count = int(metrics.get("skipped_count") or 0)
    error_count = int(metrics.get("error_count") or 0)
    if case_count > 0 and completed_count == 0 and skipped_count == case_count:
        return "skipped"
    if case_count > 0 and completed_count == 0 and error_count:
        return "error"
    return "measured"


def _case_audit_status(audit: dict[str, Any]) -> str:
    summary = audit["summary"]
    if int(summary.get("blocked_count", 0)) or not bool(summary.get("loader_passed", False)):
        return "blocked"
    if int(summary.get("warning_count", 0)):
        return "ready-with-warnings"
    return "ready"


def render_benchmark_matrix_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# VeriSec Benchmark Matrix",
        "",
        *_render_benchmark_matrix_table(result),
    ]
    lines.extend(_render_benchmark_claim_boundaries(result))
    return "\n".join(lines).rstrip() + "\n"


def _render_benchmark_matrix_table(result: dict[str, Any]) -> list[str]:
    lines = [
        (
            "| System | Status | Positive Cases | Negative Controls | Primary Recall | "
            "Primary Precision | Findings | Raw | Out Scope | Validation | Tool Evidence | "
            "Neg Ctrl Violations | Notes |"
        ),
        (
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | "
            "---: | ---: | --- |"
        ),
    ]
    for system in result["systems"]:
        metrics = system["metrics"]
        lines.append(
            "| "
            f"{system['label']} | "
            f"{system['status']} | "
            f"{_format_count(metrics.get('positive_cases'))} | "
            f"{_format_count(metrics.get('negative_controls'))} | "
            f"{_format_rate(metrics.get('primary_recall'))} | "
            f"{_format_rate(metrics.get('primary_precision'))} | "
            f"{_format_count(metrics.get('findings'))} | "
            f"{_format_count(metrics.get('raw_tool_findings'))} | "
            f"{_format_count(metrics.get('out_of_scope_findings'))} | "
            f"{_format_rate(metrics.get('validation_coverage'))} | "
            f"{_format_rate(metrics.get('tool_evidence_rate'))} | "
            f"{_format_count(metrics.get('negative_control_violations'))} | "
            f"{system.get('notes', '') or '-'} |"
        )
    return lines


def _render_benchmark_claim_boundaries(result: dict[str, Any]) -> list[str]:
    boundaries = result.get("claim_boundaries", ())
    if not boundaries:
        return []
    return [
        "",
        "## Claim Boundaries",
        "",
        *(f"- {boundary}" for boundary in boundaries),
    ]


def _format_count(value: Any) -> str:
    if value is None:
        return "n/a"
    return str(int(value))
