from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class LabeledPath:
    label: str
    path: Path


class DashboardError(RuntimeError):
    pass


HIGHER_IS_BETTER = (
    "validation_coverage_rate",
    "accepted_finding_rate",
    "primary_precision",
    "primary_finding_recall",
    "supporting_evidence_rate",
    "expected_rule_recall",
    "expected_rule_precision",
    "expected_finding_recall",
    "tool_evidence_rate",
)

LOWER_IS_BETTER = (
    "error_count",
    "validation_gap_rate",
    "unexpected_finding_rate",
    "negative_control_violation_count",
    "required_failure_count",
    "policy_blocked_count",
    "policy_warning_count",
)

MATRIX_COLUMNS = (
    ("cases", "case_count"),
    ("findings", "finding_count"),
    ("validation", "validation_coverage_rate"),
    ("accepted", "accepted_finding_rate"),
    ("primary_precision", "primary_precision"),
    ("primary_recall", "primary_finding_recall"),
    ("supporting", "supporting_evidence_rate"),
    ("unexpected", "unexpected_finding_rate"),
    ("negative_control_violations", "negative_control_violation_count"),
    ("expected_rule_recall", "expected_rule_recall"),
    ("expected_finding_recall", "expected_finding_recall"),
)


def parse_labeled_path(value: str) -> LabeledPath:
    label, separator, raw_path = value.partition("=")
    if not separator or not label.strip() or not raw_path.strip():
        raise DashboardError("Expected labeled path in the form label=path.")
    return LabeledPath(label=label.strip(), path=Path(raw_path.strip()).resolve())


def run_dashboard(
    *,
    evaluations: tuple[LabeledPath, ...],
    output_dir: Path,
    gates: tuple[LabeledPath, ...] = (),
    baseline_path: Path | None = None,
    write_github_summary: bool = False,
) -> dict[str, Any]:
    if not evaluations:
        raise DashboardError("At least one evaluation is required.")

    gate_paths = {gate.label: gate.path for gate in gates}
    suites = tuple(_suite_from_evaluation(item, gate_paths.get(item.label)) for item in evaluations)
    baseline = _load_baseline(baseline_path) if baseline_path is not None else None
    regressions = _compare_with_baseline(suites, baseline) if baseline is not None else []
    result = {
        "summary": _dashboard_summary(suites, regressions),
        "suites": suites,
        "regressions": regressions,
        "baseline_path": str(baseline_path) if baseline_path is not None else None,
    }

    markdown = render_dashboard_markdown(result)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "dashboard.json").write_text(
        json.dumps(result, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (output_dir / "dashboard.md").write_text(markdown, encoding="utf-8")

    if write_github_summary:
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            with Path(summary_path).open("a", encoding="utf-8") as handle:
                handle.write(markdown)
                handle.write("\n")

    return result


def render_dashboard_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# VeriSec Regression Dashboard",
        "",
        "## Summary",
        "",
        f"- Suites: {summary['suite_count']}",
        f"- Total cases: {summary['total_cases']}",
        f"- Total findings: {summary['total_findings']}",
        f"- Gates passed: {summary['gates_passed']}/{summary['gates_total']}",
        f"- Regressions: {summary['regression_count']}",
        "",
        "## Release Matrix",
        "",
        (
            "| Suite | Gate | Cases | Findings | Validation | Accepted | Primary Precision | "
            "Primary Recall | Supporting | Unexpected | Neg Ctrl | Exp Rule | Exp Finding |"
        ),
        (
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | "
            "---: | ---: | ---: | ---: |"
        ),
    ]
    for suite in result["suites"]:
        metrics = suite["metrics"]
        lines.append(
            "| "
            f"{suite['label']} | "
            f"{_format_gate(suite)} | "
            f"{metrics['case_count']} | "
            f"{metrics['finding_count']} | "
            f"{_format_rate(metrics.get('validation_coverage_rate'))} | "
            f"{_format_rate(metrics.get('accepted_finding_rate'))} | "
            f"{_format_rate(metrics.get('primary_precision'))} | "
            f"{_format_rate(metrics.get('primary_finding_recall'))} | "
            f"{_format_rate(metrics.get('supporting_evidence_rate'))} | "
            f"{_format_rate(metrics.get('unexpected_finding_rate'))} | "
            f"{metrics.get('negative_control_violation_count', 0)} | "
            f"{_format_rate(metrics.get('expected_rule_recall'))} | "
            f"{_format_rate(metrics.get('expected_finding_recall'))} |"
        )

    lines.extend(["", "## Regressions", ""])
    if result["regressions"]:
        for regression in result["regressions"]:
            lines.append(
                "- "
                f"{regression['suite']} `{regression['metric']}` "
                f"changed from {_format_value(regression['baseline'])} "
                f"to {_format_value(regression['current'])}."
            )
    else:
        lines.append("No regressions detected.")

    lines.extend(["", "## Sources", "", "| Suite | Evaluation | Gate |", "| --- | --- | --- |"])
    for suite in result["suites"]:
        gate_path = suite.get("gate_path") or "-"
        lines.append(
            "| "
            f"{suite['label']} | "
            f"`{suite['evaluation_path']}` | "
            f"`{gate_path}` |"
        )

    return "\n".join(lines).rstrip() + "\n"


def _suite_from_evaluation(item: LabeledPath, gate_path: Path | None) -> dict[str, Any]:
    evaluation = _load_json(item.path, kind="evaluation")
    summary = evaluation.get("summary", {})
    gate = _load_json(gate_path, kind="gate") if gate_path is not None else None
    return {
        "label": item.label,
        "evaluation_path": str(item.path),
        "gate_path": str(gate_path) if gate_path is not None else None,
        "gate_passed": bool(gate.get("passed")) if gate is not None else None,
        "metrics": _dashboard_metrics(summary),
    }


def _dashboard_metrics(summary: dict[str, Any]) -> dict[str, Any]:
    metrics = {key: _metric_value(summary.get(key)) for _, key in MATRIX_COLUMNS}
    metrics.update(
        {
            "error_count": _metric_value(summary.get("error_count")),
            "validation_gap_rate": _metric_value(summary.get("validation_gap_rate")),
            "required_failure_count": _metric_value(summary.get("required_failure_count")),
            "policy_blocked_count": _metric_value(summary.get("policy_blocked_count")),
            "policy_warning_count": _metric_value(summary.get("policy_warning_count")),
            "avg_confidence": _metric_value(summary.get("avg_confidence")),
        }
    )
    return metrics


def _dashboard_summary(
    suites: tuple[dict[str, Any], ...],
    regressions: list[dict[str, Any]],
) -> dict[str, Any]:
    gates = [suite["gate_passed"] for suite in suites if suite["gate_passed"] is not None]
    return {
        "suite_count": len(suites),
        "total_cases": sum(int(suite["metrics"].get("case_count") or 0) for suite in suites),
        "total_findings": sum(
            int(suite["metrics"].get("finding_count") or 0) for suite in suites
        ),
        "gates_total": len(gates),
        "gates_passed": sum(1 for passed in gates if passed),
        "regression_count": len(regressions),
    }


def _compare_with_baseline(
    suites: tuple[dict[str, Any], ...],
    baseline: dict[str, Any],
) -> list[dict[str, Any]]:
    current_by_label = {suite["label"]: suite for suite in suites}
    baseline_by_label = {suite["label"]: suite for suite in baseline.get("suites", ())}
    regressions: list[dict[str, Any]] = []
    for label, baseline_suite in baseline_by_label.items():
        current_suite = current_by_label.get(label)
        if current_suite is None:
            regressions.append(
                {
                    "suite": label,
                    "metric": "suite_presence",
                    "baseline": "present",
                    "current": "missing",
                }
            )
            continue
        regressions.extend(_metric_regressions(label, baseline_suite, current_suite))
        if baseline_suite.get("gate_passed") is True and current_suite.get("gate_passed") is False:
            regressions.append(
                {
                    "suite": label,
                    "metric": "gate_passed",
                    "baseline": True,
                    "current": False,
                }
            )
    return regressions


def _metric_regressions(
    label: str,
    baseline_suite: dict[str, Any],
    current_suite: dict[str, Any],
) -> list[dict[str, Any]]:
    baseline_metrics = baseline_suite.get("metrics", {})
    current_metrics = current_suite.get("metrics", {})
    regressions: list[dict[str, Any]] = []
    for metric in HIGHER_IS_BETTER:
        baseline = baseline_metrics.get(metric)
        current = current_metrics.get(metric)
        if _is_number(baseline) and _is_number(current) and float(current) < float(baseline):
            regressions.append(_regression(label, metric, baseline, current))
    for metric in LOWER_IS_BETTER:
        baseline = baseline_metrics.get(metric)
        current = current_metrics.get(metric)
        if _is_number(baseline) and _is_number(current) and float(current) > float(baseline):
            regressions.append(_regression(label, metric, baseline, current))
    return regressions


def _regression(label: str, metric: str, baseline: Any, current: Any) -> dict[str, Any]:
    return {
        "suite": label,
        "metric": metric,
        "baseline": baseline,
        "current": current,
    }


def _load_baseline(path: Path) -> dict[str, Any]:
    return _load_json(path, kind="baseline dashboard")


def _load_json(path: Path | None, *, kind: str) -> dict[str, Any]:
    if path is None:
        return {}
    if not path.exists():
        raise DashboardError(f"{kind.title()} path does not exist: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _metric_value(value: Any) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return value
    return float(value)


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _format_gate(suite: dict[str, Any]) -> str:
    if suite.get("gate_passed") is None:
        return "n/a"
    return "passed" if suite["gate_passed"] else "failed"


def _format_rate(value: Any) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.2f}"


def _format_value(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)
