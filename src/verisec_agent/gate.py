from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class GateThresholds:
    min_validation_coverage: float = 0.0
    min_tool_evidence_rate: float = 0.0
    min_avg_confidence: float = 0.0
    min_accepted_finding_rate: float = 0.0
    min_primary_precision: float = 0.0
    min_primary_finding_recall: float = 0.0
    min_supporting_evidence_rate: float = 0.0
    max_validation_gap_rate: float = 1.0
    max_unexpected_finding_rate: float = 1.0
    max_negative_control_violations: int = 0
    max_required_failures: int = 0
    max_errors: int = 0
    max_policy_blocked: int = 0
    max_critical: int | None = None
    max_high: int | None = None
    # Total findings across the suite. Ratchets a noise measurement where every
    # finding is unexpected, so rate-based thresholds collapse to all-or-nothing.
    max_findings: int | None = None


class GateError(RuntimeError):
    pass


def run_gate(
    *,
    report_path: Path | None = None,
    evaluation_path: Path | None = None,
    thresholds: GateThresholds | None = None,
    output_dir: Path | None = None,
    write_github_summary: bool = False,
) -> dict[str, Any]:
    if (report_path is None) == (evaluation_path is None):
        raise GateError("Provide exactly one gate source: report_path or evaluation_path.")

    thresholds = thresholds or GateThresholds()
    source_path = report_path or evaluation_path
    assert source_path is not None
    if not source_path.exists():
        raise GateError(f"Gate source does not exist: {source_path}")

    payload = json.loads(source_path.read_text(encoding="utf-8"))
    metrics = (
        _metrics_from_report(payload)
        if report_path is not None
        else _metrics_from_evaluation(payload)
    )
    failures = _evaluate_thresholds(metrics, thresholds)
    result = {
        "passed": not failures,
        "source_kind": "report" if report_path is not None else "evaluation",
        "source_path": str(source_path),
        "thresholds": thresholds.__dict__,
        "metrics": metrics,
        "failures": failures,
    }

    markdown = render_gate_markdown(result)
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "gate.json").write_text(
            json.dumps(result, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        (output_dir / "gate.md").write_text(markdown, encoding="utf-8")

    if write_github_summary:
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            with Path(summary_path).open("a", encoding="utf-8") as handle:
                handle.write(markdown)
                handle.write("\n")

    return result


def render_gate_markdown(result: dict[str, Any]) -> str:
    status = "passed" if result["passed"] else "failed"
    metrics = result["metrics"]
    lines = [
        f"# VeriSec Gate: {status}",
        "",
        f"- Source: `{result['source_path']}`",
        f"- Findings: {metrics['finding_count']}",
        f"- Average confidence: {metrics['avg_confidence']:.2f}",
        f"- Validation coverage: {metrics['validation_coverage_rate']:.2f}",
        f"- Tool evidence rate: {metrics['tool_evidence_rate']:.2f}",
        f"- Validation gap rate: {metrics['validation_gap_rate']:.2f}",
        f"- Required failures: {metrics['required_failure_count']}",
        f"- Policy-blocked tools: {metrics['policy_blocked_count']}",
        f"- Errors: {metrics['error_count']}",
        f"- Critical findings: {metrics['critical_count']}",
        f"- High findings: {metrics['high_count']}",
    ]
    if metrics["reviewer_noise_available"]:
        lines.extend(
            [
                f"- Accepted finding rate: {metrics['accepted_finding_rate']:.2f}",
                f"- Primary precision: {metrics['primary_precision']:.2f}",
                f"- Primary finding recall: {metrics['primary_finding_recall']:.2f}",
                f"- Supporting evidence rate: {metrics['supporting_evidence_rate']:.2f}",
                f"- Unexpected finding rate: {metrics['unexpected_finding_rate']:.2f}",
                "- Negative-control violations: "
                f"{metrics['negative_control_violation_count']}",
            ]
        )
    else:
        lines.append("- Reviewer-noise metrics: not available for this source")
    lines.append("")
    if result["failures"]:
        lines.extend(["## Failures", ""])
        lines.extend(f"- {failure}" for failure in result["failures"])
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _metrics_from_report(report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get("summary", {})
    finding_count = int(summary.get("finding_count", 0))
    validation_steps = int(summary.get("validation_step_count", 0))
    validation_covered = int(summary.get("validation_covered", 0))
    severity_counts = summary.get("severity_counts", {})
    return {
        "case_count": 1,
        "error_count": 0,
        "finding_count": finding_count,
        "avg_confidence": float(summary.get("avg_confidence", 0.0)),
        "validation_coverage_rate": _coverage_rate(
            validation_covered,
            validation_steps,
            finding_count,
        ),
        "tool_evidence_rate": _safe_div(
            int(summary.get("tool_supported_findings", 0)),
            finding_count,
        ),
        "validation_gap_rate": _safe_div(
            int(summary.get("validation_gap_findings", 0)),
            finding_count,
        ),
        "reviewer_noise_available": _has_reviewer_noise_summary(summary),
        "accepted_finding_rate": _summary_float(summary, "accepted_finding_rate"),
        "primary_precision": _summary_float(summary, "primary_precision"),
        "primary_finding_recall": _summary_float(summary, "primary_finding_recall"),
        "supporting_evidence_rate": _summary_float(summary, "supporting_evidence_rate"),
        "unexpected_finding_rate": _summary_float(summary, "unexpected_finding_rate"),
        "negative_control_violation_count": int(
            summary.get("negative_control_violation_count", 0)
        ),
        "required_failure_count": len(summary.get("required_failures", ())),
        "policy_blocked_count": int(summary.get("policy_blocked_count", 0)),
        "critical_count": int(severity_counts.get("critical", 0)),
        "high_count": int(severity_counts.get("high", 0)),
    }


def _metrics_from_evaluation(evaluation: dict[str, Any]) -> dict[str, Any]:
    summary = evaluation.get("summary", {})
    finding_count = int(summary.get("finding_count", 0))
    validation_steps = int(summary.get("validation_step_count", 0))
    validation_covered = int(summary.get("validation_covered", 0))
    return {
        "case_count": int(summary.get("case_count", 0)),
        "error_count": int(summary.get("error_count", 0)),
        "finding_count": finding_count,
        "avg_confidence": float(summary.get("avg_confidence", 0.0)),
        "validation_coverage_rate": float(
            summary.get(
                "validation_coverage_rate",
                _coverage_rate(validation_covered, validation_steps, finding_count),
            )
        ),
        "tool_evidence_rate": float(summary.get("tool_evidence_rate", 0.0)),
        "validation_gap_rate": float(summary.get("validation_gap_rate", 0.0)),
        "reviewer_noise_available": _has_reviewer_noise_summary(summary),
        "accepted_finding_rate": _summary_float(summary, "accepted_finding_rate"),
        "primary_precision": _summary_float(summary, "primary_precision"),
        "primary_finding_recall": _summary_float(summary, "primary_finding_recall"),
        "supporting_evidence_rate": _summary_float(summary, "supporting_evidence_rate"),
        "unexpected_finding_rate": _summary_float(summary, "unexpected_finding_rate"),
        "negative_control_violation_count": int(
            summary.get("negative_control_violation_count", 0)
        ),
        "required_failure_count": int(summary.get("required_failure_count", 0)),
        "policy_blocked_count": int(summary.get("policy_blocked_count", 0)),
        "critical_count": _count_case_severity(evaluation, "critical"),
        "high_count": _count_case_severity(evaluation, "high"),
    }


def _evaluate_thresholds(metrics: dict[str, Any], thresholds: GateThresholds) -> list[str]:
    failures: list[str] = []
    _check_min(
        failures,
        "validation coverage",
        metrics["validation_coverage_rate"],
        thresholds.min_validation_coverage,
    )
    _check_min(
        failures,
        "tool evidence rate",
        metrics["tool_evidence_rate"],
        thresholds.min_tool_evidence_rate,
    )
    # A review with no findings has nothing to be confident about, and the mean of
    # an empty set is reported as 0.0. Asserting a floor on it would fail exactly
    # the reviews that found nothing wrong, so the check is vacuous here - matching
    # how _coverage_rate already treats an empty validation plan.
    if metrics["finding_count"]:
        _check_min(
            failures,
            "average confidence",
            metrics["avg_confidence"],
            thresholds.min_avg_confidence,
        )
    _check_min(
        failures,
        "accepted finding rate",
        metrics["accepted_finding_rate"],
        thresholds.min_accepted_finding_rate,
    )
    _check_min(
        failures,
        "primary precision",
        metrics["primary_precision"],
        thresholds.min_primary_precision,
    )
    _check_min(
        failures,
        "primary finding recall",
        metrics["primary_finding_recall"],
        thresholds.min_primary_finding_recall,
    )
    _check_min(
        failures,
        "supporting evidence rate",
        metrics["supporting_evidence_rate"],
        thresholds.min_supporting_evidence_rate,
    )
    _check_max(
        failures,
        "validation gap rate",
        metrics["validation_gap_rate"],
        thresholds.max_validation_gap_rate,
    )
    _check_max(
        failures,
        "unexpected finding rate",
        metrics["unexpected_finding_rate"],
        thresholds.max_unexpected_finding_rate,
    )
    _check_max(
        failures,
        "negative-control violations",
        metrics["negative_control_violation_count"],
        thresholds.max_negative_control_violations,
    )
    _check_max(
        failures,
        "required failures",
        metrics["required_failure_count"],
        thresholds.max_required_failures,
    )
    _check_max(
        failures,
        "policy-blocked tools",
        metrics["policy_blocked_count"],
        thresholds.max_policy_blocked,
    )
    _check_max(failures, "errors", metrics["error_count"], thresholds.max_errors)
    if thresholds.max_critical is not None:
        _check_max(
            failures,
            "critical findings",
            metrics["critical_count"],
            thresholds.max_critical,
        )
    if thresholds.max_high is not None:
        _check_max(failures, "high findings", metrics["high_count"], thresholds.max_high)
    if thresholds.max_findings is not None:
        _check_max(failures, "findings", metrics["finding_count"], thresholds.max_findings)
    return failures


def _check_min(failures: list[str], name: str, actual: float, expected: float) -> None:
    if actual < expected:
        failures.append(f"{name} {actual:.2f} is below required minimum {expected:.2f}")


def _check_max(failures: list[str], name: str, actual: float, expected: float) -> None:
    if actual > expected:
        failures.append(f"{name} {actual:.2f} exceeds allowed maximum {expected:.2f}")


def _count_case_severity(evaluation: dict[str, Any], severity: str) -> int:
    # Batch summaries intentionally stay compact. If future case summaries carry
    # severity counts, gate will consume them without changing the contract.
    return sum(
        int(case.get("severity_counts", {}).get(severity, 0))
        for case in evaluation.get("cases", ())
    )


def _summary_float(summary: dict[str, Any], key: str) -> float:
    value = summary.get(key, 0.0)
    if value is None:
        return 0.0
    return float(value)


def _has_reviewer_noise_summary(summary: dict[str, Any]) -> bool:
    return any(
        key in summary
        for key in (
            "accepted_finding_rate",
            "primary_precision",
            "primary_finding_recall",
            "supporting_evidence_rate",
            "unexpected_finding_rate",
            "negative_control_violation_count",
        )
    )


def _safe_div(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 4)


def _coverage_rate(covered: int, total: int, finding_count: int) -> float:
    if total == 0 and finding_count == 0:
        return 1.0
    return _safe_div(covered, total)
