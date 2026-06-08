import json
from pathlib import Path

import pytest

from verisec_agent.dashboard import (
    DashboardError,
    LabeledPath,
    parse_labeled_path,
    run_dashboard,
)


def test_run_dashboard_writes_release_matrix(tmp_path: Path) -> None:
    demo_eval = _write_evaluation(
        tmp_path / "demo-evaluation.json",
        case_count=1,
        finding_count=1,
        validation_coverage_rate=0.5,
        accepted_finding_rate=1.0,
        primary_precision=1.0,
        primary_finding_recall=1.0,
        unexpected_finding_rate=0.0,
        negative_control_violation_count=0,
    )
    negative_eval = _write_evaluation(
        tmp_path / "negative-evaluation.json",
        case_count=10,
        finding_count=1,
        validation_coverage_rate=0.0,
        accepted_finding_rate=1.0,
        primary_precision=0.0,
        primary_finding_recall=None,
        unexpected_finding_rate=0.0,
        negative_control_violation_count=0,
    )
    demo_gate = _write_gate(tmp_path / "demo-gate.json", passed=True)

    result = run_dashboard(
        evaluations=(
            LabeledPath("demo", demo_eval),
            LabeledPath("negative-controls", negative_eval),
        ),
        gates=(LabeledPath("demo", demo_gate),),
        output_dir=tmp_path / "dashboard",
    )

    assert result["summary"]["suite_count"] == 2
    assert result["summary"]["total_cases"] == 11
    assert result["summary"]["gates_passed"] == 1
    assert result["summary"]["regression_count"] == 0
    assert (tmp_path / "dashboard" / "dashboard.json").exists()
    markdown = (tmp_path / "dashboard" / "dashboard.md").read_text(encoding="utf-8")
    assert "| demo | passed | 1 | 1 | 0.50 | 1.00 | 1.00 | 1.00 |" in markdown
    assert "| negative-controls | n/a | 10 | 1 | 0.00 | 1.00 | 0.00 | n/a |" in markdown


def test_run_dashboard_reports_quality_regressions_against_baseline(
    tmp_path: Path,
) -> None:
    baseline_eval = _write_evaluation(
        tmp_path / "baseline-evaluation.json",
        case_count=1,
        finding_count=1,
        validation_coverage_rate=1.0,
        accepted_finding_rate=1.0,
        primary_precision=1.0,
        primary_finding_recall=1.0,
        unexpected_finding_rate=0.0,
        negative_control_violation_count=0,
    )
    baseline_result = run_dashboard(
        evaluations=(LabeledPath("demo", baseline_eval),),
        output_dir=tmp_path / "baseline",
    )
    current_eval = _write_evaluation(
        tmp_path / "current-evaluation.json",
        case_count=1,
        finding_count=2,
        validation_coverage_rate=0.5,
        accepted_finding_rate=0.5,
        primary_precision=0.5,
        primary_finding_recall=1.0,
        unexpected_finding_rate=0.5,
        negative_control_violation_count=1,
    )

    result = run_dashboard(
        evaluations=(LabeledPath("demo", current_eval),),
        baseline_path=tmp_path / "baseline" / "dashboard.json",
        output_dir=tmp_path / "current",
    )

    assert baseline_result["summary"]["regression_count"] == 0
    metrics = {(item["suite"], item["metric"]) for item in result["regressions"]}
    assert ("demo", "validation_coverage_rate") in metrics
    assert ("demo", "accepted_finding_rate") in metrics
    assert ("demo", "primary_precision") in metrics
    assert ("demo", "unexpected_finding_rate") in metrics
    assert ("demo", "negative_control_violation_count") in metrics


def test_parse_labeled_path_requires_label_and_path() -> None:
    parsed = parse_labeled_path("demo=out/evaluation.json")

    assert parsed.label == "demo"
    assert parsed.path.name == "evaluation.json"
    with pytest.raises(DashboardError, match="label=path"):
        parse_labeled_path("evaluation.json")


def _write_evaluation(
    path: Path,
    *,
    case_count: int,
    finding_count: int,
    validation_coverage_rate: float,
    accepted_finding_rate: float,
    primary_precision: float,
    primary_finding_recall: float | None,
    unexpected_finding_rate: float,
    negative_control_violation_count: int,
) -> Path:
    summary = {
        "case_count": case_count,
        "finding_count": finding_count,
        "validation_coverage_rate": validation_coverage_rate,
        "accepted_finding_rate": accepted_finding_rate,
        "primary_precision": primary_precision,
        "primary_finding_recall": primary_finding_recall,
        "supporting_evidence_rate": 0.0,
        "unexpected_finding_rate": unexpected_finding_rate,
        "negative_control_violation_count": negative_control_violation_count,
        "expected_rule_recall": 1.0,
        "expected_rule_precision": 1.0,
        "expected_finding_recall": primary_finding_recall,
        "tool_evidence_rate": 0.0,
        "validation_gap_rate": 0.0,
        "error_count": 0,
        "required_failure_count": 0,
        "policy_blocked_count": 0,
        "policy_warning_count": 0,
        "avg_confidence": 0.7,
    }
    path.write_text(json.dumps({"summary": summary, "cases": []}), encoding="utf-8")
    return path


def _write_gate(path: Path, *, passed: bool) -> Path:
    path.write_text(json.dumps({"passed": passed, "failures": []}), encoding="utf-8")
    return path
