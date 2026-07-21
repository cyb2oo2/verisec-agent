import json
from pathlib import Path

from verisec_agent.gate import GateThresholds, run_gate


def test_gate_max_findings_ratchets_total_count(tmp_path: Path) -> None:
    """A noise corpus has no expected findings, so rate thresholds collapse to all-or-nothing.

    `max_findings` is what lets a measured level be held without demanding zero.
    """
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps({"summary": {"finding_count": 22, "severity_counts": {}}}),
        encoding="utf-8",
    )

    at_ceiling = run_gate(
        report_path=report_path,
        thresholds=GateThresholds(max_findings=22),
        output_dir=tmp_path / "at",
    )
    over_ceiling = run_gate(
        report_path=report_path,
        thresholds=GateThresholds(max_findings=21),
        output_dir=tmp_path / "over",
    )

    assert at_ceiling["passed"] is True
    assert over_ceiling["passed"] is False
    assert any("findings" in failure for failure in over_ceiling["failures"])


def test_gate_passes_report_when_thresholds_are_met(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "finding_count": 1,
                    "avg_confidence": 0.82,
                    "validation_step_count": 2,
                    "validation_covered": 2,
                    "tool_supported_findings": 1,
                    "validation_gap_findings": 0,
                    "required_failures": [],
                    "severity_counts": {"high": 1},
                }
            }
        ),
        encoding="utf-8",
    )

    result = run_gate(
        report_path=report_path,
        thresholds=GateThresholds(
            min_validation_coverage=1.0,
            min_tool_evidence_rate=1.0,
            min_avg_confidence=0.8,
            max_high=1,
        ),
        output_dir=tmp_path / "gate",
    )

    assert result["passed"] is True
    assert result["failures"] == []
    assert (tmp_path / "gate" / "gate.json").exists()
    assert (tmp_path / "gate" / "gate.md").exists()
    assert "Reviewer-noise metrics: not available" in (
        tmp_path / "gate" / "gate.md"
    ).read_text(encoding="utf-8")


def test_gate_treats_clean_report_as_fully_covered(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "finding_count": 0,
                    "avg_confidence": 0.0,
                    "validation_step_count": 0,
                    "validation_covered": 0,
                    "tool_supported_findings": 0,
                    "validation_gap_findings": 0,
                    "required_failures": [],
                    "severity_counts": {},
                }
            }
        ),
        encoding="utf-8",
    )

    result = run_gate(
        report_path=report_path,
        thresholds=GateThresholds(min_validation_coverage=1.0),
    )

    assert result["passed"] is True
    assert result["metrics"]["validation_coverage_rate"] == 1.0


def test_gate_does_not_apply_confidence_floor_to_a_clean_report(tmp_path: Path) -> None:
    """A review with no findings must not fail the average-confidence floor.

    The mean of an empty set is reported as 0.0, so applying the floor would fail
    exactly the reviews that found nothing wrong - a documentation-only pull
    request, for instance.
    """
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "finding_count": 0,
                    "avg_confidence": 0.0,
                    "validation_step_count": 0,
                    "validation_covered": 0,
                    "tool_supported_findings": 0,
                    "validation_gap_findings": 0,
                    "required_failures": [],
                    "severity_counts": {},
                }
            }
        ),
        encoding="utf-8",
    )

    result = run_gate(
        report_path=report_path,
        thresholds=GateThresholds(min_avg_confidence=0.6),
    )

    assert result["passed"] is True
    assert result["failures"] == []


def test_gate_still_applies_confidence_floor_when_findings_exist(tmp_path: Path) -> None:
    """Guard against the clean-report exemption swallowing real low-confidence runs."""
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "finding_count": 2,
                    "avg_confidence": 0.4,
                    "validation_step_count": 2,
                    "validation_covered": 2,
                    "tool_supported_findings": 2,
                    "validation_gap_findings": 0,
                    "required_failures": [],
                    "severity_counts": {"medium": 2},
                }
            }
        ),
        encoding="utf-8",
    )

    result = run_gate(
        report_path=report_path,
        thresholds=GateThresholds(min_avg_confidence=0.6),
    )

    assert result["passed"] is False
    assert any("average confidence" in failure for failure in result["failures"])


def test_gate_fails_evaluation_when_thresholds_are_missed(tmp_path: Path) -> None:
    evaluation_path = tmp_path / "evaluation.json"
    evaluation_path.write_text(
        json.dumps(
            {
                "summary": {
                    "case_count": 2,
                    "error_count": 1,
                    "finding_count": 4,
                    "avg_confidence": 0.52,
                    "validation_coverage_rate": 0.25,
                    "tool_evidence_rate": 0.0,
                    "validation_gap_rate": 0.75,
                    "required_failure_count": 1,
                },
                "cases": [],
            }
        ),
        encoding="utf-8",
    )

    result = run_gate(
        evaluation_path=evaluation_path,
        thresholds=GateThresholds(
            min_validation_coverage=0.8,
            min_tool_evidence_rate=0.2,
            min_avg_confidence=0.6,
            max_validation_gap_rate=0.2,
            max_required_failures=0,
            max_errors=0,
        ),
    )

    assert result["passed"] is False
    assert len(result["failures"]) == 6
    assert any("validation coverage" in failure for failure in result["failures"])
    assert any("errors" in failure for failure in result["failures"])


def test_gate_fails_evaluation_when_reviewer_noise_thresholds_are_missed(
    tmp_path: Path,
) -> None:
    evaluation_path = tmp_path / "evaluation.json"
    evaluation_path.write_text(
        json.dumps(
            {
                "summary": {
                    "case_count": 1,
                    "error_count": 0,
                    "finding_count": 3,
                    "avg_confidence": 0.72,
                    "validation_coverage_rate": 1.0,
                    "tool_evidence_rate": 0.0,
                    "validation_gap_rate": 0.0,
                    "required_failure_count": 0,
                    "accepted_finding_rate": 0.67,
                    "primary_precision": 0.33,
                    "primary_finding_recall": 0.5,
                    "supporting_evidence_rate": 0.34,
                    "unexpected_finding_rate": 0.33,
                    "negative_control_violation_count": 1,
                },
                "cases": [],
            }
        ),
        encoding="utf-8",
    )

    result = run_gate(
        evaluation_path=evaluation_path,
        thresholds=GateThresholds(
            min_accepted_finding_rate=0.9,
            min_primary_precision=0.5,
            min_primary_finding_recall=0.8,
            min_supporting_evidence_rate=0.5,
            max_unexpected_finding_rate=0.1,
            max_negative_control_violations=0,
        ),
    )

    assert result["passed"] is False
    assert len(result["failures"]) == 6
    assert result["metrics"]["accepted_finding_rate"] == 0.67
    assert result["metrics"]["reviewer_noise_available"] is True
    assert any("accepted finding rate" in failure for failure in result["failures"])
    assert any("primary precision" in failure for failure in result["failures"])
    assert any("primary finding recall" in failure for failure in result["failures"])
    assert any("supporting evidence rate" in failure for failure in result["failures"])
    assert any("unexpected finding rate" in failure for failure in result["failures"])
    assert any("negative-control violations" in failure for failure in result["failures"])
