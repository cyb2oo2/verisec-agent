import json
from pathlib import Path

from pytest import MonkeyPatch, raises

from verisec_agent.pr_comment import (
    COMMENT_MARKER,
    PullRequestCommentError,
    render_pr_comment,
    write_pr_comment,
)


def test_render_report_pr_comment_includes_findings_and_gate(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "finding_count": 1,
                    "avg_confidence": 0.66,
                    "validation_covered": 1,
                    "validation_step_count": 2,
                    "tool_supported_findings": 0,
                    "validation_gap_findings": 1,
                    "tool_finding_count": 0,
                    "required_failures": [],
                },
                "findings": [
                    {
                        "rule_id": "py-shell-true",
                        "title": "Shell execution path introduced",
                        "severity": "high",
                        "confidence": 0.66,
                        "file_path": "app.py",
                        "start_line": 3,
                        "end_line": 3,
                        "risk": "Command injection",
                        "fix_guidance": "Use shell=False",
                        "confidence_notes": "Validation gap remains.",
                        "evidence": "+3: subprocess.run(user_input, shell=True)",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    gate_path = tmp_path / "gate.json"
    gate_path.write_text(
        json.dumps({"passed": True, "failures": []}),
        encoding="utf-8",
    )

    markdown = render_pr_comment(report_path=report_path, gate_path=gate_path)

    assert COMMENT_MARKER in markdown
    assert "**Gate:** passed" in markdown
    assert "py-shell-true" in markdown
    assert "Validation gap remains." in markdown


def test_write_evaluation_pr_comment_includes_case_table_and_gate_failures(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    bundle_path = tmp_path / "verisec-runs" / "demo"
    evaluation_path = tmp_path / "evaluation.json"
    evaluation_path.write_text(
        json.dumps(
            {
                "summary": {
                    "case_count": 1,
                    "completed_count": 1,
                    "error_count": 0,
                    "finding_count": 1,
                    "avg_confidence": 0.66,
                    "validation_coverage_rate": 0.5,
                    "tool_evidence_rate": 0.0,
                    "validation_gap_rate": 1.0,
                    "expected_rule_recall": 1.0,
                    "expected_rule_precision": 1.0,
                },
                "cases": [
                    {
                        "case_id": "demo",
                        "status": "completed",
                        "finding_count": 1,
                        "expected_rule_hits": ["py-shell-true"],
                        "bundle_path": str(bundle_path),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    gate_path = tmp_path / "gate.json"
    gate_path.write_text(
        json.dumps(
            {
                "passed": False,
                "failures": ["validation coverage 0.50 is below required minimum 0.90"],
            }
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "comment.md"

    monkeypatch.chdir(tmp_path)
    markdown = write_pr_comment(
        output_path=output_path,
        evaluation_path=evaluation_path,
        gate_path=gate_path,
    )

    assert output_path.read_text(encoding="utf-8") == markdown
    assert "**Gate:** failed" in markdown
    assert "validation coverage 0.50" in markdown
    assert "| demo | completed | 1 | py-shell-true | `verisec-runs/demo` |" in markdown


def test_render_pr_comment_reports_invalid_json(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text("{not json", encoding="utf-8")

    with raises(PullRequestCommentError, match="JSON source is invalid"):
        render_pr_comment(report_path=report_path)
