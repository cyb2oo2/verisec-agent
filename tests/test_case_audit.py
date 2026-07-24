import json
from pathlib import Path

from verisec_agent.case_audit import run_case_audit


def test_run_case_audit_scores_ready_seed_cases() -> None:
    result = run_case_audit(
        cases_path=Path("examples/oss_seed_cases.json"),
        require_verification=True,
    )

    summary = result["summary"]
    assert summary["case_count"] == 3
    assert summary["ready_count"] == 3
    assert summary["blocked_count"] == 0
    assert summary["positive_case_count"] == 3
    assert summary["security_advisory_case_count"] == 3
    assert summary["verification_ready_count"] == 3
    assert summary["loader_passed"] is True


def test_run_case_audit_reports_blockers_and_warnings(tmp_path: Path) -> None:
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "id": "bad-case",
                        "diff": "missing.diff",
                        "expected_findings": [
                            {
                                "rule_id": "py-shell-true",
                                "role": "maybe",
                            }
                        ],
                    },
                    {
                        "id": "bad-case",
                        "repo_url": "https://example.test/repo.git",
                        "base_ref": "abc",
                        "head_ref": "def",
                        "expected_findings": [
                            {
                                "rule_id": "py-shell-true",
                                "role": "primary",
                            }
                        ],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    result = run_case_audit(
        cases_path=cases_path,
        output_dir=tmp_path / "audit",
        require_verification=True,
    )

    assert result["summary"]["case_count"] == 2
    assert result["summary"]["blocked_count"] == 2
    assert result["summary"]["warning_count"] > 0
    assert result["loader_error"] is not None
    assert any("duplicated" in error for error in result["cases"][0]["errors"])
    assert any("unknown role" in error for error in result["cases"][0]["errors"])
    assert any("diff path does not exist" in error for error in result["cases"][0]["errors"])
    assert (tmp_path / "audit" / "case_audit.json").exists()
    assert (tmp_path / "audit" / "case_audit.md").exists()


def test_run_case_audit_handles_negative_controls_without_verification() -> None:
    result = run_case_audit(
        cases_path=Path("examples/negative_control_cases.json"),
        require_verification=True,
    )

    summary = result["summary"]
    assert summary["case_count"] == 15
    assert summary["blocked_count"] == 0
    assert summary["negative_control_case_count"] == 15
    assert summary["verification_ready_count"] == 0
