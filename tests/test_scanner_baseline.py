import json
from pathlib import Path

from verisec_agent.scanner_baseline import run_scanner_baseline


def test_run_scanner_baseline_scores_semgrep_artifacts(tmp_path: Path) -> None:
    cases_path = _write_cases(
        tmp_path,
        [
            {
                "id": "shell-case",
                "diff": "case.diff",
                "expected_findings": [
                    {
                        "rule_id": "py-shell-true",
                        "file_path": "app.py",
                        "start_line": 7,
                        "severity": "medium",
                        "role": "primary",
                    }
                ],
            }
        ],
    )
    results_path = _write_results(
        tmp_path,
        [
            {
                "id": "shell-case",
                "results": [
                    _semgrep_result(
                        check_id="python.lang.security.audit.subprocess-shell-true",
                        path="app.py",
                        line=7,
                    )
                ],
            }
        ],
    )

    result = run_scanner_baseline(
        cases_path=cases_path,
        results_path=results_path,
        output_dir=tmp_path / "baseline",
        fail_fast=True,
    )

    summary = result["summary"]
    assert summary["case_count"] == 1
    assert summary["finding_count"] == 1
    assert summary["expected_finding_recall"] == 1.0
    assert summary["primary_precision"] == 1.0
    assert summary["primary_finding_recall"] == 1.0
    assert summary["tool_evidence_rate"] == 1.0
    assert summary["validation_coverage_rate"] == 0.0
    assert (tmp_path / "baseline" / "baseline.json").exists()
    assert (tmp_path / "baseline" / "baseline.md").exists()


def test_run_scanner_baseline_counts_negative_control_violations(tmp_path: Path) -> None:
    cases_path = _write_cases(
        tmp_path,
        [
            {
                "id": "negative-shell",
                "diff": "case.diff",
                "expected_findings": [
                    {
                        "rule_id": "py-shell-true",
                        "file_path": "app.py",
                        "role": "negative-control",
                    }
                ],
            }
        ],
    )
    results_path = _write_results(
        tmp_path,
        [
            {
                "id": "negative-shell",
                "results": [
                    _semgrep_result(
                        check_id="python.lang.security.audit.subprocess-shell-true",
                        path="app.py",
                        line=10,
                    )
                ],
            }
        ],
    )

    result = run_scanner_baseline(
        cases_path=cases_path,
        results_path=results_path,
        output_dir=tmp_path / "baseline",
        fail_fast=True,
    )

    summary = result["summary"]
    assert summary["negative_control_violation_count"] == 1
    assert summary["unexpected_taxonomy"] == {"negative-control-violation": 1}


def test_run_scanner_baseline_uses_default_semgrep_rule_map(tmp_path: Path) -> None:
    cases_path = _write_cases(
        tmp_path,
        [
            {
                "id": "shell-case",
                "diff": "case.diff",
                "expected_findings": [
                    {
                        "rule_id": "py-shell-true",
                        "file_path": "app.py",
                        "start_line": 7,
                        "severity": "high",
                        "role": "primary",
                    }
                ],
            }
        ],
    )
    results_path = tmp_path / "semgrep.json"
    results_path.write_text(
        json.dumps(
            {
                "adapter": "semgrep",
                "cases": [
                    {
                        "id": "shell-case",
                        "results": [
                            _semgrep_result(
                                check_id=(
                                    "python.lang.security.audit."
                                    "subprocess-shell-true.subprocess-shell-true"
                                ),
                                path="app.py",
                                line=7,
                                severity="ERROR",
                            )
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = run_scanner_baseline(
        cases_path=cases_path,
        results_path=results_path,
        output_dir=tmp_path / "baseline",
        fail_fast=True,
    )

    assert result["summary"]["expected_finding_recall"] == 1.0
    assert result["cases"][0]["finding_labels"][0]["role"] == "primary"


def test_run_scanner_baseline_scores_only_diff_scoped_findings(tmp_path: Path) -> None:
    cases_path = _write_cases(
        tmp_path,
        [
            {
                "id": "shell-case",
                "diff": "case.diff",
                "expected_findings": [
                    {
                        "rule_id": "py-shell-true",
                        "file_path": "app.py",
                        "start_line": 7,
                        "severity": "medium",
                        "role": "primary",
                    }
                ],
            }
        ],
    )
    results_path = _write_results(
        tmp_path,
        [
            {
                "id": "shell-case",
                "results": [
                    _semgrep_result(
                        check_id="python.lang.security.audit.subprocess-shell-true",
                        path="app.py",
                        line=7,
                    ),
                    _semgrep_result(
                        check_id="python.lang.security.audit.subprocess-shell-true",
                        path="app.py",
                        line=50,
                    ),
                ],
            }
        ],
    )

    result = run_scanner_baseline(
        cases_path=cases_path,
        results_path=results_path,
        output_dir=tmp_path / "baseline",
        fail_fast=True,
    )

    case = result["cases"][0]
    assert result["summary"]["finding_count"] == 1
    assert result["summary"]["raw_tool_finding_count"] == 2
    assert result["summary"]["out_of_scope_finding_count"] == 1
    assert result["summary"]["primary_precision"] == 1.0
    assert case["scanner_findings"][0]["start_line"] == 7
    assert case["out_of_scope_finding_samples"][0]["start_line"] == 50


def test_run_scanner_baseline_uses_inline_diff_scope(tmp_path: Path) -> None:
    cases_path = _write_cases(
        tmp_path,
        [
            {
                "id": "shell-case",
                "diff": "case.diff",
                "expected_findings": [
                    {
                        "rule_id": "py-shell-true",
                        "file_path": "app.py",
                        "start_line": 7,
                        "severity": "medium",
                        "role": "primary",
                    }
                ],
            }
        ],
    )
    inline_diff = (tmp_path / "case.diff").read_text(encoding="utf-8")
    results_path = _write_results(
        tmp_path,
        [
            {
                "id": "shell-case",
                "diff": inline_diff,
                "results": [
                    _semgrep_result(
                        check_id="python.lang.security.audit.subprocess-shell-true",
                        path="app.py",
                        line=50,
                    )
                ],
            }
        ],
    )

    result = run_scanner_baseline(
        cases_path=cases_path,
        results_path=results_path,
        output_dir=tmp_path / "baseline",
        fail_fast=True,
    )

    case = result["cases"][0]
    assert case["diff_scope"]["source"] == "inline"
    assert result["summary"]["finding_count"] == 0
    assert result["summary"]["raw_tool_finding_count"] == 1
    assert result["summary"]["out_of_scope_finding_count"] == 1


def _write_cases(tmp_path: Path, cases: list[dict[str, object]]) -> Path:
    (tmp_path / "case.diff").write_text(
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,10 +1,10 @@\n"
        " line1\n"
        " line2\n"
        " line3\n"
        " line4\n"
        " line5\n"
        " line6\n"
        "-old7\n"
        "+new7\n"
        " line8\n"
        " line9\n"
        " line10\n",
        encoding="utf-8",
    )
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(json.dumps({"cases": cases}), encoding="utf-8")
    return cases_path


def _write_results(tmp_path: Path, cases: list[dict[str, object]]) -> Path:
    results_path = tmp_path / "semgrep.json"
    results_path.write_text(
        json.dumps(
            {
                "adapter": "semgrep",
                "rule_map": {
                    "python.lang.security.audit.subprocess-shell-true": "py-shell-true"
                },
                "severity_map": {
                    "warning": "medium",
                },
                "cases": cases,
            }
        ),
        encoding="utf-8",
    )
    return results_path


def _semgrep_result(
    *,
    check_id: str,
    path: str,
    line: int,
    severity: str = "WARNING",
) -> dict[str, object]:
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line},
        "end": {"line": line},
        "extra": {
            "message": "Detected risky pattern.",
            "severity": severity,
        },
    }
