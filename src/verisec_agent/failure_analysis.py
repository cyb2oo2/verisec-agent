from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


class FailureAnalysisError(RuntimeError):
    pass


def run_failure_analysis(
    *,
    evaluation_path: Path,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    if not evaluation_path.exists():
        raise FailureAnalysisError(
            f"Evaluation artifact does not exist: {evaluation_path}"
        )
    try:
        evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FailureAnalysisError(
            f"Invalid evaluation JSON: {evaluation_path}"
        ) from exc

    raw_cases = evaluation.get("cases", ())
    if not isinstance(raw_cases, list):
        raise FailureAnalysisError("Evaluation artifact must contain a cases list.")
    case_results = tuple(_analyze_case(case) for case in raw_cases)
    taxonomy = Counter(
        failure["category"]
        for case in case_results
        for failure in case["failures"]
    )
    result = {
        "evaluation_path": str(evaluation_path),
        "summary": {
            "case_count": len(case_results),
            "case_failure_count": sum(
                1 for case in case_results if case["failures"]
            ),
            "failure_count": sum(
                len(case["failures"]) for case in case_results
            ),
            "verified_patch_failure_count": sum(
                1
                for case in case_results
                for failure in case["failures"]
                if failure["verification_passed"]
            ),
            "taxonomy": dict(sorted(taxonomy.items())),
        },
        "cases": case_results,
    }
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "failure_analysis.json").write_text(
            json.dumps(result, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        (output_dir / "failure_analysis.md").write_text(
            render_failure_analysis_markdown(result),
            encoding="utf-8",
        )
    return result


def render_failure_analysis_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# VeriSec Failure Analysis",
        "",
        f"- Evaluation: `{result['evaluation_path']}`",
        f"- Cases: {summary['case_count']}",
        f"- Cases with failures: {summary['case_failure_count']}",
        f"- Classified failures: {summary['failure_count']}",
        f"- Verified-patch failures: {summary['verified_patch_failure_count']}",
        "",
        "## Taxonomy",
        "",
        "| Category | Count |",
        "| --- | ---: |",
    ]
    for category, count in summary["taxonomy"].items():
        lines.append(f"| {category} | {count} |")
    lines.extend(
        [
            "",
            "## Cases",
            "",
            "| Case | Category | Expected | Actual | Verification |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for case in result["cases"]:
        for failure in case["failures"]:
            expected = failure.get("expected_rule_id") or "-"
            actual = failure.get("actual_rule_id") or "-"
            verification = (
                f"{failure['verification_passed_count']}/"
                f"{failure['verification_count']} passed"
            )
            lines.append(
                "| "
                f"{case['case_id']} | "
                f"{failure['category']} | "
                f"{expected} | "
                f"{actual} | "
                f"{verification} |"
            )
    return "\n".join(lines).rstrip() + "\n"


def _analyze_case(case: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(case, dict):
        raise FailureAnalysisError("Evaluation case entries must be objects.")
    case_id = str(case.get("case_id") or "")
    verification_count = int(case.get("verification_count") or 0)
    verification_passed_count = int(case.get("verification_passed") or 0)
    verification_passed = (
        verification_count > 0
        and verification_passed_count == verification_count
    )
    misses = case.get("expected_finding_misses", ())
    labels = case.get("finding_labels", ())
    if not isinstance(misses, list) or not isinstance(labels, list):
        raise FailureAnalysisError(
            f"Evaluation case has invalid finding labels: {case_id}"
        )
    unexpected = tuple(
        label
        for label in labels
        if isinstance(label, dict) and label.get("role") == "unexpected"
    )
    failures: list[dict[str, Any]] = []
    related_finding_ids: set[str] = set()
    for miss in misses:
        if not isinstance(miss, dict):
            continue
        failure, related_id = _classify_miss(
            miss,
            unexpected,
            verification_count=verification_count,
            verification_passed_count=verification_passed_count,
            verification_passed=verification_passed,
        )
        failures.append(failure)
        if related_id:
            related_finding_ids.add(related_id)
    for finding in unexpected:
        finding_id = str(finding.get("finding_id") or "")
        if finding_id in related_finding_ids:
            continue
        failures.append(
            _failure(
                category="unexpected-finding",
                expected=None,
                actual=finding,
                verification_count=verification_count,
                verification_passed_count=verification_passed_count,
                verification_passed=verification_passed,
            )
        )
    if case.get("status") == "error":
        failures.append(
            {
                "category": "execution-error",
                "expected_rule_id": None,
                "expected_file_path": None,
                "actual_rule_id": None,
                "actual_file_path": None,
                "actual_finding_id": None,
                "verification_count": verification_count,
                "verification_passed_count": verification_passed_count,
                "verification_passed": verification_passed,
                "error": str(case.get("error") or "unknown evaluation error"),
            }
        )
    return {
        "case_id": case_id,
        "status": case.get("status"),
        "metadata": case.get("metadata", {}),
        "failures": tuple(failures),
    }


def _classify_miss(
    miss: dict[str, Any],
    unexpected: tuple[dict[str, Any], ...],
    *,
    verification_count: int,
    verification_passed_count: int,
    verification_passed: bool,
) -> tuple[dict[str, Any], str | None]:
    expected_rule = str(miss.get("rule_id") or "")
    expected_file = str(miss.get("file_path") or "")
    same_file = next(
        (
            finding
            for finding in unexpected
            if expected_file
            and str(finding.get("file_path") or "") == expected_file
        ),
        None,
    )
    same_rule = next(
        (
            finding
            for finding in unexpected
            if expected_rule
            and str(finding.get("rule_id") or "") == expected_rule
        ),
        None,
    )
    if same_file and str(same_file.get("rule_id") or "") != expected_rule:
        category = "semantic-rule-confusion"
        actual = same_file
    elif same_rule:
        category = "rule-location-mismatch"
        actual = same_rule
    elif expected_file:
        category = "undetected-labeled-location"
        actual = None
    else:
        category = "undetected-expected-finding"
        actual = None
    return (
        _failure(
            category=category,
            expected=miss,
            actual=actual,
            verification_count=verification_count,
            verification_passed_count=verification_passed_count,
            verification_passed=verification_passed,
        ),
        str(actual.get("finding_id") or "") if actual else None,
    )


def _failure(
    *,
    category: str,
    expected: dict[str, Any] | None,
    actual: dict[str, Any] | None,
    verification_count: int,
    verification_passed_count: int,
    verification_passed: bool,
) -> dict[str, Any]:
    return {
        "category": category,
        "expected_rule_id": expected.get("rule_id") if expected else None,
        "expected_file_path": expected.get("file_path") if expected else None,
        "actual_rule_id": actual.get("rule_id") if actual else None,
        "actual_file_path": actual.get("file_path") if actual else None,
        "actual_finding_id": actual.get("finding_id") if actual else None,
        "verification_count": verification_count,
        "verification_passed_count": verification_passed_count,
        "verification_passed": verification_passed,
    }
