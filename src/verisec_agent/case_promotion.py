from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from verisec_agent.case_audit import CaseAuditError, run_case_audit


class CasePromotionError(RuntimeError):
    pass


SECURITY_METADATA_KEYS = ("cve", "ghsa", "advisory", "advisory_url", "upstream_pr")


def plan_case_promotions(
    *,
    candidates_path: Path,
    output_dir: Path | None = None,
    evaluation_path: Path | None = None,
    existing_promoted_path: Path | None = None,
    promoted_manifest_path: Path | None = None,
    require_evaluation: bool = True,
    min_validation_coverage: float = 1.0,
    min_tool_evidence_rate: float = 1.0,
    min_primary_precision: float = 0.5,
    min_primary_finding_recall: float = 1.0,
    min_expected_finding_recall: float = 1.0,
) -> dict[str, Any]:
    raw_cases = _load_cases(candidates_path)
    audit = _run_audit(candidates_path)
    audit_cases = {case["case_id"]: case for case in audit["cases"]}
    evaluation = _load_optional_json(evaluation_path)
    evaluation_cases = _cases_by_id(evaluation.get("cases", ())) if evaluation else {}
    existing_promoted_ids = _case_ids(_load_cases(existing_promoted_path))

    decisions = [
        _case_decision(
            raw_case=raw_case,
            audit_case=audit_cases.get(_raw_case_id(raw_case)),
            evaluation_case=evaluation_cases.get(_raw_case_id(raw_case)),
            already_promoted=_raw_case_id(raw_case) in existing_promoted_ids,
            require_evaluation=require_evaluation,
            min_validation_coverage=min_validation_coverage,
            min_tool_evidence_rate=min_tool_evidence_rate,
            min_primary_precision=min_primary_precision,
            min_primary_finding_recall=min_primary_finding_recall,
            min_expected_finding_recall=min_expected_finding_recall,
        )
        for raw_case in raw_cases
    ]
    promoted_cases = [
        _promoted_case(raw_case)
        for raw_case, decision in zip(raw_cases, decisions, strict=True)
        if decision["status"] == "eligible"
    ]
    result = {
        "candidates_path": str(candidates_path),
        "evaluation_path": str(evaluation_path) if evaluation_path else None,
        "existing_promoted_path": (
            str(existing_promoted_path) if existing_promoted_path else None
        ),
        "require_evaluation": require_evaluation,
        "thresholds": {
            "min_validation_coverage": min_validation_coverage,
            "min_tool_evidence_rate": min_tool_evidence_rate,
            "min_primary_precision": min_primary_precision,
            "min_primary_finding_recall": min_primary_finding_recall,
            "min_expected_finding_recall": min_expected_finding_recall,
        },
        "summary": _summary(decisions, evaluation_cases=evaluation_cases),
        "audit_summary": audit["summary"],
        "cases": decisions,
        "promoted_cases": promoted_cases,
    }
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "case_promotion.json").write_text(
            json.dumps(result, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        (output_dir / "case_promotion.md").write_text(
            render_case_promotion_markdown(result),
            encoding="utf-8",
        )
    if promoted_manifest_path is not None:
        promoted_manifest_path.parent.mkdir(parents=True, exist_ok=True)
        promoted_manifest_path.write_text(
            json.dumps({"cases": promoted_cases}, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    return result


def render_case_promotion_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# VeriSec Case Promotion Plan",
        "",
        "## Summary",
        "",
        f"- Candidates: {summary['candidate_count']}",
        f"- Eligible: {summary['eligible_count']}",
        f"- Already promoted: {summary['already_promoted_count']}",
        f"- Blocked: {summary['blocked_count']}",
        f"- Evaluation cases: {summary['evaluation_case_count']}",
        f"- Require evaluation: {'yes' if result['require_evaluation'] else 'no'}",
        "",
        "## Cases",
        "",
        "| Case | Status | Evidence | Blockers |",
        "| --- | --- | --- | --- |",
    ]
    for case in result["cases"]:
        blockers = "<br>".join(case["blockers"]) if case["blockers"] else "-"
        lines.append(
            "| "
            f"{case['case_id']} | "
            f"{case['status']} | "
            f"{case['evidence_summary']} | "
            f"{blockers} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def _case_decision(
    *,
    raw_case: dict[str, Any],
    audit_case: dict[str, Any] | None,
    evaluation_case: dict[str, Any] | None,
    already_promoted: bool,
    require_evaluation: bool,
    min_validation_coverage: float,
    min_tool_evidence_rate: float,
    min_primary_precision: float,
    min_primary_finding_recall: float,
    min_expected_finding_recall: float,
) -> dict[str, Any]:
    case_id = str(raw_case.get("id") or raw_case.get("case_id") or "")
    blockers: list[str] = []
    warnings: list[str] = []
    if already_promoted:
        return {
            "case_id": case_id,
            "status": "already-promoted",
            "blockers": (),
            "warnings": ("case already exists in promoted manifest",),
            "evidence": _evidence_metrics(evaluation_case),
            "evidence_summary": _evidence_summary(evaluation_case),
        }

    if audit_case is None:
        blockers.append("case is missing from audit result")
    else:
        blockers.extend(f"audit error: {error}" for error in audit_case.get("errors", ()))
        audit_warnings = tuple(str(item) for item in audit_case.get("warnings", ()))
        if audit_warnings:
            blockers.extend(f"audit warning: {warning}" for warning in audit_warnings)

    if not raw_case.get("config"):
        blockers.append("verification config is required for measured promotion")
    if not _has_primary_expected_finding(raw_case):
        blockers.append("at least one primary expected finding is required")
    if not _has_security_metadata(raw_case):
        blockers.append("CVE/GHSA/advisory/upstream PR metadata is required")

    if evaluation_case is None:
        if require_evaluation:
            blockers.append("evaluation evidence is required")
    else:
        blockers.extend(
            _evaluation_blockers(
                evaluation_case=evaluation_case,
                min_validation_coverage=min_validation_coverage,
                min_tool_evidence_rate=min_tool_evidence_rate,
                min_primary_precision=min_primary_precision,
                min_primary_finding_recall=min_primary_finding_recall,
                min_expected_finding_recall=min_expected_finding_recall,
            )
        )

    status = "eligible" if not blockers else "blocked"
    return {
        "case_id": case_id,
        "status": status,
        "blockers": tuple(blockers),
        "warnings": tuple(warnings),
        "evidence": _evidence_metrics(evaluation_case),
        "evidence_summary": _evidence_summary(evaluation_case),
    }


def _evaluation_blockers(
    *,
    evaluation_case: dict[str, Any],
    min_validation_coverage: float,
    min_tool_evidence_rate: float,
    min_primary_precision: float,
    min_primary_finding_recall: float,
    min_expected_finding_recall: float,
) -> tuple[str, ...]:
    blockers: list[str] = []
    if evaluation_case.get("status") != "completed":
        blockers.append(f"evaluation status is {evaluation_case.get('status')}")
    if int(evaluation_case.get("finding_count", 0)) <= 0:
        blockers.append("evaluation produced no findings")
    if int(evaluation_case.get("verification_count", 0)) <= 0:
        blockers.append("evaluation has no verification command")
    if int(evaluation_case.get("verification_passed", 0)) < int(
        evaluation_case.get("verification_count", 0)
    ):
        blockers.append("not all verification commands passed")
    if int(evaluation_case.get("required_failure_count", 0)) > 0:
        blockers.append("required verification failed")
    if int(evaluation_case.get("policy_blocked_count", 0)) > 0:
        blockers.append("policy blocked at least one verification command")
    if int(evaluation_case.get("validation_gap_findings", 0)) > 0:
        blockers.append("validation gaps remain")
    if evaluation_case.get("unexpected_taxonomy"):
        blockers.append("unexpected findings remain")

    metrics = _evidence_metrics(evaluation_case)
    blockers.extend(
        _min_rate_blockers(
            metrics,
            {
                "validation_coverage": min_validation_coverage,
                "tool_evidence_rate": min_tool_evidence_rate,
                "primary_precision": min_primary_precision,
                "primary_finding_recall": min_primary_finding_recall,
                "expected_finding_recall": min_expected_finding_recall,
            },
        )
    )
    return tuple(blockers)


def _min_rate_blockers(
    metrics: dict[str, Any],
    thresholds: dict[str, float],
) -> tuple[str, ...]:
    blockers: list[str] = []
    for key, threshold in thresholds.items():
        value = metrics.get(key)
        if value is None or float(value) < threshold:
            blockers.append(f"{key} {value if value is not None else 'n/a'} < {threshold}")
    return tuple(blockers)


def _evidence_metrics(evaluation_case: dict[str, Any] | None) -> dict[str, Any]:
    if evaluation_case is None:
        return {}
    finding_count = int(evaluation_case.get("finding_count", 0))
    validation_steps = int(evaluation_case.get("validation_step_count", 0))
    validation_covered = int(evaluation_case.get("validation_covered", 0))
    expected_findings = [
        item
        for item in evaluation_case.get("expected_findings", ())
        if item.get("role", "primary") != "negative-control"
    ]
    expected_hits = evaluation_case.get("expected_finding_hits", ())
    primary_expected = [
        item for item in expected_findings if item.get("role", "primary") == "primary"
    ]
    primary_hits = [
        item for item in expected_hits if item.get("role", "primary") == "primary"
    ]
    role_counts = evaluation_case.get("finding_role_counts", {})
    primary_findings = int(role_counts.get("primary", 0)) if isinstance(role_counts, dict) else 0
    return {
        "validation_coverage": _rate(validation_covered, validation_steps),
        "tool_evidence_rate": _rate(
            int(evaluation_case.get("tool_supported_findings", 0)),
            finding_count,
        ),
        "primary_precision": _rate(primary_findings, finding_count),
        "primary_finding_recall": _rate(len(primary_hits), len(primary_expected)),
        "expected_finding_recall": _rate(len(expected_hits), len(expected_findings)),
        "avg_confidence": float(evaluation_case.get("avg_confidence", 0.0)),
    }


def _evidence_summary(evaluation_case: dict[str, Any] | None) -> str:
    if evaluation_case is None:
        return "missing"
    metrics = _evidence_metrics(evaluation_case)
    return (
        f"validation={_format_rate(metrics.get('validation_coverage'))}, "
        f"tool={_format_rate(metrics.get('tool_evidence_rate'))}, "
        f"primary={_format_rate(metrics.get('primary_finding_recall'))}, "
        f"expected={_format_rate(metrics.get('expected_finding_recall'))}"
    )


def _promoted_case(raw_case: dict[str, Any]) -> dict[str, Any]:
    promoted = dict(raw_case)
    tags = [str(tag) for tag in promoted.get("tags", ())]
    promoted["tags"] = tuple(["promoted", *[tag for tag in tags if tag != "candidate"]])
    return promoted


def _summary(
    decisions: list[dict[str, Any]],
    *,
    evaluation_cases: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        "candidate_count": len(decisions),
        "eligible_count": _status_count(decisions, "eligible"),
        "already_promoted_count": _status_count(decisions, "already-promoted"),
        "blocked_count": _status_count(decisions, "blocked"),
        "evaluation_case_count": len(evaluation_cases),
    }


def _run_audit(candidates_path: Path) -> dict[str, Any]:
    try:
        return run_case_audit(cases_path=candidates_path, require_verification=True)
    except CaseAuditError as exc:
        raise CasePromotionError(str(exc)) from exc


def _load_cases(path: Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    data = _load_json(path)
    raw_cases = data.get("cases", data) if isinstance(data, dict) else data
    if not isinstance(raw_cases, list):
        raise CasePromotionError(f"Case manifest must contain a cases list: {path}")
    return [case for case in raw_cases if isinstance(case, dict)]


def _load_optional_json(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    data = _load_json(path)
    if not isinstance(data, dict):
        raise CasePromotionError(f"Expected JSON object: {path}")
    return data


def _load_json(path: Path) -> Any:
    if not path.exists():
        raise CasePromotionError(f"Path does not exist: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CasePromotionError(f"Invalid JSON: {path}") from exc


def _cases_by_id(raw_cases: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(raw_cases, list):
        return {}
    return {
        str(case.get("case_id") or case.get("id")): case
        for case in raw_cases
        if isinstance(case, dict)
    }


def _case_ids(raw_cases: list[dict[str, Any]]) -> set[str]:
    return {str(case.get("id") or case.get("case_id")) for case in raw_cases}


def _raw_case_id(raw_case: dict[str, Any]) -> str:
    return str(raw_case.get("id") or raw_case.get("case_id") or "")


def _has_primary_expected_finding(raw_case: dict[str, Any]) -> bool:
    findings = raw_case.get("expected_findings", ())
    return any(
        isinstance(finding, dict) and finding.get("role", "primary") == "primary"
        for finding in findings
    )


def _has_security_metadata(raw_case: dict[str, Any]) -> bool:
    metadata = raw_case.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    return any(raw_case.get(key) or metadata.get(key) for key in SECURITY_METADATA_KEYS)


def _status_count(decisions: list[dict[str, Any]], status: str) -> int:
    return sum(1 for decision in decisions if decision["status"] == status)


def _rate(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 4)


def _format_rate(value: Any) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.2f}"
