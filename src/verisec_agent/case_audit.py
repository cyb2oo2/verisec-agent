from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from verisec_agent.config import load_config
from verisec_agent.evaluation import EvaluationError, load_evaluation_cases


class CaseAuditError(RuntimeError):
    pass


VALID_ROLES = {"primary", "supporting", "benign", "negative-control"}
SECURITY_METADATA_KEYS = ("cve", "ghsa", "advisory", "advisory_url", "upstream_pr")


def run_case_audit(
    *,
    cases_path: Path,
    output_dir: Path | None = None,
    require_verification: bool = False,
) -> dict[str, Any]:
    raw_cases = _load_raw_cases(cases_path)
    base_dir = cases_path.parent
    duplicate_ids = _duplicate_ids(raw_cases)
    case_results = [
        _audit_raw_case(
            raw_case=raw_case,
            index=index,
            base_dir=base_dir,
            duplicate_ids=duplicate_ids,
            require_verification=require_verification,
        )
        for index, raw_case in enumerate(raw_cases, start=1)
    ]

    loader_error: str | None = None
    try:
        load_evaluation_cases(cases_path)
    except EvaluationError as exc:
        loader_error = str(exc)

    summary = _summary(case_results, loader_error=loader_error)
    result = {
        "cases_path": str(cases_path),
        "summary": summary,
        "loader_error": loader_error,
        "cases": case_results,
    }
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "case_audit.json").write_text(
            json.dumps(result, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        (output_dir / "case_audit.md").write_text(
            render_case_audit_markdown(result),
            encoding="utf-8",
        )
    return result


def render_case_audit_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# VeriSec Case Audit",
        "",
        "## Summary",
        "",
        f"- Cases: {summary['case_count']}",
        f"- Ready: {summary['ready_count']}",
        f"- Blocked: {summary['blocked_count']}",
        f"- Errors: {summary['error_count']}",
        f"- Warnings: {summary['warning_count']}",
        f"- Positive cases: {summary['positive_case_count']}",
        f"- Negative-control cases: {summary['negative_control_case_count']}",
        f"- Security advisory cases: {summary['security_advisory_case_count']}",
        f"- Verification-ready cases: {summary['verification_ready_count']}",
    ]
    if result.get("loader_error"):
        lines.extend(["", f"- Loader error: `{result['loader_error']}`"])
    lines.extend(
        [
            "",
            "## Cases",
            "",
            "| Case | Status | Errors | Warnings | Source | Labels | Verification |",
            "| --- | --- | ---: | ---: | --- | --- | --- |",
        ]
    )
    for case in result["cases"]:
        lines.append(
            "| "
            f"{case['case_id']} | "
            f"{case['status']} | "
            f"{len(case['errors'])} | "
            f"{len(case['warnings'])} | "
            f"{case['source_kind']} | "
            f"{case['label_summary']} | "
            f"{case['verification_status']} |"
        )
    blocked = [case for case in result["cases"] if case["errors"] or case["warnings"]]
    if blocked:
        lines.extend(["", "## Findings", ""])
        for case in blocked:
            for error in case["errors"]:
                lines.append(f"- {case['case_id']}: error: {error}")
            for warning in case["warnings"]:
                lines.append(f"- {case['case_id']}: warning: {warning}")
    return "\n".join(lines).rstrip() + "\n"


def _load_raw_cases(cases_path: Path) -> list[dict[str, Any]]:
    if not cases_path.exists():
        raise CaseAuditError(f"Case manifest does not exist: {cases_path}")
    try:
        data = json.loads(cases_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CaseAuditError(f"Invalid case manifest JSON: {cases_path}") from exc
    raw_cases = data.get("cases", data) if isinstance(data, dict) else data
    if not isinstance(raw_cases, list):
        raise CaseAuditError("Case manifest must be a JSON list or object with cases.")
    return [case if isinstance(case, dict) else {"_invalid": case} for case in raw_cases]


def _audit_raw_case(
    *,
    raw_case: dict[str, Any],
    index: int,
    base_dir: Path,
    duplicate_ids: set[str],
    require_verification: bool,
) -> dict[str, Any]:
    case_id = str(raw_case.get("id") or raw_case.get("case_id") or f"case-{index}")
    errors: list[str] = []
    warnings: list[str] = []
    if "_invalid" in raw_case:
        errors.append("case entry must be a JSON object")

    if not raw_case.get("id") and not raw_case.get("case_id"):
        errors.append("case id is missing")
    if case_id in duplicate_ids:
        errors.append("case id is duplicated")

    source_kind, source_errors, source_warnings = _source_status(raw_case, base_dir=base_dir)
    errors.extend(source_errors)
    warnings.extend(source_warnings)

    label_summary, has_positive_label, has_negative_control, label_errors, label_warnings = (
        _label_status(raw_case)
    )
    errors.extend(label_errors)
    warnings.extend(label_warnings)

    metadata = _metadata(raw_case)
    if not metadata.get("project"):
        warnings.append("metadata.project is missing")
    if not metadata.get("language"):
        warnings.append("metadata.language is missing")
    if not metadata.get("vulnerability_class"):
        warnings.append("metadata.vulnerability_class is missing")
    is_security_advisory = any(metadata.get(key) for key in SECURITY_METADATA_KEYS)
    if has_positive_label and not is_security_advisory:
        warnings.append("positive case should include CVE/GHSA/advisory/upstream PR metadata")

    tags = tuple(str(tag) for tag in raw_case.get("tags", ()))
    if has_negative_control and "negative-control" not in tags:
        warnings.append("negative-control case should include the negative-control tag")
    if has_positive_label and not {"oss", "cve", "github-advisory"} & set(tags):
        warnings.append("positive case should include an OSS/advisory tag")

    verification_status, verification_warnings = _verification_status(
        raw_case,
        base_dir=base_dir,
        require_verification=require_verification and has_positive_label,
    )
    warnings.extend(verification_warnings)

    return {
        "case_id": case_id,
        "status": "ready" if not errors else "blocked",
        "errors": tuple(errors),
        "warnings": tuple(warnings),
        "source_kind": source_kind,
        "label_summary": label_summary,
        "verification_status": verification_status,
        "metadata": metadata,
        "tags": tags,
        "has_positive_label": has_positive_label,
        "has_negative_control": has_negative_control,
        "is_security_advisory": is_security_advisory,
    }


def _source_status(
    raw_case: dict[str, Any],
    *,
    base_dir: Path,
) -> tuple[str, list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    has_diff = bool(raw_case.get("diff") or raw_case.get("diff_url") or raw_case.get("patch_url"))
    has_git_pair = bool(
        (raw_case.get("repo") or raw_case.get("repo_url"))
        and raw_case.get("base_ref")
        and raw_case.get("head_ref")
    )
    has_diff_on_base = bool(
        (raw_case.get("repo") or raw_case.get("repo_url"))
        and raw_case.get("base_ref")
        and (raw_case.get("diff_url") or raw_case.get("patch_url"))
    )
    if not has_diff and not has_git_pair:
        errors.append("case must provide diff/diff_url or repo/repo_url with base_ref/head_ref")
    if raw_case.get("diff"):
        diff_path = _resolve_path(base_dir, raw_case["diff"])
        if not diff_path.exists():
            errors.append(f"diff path does not exist: {diff_path}")
    if raw_case.get("repo"):
        repo_path = _resolve_path(base_dir, raw_case["repo"])
        if not repo_path.exists():
            errors.append(f"repo path does not exist: {repo_path}")
    if has_git_pair:
        return "git-pair", errors, warnings
    if has_diff_on_base:
        return "diff-url-on-base", errors, warnings
    if raw_case.get("diff_url") or raw_case.get("patch_url"):
        warnings.append("remote diff without base checkout limits source-context verification")
        return "remote-diff", errors, warnings
    if raw_case.get("diff"):
        return "local-diff", errors, warnings
    return "missing", errors, warnings


def _label_status(
    raw_case: dict[str, Any],
) -> tuple[str, bool, bool, list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    raw_findings = raw_case.get("expected_findings", ())
    if not isinstance(raw_findings, list):
        errors.append("expected_findings must be a list")
        raw_findings = []
    if not raw_findings:
        warnings.append("expected_findings are missing; reviewer-noise metrics will be weak")

    role_counts: dict[str, int] = {}
    has_positive_label = False
    has_negative_control = False
    for index, finding in enumerate(raw_findings, start=1):
        if isinstance(finding, str):
            role = "primary"
            has_positive_label = True
            role_counts[role] = role_counts.get(role, 0) + 1
            continue
        if not isinstance(finding, dict):
            errors.append(f"expected_findings[{index}] must be a string or object")
            continue
        role = str(finding.get("role") or "primary")
        if role not in VALID_ROLES:
            errors.append(f"expected_findings[{index}] has unknown role: {role}")
            continue
        role_counts[role] = role_counts.get(role, 0) + 1
        if not finding.get("rule_id"):
            errors.append(f"expected_findings[{index}] is missing rule_id")
        if role in {"primary", "supporting"}:
            has_positive_label = True
            if not finding.get("file_path"):
                warnings.append(f"expected_findings[{index}] should include file_path")
            if not finding.get("severity"):
                warnings.append(f"expected_findings[{index}] should include severity")
        if role == "negative-control":
            has_negative_control = True
    if has_positive_label and role_counts.get("primary", 0) == 0:
        warnings.append("positive case has no primary expected finding")
    label_summary = ", ".join(
        f"{role}:{count}" for role, count in sorted(role_counts.items())
    ) or "unlabeled"
    return label_summary, has_positive_label, has_negative_control, errors, warnings


def _verification_status(
    raw_case: dict[str, Any],
    *,
    base_dir: Path,
    require_verification: bool,
) -> tuple[str, list[str]]:
    warnings: list[str] = []
    config_value = raw_case.get("config")
    if not config_value:
        if require_verification:
            warnings.append("positive case should define a verification config")
        return "missing", warnings
    config_path = _resolve_path(base_dir, config_value)
    if not config_path.exists():
        warnings.append(f"verification config does not exist: {config_path}")
        return "missing", warnings
    config = load_config(config_path)
    command_count = len(config.verification_commands)
    if command_count == 0:
        warnings.append("verification config has no commands")
        return "empty"
    return f"{command_count} command(s)", warnings


def _summary(case_results: list[dict[str, Any]], *, loader_error: str | None) -> dict[str, Any]:
    return {
        "case_count": len(case_results),
        "ready_count": sum(1 for case in case_results if case["status"] == "ready"),
        "blocked_count": sum(1 for case in case_results if case["status"] == "blocked"),
        "error_count": sum(len(case["errors"]) for case in case_results)
        + (1 if loader_error else 0),
        "warning_count": sum(len(case["warnings"]) for case in case_results),
        "positive_case_count": sum(1 for case in case_results if case["has_positive_label"]),
        "negative_control_case_count": sum(
            1 for case in case_results if case["has_negative_control"]
        ),
        "security_advisory_case_count": sum(
            1 for case in case_results if case["is_security_advisory"]
        ),
        "verification_ready_count": sum(
            1 for case in case_results if "command" in case["verification_status"]
        ),
        "loader_passed": loader_error is None,
    }


def _duplicate_ids(raw_cases: list[dict[str, Any]]) -> set[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for index, raw_case in enumerate(raw_cases, start=1):
        case_id = str(raw_case.get("id") or raw_case.get("case_id") or f"case-{index}")
        if case_id in seen:
            duplicates.add(case_id)
        seen.add(case_id)
    return duplicates


def _metadata(raw_case: dict[str, Any]) -> dict[str, Any]:
    raw_metadata = raw_case.get("metadata", {})
    metadata = dict(raw_metadata) if isinstance(raw_metadata, dict) else {}
    for key in (
        "project",
        "package",
        "language",
        "ecosystem",
        "cve",
        "cwe",
        "ghsa",
        "advisory",
        "upstream_pr",
        "upstream_commit",
        "advisory_url",
        "vulnerability_class",
    ):
        if key in raw_case:
            metadata[key] = raw_case[key]
    return metadata


def _resolve_path(base_dir: Path, value: Any) -> Path:
    path = Path(str(value))
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()
