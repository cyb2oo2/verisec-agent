from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class PartitionAuditError(RuntimeError):
    pass


def run_partition_audit(
    *,
    cases_path: Path,
    reference_paths: tuple[Path, ...],
    output_dir: Path | None = None,
) -> dict[str, Any]:
    if not reference_paths:
        raise PartitionAuditError("Partition audit requires at least one reference manifest.")

    cases = _load_cases(cases_path)
    references = tuple(
        (reference_path, _load_cases(reference_path))
        for reference_path in reference_paths
    )
    overlaps = tuple(
        overlap
        for case in cases
        for reference_path, reference_cases in references
        for reference_case in reference_cases
        if (
            overlap := _case_overlap(
                case,
                reference_case,
                reference_path=reference_path,
            )
        )
    )
    overlapping_case_ids = {
        str(overlap["case_id"])
        for overlap in overlaps
    }
    result = {
        "passed": not overlaps,
        "cases_path": str(cases_path),
        "reference_paths": tuple(str(path) for path in reference_paths),
        "summary": {
            "case_count": len(cases),
            "reference_manifest_count": len(references),
            "reference_case_count": sum(
                len(reference_cases)
                for _, reference_cases in references
            ),
            "overlapping_case_count": len(overlapping_case_ids),
            "overlap_count": len(overlaps),
        },
        "overlaps": overlaps,
    }
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "partition_audit.json").write_text(
            json.dumps(result, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        (output_dir / "partition_audit.md").write_text(
            render_partition_audit_markdown(result),
            encoding="utf-8",
        )
    return result


def render_partition_audit_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    status = "passed" if result["passed"] else "failed"
    lines = [
        f"# VeriSec Partition Audit: {status}",
        "",
        f"- Cases: `{result['cases_path']}`",
        f"- Reference manifests: {summary['reference_manifest_count']}",
        f"- Reference cases: {summary['reference_case_count']}",
        f"- Overlapping cases: {summary['overlapping_case_count']}",
        f"- Overlap pairs: {summary['overlap_count']}",
    ]
    if result["overlaps"]:
        lines.extend(
            [
                "",
                "## Overlaps",
                "",
                "| Case | Reference Case | Reference Manifest | Reasons |",
                "| --- | --- | --- | --- |",
            ]
        )
        for overlap in result["overlaps"]:
            lines.append(
                "| "
                f"{overlap['case_id']} | "
                f"{overlap['reference_case_id']} | "
                f"`{overlap['reference_path']}` | "
                f"{', '.join(overlap['reasons'])} |"
            )
    return "\n".join(lines).rstrip() + "\n"


def _load_cases(path: Path) -> tuple[dict[str, Any], ...]:
    if not path.exists():
        raise PartitionAuditError(f"Case manifest does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PartitionAuditError(f"Invalid case manifest JSON: {path}") from exc
    raw_cases = payload.get("cases", payload) if isinstance(payload, dict) else payload
    if not isinstance(raw_cases, list):
        raise PartitionAuditError(
            f"Case manifest must be a list or object with cases: {path}"
        )
    cases: list[dict[str, Any]] = []
    for index, raw_case in enumerate(raw_cases, start=1):
        if not isinstance(raw_case, dict):
            raise PartitionAuditError(f"Case {index} must be an object: {path}")
        cases.append(raw_case)
    return tuple(cases)


def _case_overlap(
    case: dict[str, Any],
    reference_case: dict[str, Any],
    *,
    reference_path: Path,
) -> dict[str, Any] | None:
    reasons = sorted(_fingerprints(case) & _fingerprints(reference_case))
    if not reasons:
        return None
    return {
        "case_id": _case_id(case),
        "reference_case_id": _case_id(reference_case),
        "reference_path": str(reference_path),
        "reasons": tuple(reasons),
    }


def _fingerprints(case: dict[str, Any]) -> set[str]:
    metadata = case.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    fingerprints: set[str] = set()

    case_id = _case_id(case)
    if case_id:
        fingerprints.add(f"case-id:{case_id.lower()}")

    for key in ("cve", "ghsa", "advisory"):
        value = case.get(key) or metadata.get(key)
        if value:
            fingerprints.add(f"{key}:{str(value).strip().lower()}")

    repo = case.get("repo_url") or case.get("repo")
    base_ref = case.get("base_ref")
    head_ref = case.get("head_ref")
    if repo and base_ref and head_ref:
        fingerprints.add(
            "source-pair:"
            f"{_normalize_value(repo)}@{_normalize_value(base_ref)}"
            f"..{_normalize_value(head_ref)}"
        )

    diff_url = case.get("diff_url") or case.get("patch_url")
    if diff_url:
        fingerprints.add(f"diff-url:{_normalize_value(diff_url)}")

    upstream_commit = case.get("upstream_commit") or metadata.get("upstream_commit")
    if upstream_commit:
        fingerprints.add(
            f"upstream-commit:{_normalize_value(upstream_commit)}"
        )
    return fingerprints


def _case_id(case: dict[str, Any]) -> str:
    return str(case.get("id") or case.get("case_id") or "")


def _normalize_value(value: Any) -> str:
    return str(value).strip().rstrip("/").lower()
