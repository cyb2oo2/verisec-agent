from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from verisec_agent.diff_parser import evidence_windows, parse_unified_diff
from verisec_agent.evaluation import (
    _expected_finding_results,
    _format_optional_rate,
    _label_findings,
    _safe_case_id,
    _summarize_results,
    load_evaluation_cases,
)
from verisec_agent.inputs import fetch_url_diff
from verisec_agent.models import ToolFinding
from verisec_agent.tool_output import parse_sarif_json, parse_semgrep_json


class ScannerBaselineError(RuntimeError):
    pass


DEFAULT_SEVERITY_MAP = {
    "warning": "medium",
    "error": "high",
    "note": "low",
}

DEFAULT_RULE_MAP = {
    "python.lang.security.audit.subprocess-shell-true": "py-shell-true",
    "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true": "py-shell-true",
    "python.lang.security.deserialization.pyyaml-load": "py-unsafe-yaml",
    "python.lang.security.audit.insecure-hash-algorithms": "weak-hash",
    "python.lang.security.audit.eval-exec": "py-eval-exec",
    "python.lang.security.audit.redos": "py-regex-redos-hardening",
    "py/command-line-injection": "py-shell-true",
}
DIFF_SCOPE_MAX_LINES = 12
OUT_OF_SCOPE_SAMPLE_LIMIT = 25


def run_scanner_baseline(
    *,
    cases_path: Path,
    results_path: Path,
    output_dir: Path,
    adapter: str | None = None,
    label: str | None = None,
    fail_fast: bool = False,
) -> dict[str, Any]:
    if not results_path.exists():
        raise ScannerBaselineError(f"Scanner baseline results do not exist: {results_path}")

    try:
        cases = load_evaluation_cases(cases_path)
    except Exception as exc:
        raise ScannerBaselineError(f"Failed to load evaluation cases: {exc}") from exc
    manifest = _load_manifest(results_path)
    adapter_name = str(adapter or manifest.get("adapter") or "semgrep")
    tool_name = str(manifest.get("tool_name") or adapter_name)
    global_rule_map = {
        **DEFAULT_RULE_MAP,
        **_string_map(manifest.get("rule_map", {})),
    }
    global_severity_map = {
        **DEFAULT_SEVERITY_MAP,
        **_string_map(manifest.get("severity_map", {})),
    }
    baseline_cases = _manifest_cases(manifest)

    output_dir.mkdir(parents=True, exist_ok=True)
    case_results: list[dict[str, Any]] = []
    for case in cases:
        try:
            raw_case = baseline_cases.get(case.case_id)
            if raw_case is None:
                raise ScannerBaselineError(
                    f"Scanner baseline is missing result artifact for case: {case.case_id}"
                )
            raw_status = str(raw_case.get("status", "completed"))
            if raw_status == "skipped":
                case_results.append(_skipped_case(case, raw_case))
                continue
            if raw_status == "error":
                case_results.append(_error_case(case, raw_case))
                continue
            case_results.append(
                _run_case(
                    case=case,
                    raw_case=raw_case,
                    adapter=adapter_name,
                    tool_name=tool_name,
                    results_base_dir=results_path.parent,
                    global_rule_map=global_rule_map,
                    global_severity_map=global_severity_map,
                )
            )
        except Exception as exc:
            if fail_fast:
                if isinstance(exc, ScannerBaselineError):
                    raise
                raise ScannerBaselineError(str(exc)) from exc
            case_results.append(
                {
                    "case_id": case.case_id,
                    "status": "error",
                    "error": str(exc),
                    "expected_rules": case.expected_rules,
                    "expected_findings": tuple(
                        finding.__dict__ for finding in case.expected_findings
                    ),
                    "tags": case.tags,
                    "metadata": case.metadata or {},
                }
            )

    summary = _summarize_results(case_results)
    summary["skipped_count"] = sum(1 for case in case_results if case["status"] == "skipped")
    summary["error_count"] = sum(1 for case in case_results if case["status"] == "error")
    summary["raw_tool_finding_count"] = sum(
        int(case.get("raw_tool_finding_count", case.get("tool_finding_count", 0)))
        for case in case_results
        if case["status"] == "completed"
    )
    summary["out_of_scope_finding_count"] = sum(
        int(case.get("out_of_scope_finding_count", 0))
        for case in case_results
        if case["status"] == "completed"
    )
    result = {
        "label": label or manifest.get("label") or adapter_name,
        "adapter": adapter_name,
        "tool_name": tool_name,
        "cases_path": str(cases_path),
        "results_path": str(results_path),
        "output_dir": str(output_dir),
        "scanner_execution": {
            "command_argv_template": manifest.get("command_argv_template", ()),
            "executable": manifest.get("executable"),
            "executable_path": manifest.get("executable_path"),
        },
        "summary": summary,
        "cases": case_results,
    }
    (output_dir / "baseline.json").write_text(
        json.dumps(result, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (output_dir / "baseline.md").write_text(
        render_scanner_baseline_markdown(result),
        encoding="utf-8",
    )
    return result


def render_scanner_baseline_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        f"# Scanner Baseline: {result['label']}",
        "",
        "## Summary",
        "",
        f"- Adapter: `{result['adapter']}`",
        f"- Cases: {summary['case_count']}",
        f"- Completed: {summary['completed_count']}",
        f"- Skipped: {summary.get('skipped_count', 0)}",
        f"- Errors: {summary['error_count']}",
        f"- Findings: {summary['finding_count']}",
        f"- Raw tool findings: {summary.get('raw_tool_finding_count', summary['finding_count'])}",
        f"- Out-of-scope findings: {summary.get('out_of_scope_finding_count', 0)}",
        (
            "- Expected finding recall: "
            f"{_format_optional_rate(summary.get('expected_finding_recall'))}"
        ),
        f"- Primary precision: {summary['primary_precision']:.2f}",
        f"- Primary finding recall: {_format_optional_rate(summary.get('primary_finding_recall'))}",
        f"- Tool evidence rate: {summary['tool_evidence_rate']:.2f}",
        f"- Unexpected finding rate: {summary['unexpected_finding_rate']:.2f}",
        f"- Negative-control violations: {summary['negative_control_violation_count']}",
        "",
        "## Cases",
        "",
        "| Case | Status | Findings | Raw | Out of Scope | Expected Hits | Unexpected |",
        "| --- | --- | ---: | ---: | ---: | --- | ---: |",
    ]
    for case in result["cases"]:
        hits = ", ".join(
            expected.get("rule_id", "") for expected in case.get("expected_finding_hits", ())
        )
        labels = case.get("finding_labels", ())
        unexpected_count = sum(1 for label in labels if label.get("role") == "unexpected")
        lines.append(
            "| "
            f"{case['case_id']} | "
            f"{case['status']} | "
            f"{case.get('finding_count', 0)} | "
            f"{case.get('raw_tool_finding_count', case.get('tool_finding_count', 0))} | "
            f"{case.get('out_of_scope_finding_count', 0)} | "
            f"{hits or '-'} | "
            f"{unexpected_count} |"
        )
    if summary.get("finding_role_counts"):
        lines.extend(["", "## Finding Roles", "", "| Role | Findings |", "| --- | ---: |"])
        for role, count in sorted(summary["finding_role_counts"].items()):
            lines.append(f"| {role} | {count} |")
    if summary.get("unexpected_taxonomy"):
        lines.extend(
            [
                "",
                "## Unexpected Taxonomy",
                "",
                "| Category | Findings |",
                "| --- | ---: |",
            ]
        )
        for category, count in sorted(summary["unexpected_taxonomy"].items()):
            lines.append(f"| {category} | {count} |")
    return "\n".join(lines).rstrip() + "\n"


def _load_manifest(results_path: Path) -> dict[str, Any]:
    try:
        data = json.loads(results_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ScannerBaselineError(f"Invalid scanner baseline JSON: {results_path}") from exc
    if not isinstance(data, dict):
        raise ScannerBaselineError("Scanner baseline results must be a JSON object.")
    return data


def _manifest_cases(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw_cases = manifest.get("cases")
    if not isinstance(raw_cases, list):
        raise ScannerBaselineError("Scanner baseline results must contain a cases list.")

    cases: dict[str, dict[str, Any]] = {}
    for index, raw_case in enumerate(raw_cases, start=1):
        if not isinstance(raw_case, dict):
            raise ScannerBaselineError(f"Scanner baseline case {index} must be an object.")
        case_id = str(raw_case.get("id") or raw_case.get("case_id") or "").strip()
        if not case_id:
            raise ScannerBaselineError(f"Scanner baseline case {index} is missing id.")
        cases[case_id] = raw_case
    return cases


def _run_case(
    *,
    case: Any,
    raw_case: dict[str, Any],
    adapter: str,
    tool_name: str,
    results_base_dir: Path,
    global_rule_map: dict[str, str],
    global_severity_map: dict[str, str],
) -> dict[str, Any]:
    case_adapter = str(raw_case.get("adapter") or adapter)
    case_tool_name = str(raw_case.get("tool_name") or tool_name)
    rule_map = {**global_rule_map, **_string_map(raw_case.get("rule_map", {}))}
    severity_map = {**global_severity_map, **_string_map(raw_case.get("severity_map", {}))}
    tool_findings, artifact_present = _parse_case_findings(
        raw_case=raw_case,
        adapter=case_adapter,
        tool_name=case_tool_name,
        results_base_dir=results_base_dir,
    )
    findings = _normalize_tool_findings(
        case_id=case.case_id,
        tool_findings=tool_findings,
        rule_map=rule_map,
        severity_map=severity_map,
    )
    diff_scope = _case_diff_scope(
        case=case,
        raw_case=raw_case,
        results_base_dir=results_base_dir,
    )
    scoped_findings, out_of_scope_findings = _split_diff_scoped_findings(
        findings=findings,
        diff_scope=diff_scope,
    )
    found_rules = tuple(finding["rule_id"] for finding in scoped_findings)
    expected_rule_hits = tuple(rule for rule in case.expected_rules if rule in found_rules)
    expected_rule_misses = tuple(rule for rule in case.expected_rules if rule not in found_rules)
    expected_finding_hits, expected_finding_misses = _expected_finding_results(
        case.expected_findings,
        scoped_findings,
    )
    finding_labels = _label_findings(case.expected_findings, scoped_findings)

    return {
        "case_id": case.case_id,
        "status": "completed",
        "adapter": case_adapter,
        "tool_name": case_tool_name,
        "metadata": case.metadata or {},
        "found_rules": tuple(sorted(set(found_rules))),
        "scanner_findings": scoped_findings,
        "diff_scope": diff_scope,
        "raw_tool_finding_count": len(findings),
        "out_of_scope_finding_count": len(out_of_scope_findings),
        "out_of_scope_finding_samples": _finding_samples(out_of_scope_findings),
        "expected_rules": case.expected_rules,
        "expected_rule_hits": expected_rule_hits,
        "expected_rule_misses": expected_rule_misses,
        "expected_findings": tuple(finding.__dict__ for finding in case.expected_findings),
        "expected_finding_hits": expected_finding_hits,
        "expected_finding_misses": expected_finding_misses,
        "finding_labels": finding_labels,
        "finding_role_counts": _role_counts(finding_labels),
        "unexpected_taxonomy": _unexpected_taxonomy_counts(finding_labels),
        "tags": case.tags,
        **_case_metrics(
            findings=scoped_findings,
            artifact_present=artifact_present,
            raw_finding_count=len(findings),
            out_of_scope_finding_count=len(out_of_scope_findings),
        ),
    }


def _skipped_case(case: Any, raw_case: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": case.case_id,
        "status": "skipped",
        "adapter": str(raw_case.get("adapter", "")),
        "tool_name": str(raw_case.get("tool_name", "")),
        "skip_reason": str(raw_case.get("skip_reason", "scanner execution skipped")),
        "metadata": case.metadata or {},
        "found_rules": (),
        "scanner_findings": (),
        "expected_rules": case.expected_rules,
        "expected_rule_hits": (),
        "expected_rule_misses": case.expected_rules,
        "expected_findings": tuple(finding.__dict__ for finding in case.expected_findings),
        "expected_finding_hits": (),
        "expected_finding_misses": tuple(
            finding.__dict__
            for finding in case.expected_findings
            if finding.role != "negative-control"
        ),
        "finding_labels": (),
        "finding_role_counts": {},
        "unexpected_taxonomy": {},
        "tags": case.tags,
        "finding_count": 0,
    }


def _error_case(case: Any, raw_case: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": case.case_id,
        "status": "error",
        "adapter": str(raw_case.get("adapter", "")),
        "tool_name": str(raw_case.get("tool_name", "")),
        "error": str(raw_case.get("error", "scanner execution failed")),
        "metadata": case.metadata or {},
        "found_rules": (),
        "scanner_findings": (),
        "expected_rules": case.expected_rules,
        "expected_rule_hits": (),
        "expected_rule_misses": case.expected_rules,
        "expected_findings": tuple(finding.__dict__ for finding in case.expected_findings),
        "expected_finding_hits": (),
        "expected_finding_misses": tuple(
            finding.__dict__
            for finding in case.expected_findings
            if finding.role != "negative-control"
        ),
        "finding_labels": (),
        "finding_role_counts": {},
        "unexpected_taxonomy": {},
        "tags": case.tags,
        "finding_count": 0,
    }


def _parse_case_findings(
    *,
    raw_case: dict[str, Any],
    adapter: str,
    tool_name: str,
    results_base_dir: Path,
) -> tuple[tuple[ToolFinding, ...], bool]:
    payload, artifact_present = _case_payload(raw_case, adapter=adapter, base_dir=results_base_dir)
    if adapter == "semgrep":
        return parse_semgrep_json(tool_name=tool_name, payload=payload), artifact_present
    if adapter in {"codeql", "sarif"}:
        sarif_adapter = "codeql" if adapter == "sarif" else adapter
        return (
            parse_sarif_json(tool_name=tool_name, adapter=sarif_adapter, payload=payload),
            artifact_present,
        )
    raise ScannerBaselineError(f"Unsupported scanner baseline adapter: {adapter}")


def _case_payload(
    raw_case: dict[str, Any],
    *,
    adapter: str,
    base_dir: Path,
) -> tuple[str, bool]:
    artifact = raw_case.get("artifact")
    if artifact:
        artifact_path = _resolve_path(base_dir, artifact)
        if not artifact_path.exists():
            raise ScannerBaselineError(f"Scanner baseline artifact does not exist: {artifact_path}")
        return artifact_path.read_text(encoding="utf-8", errors="replace"), True

    if "payload" in raw_case:
        return json.dumps(raw_case["payload"]), True
    if adapter == "semgrep" and "semgrep" in raw_case:
        return json.dumps(raw_case["semgrep"]), True
    if adapter in {"codeql", "sarif"} and "sarif" in raw_case:
        return json.dumps(raw_case["sarif"]), True
    if adapter == "semgrep" and "results" in raw_case:
        return json.dumps({"results": raw_case["results"]}), True
    if adapter in {"codeql", "sarif"} and "runs" in raw_case:
        return json.dumps({"runs": raw_case["runs"]}), True
    return "", False


def _normalize_tool_findings(
    *,
    case_id: str,
    tool_findings: tuple[ToolFinding, ...],
    rule_map: dict[str, str],
    severity_map: dict[str, str],
) -> tuple[dict[str, Any], ...]:
    findings: list[dict[str, Any]] = []
    safe_case = _safe_case_id(case_id)
    for index, finding in enumerate(tool_findings, start=1):
        scanner_rule_id = finding.rule_id
        severity = severity_map.get(finding.severity.lower(), finding.severity.lower())
        findings.append(
            {
                "finding_id": f"{safe_case}:scanner:{index}",
                "rule_id": rule_map.get(scanner_rule_id, scanner_rule_id),
                "scanner_rule_id": scanner_rule_id,
                "tool_name": finding.tool_name,
                "adapter": finding.adapter,
                "message": finding.message,
                "file_path": finding.file_path,
                "start_line": finding.start_line,
                "end_line": finding.end_line,
                "severity": severity,
                "metadata": finding.metadata,
            }
        )
    return tuple(findings)


def _case_metrics(
    *,
    findings: tuple[dict[str, Any], ...],
    artifact_present: bool,
    raw_finding_count: int | None = None,
    out_of_scope_finding_count: int = 0,
) -> dict[str, Any]:
    severity_counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity", "unknown"))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    finding_count = len(findings)
    raw_count = raw_finding_count if raw_finding_count is not None else finding_count
    return {
        "finding_count": finding_count,
        "severity_counts": severity_counts,
        "avg_confidence": 0.0,
        "verification_count": 0,
        "verification_passed": 0,
        "required_failure_count": 0,
        "validation_step_count": 0,
        "validation_covered": 0,
        "validation_missing": 0,
        "tool_finding_count": raw_count,
        "raw_tool_finding_count": raw_count,
        "out_of_scope_finding_count": out_of_scope_finding_count,
        "tool_artifact_count": 1 if artifact_present else 0,
        "tool_supported_findings": finding_count,
        "validation_gap_findings": 0,
        "scanner_dampened_findings": 0,
        "policy_blocked_count": 0,
        "policy_warning_count": 0,
    }


def _case_diff_scope(
    *,
    case: Any,
    raw_case: dict[str, Any],
    results_base_dir: Path,
) -> dict[str, Any]:
    diff_text, source = _case_diff_text(
        case=case,
        raw_case=raw_case,
        results_base_dir=results_base_dir,
    )
    if not diff_text:
        return {
            "available": False,
            "source": source,
            "changed_line_count": 0,
            "window_count": 0,
            "files": (),
            "ranges": {},
        }

    changed_lines = parse_unified_diff(diff_text)
    windows = evidence_windows(changed_lines, max_lines=DIFF_SCOPE_MAX_LINES)
    ranges: dict[str, list[tuple[int, int]]] = {}
    for window in windows:
        ranges.setdefault(_normalize_path(window.file_path), []).append(
            (window.start_line, window.end_line)
        )
    return {
        "available": bool(ranges),
        "source": source,
        "changed_line_count": sum(1 for line in changed_lines if line.change_type != "context"),
        "window_count": len(windows),
        "files": tuple(sorted(ranges)),
        "ranges": {
            file_path: tuple(_merge_ranges(file_ranges))
            for file_path, file_ranges in sorted(ranges.items())
        },
    }


def _case_diff_text(
    *,
    case: Any,
    raw_case: dict[str, Any],
    results_base_dir: Path,
) -> tuple[str, str]:
    raw_diff = raw_case.get("diff")
    if isinstance(raw_diff, str) and raw_diff:
        return raw_diff, "inline"

    raw_diff_path = raw_case.get("diff_path")
    if raw_diff_path:
        diff_path = _resolve_path(results_base_dir, raw_diff_path)
        if diff_path.exists():
            return diff_path.read_text(encoding="utf-8", errors="replace"), str(diff_path)

    if case.diff_path is not None and case.diff_path.exists():
        return case.diff_path.read_text(encoding="utf-8", errors="replace"), str(case.diff_path)

    if case.diff_url:
        try:
            return fetch_url_diff(case.diff_url), case.diff_url
        except Exception as exc:
            return "", f"{case.diff_url} ({exc})"

    return "", "unavailable"


def _split_diff_scoped_findings(
    *,
    findings: tuple[dict[str, Any], ...],
    diff_scope: dict[str, Any],
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    if not diff_scope.get("available"):
        return findings, ()
    in_scope: list[dict[str, Any]] = []
    out_of_scope: list[dict[str, Any]] = []
    for finding in findings:
        if _finding_in_diff_scope(finding, diff_scope):
            in_scope.append(finding)
        else:
            out_of_scope.append(finding)
    return tuple(in_scope), tuple(out_of_scope)


def _finding_in_diff_scope(finding: dict[str, Any], diff_scope: dict[str, Any]) -> bool:
    finding_path = _normalize_path(str(finding.get("file_path", "")))
    finding_start = int(finding.get("start_line") or 0)
    finding_end = int(finding.get("end_line") or finding_start)
    if not finding_path or finding_start <= 0:
        return False
    ranges = diff_scope.get("ranges", {})
    if not isinstance(ranges, dict):
        return False
    for scoped_path, scoped_ranges in ranges.items():
        if not _paths_overlap(finding_path, str(scoped_path)):
            continue
        for start, end in scoped_ranges:
            if finding_start <= int(end) and int(start) <= finding_end:
                return True
    return False


def _finding_samples(findings: tuple[dict[str, Any], ...]) -> tuple[dict[str, Any], ...]:
    return tuple(
        {
            "rule_id": finding.get("rule_id", ""),
            "scanner_rule_id": finding.get("scanner_rule_id", ""),
            "file_path": finding.get("file_path", ""),
            "start_line": finding.get("start_line"),
            "end_line": finding.get("end_line"),
            "severity": finding.get("severity", ""),
        }
        for finding in findings[:OUT_OF_SCOPE_SAMPLE_LIMIT]
    )


def _merge_ranges(ranges: list[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    if not ranges:
        return ()
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if not merged or start > merged[-1][1] + 1:
            merged.append((start, end))
        else:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
    return tuple(merged)


def _paths_overlap(first: str, second: str) -> bool:
    first = _normalize_path(first)
    second = _normalize_path(second)
    return first == second or first.endswith(f"/{second}") or second.endswith(f"/{first}")


def _normalize_path(value: str) -> str:
    return value.replace("\\", "/").lstrip("./")


def _role_counts(labels: tuple[dict[str, Any], ...]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for label in labels:
        role = str(label.get("role", "unexpected"))
        counts[role] = counts.get(role, 0) + 1
    return counts


def _unexpected_taxonomy_counts(labels: tuple[dict[str, Any], ...]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for label in labels:
        if label.get("role") in {"primary", "supporting", "benign"}:
            continue
        taxonomy = str(label.get("taxonomy", "unclassified"))
        counts[taxonomy] = counts.get(taxonomy, 0) + 1
    return counts


def _resolve_path(base_dir: Path, value: Any) -> Path:
    path = Path(str(value))
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def _string_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}
