from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from verisec_agent.models import Finding, ValidationStep, VerificationResult

_EVIDENCE_PREFIX = "VERISEC_EVIDENCE:"


@dataclass(frozen=True)
class _ValidationEvidence:
    kind: str
    message: str
    rule_id: str = ""
    finding_id: str = ""
    file_path: str = ""
    start_line: int | None = None
    end_line: int | None = None
    check: str = ""
    payload: str = ""
    assertion: str = ""


def build_validation_plan(
    findings: Iterable[Finding],
    verification: Iterable[VerificationResult],
) -> tuple[ValidationStep, ...]:
    results = tuple(verification)
    steps: list[ValidationStep] = []

    for finding in findings:
        for recommended_check in finding.recommended_validation:
            candidates = tuple(
                result
                for result in results
                if result.passed and _check_matches_command(recommended_check, result)
            )
            evidence_by_tool = tuple(
                (result.name, _structured_evidence_for_result(result, finding, recommended_check))
                for result in candidates
            )
            covered_by = tuple(
                tool_name for tool_name, evidence in evidence_by_tool if evidence
            )
            candidate_tools = tuple(
                result.name for result in candidates if result.name not in covered_by
            )
            tool_evidence = tuple(
                evidence_item
                for _, evidence in evidence_by_tool
                for evidence_item in evidence
            )
            steps.append(
                ValidationStep(
                    finding_id=finding.finding_id,
                    objective=f"Validate {finding.title}",
                    recommended_check=recommended_check,
                    status="covered" if covered_by else "missing",
                    covered_by=covered_by,
                    tool_evidence=tool_evidence,
                    candidate_tools=candidate_tools,
                    failure_boundary=_failure_boundary(
                        recommended_check,
                        covered_by,
                        candidate_tools,
                    ),
                )
            )

    return tuple(steps)


def _structured_evidence_for_result(
    result: VerificationResult,
    finding: Finding,
    recommended_check: str,
) -> tuple[str, ...]:
    tool_findings = tuple(
        _render_tool_finding(result.name, tool_finding)
        for tool_finding in result.tool_findings
        if _tool_finding_matches_review_finding(tool_finding, finding)
    )
    validation_markers = tuple(
        _render_validation_evidence(result.name, evidence)
        for evidence in _validation_evidence_from_result(result)
        if _validation_evidence_matches(
            evidence,
            finding=finding,
            recommended_check=recommended_check,
        )
    )
    return tool_findings + validation_markers


def _check_matches_command(recommended_check: str, result: VerificationResult) -> bool:
    if _check_matches_capabilities(recommended_check, result.capabilities):
        return True

    name = result.name.lower()
    command = result.command.lower()
    haystack = f"{name} {command}"
    check = recommended_check.lower()

    if "unit" in check or "regression" in check:
        return _has_any(name, ("test", "unit", "regression")) or _has_any(
            command,
            ("pytest", "unittest"),
        )
    if "command-injection" in check or "shell" in check:
        return _has_any(
            haystack,
            ("semgrep", "codeql", "command-injection", "shell-injection"),
        )
    if "static" in check or "taint" in check:
        return _has_any(haystack, ("semgrep", "codeql", "ruff", "bandit", "mypy", "taint"))
    if "semgrep" in check:
        return "semgrep" in haystack
    if "codeql" in check:
        return "codeql" in haystack
    if "fuzz" in check:
        return _has_any(haystack, ("fuzz", "atheris", "hypothesis", "libfuzzer"))
    if "sanitizer" in check:
        return _has_any(haystack, ("asan", "ubsan", "sanitizer"))
    if "crypto" in check or "policy" in check:
        return _has_any(haystack, ("semgrep", "codeql", "bandit", "crypto", "policy"))
    if "sql" in check:
        return _has_any(name, ("test", "sql")) or _has_any(
            command,
            ("pytest", "unittest", "semgrep", "codeql", "sql"),
        )
    return check in haystack


def _check_matches_capabilities(
    recommended_check: str,
    capabilities: tuple[str, ...],
) -> bool:
    caps = {capability.lower() for capability in capabilities}
    check = recommended_check.lower()

    if "semgrep" in check:
        return "semgrep" in caps
    if "codeql" in check:
        return "codeql" in caps
    if "unit" in check:
        return bool(caps & {"unit-test", "regression-test"})
    if "regression" in check or "malicious input" in check:
        return bool(caps & {"unit-test", "regression-test", "exploit-regression", "poc"})
    if "command-injection" in check or "shell" in check:
        return "command-injection" in caps
    if "sql" in check:
        return bool(caps & {"sql-injection", "database-security", "static-analysis"})
    if "taint" in check:
        return bool(caps & {"taint-analysis", "dataflow-analysis"})
    if "static" in check:
        return "static-analysis" in caps
    if "integration" in check:
        return bool(caps & {"integration-test", "regression-test"})
    if "fuzz" in check:
        return "fuzzing" in caps
    if "sanitizer" in check:
        return "sanitizer" in caps
    if "crypto" in check or "policy" in check:
        return bool(caps & {"crypto-policy", "policy-check", "static-analysis"})
    return False


def _has_any(value: str, keywords: tuple[str, ...]) -> bool:
    return any(keyword in value for keyword in keywords)


def _tool_finding_matches_review_finding(tool_finding, finding: Finding) -> bool:
    if _normalize_path(tool_finding.file_path) != _normalize_path(finding.file_path):
        return False
    return not (
        tool_finding.end_line < finding.start_line
        or tool_finding.start_line > finding.end_line
    )


def _render_tool_finding(tool_name: str, tool_finding) -> str:
    message = f": {tool_finding.message}" if tool_finding.message else ""
    return (
        f"{tool_name}/{tool_finding.rule_id} at {tool_finding.location()} "
        f"({tool_finding.severity}){message}"
    )


def _validation_evidence_from_result(
    result: VerificationResult,
) -> tuple[_ValidationEvidence, ...]:
    evidence: list[_ValidationEvidence] = []
    for output_path in (result.stdout_path, result.stderr_path):
        if output_path is None:
            continue
        path = Path(output_path)
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            marker = _parse_validation_marker(line)
            if marker is not None:
                evidence.append(marker)
    return tuple(evidence)


def _parse_validation_marker(line: str) -> _ValidationEvidence | None:
    if _EVIDENCE_PREFIX not in line:
        return None
    raw_payload = line.split(_EVIDENCE_PREFIX, maxsplit=1)[1].strip()
    if not raw_payload:
        return None
    try:
        data = json.loads(raw_payload)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None

    return _ValidationEvidence(
        kind=str(data.get("kind") or "validation"),
        message=str(data.get("message") or ""),
        rule_id=str(data.get("rule_id") or data.get("rule") or ""),
        finding_id=str(data.get("finding_id") or ""),
        file_path=str(data.get("file_path") or data.get("file") or ""),
        start_line=_optional_int(data.get("start_line") or data.get("line")),
        end_line=_optional_int(data.get("end_line") or data.get("line")),
        check=str(data.get("check") or ""),
        payload=str(data.get("payload") or ""),
        assertion=str(data.get("assertion") or ""),
    )


def _validation_evidence_matches(
    evidence: _ValidationEvidence,
    *,
    finding: Finding,
    recommended_check: str,
) -> bool:
    if evidence.check and not _text_overlaps(evidence.check, recommended_check):
        return False
    if evidence.finding_id:
        return evidence.finding_id == finding.finding_id
    if evidence.rule_id and evidence.rule_id != finding.rule_id:
        return False
    if evidence.file_path and _normalize_path(evidence.file_path) != _normalize_path(
        finding.file_path
    ):
        return False
    if (
        evidence.start_line is not None
        and evidence.end_line is not None
        and (evidence.end_line < finding.start_line or evidence.start_line > finding.end_line)
    ):
        return False
    return bool(evidence.rule_id or evidence.file_path or evidence.start_line is not None)


def _render_validation_evidence(tool_name: str, evidence: _ValidationEvidence) -> str:
    location = ""
    if evidence.file_path:
        if evidence.start_line is not None:
            end_line = evidence.end_line or evidence.start_line
            location = f" at {_normalize_path(evidence.file_path)}:{evidence.start_line}-{end_line}"
        else:
            location = f" at {_normalize_path(evidence.file_path)}"

    labels = [f"{tool_name}/{evidence.kind}{location}"]
    if evidence.rule_id:
        labels.append(f"rule={evidence.rule_id}")
    if evidence.message:
        labels.append(evidence.message)
    if evidence.payload:
        labels.append(f"payload={evidence.payload}")
    if evidence.assertion:
        labels.append(f"assertion={evidence.assertion}")
    return " | ".join(labels)


def _text_overlaps(left: str, right: str) -> bool:
    left_normalized = _normalize_text(left)
    right_normalized = _normalize_text(right)
    return left_normalized in right_normalized or right_normalized in left_normalized


def _normalize_text(value: str) -> str:
    return " ".join(value.lower().replace("-", " ").replace("_", " ").split())


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _failure_boundary(
    recommended_check: str,
    covered_by: tuple[str, ...],
    candidate_tools: tuple[str, ...],
) -> str:
    if covered_by:
        return (
            "This check has matching structured evidence from the listed tool(s), but reviewer "
            "judgment is still needed for exploitability and production exposure."
        )
    if candidate_tools:
        return (
            "Candidate tool(s) ran for this check, but none produced a matching scanner finding, "
            "test marker, payload assertion, or changed-line evidence. Treat this as unvalidated "
            f"until '{recommended_check}' is tied to structured evidence."
        )
    return (
        f"No configured tool currently covers '{recommended_check}'. Confidence rests on "
        "localized evidence and deterministic rules until this validation is added."
    )
