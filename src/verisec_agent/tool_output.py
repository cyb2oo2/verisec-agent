from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from verisec_agent.models import ToolFinding


@dataclass(frozen=True)
class ParsedToolOutput:
    findings: tuple[ToolFinding, ...] = ()
    artifact_paths: tuple[Path, ...] = ()


def parse_tool_output(
    *,
    adapter: str,
    tool_name: str,
    stdout: str,
    tool_dir: Path,
) -> ParsedToolOutput:
    if adapter == "semgrep":
        return ParsedToolOutput(findings=parse_semgrep_json(tool_name=tool_name, payload=stdout))
    if adapter == "codeql":
        return _parse_codeql_output(tool_name=tool_name, stdout=stdout, tool_dir=tool_dir)
    return ParsedToolOutput()


def parse_semgrep_json(*, tool_name: str, payload: str) -> tuple[ToolFinding, ...]:
    if not payload.strip():
        return ()
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return ()

    findings: list[ToolFinding] = []
    for item in data.get("results", []):
        finding = _semgrep_result_to_finding(tool_name, item)
        if finding is not None:
            findings.append(finding)
    return tuple(findings)


def parse_sarif_json(*, tool_name: str, adapter: str, payload: str) -> tuple[ToolFinding, ...]:
    if not payload.strip():
        return ()
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return ()

    findings: list[ToolFinding] = []
    for run in data.get("runs", []):
        rules = _sarif_rules_by_id(run)
        for item in run.get("results", []):
            finding = _sarif_result_to_finding(
                tool_name=tool_name,
                adapter=adapter,
                item=item,
                rules=rules,
            )
            if finding is not None:
                findings.append(finding)
    return tuple(findings)


def _semgrep_result_to_finding(tool_name: str, item: dict[str, Any]) -> ToolFinding | None:
    start = item.get("start", {})
    end = item.get("end", {})
    extra = item.get("extra", {})
    file_path = str(item.get("path", ""))
    if not file_path:
        return None

    start_line = _int_or_default(start.get("line"), 0)
    end_line = _int_or_default(end.get("line"), start_line)
    if start_line <= 0:
        return None

    return ToolFinding(
        tool_name=tool_name,
        adapter="semgrep",
        rule_id=str(item.get("check_id", "")),
        message=str(extra.get("message", "")),
        file_path=file_path.replace("\\", "/"),
        start_line=start_line,
        end_line=end_line,
        severity=str(extra.get("severity", "unknown")).lower(),
        metadata=_compact_metadata(extra.get("metadata", {})),
    )


def _parse_codeql_output(*, tool_name: str, stdout: str, tool_dir: Path) -> ParsedToolOutput:
    stdout_findings = parse_sarif_json(tool_name=tool_name, adapter="codeql", payload=stdout)
    artifact_paths = _sarif_artifact_candidates(tool_name=tool_name, tool_dir=tool_dir)
    file_findings: list[ToolFinding] = []
    parsed_artifacts: list[Path] = []

    for artifact_path in artifact_paths:
        if not artifact_path.exists():
            continue
        findings = parse_sarif_json(
            tool_name=tool_name,
            adapter="codeql",
            payload=artifact_path.read_text(encoding="utf-8", errors="replace"),
        )
        parsed_artifacts.append(artifact_path)
        file_findings.extend(findings)

    return ParsedToolOutput(
        findings=stdout_findings + tuple(file_findings),
        artifact_paths=tuple(parsed_artifacts),
    )


def _sarif_result_to_finding(
    *,
    tool_name: str,
    adapter: str,
    item: dict[str, Any],
    rules: dict[str, dict[str, Any]],
) -> ToolFinding | None:
    rule_id = str(item.get("ruleId", ""))
    location = _first_sarif_location(item)
    if location is None:
        return None

    physical = location.get("physicalLocation", {})
    artifact = physical.get("artifactLocation", {})
    region = physical.get("region", {})
    file_path = str(artifact.get("uri", ""))
    start_line = _int_or_default(region.get("startLine"), 0)
    end_line = _int_or_default(region.get("endLine"), start_line)
    if not file_path or start_line <= 0:
        return None

    rule = rules.get(rule_id, {})
    severity = str(
        item.get("level")
        or rule.get("defaultConfiguration", {}).get("level")
        or "unknown"
    ).lower()
    return ToolFinding(
        tool_name=tool_name,
        adapter=adapter,
        rule_id=rule_id,
        message=_sarif_message(item),
        file_path=_normalize_sarif_uri(file_path),
        start_line=start_line,
        end_line=end_line,
        severity=severity,
        metadata=_compact_metadata(rule.get("properties", {})),
    )


def _sarif_rules_by_id(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    driver = run.get("tool", {}).get("driver", {})
    extensions = run.get("tool", {}).get("extensions", [])
    rules: dict[str, dict[str, Any]] = {}
    for container in (driver, *extensions):
        for rule in container.get("rules", []):
            rule_id = str(rule.get("id", ""))
            if rule_id:
                rules[rule_id] = rule
    return rules


def _first_sarif_location(item: dict[str, Any]) -> dict[str, Any] | None:
    locations = item.get("locations", [])
    if not locations:
        return None
    first = locations[0]
    return first if isinstance(first, dict) else None


def _sarif_message(item: dict[str, Any]) -> str:
    message = item.get("message", {})
    if not isinstance(message, dict):
        return ""
    return str(message.get("text") or message.get("markdown") or "")


def _sarif_artifact_candidates(*, tool_name: str, tool_dir: Path) -> tuple[Path, ...]:
    candidates = (
        tool_dir / f"{tool_name}.sarif",
        tool_dir / "codeql.sarif",
    )
    unique: list[Path] = []
    for path in candidates:
        if path not in unique:
            unique.append(path)
    return tuple(unique)


def _normalize_sarif_uri(uri: str) -> str:
    normalized = uri.replace("\\", "/")
    prefixes = ("file:///", "file://")
    for prefix in prefixes:
        if normalized.startswith(prefix):
            return normalized.removeprefix(prefix)
    return normalized.lstrip("./")


def _compact_metadata(metadata: Any) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}
    return {
        str(key): value
        for key, value in metadata.items()
        if isinstance(value, str | int | float | bool | list | dict | type(None))
    }


def _int_or_default(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
