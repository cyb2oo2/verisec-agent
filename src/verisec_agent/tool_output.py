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
    parser = _resolve_parser_name(adapter)
    if parser == "semgrep" or adapter == "semgrep":
        return ParsedToolOutput(findings=parse_semgrep_json(tool_name=tool_name, payload=stdout))
    if parser == "codeql" or adapter == "codeql":
        return _parse_codeql_output(tool_name=tool_name, stdout=stdout, tool_dir=tool_dir)
    if parser == "bandit-json" or adapter == "bandit":
        return ParsedToolOutput(
            findings=parse_bandit_json(tool_name=tool_name, payload=stdout)
        )
    if parser == "pip-audit-json" or adapter in {"pip-audit", "pip_audit"}:
        return ParsedToolOutput(
            findings=parse_pip_audit_json(tool_name=tool_name, payload=stdout)
        )
    return ParsedToolOutput()


def _resolve_parser_name(adapter: str) -> str:
    try:
        from verisec_agent.adapters_api import get_adapter_registry

        return get_adapter_registry().parser_for(adapter)
    except Exception:
        return ""


def parse_bandit_json(*, tool_name: str, payload: str) -> tuple[ToolFinding, ...]:
    """Parse Bandit ``-f json`` output into tool findings."""
    if not payload.strip():
        return ()
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return ()

    findings: list[ToolFinding] = []
    for item in data.get("results", []):
        file_path = str(item.get("filename") or item.get("path") or "")
        if not file_path:
            continue
        start_line = _int_or_default(item.get("line_number"), 0)
        if start_line <= 0:
            continue
        line_range = item.get("line_range")
        if isinstance(line_range, list) and line_range:
            end_line = _int_or_default(line_range[-1], start_line)
        else:
            end_line = start_line
        severity = str(item.get("issue_severity") or item.get("severity") or "unknown")
        findings.append(
            ToolFinding(
                tool_name=tool_name,
                adapter="bandit",
                rule_id=str(item.get("test_id") or item.get("test_name") or ""),
                message=str(item.get("issue_text") or item.get("message") or ""),
                file_path=file_path.replace("\\", "/"),
                start_line=start_line,
                end_line=end_line,
                severity=severity.lower(),
                metadata={
                    key: value
                    for key, value in {
                        "test_name": item.get("test_name"),
                        "issue_confidence": item.get("issue_confidence"),
                        "more_info": item.get("more_info"),
                    }.items()
                    if value is not None
                },
            )
        )
    return tuple(findings)


def parse_pip_audit_json(*, tool_name: str, payload: str) -> tuple[ToolFinding, ...]:
    """Parse ``pip-audit --format json`` dependency vulnerability results.

    pip-audit reports package-level issues (not source lines). Findings are mapped
    to synthetic paths ``dependencies/<package>`` at line 1 so they still flow
    through VeriSec tool-finding plumbing and reports.
    """
    if not payload.strip():
        return ()
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return ()

    dependencies = _pip_audit_dependencies(data)
    findings: list[ToolFinding] = []
    for dep in dependencies:
        name = str(dep.get("name") or dep.get("package") or "").strip()
        version = str(dep.get("version") or dep.get("installed_version") or "").strip()
        if not name:
            continue
        vulns = dep.get("vulns") or dep.get("vulnerabilities") or []
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            vuln_id = str(
                vuln.get("id")
                or vuln.get("advisory")
                or (vuln.get("aliases") or ["unknown"])[0]
            )
            aliases = vuln.get("aliases") or []
            if not isinstance(aliases, list):
                aliases = []
            fix_versions = vuln.get("fix_versions") or vuln.get("fixed_versions") or []
            if not isinstance(fix_versions, list):
                fix_versions = []
            description = str(vuln.get("description") or vuln.get("summary") or "")
            package_label = f"{name}=={version}" if version else name
            message = description or f"Vulnerable dependency {package_label}"
            if fix_versions:
                message = f"{message} (fix: {', '.join(str(v) for v in fix_versions)})"
            findings.append(
                ToolFinding(
                    tool_name=tool_name,
                    adapter="pip-audit",
                    rule_id=vuln_id,
                    message=message,
                    file_path=f"dependencies/{name}",
                    start_line=1,
                    end_line=1,
                    severity="high" if fix_versions else "medium",
                    metadata={
                        key: value
                        for key, value in {
                            "package": name,
                            "version": version,
                            "aliases": aliases,
                            "fix_versions": fix_versions,
                        }.items()
                        if value not in (None, "", [])
                    },
                )
            )
    return tuple(findings)


def _pip_audit_dependencies(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("dependencies", "packages", "results"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


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
