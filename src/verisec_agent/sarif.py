"""Export VeriSec review findings as SARIF 2.1.0 for GitHub code scanning UIs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from verisec_agent.models import Finding, ReviewReport

_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_SEVERITY_TO_SECURITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "none",
}


def render_sarif_report(report: ReviewReport) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from a VeriSec review report."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in report.findings:
        rules_by_id.setdefault(finding.rule_id, _rule_descriptor(finding))
        results.append(_result_from_finding(finding))

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VeriSec Agent",
                        "informationUri": "https://github.com/search?q=verisec-agent",
                        "version": "0.1.0",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "workingDirectory": {"uri": _path_uri(report.repo_path)},
                    }
                ],
                "properties": {
                    "verisec.subject": report.subject,
                    "verisec.bundle_path": report.bundle_path,
                    "verisec.diff_path": report.diff_path,
                    "verisec.summary": report.summary,
                },
            }
        ],
    }


def write_sarif_report(report: ReviewReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(render_sarif_report(report), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _rule_descriptor(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.rule_id,
        "name": finding.rule_id,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.risk or finding.title},
        "help": {
            "text": finding.fix_guidance or finding.risk or finding.title,
            "markdown": _help_markdown(finding),
        },
        "defaultConfiguration": {
            "level": _SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
        },
        "properties": {
            "security-severity": _SEVERITY_TO_SECURITY.get(finding.severity, "medium"),
            "tags": ["security", "verisec", finding.severity],
        },
    }


def _result_from_finding(finding: Finding) -> dict[str, Any]:
    message_parts = [finding.title]
    if finding.fix_guidance:
        message_parts.append(f"Fix: {finding.fix_guidance}")
    if finding.analysis_notes:
        message_parts.append(finding.analysis_notes)

    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": _SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
        "message": {"text": " ".join(message_parts)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file_path.replace("\\", "/"),
                    },
                    "region": {
                        "startLine": max(1, finding.start_line),
                        "endLine": max(finding.start_line, finding.end_line),
                    },
                }
            }
        ],
        "partialFingerprints": {
            "verisecFindingId": finding.finding_id,
        },
        "properties": {
            "verisec.confidence": finding.confidence,
            "verisec.base_confidence": finding.base_confidence,
            "verisec.severity": finding.severity,
            "verisec.analysis_scope": finding.analysis_scope,
            "verisec.recommended_validation": list(finding.recommended_validation),
        },
    }
    if finding.dataflow_steps:
        result["properties"]["verisec.dataflow_steps"] = list(finding.dataflow_steps)
    return result


def _help_markdown(finding: Finding) -> str:
    lines = [
        f"## {finding.title}",
        "",
        finding.risk or "",
        "",
    ]
    if finding.fix_guidance:
        lines.extend(["### Fix guidance", "", finding.fix_guidance, ""])
    if finding.recommended_validation:
        lines.extend(["### Recommended validation", ""])
        lines.extend(f"- {item}" for item in finding.recommended_validation)
        lines.append("")
    if finding.false_positive_notes:
        lines.extend(["### False-positive notes", "", finding.false_positive_notes, ""])
    return "\n".join(lines).strip() + "\n"


def _path_uri(path: str) -> str:
    resolved = Path(path).resolve()
    return resolved.as_uri()
