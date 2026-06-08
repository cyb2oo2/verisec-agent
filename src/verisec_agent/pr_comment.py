from __future__ import annotations

import json
from pathlib import Path
from typing import Any

COMMENT_MARKER = "<!-- verisec-agent:pr-comment -->"


class PullRequestCommentError(RuntimeError):
    pass


def write_pr_comment(
    *,
    output_path: Path,
    report_path: Path | None = None,
    evaluation_path: Path | None = None,
    gate_path: Path | None = None,
    max_findings: int = 5,
) -> str:
    markdown = render_pr_comment(
        report_path=report_path,
        evaluation_path=evaluation_path,
        gate_path=gate_path,
        max_findings=max_findings,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(markdown, encoding="utf-8")
    return markdown


def render_pr_comment(
    *,
    report_path: Path | None = None,
    evaluation_path: Path | None = None,
    gate_path: Path | None = None,
    max_findings: int = 5,
) -> str:
    if (report_path is None) == (evaluation_path is None):
        raise PullRequestCommentError(
            "Provide exactly one PR comment source: report_path or evaluation_path."
        )

    gate = _load_json(gate_path) if gate_path is not None else None
    if report_path is not None:
        return render_report_comment(
            report=_load_json(report_path),
            gate=gate,
            source_path=report_path,
            max_findings=max_findings,
        )
    assert evaluation_path is not None
    return render_evaluation_comment(
        evaluation=_load_json(evaluation_path),
        gate=gate,
        source_path=evaluation_path,
    )


def render_report_comment(
    *,
    report: dict[str, Any],
    gate: dict[str, Any] | None,
    source_path: Path,
    max_findings: int,
) -> str:
    summary = report.get("summary", {})
    lines = [
        COMMENT_MARKER,
        "## VeriSec Security Review",
        "",
        *_render_gate_status(gate),
        _metrics_table(
            (
                ("Findings", summary.get("finding_count", 0)),
                ("Average confidence", _format_float(summary.get("avg_confidence", 0))),
                ("Validation coverage", _coverage(summary)),
                ("Tool-supported findings", summary.get("tool_supported_findings", 0)),
                ("Validation-gap findings", summary.get("validation_gap_findings", 0)),
                ("Tool findings", summary.get("tool_finding_count", 0)),
                ("Policy-blocked tools", summary.get("policy_blocked_count", 0)),
                ("Policy warnings", summary.get("policy_warning_count", 0)),
                ("Required failures", len(summary.get("required_failures", ()))),
            )
        ),
        "",
        f"Source report: `{_display_path(source_path)}`",
        "",
    ]

    findings = report.get("findings", ())
    if findings:
        lines.extend(["### Findings", ""])
        for finding in findings[:max_findings]:
            lines.extend(_render_finding_details(finding))
        if len(findings) > max_findings:
            lines.append(f"_Showing {max_findings} of {len(findings)} findings._")
            lines.append("")
    else:
        lines.extend(["### Findings", "", "No findings were reported.", ""])

    return "\n".join(lines).rstrip() + "\n"


def render_evaluation_comment(
    *,
    evaluation: dict[str, Any],
    gate: dict[str, Any] | None,
    source_path: Path,
) -> str:
    summary = evaluation.get("summary", {})
    lines = [
        COMMENT_MARKER,
        "## VeriSec Evaluation",
        "",
        *_render_gate_status(gate),
        _metrics_table(
            (
                ("Cases", summary.get("case_count", 0)),
                ("Completed", summary.get("completed_count", 0)),
                ("Errors", summary.get("error_count", 0)),
                ("Findings", summary.get("finding_count", 0)),
                ("Average confidence", _format_float(summary.get("avg_confidence", 0))),
                (
                    "Validation coverage",
                    _format_float(summary.get("validation_coverage_rate", 0)),
                ),
                ("Tool evidence rate", _format_float(summary.get("tool_evidence_rate", 0))),
                ("Validation gap rate", _format_float(summary.get("validation_gap_rate", 0))),
                ("Policy-blocked tools", summary.get("policy_blocked_count", 0)),
                ("Policy warnings", summary.get("policy_warning_count", 0)),
                ("Accepted finding rate", _format_float(summary.get("accepted_finding_rate", 0))),
                ("Primary precision", _format_float(summary.get("primary_precision", 0))),
                (
                    "Primary finding recall",
                    _format_optional(summary.get("primary_finding_recall")),
                ),
                (
                    "Supporting evidence rate",
                    _format_float(summary.get("supporting_evidence_rate", 0)),
                ),
                (
                    "Unexpected finding rate",
                    _format_float(summary.get("unexpected_finding_rate", 0)),
                ),
                (
                    "Negative-control violations",
                    summary.get("negative_control_violation_count", 0),
                ),
                ("Expected rule recall", _format_optional(summary.get("expected_rule_recall"))),
                (
                    "Expected rule precision",
                    _format_optional(summary.get("expected_rule_precision")),
                ),
                (
                    "Expected finding recall",
                    _format_optional(summary.get("expected_finding_recall")),
                ),
                ("CVE/advisory cases", summary.get("security_advisory_case_count", 0)),
            )
        ),
        "",
        f"Source evaluation: `{_display_path(source_path)}`",
        "",
    ]

    cases = evaluation.get("cases", ())
    if cases:
        lines.extend(["### Cases", "", "| Case | Status | Findings | Expected hits | Bundle |"])
        lines.append("| --- | --- | ---: | --- | --- |")
        for case in cases:
            hits = ", ".join(case.get("expected_rule_hits", ())) or "-"
            lines.append(
                "| "
                f"{_escape_table(str(case.get('case_id', '')))} | "
                f"{_escape_table(str(case.get('status', '')))} | "
                f"{case.get('finding_count', 0)} | "
                f"{_escape_table(hits)} | "
                f"`{_display_path(str(case.get('bundle_path', '')))}` |"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _render_gate_status(gate: dict[str, Any] | None) -> list[str]:
    if gate is None:
        return []
    status = "passed" if gate.get("passed") else "failed"
    lines = [f"**Gate:** {status}", ""]
    failures = gate.get("failures", ())
    if failures:
        lines.extend(["Gate failures:", ""])
        lines.extend(f"- {failure}" for failure in failures)
        lines.append("")
    return lines


def _render_finding_details(finding: dict[str, Any]) -> list[str]:
    title = finding.get("title", "Finding")
    rule_id = finding.get("rule_id", "unknown-rule")
    severity = finding.get("severity", "unknown")
    confidence = _format_float(finding.get("confidence", 0))
    location = (
        f"{finding.get('file_path', '')}:"
        f"{finding.get('start_line', 0)}-{finding.get('end_line', 0)}"
    )
    evidence = finding.get("evidence", "")
    notes = finding.get("confidence_notes", "")
    lines = [
        f"<details><summary>{severity} `{rule_id}` - {title} ({confidence})</summary>",
        "",
        f"- Location: `{location}`",
        f"- Risk: {finding.get('risk', '')}",
        f"- Fix guidance: {finding.get('fix_guidance', '')}",
    ]
    if notes:
        lines.append(f"- Confidence notes: {notes}")
    if evidence:
        lines.extend(["", "```diff", evidence, "```"])
    lines.extend(["", "</details>", ""])
    return lines


def _metrics_table(rows: tuple[tuple[str, Any], ...]) -> str:
    lines = ["| Metric | Value |", "| --- | ---: |"]
    for name, value in rows:
        lines.append(f"| {_escape_table(name)} | {_escape_table(str(value))} |")
    return "\n".join(lines)


def _coverage(summary: dict[str, Any]) -> str:
    covered = summary.get("validation_covered", 0)
    total = summary.get("validation_step_count", 0)
    return f"{covered}/{total}"


def _format_float(value: Any) -> str:
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return "0.00"


def _format_optional(value: Any) -> str:
    if value is None:
        return "n/a"
    return _format_float(value)


def _escape_table(value: str) -> str:
    return value.replace("|", "\\|")


def _display_path(path: str | Path) -> str:
    raw_path = Path(path)
    try:
        display_path = raw_path.resolve().relative_to(Path.cwd().resolve())
    except (OSError, ValueError):
        display_path = raw_path
    return str(display_path).replace("\\", "/")


def _load_json(path: Path | None) -> dict[str, Any]:
    if path is None:
        raise PullRequestCommentError("Missing JSON path.")
    if not path.exists():
        raise PullRequestCommentError(f"JSON source does not exist: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PullRequestCommentError(f"JSON source is invalid: {path}: {exc}") from exc
