from __future__ import annotations

from verisec_agent.models import Finding, ReviewReport, ValidationStep


def render_markdown_report(report: ReviewReport) -> str:
    lines = [
        f"# VeriSec Review: {report.subject}",
        "",
        "## Summary",
        "",
        f"- Findings: {report.summary.get('finding_count', len(report.findings))}",
        f"- Average confidence: {report.summary.get('avg_confidence', 0):.2f}",
        f"- Tool-supported findings: {report.summary.get('tool_supported_findings', 0)}",
        f"- Validation-gap findings: {report.summary.get('validation_gap_findings', 0)}",
        (
            "- Verification: "
            f"{report.summary.get('verification_passed', 0)}/"
            f"{report.summary.get('verification_count', len(report.verification))} passed"
        ),
        (
            "- Validation coverage: "
            f"{report.summary.get('validation_covered', 0)}/"
            f"{report.summary.get('validation_step_count', len(report.validation_plan))} covered"
        ),
        f"- Tool findings: {report.summary.get('tool_finding_count', 0)}",
        f"- Tool artifacts: {report.summary.get('tool_artifact_count', 0)}",
        f"- Policy-blocked tools: {report.summary.get('policy_blocked_count', 0)}",
        f"- Policy warnings: {report.summary.get('policy_warning_count', 0)}",
        f"- Bundle: `{report.bundle_path}`",
        "",
    ]

    required_failures = report.summary.get("required_failures", [])
    if required_failures:
        lines.extend(
            [
                "## Required Failures",
                "",
                *[f"- {name}" for name in required_failures],
                "",
            ]
        )

    if report.findings:
        lines.extend(["## Findings", ""])
        validation_by_finding = _validation_by_finding(report.validation_plan)
        for finding in report.findings:
            lines.extend(
                _render_finding(
                    finding,
                    validation_by_finding.get(finding.finding_id, ()),
                )
            )
    else:
        lines.extend(["## Findings", "", "No security findings were generated.", ""])

    if report.verification:
        lines.extend(["## Tool Coverage", ""])
        for result in report.verification:
            capabilities = ", ".join(result.capabilities) if result.capabilities else "none"
            adapter = result.adapter if result.adapter else "custom"
            description = f" - {result.description}" if result.description else ""
            lines.append(
                f"- `{result.name}` via `{adapter}`: {capabilities}{description}"
            )
            if result.policy_reasons:
                lines.append(f"  Policy blocked: {'; '.join(result.policy_reasons)}")
            if result.policy_warnings:
                lines.append(f"  Policy warnings: {'; '.join(result.policy_warnings)}")
            if result.artifact_paths:
                artifacts = ", ".join(f"`{path}`" for path in result.artifact_paths)
                lines.append(f"  Artifacts: {artifacts}")
        lines.append("")

        tool_findings = [
            tool_finding
            for result in report.verification
            for tool_finding in result.tool_findings
        ]
        if tool_findings:
            lines.extend(["## Tool Findings", ""])
            for tool_finding in tool_findings:
                message = f" - {tool_finding.message}" if tool_finding.message else ""
                lines.append(
                    f"- `{tool_finding.tool_name}/{tool_finding.rule_id}` at "
                    f"`{tool_finding.location()}` ({tool_finding.severity}){message}"
                )
            lines.append("")

        lines.extend(["## Verification Trace", ""])
        for result in report.verification:
            status = "blocked" if result.policy_status == "blocked" else (
                "passed" if result.passed else "failed"
            )
            lines.append(
                f"- `{result.name}` {status} in {result.duration_seconds}s "
                f"(exit={result.exit_code}, timeout={result.timed_out})"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _render_finding(finding: Finding, validation_steps: tuple[ValidationStep, ...]) -> list[str]:
    lines = [
        f"### {finding.finding_id}: {finding.title}",
        "",
        f"- Severity: {finding.severity}",
        f"- Confidence: {finding.confidence:.2f}",
        f"- Base confidence: {_format_base_confidence(finding)}",
        f"- Location: `{finding.file_path}:{finding.start_line}-{finding.end_line}`",
        f"- Risk: {finding.risk}",
        f"- Fix guidance: {finding.fix_guidance}",
        f"- False-positive notes: {finding.false_positive_notes}",
        "",
        "Evidence:",
        "",
        "```diff",
        finding.evidence,
        "```",
        "",
    ]
    if finding.confidence_notes:
        lines.extend([f"Confidence notes: {finding.confidence_notes}", ""])

    if finding.source_context is not None:
        lines.extend(["Repository context:", ""])
        if finding.source_context.available:
            lines.extend(
                [
                    "```text",
                    finding.source_context.snippet(),
                    "```",
                    "",
                ]
            )
        else:
            lines.extend([f"{finding.source_context.rationale}", ""])

    if validation_steps:
        lines.extend(["Validation plan:", ""])
        for step in validation_steps:
            covered = ", ".join(step.covered_by) if step.covered_by else "not covered"
            lines.append(
                f"- [{step.status}] {step.recommended_check} "
                f"(covered by: {covered})"
            )
            if step.candidate_tools:
                lines.append(
                    f"  Candidate tools without matching evidence: "
                    f"{', '.join(step.candidate_tools)}"
                )
            for evidence in step.tool_evidence:
                lines.append(f"  Tool evidence: {evidence}")
            lines.append(f"  Boundary: {step.failure_boundary}")
        lines.append("")

    return lines


def _format_base_confidence(finding: Finding) -> str:
    if finding.base_confidence is None:
        return f"{finding.confidence:.2f}"
    return f"{finding.base_confidence:.2f}"


def _validation_by_finding(
    validation_plan: tuple[ValidationStep, ...],
) -> dict[str, tuple[ValidationStep, ...]]:
    grouped: dict[str, list[ValidationStep]] = {}
    for step in validation_plan:
        grouped.setdefault(step.finding_id, []).append(step)
    return {finding_id: tuple(steps) for finding_id, steps in grouped.items()}
