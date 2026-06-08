from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from verisec_agent.models import Finding, ValidationStep, VerificationResult


def calibrate_findings(
    findings: Iterable[Finding],
    validation_plan: Iterable[ValidationStep],
    verification: Iterable[VerificationResult],
) -> tuple[Finding, ...]:
    steps_by_finding = _steps_by_finding(validation_plan)
    verification_by_name = {result.name: result for result in verification}

    calibrated: list[Finding] = []
    for finding in findings:
        steps = steps_by_finding.get(finding.finding_id, ())
        confidence, notes = _calibrate_finding(
            finding=finding,
            steps=steps,
            verification_by_name=verification_by_name,
        )
        calibrated.append(
            replace(
                finding,
                base_confidence=finding.confidence,
                confidence=confidence,
                confidence_notes=notes,
            )
        )
    return tuple(calibrated)


def _calibrate_finding(
    *,
    finding: Finding,
    steps: tuple[ValidationStep, ...],
    verification_by_name: dict[str, VerificationResult],
) -> tuple[float, str]:
    confidence = finding.confidence
    notes: list[str] = []

    if not steps:
        return (
            _clamp(confidence - 0.04),
            "No validation recommendations were attached to this finding.",
        )

    if any(step.tool_evidence for step in steps):
        confidence += 0.12
        notes.append("Matched structured tool evidence on the same file and line range.")

    scanner_covered_without_hit = _scanner_covered_without_hit(steps, verification_by_name)
    if scanner_covered_without_hit:
        confidence -= 0.08
        notes.append(
            "A configured security scanner covered this check but did not emit a matching finding."
        )

    missing_count = sum(1 for step in steps if step.status == "missing")
    if missing_count:
        confidence -= min(0.10, missing_count * 0.04)
        notes.append(f"{missing_count} recommended validation check(s) are still missing.")

    covered_count = sum(1 for step in steps if step.status == "covered")
    if covered_count and not any(step.tool_evidence for step in steps):
        notes.append("Validation coverage exists, but no structured tool finding was matched.")

    return _clamp(confidence), " ".join(notes)


def _scanner_covered_without_hit(
    steps: tuple[ValidationStep, ...],
    verification_by_name: dict[str, VerificationResult],
) -> bool:
    for step in steps:
        if step.tool_evidence:
            continue
        candidate_tools = step.candidate_tools or (
            step.covered_by if step.status == "covered" else ()
        )
        for tool_name in candidate_tools:
            result = verification_by_name.get(tool_name)
            if result is not None and _is_security_scanner(result):
                return True
    return False


def _is_security_scanner(result: VerificationResult) -> bool:
    capabilities = {capability.lower() for capability in result.capabilities}
    return result.adapter in {"semgrep", "codeql"} or bool(
        capabilities
        & {
            "semgrep",
            "codeql",
            "taint-analysis",
            "dataflow-analysis",
            "command-injection",
            "sql-injection",
        }
    )


def _steps_by_finding(
    validation_plan: Iterable[ValidationStep],
) -> dict[str, tuple[ValidationStep, ...]]:
    grouped: dict[str, list[ValidationStep]] = {}
    for step in validation_plan:
        grouped.setdefault(step.finding_id, []).append(step)
    return {finding_id: tuple(steps) for finding_id, steps in grouped.items()}


def _clamp(value: float) -> float:
    return round(max(0.0, min(0.99, value)), 2)
