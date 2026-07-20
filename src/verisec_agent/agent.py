from __future__ import annotations

from pathlib import Path
from typing import Any

from verisec_agent.bundle import BundleWriter
from verisec_agent.calibration import calibrate_findings
from verisec_agent.config import ReviewConfig
from verisec_agent.diff_parser import evidence_windows, parse_unified_diff
from verisec_agent.hypotheses import generate_hypotheses
from verisec_agent.models import Finding, ReviewReport
from verisec_agent.source_context import load_source_context
from verisec_agent.tracing import TraceLog
from verisec_agent.validation import build_validation_plan
from verisec_agent.verification import VerificationRunner


class ReviewAgent:
    def __init__(self, config: ReviewConfig) -> None:
        self.config = config

    def review(
        self,
        *,
        diff_path: Path,
        repo_path: Path,
        output_dir: Path,
        subject: str | None = None,
        source: dict[str, Any] | None = None,
    ) -> ReviewReport:
        bundle = BundleWriter(output_dir)
        bundle.prepare()
        trace = TraceLog(output_dir / "trace.jsonl")
        source_metadata = source or {
            "kind": "file",
            "path": str(diff_path),
        }
        trace.append(
            "review.start",
            "Starting VeriSec review",
            subject=subject or diff_path.name,
            diff_path=str(diff_path),
            repo_path=str(repo_path),
            source=source_metadata,
        )

        copied_diff = bundle.copy_diff(diff_path)
        bundle.write_source_metadata(source_metadata)
        diff_text = diff_path.read_text(encoding="utf-8")
        changed_lines = parse_unified_diff(diff_text)
        trace.append("diff.parsed", "Parsed unified diff", changed_lines=len(changed_lines))

        windows = evidence_windows(changed_lines, max_lines=self.config.max_evidence_lines)
        trace.append("evidence.localized", "Localized evidence windows", windows=len(windows))

        hypotheses = generate_hypotheses(
            windows,
            min_confidence=self.config.min_confidence,
            repo_path=repo_path,
            rule_packs=self.config.rule_packs,
        )
        trace.append("hypotheses.generated", "Generated security hypotheses", count=len(hypotheses))

        verifier = VerificationRunner(repo_path, output_dir, trace, policy=self.config.policy)
        verification = verifier.run_all(self.config.verification_commands)
        findings = tuple(
            _finding_from_hypothesis(
                hypothesis,
                repo_path=repo_path,
                source_context_lines=self.config.source_context_lines,
            )
            for hypothesis in hypotheses
        )
        trace.append(
            "context.expanded",
            "Expanded repository source context",
            available=sum(
                1
                for finding in findings
                if finding.source_context is not None and finding.source_context.available
            ),
            total=len(findings),
        )
        validation_plan = build_validation_plan(findings, verification)
        findings = calibrate_findings(findings, validation_plan, verification)
        trace.append(
            "validation.planned",
            "Planned validation steps for findings",
            steps=len(validation_plan),
            covered=sum(1 for step in validation_plan if step.status == "covered"),
        )
        trace.append(
            "confidence.calibrated",
            "Calibrated finding confidence from validation coverage",
            findings=len(findings),
            with_notes=sum(1 for finding in findings if finding.confidence_notes),
        )
        summary = _summarize(findings, verification, validation_plan)

        report = ReviewReport(
            subject=subject or diff_path.name,
            repo_path=str(repo_path),
            diff_path=str(copied_diff),
            findings=findings,
            verification=verification,
            validation_plan=validation_plan,
            bundle_path=str(output_dir),
            source=source_metadata,
            summary=summary,
        )
        bundle.write_report(report)
        trace.append("review.finish", "Finished VeriSec review", **summary)
        return report


def _finding_from_hypothesis(
    hypothesis,
    *,
    repo_path: Path,
    source_context_lines: int,
) -> Finding:
    evidence = hypothesis.evidence
    finding_id = (
        f"{hypothesis.rule_id}@"
        f"{evidence.file_path}:{evidence.start_line}-{evidence.end_line}"
    )
    source_context = load_source_context(
        repo_path=repo_path,
        evidence=evidence,
        radius=source_context_lines,
    )
    return Finding(
        finding_id=finding_id,
        rule_id=hypothesis.rule_id,
        title=hypothesis.title,
        severity=hypothesis.severity,
        confidence=hypothesis.confidence,
        file_path=evidence.file_path,
        start_line=evidence.start_line,
        end_line=evidence.end_line,
        evidence=evidence.snippet(),
        source_context=source_context,
        risk=hypothesis.risk,
        fix_guidance=hypothesis.fix_guidance,
        recommended_validation=hypothesis.recommended_validation,
        false_positive_notes=hypothesis.false_positive_notes,
        dataflow_steps=hypothesis.dataflow_steps,
        analysis_scope=hypothesis.analysis_scope,
        analysis_notes=hypothesis.analysis_notes,
    )


def _summarize(findings, verification, validation_plan) -> dict[str, object]:
    required_failures = [
        result.name
        for result in verification
        if result.required and not result.passed
    ]
    severities: dict[str, int] = {}
    for finding in findings:
        severities[finding.severity] = severities.get(finding.severity, 0) + 1
    tool_finding_count = sum(len(result.tool_findings) for result in verification)
    tool_artifact_count = sum(len(result.artifact_paths) for result in verification)
    policy_blocked_count = sum(
        1 for result in verification if result.policy_status == "blocked"
    )
    policy_warning_count = sum(len(result.policy_warnings) for result in verification)
    return {
        "finding_count": len(findings),
        "severity_counts": severities,
        "avg_confidence": _average_confidence(findings),
        "tool_supported_findings": sum(
            1
            for finding in findings
            if "Matched structured tool evidence" in finding.confidence_notes
        ),
        "validation_gap_findings": sum(
            1
            for finding in findings
            if "recommended validation check(s) are still missing"
            in finding.confidence_notes
        ),
        "scanner_dampened_findings": sum(
            1
            for finding in findings
            if "did not emit a matching finding" in finding.confidence_notes
        ),
        "tool_artifact_count": tool_artifact_count,
        "policy_blocked_count": policy_blocked_count,
        "policy_warning_count": policy_warning_count,
        "verification_count": len(verification),
        "verification_passed": sum(1 for result in verification if result.passed),
        "required_failures": required_failures,
        "validation_step_count": len(validation_plan),
        "validation_covered": sum(
            1 for step in validation_plan if step.status == "covered"
        ),
        "validation_missing": sum(
            1 for step in validation_plan if step.status == "missing"
        ),
        "tool_finding_count": tool_finding_count,
        "validation_with_tool_evidence": sum(
            1 for step in validation_plan if step.tool_evidence
        ),
    }


def _average_confidence(findings) -> float:
    if not findings:
        return 0.0
    return round(sum(finding.confidence for finding in findings) / len(findings), 2)
