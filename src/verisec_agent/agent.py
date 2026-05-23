from __future__ import annotations

from pathlib import Path
from typing import Any

from verisec_agent.bundle import BundleWriter
from verisec_agent.config import ReviewConfig
from verisec_agent.diff_parser import evidence_windows, parse_unified_diff
from verisec_agent.hypotheses import generate_hypotheses
from verisec_agent.models import Finding, ReviewReport
from verisec_agent.tracing import TraceLog
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
        )
        trace.append("hypotheses.generated", "Generated security hypotheses", count=len(hypotheses))

        verifier = VerificationRunner(repo_path, output_dir, trace)
        verification = verifier.run_all(self.config.verification_commands)
        findings = tuple(_finding_from_hypothesis(hypothesis) for hypothesis in hypotheses)
        summary = _summarize(findings, verification)

        report = ReviewReport(
            subject=subject or diff_path.name,
            repo_path=str(repo_path),
            diff_path=str(copied_diff),
            findings=findings,
            verification=verification,
            bundle_path=str(output_dir),
            source=source_metadata,
            summary=summary,
        )
        bundle.write_report(report)
        trace.append("review.finish", "Finished VeriSec review", **summary)
        return report


def _finding_from_hypothesis(hypothesis) -> Finding:
    evidence = hypothesis.evidence
    return Finding(
        rule_id=hypothesis.rule_id,
        title=hypothesis.title,
        severity=hypothesis.severity,
        confidence=hypothesis.confidence,
        file_path=evidence.file_path,
        start_line=evidence.start_line,
        end_line=evidence.end_line,
        evidence=evidence.snippet(),
        risk=hypothesis.risk,
        fix_guidance=hypothesis.fix_guidance,
        recommended_validation=hypothesis.recommended_validation,
        false_positive_notes=hypothesis.false_positive_notes,
    )


def _summarize(findings, verification) -> dict[str, object]:
    required_failures = [
        result.name
        for result in verification
        if result.required and not result.passed
    ]
    severities: dict[str, int] = {}
    for finding in findings:
        severities[finding.severity] = severities.get(finding.severity, 0) + 1
    return {
        "finding_count": len(findings),
        "severity_counts": severities,
        "verification_count": len(verification),
        "verification_passed": sum(1 for result in verification if result.passed),
        "required_failures": required_failures,
    }
