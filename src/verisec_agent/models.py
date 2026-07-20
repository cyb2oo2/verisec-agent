from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]
ValidationStatus = Literal["covered", "missing"]
SourceContextRole = Literal["changed", "context"]
PolicyStatus = Literal["allowed", "blocked"]


@dataclass(frozen=True)
class ChangedLine:
    file_path: str
    old_line: int | None
    new_line: int | None
    content: str
    change_type: Literal["add", "delete", "context"]

    def location(self) -> str:
        line = self.new_line if self.new_line is not None else self.old_line
        return f"{self.file_path}:{line or 0}"


@dataclass(frozen=True)
class EvidenceWindow:
    file_path: str
    start_line: int
    end_line: int
    lines: tuple[ChangedLine, ...]
    rationale: str

    def snippet(self) -> str:
        rendered: list[str] = []
        for line in self.lines:
            marker = {"add": "+", "delete": "-", "context": " "}[line.change_type]
            number = line.new_line if line.new_line is not None else line.old_line
            rendered.append(f"{marker}{number or 0}: {line.content}")
        return "\n".join(rendered)


@dataclass(frozen=True)
class SourceContextLine:
    line_number: int
    content: str
    role: SourceContextRole = "context"


@dataclass(frozen=True)
class SourceContext:
    file_path: str
    start_line: int
    end_line: int
    available: bool
    rationale: str
    lines: tuple[SourceContextLine, ...] = ()

    def snippet(self) -> str:
        rendered: list[str] = []
        for line in self.lines:
            marker = ">" if line.role == "changed" else " "
            rendered.append(f"{marker}{line.line_number}: {line.content}")
        return "\n".join(rendered)


@dataclass(frozen=True)
class SecurityHypothesis:
    rule_id: str
    title: str
    severity: Severity
    confidence: float
    evidence: EvidenceWindow
    risk: str
    recommended_validation: tuple[str, ...] = ()
    fix_guidance: str = ""
    false_positive_notes: str = ""
    dataflow_steps: tuple[str, ...] = ()
    analysis_scope: str = ""
    analysis_notes: str = ""


@dataclass(frozen=True)
class VerificationCommand:
    name: str
    command: str
    timeout_seconds: int = 60
    required: bool = False
    adapter: str = "custom"
    description: str = ""
    capabilities: tuple[str, ...] = ()
    command_argv: tuple[str, ...] = ()


@dataclass(frozen=True)
class ToolFinding:
    tool_name: str
    adapter: str
    rule_id: str
    message: str
    file_path: str
    start_line: int
    end_line: int
    severity: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)

    def location(self) -> str:
        return f"{self.file_path}:{self.start_line}-{self.end_line}"


@dataclass(frozen=True)
class VerificationResult:
    name: str
    command: str
    command_template: str
    timeout_seconds: int
    required: bool
    adapter: str
    description: str
    capabilities: tuple[str, ...]
    exit_code: int | None
    duration_seconds: float
    timed_out: bool
    stdout_path: str | None
    stderr_path: str | None
    command_argv: tuple[str, ...] = ()
    command_argv_template: tuple[str, ...] = ()
    tool_findings: tuple[ToolFinding, ...] = ()
    artifact_paths: tuple[str, ...] = ()
    policy_status: PolicyStatus = "allowed"
    policy_reasons: tuple[str, ...] = ()
    policy_warnings: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return self.policy_status == "allowed" and self.exit_code == 0 and not self.timed_out


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: str
    title: str
    severity: Severity
    confidence: float
    file_path: str
    start_line: int
    end_line: int
    evidence: str
    source_context: SourceContext | None
    risk: str
    fix_guidance: str
    recommended_validation: tuple[str, ...]
    false_positive_notes: str
    base_confidence: float | None = None
    confidence_notes: str = ""
    dataflow_steps: tuple[str, ...] = ()
    analysis_scope: str = ""
    analysis_notes: str = ""


@dataclass(frozen=True)
class ValidationStep:
    finding_id: str
    objective: str
    recommended_check: str
    status: ValidationStatus
    covered_by: tuple[str, ...] = ()
    tool_evidence: tuple[str, ...] = ()
    candidate_tools: tuple[str, ...] = ()
    failure_boundary: str = ""


@dataclass(frozen=True)
class ReviewReport:
    subject: str
    repo_path: str
    diff_path: str
    findings: tuple[Finding, ...]
    verification: tuple[VerificationResult, ...]
    validation_plan: tuple[ValidationStep, ...]
    bundle_path: str
    source: dict[str, Any] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def write_json(self, path: Path) -> None:
        import json

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
