from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]


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


@dataclass(frozen=True)
class VerificationCommand:
    name: str
    command: str
    timeout_seconds: int = 60
    required: bool = False


@dataclass(frozen=True)
class VerificationResult:
    name: str
    command: str
    required: bool
    exit_code: int | None
    duration_seconds: float
    timed_out: bool
    stdout_path: str | None
    stderr_path: str | None

    @property
    def passed(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    confidence: float
    file_path: str
    start_line: int
    end_line: int
    evidence: str
    risk: str
    fix_guidance: str
    recommended_validation: tuple[str, ...]
    false_positive_notes: str


@dataclass(frozen=True)
class ReviewReport:
    subject: str
    repo_path: str
    diff_path: str
    findings: tuple[Finding, ...]
    verification: tuple[VerificationResult, ...]
    bundle_path: str
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def write_json(self, path: Path) -> None:
        import json

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
