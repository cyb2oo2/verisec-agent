"""Built-in rule pack: general Python security rules + AST/dataflow analysis."""

from __future__ import annotations

from pathlib import Path

from verisec_agent.models import EvidenceWindow
from verisec_agent.python_semantics import (
    SemanticMatch,
    analyze_python_file,
    analyze_python_window,
)


class BuiltinRuleProvider:
    """Default pack containing core VeriSec rules and semantic analysis."""

    @property
    def pack_id(self) -> str:
        return "builtin"

    def rules(self) -> tuple:
        # Imported lazily so RULES can stay defined in hypotheses for now.
        from verisec_agent.hypotheses import BUILTIN_RULES

        return BUILTIN_RULES

    def analyze_window(self, window: EvidenceWindow) -> tuple[SemanticMatch, ...]:
        return analyze_python_window(window)

    def analyze_file(
        self,
        *,
        file_path: Path,
        changed_lines: set[int],
    ) -> tuple[SemanticMatch, ...]:
        return analyze_python_file(file_path=file_path, changed_lines=changed_lines)
