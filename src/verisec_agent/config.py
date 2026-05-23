from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from verisec_agent.models import VerificationCommand


@dataclass(frozen=True)
class ReviewConfig:
    max_evidence_lines: int = 12
    min_confidence: float = 0.35
    verification_commands: tuple[VerificationCommand, ...] = ()


def load_config(path: Path | None) -> ReviewConfig:
    if path is None or not path.exists():
        return ReviewConfig()

    data = tomllib.loads(path.read_text(encoding="utf-8"))
    review = data.get("review", {})
    verification = data.get("verification", {})
    commands = tuple(
        VerificationCommand(
            name=item["name"],
            command=item["command"],
            timeout_seconds=int(item.get("timeout_seconds", 60)),
            required=bool(item.get("required", False)),
        )
        for item in verification.get("commands", [])
    )
    return ReviewConfig(
        max_evidence_lines=int(review.get("max_evidence_lines", 12)),
        min_confidence=float(review.get("min_confidence", 0.35)),
        verification_commands=commands,
    )
