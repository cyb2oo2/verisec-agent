from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from verisec_agent.models import VerificationCommand
from verisec_agent.tracing import TraceLog
from verisec_agent.verification import VerificationRunner


class ReplayError(RuntimeError):
    pass


def replay_bundle(
    *,
    bundle_path: Path,
    repo_path: Path,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    report_path = bundle_path / "report.json"
    if not report_path.exists():
        raise ReplayError(f"Bundle report does not exist: {report_path}")

    report = json.loads(report_path.read_text(encoding="utf-8"))
    commands = _commands_from_report(report)
    if not commands:
        raise ReplayError(f"Bundle does not contain verification commands: {report_path}")

    target_dir = output_dir or bundle_path / "replay"
    target_dir.mkdir(parents=True, exist_ok=True)
    trace = TraceLog(target_dir / "trace.jsonl")
    trace.append(
        "replay.start",
        "Starting VeriSec verification replay",
        source_bundle=str(bundle_path),
        repo_path=str(repo_path),
        commands=len(commands),
    )

    runner = VerificationRunner(repo_path, target_dir, trace)
    verification = runner.run_all(commands)
    summary = {
        "source_bundle": str(bundle_path),
        "subject": report.get("subject"),
        "repo_path": str(repo_path),
        "replayed_at": datetime.now(UTC).isoformat(),
        "verification_count": len(verification),
        "verification_passed": sum(1 for result in verification if result.passed),
        "required_failures": [
            result.name for result in verification if result.required and not result.passed
        ],
        "verification": [asdict(result) for result in verification],
    }
    (target_dir / "replay.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    trace.append("replay.finish", "Finished VeriSec verification replay", **summary)
    return summary


def _commands_from_report(report: dict[str, Any]) -> tuple[VerificationCommand, ...]:
    commands: list[VerificationCommand] = []
    for item in report.get("verification", []):
        commands.append(
            VerificationCommand(
                name=item["name"],
                command=item.get("command_template", item["command"]),
                timeout_seconds=int(item.get("timeout_seconds", 60)),
                required=bool(item.get("required", False)),
                adapter=str(item.get("adapter", "custom")),
                description=str(item.get("description", "")),
                capabilities=tuple(str(value) for value in item.get("capabilities", ())),
                command_argv=tuple(
                    str(value) for value in item.get("command_argv_template", ())
                ),
            )
        )
    return tuple(commands)
