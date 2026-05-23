from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

from verisec_agent.models import VerificationCommand, VerificationResult
from verisec_agent.tracing import TraceLog


class VerificationRunner:
    def __init__(self, repo_path: Path, output_dir: Path, trace: TraceLog) -> None:
        self.repo_path = repo_path
        self.output_dir = output_dir
        self.trace = trace

    def run_all(self, commands: tuple[VerificationCommand, ...]) -> tuple[VerificationResult, ...]:
        results: list[VerificationResult] = []
        for command in commands:
            results.append(self.run(command))
        return tuple(results)

    def run(self, command: VerificationCommand) -> VerificationResult:
        tool_dir = self.output_dir / "tools"
        tool_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = tool_dir / f"{command.name}.stdout.txt"
        stderr_path = tool_dir / f"{command.name}.stderr.txt"
        rendered_command = command.command.format(python=sys.executable)

        self.trace.append(
            "tool.start",
            f"Running verification command {command.name}",
            command=rendered_command,
            timeout_seconds=command.timeout_seconds,
            required=command.required,
        )

        start = time.perf_counter()
        try:
            completed = subprocess.run(
                rendered_command,
                cwd=self.repo_path,
                shell=True,
                text=True,
                capture_output=True,
                timeout=command.timeout_seconds,
                check=False,
            )
            timed_out = False
            exit_code: int | None = completed.returncode
            stdout = completed.stdout
            stderr = completed.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            exit_code = None
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""

        duration = time.perf_counter() - start
        stdout_path.write_text(stdout or "", encoding="utf-8")
        stderr_path.write_text(stderr or "", encoding="utf-8")

        result = VerificationResult(
            name=command.name,
            command=rendered_command,
            required=command.required,
            exit_code=exit_code,
            duration_seconds=round(duration, 3),
            timed_out=timed_out,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        )
        self.trace.append(
            "tool.finish",
            f"Verification command {command.name} finished",
            exit_code=exit_code,
            timed_out=timed_out,
            duration_seconds=result.duration_seconds,
        )
        return result
