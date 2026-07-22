from __future__ import annotations

import ctypes
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from verisec_agent.models import VerificationCommand, VerificationResult
from verisec_agent.policy import ReviewPolicy, evaluate_verification_command
from verisec_agent.tool_output import parse_tool_output
from verisec_agent.tracing import TraceLog


@dataclass(frozen=True)
class _RenderedInvocation:
    command: str
    argv: tuple[str, ...]
    argv_template: tuple[str, ...]


class VerificationRunner:
    def __init__(
        self,
        repo_path: Path,
        output_dir: Path,
        trace: TraceLog,
        policy: ReviewPolicy | None = None,
    ) -> None:
        self.repo_path = repo_path
        self.output_dir = output_dir
        self.trace = trace
        self.policy = policy or ReviewPolicy()

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
        try:
            invocation = _render_invocation(command, tool_dir=tool_dir)
            render_error = ""
        except ValueError as exc:
            invocation = _RenderedInvocation(
                command=command.command,
                argv=(),
                argv_template=command.command_argv,
            )
            render_error = str(exc)
        policy_decision = evaluate_verification_command(
            command,
            self.policy,
            rendered_command=invocation.command,
            rendered_argv=invocation.argv,
        )
        policy_reasons = policy_decision.reasons
        if render_error:
            policy_reasons = (*policy_reasons, render_error)
        policy_status = "blocked" if policy_reasons else policy_decision.status
        if policy_decision.warnings:
            self.trace.append(
                "tool.policy_warning",
                f"Policy warnings for verification command {command.name}",
                tool=command.name,
                adapter=command.adapter,
                execution_profile=self.policy.execution_profile,
                warnings=policy_decision.warnings,
            )
        if policy_reasons:
            stderr = _policy_block_message(policy_reasons)
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text(stderr, encoding="utf-8")
            self.trace.append(
                "tool.policy_blocked",
                f"Blocked verification command {command.name}",
                command=invocation.command,
                argv=invocation.argv,
                adapter=command.adapter,
                execution_profile=self.policy.execution_profile,
                reasons=policy_reasons,
                warnings=policy_decision.warnings,
            )
            return VerificationResult(
                name=command.name,
                command=invocation.command,
                command_template=command.command,
                timeout_seconds=command.timeout_seconds,
                required=command.required,
                adapter=command.adapter,
                description=command.description,
                capabilities=command.capabilities,
                exit_code=None,
                duration_seconds=0.0,
                timed_out=False,
                stdout_path=str(stdout_path),
                stderr_path=str(stderr_path),
                command_argv=invocation.argv,
                command_argv_template=invocation.argv_template,
                policy_status=policy_status,
                policy_reasons=policy_reasons,
                policy_warnings=policy_decision.warnings,
            )

        self.trace.append(
            "tool.start",
            f"Running verification command {command.name}",
            command=invocation.command,
            argv=invocation.argv,
            adapter=command.adapter,
            capabilities=command.capabilities,
            timeout_seconds=command.timeout_seconds,
            required=command.required,
            execution_profile=self.policy.execution_profile,
            environment_mode=self.policy.environment_mode,
            network_access=self.policy.network_access,
        )

        start = time.perf_counter()
        try:
            completed = subprocess.run(
                invocation.argv,
                cwd=self.repo_path,
                shell=False,
                text=True,
                capture_output=True,
                timeout=command.timeout_seconds,
                check=False,
                env=_verification_environment(self.policy),
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
        except OSError as exc:
            timed_out = False
            exit_code = None
            stdout = ""
            stderr = f"Failed to start verification command: {exc}\n"

        duration = time.perf_counter() - start
        stdout = _limit_output(stdout or "", max_bytes=self.policy.max_output_bytes)
        stderr = _limit_output(stderr or "", max_bytes=self.policy.max_output_bytes)
        stdout_path.write_text(stdout or "", encoding="utf-8")
        stderr_path.write_text(stderr or "", encoding="utf-8")
        parsed_output = parse_tool_output(
            adapter=command.adapter,
            tool_name=command.name,
            stdout=stdout or "",
            tool_dir=tool_dir,
        )

        result = VerificationResult(
            name=command.name,
            command=invocation.command,
            command_template=command.command,
            timeout_seconds=command.timeout_seconds,
            required=command.required,
            adapter=command.adapter,
            description=command.description,
            capabilities=command.capabilities,
            exit_code=exit_code,
            duration_seconds=round(duration, 3),
            timed_out=timed_out,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            command_argv=invocation.argv,
            command_argv_template=invocation.argv_template,
            tool_findings=parsed_output.findings,
            artifact_paths=tuple(str(path) for path in parsed_output.artifact_paths),
            policy_status=policy_decision.status,
            policy_reasons=policy_decision.reasons,
            policy_warnings=policy_decision.warnings,
        )
        if parsed_output.findings:
            self.trace.append(
                "tool.findings",
                f"Parsed {len(parsed_output.findings)} finding(s) from {command.name}",
                tool=command.name,
                adapter=command.adapter,
                findings=len(parsed_output.findings),
            )
        if parsed_output.artifact_paths:
            self.trace.append(
                "tool.artifacts",
                f"Captured {len(parsed_output.artifact_paths)} artifact(s) from {command.name}",
                tool=command.name,
                adapter=command.adapter,
                artifacts=[str(path) for path in parsed_output.artifact_paths],
            )
        self.trace.append(
            "tool.finish",
            f"Verification command {command.name} finished",
            exit_code=exit_code,
            timed_out=timed_out,
            duration_seconds=result.duration_seconds,
        )
        return result


def _policy_block_message(reasons: tuple[str, ...]) -> str:
    lines = ["Blocked by VeriSec verification policy:"]
    lines.extend(f"- {reason}" for reason in reasons)
    return "\n".join(lines) + "\n"


def _render_invocation(command: VerificationCommand, *, tool_dir: Path) -> _RenderedInvocation:
    substitutions = {
        "python": sys.executable,
        "tool_dir": str(tool_dir),
    }
    if command.command_argv:
        argv_template = command.command_argv
        argv = tuple(_expand_placeholders(arg, substitutions) for arg in command.command_argv)
    else:
        rendered_command = _expand_placeholders(command.command, substitutions)
        argv_template = _split_command_line(command.command)
        argv = _split_command_line(rendered_command)
    if not argv:
        raise ValueError("verification command rendered to an empty argv")
    return _RenderedInvocation(
        command=_display_command(argv),
        argv=argv,
        argv_template=argv_template,
    )


_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_placeholders(text: str, substitutions: dict[str, str]) -> str:
    # Expand only the named `{placeholder}` tokens we define; leave every other brace
    # untouched. str.format would treat an unrelated `{1,36}` regex quantifier or JSON
    # literal in a `-c` script as a field reference and crash (T-010).
    def _replace(match: re.Match[str]) -> str:
        return substitutions.get(match.group(1), match.group(0))

    return _PLACEHOLDER_RE.sub(_replace, text)


def _split_command_line(command: str) -> tuple[str, ...]:
    if not command.strip():
        return ()
    if os.name == "nt":
        return _windows_command_line_to_argv(command)
    return tuple(shlex.split(command, posix=True))


def _windows_command_line_to_argv(command: str) -> tuple[str, ...]:
    argc = ctypes.c_int()
    shell32 = ctypes.windll.shell32
    kernel32 = ctypes.windll.kernel32
    shell32.CommandLineToArgvW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
    shell32.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    argv_pointer = shell32.CommandLineToArgvW(command, ctypes.byref(argc))
    if not argv_pointer:
        raise ValueError("Windows CommandLineToArgvW failed")
    try:
        return tuple(argv_pointer[index] for index in range(argc.value))
    finally:
        kernel32.LocalFree(argv_pointer)


def _display_command(argv: tuple[str, ...]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(argv)
    return shlex.join(argv)


def _verification_environment(policy: ReviewPolicy) -> dict[str, str] | None:
    if policy.environment_mode == "inherit":
        env = dict(os.environ)
    else:
        keep = {
            "ALLUSERSPROFILE",
            "APPDATA",
            "HOME",
            "HOMEDRIVE",
            "HOMEPATH",
            "LOCALAPPDATA",
            "PATH",
            "PATHEXT",
            "PROGRAMDATA",
            "PROGRAMFILES",
            "PROGRAMFILES(X86)",
            "SYSTEMDRIVE",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "WINDIR",
        }
        env = {key: value for key, value in os.environ.items() if key.upper() in keep}
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    if policy.network_access == "disabled":
        env["VERISEC_NETWORK"] = "disabled"
        env["NO_PROXY"] = "*"
        env["HTTP_PROXY"] = ""
        env["HTTPS_PROXY"] = ""
    return env


def _limit_output(value: str, *, max_bytes: int) -> str:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return value
    truncated = encoded[:max_bytes].decode("utf-8", errors="replace")
    return (
        truncated
        + f"\n[verisec: truncated tool output to {max_bytes} bytes]\n"
    )
