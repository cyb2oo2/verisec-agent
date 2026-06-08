from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from verisec_agent.evaluation import _materialize_case, _safe_case_id, load_evaluation_cases


class ScannerExecutionError(RuntimeError):
    pass


DEFAULT_COMMANDS: dict[str, tuple[tuple[str, ...], ...]] = {
    "semgrep": (("{semgrep}", "scan", "--json", "--config", "p/security-audit", "."),),
    "codeql": (
        (
            "{codeql}",
            "database",
            "create",
            "{database}",
            "--language=python",
            "--build-mode=none",
            "--source-root",
            "{repo}",
            "--overwrite",
        ),
        (
            "{codeql}",
            "database",
            "analyze",
            "{database}",
            "python-security-extended.qls",
            "--format=sarifv2.1.0",
            "--output",
            "{artifact}",
        ),
    ),
}


def run_scanner_execution(
    *,
    cases_path: Path,
    output_dir: Path,
    adapter: str = "semgrep",
    label: str | None = None,
    command_argv: tuple[str, ...] | None = None,
    command_sequence: tuple[tuple[str, ...], ...] | None = None,
    timeout_seconds: int = 300,
    fail_fast: bool = False,
) -> dict[str, Any]:
    try:
        cases = load_evaluation_cases(cases_path)
    except Exception as exc:
        raise ScannerExecutionError(f"Failed to load evaluation cases: {exc}") from exc

    adapter_name = adapter.lower()
    sequence_template = _resolve_command_sequence(
        adapter=adapter_name,
        command_argv=command_argv,
        command_sequence=command_sequence,
    )
    if sequence_template is None:
        raise ScannerExecutionError(
            f"Scanner adapter '{adapter_name}' needs an explicit argv template."
        )
    source_sequence_template = sequence_template
    sequence_template = _resolve_tool_placeholders(sequence_template)

    output_dir.mkdir(parents=True, exist_ok=True)
    executable = sequence_template[0][0]
    executable_path = _which_executable(executable)
    executable_paths = _executable_paths(sequence_template)
    missing_executables = tuple(
        executable for executable, path in executable_paths.items() if path is None
    )
    cases_out: list[dict[str, Any]] = []

    if missing_executables:
        cases_out = [
            _skipped_case_result(
                case,
                adapter=adapter_name,
                missing_executables=missing_executables,
            )
            for case in cases
        ]
    else:
        for case in cases:
            try:
                case_output = output_dir / "cases" / _safe_case_id(case.case_id)
                materialized = _materialize_case(case=case, case_output=case_output)
                cases_out.append(
                    _run_case(
                        case=case,
                        materialized=materialized,
                        output_dir=output_dir,
                        adapter=adapter_name,
                        executable_path=str(executable_paths[executable]),
                        sequence_template=sequence_template,
                        timeout_seconds=timeout_seconds,
                    )
                )
            except Exception as exc:
                if fail_fast:
                    if isinstance(exc, ScannerExecutionError):
                        raise
                    raise ScannerExecutionError(str(exc)) from exc
                cases_out.append(
                    {
                        "id": case.case_id,
                        "case_id": case.case_id,
                        "status": "error",
                        "adapter": adapter_name,
                        "error": str(exc),
                    }
                )

    result = {
        "label": label or adapter_name,
        "adapter": adapter_name,
        "tool_name": adapter_name,
        "cases_path": str(cases_path),
        "output_dir": str(output_dir),
        "command_argv_template": sequence_template[0],
        "command_sequence_template": sequence_template,
        "command_source_sequence_template": source_sequence_template,
        "executable": executable,
        "executable_path": executable_path,
        "executables": executable_paths,
        "missing_executables": missing_executables,
        "summary": _summary(cases_out),
        "cases": cases_out,
    }
    manifest_path = output_dir / "scanner_results.json"
    manifest_path.write_text(
        json.dumps(result, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (output_dir / "scanner_results.md").write_text(
        render_scanner_execution_markdown(result),
        encoding="utf-8",
    )
    return result


def render_scanner_execution_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        f"# Scanner Execution: {result['label']}",
        "",
        "## Summary",
        "",
        f"- Adapter: `{result['adapter']}`",
        f"- Executable: `{result['executable']}`",
        f"- Executable path: `{result.get('executable_path') or 'missing'}`",
        f"- Command steps: {len(result.get('command_sequence_template', ()))}",
        f"- Cases: {summary['case_count']}",
        f"- Completed: {summary['completed_count']}",
        f"- Skipped: {summary['skipped_count']}",
        f"- Errors: {summary['error_count']}",
        "",
        "## Cases",
        "",
        "| Case | Status | Exit | Steps | Duration | Artifact |",
        "| --- | --- | ---: | ---: | ---: | --- |",
    ]
    for case in result["cases"]:
        exit_code = case.get("exit_code")
        steps = len(case.get("steps", ()))
        lines.append(
            "| "
            f"{case.get('case_id') or case.get('id')} | "
            f"{case.get('status')} | "
            f"{exit_code if exit_code is not None else 'n/a'} | "
            f"{steps} | "
            f"{float(case.get('duration_seconds', 0.0)):.2f} | "
            f"`{case.get('artifact', '') or '-'}` |"
        )
    return "\n".join(lines).rstrip() + "\n"


def _run_case(
    *,
    case: Any,
    materialized: dict[str, Any],
    output_dir: Path,
    adapter: str,
    executable_path: str,
    sequence_template: tuple[tuple[str, ...], ...],
    timeout_seconds: int,
) -> dict[str, Any]:
    safe_case = _safe_case_id(case.case_id)
    case_artifact_dir = output_dir / "artifacts" / safe_case
    case_artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = case_artifact_dir / _artifact_filename(adapter)
    repo_path = Path(str(materialized["repo_path"]))

    started = time.monotonic()
    steps: list[dict[str, Any]] = []
    final_stdout = ""
    final_exit_code: int | None = 0
    timed_out = False
    failed_step: dict[str, Any] | None = None

    for index, argv_template in enumerate(sequence_template, start=1):
        stdout_path = case_artifact_dir / f"step-{index:02d}.stdout.txt"
        stderr_path = case_artifact_dir / f"step-{index:02d}.stderr.txt"
        argv = _render_argv(
            argv_template,
            case_id=case.case_id,
            repo_path=repo_path,
            output_dir=case_artifact_dir,
            artifact_path=artifact_path,
        )
        step = _run_step(
            argv=argv,
            cwd=repo_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            timeout_seconds=timeout_seconds,
        )
        steps.append(step)
        final_stdout = stdout_path.read_text(encoding="utf-8", errors="replace")
        final_exit_code = step["exit_code"]
        timed_out = bool(step["timed_out"])
        if step["exit_code"] != 0 or step["timed_out"]:
            failed_step = step
            break
    duration = round(time.monotonic() - started, 4)

    if not artifact_path.exists():
        artifact_path.write_text(final_stdout, encoding="utf-8", errors="replace")

    status = "completed" if failed_step is None else "error"
    last_step = steps[-1] if steps else {}
    last_template = _step_template(sequence_template, last_step)
    result = {
        "id": case.case_id,
        "case_id": case.case_id,
        "status": status,
        "adapter": adapter,
        "tool_name": adapter,
        "artifact": _relative_to_output(output_dir, artifact_path),
        "stdout_path": last_step.get("stdout_path"),
        "stderr_path": last_step.get("stderr_path"),
        "command_argv": last_step.get("command_argv", ()),
        "command_argv_template": last_template,
        "command_sequence_template": sequence_template,
        "executable_path": executable_path,
        "exit_code": final_exit_code,
        "duration_seconds": duration,
        "timed_out": timed_out,
        "steps": tuple(steps),
        "repo_path": str(repo_path),
        "diff_path": str(materialized["diff_path"]),
        "materialized_from": materialized.get("source_kind"),
    }
    if status == "error":
        result["error"] = _execution_error(
            exit_code=final_exit_code,
            timed_out=timed_out,
            step_index=int(failed_step.get("index", 0)) if failed_step else None,
        )
    return result


def _run_step(
    *,
    argv: tuple[str, ...],
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    started = time.monotonic()
    timed_out = False
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            env=_scanner_environment(),
            timeout=timeout_seconds,
            check=False,
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = None
        stdout = _decode_timeout_output(exc.stdout)
        stderr = _decode_timeout_output(exc.stderr)
    duration = round(time.monotonic() - started, 4)
    stdout_path.write_text(stdout, encoding="utf-8", errors="replace")
    stderr_path.write_text(stderr, encoding="utf-8", errors="replace")
    return {
        "index": _step_index_from_path(stdout_path),
        "command_argv": argv,
        "exit_code": exit_code,
        "duration_seconds": duration,
        "timed_out": timed_out,
        "stdout_path": _relative_to_output(stdout_path.parents[2], stdout_path),
        "stderr_path": _relative_to_output(stderr_path.parents[2], stderr_path),
    }


def _skipped_case_result(
    case: Any,
    *,
    adapter: str,
    missing_executables: tuple[str, ...],
) -> dict[str, Any]:
    executable_list = ", ".join(missing_executables)
    return {
        "id": case.case_id,
        "case_id": case.case_id,
        "status": "skipped",
        "adapter": adapter,
        "tool_name": adapter,
        "skip_reason": f"Scanner executable(s) not found: {executable_list}",
        "missing_executables": missing_executables,
    }


def _resolve_command_sequence(
    *,
    adapter: str,
    command_argv: tuple[str, ...] | None,
    command_sequence: tuple[tuple[str, ...], ...] | None,
) -> tuple[tuple[str, ...], ...] | None:
    if command_argv and command_sequence:
        raise ScannerExecutionError("Use either command_argv or command_sequence, not both.")
    if command_sequence:
        _validate_command_sequence(command_sequence)
        return command_sequence
    if command_argv:
        _validate_command_sequence((command_argv,))
        return (command_argv,)
    return DEFAULT_COMMANDS.get(adapter)


def _validate_command_sequence(sequence: tuple[tuple[str, ...], ...]) -> None:
    if not sequence:
        raise ScannerExecutionError("Scanner command sequence cannot be empty.")
    for index, argv in enumerate(sequence, start=1):
        if not argv or not all(isinstance(part, str) and part for part in argv):
            raise ScannerExecutionError(f"Scanner command step {index} must be non-empty argv.")


def _executable_paths(sequence: tuple[tuple[str, ...], ...]) -> dict[str, str | None]:
    paths: dict[str, str | None] = {}
    for argv in sequence:
        executable = argv[0]
        if executable not in paths:
            paths[executable] = _which_executable(executable)
    return paths


def _which_executable(executable: str) -> str | None:
    path = Path(executable)
    if path.is_absolute() or "\\" in executable or "/" in executable:
        return str(path.resolve()) if path.exists() else None
    return shutil.which(executable)


def _resolve_tool_placeholders(
    sequence: tuple[tuple[str, ...], ...],
) -> tuple[tuple[str, ...], ...]:
    tool_paths = {
        "semgrep": _find_tool_executable("semgrep"),
        "codeql": _find_tool_executable("codeql"),
    }
    return tuple(
        tuple(_replace_tool_placeholders(part, tool_paths) for part in argv)
        for argv in sequence
    )


def _replace_tool_placeholders(part: str, tool_paths: dict[str, str | None]) -> str:
    rendered = part
    for tool, path in tool_paths.items():
        placeholder = "{" + tool + "}"
        if path and placeholder in rendered:
            rendered = rendered.replace(placeholder, path)
    return rendered


def _find_tool_executable(tool: str) -> str | None:
    env_value = os.environ.get(f"VERISEC_{tool.upper()}") or os.environ.get(tool.upper())
    if env_value:
        return env_value
    path_value = shutil.which(tool)
    if path_value:
        return path_value
    for candidate in _local_tool_candidates(tool):
        if candidate.exists():
            return str(candidate.resolve())
    return None


def _scanner_environment() -> dict[str, str]:
    env = os.environ.copy()
    path_parts = [
        str(candidate)
        for root in _project_roots()
        for candidate in (
            root / "tools" / "shims",
            root / ".venv" / "Scripts",
            root / ".venv" / "bin",
        )
        if candidate.exists()
    ]
    if path_parts:
        env["PATH"] = os.pathsep.join(path_parts + [env.get("PATH", "")])
    python_executable = _find_python_executable()
    if python_executable:
        env.setdefault(
            "CODEQL_EXTRACTOR_PYTHON_OPTION_PYTHON_EXECUTABLE_NAME",
            python_executable,
        )
    return env


def _find_python_executable() -> str | None:
    for root in _project_roots():
        for candidate in (
            root / ".venv" / "Scripts" / "python.exe",
            root / ".venv" / "bin" / "python",
        ):
            if candidate.exists():
                return str(candidate.resolve())
    return shutil.which("python")


def _local_tool_candidates(tool: str) -> tuple[Path, ...]:
    candidates: list[Path] = []
    for root in _project_roots():
        if tool == "semgrep":
            candidates.extend(
                (
                    root / ".venv" / "Scripts" / "semgrep.exe",
                    root / ".venv" / "Scripts" / "semgrep",
                    root / ".venv" / "bin" / "semgrep",
                )
            )
        elif tool == "codeql":
            candidates.extend(
                (
                    root / "tools" / "codeql" / "codeql.exe",
                    root / "tools" / "codeql" / "codeql",
                )
            )
            tools_dir = root / "tools"
            if tools_dir.exists():
                for bundle_dir in sorted(tools_dir.glob("codeql*")):
                    candidates.extend(
                        (
                            bundle_dir / "codeql" / "codeql.exe",
                            bundle_dir / "codeql" / "codeql",
                            bundle_dir / "codeql.exe",
                            bundle_dir / "codeql",
                        )
                    )
    return tuple(_dedupe_paths(candidates))


def _project_roots() -> tuple[Path, ...]:
    roots = [Path.cwd()]
    with suppress(IndexError):
        roots.append(Path(__file__).resolve().parents[2])
    return tuple(_dedupe_paths(roots))


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    deduped: list[Path] = []
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped


def _render_argv(
    argv_template: tuple[str, ...],
    *,
    case_id: str,
    repo_path: Path,
    output_dir: Path,
    artifact_path: Path,
) -> tuple[str, ...]:
    values = {
        "case_id": case_id,
        "repo": str(repo_path),
        "output": str(output_dir),
        "artifact": str(artifact_path),
        "database": str(output_dir / "codeql-db"),
    }
    return tuple(str(part).format(**values) for part in argv_template)


def _artifact_filename(adapter: str) -> str:
    if adapter in {"codeql", "sarif"}:
        return "scanner.sarif"
    return "scanner.json"


def _relative_to_output(output_dir: Path, path: Path) -> str:
    try:
        return str(path.relative_to(output_dir))
    except ValueError:
        return str(path)


def _decode_timeout_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _execution_error(
    *,
    exit_code: int | None,
    timed_out: bool,
    step_index: int | None = None,
) -> str:
    prefix = f"Scanner command step {step_index} " if step_index else "Scanner command "
    if timed_out:
        return f"{prefix}timed out."
    return f"{prefix}exited with code {exit_code}."


def _step_index_from_path(path: Path) -> int:
    try:
        return int(path.name.removeprefix("step-").split(".")[0])
    except (ValueError, IndexError):
        return 0


def _step_template(
    sequence_template: tuple[tuple[str, ...], ...],
    step: dict[str, Any],
) -> tuple[str, ...]:
    index = int(step.get("index") or len(sequence_template))
    if 1 <= index <= len(sequence_template):
        return sequence_template[index - 1]
    return sequence_template[-1]


def _summary(cases: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "case_count": len(cases),
        "completed_count": sum(1 for case in cases if case.get("status") == "completed"),
        "skipped_count": sum(1 for case in cases if case.get("status") == "skipped"),
        "error_count": sum(1 for case in cases if case.get("status") == "error"),
    }
