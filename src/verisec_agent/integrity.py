from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ArtifactSpec:
    label: str
    kind: str
    path: Path


class IntegrityError(RuntimeError):
    pass


def attest_artifact_index(
    *,
    index_path: Path,
    root_dir: Path | None = None,
    output_dir: Path | None = None,
    write_github_summary: bool = False,
) -> dict[str, Any]:
    if not index_path.exists():
        raise IntegrityError(f"Artifact index does not exist: {index_path}")
    index = json.loads(index_path.read_text(encoding="utf-8"))
    attestation_root = (root_dir or Path(str(index.get("root_dir", index_path.parent)))).resolve()
    artifacts = tuple(
        _attest_artifact(attestation_root, artifact)
        for artifact in index.get("artifacts", ())
    )
    failures = tuple(
        failure
        for artifact in artifacts
        for failure in artifact.get("failures", ())
    )
    result = {
        "passed": not failures,
        "checked_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "index_path": str(index_path.resolve()),
        "root_dir": str(attestation_root),
        "artifact_count": len(artifacts),
        "failure_count": len(failures),
        "artifacts": artifacts,
        "failures": failures,
    }
    markdown = render_attestation_markdown(result)
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "attestation.json").write_text(
            json.dumps(result, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        (output_dir / "attestation.md").write_text(markdown, encoding="utf-8")

    if write_github_summary:
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            with Path(summary_path).open("a", encoding="utf-8") as handle:
                handle.write(markdown)
                handle.write("\n")

    return result


def write_artifact_index(
    *,
    output_dir: Path,
    root_dir: Path,
    artifacts: tuple[ArtifactSpec, ...],
    manifest_path: Path | None = None,
    command_line: str | None = None,
    repo_path: Path | None = None,
) -> dict[str, Any]:
    index = build_artifact_index(
        root_dir=root_dir,
        artifacts=artifacts,
        manifest_path=manifest_path,
        command_line=command_line,
        repo_path=repo_path,
    )
    markdown = render_artifact_index_markdown(index)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "artifact_index.json").write_text(
        json.dumps(index, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (output_dir / "artifact_index.md").write_text(markdown, encoding="utf-8")
    return index


def render_attestation_markdown(result: dict[str, Any]) -> str:
    status = "passed" if result["passed"] else "failed"
    lines = [
        f"# VeriSec Attestation: {status}",
        "",
        f"- Index: `{result['index_path']}`",
        f"- Root: `{result['root_dir']}`",
        f"- Artifacts: {result['artifact_count']}",
        f"- Failures: {result['failure_count']}",
        "",
    ]
    if result["failures"]:
        lines.extend(["## Failures", ""])
        lines.extend(f"- {failure}" for failure in result["failures"])
        lines.append("")
    lines.extend(
        [
            "## Artifacts",
            "",
            "| Label | Kind | Path | Status | SHA-256 |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for artifact in result["artifacts"]:
        status = "passed" if artifact["passed"] else "failed"
        lines.append(
            "| "
            f"{artifact['label']} | "
            f"{artifact['kind']} | "
            f"`{artifact['path']}` | "
            f"{status} | "
            f"`{artifact.get('actual_sha256') or 'missing'}` |"
        )
    return "\n".join(lines).rstrip() + "\n"


def build_artifact_index(
    *,
    root_dir: Path,
    artifacts: tuple[ArtifactSpec, ...],
    manifest_path: Path | None = None,
    command_line: str | None = None,
    repo_path: Path | None = None,
) -> dict[str, Any]:
    if not artifacts:
        raise IntegrityError("Artifact index requires at least one artifact.")
    root_dir = root_dir.resolve()
    return {
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "command": command_line or "",
        "root_dir": str(root_dir),
        "manifest_path": str(manifest_path.resolve()) if manifest_path else None,
        "environment": _environment(repo_path or root_dir),
        "artifacts": tuple(_artifact_entry(root_dir, artifact) for artifact in artifacts),
    }


def render_artifact_index_markdown(index: dict[str, Any]) -> str:
    lines = [
        "# VeriSec Artifact Index",
        "",
        f"- Generated: {index['generated_at']}",
        f"- Command: `{index.get('command') or 'n/a'}`",
        f"- Root: `{index['root_dir']}`",
        f"- Manifest: `{index.get('manifest_path') or 'n/a'}`",
        "",
        "## Environment",
        "",
    ]
    for key, value in index.get("environment", {}).items():
        lines.append(f"- {key}: `{value}`")

    lines.extend(
        [
            "",
            "## Artifacts",
            "",
            "| Label | Kind | Path | Bytes | SHA-256 |",
            "| --- | --- | --- | ---: | --- |",
        ]
    )
    for artifact in index["artifacts"]:
        lines.append(
            "| "
            f"{artifact['label']} | "
            f"{artifact['kind']} | "
            f"`{artifact['path']}` | "
            f"{artifact['bytes']} | "
            f"`{artifact['sha256']}` |"
        )
    return "\n".join(lines).rstrip() + "\n"


def _attest_artifact(root_dir: Path, artifact: dict[str, Any]) -> dict[str, Any]:
    display_path = str(artifact.get("path", ""))
    path = _resolve_attestation_path(root_dir, artifact)
    failures: list[str] = []
    actual_sha = None
    actual_bytes = None
    if not path.exists():
        failures.append(f"{artifact.get('label', '?')} {artifact.get('kind', '?')} missing: {path}")
    else:
        data = path.read_bytes()
        actual_bytes = len(data)
        actual_sha = hashlib.sha256(data).hexdigest()
        expected_bytes = int(artifact.get("bytes", -1))
        expected_sha = str(artifact.get("sha256", ""))
        if actual_bytes != expected_bytes:
            failures.append(
                f"{artifact.get('label', '?')} {artifact.get('kind', '?')} byte size "
                f"changed from {expected_bytes} to {actual_bytes}: {display_path}"
            )
        if actual_sha != expected_sha:
            failures.append(
                f"{artifact.get('label', '?')} {artifact.get('kind', '?')} SHA-256 "
                f"changed from {expected_sha} to {actual_sha}: {display_path}"
            )
    return {
        "label": artifact.get("label", ""),
        "kind": artifact.get("kind", ""),
        "path": display_path,
        "resolved_path": str(path),
        "expected_bytes": artifact.get("bytes"),
        "actual_bytes": actual_bytes,
        "expected_sha256": artifact.get("sha256"),
        "actual_sha256": actual_sha,
        "passed": not failures,
        "failures": tuple(failures),
    }


def _resolve_attestation_path(root_dir: Path, artifact: dict[str, Any]) -> Path:
    raw_path = Path(str(artifact.get("path", "")))
    if raw_path.is_absolute():
        return raw_path
    return (root_dir / raw_path).resolve()


def _artifact_entry(root_dir: Path, artifact: ArtifactSpec) -> dict[str, Any]:
    path = artifact.path.resolve()
    if not path.exists():
        raise IntegrityError(f"Artifact does not exist: {path}")
    data = path.read_bytes()
    return {
        "label": artifact.label,
        "kind": artifact.kind,
        "path": _display_path(root_dir, path),
        "absolute_path": str(path),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _display_path(root_dir: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root_dir))
    except ValueError:
        return str(path)


def _environment(repo_path: Path) -> dict[str, Any]:
    return {
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "verisec_agent_version": _package_version(),
        "git_commit": _git(repo_path, "rev-parse", "HEAD"),
        "git_branch": _git(repo_path, "rev-parse", "--abbrev-ref", "HEAD"),
        "git_dirty": bool(_git(repo_path, "status", "--short")),
    }


def _package_version() -> str:
    try:
        return metadata.version("verisec-agent")
    except metadata.PackageNotFoundError:
        return "unknown"


def _git(repo_path: Path, *args: str) -> str:
    completed = subprocess.run(
        ("git", *args),
        cwd=repo_path,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        return "unknown"
    return completed.stdout.strip()
