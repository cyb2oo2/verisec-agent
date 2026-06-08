from __future__ import annotations

from pathlib import Path

from verisec_agent.models import EvidenceWindow, SourceContext, SourceContextLine


def load_source_context(
    *,
    repo_path: Path,
    evidence: EvidenceWindow,
    radius: int,
) -> SourceContext:
    repo_root = repo_path.resolve()
    target = (repo_root / evidence.file_path).resolve()
    if not _is_within_repo(repo_root, target):
        return SourceContext(
            file_path=evidence.file_path,
            start_line=evidence.start_line,
            end_line=evidence.end_line,
            available=False,
            rationale="Skipped because the diff path resolves outside the repository.",
        )
    if not target.exists():
        return SourceContext(
            file_path=evidence.file_path,
            start_line=evidence.start_line,
            end_line=evidence.end_line,
            available=False,
            rationale="Skipped because the changed file is not present in the repository.",
        )
    if not target.is_file():
        return SourceContext(
            file_path=evidence.file_path,
            start_line=evidence.start_line,
            end_line=evidence.end_line,
            available=False,
            rationale="Skipped because the changed path is not a regular file.",
        )

    try:
        source_lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return SourceContext(
            file_path=evidence.file_path,
            start_line=evidence.start_line,
            end_line=evidence.end_line,
            available=False,
            rationale=f"Skipped because the file could not be read: {exc}",
        )

    if not source_lines:
        return SourceContext(
            file_path=evidence.file_path,
            start_line=0,
            end_line=0,
            available=True,
            rationale="Changed file is empty in the repository checkout.",
        )

    changed_numbers = {
        line.new_line
        for line in evidence.lines
        if line.change_type == "add" and line.new_line is not None
    }
    start_line = max(1, evidence.start_line - radius)
    end_line = min(len(source_lines), evidence.end_line + radius)
    context_lines = tuple(
        SourceContextLine(
            line_number=line_number,
            content=source_lines[line_number - 1],
            role="changed" if line_number in changed_numbers else "context",
        )
        for line_number in range(start_line, end_line + 1)
    )
    return SourceContext(
        file_path=evidence.file_path,
        start_line=start_line,
        end_line=end_line,
        available=True,
        rationale="Repository source context around the changed line range.",
        lines=context_lines,
    )


def _is_within_repo(repo_root: Path, target: Path) -> bool:
    try:
        target.relative_to(repo_root)
    except ValueError:
        return False
    return True
