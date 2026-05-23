from __future__ import annotations

import re
from collections.abc import Iterable

from verisec_agent.models import ChangedLine, EvidenceWindow

FILE_HEADER_RE = re.compile(r"^\+\+\+ b/(.+)$")
HUNK_RE = re.compile(r"^@@ -(?P<old>\d+)(?:,\d+)? \+(?P<new>\d+)(?:,\d+)? @@")


def parse_unified_diff(diff_text: str) -> tuple[ChangedLine, ...]:
    current_file = ""
    old_line: int | None = None
    new_line: int | None = None
    changed: list[ChangedLine] = []

    for raw_line in diff_text.splitlines():
        file_match = FILE_HEADER_RE.match(raw_line)
        if file_match:
            current_file = file_match.group(1)
            continue

        hunk_match = HUNK_RE.match(raw_line)
        if hunk_match:
            old_line = int(hunk_match.group("old"))
            new_line = int(hunk_match.group("new"))
            continue

        if not current_file or old_line is None or new_line is None:
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            changed.append(
                ChangedLine(current_file, None, new_line, raw_line[1:], change_type="add")
            )
            new_line += 1
        elif raw_line.startswith("-") and not raw_line.startswith("---"):
            changed.append(
                ChangedLine(current_file, old_line, None, raw_line[1:], change_type="delete")
            )
            old_line += 1
        elif raw_line.startswith(" "):
            changed.append(
                ChangedLine(current_file, old_line, new_line, raw_line[1:], change_type="context")
            )
            old_line += 1
            new_line += 1

    return tuple(changed)


def evidence_windows(
    lines: Iterable[ChangedLine],
    *,
    max_lines: int = 12,
) -> tuple[EvidenceWindow, ...]:
    additions = [line for line in lines if line.change_type == "add"]
    windows: list[EvidenceWindow] = []

    for line in additions:
        line_number = line.new_line or 0
        start = max(1, line_number - max_lines // 2)
        end = line_number + max_lines // 2
        same_file = [
            candidate
            for candidate in lines
            if candidate.file_path == line.file_path
            and _line_number(candidate) is not None
            and start <= (_line_number(candidate) or 0) <= end
        ]
        windows.append(
            EvidenceWindow(
                file_path=line.file_path,
                start_line=start,
                end_line=end,
                lines=tuple(same_file[:max_lines]),
                rationale="Changed code near a security-relevant addition.",
            )
        )

    return tuple(windows)


def _line_number(line: ChangedLine) -> int | None:
    return line.new_line if line.new_line is not None else line.old_line
