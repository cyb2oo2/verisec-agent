from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from verisec_agent.inputs import DiffInputError, resolve_diff_input


def test_resolve_local_diff_input(tmp_path: Path) -> None:
    diff_path = tmp_path / "change.diff"
    diff_path.write_text("diff --git a/a.py b/a.py\n", encoding="utf-8")

    resolved = resolve_diff_input(
        diff_path=diff_path,
        pr=None,
        diff_url=None,
        github_repo=None,
        output_dir=tmp_path / "out",
    )

    assert resolved.diff_path == diff_path.resolve()
    assert resolved.subject == "change.diff"
    assert resolved.source["kind"] == "file"


def test_resolve_github_pr_diff_uses_gh(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def fake_runner(command, **kwargs):
        calls.append(command)
        assert kwargs["text"] is True
        assert kwargs["capture_output"] is True
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="diff --git a/a.py b/a.py\n",
            stderr="",
        )

    resolved = resolve_diff_input(
        diff_path=None,
        pr="123",
        diff_url=None,
        github_repo="owner/repo",
        output_dir=tmp_path / "out",
        runner=fake_runner,
    )

    assert calls == [
        ["gh", "pr", "diff", "123", "--patch", "--color", "never", "--repo", "owner/repo"]
    ]
    assert resolved.diff_path.read_text(encoding="utf-8").startswith("diff --git")
    assert resolved.subject == "pr-123"
    assert resolved.source["kind"] == "github_pr"


def test_resolve_diff_input_requires_exactly_one_source(tmp_path: Path) -> None:
    with pytest.raises(DiffInputError):
        resolve_diff_input(
            diff_path=None,
            pr=None,
            diff_url=None,
            github_repo=None,
            output_dir=tmp_path,
        )
