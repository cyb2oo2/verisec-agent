from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class ResolvedDiffInput:
    diff_path: Path
    subject: str
    source: dict[str, Any]


class DiffInputError(RuntimeError):
    pass


Runner = Callable[..., subprocess.CompletedProcess[str]]


def resolve_diff_input(
    *,
    diff_path: Path | None,
    pr: str | None,
    diff_url: str | None,
    github_repo: str | None,
    output_dir: Path,
    runner: Runner = subprocess.run,
) -> ResolvedDiffInput:
    choices = [diff_path is not None, pr is not None, diff_url is not None]
    if sum(choices) != 1:
        raise DiffInputError("Provide exactly one diff source: --diff, --pr, or --diff-url.")

    if diff_path is not None:
        resolved = diff_path.resolve()
        if not resolved.exists():
            raise DiffInputError(f"Diff file does not exist: {resolved}")
        return ResolvedDiffInput(
            diff_path=resolved,
            subject=resolved.name,
            source={"kind": "file", "path": str(resolved)},
        )

    scratch_dir = output_dir / "_source"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    if pr is not None:
        target = scratch_dir / "github-pr.diff"
        diff_text = fetch_github_pr_diff(pr=pr, github_repo=github_repo, runner=runner)
        target.write_text(diff_text, encoding="utf-8")
        return ResolvedDiffInput(
            diff_path=target,
            subject=f"pr-{pr}",
            source={
                "kind": "github_pr",
                "selector": pr,
                "github_repo": github_repo,
                "resolved_diff": str(target),
            },
        )

    assert diff_url is not None
    target = scratch_dir / "remote.diff"
    diff_text = fetch_url_diff(diff_url)
    target.write_text(diff_text, encoding="utf-8")
    return ResolvedDiffInput(
        diff_path=target,
        subject=diff_url.rsplit("/", 1)[-1] or "remote-diff",
        source={"kind": "url", "url": diff_url, "resolved_diff": str(target)},
    )


def fetch_github_pr_diff(
    *,
    pr: str,
    github_repo: str | None,
    runner: Runner = subprocess.run,
) -> str:
    command = ["gh", "pr", "diff", pr, "--patch", "--color", "never"]
    if github_repo:
        command.extend(["--repo", github_repo])

    completed = runner(
        command,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise DiffInputError(
            "gh pr diff failed"
            f" for {pr}: {(completed.stderr or completed.stdout or '').strip()}"
        )
    if not completed.stdout.strip():
        raise DiffInputError(f"gh pr diff returned an empty diff for {pr}")
    return completed.stdout


def fetch_url_diff(diff_url: str) -> str:
    request = Request(diff_url, headers={"User-Agent": "verisec-agent/0.1"})
    with urlopen(request, timeout=30) as response:
        raw = response.read()
    text = raw.decode("utf-8")
    if not text.strip():
        raise DiffInputError(f"URL returned an empty diff: {diff_url}")
    return text
