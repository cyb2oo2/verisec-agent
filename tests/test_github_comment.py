import json
from pathlib import Path
from typing import Any

from pytest import MonkeyPatch, raises

from verisec_agent.github_comment import (
    GitHubCommentError,
    publish_pr_comment,
    resolve_github_context,
)
from verisec_agent.pr_comment import COMMENT_MARKER


class FakeCommentClient:
    def __init__(self, comments: list[dict[str, Any]] | None = None) -> None:
        self.comments = comments or []
        self.created: str | None = None
        self.updated: tuple[int, str] | None = None

    def list_comments(self) -> list[dict[str, Any]]:
        return self.comments

    def create_comment(self, body: str) -> dict[str, Any]:
        self.created = body
        return {"id": 10, "html_url": "https://github.test/comment/10"}

    def update_comment(self, comment_id: int, body: str) -> dict[str, Any]:
        self.updated = (comment_id, body)
        return {"id": comment_id, "html_url": f"https://github.test/comment/{comment_id}"}


def test_publish_pr_comment_updates_existing_marker_comment(tmp_path: Path) -> None:
    body_path = tmp_path / "comment.md"
    body_path.write_text(f"{COMMENT_MARKER}\nbody", encoding="utf-8")
    client = FakeCommentClient(
        comments=[
            {"id": 7, "body": "ordinary comment"},
            {"id": 9, "body": f"old\n{COMMENT_MARKER}"},
        ]
    )

    result = publish_pr_comment(
        body_path=body_path,
        repository="owner/repo",
        pr_number=123,
        token="token",
        client=client,
    )

    assert result["action"] == "updated"
    assert result["comment_id"] == 9
    assert client.updated == (9, f"{COMMENT_MARKER}\nbody")
    assert client.created is None


def test_publish_pr_comment_creates_when_marker_is_absent(tmp_path: Path) -> None:
    body_path = tmp_path / "comment.md"
    body_path.write_text(f"{COMMENT_MARKER}\nbody", encoding="utf-8")
    client = FakeCommentClient(comments=[{"id": 7, "body": "ordinary comment"}])

    result = publish_pr_comment(
        body_path=body_path,
        repository="owner/repo",
        pr_number=123,
        token="token",
        client=client,
    )

    assert result["action"] == "created"
    assert result["comment_id"] == 10
    assert client.created == f"{COMMENT_MARKER}\nbody"
    assert client.updated is None


def test_publish_pr_comment_requires_marker(tmp_path: Path) -> None:
    body_path = tmp_path / "comment.md"
    body_path.write_text("body without marker", encoding="utf-8")

    with raises(GitHubCommentError, match="missing marker"):
        publish_pr_comment(
            body_path=body_path,
            repository="owner/repo",
            pr_number=123,
            token="token",
            client=FakeCommentClient(),
        )


def test_resolve_github_context_from_event_and_environment(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps({"pull_request": {"number": 321}}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setenv("GITHUB_API_URL", "https://github.enterprise/api/v3")

    context = resolve_github_context(event_path=event_path)

    assert context.repository == "owner/repo"
    assert context.pr_number == 321
    assert context.token == "token"
    assert context.api_url == "https://github.enterprise/api/v3"


def test_publish_pr_comment_skips_fork_pull_request(tmp_path: Path) -> None:
    body_path = tmp_path / "comment.md"
    body_path.write_text(f"{COMMENT_MARKER}\nbody", encoding="utf-8")
    event_path = tmp_path / "event.json"
    event_path.write_text(
        json.dumps(
            {
                "pull_request": {
                    "number": 123,
                    "head": {"repo": {"full_name": "fork/repo"}},
                }
            }
        ),
        encoding="utf-8",
    )
    client = FakeCommentClient()

    result = publish_pr_comment(
        body_path=body_path,
        repository="owner/repo",
        token="token",
        event_path=event_path,
        skip_forks=True,
        client=client,
    )

    assert result["action"] == "skipped"
    assert "fork/repo" in result["reason"]
    assert client.created is None
    assert client.updated is None
