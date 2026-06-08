from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from verisec_agent.pr_comment import COMMENT_MARKER


class GitHubCommentError(RuntimeError):
    pass


class IssueCommentClient(Protocol):
    def list_comments(self) -> list[dict[str, Any]]:
        pass

    def create_comment(self, body: str) -> dict[str, Any]:
        pass

    def update_comment(self, comment_id: int, body: str) -> dict[str, Any]:
        pass


@dataclass(frozen=True)
class GitHubContext:
    repository: str
    pr_number: int
    api_url: str
    token: str | None = None
    event: dict[str, Any] | None = None


class GitHubIssueCommentClient:
    def __init__(self, context: GitHubContext) -> None:
        if not context.token:
            raise GitHubCommentError("GitHub token is required to publish a PR comment.")
        self.context = context

    def list_comments(self) -> list[dict[str, Any]]:
        comments: list[dict[str, Any]] = []
        page = 1
        while True:
            batch = self._request(
                "GET",
                f"/issues/{self.context.pr_number}/comments",
                query={"per_page": "100", "page": str(page)},
            )
            if not isinstance(batch, list):
                raise GitHubCommentError("GitHub comments response was not a list.")
            comments.extend(batch)
            if len(batch) < 100:
                return comments
            page += 1

    def create_comment(self, body: str) -> dict[str, Any]:
        response = self._request(
            "POST",
            f"/issues/{self.context.pr_number}/comments",
            payload={"body": body},
        )
        if not isinstance(response, dict):
            raise GitHubCommentError("GitHub create-comment response was not an object.")
        return response

    def update_comment(self, comment_id: int, body: str) -> dict[str, Any]:
        response = self._request(
            "PATCH",
            f"/issues/comments/{comment_id}",
            payload={"body": body},
        )
        if not isinstance(response, dict):
            raise GitHubCommentError("GitHub update-comment response was not an object.")
        return response

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        query: dict[str, str] | None = None,
    ) -> Any:
        url = _github_api_url(self.context, path, query=query)
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.context.token}",
                "Content-Type": "application/json",
                "User-Agent": "verisec-agent",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                response_body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            raise GitHubCommentError(
                f"GitHub API request failed with HTTP {exc.code}: {error_body}"
            ) from exc
        except urllib.error.URLError as exc:
            raise GitHubCommentError(f"GitHub API request failed: {exc}") from exc
        return json.loads(response_body) if response_body else {}


def publish_pr_comment(
    *,
    body_path: Path,
    repository: str | None = None,
    pr_number: int | None = None,
    token: str | None = None,
    api_url: str | None = None,
    event_path: Path | None = None,
    marker: str = COMMENT_MARKER,
    skip_forks: bool = False,
    dry_run: bool = False,
    client: IssueCommentClient | None = None,
) -> dict[str, Any]:
    if not body_path.exists():
        raise GitHubCommentError(f"PR comment body does not exist: {body_path}")
    body = body_path.read_text(encoding="utf-8")
    if marker not in body:
        raise GitHubCommentError(f"PR comment body is missing marker: {marker}")

    context = resolve_github_context(
        repository=repository,
        pr_number=pr_number,
        token=token,
        api_url=api_url,
        event_path=event_path,
    )
    skipped_reason = _skip_reason_for_fork(context, skip_forks=skip_forks)
    if skipped_reason:
        return _result("skipped", context, body_path, reason=skipped_reason)

    if dry_run:
        action = "update" if _find_marker_comment(_fixture_comments(client), marker) else "create"
        return _result("dry-run", context, body_path, planned_action=action)

    active_client = client or GitHubIssueCommentClient(context)
    existing = _find_marker_comment(active_client.list_comments(), marker)
    if existing is None:
        comment = active_client.create_comment(body)
        return _result("created", context, body_path, comment=comment)

    comment_id = int(existing["id"])
    comment = active_client.update_comment(comment_id, body)
    return _result("updated", context, body_path, comment=comment)


def resolve_github_context(
    *,
    repository: str | None = None,
    pr_number: int | None = None,
    token: str | None = None,
    api_url: str | None = None,
    event_path: Path | None = None,
) -> GitHubContext:
    event = _load_event(event_path)
    resolved_repository = repository or os.environ.get("GITHUB_REPOSITORY")
    resolved_pr_number = pr_number or _event_pr_number(event)
    resolved_api_url = api_url or os.environ.get("GITHUB_API_URL") or "https://api.github.com"
    resolved_token = token or os.environ.get("GITHUB_TOKEN")

    if not resolved_repository:
        raise GitHubCommentError("GitHub repository is required, for example owner/repo.")
    if resolved_pr_number is None:
        raise GitHubCommentError("GitHub PR number is required.")

    return GitHubContext(
        repository=resolved_repository,
        pr_number=resolved_pr_number,
        api_url=resolved_api_url,
        token=resolved_token,
        event=event,
    )


def _find_marker_comment(
    comments: list[dict[str, Any]],
    marker: str,
) -> dict[str, Any] | None:
    for comment in comments:
        if marker in str(comment.get("body", "")):
            return comment
    return None


def _load_event(event_path: Path | None) -> dict[str, Any] | None:
    resolved_event_path = event_path or _env_path("GITHUB_EVENT_PATH")
    if resolved_event_path is None or not resolved_event_path.exists():
        return None
    return json.loads(resolved_event_path.read_text(encoding="utf-8"))


def _event_pr_number(event: dict[str, Any] | None) -> int | None:
    if not event:
        return None
    pull_request = event.get("pull_request")
    if isinstance(pull_request, dict) and pull_request.get("number") is not None:
        return int(pull_request["number"])
    if event.get("number") is not None:
        return int(event["number"])
    return None


def _skip_reason_for_fork(context: GitHubContext, *, skip_forks: bool) -> str | None:
    if not skip_forks or context.event is None:
        return None
    pull_request = context.event.get("pull_request")
    if not isinstance(pull_request, dict):
        return None
    head = pull_request.get("head")
    head_repo = head.get("repo") if isinstance(head, dict) else None
    head_full_name = head_repo.get("full_name") if isinstance(head_repo, dict) else None
    if head_full_name and head_full_name != context.repository:
        return (
            "pull request comes from a fork; skipping privileged comment update "
            f"for {head_full_name}"
        )
    return None


def _fixture_comments(client: IssueCommentClient | None) -> list[dict[str, Any]]:
    if client is None:
        return []
    return client.list_comments()


def _result(
    action: str,
    context: GitHubContext,
    body_path: Path,
    *,
    comment: dict[str, Any] | None = None,
    reason: str | None = None,
    planned_action: str | None = None,
) -> dict[str, Any]:
    result = {
        "action": action,
        "repository": context.repository,
        "pr_number": context.pr_number,
        "body_path": str(body_path),
    }
    if comment is not None:
        result["comment_id"] = comment.get("id")
        result["comment_url"] = comment.get("html_url") or comment.get("url")
    if reason is not None:
        result["reason"] = reason
    if planned_action is not None:
        result["planned_action"] = planned_action
    return result


def _github_api_url(
    context: GitHubContext,
    path: str,
    *,
    query: dict[str, str] | None = None,
) -> str:
    owner_repo = "/".join(
        urllib.parse.quote(part, safe="") for part in context.repository.split("/", 1)
    )
    url = f"{context.api_url.rstrip('/')}/repos/{owner_repo}{path}"
    if query:
        url = f"{url}?{urllib.parse.urlencode(query)}"
    return url


def _env_path(name: str) -> Path | None:
    value = os.environ.get(name)
    return Path(value) if value else None
