from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from verisec_agent.agent import ReviewAgent
from verisec_agent.config import load_config
from verisec_agent.inputs import fetch_url_diff


@dataclass(frozen=True)
class ExpectedFinding:
    rule_id: str
    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    severity: str | None = None
    role: str = "primary"
    notes: str = ""


@dataclass(frozen=True)
class EvaluationCase:
    case_id: str
    diff_path: Path | None
    repo_path: Path | None
    diff_url: str | None = None
    repo_url: str | None = None
    base_ref: str | None = None
    head_ref: str | None = None
    config_path: Path | None = None
    expected_rules: tuple[str, ...] = ()
    expected_findings: tuple[ExpectedFinding, ...] = ()
    tags: tuple[str, ...] = ()
    metadata: dict[str, Any] | None = None


class EvaluationError(RuntimeError):
    pass


def run_evaluation(
    *,
    cases_path: Path,
    output_dir: Path,
    default_config_path: Path | None = None,
    fail_fast: bool = False,
    policy_profile: str | None = None,
    resume: bool = False,
) -> dict[str, Any]:
    cases = load_evaluation_cases(cases_path, default_config_path=default_config_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    source_cache_dir = output_dir / "_source-cache"
    case_results: list[dict[str, Any]] = []

    for case in cases:
        try:
            case_results.append(
                _run_case(
                    case=case,
                    output_dir=output_dir,
                    policy_profile=policy_profile,
                    source_cache_dir=source_cache_dir,
                    resume=resume,
                )
            )
        except Exception as exc:
            if fail_fast:
                raise
            case_results.append(
                {
                    "case_id": case.case_id,
                    "status": "error",
                    "error": str(exc),
                    "bundle_path": str(output_dir / "cases" / _safe_case_id(case.case_id)),
                    "expected_rules": case.expected_rules,
                    "expected_findings": tuple(
                        finding.__dict__ for finding in case.expected_findings
                    ),
                    "tags": case.tags,
                    "metadata": case.metadata or {},
                }
            )

    summary = _summarize_results(case_results)
    result = {
        "cases_path": str(cases_path),
        "output_dir": str(output_dir),
        "summary": summary,
        "cases": case_results,
    }
    (output_dir / "evaluation.json").write_text(
        json.dumps(result, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (output_dir / "evaluation.md").write_text(render_evaluation_markdown(result), encoding="utf-8")
    return result


def load_evaluation_cases(
    cases_path: Path,
    *,
    default_config_path: Path | None = None,
) -> tuple[EvaluationCase, ...]:
    if not cases_path.exists():
        raise EvaluationError(f"Evaluation cases file does not exist: {cases_path}")

    data = json.loads(cases_path.read_text(encoding="utf-8"))
    raw_cases = data.get("cases", data) if isinstance(data, dict) else data
    if not isinstance(raw_cases, list):
        raise EvaluationError(
            "Evaluation cases must be a JSON list or an object with a cases list."
        )

    base_dir = cases_path.parent
    cases: list[EvaluationCase] = []
    for index, item in enumerate(raw_cases, start=1):
        if not isinstance(item, dict):
            raise EvaluationError(f"Case {index} must be an object.")
        case_id = str(item.get("id") or item.get("case_id") or f"case-{index}")
        diff_path = _resolve_optional_path(base_dir, item.get("diff"))
        diff_url = _optional_str(item.get("diff_url") or item.get("patch_url"))
        repo_path = _resolve_optional_path(base_dir, item.get("repo"))
        repo_url = _resolve_repo_url(base_dir, item.get("repo_url"))
        base_ref = _optional_str(item.get("base_ref"))
        head_ref = _optional_str(item.get("head_ref"))
        if diff_path is not None and not diff_path.exists():
            raise EvaluationError(f"Evaluation path does not exist: {diff_path}")
        has_git_source = (repo_path is not None or repo_url) and base_ref and head_ref
        if diff_path is None and diff_url is None and not has_git_source:
            raise EvaluationError(
                f"Case {case_id} must provide diff, diff_url, or repo/repo_url "
                "with base_ref and head_ref."
            )
        config_path = _resolve_optional_path(base_dir, item.get("config")) or default_config_path
        expected_findings = _parse_expected_findings(item)
        expected_rules = tuple(str(value) for value in item.get("expected_rules", ()))
        if not expected_rules and expected_findings:
            expected_rules = tuple(
                dict.fromkeys(
                    finding.rule_id
                    for finding in expected_findings
                    if finding.role != "negative-control"
                )
            )
        cases.append(
            EvaluationCase(
                case_id=case_id,
                diff_path=diff_path,
                repo_path=repo_path or base_dir,
                diff_url=diff_url,
                repo_url=repo_url,
                base_ref=base_ref,
                head_ref=head_ref,
                config_path=config_path,
                expected_rules=expected_rules,
                expected_findings=expected_findings,
                tags=tuple(str(value) for value in item.get("tags", ())),
                metadata=_case_metadata(item),
            )
        )
    return tuple(cases)


def render_evaluation_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# VeriSec Evaluation",
        "",
        "## Summary",
        "",
        f"- Cases: {summary['case_count']}",
        f"- Completed: {summary['completed_count']}",
        f"- Errors: {summary['error_count']}",
        f"- Findings: {summary['finding_count']}",
        f"- Average confidence: {summary['avg_confidence']:.2f}",
        f"- Validation coverage: {summary['validation_coverage_rate']:.2f}",
        f"- Tool evidence rate: {summary['tool_evidence_rate']:.2f}",
        f"- Validation gap rate: {summary['validation_gap_rate']:.2f}",
        f"- Policy-blocked tools: {summary['policy_blocked_count']}",
        f"- Policy warnings: {summary['policy_warning_count']}",
        f"- Accepted finding rate: {summary['accepted_finding_rate']:.2f}",
        f"- Primary precision: {summary['primary_precision']:.2f}",
        f"- Primary finding recall: {_format_optional_rate(summary.get('primary_finding_recall'))}",
        f"- Supporting evidence rate: {summary['supporting_evidence_rate']:.2f}",
        f"- Unexpected finding rate: {summary['unexpected_finding_rate']:.2f}",
        f"- Negative-control violations: {summary['negative_control_violation_count']}",
        f"- Expected rule recall: {_format_optional_rate(summary.get('expected_rule_recall'))}",
        (
            "- Expected rule precision: "
            f"{_format_optional_rate(summary.get('expected_rule_precision'))}"
        ),
        (
            "- Expected finding recall: "
            f"{_format_optional_rate(summary.get('expected_finding_recall'))}"
        ),
        f"- CVE/advisory cases: {summary['security_advisory_case_count']}",
        "",
        "## Cases",
        "",
        "| Case | Status | Project | Findings | Avg Confidence | Expected Hits | Bundle |",
        "| --- | --- | --- | ---: | ---: | --- | --- |",
    ]
    for case in result["cases"]:
        hits = ", ".join(case.get("expected_rule_hits", ())) or "-"
        metadata = case.get("metadata", {})
        project = metadata.get("project") or metadata.get("package") or "-"
        lines.append(
            "| "
            f"{case['case_id']} | "
            f"{case['status']} | "
            f"{project} | "
            f"{case.get('finding_count', 0)} | "
            f"{case.get('avg_confidence', 0):.2f} | "
            f"{hits} | "
            f"`{case.get('bundle_path', '')}` |"
        )
    if summary.get("tag_counts"):
        lines.extend(["", "## Tags", "", "| Tag | Cases |", "| --- | ---: |"])
        for tag, count in sorted(summary["tag_counts"].items()):
            lines.append(f"| {tag} | {count} |")
    if summary.get("finding_role_counts"):
        lines.extend(["", "## Finding Roles", "", "| Role | Findings |", "| --- | ---: |"])
        for role, count in sorted(summary["finding_role_counts"].items()):
            lines.append(f"| {role} | {count} |")
    if summary.get("unexpected_taxonomy"):
        lines.extend(
            [
                "",
                "## Unexpected Taxonomy",
                "",
                "| Category | Findings |",
                "| --- | ---: |",
            ]
        )
        for category, count in sorted(summary["unexpected_taxonomy"].items()):
            lines.append(f"| {category} | {count} |")
    return "\n".join(lines).rstrip() + "\n"


def _run_case(
    *,
    case: EvaluationCase,
    output_dir: Path,
    policy_profile: str | None = None,
    source_cache_dir: Path | None = None,
    resume: bool = False,
) -> dict[str, Any]:
    case_output = output_dir / "cases" / _safe_case_id(case.case_id)
    report_path = case_output / "report.json"
    if resume and report_path.exists():
        report_dict = json.loads(report_path.read_text(encoding="utf-8"))
        return _case_result_from_report(
            case,
            report_dict,
            bundle_path=case_output,
            materialized=None,
            status="resumed",
        )

    materialized = _materialize_case(
        case=case,
        case_output=case_output,
        source_cache_dir=source_cache_dir,
    )
    report = ReviewAgent(load_config(case.config_path, policy_profile=policy_profile)).review(
        diff_path=materialized["diff_path"],
        repo_path=materialized["repo_path"],
        output_dir=case_output,
        subject=case.case_id,
        source={
            "kind": "evaluation_case",
            "case_id": case.case_id,
            "diff_path": str(materialized["diff_path"]),
            "diff_url": case.diff_url,
            "repo_path": str(materialized["repo_path"]),
            "repo_url": case.repo_url,
            "base_ref": case.base_ref,
            "head_ref": case.head_ref,
            "config_path": str(case.config_path) if case.config_path else None,
            "expected_rules": case.expected_rules,
            "expected_findings": tuple(finding.__dict__ for finding in case.expected_findings),
            "tags": case.tags,
            "metadata": case.metadata or {},
            "materialized_from": materialized["source_kind"],
            "source_fetch_mode": materialized.get("source_fetch_mode", "direct"),
            "source_cache_path": materialized.get("source_cache_path"),
        },
    )
    return _case_result_from_report(
        case,
        report.to_dict(),
        bundle_path=report.bundle_path,
        materialized=materialized,
        status="completed",
    )


def _case_result_from_report(
    case: EvaluationCase,
    report: dict[str, Any],
    *,
    bundle_path: Path,
    materialized: dict[str, Any] | None,
    status: str,
) -> dict[str, Any]:
    findings = tuple(report.get("findings", ()))
    source = report.get("source", {})
    found_rules = tuple(str(finding.get("rule_id")) for finding in findings)
    expected_rule_hits = tuple(rule for rule in case.expected_rules if rule in found_rules)
    expected_rule_misses = tuple(rule for rule in case.expected_rules if rule not in found_rules)
    expected_finding_hits, expected_finding_misses = _expected_finding_results(
        case.expected_findings,
        findings,
    )
    finding_labels = _label_findings(case.expected_findings, findings)
    role_counts = _role_counts(finding_labels)
    unexpected_taxonomy = _unexpected_taxonomy_counts(finding_labels)
    unexpected_rules = tuple(
        sorted(
            {
                rule
                for rule in found_rules
                if case.expected_rules and rule not in case.expected_rules
            }
        )
    )
    diff_path = (
        str(materialized["diff_path"])
        if materialized
        else str(source.get("diff_path") or "")
    )
    repo_path = (
        str(materialized["repo_path"])
        if materialized
        else str(source.get("repo_path") or "")
    )
    source_kind = (
        str(materialized["source_kind"])
        if materialized
        else str(source.get("materialized_from") or "")
    )
    source_fetch_mode = (
        str(materialized.get("source_fetch_mode", "direct"))
        if materialized
        else str(source.get("source_fetch_mode") or "resumed")
    )
    source_cache_path = (
        materialized.get("source_cache_path")
        if materialized
        else source.get("source_cache_path")
    )

    return {
        "case_id": case.case_id,
        "status": status,
        "bundle_path": str(bundle_path),
        "diff_path": diff_path,
        "diff_url": case.diff_url,
        "repo_path": repo_path,
        "repo_url": case.repo_url,
        "base_ref": case.base_ref,
        "head_ref": case.head_ref,
        "materialized_from": source_kind,
        "source_fetch_mode": source_fetch_mode,
        "source_cache_path": source_cache_path,
        "metadata": case.metadata or {},
        "found_rules": tuple(sorted(set(found_rules))),
        "expected_rules": case.expected_rules,
        "expected_rule_hits": expected_rule_hits,
        "expected_rule_misses": expected_rule_misses,
        "expected_findings": tuple(finding.__dict__ for finding in case.expected_findings),
        "expected_finding_hits": expected_finding_hits,
        "expected_finding_misses": expected_finding_misses,
        "finding_labels": finding_labels,
        "finding_role_counts": role_counts,
        "unexpected_taxonomy": unexpected_taxonomy,
        "unexpected_rules": unexpected_rules,
        "tags": case.tags,
        **_case_metrics(report),
    }


def _case_metrics(report: dict[str, Any]) -> dict[str, Any]:
    summary = report["summary"]
    return {
        "finding_count": summary.get("finding_count", 0),
        "severity_counts": summary.get("severity_counts", {}),
        "avg_confidence": summary.get("avg_confidence", 0.0),
        "verification_count": summary.get("verification_count", 0),
        "verification_passed": summary.get("verification_passed", 0),
        "required_failure_count": len(summary.get("required_failures", ())),
        "validation_step_count": summary.get("validation_step_count", 0),
        "validation_covered": summary.get("validation_covered", 0),
        "validation_missing": summary.get("validation_missing", 0),
        "tool_finding_count": summary.get("tool_finding_count", 0),
        "tool_artifact_count": summary.get("tool_artifact_count", 0),
        "tool_supported_findings": summary.get("tool_supported_findings", 0),
        "validation_gap_findings": summary.get("validation_gap_findings", 0),
        "scanner_dampened_findings": summary.get("scanner_dampened_findings", 0),
        "policy_blocked_count": summary.get("policy_blocked_count", 0),
        "policy_warning_count": summary.get("policy_warning_count", 0),
    }


def _materialize_case(
    *,
    case: EvaluationCase,
    case_output: Path,
    source_cache_dir: Path | None = None,
) -> dict[str, Any]:
    source_dir = case_output / "_source"
    source_dir.mkdir(parents=True, exist_ok=True)

    if case.diff_url:
        diff_path = source_dir / "remote.diff"
        diff_path.write_text(fetch_url_diff(case.diff_url), encoding="utf-8")
        if case.base_ref and (case.repo_url or case.repo_path):
            repo_path = _checkout_case_repo(
                case,
                source_dir=source_dir,
                source_cache_dir=source_cache_dir,
                fetch_head=False,
            )
            source_meta = _source_meta(repo_path)
            try:
                _run_git(
                    ("apply", "--whitespace=nowarn", str(diff_path)),
                    cwd=source_meta["repo_path"],
                )
            except EvaluationError:
                if not case.head_ref:
                    raise
                repo_path = _checkout_case_repo(
                    case,
                    source_dir=source_dir,
                    source_cache_dir=source_cache_dir,
                    ref=case.head_ref,
                )
                source_meta = _source_meta(repo_path)
                git_diff_path = source_dir / "git.diff"
                git_diff_path.write_text(
                    _git_diff(source_meta["repo_path"], case.base_ref, case.head_ref),
                    encoding="utf-8",
                )
                return {
                    "diff_path": git_diff_path,
                    "repo_path": source_meta["repo_path"],
                    "source_kind": "diff_url_apply_fallback_git_diff",
                    "source_fetch_mode": source_meta["source_fetch_mode"],
                    "source_cache_path": source_meta["source_cache_path"],
                }
            return {
                "diff_path": diff_path,
                "repo_path": source_meta["repo_path"],
                "source_kind": "diff_url_applied_to_base",
                "source_fetch_mode": source_meta["source_fetch_mode"],
                "source_cache_path": source_meta["source_cache_path"],
            }
        return {
            "diff_path": diff_path,
            "repo_path": case.repo_path or source_dir,
            "source_kind": "diff_url",
            "source_fetch_mode": "direct",
            "source_cache_path": None,
        }

    if case.base_ref and case.head_ref:
        diff_path = source_dir / "git.diff"
        if case.repo_url:
            repo_path = _checkout_case_repo(
                case,
                source_dir=source_dir,
                source_cache_dir=source_cache_dir,
                ref=case.head_ref,
            )
            source_meta = _source_meta(repo_path)
            diff_text = _git_diff(source_meta["repo_path"], case.base_ref, case.head_ref)
            diff_path.write_text(diff_text, encoding="utf-8")
            return {
                "diff_path": diff_path,
                "repo_path": source_meta["repo_path"],
                "source_kind": "git_clone",
                "source_fetch_mode": source_meta["source_fetch_mode"],
                "source_cache_path": source_meta["source_cache_path"],
            }

        if case.repo_path is None:
            raise EvaluationError(
                f"Case {case.case_id} needs repo or repo_url for base/head materialization."
            )
        # Check out head_ref into an isolated clone, exactly as the repo_url branch does,
        # so the returned repo_path is the patched revision the diff describes rather than
        # the caller's working tree at whatever HEAD happens to be. _file_string_lines
        # resolves multi-line string spans against this checkout assuming it is head_ref
        # (D-008); returning the source tree silently consulted the wrong lines (T-009).
        checkout = _checkout_case_repo(
            case,
            source_dir=source_dir,
            source_cache_dir=source_cache_dir,
            ref=case.head_ref,
        )
        source_meta = _source_meta(checkout)
        diff_text = _git_diff(source_meta["repo_path"], case.base_ref, case.head_ref)
        diff_path.write_text(diff_text, encoding="utf-8")
        return {
            "diff_path": diff_path,
            "repo_path": source_meta["repo_path"],
            "source_kind": "git_existing_repo",
            "source_fetch_mode": source_meta["source_fetch_mode"],
            "source_cache_path": source_meta["source_cache_path"],
        }

    if case.diff_path is None:
        raise EvaluationError(f"Case {case.case_id} does not have a materializable diff.")
    return {
        "diff_path": case.diff_path,
        "repo_path": case.repo_path or case.diff_path.parent,
        "source_kind": "local_diff",
        "source_fetch_mode": "direct",
        "source_cache_path": None,
    }


def _checkout_case_repo(
    case: EvaluationCase,
    *,
    source_dir: Path,
    source_cache_dir: Path | None = None,
    ref: str | None = None,
    fetch_head: bool = True,
) -> dict[str, Any]:
    source = case.repo_url or (str(case.repo_path) if case.repo_path is not None else None)
    if source is None:
        raise EvaluationError(f"Case {case.case_id} has no repository to checkout.")

    source_fetch_mode = "direct"
    source_cache_path: Path | None = None
    remote_source = source
    fetch_ref_map: dict[str, str] = {}
    if source_cache_dir is not None:
        source_cache_path = _prepare_source_cache(source_cache_dir, source)
        remote_source = str(source_cache_path)
        source_fetch_mode = "source-cache"

    repo_path = source_dir / "repo"
    if not repo_path.exists():
        _run_git(("init", "--quiet", str(repo_path)))
        _enable_git_long_paths(repo_path)
        _run_git(("remote", "add", "origin", remote_source), cwd=repo_path)
    else:
        _enable_git_long_paths(repo_path)
        _run_git(("remote", "set-url", "origin", remote_source), cwd=repo_path)
        _run_git(("reset", "--hard", "--quiet"), cwd=repo_path)
        _run_git(("clean", "-fd", "--quiet"), cwd=repo_path)

    refs = tuple(
        dict.fromkeys(
            value
            for value in (
                case.base_ref,
                case.head_ref if fetch_head else None,
                ref,
            )
            if value
        )
    )
    for fetch_ref in refs:
        local_fetch_ref = fetch_ref
        if source_cache_path is not None:
            local_fetch_ref = _fetch_ref_into_cache(source_cache_path, fetch_ref)
            fetch_ref_map[fetch_ref] = local_fetch_ref
        _fetch_ref(repo_path, local_fetch_ref, filtered=source_cache_path is None)

    checkout_ref = ref or case.base_ref
    if checkout_ref:
        _run_git(("checkout", "--quiet", checkout_ref), cwd=repo_path)
    return {
        "repo_path": repo_path,
        "source_fetch_mode": source_fetch_mode,
        "source_cache_path": str(source_cache_path) if source_cache_path else None,
        "cached_refs": fetch_ref_map,
    }


def _source_meta(checkout: dict[str, Any]) -> dict[str, Any]:
    return {
        "repo_path": checkout["repo_path"],
        "source_fetch_mode": checkout.get("source_fetch_mode", "direct"),
        "source_cache_path": checkout.get("source_cache_path"),
    }


def _prepare_source_cache(source_cache_dir: Path, source: str) -> Path:
    cache_root = source_cache_dir / "repos"
    cache_root.mkdir(parents=True, exist_ok=True)
    cache_path = cache_root / _hash_key(source)
    if not cache_path.exists():
        _run_git(("init", "--bare", "--quiet", str(cache_path)))
        _enable_git_long_paths(cache_path)
        _run_git(("remote", "add", "origin", source), cwd=cache_path)
    else:
        _enable_git_long_paths(cache_path)
        _run_git(("remote", "set-url", "origin", source), cwd=cache_path)
    metadata = {
        "source": source,
        "cache_path": str(cache_path),
    }
    (cache_path / "verisec-source.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return cache_path


def _fetch_ref_into_cache(cache_repo: Path, ref: str) -> str:
    cache_ref = f"refs/verisec/{_hash_key(ref)}"
    refspec = f"+{ref}:{cache_ref}"
    attempts = (
        (
            "shallow",
            (
                "fetch",
                "--quiet",
                "--no-tags",
                "--depth=1",
                "origin",
                refspec,
            ),
        ),
        (
            "full",
            (
                "fetch",
                "--quiet",
                "--no-tags",
                "origin",
                refspec,
            ),
        ),
    )
    errors: list[str] = []
    for label, args in attempts:
        try:
            _run_git(args, cwd=cache_repo)
            return cache_ref
        except EvaluationError as exc:
            errors.append(f"{label}: {exc}")
    joined_errors = "\n".join(errors)
    raise EvaluationError(
        f"git cache fetch failed for {ref} after {len(attempts)} attempts:\n"
        f"{joined_errors}"
    )


def _hash_key(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()[:24]


def _enable_git_long_paths(repo_path: Path) -> None:
    _run_git(("config", "core.longpaths", "true"), cwd=repo_path)


def _fetch_ref(repo_path: Path, ref: str, *, filtered: bool = True) -> None:
    if not filtered:
        try:
            _run_git(("fetch", "--quiet", "--no-tags", "origin", ref), cwd=repo_path)
            return
        except EvaluationError as exc:
            raise EvaluationError(f"git fetch failed for {ref}: {exc}") from exc

    attempts = (
        (
            "shallow-filtered",
            (
                "fetch",
                "--quiet",
                "--no-tags",
                "--depth=1",
                "--filter=blob:none",
                "origin",
                ref,
            ),
        ),
        (
            "filtered",
            (
                "fetch",
                "--quiet",
                "--no-tags",
                "--filter=blob:none",
                "origin",
                ref,
            ),
        ),
        (
            "full",
            (
                "fetch",
                "--quiet",
                "--no-tags",
                "origin",
                ref,
            ),
        ),
    )
    errors: list[str] = []
    for label, args in attempts:
        try:
            _run_git(args, cwd=repo_path)
            return
        except EvaluationError as exc:
            errors.append(f"{label}: {exc}")
    joined_errors = "\n".join(errors)
    raise EvaluationError(
        f"git fetch failed for {ref} after {len(attempts)} attempts:\n"
        f"{joined_errors}"
    )


def _git_diff(repo_path: Path, base_ref: str, head_ref: str) -> str:
    completed = _run_git(
        ("diff", "--no-ext-diff", "--binary", f"{base_ref}..{head_ref}", "--"),
        cwd=repo_path,
    )
    diff_text = completed.stdout
    if not diff_text.strip():
        raise EvaluationError(f"Git diff was empty for {base_ref}..{head_ref}.")
    return diff_text


def _run_git(
    args: tuple[str, ...],
    *,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ("git", *args),
        cwd=cwd,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        location = f" in {cwd}" if cwd else ""
        raise EvaluationError(f"git {' '.join(args)} failed{location}: {detail}")
    return completed


def _expected_finding_results(
    expected_findings: tuple[ExpectedFinding, ...],
    findings: tuple[dict[str, Any], ...],
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    hits: list[dict[str, Any]] = []
    misses: list[dict[str, Any]] = []
    for expected in expected_findings:
        if expected.role == "negative-control":
            continue
        serialized = expected.__dict__
        if any(_finding_matches(expected, finding) for finding in findings):
            hits.append(serialized)
        else:
            misses.append(serialized)
    return tuple(hits), tuple(misses)


def _label_findings(
    expected_findings: tuple[ExpectedFinding, ...],
    findings: tuple[dict[str, Any], ...],
) -> tuple[dict[str, Any], ...]:
    labels: list[dict[str, Any]] = []
    for finding in findings:
        expected = _best_expected_match(expected_findings, finding)
        role = expected.role if expected is not None else "unexpected"
        taxonomy = (
            "expected"
            if expected is not None and expected.role != "negative-control"
            else _finding_taxonomy(finding, role)
        )
        labels.append(
            {
                "finding_id": finding.get("finding_id", ""),
                "rule_id": finding.get("rule_id", ""),
                "file_path": finding.get("file_path", ""),
                "severity": finding.get("severity", ""),
                "role": role,
                "taxonomy": taxonomy,
                "matched_expected": expected.__dict__ if expected is not None else None,
            }
        )
    return tuple(labels)


def _best_expected_match(
    expected_findings: tuple[ExpectedFinding, ...],
    finding: dict[str, Any],
) -> ExpectedFinding | None:
    matches = [
        expected
        for expected in expected_findings
        if _finding_matches(expected, finding)
    ]
    if not matches:
        return None
    priority = {
        "negative-control": 0,
        "primary": 1,
        "supporting": 2,
        "benign": 3,
    }
    return sorted(matches, key=lambda expected: priority.get(expected.role, 99))[0]


def _finding_taxonomy(finding: dict[str, Any], role: str) -> str:
    if role == "negative-control":
        return "negative-control-violation"
    file_path = _normalize_path(str(finding.get("file_path", "")))
    if file_path.startswith("tests/") or "/test" in file_path or file_path.startswith("test"):
        return "test-only-unlabeled"
    return "unlabeled-rule-or-location"


def _role_counts(labels: tuple[dict[str, Any], ...]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for label in labels:
        role = str(label.get("role", "unexpected"))
        counts[role] = counts.get(role, 0) + 1
    return counts


def _unexpected_taxonomy_counts(labels: tuple[dict[str, Any], ...]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for label in labels:
        if label.get("role") in {"primary", "supporting", "benign"}:
            continue
        taxonomy = str(label.get("taxonomy", "unclassified"))
        counts[taxonomy] = counts.get(taxonomy, 0) + 1
    return counts


def _finding_matches(expected: ExpectedFinding, finding: dict[str, Any]) -> bool:
    if finding.get("rule_id") != expected.rule_id:
        return False
    if expected.severity and finding.get("severity") != expected.severity:
        return False
    if expected.file_path and _normalize_path(finding.get("file_path", "")) != _normalize_path(
        expected.file_path
    ):
        return False
    if expected.start_line is None:
        return True
    finding_start = int(finding.get("start_line", 0))
    finding_end = int(finding.get("end_line", finding_start))
    expected_end = expected.end_line or expected.start_line
    return finding_start <= expected_end and expected.start_line <= finding_end


def _summarize_results(case_results: list[dict[str, Any]]) -> dict[str, Any]:
    completed = [
        case for case in case_results if case["status"] in {"completed", "resumed"}
    ]
    finding_count = sum(int(case.get("finding_count", 0)) for case in completed)
    validation_steps = sum(int(case.get("validation_step_count", 0)) for case in completed)
    validation_covered = sum(int(case.get("validation_covered", 0)) for case in completed)
    validation_with_evidence = sum(
        int(case.get("tool_supported_findings", 0)) for case in completed
    )
    validation_gap_findings = sum(
        int(case.get("validation_gap_findings", 0)) for case in completed
    )
    expected_cases = [case for case in completed if case.get("expected_rules")]
    expected_hits = sum(len(case.get("expected_rule_hits", ())) for case in expected_cases)
    expected_total = sum(len(case.get("expected_rules", ())) for case in expected_cases)
    found_labeled_total = sum(
        len(set(case.get("found_rules", ()))) for case in expected_cases
    )
    expected_finding_cases = [case for case in completed if case.get("expected_findings")]
    expected_finding_hits = sum(
        len(case.get("expected_finding_hits", ())) for case in expected_finding_cases
    )
    expected_finding_total = sum(
        1
        for case in expected_finding_cases
        for expected in case.get("expected_findings", ())
        if expected.get("role", "primary") != "negative-control"
    )
    primary_expected_total = sum(
        1
        for case in completed
        for expected in case.get("expected_findings", ())
        if expected.get("role", "primary") == "primary"
    )
    primary_expected_hits = sum(
        1
        for case in completed
        for expected in case.get("expected_finding_hits", ())
        if expected.get("role", "primary") == "primary"
    )
    role_counts = _aggregate_counts(
        case.get("finding_role_counts", {}) for case in completed
    )
    unexpected_taxonomy = _aggregate_counts(
        case.get("unexpected_taxonomy", {}) for case in completed
    )
    accepted_count = sum(
        int(role_counts.get(role, 0)) for role in ("primary", "supporting", "benign")
    )
    primary_count = int(role_counts.get("primary", 0))
    supporting_count = int(role_counts.get("supporting", 0))
    unexpected_count = int(role_counts.get("unexpected", 0))
    negative_control_violation_count = int(role_counts.get("negative-control", 0))
    tag_counts = _tag_counts(case_results)

    return {
        "case_count": len(case_results),
        "completed_count": len(completed),
        "error_count": len(case_results) - len(completed),
        "security_advisory_case_count": sum(
            1 for case in case_results if _has_security_advisory(case.get("metadata", {}))
        ),
        "tag_counts": tag_counts,
        "finding_role_counts": role_counts,
        "unexpected_taxonomy": unexpected_taxonomy,
        "finding_count": finding_count,
        "accepted_finding_rate": _accepted_finding_rate(accepted_count, finding_count),
        "primary_precision": _safe_div(primary_count, finding_count),
        "primary_finding_recall": (
            _safe_div(primary_expected_hits, primary_expected_total)
            if primary_expected_total
            else None
        ),
        "supporting_evidence_rate": _safe_div(supporting_count, finding_count),
        "unexpected_finding_rate": _safe_div(unexpected_count, finding_count),
        "negative_control_violation_count": negative_control_violation_count,
        "avg_findings_per_case": _safe_div(finding_count, len(completed)),
        "avg_confidence": _weighted_avg_confidence(completed),
        "verification_count": sum(int(case.get("verification_count", 0)) for case in completed),
        "verification_passed": sum(int(case.get("verification_passed", 0)) for case in completed),
        "required_failure_count": sum(
            int(case.get("required_failure_count", 0)) for case in completed
        ),
        "policy_blocked_count": sum(
            int(case.get("policy_blocked_count", 0)) for case in completed
        ),
        "policy_warning_count": sum(
            int(case.get("policy_warning_count", 0)) for case in completed
        ),
        "validation_step_count": validation_steps,
        "validation_covered": validation_covered,
        "validation_coverage_rate": _coverage_rate(
            validation_covered,
            validation_steps,
            finding_count,
        ),
        "tool_finding_count": sum(int(case.get("tool_finding_count", 0)) for case in completed),
        "tool_artifact_count": sum(int(case.get("tool_artifact_count", 0)) for case in completed),
        "tool_evidence_rate": _safe_div(validation_with_evidence, finding_count),
        "validation_gap_rate": _safe_div(validation_gap_findings, finding_count),
        "scanner_dampened_findings": sum(
            int(case.get("scanner_dampened_findings", 0)) for case in completed
        ),
        "expected_rule_recall": (
            _safe_div(expected_hits, expected_total) if expected_cases else None
        ),
        "expected_rule_precision": (
            _safe_div(expected_hits, found_labeled_total) if expected_cases else None
        ),
        "expected_finding_recall": (
            _safe_div(expected_finding_hits, expected_finding_total)
            if expected_finding_total
            else None
        ),
    }


def _weighted_avg_confidence(cases: list[dict[str, Any]]) -> float:
    total_findings = sum(int(case.get("finding_count", 0)) for case in cases)
    if total_findings == 0:
        return 0.0
    weighted = sum(
        float(case.get("avg_confidence", 0.0)) * int(case.get("finding_count", 0))
        for case in cases
    )
    return round(weighted / total_findings, 2)


def _accepted_finding_rate(accepted_count: int, finding_count: int) -> float:
    if finding_count == 0:
        return 1.0
    return _safe_div(accepted_count, finding_count)


def _resolve_required_path(base_dir: Path, item: dict[str, Any], key: str) -> Path:
    value = item.get(key)
    if not value:
        raise EvaluationError(f"Evaluation case is missing required field: {key}")
    path = _resolve_optional_path(base_dir, value)
    assert path is not None
    if not path.exists():
        raise EvaluationError(f"Evaluation path does not exist: {path}")
    return path


def _resolve_optional_path(base_dir: Path, value: Any) -> Path | None:
    if value is None:
        return None
    path = Path(str(value))
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def _resolve_repo_url(base_dir: Path, value: Any) -> str | None:
    if value is None:
        return None
    raw_value = str(value)
    if "://" in raw_value or raw_value.startswith("git@"):
        return raw_value
    path = Path(raw_value)
    if not path.is_absolute():
        path = base_dir / path
    return str(path.resolve()) if path.exists() else raw_value


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _parse_expected_findings(item: dict[str, Any]) -> tuple[ExpectedFinding, ...]:
    raw_findings = item.get("expected_findings", ())
    findings: list[ExpectedFinding] = []
    for index, raw_finding in enumerate(raw_findings, start=1):
        if isinstance(raw_finding, str):
            findings.append(ExpectedFinding(rule_id=raw_finding))
            continue
        if not isinstance(raw_finding, dict):
            raise EvaluationError(f"expected_findings[{index}] must be a string or object.")
        rule_id = raw_finding.get("rule_id")
        if not rule_id:
            raise EvaluationError(f"expected_findings[{index}] is missing rule_id.")
        findings.append(
            ExpectedFinding(
                rule_id=str(rule_id),
                file_path=_optional_str(raw_finding.get("file_path")),
                start_line=_optional_int(raw_finding.get("start_line")),
                end_line=_optional_int(raw_finding.get("end_line")),
                severity=_optional_str(raw_finding.get("severity")),
                role=_parse_expected_role(raw_finding.get("role")),
                notes=str(raw_finding.get("notes", "")),
            )
        )
    return tuple(findings)


def _parse_expected_role(value: Any) -> str:
    role = str(value or "primary")
    if role not in {"primary", "supporting", "benign", "negative-control"}:
        raise EvaluationError(
            "expected finding role must be one of: primary, supporting, benign, "
            "negative-control"
        )
    return role


def _case_metadata(item: dict[str, Any]) -> dict[str, Any]:
    metadata = dict(item.get("metadata", {}))
    for key in (
        "project",
        "package",
        "language",
        "ecosystem",
        "cve",
        "cwe",
        "advisory",
        "upstream_pr",
        "vulnerability_class",
    ):
        if key in item:
            metadata[key] = item[key]
    return metadata


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return int(value)


def _safe_case_id(case_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", case_id).strip("-")
    return safe or "case"


def _safe_div(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 4)


def _coverage_rate(covered: int, total: int, finding_count: int) -> float:
    if total == 0 and finding_count == 0:
        return 1.0
    return _safe_div(covered, total)


def _tag_counts(case_results: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for case in case_results:
        for tag in case.get("tags", ()):
            counts[str(tag)] = counts.get(str(tag), 0) + 1
    return counts


def _aggregate_counts(items: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        for key, value in item.items():
            counts[str(key)] = counts.get(str(key), 0) + int(value)
    return counts


def _has_security_advisory(metadata: dict[str, Any]) -> bool:
    return any(metadata.get(key) for key in ("cve", "advisory", "upstream_pr"))


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _format_optional_rate(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.2f}"
