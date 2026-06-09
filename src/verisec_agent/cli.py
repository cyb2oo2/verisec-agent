from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

from verisec_agent.agent import ReviewAgent
from verisec_agent.case_audit import CaseAuditError, run_case_audit
from verisec_agent.case_promotion import CasePromotionError, plan_case_promotions
from verisec_agent.config import load_config
from verisec_agent.dashboard import DashboardError, parse_labeled_path, run_dashboard
from verisec_agent.evaluation import EvaluationError, run_evaluation
from verisec_agent.failure_analysis import FailureAnalysisError, run_failure_analysis
from verisec_agent.gate import GateError, GateThresholds, run_gate
from verisec_agent.github_comment import GitHubCommentError, publish_pr_comment
from verisec_agent.inputs import DiffInputError, resolve_diff_input
from verisec_agent.integrity import IntegrityError, attest_artifact_index
from verisec_agent.partition_audit import PartitionAuditError, run_partition_audit
from verisec_agent.policy import POLICY_PROFILES
from verisec_agent.portfolio import PortfolioError, run_portfolio
from verisec_agent.pr_comment import PullRequestCommentError, write_pr_comment
from verisec_agent.replay import ReplayError, replay_bundle
from verisec_agent.scanner_baseline import ScannerBaselineError, run_scanner_baseline
from verisec_agent.scanner_execution import ScannerExecutionError, run_scanner_execution
from verisec_agent.tool_adapters import list_builtin_adapters


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="verisec", description="VeriSec Agent CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    review = subparsers.add_parser("review", help="Review a diff source")
    source = review.add_mutually_exclusive_group(required=True)
    source.add_argument("--diff", type=Path, help="Path to a unified diff")
    source.add_argument("--pr", help="GitHub PR number, URL, or branch for gh pr diff")
    source.add_argument("--diff-url", help="URL that returns a unified diff or patch")
    review.add_argument("--repo", default=Path("."), type=Path, help="Repository root")
    review.add_argument("--github-repo", help="GitHub repository for --pr, as owner/repo")
    review.add_argument(
        "--out",
        default=Path("verisec-runs/latest"),
        type=Path,
        help="Bundle output dir",
    )
    review.add_argument("--config", default=Path("verisec.toml"), type=Path, help="Config TOML")
    review.add_argument(
        "--policy-profile",
        choices=POLICY_PROFILES,
        help="Execution policy profile",
    )
    review.add_argument("--json", action="store_true", help="Print full JSON report")

    replay = subparsers.add_parser("replay", help="Replay verification commands from a bundle")
    replay.add_argument("--bundle", required=True, type=Path, help="Existing VeriSec bundle")
    replay.add_argument("--repo", default=Path("."), type=Path, help="Repository root")
    replay.add_argument("--out", type=Path, help="Replay output dir")
    replay.add_argument("--json", action="store_true", help="Print full JSON replay summary")

    tools = subparsers.add_parser("tools", help="List verification tool adapters")
    tools.add_argument("--config", default=Path("verisec.toml"), type=Path, help="Config TOML")
    tools.add_argument("--policy-profile", choices=POLICY_PROFILES, help="Execution policy profile")
    tools.add_argument("--json", action="store_true", help="Print JSON tool metadata")

    evaluate = subparsers.add_parser("eval", help="Run a batch evaluation manifest")
    evaluate.add_argument("--cases", required=True, type=Path, help="Evaluation cases JSON")
    evaluate.add_argument("--out", required=True, type=Path, help="Evaluation output dir")
    evaluate.add_argument("--config", type=Path, help="Default config TOML for cases")
    evaluate.add_argument(
        "--policy-profile",
        choices=POLICY_PROFILES,
        help="Execution policy profile",
    )
    evaluate.add_argument("--fail-fast", action="store_true", help="Stop on the first case error")
    evaluate.add_argument(
        "--resume",
        action="store_true",
        help="Reuse existing per-case report.json bundles in the output directory",
    )
    evaluate.add_argument("--json", action="store_true", help="Print full JSON evaluation result")

    case_audit = subparsers.add_parser(
        "case-audit",
        help="Audit evaluation case manifests for benchmark-readiness",
    )
    case_audit.add_argument("--cases", required=True, type=Path, help="Evaluation cases JSON")
    case_audit.add_argument("--out", type=Path, help="Optional audit output dir")
    case_audit.add_argument(
        "--require-verification",
        action="store_true",
        help="Warn when positive cases lack a verification config",
    )
    case_audit.add_argument(
        "--fail-on-blocked",
        action="store_true",
        help="Exit non-zero when any case has blocking errors",
    )
    case_audit.add_argument("--json", action="store_true", help="Print full JSON audit result")

    case_promote = subparsers.add_parser(
        "case-promote",
        help="Plan measured benchmark promotion for candidate CVE/PR cases",
    )
    case_promote.add_argument("--candidates", required=True, type=Path)
    case_promote.add_argument("--out", type=Path, help="Optional promotion-plan output dir")
    case_promote.add_argument(
        "--evaluation",
        type=Path,
        help="Optional evaluation.json with per-case validation evidence",
    )
    case_promote.add_argument(
        "--existing-promoted",
        type=Path,
        help="Optional promoted case manifest used to suppress duplicates",
    )
    case_promote.add_argument(
        "--promoted-manifest",
        type=Path,
        help="Optional output manifest containing newly eligible promoted cases",
    )
    case_promote.add_argument(
        "--allow-missing-evaluation",
        action="store_true",
        help="Do not block promotion solely because evaluation evidence is absent",
    )
    case_promote.add_argument("--min-validation-coverage", default=1.0, type=float)
    case_promote.add_argument("--min-tool-evidence-rate", default=1.0, type=float)
    case_promote.add_argument("--min-primary-precision", default=0.5, type=float)
    case_promote.add_argument("--min-primary-finding-recall", default=1.0, type=float)
    case_promote.add_argument("--min-expected-finding-recall", default=1.0, type=float)
    case_promote.add_argument("--json", action="store_true", help="Print full JSON promotion plan")

    partition_audit = subparsers.add_parser(
        "partition-audit",
        help="Check a benchmark partition for leakage against reference manifests",
    )
    partition_audit.add_argument("--cases", required=True, type=Path)
    partition_audit.add_argument(
        "--against",
        action="append",
        required=True,
        type=Path,
        help="Reference case manifest; may be repeated",
    )
    partition_audit.add_argument("--out", type=Path, help="Optional audit output dir")
    partition_audit.add_argument(
        "--fail-on-overlap",
        action="store_true",
        help="Exit non-zero when any case overlaps a reference manifest",
    )
    partition_audit.add_argument("--json", action="store_true", help="Print full JSON result")

    failure_analysis = subparsers.add_parser(
        "failure-analysis",
        help="Classify missed and unexpected findings in an evaluation artifact",
    )
    failure_analysis.add_argument("--evaluation", required=True, type=Path)
    failure_analysis.add_argument("--out", type=Path, help="Optional analysis output dir")
    failure_analysis.add_argument("--json", action="store_true", help="Print full JSON result")

    scanner_baseline = subparsers.add_parser(
        "scanner-baseline",
        help="Evaluate structured scanner output against VeriSec cases",
    )
    scanner_baseline.add_argument("--cases", required=True, type=Path, help="Evaluation cases JSON")
    scanner_baseline.add_argument(
        "--results",
        required=True,
        type=Path,
        help="Scanner baseline artifact manifest",
    )
    scanner_baseline.add_argument("--out", required=True, type=Path, help="Baseline output dir")
    scanner_baseline.add_argument("--adapter", help="Override scanner adapter")
    scanner_baseline.add_argument("--label", help="Baseline label")
    scanner_baseline.add_argument("--fail-fast", action="store_true", help="Stop on first error")
    scanner_baseline.add_argument("--json", action="store_true", help="Print full JSON result")

    scanner_run = subparsers.add_parser(
        "scanner-run",
        help="Run a scanner over evaluation cases and capture baseline artifacts",
    )
    scanner_run.add_argument("--cases", required=True, type=Path, help="Evaluation cases JSON")
    scanner_run.add_argument("--out", required=True, type=Path, help="Scanner artifact output dir")
    scanner_run.add_argument(
        "--adapter",
        default="semgrep",
        help="Scanner adapter name; semgrep has a built-in default command",
    )
    scanner_run.add_argument("--label", help="Baseline label")
    scanner_run.add_argument(
        "--argv",
        nargs="+",
        help=(
            "Command argv template. Supports {repo}, {case_id}, {output}, and {artifact}. "
            "Defaults to semgrep scan --json --config p/security-audit . for Semgrep."
        ),
    )
    scanner_run.add_argument(
        "--scanner-command",
        help=(
            "Shell-like scanner command template parsed with shlex.split and executed "
            "with shell=False. Supports {repo}, {case_id}, {output}, and {artifact}."
        ),
    )
    scanner_run.add_argument(
        "--step",
        action="append",
        help=(
            "Shell-like scanner command step parsed with shlex.split. Repeat for "
            "multi-step scanners such as CodeQL database create/analyze."
        ),
    )
    scanner_run.add_argument("--timeout-seconds", default=300, type=int)
    scanner_run.add_argument("--fail-fast", action="store_true", help="Stop on first error")
    scanner_run.add_argument("--json", action="store_true", help="Print full JSON result")

    gate = subparsers.add_parser("gate", help="Apply CI thresholds to a report or evaluation")
    gate_source = gate.add_mutually_exclusive_group(required=True)
    gate_source.add_argument("--report", type=Path, help="Path to a VeriSec report.json")
    gate_source.add_argument("--evaluation", type=Path, help="Path to a VeriSec evaluation.json")
    gate.add_argument("--out", type=Path, help="Optional gate output dir")
    gate.add_argument("--min-validation-coverage", default=0.0, type=float)
    gate.add_argument("--min-tool-evidence-rate", default=0.0, type=float)
    gate.add_argument("--min-avg-confidence", default=0.0, type=float)
    gate.add_argument("--min-accepted-finding-rate", default=0.0, type=float)
    gate.add_argument("--min-primary-precision", default=0.0, type=float)
    gate.add_argument("--min-primary-finding-recall", default=0.0, type=float)
    gate.add_argument("--min-supporting-evidence-rate", default=0.0, type=float)
    gate.add_argument("--max-validation-gap-rate", default=1.0, type=float)
    gate.add_argument("--max-unexpected-finding-rate", default=1.0, type=float)
    gate.add_argument("--max-negative-control-violations", default=0, type=int)
    gate.add_argument("--max-required-failures", default=0, type=int)
    gate.add_argument("--max-errors", default=0, type=int)
    gate.add_argument("--max-policy-blocked", default=0, type=int)
    gate.add_argument("--max-critical", type=int)
    gate.add_argument("--max-high", type=int)
    gate.add_argument(
        "--github-step-summary",
        action="store_true",
        help="Append Markdown output to GITHUB_STEP_SUMMARY when set",
    )
    gate.add_argument("--json", action="store_true", help="Print full JSON gate result")

    dashboard = subparsers.add_parser(
        "dashboard",
        help="Build a regression dashboard from one or more evaluations",
    )
    dashboard.add_argument(
        "--evaluation",
        action="append",
        required=True,
        help="Labeled evaluation path as label=path; may be repeated",
    )
    dashboard.add_argument(
        "--gate",
        action="append",
        default=[],
        help="Optional labeled gate path as label=path; may be repeated",
    )
    dashboard.add_argument("--baseline", type=Path, help="Previous dashboard.json to compare")
    dashboard.add_argument("--out", required=True, type=Path, help="Dashboard output dir")
    dashboard.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Exit non-zero when the dashboard detects a regression",
    )
    dashboard.add_argument(
        "--github-step-summary",
        action="store_true",
        help="Append Markdown output to GITHUB_STEP_SUMMARY when set",
    )
    dashboard.add_argument("--json", action="store_true", help="Print full JSON dashboard")

    portfolio = subparsers.add_parser(
        "portfolio",
        help="Run a portfolio manifest through eval, gate, and dashboard",
    )
    portfolio.add_argument("--manifest", required=True, type=Path, help="Portfolio JSON path")
    portfolio.add_argument("--out", required=True, type=Path, help="Portfolio output dir")
    portfolio.add_argument("--baseline", type=Path, help="Previous dashboard.json override")
    portfolio.add_argument(
        "--policy-profile",
        choices=POLICY_PROFILES,
        help="Execution policy profile",
    )
    portfolio.add_argument(
        "--github-step-summary",
        action="store_true",
        help="Append Markdown output to GITHUB_STEP_SUMMARY when set",
    )
    portfolio.add_argument("--json", action="store_true", help="Print full JSON portfolio")

    attest = subparsers.add_parser(
        "attest",
        help="Verify artifacts against an artifact_index.json",
    )
    attest.add_argument("--index", required=True, type=Path, help="Artifact index JSON path")
    attest.add_argument("--root", type=Path, help="Override artifact root directory")
    attest.add_argument("--out", type=Path, help="Optional attestation output dir")
    attest.add_argument(
        "--github-step-summary",
        action="store_true",
        help="Append Markdown output to GITHUB_STEP_SUMMARY when set",
    )
    attest.add_argument("--json", action="store_true", help="Print full JSON attestation")

    pr_comment = subparsers.add_parser(
        "pr-comment",
        help="Render a GitHub PR comment from a report or evaluation",
    )
    pr_source = pr_comment.add_mutually_exclusive_group(required=True)
    pr_source.add_argument("--report", type=Path, help="Path to a VeriSec report.json")
    pr_source.add_argument("--evaluation", type=Path, help="Path to a VeriSec evaluation.json")
    pr_comment.add_argument("--gate", type=Path, help="Optional gate.json to include")
    pr_comment.add_argument("--out", required=True, type=Path, help="Output Markdown path")
    pr_comment.add_argument("--max-findings", default=5, type=int)

    github_comment = subparsers.add_parser(
        "github-comment",
        help="Create or update a GitHub PR comment from a rendered Markdown body",
    )
    github_comment.add_argument("--body", required=True, type=Path, help="Markdown body path")
    github_comment.add_argument("--repo", help="GitHub repository as owner/repo")
    github_comment.add_argument("--pr", type=int, help="Pull request number")
    github_comment.add_argument("--token", help="GitHub token; defaults to GITHUB_TOKEN")
    github_comment.add_argument("--api-url", help="GitHub API URL; defaults to GITHUB_API_URL")
    github_comment.add_argument("--event", type=Path, help="GitHub event JSON path")
    github_comment.add_argument(
        "--skip-forks",
        action="store_true",
        help="Skip comment updates when the pull request head repository is a fork",
    )
    github_comment.add_argument(
        "--dry-run",
        action="store_true",
        help="Resolve context and planned action without writing a GitHub comment",
    )
    github_comment.add_argument("--json", action="store_true", help="Print full JSON result")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "review":
        config = load_config(args.config, policy_profile=args.policy_profile)
        agent = ReviewAgent(config)
        output_dir = args.out.resolve()
        try:
            diff_input = resolve_diff_input(
                diff_path=args.diff,
                pr=args.pr,
                diff_url=args.diff_url,
                github_repo=args.github_repo,
                output_dir=output_dir,
            )
            report = agent.review(
                diff_path=diff_input.diff_path,
                repo_path=args.repo.resolve(),
                output_dir=output_dir,
                subject=diff_input.subject,
                source=diff_input.source,
            )
        except DiffInputError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        else:
            summary = report.summary
            print(
                f"VeriSec review complete: {summary['finding_count']} finding(s), "
                f"{summary['verification_passed']}/{summary['verification_count']} checks passed."
            )
            print(f"Bundle: {report.bundle_path}")

    if args.command == "replay":
        try:
            summary = replay_bundle(
                bundle_path=args.bundle.resolve(),
                repo_path=args.repo.resolve(),
                output_dir=args.out.resolve() if args.out else None,
            )
        except ReplayError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(summary, indent=2, sort_keys=True))
        else:
            print(
                "VeriSec replay complete: "
                f"{summary['verification_passed']}/"
                f"{summary['verification_count']} checks passed."
            )

    if args.command == "tools":
        adapters = list_builtin_adapters()
        config = load_config(args.config, policy_profile=args.policy_profile)
        configured = [command.__dict__ for command in config.verification_commands]
        if args.json:
            print(
                json.dumps(
                    {
                        "available_adapters": [
                            adapter.to_dict() for adapter in adapters
                        ],
                        "configured_commands": configured,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print("Built-in adapters:")
            for adapter in adapters:
                status = "available" if adapter.available else "missing"
                caps = ", ".join(adapter.adapter.capabilities)
                print(f"- {adapter.adapter.adapter_id}: {status}; capabilities: {caps}")
            print("Configured commands:")
            for command in config.verification_commands:
                caps = ", ".join(command.capabilities) if command.capabilities else "none"
                print(f"- {command.name} via {command.adapter}; capabilities: {caps}")

    if args.command == "eval":
        try:
            result = run_evaluation(
                cases_path=args.cases.resolve(),
                output_dir=args.out.resolve(),
                default_config_path=args.config.resolve() if args.config else None,
                fail_fast=args.fail_fast,
                policy_profile=args.policy_profile,
                resume=args.resume,
            )
        except EvaluationError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            summary = result["summary"]
            print(
                "VeriSec evaluation complete: "
                f"{summary['completed_count']}/{summary['case_count']} cases, "
                f"{summary['finding_count']} finding(s), "
                f"validation coverage {summary['validation_coverage_rate']:.2f}."
            )
            print(f"Evaluation: {result['output_dir']}")

    if args.command == "case-audit":
        try:
            result = run_case_audit(
                cases_path=args.cases.resolve(),
                output_dir=args.out.resolve() if args.out else None,
                require_verification=args.require_verification,
            )
        except CaseAuditError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            summary = result["summary"]
            print(
                "VeriSec case audit complete: "
                f"{summary['ready_count']}/{summary['case_count']} ready, "
                f"{summary['blocked_count']} blocked, "
                f"{summary['warning_count']} warning(s)."
            )
            if args.out:
                print(f"Audit: {args.out.resolve()}")
        if args.fail_on_blocked and result["summary"]["blocked_count"]:
            raise SystemExit(1)

    if args.command == "case-promote":
        try:
            result = plan_case_promotions(
                candidates_path=args.candidates.resolve(),
                output_dir=args.out.resolve() if args.out else None,
                evaluation_path=args.evaluation.resolve() if args.evaluation else None,
                existing_promoted_path=(
                    args.existing_promoted.resolve() if args.existing_promoted else None
                ),
                promoted_manifest_path=(
                    args.promoted_manifest.resolve() if args.promoted_manifest else None
                ),
                require_evaluation=not args.allow_missing_evaluation,
                min_validation_coverage=args.min_validation_coverage,
                min_tool_evidence_rate=args.min_tool_evidence_rate,
                min_primary_precision=args.min_primary_precision,
                min_primary_finding_recall=args.min_primary_finding_recall,
                min_expected_finding_recall=args.min_expected_finding_recall,
            )
        except CasePromotionError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            summary = result["summary"]
            print(
                "VeriSec case promotion plan: "
                f"{summary['eligible_count']} eligible, "
                f"{summary['already_promoted_count']} already promoted, "
                f"{summary['blocked_count']} blocked."
            )
            if args.out:
                print(f"Promotion plan: {args.out.resolve()}")

    if args.command == "partition-audit":
        try:
            result = run_partition_audit(
                cases_path=args.cases.resolve(),
                reference_paths=tuple(path.resolve() for path in args.against),
                output_dir=args.out.resolve() if args.out else None,
            )
        except PartitionAuditError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            summary = result["summary"]
            status = "passed" if result["passed"] else "failed"
            print(
                "VeriSec partition audit "
                f"{status}: {summary['case_count']} case(s), "
                f"{summary['overlap_count']} overlap pair(s)."
            )
            if args.out:
                print(f"Partition audit: {args.out.resolve()}")
        if args.fail_on_overlap and not result["passed"]:
            raise SystemExit(1)

    if args.command == "failure-analysis":
        try:
            result = run_failure_analysis(
                evaluation_path=args.evaluation.resolve(),
                output_dir=args.out.resolve() if args.out else None,
            )
        except FailureAnalysisError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            summary = result["summary"]
            print(
                "VeriSec failure analysis complete: "
                f"{summary['case_failure_count']}/{summary['case_count']} case(s), "
                f"{summary['failure_count']} classified failure(s)."
            )
            if args.out:
                print(f"Failure analysis: {args.out.resolve()}")

    if args.command == "scanner-baseline":
        try:
            result = run_scanner_baseline(
                cases_path=args.cases.resolve(),
                results_path=args.results.resolve(),
                output_dir=args.out.resolve(),
                adapter=args.adapter,
                label=args.label,
                fail_fast=args.fail_fast,
            )
        except ScannerBaselineError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            summary = result["summary"]
            print(
                "Scanner baseline complete: "
                f"{summary['completed_count']}/{summary['case_count']} cases, "
                f"{summary['finding_count']} finding(s), "
                f"expected finding recall "
                f"{summary.get('expected_finding_recall') or 0.0:.2f}."
            )
            print(f"Baseline: {result['output_dir']}")

    if args.command == "scanner-run":
        try:
            if sum(bool(value) for value in (args.argv, args.scanner_command, args.step)) > 1:
                parser.error("scanner-run accepts only one of --argv, --scanner-command, or --step")
            command_argv = (
                tuple(args.argv)
                if args.argv
                else tuple(shlex.split(args.scanner_command))
                if args.scanner_command
                else None
            )
            command_sequence = (
                tuple(tuple(shlex.split(step)) for step in args.step)
                if args.step
                else None
            )
            result = run_scanner_execution(
                cases_path=args.cases.resolve(),
                output_dir=args.out.resolve(),
                adapter=args.adapter,
                label=args.label,
                command_argv=command_argv,
                command_sequence=command_sequence,
                timeout_seconds=args.timeout_seconds,
                fail_fast=args.fail_fast,
            )
        except ScannerExecutionError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            summary = result["summary"]
            print(
                "Scanner run complete: "
                f"{summary['completed_count']}/{summary['case_count']} completed, "
                f"{summary['skipped_count']} skipped, "
                f"{summary['error_count']} error(s)."
            )
            print(f"Scanner results: {args.out.resolve() / 'scanner_results.json'}")

    if args.command == "gate":
        thresholds = GateThresholds(
            min_validation_coverage=args.min_validation_coverage,
            min_tool_evidence_rate=args.min_tool_evidence_rate,
            min_avg_confidence=args.min_avg_confidence,
            min_accepted_finding_rate=args.min_accepted_finding_rate,
            min_primary_precision=args.min_primary_precision,
            min_primary_finding_recall=args.min_primary_finding_recall,
            min_supporting_evidence_rate=args.min_supporting_evidence_rate,
            max_validation_gap_rate=args.max_validation_gap_rate,
            max_unexpected_finding_rate=args.max_unexpected_finding_rate,
            max_negative_control_violations=args.max_negative_control_violations,
            max_required_failures=args.max_required_failures,
            max_errors=args.max_errors,
            max_policy_blocked=args.max_policy_blocked,
            max_critical=args.max_critical,
            max_high=args.max_high,
        )
        try:
            result = run_gate(
                report_path=args.report.resolve() if args.report else None,
                evaluation_path=args.evaluation.resolve() if args.evaluation else None,
                thresholds=thresholds,
                output_dir=args.out.resolve() if args.out else None,
                write_github_summary=args.github_step_summary,
            )
        except GateError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            status = "passed" if result["passed"] else "failed"
            print(f"VeriSec gate {status}: {len(result['failures'])} failure(s).")
            for failure in result["failures"]:
                print(f"- {failure}")
        if not result["passed"]:
            raise SystemExit(1)

    if args.command == "dashboard":
        try:
            result = run_dashboard(
                evaluations=tuple(parse_labeled_path(value) for value in args.evaluation),
                gates=tuple(parse_labeled_path(value) for value in args.gate),
                baseline_path=args.baseline.resolve() if args.baseline else None,
                output_dir=args.out.resolve(),
                write_github_summary=args.github_step_summary,
            )
        except DashboardError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            summary = result["summary"]
            print(
                "VeriSec dashboard complete: "
                f"{summary['suite_count']} suite(s), "
                f"{summary['regression_count']} regression(s)."
            )
            print(f"Dashboard: {args.out.resolve()}")
        if args.fail_on_regression and result["regressions"]:
            raise SystemExit(1)

    if args.command == "portfolio":
        try:
            result = run_portfolio(
                manifest_path=args.manifest.resolve(),
                output_dir=args.out.resolve(),
                baseline_path=args.baseline.resolve() if args.baseline else None,
                command_line=shlex.join(sys.argv),
                write_github_summary=args.github_step_summary,
                policy_profile=args.policy_profile,
            )
        except PortfolioError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            status = "passed" if result["passed"] else "failed"
            dashboard = result["dashboard_summary"]
            print(
                "VeriSec portfolio "
                f"{status}: {dashboard['suite_count']} suite(s), "
                f"{len(result['failures'])} failure(s)."
            )
            print(f"Portfolio: {args.out.resolve()}")
        if not result["passed"]:
            raise SystemExit(1)

    if args.command == "attest":
        try:
            result = attest_artifact_index(
                index_path=args.index.resolve(),
                root_dir=args.root.resolve() if args.root else None,
                output_dir=args.out.resolve() if args.out else None,
                write_github_summary=args.github_step_summary,
            )
        except IntegrityError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            status = "passed" if result["passed"] else "failed"
            print(
                "VeriSec attestation "
                f"{status}: {result['artifact_count']} artifact(s), "
                f"{result['failure_count']} failure(s)."
            )
            if args.out:
                print(f"Attestation: {args.out.resolve()}")
            for failure in result["failures"]:
                print(f"- {failure}")
        if not result["passed"]:
            raise SystemExit(1)

    if args.command == "pr-comment":
        try:
            write_pr_comment(
                output_path=args.out.resolve(),
                report_path=args.report if args.report else None,
                evaluation_path=args.evaluation if args.evaluation else None,
                gate_path=args.gate if args.gate else None,
                max_findings=args.max_findings,
            )
        except PullRequestCommentError as exc:
            parser.error(str(exc))
        print(f"VeriSec PR comment written: {args.out.resolve()}")

    if args.command == "github-comment":
        try:
            result = publish_pr_comment(
                body_path=args.body,
                repository=args.repo,
                pr_number=args.pr,
                token=args.token,
                api_url=args.api_url,
                event_path=args.event,
                skip_forks=args.skip_forks,
                dry_run=args.dry_run,
            )
        except GitHubCommentError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        elif result["action"] == "skipped":
            print(f"VeriSec GitHub comment skipped: {result['reason']}")
        elif result["action"] == "dry-run":
            print(
                "VeriSec GitHub comment dry run: "
                f"would {result['planned_action']} comment on "
                f"{result['repository']}#{result['pr_number']}."
            )
        else:
            print(
                f"VeriSec GitHub comment {result['action']}: "
                f"{result.get('comment_url', 'no URL returned')}"
            )
