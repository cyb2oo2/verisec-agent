from __future__ import annotations

import argparse
import json
from pathlib import Path

from verisec_agent.agent import ReviewAgent
from verisec_agent.config import load_config
from verisec_agent.inputs import DiffInputError, resolve_diff_input


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
    review.add_argument("--json", action="store_true", help="Print full JSON report")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "review":
        config = load_config(args.config)
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
