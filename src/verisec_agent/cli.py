from __future__ import annotations

import argparse
import json
from pathlib import Path

from verisec_agent.agent import ReviewAgent
from verisec_agent.config import load_config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="verisec", description="VeriSec Agent CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    review = subparsers.add_parser("review", help="Review a unified diff")
    review.add_argument("--diff", required=True, type=Path, help="Path to a unified diff")
    review.add_argument("--repo", default=Path("."), type=Path, help="Repository root")
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
        report = agent.review(
            diff_path=args.diff.resolve(),
            repo_path=args.repo.resolve(),
            output_dir=args.out.resolve(),
        )
        if args.json:
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        else:
            summary = report.summary
            print(
                f"VeriSec review complete: {summary['finding_count']} finding(s), "
                f"{summary['verification_passed']}/{summary['verification_count']} checks passed."
            )
            print(f"Bundle: {report.bundle_path}")
