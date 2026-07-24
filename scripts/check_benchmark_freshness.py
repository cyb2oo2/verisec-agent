from __future__ import annotations

import argparse
import difflib
import json
import sys
from pathlib import Path
from typing import Any


class FreshnessError(RuntimeError):
    pass


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise FreshnessError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise FreshnessError(f"{path} is not valid JSON: {exc}") from exc


def _load_lines(path: Path) -> list[str]:
    """Read as text lines.

    Comparison is line-based rather than byte-based because Git stores the
    committed snapshot LF-normalized while the generator emits the platform
    ending. A byte comparison fails on Windows every run for a reason that has
    nothing to do with staleness.
    """
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise FreshnessError(f"cannot read {path}: {exc}") from exc


def check_benchmark_freshness(
    *,
    generated_dir: Path,
    benchmark_json_path: Path,
    benchmark_md_path: Path,
) -> list[str]:
    """Compare a freshly generated benchmark matrix against the committed snapshot.

    Returns a list of human-readable differences; empty means the snapshot is
    current. JSON is compared parsed so key ordering and formatting cannot
    produce a false mismatch — only values are load-bearing.
    """
    generated_json = generated_dir / "benchmark_matrix.json"
    generated_md = generated_dir / "benchmark_matrix.md"
    for path in (generated_json, generated_md, benchmark_json_path, benchmark_md_path):
        if not path.is_file():
            raise FreshnessError(f"missing required file: {path}")

    problems: list[str] = []

    if _load_json(generated_json) != _load_json(benchmark_json_path):
        diff = difflib.unified_diff(
            json.dumps(_load_json(benchmark_json_path), indent=2, sort_keys=True).splitlines(),
            json.dumps(_load_json(generated_json), indent=2, sort_keys=True).splitlines(),
            fromfile=str(benchmark_json_path),
            tofile=str(generated_json),
            lineterm="",
        )
        problems.append("\n".join(diff))

    committed_md = _load_lines(benchmark_md_path)
    fresh_md = _load_lines(generated_md)
    if committed_md != fresh_md:
        diff = difflib.unified_diff(
            committed_md,
            fresh_md,
            fromfile=str(benchmark_md_path),
            tofile=str(generated_md),
            lineterm="",
        )
        problems.append("\n".join(diff))

    return problems


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the committed benchmark snapshot matches a freshly generated one. "
            "Point --generated at the benchmark-matrix directory of a portfolio run."
        )
    )
    parser.add_argument("--generated", required=True, type=Path)
    parser.add_argument(
        "--benchmark-json",
        default=Path("docs/release_benchmark_matrix.json"),
        type=Path,
    )
    parser.add_argument(
        "--benchmark-md",
        default=Path("docs/RELEASE_BENCHMARK.md"),
        type=Path,
    )
    args = parser.parse_args()

    try:
        problems = check_benchmark_freshness(
            generated_dir=args.generated,
            benchmark_json_path=args.benchmark_json,
            benchmark_md_path=args.benchmark_md,
        )
    except FreshnessError as exc:
        print(f"Benchmark freshness check failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    if problems:
        print("Committed benchmark snapshot is stale.", file=sys.stderr)
        for problem in problems:
            print(problem, file=sys.stderr)
        print(
            "\nRegenerate with `verisec portfolio` and publish the artifacts verbatim; "
            "never hand-edit the numbers.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    print("Benchmark snapshot is current.")


if __name__ == "__main__":
    main()
