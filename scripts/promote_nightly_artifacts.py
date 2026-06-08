from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path, PurePosixPath
from typing import Any

from freeze_scanner_results import freeze_scanner_results

DEFAULT_PROMOTIONS = {
    "semgrep-oss-seed-live": "semgrep_oss_seed.json",
    "semgrep-negative-controls-live": "semgrep_negative_controls.json",
    "codeql-oss-seed-live": "codeql_oss_seed_frozen.json",
    "codeql-negative-controls-live": "codeql_negative_controls_frozen.json",
}


class PromotionError(RuntimeError):
    pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Promote a passed live nightly VeriSec portfolio into release artifacts."
    )
    parser.add_argument("--nightly-dir", required=True, type=Path)
    parser.add_argument(
        "--attestation",
        required=True,
        type=Path,
        help="Path to attestation.json or a directory containing attestation.json.",
    )
    parser.add_argument("--baselines-dir", default=Path("examples/baselines"), type=Path)
    parser.add_argument("--release-dir", type=Path)
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
    parser.add_argument("--out", default=Path("verisec-runs/nightly-promotion"), type=Path)
    args = parser.parse_args()

    try:
        result = promote_nightly_artifacts(
            nightly_dir=args.nightly_dir,
            attestation_path=args.attestation,
            baselines_dir=args.baselines_dir,
            release_dir=args.release_dir,
            benchmark_json_path=args.benchmark_json,
            benchmark_md_path=args.benchmark_md,
            output_dir=args.out,
        )
    except PromotionError as exc:
        parser.error(str(exc))
    print(
        "Nightly promotion complete: "
        f"{len(result['promotions'])} scanner artifact(s), "
        f"benchmark updated: {bool(result.get('benchmark'))}."
    )
    print(f"Promotion: {args.out.resolve()}")


def promote_nightly_artifacts(
    *,
    nightly_dir: Path,
    attestation_path: Path,
    baselines_dir: Path,
    release_dir: Path | None = None,
    benchmark_json_path: Path | None = None,
    benchmark_md_path: Path | None = None,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    nightly_dir = nightly_dir.resolve()
    baselines_dir = baselines_dir.resolve()
    _require_passed_portfolio(nightly_dir / "portfolio.json", label="nightly portfolio")
    resolved_attestation = _attestation_json_path(attestation_path)
    _require_passed_attestation(resolved_attestation)

    baselines_dir.mkdir(parents=True, exist_ok=True)
    promotions = [
        _promote_scanner_artifact(
            nightly_dir=nightly_dir,
            baselines_dir=baselines_dir,
            label=label,
            target_name=target_name,
        )
        for label, target_name in DEFAULT_PROMOTIONS.items()
    ]

    benchmark = None
    if release_dir is not None:
        if benchmark_json_path is None or benchmark_md_path is None:
            raise PromotionError("benchmark_json_path and benchmark_md_path are required.")
        benchmark = _promote_benchmark_snapshot(
            release_dir=release_dir.resolve(),
            benchmark_json_path=benchmark_json_path.resolve(),
            benchmark_md_path=benchmark_md_path.resolve(),
        )

    result = {
        "passed": True,
        "nightly_dir": str(nightly_dir),
        "nightly_portable_path": _portable_workspace_path(nightly_dir),
        "attestation_path": str(resolved_attestation.resolve()),
        "attestation_portable_path": _portable_workspace_path(resolved_attestation),
        "baselines_dir": str(baselines_dir),
        "baselines_portable_path": _portable_workspace_path(baselines_dir),
        "promotions": promotions,
        "benchmark": benchmark,
    }
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "promotion.json").write_text(
            json.dumps(result, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        (output_dir / "promotion.md").write_text(
            render_promotion_markdown(result),
            encoding="utf-8",
        )
    return result


def render_promotion_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# VeriSec Nightly Promotion",
        "",
        f"- Nightly portfolio: `{result.get('nightly_portable_path', result['nightly_dir'])}`",
        f"- Attestation: `{result.get('attestation_portable_path', result['attestation_path'])}`",
        f"- Baselines: `{result.get('baselines_portable_path', result['baselines_dir'])}`",
        f"- Benchmark updated: {'yes' if result.get('benchmark') else 'no'}",
        "",
        "## Scanner Artifacts",
        "",
        "| Label | Target | Bytes | SHA-256 |",
        "| --- | --- | ---: | --- |",
    ]
    for promotion in result["promotions"]:
        lines.append(
            "| "
            f"{promotion['label']} | "
            f"`{promotion.get('target_portable_path', promotion['target_path'])}` | "
            f"{promotion['bytes']} | "
            f"`{promotion['sha256']}` |"
        )
    if result.get("benchmark"):
        benchmark = result["benchmark"]
        markdown_path = benchmark.get("markdown_portable_path", benchmark["markdown_path"])
        lines.extend(
            [
                "",
                "## Benchmark Snapshot",
                "",
                f"- JSON: `{benchmark.get('json_portable_path', benchmark['json_path'])}`",
                f"- Markdown: `{markdown_path}`",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _promote_scanner_artifact(
    *,
    nightly_dir: Path,
    baselines_dir: Path,
    label: str,
    target_name: str,
) -> dict[str, Any]:
    scanner_results_path = nightly_dir / "scanner-runs" / label / "scanner_results.json"
    if not scanner_results_path.exists():
        raise PromotionError(f"Missing nightly scanner result for {label}: {scanner_results_path}")
    frozen = freeze_scanner_results(scanner_results_path)
    portable_source_path = _portable_scanner_result_path(label)
    frozen["frozen_from"] = portable_source_path
    target_path = baselines_dir / target_name
    target_path.write_text(
        json.dumps(frozen, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    entry = _artifact_entry(target_path)
    return {
        "label": label,
        "source_path": str(scanner_results_path.resolve()),
        "source_portable_path": portable_source_path,
        "target_path": str(target_path.resolve()),
        "target_portable_path": _portable_workspace_path(target_path),
        "adapter": frozen.get("adapter"),
        "case_count": len(frozen.get("cases", ())),
        **entry,
    }


def _promote_benchmark_snapshot(
    *,
    release_dir: Path,
    benchmark_json_path: Path,
    benchmark_md_path: Path,
) -> dict[str, Any]:
    _require_passed_portfolio(release_dir / "portfolio.json", label="release portfolio")
    source_json = release_dir / "benchmark-matrix" / "benchmark_matrix.json"
    source_md = release_dir / "benchmark-matrix" / "benchmark_matrix.md"
    if not source_json.exists() or not source_md.exists():
        raise PromotionError(f"Release benchmark matrix does not exist under: {release_dir}")
    benchmark_json_path.parent.mkdir(parents=True, exist_ok=True)
    benchmark_md_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_json, benchmark_json_path)
    shutil.copyfile(source_md, benchmark_md_path)
    json_entry = _artifact_entry(benchmark_json_path)
    md_entry = _artifact_entry(benchmark_md_path)
    return {
        "release_dir": str(release_dir),
        "release_portable_path": _portable_workspace_path(release_dir),
        "json_path": str(benchmark_json_path),
        "json_portable_path": _portable_workspace_path(benchmark_json_path),
        "json_bytes": json_entry["bytes"],
        "json_sha256": json_entry["sha256"],
        "markdown_path": str(benchmark_md_path),
        "markdown_portable_path": _portable_workspace_path(benchmark_md_path),
        "markdown_bytes": md_entry["bytes"],
        "markdown_sha256": md_entry["sha256"],
    }


def _require_passed_portfolio(path: Path, *, label: str) -> None:
    if not path.exists():
        raise PromotionError(f"Missing {label}: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not payload.get("passed"):
        failures = payload.get("failures", ())
        raise PromotionError(f"{label} did not pass: {failures}")


def _require_passed_attestation(path: Path) -> None:
    if not path.exists():
        raise PromotionError(f"Missing attestation: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not payload.get("passed"):
        failures = payload.get("failures", ())
        raise PromotionError(f"Attestation did not pass: {failures}")


def _attestation_json_path(path: Path) -> Path:
    if path.is_dir():
        return path / "attestation.json"
    return path


def _artifact_entry(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _portable_scanner_result_path(label: str) -> str:
    return str(PurePosixPath("scanner-runs") / label / "scanner_results.json")


def _portable_workspace_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return str(resolved)


if __name__ == "__main__":
    main()
