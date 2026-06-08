from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inline scanner-run case artifacts into a portable baseline JSON."
    )
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    frozen = freeze_scanner_results(args.results)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(frozen, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def freeze_scanner_results(results_path: Path) -> dict[str, Any]:
    manifest = json.loads(results_path.read_text(encoding="utf-8"))
    base_dir = results_path.parent
    adapter = str(manifest.get("adapter") or manifest.get("tool_name") or "")
    frozen_cases = []
    for raw_case in manifest.get("cases", ()):
        if not isinstance(raw_case, dict):
            continue
        frozen_case = {
            key: raw_case[key]
            for key in (
                "id",
                "case_id",
                "status",
                "adapter",
                "tool_name",
                "skip_reason",
                "error",
                "materialized_from",
            )
            if key in raw_case
        }
        diff_path = raw_case.get("diff_path")
        if diff_path:
            resolved_diff = Path(str(diff_path))
            if not resolved_diff.is_absolute():
                resolved_diff = base_dir / resolved_diff
            if resolved_diff.exists():
                frozen_case["diff"] = resolved_diff.read_text(
                    encoding="utf-8",
                    errors="replace",
                )
                frozen_case["frozen_diff_source"] = resolved_diff.name
        artifact = raw_case.get("artifact")
        if artifact and str(raw_case.get("status", "completed")) == "completed":
            payload = json.loads((base_dir / str(artifact)).read_text(encoding="utf-8"))
            _inline_payload(frozen_case, adapter=adapter, payload=payload)
        frozen_cases.append(frozen_case)

    return {
        "label": manifest.get("label"),
        "adapter": adapter,
        "tool_name": manifest.get("tool_name") or adapter,
        "command_source_sequence_template": manifest.get(
            "command_source_sequence_template",
            (),
        ),
        "executable": _portable_executable(manifest.get("executable")),
        "frozen_from": str(results_path),
        "summary": manifest.get("summary", {}),
        "cases": frozen_cases,
    }


def _inline_payload(
    frozen_case: dict[str, Any],
    *,
    adapter: str,
    payload: dict[str, Any],
) -> None:
    if adapter in {"codeql", "sarif"}:
        frozen_case["runs"] = payload.get("runs", [])
    elif adapter == "semgrep":
        frozen_case["results"] = payload.get("results", [])
    else:
        frozen_case["payload"] = payload


def _portable_executable(value: Any) -> str | None:
    if value is None:
        return None
    raw_value = str(value)
    path = Path(raw_value)
    if path.name and (path.is_absolute() or "\\" in raw_value or "/" in raw_value):
        return path.name
    return raw_value


if __name__ == "__main__":
    main()
