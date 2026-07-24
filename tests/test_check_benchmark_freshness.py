import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]

MATRIX = {
    "claim_boundaries": ["Curated benchmark of 3 cases."],
    "summary": {"system_count": 1},
    "systems": [
        {
            "label": "VeriSec Agent",
            "status": "measured",
            "metrics": {"positive_cases": 3, "negative_controls": 12},
            "notes": "example",
        }
    ],
}
MARKDOWN = "# VeriSec Benchmark Matrix\n\n| System |\n| --- |\n| VeriSec Agent |\n"


def test_reports_no_problems_when_snapshot_is_current(tmp_path: Path) -> None:
    module = _load_module()
    generated, committed_json, committed_md = _write_pair(tmp_path, MATRIX, MARKDOWN)

    problems = module.check_benchmark_freshness(
        generated_dir=generated,
        benchmark_json_path=committed_json,
        benchmark_md_path=committed_md,
    )

    assert problems == []


def test_ignores_line_ending_differences(tmp_path: Path) -> None:
    """Git stores the snapshot LF-normalized while the generator emits CRLF on Windows.

    A byte comparison would fail every run for a reason unrelated to staleness.
    """
    module = _load_module()
    generated, committed_json, committed_md = _write_pair(tmp_path, MATRIX, MARKDOWN)
    committed_md.write_bytes(MARKDOWN.replace("\n", "\r\n").encode("utf-8"))

    problems = module.check_benchmark_freshness(
        generated_dir=generated,
        benchmark_json_path=committed_json,
        benchmark_md_path=committed_md,
    )

    assert problems == []


def test_ignores_json_key_ordering(tmp_path: Path) -> None:
    module = _load_module()
    generated, committed_json, committed_md = _write_pair(tmp_path, MATRIX, MARKDOWN)
    committed_json.write_text(json.dumps(MATRIX, indent=4, sort_keys=False), encoding="utf-8")

    problems = module.check_benchmark_freshness(
        generated_dir=generated,
        benchmark_json_path=committed_json,
        benchmark_md_path=committed_md,
    )

    assert problems == []


def test_detects_stale_metric(tmp_path: Path) -> None:
    module = _load_module()
    stale = json.loads(json.dumps(MATRIX))
    stale["systems"][0]["metrics"]["negative_controls"] = 11
    generated, committed_json, committed_md = _write_pair(tmp_path, MATRIX, MARKDOWN)
    committed_json.write_text(json.dumps(stale, indent=2, sort_keys=True), encoding="utf-8")

    problems = module.check_benchmark_freshness(
        generated_dir=generated,
        benchmark_json_path=committed_json,
        benchmark_md_path=committed_md,
    )

    assert len(problems) == 1
    assert "negative_controls" in problems[0]


def test_detects_stale_markdown(tmp_path: Path) -> None:
    module = _load_module()
    generated, committed_json, committed_md = _write_pair(tmp_path, MATRIX, MARKDOWN)
    committed_md.write_text(MARKDOWN.replace("VeriSec Agent |", "Stale Label |"), encoding="utf-8")

    problems = module.check_benchmark_freshness(
        generated_dir=generated,
        benchmark_json_path=committed_json,
        benchmark_md_path=committed_md,
    )

    assert len(problems) == 1
    assert "Stale Label" in problems[0]


def test_raises_when_a_required_file_is_missing(tmp_path: Path) -> None:
    module = _load_module()
    generated, committed_json, committed_md = _write_pair(tmp_path, MATRIX, MARKDOWN)
    committed_md.unlink()

    with pytest.raises(module.FreshnessError, match="missing required file"):
        module.check_benchmark_freshness(
            generated_dir=generated,
            benchmark_json_path=committed_json,
            benchmark_md_path=committed_md,
        )


def _write_pair(tmp_path: Path, matrix: dict, markdown: str) -> tuple[Path, Path, Path]:
    generated = tmp_path / "benchmark-matrix"
    generated.mkdir(parents=True, exist_ok=True)
    (generated / "benchmark_matrix.json").write_text(
        json.dumps(matrix, indent=2, sort_keys=True), encoding="utf-8"
    )
    (generated / "benchmark_matrix.md").write_text(markdown, encoding="utf-8")

    docs = tmp_path / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    committed_json = docs / "release_benchmark_matrix.json"
    committed_md = docs / "RELEASE_BENCHMARK.md"
    committed_json.write_text(json.dumps(matrix, indent=2, sort_keys=True), encoding="utf-8")
    committed_md.write_text(markdown, encoding="utf-8")
    return generated, committed_json, committed_md


def _load_module() -> ModuleType:
    scripts_dir = ROOT / "scripts"
    module_path = scripts_dir / "check_benchmark_freshness.py"
    sys.path.insert(0, str(scripts_dir))
    try:
        spec = importlib.util.spec_from_file_location(
            "check_benchmark_freshness_under_test",
            module_path,
        )
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(scripts_dir))
