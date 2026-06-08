import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROMOTION_LABELS = {
    "semgrep-oss-seed-live": "semgrep",
    "semgrep-negative-controls-live": "semgrep",
    "codeql-oss-seed-live": "codeql",
    "codeql-negative-controls-live": "codeql",
}


def test_promote_nightly_artifacts_freezes_scanners_and_release_docs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_promotion_module()
    monkeypatch.chdir(tmp_path)
    nightly_dir = tmp_path / "nightly"
    attestation_dir = tmp_path / "attestation"
    baselines_dir = tmp_path / "baselines"
    release_dir = tmp_path / "release"
    benchmark_json = tmp_path / "docs" / "release_benchmark_matrix.json"
    benchmark_md = tmp_path / "docs" / "RELEASE_BENCHMARK.md"
    output_dir = tmp_path / "promotion"

    _write_json(nightly_dir / "portfolio.json", {"passed": True, "failures": []})
    _write_json(attestation_dir / "attestation.json", {"passed": True, "failures": []})
    for label, adapter in PROMOTION_LABELS.items():
        _write_scanner_run(nightly_dir=nightly_dir, label=label, adapter=adapter)
    _write_release_benchmark(release_dir)

    result = module.promote_nightly_artifacts(
        nightly_dir=nightly_dir,
        attestation_path=attestation_dir,
        baselines_dir=baselines_dir,
        release_dir=release_dir,
        benchmark_json_path=benchmark_json,
        benchmark_md_path=benchmark_md,
        output_dir=output_dir,
    )

    assert result["passed"] is True
    assert len(result["promotions"]) == 4
    assert (output_dir / "promotion.json").exists()
    assert (output_dir / "promotion.md").exists()
    assert json.loads(benchmark_json.read_text(encoding="utf-8")) == {"systems": []}
    assert benchmark_md.read_text(encoding="utf-8") == "# Matrix\n"

    semgrep = _load_json(baselines_dir / "semgrep_oss_seed.json")
    codeql = _load_json(baselines_dir / "codeql_oss_seed_frozen.json")
    semgrep_check_id = semgrep["cases"][0]["results"][0]["check_id"]

    assert semgrep_check_id == "python.lang.security.audit.subprocess-shell-true"
    assert codeql["cases"][0]["runs"][0]["tool"]["driver"]["name"] == "CodeQL"
    assert semgrep["frozen_from"] == (
        "scanner-runs/semgrep-oss-seed-live/scanner_results.json"
    )
    assert codeql["frozen_from"] == (
        "scanner-runs/codeql-oss-seed-live/scanner_results.json"
    )

    for baseline_path in baselines_dir.glob("*.json"):
        baseline_text = baseline_path.read_text(encoding="utf-8")
        assert str(tmp_path) not in baseline_text

    promotion_text = (output_dir / "promotion.md").read_text(encoding="utf-8")
    assert str(tmp_path) not in promotion_text
    assert "`baselines/semgrep_oss_seed.json`" in promotion_text


def test_promote_nightly_artifacts_rejects_failed_attestation(tmp_path: Path) -> None:
    module = _load_promotion_module()
    nightly_dir = tmp_path / "nightly"
    attestation_path = tmp_path / "attestation.json"

    _write_json(nightly_dir / "portfolio.json", {"passed": True, "failures": []})
    _write_json(
        attestation_path,
        {"passed": False, "failures": [{"path": "artifact.json"}]},
    )

    with pytest.raises(module.PromotionError, match="Attestation did not pass"):
        module.promote_nightly_artifacts(
            nightly_dir=nightly_dir,
            attestation_path=attestation_path,
            baselines_dir=tmp_path / "baselines",
        )


def _load_promotion_module() -> ModuleType:
    scripts_dir = ROOT / "scripts"
    module_path = scripts_dir / "promote_nightly_artifacts.py"
    sys.path.insert(0, str(scripts_dir))
    try:
        spec = importlib.util.spec_from_file_location(
            "promote_nightly_artifacts_under_test",
            module_path,
        )
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(scripts_dir))


def _write_scanner_run(*, nightly_dir: Path, label: str, adapter: str) -> None:
    run_dir = nightly_dir / "scanner-runs" / label
    artifact_dir = run_dir / "artifacts" / "case-1"
    diff_path = artifact_dir / "case.diff"
    artifact_name = "scanner.sarif" if adapter == "codeql" else "scanner.json"
    artifact_path = artifact_dir / artifact_name

    diff_path.parent.mkdir(parents=True, exist_ok=True)
    diff_path.write_text(
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,1 +1,1 @@\n"
        "-old\n"
        "+new\n",
        encoding="utf-8",
    )
    _write_json(artifact_path, _scanner_payload(adapter))
    _write_json(
        run_dir / "scanner_results.json",
        {
            "label": label,
            "adapter": adapter,
            "tool_name": adapter,
            "executable": str(nightly_dir / "tools" / f"{adapter}.exe"),
            "summary": {"case_count": 1, "completed_count": 1},
            "cases": [
                {
                    "id": f"{label}-case",
                    "status": "completed",
                    "artifact": f"artifacts/case-1/{artifact_name}",
                    "diff_path": "artifacts/case-1/case.diff",
                }
            ],
        },
    )


def _scanner_payload(adapter: str) -> dict[str, object]:
    if adapter == "codeql":
        return {"runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": []}]}
    return {
        "results": [
            {
                "check_id": "python.lang.security.audit.subprocess-shell-true",
                "path": "app.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"message": "shell=True", "severity": "WARNING"},
            }
        ]
    }


def _write_release_benchmark(release_dir: Path) -> None:
    _write_json(release_dir / "portfolio.json", {"passed": True, "failures": []})
    _write_json(release_dir / "benchmark-matrix" / "benchmark_matrix.json", {"systems": []})
    (release_dir / "benchmark-matrix").mkdir(parents=True, exist_ok=True)
    (release_dir / "benchmark-matrix" / "benchmark_matrix.md").write_text(
        "# Matrix\n",
        encoding="utf-8",
    )


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))
