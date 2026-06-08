import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_release_portfolio_uses_frozen_codeql_artifacts() -> None:
    manifest = _load_manifest("verisec_portfolio.json")
    baselines = _baselines_by_label(manifest)

    semgrep_negative = baselines["semgrep-negative-controls"]
    codeql_oss = baselines["codeql-oss-seed-live"]
    codeql_negative = baselines["codeql-negative-controls-live"]

    assert semgrep_negative["cases"] == "examples/scanner_negative_control_cases.json"
    assert codeql_oss["run"] is True
    assert codeql_oss["reuse_results"] is True
    assert codeql_oss["reuse_from"] == "examples/baselines/codeql_oss_seed_frozen.json"
    assert codeql_negative["run"] is True
    assert codeql_negative["reuse_results"] is True
    assert (
        codeql_negative["reuse_from"]
        == "examples/baselines/codeql_negative_controls_frozen.json"
    )


def test_nightly_portfolio_runs_live_scanners_on_isolated_controls() -> None:
    manifest = _load_manifest("verisec_portfolio.nightly.json")
    baselines = _baselines_by_label(manifest)

    for label in (
        "semgrep-oss-seed-live",
        "semgrep-negative-controls-live",
        "codeql-oss-seed-live",
        "codeql-negative-controls-live",
    ):
        baseline = baselines[label]
        assert baseline["run"] is True
        assert baseline["reuse_results"] is False
        assert "reuse_from" not in baseline

    assert (
        baselines["semgrep-negative-controls-live"]["cases"]
        == "examples/scanner_negative_control_cases.json"
    )
    assert (
        baselines["codeql-negative-controls-live"]["cases"]
        == "examples/scanner_negative_control_cases.json"
    )


def test_release_semgrep_negative_baseline_matches_scanner_controls() -> None:
    scanner_cases = _case_ids(_load_manifest("examples/scanner_negative_control_cases.json"))
    baseline = _load_manifest("examples/baselines/semgrep_negative_controls.json")
    baseline_cases = _case_ids(baseline)

    assert baseline_cases == scanner_cases


def _load_manifest(name: str) -> dict[str, object]:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def _baselines_by_label(manifest: dict[str, object]) -> dict[str, dict[str, object]]:
    baselines = manifest["scanner_baselines"]
    assert isinstance(baselines, list)
    return {str(item["label"]): item for item in baselines}


def _case_ids(manifest: dict[str, object]) -> tuple[str, ...]:
    cases = manifest["cases"]
    assert isinstance(cases, list)
    return tuple(str(item["id"]) for item in cases)
