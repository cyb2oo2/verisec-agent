import json
from pathlib import Path

from verisec_agent.partition_audit import run_partition_audit


def test_partition_audit_passes_for_disjoint_cases(tmp_path: Path) -> None:
    holdout = _write_cases(
        tmp_path / "holdout.json",
        [
            {
                "id": "holdout-case",
                "repo_url": "https://example.test/holdout.git",
                "base_ref": "base-a",
                "head_ref": "head-a",
                "metadata": {"cve": "CVE-2099-0001"},
            }
        ],
    )
    measured = _write_cases(
        tmp_path / "measured.json",
        [
            {
                "id": "measured-case",
                "repo_url": "https://example.test/measured.git",
                "base_ref": "base-b",
                "head_ref": "head-b",
                "metadata": {"cve": "CVE-2099-0002"},
            }
        ],
    )

    result = run_partition_audit(
        cases_path=holdout,
        reference_paths=(measured,),
        output_dir=tmp_path / "audit",
    )

    assert result["passed"] is True
    assert result["summary"]["overlap_count"] == 0
    assert (tmp_path / "audit" / "partition_audit.json").exists()
    assert (tmp_path / "audit" / "partition_audit.md").exists()


def test_partition_audit_reports_advisory_and_source_overlap(tmp_path: Path) -> None:
    shared = {
        "repo_url": "https://example.test/project.git",
        "base_ref": "base",
        "head_ref": "head",
        "metadata": {"cve": "CVE-2099-0001"},
    }
    holdout = _write_cases(
        tmp_path / "holdout.json",
        [{"id": "holdout-case", **shared}],
    )
    measured = _write_cases(
        tmp_path / "measured.json",
        [{"id": "renamed-case", **shared}],
    )

    result = run_partition_audit(
        cases_path=holdout,
        reference_paths=(measured,),
    )

    assert result["passed"] is False
    assert result["summary"]["overlapping_case_count"] == 1
    assert result["summary"]["overlap_count"] == 1
    reasons = result["overlaps"][0]["reasons"]
    assert "cve:cve-2099-0001" in reasons
    assert any(reason.startswith("source-pair:") for reason in reasons)


def _write_cases(path: Path, cases: list[dict[str, object]]) -> Path:
    path.write_text(json.dumps({"cases": cases}), encoding="utf-8")
    return path
