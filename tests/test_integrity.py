import hashlib
from pathlib import Path

import pytest

from verisec_agent.integrity import (
    ArtifactSpec,
    IntegrityError,
    attest_artifact_index,
    build_artifact_index,
    render_artifact_index_markdown,
    render_attestation_markdown,
    write_artifact_index,
)


def test_write_artifact_index_records_hashes_and_environment(tmp_path: Path) -> None:
    artifact = tmp_path / "evaluation.json"
    artifact.write_text('{"summary": {}}', encoding="utf-8")
    expected_hash = hashlib.sha256(artifact.read_bytes()).hexdigest()

    index = write_artifact_index(
        output_dir=tmp_path / "index",
        root_dir=tmp_path,
        artifacts=(ArtifactSpec("demo", "evaluation-json", artifact),),
        manifest_path=tmp_path / "portfolio.json",
        command_line="verisec portfolio --manifest portfolio.json",
        repo_path=tmp_path,
    )

    assert index["command"] == "verisec portfolio --manifest portfolio.json"
    assert index["artifacts"][0]["path"] == "evaluation.json"
    assert index["artifacts"][0]["sha256"] == expected_hash
    assert index["environment"]["python_version"]
    assert (tmp_path / "index" / "artifact_index.json").exists()
    markdown = (tmp_path / "index" / "artifact_index.md").read_text(encoding="utf-8")
    assert "VeriSec Artifact Index" in markdown
    assert expected_hash in markdown


def test_build_artifact_index_rejects_missing_artifact(tmp_path: Path) -> None:
    with pytest.raises(IntegrityError, match="Artifact does not exist"):
        build_artifact_index(
            root_dir=tmp_path,
            artifacts=(ArtifactSpec("demo", "evaluation-json", tmp_path / "missing.json"),),
        )


def test_attest_artifact_index_passes_for_unchanged_artifacts(tmp_path: Path) -> None:
    artifact = tmp_path / "portfolio.json"
    artifact.write_text('{"passed": true}', encoding="utf-8")
    index = write_artifact_index(
        output_dir=tmp_path / "index",
        root_dir=tmp_path,
        artifacts=(ArtifactSpec("portfolio", "portfolio-json", artifact),),
    )

    result = attest_artifact_index(
        index_path=tmp_path / "index" / "artifact_index.json",
        output_dir=tmp_path / "attest",
    )

    assert index["artifacts"][0]["sha256"] == result["artifacts"][0]["actual_sha256"]
    assert result["passed"] is True
    assert result["failure_count"] == 0
    assert (tmp_path / "attest" / "attestation.json").exists()
    markdown = (tmp_path / "attest" / "attestation.md").read_text(encoding="utf-8")
    assert "VeriSec Attestation: passed" in markdown


def test_attest_artifact_index_reports_hash_mismatch(tmp_path: Path) -> None:
    artifact = tmp_path / "gate.json"
    artifact.write_text('{"passed": true}', encoding="utf-8")
    write_artifact_index(
        output_dir=tmp_path / "index",
        root_dir=tmp_path,
        artifacts=(ArtifactSpec("demo", "gate-json", artifact),),
    )
    artifact.write_text('{"passed": false}', encoding="utf-8")

    result = attest_artifact_index(index_path=tmp_path / "index" / "artifact_index.json")

    assert result["passed"] is False
    assert result["failure_count"] >= 1
    assert any("SHA-256" in failure for failure in result["failures"])


def test_attest_artifact_index_reports_missing_artifact(tmp_path: Path) -> None:
    artifact = tmp_path / "evaluation.json"
    artifact.write_text('{"summary": {}}', encoding="utf-8")
    write_artifact_index(
        output_dir=tmp_path / "index",
        root_dir=tmp_path,
        artifacts=(ArtifactSpec("demo", "evaluation-json", artifact),),
    )
    artifact.unlink()

    result = attest_artifact_index(index_path=tmp_path / "index" / "artifact_index.json")

    assert result["passed"] is False
    assert "missing" in result["failures"][0]


def test_render_artifact_index_markdown_formats_artifacts(tmp_path: Path) -> None:
    artifact = tmp_path / "gate.json"
    artifact.write_text('{"passed": true}', encoding="utf-8")
    index = build_artifact_index(
        root_dir=tmp_path,
        artifacts=(ArtifactSpec("demo", "gate-json", artifact),),
    )

    markdown = render_artifact_index_markdown(index)

    assert "| demo | gate-json | `gate.json` |" in markdown


def test_render_attestation_markdown_formats_failures(tmp_path: Path) -> None:
    result = {
        "passed": False,
        "index_path": str(tmp_path / "artifact_index.json"),
        "root_dir": str(tmp_path),
        "artifact_count": 1,
        "failure_count": 1,
        "failures": ("demo gate-json SHA-256 changed",),
        "artifacts": (
            {
                "label": "demo",
                "kind": "gate-json",
                "path": "gate.json",
                "passed": False,
                "actual_sha256": "abc",
            },
        ),
    }

    markdown = render_attestation_markdown(result)

    assert "VeriSec Attestation: failed" in markdown
    assert "demo gate-json SHA-256 changed" in markdown
