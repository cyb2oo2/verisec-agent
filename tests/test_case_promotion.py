import json
from pathlib import Path

from verisec_agent.case_promotion import plan_case_promotions
from verisec_agent.cli import build_parser


def test_case_promote_cli_parser_accepts_promotion_inputs() -> None:
    args = build_parser().parse_args(
        [
            "case-promote",
            "--candidates",
            "candidate_cases.json",
            "--evaluation",
            "candidate-eval/evaluation.json",
            "--existing-promoted",
            "promoted_cases.json",
            "--promoted-manifest",
            "new_promoted.json",
        ]
    )

    assert args.command == "case-promote"
    assert args.min_validation_coverage == 1.0
    assert args.min_tool_evidence_rate == 1.0


def test_plan_case_promotions_writes_eligible_manifest(tmp_path: Path) -> None:
    candidates_path = _write_candidate_manifest(tmp_path, include_config=True)
    evaluation_path = tmp_path / "evaluation.json"
    _write_json(
        evaluation_path,
        {
            "cases": [
                {
                    "case_id": "candidate-shell",
                    "status": "completed",
                    "finding_count": 1,
                    "verification_count": 1,
                    "verification_passed": 1,
                    "required_failure_count": 0,
                    "policy_blocked_count": 0,
                    "validation_gap_findings": 0,
                    "validation_step_count": 1,
                    "validation_covered": 1,
                    "tool_supported_findings": 1,
                    "expected_findings": [
                        {
                            "rule_id": "py-shell-true",
                            "file_path": "app.py",
                            "severity": "high",
                            "role": "primary",
                        }
                    ],
                    "expected_finding_hits": [
                        {
                            "rule_id": "py-shell-true",
                            "file_path": "app.py",
                            "severity": "high",
                            "role": "primary",
                        }
                    ],
                    "finding_role_counts": {"primary": 1},
                    "unexpected_taxonomy": {},
                    "avg_confidence": 0.82,
                }
            ]
        },
    )

    result = plan_case_promotions(
        candidates_path=candidates_path,
        evaluation_path=evaluation_path,
        output_dir=tmp_path / "promotion",
        promoted_manifest_path=tmp_path / "promoted_cases.json",
    )

    assert result["summary"]["eligible_count"] == 1
    assert result["summary"]["blocked_count"] == 0
    assert result["cases"][0]["status"] == "eligible"
    assert result["cases"][0]["evidence"]["validation_coverage"] == 1.0
    manifest = _load_json(tmp_path / "promoted_cases.json")
    assert manifest["cases"][0]["tags"][0] == "promoted"
    assert "candidate" not in manifest["cases"][0]["tags"]
    assert (tmp_path / "promotion" / "case_promotion.json").exists()
    assert (tmp_path / "promotion" / "case_promotion.md").exists()


def test_plan_case_promotions_blocks_missing_config_and_tracks_existing(
    tmp_path: Path,
) -> None:
    candidates_path = _write_candidate_manifest(tmp_path, include_config=False)
    existing_path = tmp_path / "existing.json"
    _write_json(existing_path, {"cases": [{"id": "candidate-shell"}]})

    result = plan_case_promotions(
        candidates_path=candidates_path,
        existing_promoted_path=existing_path,
    )

    assert result["summary"]["already_promoted_count"] == 1
    assert result["cases"][0]["status"] == "already-promoted"

    _write_json(existing_path, {"cases": []})
    result = plan_case_promotions(
        candidates_path=candidates_path,
        existing_promoted_path=existing_path,
    )

    assert result["summary"]["blocked_count"] == 1
    blockers = result["cases"][0]["blockers"]
    assert "verification config is required for measured promotion" in blockers
    assert "evaluation evidence is required" in blockers


def test_plan_case_promotions_never_promotes_frozen_holdout(
    tmp_path: Path,
) -> None:
    candidates_path = _write_candidate_manifest(tmp_path, include_config=True)
    payload = _load_json(candidates_path)
    payload["cases"][0]["tags"].append("holdout")
    _write_json(candidates_path, payload)

    result = plan_case_promotions(
        candidates_path=candidates_path,
        require_evaluation=False,
    )

    assert result["summary"]["blocked_count"] == 1
    assert (
        "frozen holdout cases cannot be promoted into the measured benchmark"
        in result["cases"][0]["blockers"]
    )


def _write_candidate_manifest(tmp_path: Path, *, include_config: bool) -> Path:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "app.py").write_text("print('demo')\n", encoding="utf-8")
    (tmp_path / "case.diff").write_text(
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,1 +1,1 @@\n"
        "-print('demo')\n"
        "+print('demo')\n",
        encoding="utf-8",
    )
    if include_config:
        (tmp_path / "verisec.toml").write_text(
            "[[verification.commands]]\n"
            "name = \"marker\"\n"
            "command = \"{python} -c \\\"print('ok')\\\"\"\n"
            "capabilities = [\"unit-test\"]\n",
            encoding="utf-8",
        )
    case = {
        "id": "candidate-shell",
        "diff": "case.diff",
        "repo": "repo",
        "metadata": {
            "project": "example/project",
            "language": "python",
            "cve": "CVE-2099-0001",
            "vulnerability_class": "command-injection",
        },
        "expected_findings": [
            {
                "rule_id": "py-shell-true",
                "file_path": "app.py",
                "severity": "high",
                "role": "primary",
            }
        ],
        "tags": ["candidate", "oss", "cve", "python"],
    }
    if include_config:
        case["config"] = "verisec.toml"
    candidates_path = tmp_path / "candidates.json"
    _write_json(candidates_path, {"cases": [case]})
    return candidates_path


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))
