import json
from pathlib import Path

from verisec_agent.failure_analysis import run_failure_analysis


def test_failure_analysis_classifies_semantic_confusion_and_miss(
    tmp_path: Path,
) -> None:
    evaluation_path = tmp_path / "evaluation.json"
    evaluation_path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "case_id": "confused",
                        "status": "completed",
                        "verification_count": 1,
                        "verification_passed": 1,
                        "expected_finding_misses": [
                            {
                                "rule_id": "expected-rule",
                                "file_path": "app.py",
                            }
                        ],
                        "finding_labels": [
                            {
                                "finding_id": "wrong@app.py:1",
                                "rule_id": "wrong-rule",
                                "file_path": "app.py",
                                "role": "unexpected",
                            }
                        ],
                    },
                    {
                        "case_id": "missed",
                        "status": "completed",
                        "verification_count": 1,
                        "verification_passed": 1,
                        "expected_finding_misses": [
                            {
                                "rule_id": "expected-rule",
                                "file_path": "other.py",
                            }
                        ],
                        "finding_labels": [],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    result = run_failure_analysis(
        evaluation_path=evaluation_path,
        output_dir=tmp_path / "analysis",
    )

    assert result["summary"]["case_failure_count"] == 2
    assert result["summary"]["verified_patch_failure_count"] == 2
    assert result["summary"]["taxonomy"] == {
        "semantic-rule-confusion": 1,
        "undetected-labeled-location": 1,
    }
    assert (tmp_path / "analysis" / "failure_analysis.json").exists()
    assert (tmp_path / "analysis" / "failure_analysis.md").exists()
