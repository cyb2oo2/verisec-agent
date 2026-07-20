from pathlib import Path

from verisec_agent.cli import build_parser, main
from verisec_agent.models import Finding, ReviewReport, ValidationStep
from verisec_agent.operator import format_review_summary, init_project


def test_init_writes_verisec_toml(tmp_path: Path) -> None:
    result = init_project(target_dir=tmp_path)
    config = tmp_path / "verisec.toml"
    assert config.is_file()
    assert str(config) in result["created"]
    assert "trusted-local" in config.read_text(encoding="utf-8")

    again = init_project(target_dir=tmp_path)
    assert again["created"] == []
    assert str(config) in again["skipped"]

    forced = init_project(target_dir=tmp_path, force=True)
    assert str(config) in forced["created"]


def test_init_cli(tmp_path: Path) -> None:
    main(["init", "--dir", str(tmp_path)])
    assert (tmp_path / "verisec.toml").is_file()


def test_review_alias_parses() -> None:
    args = build_parser().parse_args(
        ["r", "--diff", "examples/demo.diff", "--repo", ".", "--out", "verisec-runs/x"]
    )
    # argparse stores the invoked alias name; main() normalizes to "review".
    assert args.command in {"review", "r"}
    assert args.diff == Path("examples/demo.diff")


def test_format_review_summary_lists_findings_and_next_steps() -> None:
    finding = Finding(
        finding_id="py-shell-true@app.py:1-3",
        rule_id="py-shell-true",
        title="Shell execution path introduced",
        severity="high",
        confidence=0.82,
        file_path="app.py",
        start_line=1,
        end_line=3,
        evidence="+2: subprocess.run(x, shell=True)",
        source_context=None,
        risk="Command injection",
        fix_guidance="Use shell=False",
        recommended_validation=("static command-injection rules",),
        false_positive_notes="",
        analysis_scope="window",
        analysis_notes="Family: general. Mode: introduces-risk.",
    )
    report = ReviewReport(
        subject="demo.diff",
        repo_path=".",
        diff_path="inputs/diff.patch",
        findings=(finding,),
        verification=(),
        validation_plan=(
            ValidationStep(
                finding_id=finding.finding_id,
                objective="Validate shell",
                recommended_check="static command-injection rules",
                status="missing",
            ),
        ),
        bundle_path="verisec-runs/demo",
        summary={
            "finding_count": 1,
            "verification_passed": 0,
            "verification_count": 0,
            "validation_covered": 0,
            "validation_step_count": 1,
            "avg_confidence": 0.82,
        },
    )
    text = format_review_summary(report)
    assert "1 finding(s)" in text
    assert "[high] py-shell-true" in text
    assert "Still missing validation" in text
    assert "report.md" in text
    assert "report.sarif" in text
    assert "Next steps:" in text
    assert "VALIDATION_EVIDENCE" in text
    assert "docs/OPERATOR.md" in text


def test_format_review_summary_explains_empty_findings() -> None:
    report = ReviewReport(
        subject="empty.diff",
        repo_path=".",
        diff_path="inputs/diff.patch",
        findings=(),
        verification=(),
        validation_plan=(),
        bundle_path="verisec-runs/empty",
        summary={
            "finding_count": 0,
            "verification_passed": 0,
            "verification_count": 0,
            "validation_covered": 0,
            "validation_step_count": 0,
            "avg_confidence": 0.0,
        },
    )
    text = format_review_summary(report)
    assert "No security findings were generated." in text
    assert "no Python" in text
