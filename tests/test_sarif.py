import json
from pathlib import Path

from verisec_agent.agent import ReviewAgent
from verisec_agent.bundle import BundleWriter
from verisec_agent.config import ReviewConfig
from verisec_agent.models import Finding, ReviewReport
from verisec_agent.sarif import render_sarif_report, write_sarif_report


def test_render_sarif_includes_finding_location_and_rule() -> None:
    finding = Finding(
        finding_id="py-shell-true@app.py:2-4",
        rule_id="py-shell-true",
        title="Shell execution path introduced",
        severity="high",
        confidence=0.8,
        file_path="app.py",
        start_line=2,
        end_line=4,
        evidence="+3: subprocess.run(x, shell=True)",
        source_context=None,
        risk="Command injection",
        fix_guidance="Use shell=False",
        recommended_validation=("static command-injection rules",),
        false_positive_notes="",
        dataflow_steps=("parameter `x` treated as attacker-controlled",),
        analysis_scope="file",
    )
    report = ReviewReport(
        subject="demo.diff",
        repo_path=".",
        diff_path="inputs/diff.patch",
        findings=(finding,),
        verification=(),
        validation_plan=(),
        bundle_path="verisec-runs/demo",
        summary={"finding_count": 1},
    )

    sarif = render_sarif_report(report)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "VeriSec Agent"
    assert run["tool"]["driver"]["rules"][0]["id"] == "py-shell-true"
    result = run["results"][0]
    assert result["ruleId"] == "py-shell-true"
    assert result["level"] == "error"
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 2
    assert region["endLine"] == 4
    assert result["partialFingerprints"]["verisecFindingId"] == finding.finding_id
    assert result["properties"]["verisec.confidence"] == 0.8


def test_bundle_write_report_emits_sarif(tmp_path: Path) -> None:
    report = ReviewReport(
        subject="empty",
        repo_path=str(tmp_path),
        diff_path="diff.patch",
        findings=(),
        verification=(),
        validation_plan=(),
        bundle_path=str(tmp_path / "bundle"),
        summary={"finding_count": 0},
    )
    writer = BundleWriter(tmp_path / "bundle")
    writer.prepare()
    writer.write_report(report)
    sarif_path = tmp_path / "bundle" / "report.sarif"
    assert sarif_path.is_file()
    payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert payload["runs"][0]["results"] == []


def test_review_bundle_includes_sarif(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import subprocess\n"
        "def run(user_input):\n"
        "    return subprocess.run(user_input, shell=True)\n",
        encoding="utf-8",
    )
    diff_path = tmp_path / "change.diff"
    diff_path.write_text(
        """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
 import subprocess
 def run(user_input):
+    return subprocess.run(user_input, shell=True)
""",
        encoding="utf-8",
    )
    out = tmp_path / "bundle"
    ReviewAgent(ReviewConfig()).review(
        diff_path=diff_path,
        repo_path=tmp_path,
        output_dir=out,
    )
    sarif_path = out / "report.sarif"
    assert sarif_path.is_file()
    payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert payload["runs"][0]["results"]
    assert payload["runs"][0]["results"][0]["ruleId"] == "py-shell-true"


def test_write_sarif_report_roundtrip(tmp_path: Path) -> None:
    report = ReviewReport(
        subject="x",
        repo_path=str(tmp_path),
        diff_path="d",
        findings=(),
        verification=(),
        validation_plan=(),
        bundle_path=str(tmp_path),
        summary={},
    )
    path = write_sarif_report(report, tmp_path / "out.sarif")
    assert path.is_file()
