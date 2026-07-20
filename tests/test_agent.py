from pathlib import Path

from verisec_agent.agent import ReviewAgent
from verisec_agent.config import ReviewConfig
from verisec_agent.models import VerificationCommand


def test_agent_writes_review_bundle(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """def run(expr):
    return eval(expr)
""",
        encoding="utf-8",
    )
    diff_path = tmp_path / "demo.diff"
    diff_path.write_text(
        """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
 def run(expr):
+    return eval(expr)
""",
        encoding="utf-8",
    )

    report = ReviewAgent(
        ReviewConfig(
            verification_commands=(
                VerificationCommand(
                    name="unit-tests",
                    command="{python} -c \"print('ok')\"",
                    required=True,
                ),
            )
        )
    ).review(
        diff_path=diff_path,
        repo_path=tmp_path,
        output_dir=tmp_path / "bundle",
    )

    assert report.summary["finding_count"] == 1
    assert report.findings[0].rule_id == "py-eval-exec"
    assert report.findings[0].source_context is not None
    assert report.findings[0].source_context.available is True
    assert "return eval(expr)" in report.findings[0].source_context.snippet()
    assert report.validation_plan[0].status == "missing"
    assert report.validation_plan[0].covered_by == ()
    assert report.validation_plan[0].candidate_tools == ("unit-tests",)
    assert report.summary["validation_missing"] == 2
    assert (tmp_path / "bundle" / "report.json").exists()
    assert (tmp_path / "bundle" / "report.md").exists()
    assert (tmp_path / "bundle" / "trace.jsonl").exists()
    assert (tmp_path / "bundle" / "inputs" / "diff.patch").exists()


def test_agent_links_semgrep_tool_evidence(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """import subprocess
def run(user_input):
    return subprocess.run(user_input, shell=True)
""",
        encoding="utf-8",
    )
    (tmp_path / "semgrep_stub.py").write_text(
        """import json
print(json.dumps({
    "results": [{
        "check_id": "python.lang.security.audit.subprocess-shell-true",
        "path": "app.py",
        "start": {"line": 3, "col": 12},
        "end": {"line": 3, "col": 55},
        "extra": {
            "message": "Found subprocess call with shell=True",
            "severity": "WARNING"
        }
    }]
}))
""",
        encoding="utf-8",
    )
    diff_path = tmp_path / "demo.diff"
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

    report = ReviewAgent(
        ReviewConfig(
            verification_commands=(
                VerificationCommand(
                    name="semgrep",
                    command='"{python}" semgrep_stub.py',
                    adapter="semgrep",
                    capabilities=("semgrep", "command-injection"),
                ),
            )
        )
    ).review(diff_path=diff_path, repo_path=tmp_path, output_dir=tmp_path / "bundle")

    assert report.summary["tool_finding_count"] == 1
    assert report.summary["validation_with_tool_evidence"] == 1
    assert report.summary["tool_supported_findings"] == 1
    assert report.summary["avg_confidence"] == report.findings[0].confidence
    # base_confidence is pre-calibration (may already include AST/dataflow boost).
    assert report.findings[0].base_confidence is not None
    assert report.findings[0].base_confidence >= 0.7
    assert report.findings[0].confidence > report.findings[0].base_confidence
    assert "Matched structured tool evidence" in report.findings[0].confidence_notes
    assert report.findings[0].dataflow_steps
    assert report.findings[0].analysis_scope in {"window", "file"}
    assert report.validation_plan[1].status == "covered"
    assert "subprocess-shell-true" in report.validation_plan[1].tool_evidence[0]
    markdown = (tmp_path / "bundle" / "report.md").read_text(encoding="utf-8")
    assert "## Tool Findings" in markdown
    assert "Tool evidence: semgrep/" in markdown
    assert "Semantic analysis:" in markdown


def test_agent_links_codeql_sarif_artifact_evidence(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """import subprocess
def run(user_input):
    return subprocess.run(user_input, shell=True)
""",
        encoding="utf-8",
    )
    (tmp_path / "codeql_stub.py").write_text(
        """import json
import sys
from pathlib import Path

Path(sys.argv[1]).write_text(json.dumps({
    "version": "2.1.0",
    "runs": [{
        "tool": {
            "driver": {
                "name": "CodeQL",
                "rules": [{
                    "id": "py/command-line-injection",
                    "defaultConfiguration": {"level": "error"}
                }]
            }
        },
        "results": [{
            "ruleId": "py/command-line-injection",
            "message": {"text": "This command depends on user input."},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {"startLine": 3, "endLine": 3}
                }
            }]
        }]
    }]
}), encoding="utf-8")
""",
        encoding="utf-8",
    )
    diff_path = tmp_path / "demo.diff"
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

    report = ReviewAgent(
        ReviewConfig(
            verification_commands=(
                VerificationCommand(
                    name="codeql",
                    command='"{python}" codeql_stub.py "{tool_dir}\\codeql.sarif"',
                    adapter="codeql",
                    capabilities=("codeql", "command-injection"),
                ),
            )
        )
    ).review(diff_path=diff_path, repo_path=tmp_path, output_dir=tmp_path / "bundle")

    assert report.summary["tool_finding_count"] == 1
    assert report.summary["tool_supported_findings"] == 1
    assert report.summary["tool_artifact_count"] == 1
    assert report.verification[0].artifact_paths == (
        str(tmp_path / "bundle" / "tools" / "codeql.sarif"),
    )
    assert "py/command-line-injection" in report.validation_plan[1].tool_evidence[0]
    markdown = (tmp_path / "bundle" / "report.md").read_text(encoding="utf-8")
    assert "Artifacts:" in markdown
    assert "codeql/py/command-line-injection" in markdown
