from pathlib import Path

from verisec_agent.agent import ReviewAgent
from verisec_agent.config import ReviewConfig


def test_agent_writes_review_bundle(tmp_path: Path) -> None:
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

    report = ReviewAgent(ReviewConfig()).review(
        diff_path=diff_path,
        repo_path=tmp_path,
        output_dir=tmp_path / "bundle",
    )

    assert report.summary["finding_count"] == 1
    assert report.findings[0].rule_id == "py-eval-exec"
    assert (tmp_path / "bundle" / "report.json").exists()
    assert (tmp_path / "bundle" / "trace.jsonl").exists()
    assert (tmp_path / "bundle" / "inputs" / "diff.patch").exists()
