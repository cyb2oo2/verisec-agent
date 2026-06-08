import json
from pathlib import Path

from verisec_agent.agent import ReviewAgent
from verisec_agent.config import ReviewConfig
from verisec_agent.models import VerificationCommand
from verisec_agent.replay import replay_bundle


def test_replay_bundle_reruns_saved_verification(tmp_path: Path) -> None:
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
    bundle_path = tmp_path / "bundle"
    ReviewAgent(
        ReviewConfig(
            verification_commands=(
                VerificationCommand(
                    name="unit-tests",
                    command="{python} -c \"print('ok')\"",
                    required=True,
                ),
            )
        )
    ).review(diff_path=diff_path, repo_path=tmp_path, output_dir=bundle_path)
    report_path = bundle_path / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["verification"][0]["command"] = "definitely-not-the-replay-command"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    summary = replay_bundle(
        bundle_path=bundle_path,
        repo_path=tmp_path,
        output_dir=tmp_path / "replay",
    )

    assert summary["verification_count"] == 1
    assert summary["verification_passed"] == 1
    assert (tmp_path / "replay" / "replay.json").exists()
    assert (tmp_path / "replay" / "tools" / "unit-tests.stdout.txt").exists()
