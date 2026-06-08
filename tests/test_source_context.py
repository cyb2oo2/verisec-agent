from pathlib import Path

from verisec_agent.diff_parser import evidence_windows, parse_unified_diff
from verisec_agent.source_context import load_source_context


def test_load_source_context_marks_changed_lines(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """import subprocess

def run_command(user_input):
    return subprocess.run(user_input, shell=True)
""",
        encoding="utf-8",
    )
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,3 +1,4 @@\n"
        " import subprocess\n"
        " \n"
        " def run_command(user_input):\n"
        "+    return subprocess.run(user_input, shell=True)\n"
    )
    window = evidence_windows(parse_unified_diff(diff))[0]

    context = load_source_context(repo_path=tmp_path, evidence=window, radius=1)

    assert context.available is True
    assert ">4:     return subprocess.run(user_input, shell=True)" in context.snippet()


def test_load_source_context_rejects_paths_outside_repo(tmp_path: Path) -> None:
    diff = """diff --git a/../secret.py b/../secret.py
--- a/../secret.py
+++ b/../secret.py
@@ -1,1 +1,1 @@
+eval(payload)
"""
    window = evidence_windows(parse_unified_diff(diff))[0]

    context = load_source_context(repo_path=tmp_path, evidence=window, radius=1)

    assert context.available is False
    assert "outside the repository" in context.rationale
