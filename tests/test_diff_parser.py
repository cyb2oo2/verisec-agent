from verisec_agent.diff_parser import evidence_windows, parse_unified_diff


def test_parse_unified_diff_tracks_added_lines() -> None:
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
 import subprocess
+subprocess.run(user_input, shell=True)
 print("done")
"""
    lines = parse_unified_diff(diff)

    assert len(lines) == 3
    assert lines[1].file_path == "app.py"
    assert lines[1].new_line == 2
    assert lines[1].change_type == "add"


def test_evidence_windows_focus_on_additions() -> None:
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -10,2 +10,3 @@
 def run(user_input):
+    eval(user_input)
     return None
"""
    windows = evidence_windows(parse_unified_diff(diff), max_lines=6)

    assert len(windows) == 1
    assert windows[0].file_path == "app.py"
    assert "eval(user_input)" in windows[0].snippet()
