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


def test_parse_unified_diff_treats_bare_blank_lines_as_context() -> None:
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,4 +1,5 @@
 import subprocess

 def run(user_input):
+    eval(user_input)
"""
    lines = parse_unified_diff(diff)

    assert lines[1].content == ""
    assert lines[1].change_type == "context"
    assert lines[3].new_line == 4


def test_evidence_windows_focus_on_security_relevant_changes() -> None:
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


def test_evidence_windows_include_deletions_for_security_fix_review() -> None:
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -10,3 +10,2 @@
 def load(source):
-    return yaml.load(source)
     return yaml.safe_load(source)
"""
    windows = evidence_windows(parse_unified_diff(diff), max_lines=6)

    assert len(windows) == 1
    assert "yaml.load(source)" in windows[0].snippet()
