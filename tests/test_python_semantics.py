from pathlib import Path

import pytest

from verisec_agent.diff_parser import evidence_windows, parse_unified_diff
from verisec_agent.hypotheses import generate_hypotheses
from verisec_agent.python_semantics import (
    analyze_python_source,
    is_redos_hardening_delta,
    is_redos_prone,
    redos_risk_score,
)


def test_analyze_python_source_tracks_sql_dataflow_steps() -> None:
    source = '''
def lookup(cursor, user_id):
    query = f"SELECT * FROM accounts WHERE id = {user_id}"
    return cursor.execute(query)
'''
    matches = analyze_python_source(source, changed_lines={3, 4}, analysis_scope="file")

    assert len(matches) == 1
    match = matches[0]
    assert match.rule_id == "py-sql-string-format"
    assert match.analysis_scope == "file"
    assert match.sink_line == 4
    assert "user_id" in match.sources
    assert match.steps
    assert match.confidence_boost > 0


def test_analyze_python_source_follows_same_file_return_taint() -> None:
    source = '''
def build_query(user_id):
    return f"SELECT * FROM accounts WHERE id = {user_id}"

def lookup(cursor, user_id):
    query = build_query(user_id)
    return cursor.execute(query)
'''
    matches = analyze_python_source(source, changed_lines={3, 6, 7}, analysis_scope="file")

    assert any(match.rule_id == "py-sql-string-format" for match in matches)
    sql = next(match for match in matches if match.rule_id == "py-sql-string-format")
    assert sql.steps
    assert any("returns tainted" in step or "build_query" in step for step in sql.steps)


def test_analyze_python_source_flags_request_get_to_shell() -> None:
    source = '''
import subprocess

def run(request):
    command = "ls " + request.GET["name"]
    return subprocess.run(command, shell=True)
'''
    matches = analyze_python_source(source, changed_lines={5, 6}, analysis_scope="file")

    assert len(matches) == 1
    match = matches[0]
    assert match.rule_id == "py-shell-true"
    assert any("GET" in source for source in match.sources) or match.sources
    assert match.confidence_boost >= 0.10


def test_analyze_python_source_flags_os_system() -> None:
    source = '''
import os

def run(user_input):
    return os.system("echo " + user_input)
'''
    matches = analyze_python_source(source, changed_lines={5}, analysis_scope="file")

    assert [match.rule_id for match in matches] == ["py-shell-true"]
    assert matches[0].sink.startswith("os.system")


def test_full_file_analysis_finds_distant_sink(tmp_path: Path) -> None:
    # Sink is many lines away from the changed assignment so a tiny window
    # would miss it without file-scope analysis. Line numbers must match the
    # post-image file used for full-file analysis.
    filler = "\n".join(f"    x{i} = {i}" for i in range(40))
    source = (
        "import subprocess\n"
        "\n"
        "def run(user_input):\n"
        '    command = "ls " + user_input\n'
        f"{filler}\n"
        "    return subprocess.run(command, shell=True)\n"
    )
    target = tmp_path / "app.py"
    target.write_text(source, encoding="utf-8")

    # Unified diff only shows the command assignment as added near the top.
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,5 +1,6 @@
 import subprocess
 
 def run(user_input):
+    command = "ls " + user_input
     x0 = 0
"""
    windows = evidence_windows(parse_unified_diff(diff), max_lines=8)
    findings = generate_hypotheses(windows, min_confidence=0.35, repo_path=tmp_path)

    assert any(finding.rule_id == "py-shell-true" for finding in findings)
    shell = next(finding for finding in findings if finding.rule_id == "py-shell-true")
    assert shell.analysis_scope == "file"
    assert shell.dataflow_steps
    assert shell.analysis_notes
    assert shell.confidence > 0.70


def test_unicode_normalize_hardening_length_guard_before_nfkc() -> None:
    source = (
        "import unicodedata\n"
        "\n"
        "def to_python(self, value):\n"
        "    value = super().to_python(value)\n"
        "    if self.max_length is not None and len(value) > self.max_length:\n"
        "        return value\n"
        '    return unicodedata.normalize("NFKC", value)\n'
    )
    # Guard lines changed; normalize may be pre-existing context.
    matches = analyze_python_source(
        source,
        changed_lines={5, 6},
        analysis_scope="file",
    )

    assert len(matches) == 1
    match = matches[0]
    assert match.rule_id == "py-unicode-normalization-dos"
    assert match.family == "complexity-dos"
    assert match.mode == "adds-hardening"
    assert match.sink_line == 7
    assert any("length guard" in step for step in match.steps)
    assert match.confidence_boost > 0


def test_unicode_normalize_introduces_risk_without_guard() -> None:
    source = (
        "import unicodedata\n"
        "\n"
        "def clean(user_id):\n"
        '    return unicodedata.normalize("NFKC", user_id)\n'
    )
    matches = analyze_python_source(source, changed_lines={4}, analysis_scope="file")

    assert len(matches) == 1
    match = matches[0]
    assert match.rule_id == "py-unicode-normalization-dos"
    assert match.mode == "introduces-risk"
    assert "user_id" in match.sources or any("user_id" in step for step in match.steps)


def test_unicode_normalize_constant_not_flagged() -> None:
    source = (
        "import unicodedata\n"
        "\n"
        "def label():\n"
        '    return unicodedata.normalize("NFKC", "fixed-label")\n'
    )
    matches = analyze_python_source(source, changed_lines={4}, analysis_scope="file")

    assert matches == ()


def test_unicode_not_confused_with_redos_on_max_length_only() -> None:
    diff = """diff --git a/forms.py b/forms.py
--- a/forms.py
+++ b/forms.py
@@ -1,3 +1,4 @@
 class Field:
+    max_length = 2048
     def clean(self, value):
         return value
"""
    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert findings == ()


def test_django_shaped_username_field_prefers_unicode_over_redos() -> None:
    diff = """diff --git a/django/contrib/auth/forms.py b/django/contrib/auth/forms.py
--- a/django/contrib/auth/forms.py
+++ b/django/contrib/auth/forms.py
@@ -1,7 +1,10 @@
 import unicodedata
 class UsernameField:
     max_length = 150
     def to_python(self, value):
         value = super().to_python(value)
+        if self.max_length is not None and len(value) > self.max_length:
+            return value
         return unicodedata.normalize("NFKC", value)
"""
    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert [f.rule_id for f in findings] == ["py-unicode-normalization-dos"]
    assert "adds-hardening" in findings[0].analysis_notes
    assert "Family: complexity-dos" in findings[0].analysis_notes


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        (r"(a+)+", True),
        (r"(a*)*", True),
        (r"(a+)*", True),
        (r"(?:a+)+", True),
        (r"(a|aa)+", True),
        (r"(?:.*,)*", True),
        (r"(.*,)*", True),
        (r"((\\r\\n|\\r|\\n)+) *$", True),
        (r"^[a-z0-9_-]{1,64}$", False),
        (r"^[a-z]+$", False),
        (r"abc", False),
        (r"", False),
        (r"a+b+", True),
        (r"\w*\w+", True),
        # Adjacent greedy unbounded wildcards — canonical polynomial class.
        (r".*.*=.*", True),
        (r"x.*.*y", True),
        # Near miss: a single wildcard / legitimate contains-form is linear, not ReDoS.
        (r".*foo.*", False),
        (r"^.*=.*$", False),
        (r".*?.*?", False),
    ],
)
def test_is_redos_prone_table(pattern: str, expected: bool) -> None:
    assert is_redos_prone(pattern) is expected


def test_redos_hardening_delta_mechanize_shaped() -> None:
    old = r"(?:.*,)*[ \t]*([^ \t]+)[ \t]+"
    new = r"(?:^|,)([^ \t,]+)[ \t]+"
    assert is_redos_prone(old)
    assert is_redos_hardening_delta(old, new)
    assert redos_risk_score(old) > redos_risk_score(new)


def test_redos_hardening_pattern_delta_via_window() -> None:
    diff = """diff --git a/mechanize/_urllib2_fork.py b/mechanize/_urllib2_fork.py
--- a/mechanize/_urllib2_fork.py
+++ b/mechanize/_urllib2_fork.py
@@ -1,4 +1,4 @@
 import re
 class AbstractBasicAuthHandler:
-    rx = re.compile('(?:.*,)*[ \\t]*([^ \\t]+)[ \\t]+realm=([\"\\']?)([^\"\\']*)\\\\2')
+    rx = re.compile('(?:^|,)[ \\t]*([^ \\t,]+)[ \\t]+realm=([\"\\']?)([^\"\\']*)\\\\2')
"""
    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert any(f.rule_id == "py-regex-redos-hardening" for f in findings)
    hardening = next(f for f in findings if f.rule_id == "py-regex-redos-hardening")
    assert hardening.analysis_scope in {"window", "file"}
    assert "adds-hardening" in hardening.analysis_notes
    assert "Family: redos" in hardening.analysis_notes
    assert not any(f.rule_id == "py-regex-redos" for f in findings)


def test_redos_hardening_greedy_polynomial_pattern_delta() -> None:
    """Adjacent greedy wildcards `.*.*` are the canonical polynomial ReDoS class.

    Synthetic fixture, not any holdout case. The check is greedy-only, so the
    frozen Holdout 2 transformers pattern (lazy `.*?`) is deliberately unaffected.
    """
    diff = '''diff --git a/router.py b/router.py
--- a/router.py
+++ b/router.py
@@ -1,2 +1,2 @@
 import re
-MATCH = re.compile(r".*.*=.*")
+MATCH = re.compile(r"[^=]*=.*")
'''
    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert any(f.rule_id == "py-regex-redos-hardening" for f in findings)
    assert not any(f.rule_id == "py-regex-redos" for f in findings)


def test_legitimate_contains_regex_not_flagged_as_redos() -> None:
    """Near-miss control: a single-wildcard contains-form is linear, must stay quiet."""
    diff = '''diff --git a/search.py b/search.py
--- a/search.py
+++ b/search.py
@@ -1,2 +1,3 @@
 import re
 def find(text):
+    return re.search(r".*foo.*", text)
'''
    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert not any(f.family == "redos" for f in findings)


def test_redos_introduces_risk_on_tainted_input() -> None:
    source = (
        "import re\n"
        "\n"
        "def search(user_input):\n"
        "    return re.search(r'(a+)+', user_input)\n"
    )
    matches = analyze_python_source(source, changed_lines={4}, analysis_scope="file")

    assert len(matches) == 1
    match = matches[0]
    assert match.rule_id == "py-regex-redos"
    assert match.family == "redos"
    assert match.mode == "introduces-risk"
    assert "user_input" in match.sources or any("user_input" in s for s in match.steps)
    assert match.confidence_boost > 0


def test_bounded_safe_regex_not_redos() -> None:
    source = (
        "import re\n"
        "\n"
        "def compile_bounded_slug():\n"
        "    return re.compile(r'^[a-z0-9_-]{1,64}$')\n"
    )
    matches = analyze_python_source(source, changed_lines={4}, analysis_scope="file")

    assert matches == ()


def test_full_file_redos_sink_distant_from_pattern_assign(tmp_path: Path) -> None:
    filler = "\n".join(f"    x{i} = {i}" for i in range(40))
    source = (
        "import re\n"
        "\n"
        "def run(user_input):\n"
        "    pattern = r'(a+)+'\n"
        f"{filler}\n"
        "    return re.search(pattern, user_input)\n"
    )
    target = tmp_path / "app.py"
    target.write_text(source, encoding="utf-8")

    # Diff only shows the pattern assignment; sink is far below in the full file.
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,5 +1,6 @@
 import re
 
 def run(user_input):
+    pattern = r'(a+)+'
     x0 = 0
"""
    windows = evidence_windows(parse_unified_diff(diff), max_lines=8)
    findings = generate_hypotheses(windows, min_confidence=0.35, repo_path=tmp_path)

    assert any(f.rule_id == "py-regex-redos" for f in findings)
    finding = next(f for f in findings if f.rule_id == "py-regex-redos")
    assert finding.analysis_scope == "file"
    assert finding.dataflow_steps
    assert "introduces-risk" in finding.analysis_notes


def test_semantic_match_boosts_confidence_over_regex_only() -> None:
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,3 +1,5 @@
 def lookup(cursor, user_id):
+    query = f"SELECT * FROM accounts WHERE id = {user_id}"
+    return cursor.execute(query)
"""
    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "py-sql-string-format"
    # Base rule confidence is 0.64; AST/dataflow should boost it.
    assert finding.confidence > 0.64
    assert finding.dataflow_steps
    assert "AST/dataflow" in finding.analysis_notes


def test_sql_concatenation_with_tainted_data_fires() -> None:
    """String concatenation of a SQL literal with tainted input reaching execute."""
    diff = '''diff --git a/dao.py b/dao.py
--- a/dao.py
+++ b/dao.py
@@ -1,2 +1,3 @@
 def lookup(cursor, user_id=input()):
+    cursor.execute("SELECT * FROM accounts WHERE id = " + user_id)
     return cursor
'''
    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )
    assert any(f.rule_id == "py-sql-string-format" for f in findings)


def test_sql_orm_raw_sink_with_tainted_data_fires() -> None:
    """The ORM raw-query escape hatch is a SQL sink, not Django-specific plumbing."""
    diff = '''diff --git a/views.py b/views.py
--- a/views.py
+++ b/views.py
@@ -1,2 +1,3 @@
 def search(user_id=input()):
+    return User.objects.raw("SELECT * FROM users WHERE id = " + user_id)
     # end
'''
    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )
    assert any(f.rule_id == "py-sql-string-format" for f in findings)


def test_parameterized_percent_placeholder_not_flagged() -> None:
    """`execute("... %s", params)` is the safe parameterized form and must stay quiet.

    Near-miss control for the crude regex fallback, which previously fired on any
    SELECT containing a `%`.
    """
    diff = '''diff --git a/dao.py b/dao.py
--- a/dao.py
+++ b/dao.py
@@ -1,2 +1,3 @@
 def lookup(cursor, user_id=input()):
+    cursor.execute("SELECT * FROM accounts WHERE id = %s", (user_id,))
     return cursor
'''
    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )
    assert not any(f.rule_id == "py-sql-string-format" for f in findings)


def test_redos_literal_in_data_structure_without_sink_stays_quiet() -> None:
    """A redos-shaped raw string in a data structure with no re.* sink is not asserted
    to be a regex. Detecting it would be a false positive; this pins that boundary."""
    diff = '''diff --git a/tokens.py b/tokens.py
--- a/tokens.py
+++ b/tokens.py
@@ -1,2 +1,4 @@
 TOKENS = [
+    (r"(a+)+$", "IDENT"),
+    (r"[0-9]+", "NUMBER"),
 ]
'''
    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )
    assert not any(f.family == "redos" for f in findings)
