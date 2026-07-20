from verisec_agent.diff_parser import evidence_windows, parse_unified_diff
from verisec_agent.hypotheses import generate_hypotheses


def test_generate_hypotheses_flags_safe_yaml_loader_hardening() -> None:
    diff = """diff --git a/mkdocs/theme.py b/mkdocs/theme.py
--- a/mkdocs/theme.py
+++ b/mkdocs/theme.py
@@ -1,3 +1,4 @@
 import yaml
 def load(f):
-    return utils.yaml_load(f)
+    return yaml.load(f, SafeLoader)
"""

    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert [finding.rule_id for finding in findings] == ["py-yaml-safe-loader"]


def test_generate_hypotheses_does_not_flag_safe_loader_as_unsafe_yaml() -> None:
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
 import yaml
+config = yaml.load(source, SafeLoader)
"""

    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert {finding.rule_id for finding in findings} == {"py-yaml-safe-loader"}


def test_generate_hypotheses_flags_safe_load_alias_hardening() -> None:
    diff = """diff --git a/lib/yaml/__init__.py b/lib/yaml/__init__.py
--- a/lib/yaml/__init__.py
+++ b/lib/yaml/__init__.py
@@ -1,3 +1,5 @@
 def load(stream, Loader=Loader):
     return loader.get_single_data()
+safe_load = load
+def danger_load(stream):
+    return load(stream, Loader=DangerLoader)
"""

    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert {finding.rule_id for finding in findings} == {"py-yaml-safe-loader"}


def test_generate_hypotheses_flags_regex_redos_hardening() -> None:
    diff = """diff --git a/sqlparse/filters/others.py b/sqlparse/filters/others.py
--- a/sqlparse/filters/others.py
+++ b/sqlparse/filters/others.py
@@ -1,2 +1,2 @@
-m = re.search(r'((\\r\\n|\\r|\\n)+) *$', token.value)
+m = re.search(r'((\\r|\\n)+) *$', token.value)
"""

    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert {finding.rule_id for finding in findings} == {"py-regex-redos-hardening"}


def test_generate_hypotheses_does_not_treat_length_bounds_alone_as_redos() -> None:
    """Length/max_length guards without regex changes are not ReDoS signals."""
    diff = """diff --git a/django/core/validators.py b/django/core/validators.py
--- a/django/core/validators.py
+++ b/django/core/validators.py
@@ -1,6 +1,9 @@
 class URLValidator:
+    max_length = 2048
     def __call__(self, value):
+        if not isinstance(value, str) or len(value) > self.max_length:
+            raise ValidationError(self.message, code=self.code)
         return value
 class EmailValidator:
     def __call__(self, value):
+        if not value or "@" not in value or len(value) > 320:
+            raise ValidationError(self.message, code=self.code)
"""

    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert not any(finding.rule_id == "py-regex-redos-hardening" for finding in findings)


def test_generate_hypotheses_flags_unicode_normalization_hardening() -> None:
    diff = """diff --git a/django/contrib/auth/forms.py b/django/contrib/auth/forms.py
--- a/django/contrib/auth/forms.py
+++ b/django/contrib/auth/forms.py
@@ -1,6 +1,9 @@
 import unicodedata
 class UsernameField:
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

    assert [finding.rule_id for finding in findings] == ["py-unicode-normalization-dos"]
    assert findings[0].analysis_notes
    assert "adds-hardening" in findings[0].analysis_notes
    assert "complexity-dos" in findings[0].analysis_notes
    assert not any(finding.rule_id == "py-regex-redos-hardening" for finding in findings)


def test_generate_hypotheses_flags_password_similarity_dos_guard() -> None:
    diff = """diff --git a/password_validation.py b/password_validation.py
--- a/password_validation.py
+++ b/password_validation.py
@@ -1,6 +1,13 @@
+def exceeds_maximum_length_ratio(password, max_similarity, value):
+    if max_similarity < 0.1:
+        raise ValueError("max_similarity must be at least 0.1")
+    return len(password) >= 10 * len(value)
+
 class UserAttributeSimilarityValidator:
     def validate(self, password, user=None):
         for value_part in value_parts:
+            if exceeds_maximum_length_ratio(password, self.max_similarity, value_part):
+                continue
             if SequenceMatcher(a=password, b=value_part).quick_ratio() >= self.max_similarity:
                 raise ValidationError("too similar")
"""

    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert [finding.rule_id for finding in findings] == [
        "py-dos-algorithmic-complexity"
    ]


def test_generate_hypotheses_flags_sql_lookup_identifier_hardening() -> None:
    diff = """diff --git a/datetime.py b/datetime.py
--- a/datetime.py
+++ b/datetime.py
@@ -1,3 +1,5 @@
     def as_sql(self, compiler, connection):
+        if not connection.ops.extract_trunc_lookup_pattern.fullmatch(self.lookup_name):
+            raise ValueError("Invalid lookup_name: %s" % self.lookup_name)
         sql, params = compiler.compile(self.lhs)
"""

    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert [finding.rule_id for finding in findings] == ["py-sql-lookup-injection"]


def test_generate_hypotheses_flags_django_alias_and_explain_sql_hardening() -> None:
    diff = """diff --git a/django/db/models/sql/query.py b/django/db/models/sql/query.py
--- a/django/db/models/sql/query.py
+++ b/django/db/models/sql/query.py
@@ -1,3 +1,6 @@
+FORBIDDEN_ALIAS_PATTERN = _lazy_re_compile(r"['`\\"]|--|/\\*|\\*/")
+EXPLAIN_OPTIONS_PATTERN = _lazy_re_compile(r"[\\w\\-]+")
+
 class Query:
@@ -10,6 +13,9 @@
     def explain(self, using, format=None, **options):
+        for option_name in options:
+            if not EXPLAIN_OPTIONS_PATTERN.fullmatch(option_name) or "--" in option_name:
+                raise ValueError(f"Invalid option name: {option_name!r}.")
         q = self.clone()
"""

    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert [finding.rule_id for finding in findings] == [
        "py-sql-identifier-injection",
        "py-sql-explain-option-injection",
    ]


def test_generate_hypotheses_flags_stringagg_delimiter_parameterization() -> None:
    diff = """diff --git a/aggregates/general.py b/aggregates/general.py
--- a/aggregates/general.py
+++ b/aggregates/general.py
@@ -1,7 +1,8 @@
+from django.db.models import Value
 class StringAgg(OrderableAggMixin, Aggregate):
-    template = "%(function)s(%(distinct)s%(expressions)s, '%(delimiter)s'%(ordering)s)"
+    template = '%(function)s(%(distinct)s%(expressions)s %(ordering)s)'
     def __init__(self, expression, delimiter, **extra):
-        super().__init__(expression, delimiter=delimiter, **extra)
+        delimiter_expr = Value(str(delimiter))
+        super().__init__(expression, delimiter_expr, **extra)
diff --git a/tests/test_aggregates.py b/tests/test_aggregates.py
--- a/tests/test_aggregates.py
+++ b/tests/test_aggregates.py
@@ -1,2 +1,5 @@
+    def test_string_agg_delimiter_escaping(self):
+        values = AggregateTestModel.objects.aggregate(
+            stringagg=StringAgg('char_field', delimiter="'")
+        )
"""

    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert [finding.rule_id for finding in findings] == [
        "py-sql-delimiter-injection",
        "py-sql-delimiter-injection",
    ]


def test_generate_hypotheses_ignores_python_format_strings_in_gettext_catalogs() -> None:
    diff = """diff --git a/locale/az/LC_MESSAGES/django.po b/locale/az/LC_MESSAGES/django.po
--- a/locale/az/LC_MESSAGES/django.po
+++ b/locale/az/LC_MESSAGES/django.po
@@ -1,3 +1,3 @@
-msgid "Changed %(object)s - %(changes)s"
+msgid "Changed %(object)s: %(changes)s"
"""

    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert findings == ()


def test_generate_hypotheses_flags_sqlparse_lexer_redos_hardening() -> None:
    diff = """diff --git a/sqlparse/keywords.py b/sqlparse/keywords.py
--- a/sqlparse/keywords.py
+++ b/sqlparse/keywords.py
@@ -1,3 +1,5 @@
+PROCESS_AS_KEYWORD = object()
+
 SQL_REGEX = [
diff --git a/sqlparse/lexer.py b/sqlparse/lexer.py
--- a/sqlparse/lexer.py
+++ b/sqlparse/lexer.py
@@ -1,3 +1,5 @@
+                elif action is keywords.PROCESS_AS_KEYWORD:
+                    yield self.is_keyword(m.group())
"""

    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert [finding.rule_id for finding in findings] == [
        "py-regex-redos-hardening",
        "py-regex-redos-hardening",
    ]


def test_generate_hypotheses_ignores_shell_true_in_comments_and_strings() -> None:
    diff = """diff --git a/examples/negative_controls.py b/examples/negative_controls.py
--- a/examples/negative_controls.py
+++ b/examples/negative_controls.py
@@ -1,2 +1,4 @@
+# subprocess.run(user_input, shell=True) must stay forbidden.
+WARNING = "subprocess.run(user_input, shell=True)"
"""

    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert findings == ()


def test_generate_hypotheses_still_flags_shell_true_code() -> None:
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
 import subprocess
+subprocess.run(user_input, shell=True)
"""

    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert {finding.rule_id for finding in findings} == {"py-shell-true"}


def test_generate_hypotheses_flags_imported_subprocess_sink_via_ast() -> None:
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,3 +1,4 @@
 from subprocess import run
 def handle(user_input):
+    return run(user_input, shell=True)
"""

    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert [finding.rule_id for finding in findings] == ["py-shell-true"]


def test_generate_hypotheses_flags_imported_yaml_load_via_ast() -> None:
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,3 +1,4 @@
 from yaml import load
 def parse_config(source):
+    return load(source)
"""

    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert [finding.rule_id for finding in findings] == ["py-unsafe-yaml"]


def test_generate_hypotheses_flags_tainted_sql_execute_via_ast() -> None:
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

    assert [finding.rule_id for finding in findings] == ["py-sql-string-format"]


def test_generate_hypotheses_flags_changed_query_reaching_context_execute() -> None:
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,4 +1,5 @@
 def lookup(cursor, user_id):
+    query = f"SELECT * FROM accounts WHERE id = {user_id}"
     return cursor.execute(query)
"""

    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert [finding.rule_id for finding in findings] == ["py-sql-string-format"]


def test_generate_hypotheses_flags_changed_command_reaching_context_shell_sink() -> None:
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,5 +1,6 @@
 import subprocess
 def run(user_input):
+    command = "ls " + user_input
     return subprocess.run(command, shell=True)
"""

    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert [finding.rule_id for finding in findings] == ["py-shell-true"]


def test_generate_hypotheses_does_not_flag_parameterized_sql_execute() -> None:
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,3 +1,4 @@
 def lookup(cursor, user_id):
+    return cursor.execute("SELECT * FROM accounts WHERE id = ?", (user_id,))
"""

    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert findings == ()


def test_generate_hypotheses_ignores_weak_hash_in_string_literals() -> None:
    diff = """diff --git a/examples/negative_controls.py b/examples/negative_controls.py
--- a/examples/negative_controls.py
+++ b/examples/negative_controls.py
@@ -1,2 +1,3 @@
+message = "legacy code used hashlib.md5(payload)"
"""

    findings = generate_hypotheses(
        evidence_windows(parse_unified_diff(diff)),
        min_confidence=0.35,
    )

    assert findings == ()
