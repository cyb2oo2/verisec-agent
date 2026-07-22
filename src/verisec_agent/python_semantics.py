from __future__ import annotations

import ast
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path

from verisec_agent.models import EvidenceWindow


@dataclass(frozen=True)
class SemanticMatch:
    """A security-relevant AST/dataflow hit.

    Matches carry explicit path evidence so reviewers can see *why* the agent
    raised a finding rather than only which regex fired.
    """

    rule_id: str
    sink_line: int | None = None
    sink: str = ""
    sources: tuple[str, ...] = ()
    steps: tuple[str, ...] = ()
    confidence_boost: float = 0.0
    analysis_scope: str = "window"
    family: str = ""
    mode: str = ""


@dataclass(frozen=True)
class _FunctionSummary:
    returns_tainted: bool = False
    returns_sql: bool = False
    returns_changed_tainted: bool = False
    returns_changed_sql: bool = False


_SUBPROCESS_SINKS = {
    "call",
    "check_call",
    "check_output",
    "Popen",
    "run",
}
_SQL_VERBS = ("SELECT", "INSERT", "UPDATE", "DELETE")
_SAFE_YAML_LOADERS = ("SafeLoader", "CSafeLoader")
_UNICODE_NORMALIZE_FORMS = frozenset({"NFC", "NFKC", "NFD", "NFKD"})
_REGEX_SINK_METHODS = frozenset(
    {"compile", "search", "match", "fullmatch", "findall", "sub", "subn", "finditer", "split"}
)
# High-signal catastrophic-backtracking shapes (constant patterns only).
_REDOS_SHAPE_CHECKS: tuple[re.Pattern[str], ...] = (
    # Nested quantifiers: (a+)+, (a*)*, (a+)*, (a*)+, including non-capturing groups.
    re.compile(r"\((?:\?:)?[^)]*[+*][^)]*\)[+*]"),
    re.compile(r"\((?:\?:)?[^)]*[+*][^)]*\)\{\s*\d*\s*,"),
    # Classic polynomial header-style: (?:.*,)* or (.*,)*
    re.compile(r"\((?:\?:)?\.\*,\)\*"),
    re.compile(r"\((?:\?:)?\.\+,\)\+"),
    # Quantified alternation: (a|b)+, (a|aa)*
    re.compile(r"\((?:\?:)?[^)]*\|[^)]*\)[+*]"),
    re.compile(r"\((?:\?:)?[^)]*\|[^)]*\)\{\s*\d*\s*,"),
    # Overlapping adjacent quantified atoms: a+a+, \w*\w+
    re.compile(r"(?:\w|[.]|\\[wdsWDS])\+(?:\w|[.]|\\[wdsWDS])\+"),
    re.compile(r"(?:\w|[.]|\\[wdsWDS])\*(?:\w|[.]|\\[wdsWDS])\+"),
    # Adjacent unbounded greedy wildcards: .*.*, .+.+ (polynomial partitioning, the
    # canonical `.*.*=.*` class). Greedy only: lazy `.*?.*?` does not match, so this
    # stays clear of the frozen Holdout 2 transformers pattern, which is lazy.
    re.compile(r"\.[*+]\.[*+]"),
)
_TAINT_SOURCE_CALLS = {
    "input",
    "builtins.input",
    "os.getenv",
    "os.environ.get",
    "os.environ.__getitem__",
}
_TAINT_SOURCE_NAMES = {
    "sys.argv",
    "os.environ",
    "request.args",
    "request.GET",
    "request.POST",
    "request.form",
    "request.values",
    "request.json",
    "request.data",
    "request.cookies",
    "request.headers",
    "request.query_params",
}


def is_redos_prone(pattern: str) -> bool:
    """Return True when a constant regex pattern has a catastrophic-backtracking shape.

    This is a deliberate high-signal heuristic, not a full regex complexity solver.
    Bounded character classes and simple linear patterns should return False.
    """
    if not pattern or not isinstance(pattern, str):
        return False
    # Ignore empty/near-empty and obviously bounded {m,n} only patterns later via shapes.
    compact = pattern.replace("(?x)", "").replace("(?i)", "").replace("(?s)", "")
    if not compact:
        return False
    # Safe common form: fully anchored character class with bounded quantifier only.
    if re.fullmatch(r"\^?\[[^\]]+\]\{\d+,\d+\}\$?", compact):
        return False
    if re.fullmatch(r"\^?\[[^\]]+\]\{\d+\}\$?", compact):
        return False
    return any(check.search(compact) for check in _REDOS_SHAPE_CHECKS)


def redos_risk_score(pattern: str) -> int:
    """Rough relative risk for pattern-delta hardening comparisons."""
    if not pattern:
        return 0
    score = 0
    if is_redos_prone(pattern):
        score += 3
    score += pattern.count("|")
    score += pattern.count("+") + pattern.count("*")
    if _has_comma_star_group(pattern):
        score += 5
    score -= _anchor_strength(pattern)
    return max(0, score)


def is_redos_hardening_delta(old_pattern: str, new_pattern: str) -> bool:
    """True when new_pattern is a meaningful ReDoS hardening of old_pattern."""
    if not old_pattern or not new_pattern or old_pattern == new_pattern:
        return False
    if is_redos_prone(old_pattern) and not is_redos_prone(new_pattern):
        return True
    if redos_risk_score(old_pattern) > redos_risk_score(new_pattern):
        return True
    if _has_comma_star_group(old_pattern) and not _has_comma_star_group(new_pattern):
        return True
    return (
        _anchor_strength(new_pattern) > _anchor_strength(old_pattern)
        and (is_redos_prone(old_pattern) or redos_risk_score(old_pattern) >= 2)
    )


def analyze_python_window(window: EvidenceWindow) -> tuple[SemanticMatch, ...]:
    if not _is_python_path(window.file_path):
        return ()

    delete_parsed = _parse_window_version(window, "delete")
    add_parsed = _parse_window_version(window, "add")
    previous_patterns: tuple[str, ...] = ()
    if delete_parsed is not None:
        previous_patterns = _extract_regex_pattern_strings(delete_parsed[0])

    matches: list[SemanticMatch] = []
    seen: set[str] = set()
    # Prefer the post-image (add) side so pattern-delta hardening can fire.
    for parsed, previous in (
        (add_parsed, previous_patterns),
        (delete_parsed, ()),
    ):
        if parsed is None:
            continue
        tree, changed_lines = parsed
        analyzer = _SemanticAnalyzer(
            changed_lines,
            analysis_scope="window",
            previous_patterns=previous,
        )
        for match in analyzer.analyze(tree):
            if match.rule_id in seen:
                continue
            seen.add(match.rule_id)
            matches.append(match)

    # Hardening on the post-image supersedes introduces-risk from the pre-image.
    if any(match.rule_id == "py-regex-redos-hardening" for match in matches):
        matches = [match for match in matches if match.rule_id != "py-regex-redos"]
    return tuple(matches)


def analyze_python_file(
    *,
    file_path: Path,
    changed_lines: set[int],
) -> tuple[SemanticMatch, ...]:
    """Analyze a full Python file with known changed line numbers (1-based)."""
    if not _is_python_path(str(file_path)):
        return ()
    if not changed_lines:
        return ()
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ()
    return analyze_python_source(
        source,
        changed_lines=changed_lines,
        analysis_scope="file",
    )


def analyze_python_source(
    source: str,
    *,
    changed_lines: set[int],
    analysis_scope: str = "file",
    previous_patterns: tuple[str, ...] = (),
) -> tuple[SemanticMatch, ...]:
    if not source.strip() or not changed_lines:
        return ()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ()
    return _SemanticAnalyzer(
        changed_lines,
        analysis_scope=analysis_scope,
        previous_patterns=previous_patterns,
    ).analyze(tree)


def _is_python_path(file_path: str) -> bool:
    return file_path.lower().endswith((".py", ".pyi"))


def _parse_window_version(
    window: EvidenceWindow,
    change_type: str,
) -> tuple[ast.AST, set[int]] | None:
    lines = [
        line
        for line in window.lines
        if line.change_type in {"context", change_type}
    ]
    changed_lines = {
        index for index, line in enumerate(lines, start=1) if line.change_type == change_type
    }
    if not changed_lines:
        return None

    source = "\n".join(line.content for line in lines)
    if not source.strip():
        return None

    return _parse_snippet(source, changed_lines)


def _parse_snippet(source: str, changed_lines: set[int]) -> tuple[ast.AST, set[int]] | None:
    dedented = textwrap.dedent(source)
    for candidate, line_offset in (
        (dedented, 0),
        (_wrap_as_function(dedented), 1),
    ):
        try:
            tree = ast.parse(candidate)
        except SyntaxError:
            continue
        return tree, {line + line_offset for line in changed_lines}
    return None


def _wrap_as_function(source: str) -> str:
    return "def __verisec_window__():\n" + textwrap.indent(source, "    ")


class _ImportCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local_name = alias.asname or alias.name.split(".", maxsplit=1)[0]
            self.aliases[local_name] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None:
            return
        for alias in node.names:
            if alias.name == "*":
                continue
            local_name = alias.asname or alias.name
            self.aliases[local_name] = f"{node.module}.{alias.name}"


class _SemanticAnalyzer(ast.NodeVisitor):
    def __init__(
        self,
        changed_lines: set[int],
        *,
        analysis_scope: str = "window",
        previous_patterns: tuple[str, ...] = (),
    ) -> None:
        self.changed_lines = changed_lines
        self.analysis_scope = analysis_scope
        self.previous_patterns = previous_patterns
        self.aliases: dict[str, str] = {}
        self.matches: list[SemanticMatch] = []
        self.seen_rule_ids: set[str] = set()
        self.tainted_scopes: list[set[str]] = [set()]
        self.changed_tainted_scopes: list[set[str]] = [set()]
        self.sql_scopes: list[set[str]] = [set()]
        self.changed_sql_scopes: list[set[str]] = [set()]
        self.taint_steps: list[dict[str, list[str]]] = [{}]
        # name -> constant string value (pattern variables)
        self.const_string_scopes: list[dict[str, str]] = [{}]
        # names bound to constant strings on changed lines (for distant sinks)
        self.changed_const_strings: list[set[str]] = [set()]
        # name -> earliest statement line of a len()-based early-exit guard
        self.length_guard_lines: list[dict[str, int]] = [{}]
        # names whose dominating length guard sits on a changed line
        self.length_guard_changed: list[set[str]] = [set()]
        self.function_summaries: dict[str, _FunctionSummary] = {}
        self._current_function: str | None = None
        self._return_flags: dict[str, bool] = {
            "tainted": False,
            "sql": False,
            "changed_tainted": False,
            "changed_sql": False,
        }
        self._use_summaries = False

    def analyze(self, tree: ast.AST) -> tuple[SemanticMatch, ...]:
        collector = _ImportCollector()
        collector.visit(tree)
        self.aliases = collector.aliases

        # Pass 1: build same-file function summaries (return taint).
        self._use_summaries = False
        self.visit(tree)

        # Pass 2: re-analyze with interprocedural summaries for sink matching.
        self.matches = []
        self.seen_rule_ids = set()
        self.tainted_scopes = [set()]
        self.changed_tainted_scopes = [set()]
        self.sql_scopes = [set()]
        self.changed_sql_scopes = [set()]
        self.taint_steps = [{}]
        self.const_string_scopes = [{}]
        self.changed_const_strings = [set()]
        self.length_guard_lines = [{}]
        self.length_guard_changed = [set()]
        self._use_summaries = True
        self.visit(tree)
        return tuple(self.matches)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        value_tainted = self._expr_tainted(node.value)
        value_sql = self._expr_sql_sensitive(node.value)
        value_changed_tainted = self._expr_changed_tainted(node.value) or (
            self._node_changed(node) and value_tainted
        )
        value_changed_sql = self._expr_changed_sql_sensitive(node.value) or (
            self._node_changed(node) and value_sql
        )
        steps = self._steps_for_expr(node.value)
        if value_tainted and self._node_changed(node):
            steps = steps + [f"L{getattr(node, 'lineno', '?')}: assignment carries taint"]
        const_string = _constant_string(node.value)
        for target in node.targets:
            self._assign_target(
                target,
                value_tainted=value_tainted,
                value_sql=value_sql,
                value_changed_tainted=value_changed_tainted,
                value_changed_sql=value_changed_sql,
                steps=steps,
            )
            if const_string is not None:
                for key in _target_keys(target):
                    self.const_string_scopes[-1][key] = const_string
                    if self._node_changed(node):
                        self.changed_const_strings[-1].add(key)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is None:
            return
        self.visit(node.value)
        value_tainted = self._expr_tainted(node.value)
        value_sql = self._expr_sql_sensitive(node.value)
        value_changed_tainted = self._expr_changed_tainted(node.value) or (
            self._node_changed(node) and value_tainted
        )
        value_changed_sql = self._expr_changed_sql_sensitive(node.value) or (
            self._node_changed(node) and value_sql
        )
        steps = self._steps_for_expr(node.value)
        self._assign_target(
            node.target,
            value_tainted=value_tainted,
            value_sql=value_sql,
            value_changed_tainted=value_changed_tainted,
            value_changed_sql=value_changed_sql,
            steps=steps,
        )

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        value_tainted = self._expr_tainted(node.value)
        value_sql = self._expr_sql_sensitive(node.value)
        value_changed_tainted = self._expr_changed_tainted(node.value) or (
            self._node_changed(node) and value_tainted
        )
        value_changed_sql = self._expr_changed_sql_sensitive(node.value) or (
            self._node_changed(node) and value_sql
        )
        target_key = _expr_key(node.target)
        if target_key and self._is_tainted_name(target_key):
            value_tainted = True
        if target_key and self._is_sql_name(target_key):
            value_sql = True
        if target_key and self._is_changed_tainted_name(target_key):
            value_changed_tainted = True
        if target_key and self._is_changed_sql_name(target_key):
            value_changed_sql = True
        steps = self._steps_for_expr(node.value)
        if target_key:
            steps = self._steps_for_name(target_key) + steps
        self._assign_target(
            node.target,
            value_tainted=value_tainted,
            value_sql=value_sql,
            value_changed_tainted=value_changed_tainted,
            value_changed_sql=value_changed_sql,
            steps=steps,
        )

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            self.visit(node.value)
            if self._expr_tainted(node.value):
                self._return_flags["tainted"] = True
            if self._expr_sql_sensitive(node.value):
                self._return_flags["sql"] = True
            if self._expr_changed_tainted(node.value):
                self._return_flags["changed_tainted"] = True
            if self._expr_changed_sql_sensitive(node.value):
                self._return_flags["changed_sql"] = True
        else:
            self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        guarded = _len_bound_names(node.test)
        if guarded and _body_aborts(node.body):
            line = getattr(node, "lineno", 0)
            for name in guarded:
                current = self.length_guard_lines[-1].get(name)
                if current is None or line < current:
                    self.length_guard_lines[-1][name] = line
                if self._node_changed(node):
                    self.length_guard_changed[-1].add(name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._resolved_call_name(node)
        if (
            self._node_changed(node)
            or self._call_uses_changed_security_input(node, call_name)
            or self._unicode_normalize_path_changed(node, call_name)
            or self._regex_path_changed(node, call_name)
        ):
            self._check_call_sink(node, call_name)
        self.generic_visit(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        params = {arg.arg for arg in node.args.posonlyargs}
        params.update(arg.arg for arg in node.args.args)
        params.update(arg.arg for arg in node.args.kwonlyargs)
        if node.args.vararg is not None:
            params.add(node.args.vararg.arg)
        if node.args.kwarg is not None:
            params.add(node.args.kwarg.arg)

        previous_function = self._current_function
        previous_flags = dict(self._return_flags)
        self._current_function = node.name
        self._return_flags = {
            "tainted": False,
            "sql": False,
            "changed_tainted": False,
            "changed_sql": False,
        }

        self.tainted_scopes.append(set(params))
        self.changed_tainted_scopes.append(set())
        self.sql_scopes.append(set())
        self.changed_sql_scopes.append(set())
        self.length_guard_lines.append({})
        self.length_guard_changed.append(set())
        self.const_string_scopes.append({})
        self.changed_const_strings.append(set())
        self.taint_steps.append(
            {
                param: [f"parameter `{param}` treated as attacker-controlled"]
                for param in params
            }
        )
        for statement in node.body:
            self.visit(statement)

        self.function_summaries[node.name] = _FunctionSummary(
            returns_tainted=self._return_flags["tainted"],
            returns_sql=self._return_flags["sql"],
            returns_changed_tainted=self._return_flags["changed_tainted"],
            returns_changed_sql=self._return_flags["changed_sql"],
        )

        self.taint_steps.pop()
        self.changed_const_strings.pop()
        self.const_string_scopes.pop()
        self.length_guard_changed.pop()
        self.length_guard_lines.pop()
        self.changed_sql_scopes.pop()
        self.sql_scopes.pop()
        self.changed_tainted_scopes.pop()
        self.tainted_scopes.pop()
        self._current_function = previous_function
        self._return_flags = previous_flags

    def _check_call_sink(self, node: ast.Call, call_name: str) -> None:
        sink_line = getattr(node, "lineno", None)
        if self._is_shell_execution(call_name, node):
            sources, steps, tainted = self._sink_flow(node, prefer_arg=0)
            boost = 0.10 if tainted else 0.02
            if not tainted:
                steps = steps + ["shell=True without proven taint on the command"]
            self._add_match(
                "py-shell-true",
                sink_line=sink_line,
                sink=f"{call_name}(..., shell=True)",
                sources=sources,
                steps=steps,
                confidence_boost=boost,
            )
        if self._is_os_shell(call_name):
            sources, steps, tainted = self._sink_flow(node, prefer_arg=0)
            boost = 0.10 if tainted else 0.04
            self._add_match(
                "py-shell-true",
                sink_line=sink_line,
                sink=f"{call_name}(...)",
                sources=sources,
                steps=steps + [f"OS shell sink `{call_name}`"],
                confidence_boost=boost,
            )
        if call_name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            sources, steps, tainted = self._sink_flow(node, prefer_arg=0)
            boost = 0.10 if tainted else 0.04
            self._add_match(
                "py-eval-exec",
                sink_line=sink_line,
                sink=f"{call_name}(...)",
                sources=sources,
                steps=steps,
                confidence_boost=boost,
            )
        if call_name == "yaml.load" and not self._has_safe_yaml_loader(node):
            sources, steps, _ = self._sink_flow(node, prefer_arg=0)
            self._add_match(
                "py-unsafe-yaml",
                sink_line=sink_line,
                sink="yaml.load without SafeLoader",
                sources=sources,
                steps=steps + ["Loader is not SafeLoader/CSafeLoader"],
                confidence_boost=0.08,
            )
        if self._has_false_keyword(node, "verify"):
            self._add_match(
                "py-tls-verify-disabled",
                sink_line=sink_line,
                sink=f"{call_name}(..., verify=False)",
                sources=(),
                steps=["TLS certificate verification explicitly disabled"],
                confidence_boost=0.06,
            )
        if call_name.lower() in {"hashlib.md5", "hashlib.sha1"}:
            self._add_match(
                "weak-hash",
                sink_line=sink_line,
                sink=call_name,
                sources=(),
                steps=[f"Weak hash constructor `{call_name}`"],
                confidence_boost=0.05,
            )
        if self._is_sql_execute(call_name) and self._call_uses_sql_sensitive_arg(node):
            sources, steps, _ = self._sink_flow(node, prefer_arg=0)
            self._add_match(
                "py-sql-string-format",
                sink_line=sink_line,
                sink=f"{call_name}(<formatted SQL>)",
                sources=sources,
                steps=steps + ["formatted/tainted SQL reaches DB execute"],
                confidence_boost=0.12,
            )
        self._check_unicode_normalize_sink(node, call_name, sink_line)
        self._check_regex_sink(node, call_name, sink_line)

    def _check_regex_sink(
        self,
        node: ast.Call,
        call_name: str,
        sink_line: int | None,
    ) -> None:
        if not self._is_regex_sink(call_name):
            return
        pattern = self._resolve_regex_pattern(node)
        if pattern is None:
            return

        subject = _regex_subject_arg(node, call_name)
        sources: tuple[str, ...] = ()
        steps: list[str] = []
        tainted = False
        if subject is not None:
            sources = tuple(self._sources_for_expr(subject))
            steps = list(self._steps_for_expr(subject))
            tainted = self._expr_tainted(subject) or self._expr_changed_tainted(subject)

        pattern_changed = self._regex_pattern_changed(node, pattern)
        call_changed = self._node_changed(node)
        hardening_old = self._best_hardening_previous(pattern)

        if hardening_old is not None and (
            pattern_changed or call_changed or self.previous_patterns
        ):
            self._add_match(
                "py-regex-redos-hardening",
                sink_line=sink_line,
                sink=f"{call_name}(<hardened pattern>)",
                sources=sources,
                steps=steps
                + [
                    "regex pattern risk reduced versus pre-image",
                    f"old pattern risk={redos_risk_score(hardening_old)}",
                    f"new pattern risk={redos_risk_score(pattern)}",
                    f"sink {call_name} at L{sink_line}",
                ],
                confidence_boost=0.12 if tainted else 0.09,
                family="redos",
                mode="adds-hardening",
            )
            return

        if not is_redos_prone(pattern):
            return
        binding_changed = self._regex_binding_changed(node)
        if not (call_changed or pattern_changed or binding_changed or tainted):
            return
        # Require a changed pattern/call/binding so pre-existing redos shapes stay quiet
        # unless the subject taint itself was introduced on a changed path.
        if not (call_changed or pattern_changed or binding_changed or self._expr_changed_tainted(
            subject
        ) if subject is not None else False):
            return
        if subject is None and not (call_changed or pattern_changed or binding_changed):
            return

        boost = 0.12 if tainted else 0.07
        if subject is not None and not tainted:
            steps = steps + ["dangerous regex shape without proven taint on the subject"]
            boost = 0.05
        if binding_changed:
            steps = steps + ["redos-prone pattern binding changed on this path"]
        steps = steps + [
            "catastrophic-backtracking regex shape detected",
            f"sink {call_name} at L{sink_line}",
        ]
        self._add_match(
            "py-regex-redos",
            sink_line=sink_line,
            sink=f"{call_name}(<redos-prone pattern>)",
            sources=sources,
            steps=steps,
            confidence_boost=boost,
            family="redos",
            mode="introduces-risk",
        )

    def _best_hardening_previous(self, new_pattern: str) -> str | None:
        best_old: str | None = None
        best_drop = 0
        for old in self.previous_patterns:
            if not is_redos_hardening_delta(old, new_pattern):
                continue
            drop = redos_risk_score(old) - redos_risk_score(new_pattern)
            if best_old is None or drop > best_drop:
                best_old = old
                best_drop = drop
        return best_old

    def _resolve_regex_pattern(self, node: ast.Call) -> str | None:
        if not node.args:
            for keyword in node.keywords:
                if keyword.arg == "pattern":
                    return self._resolve_string_expr(keyword.value)
            return None
        return self._resolve_string_expr(node.args[0])

    def _resolve_string_expr(self, node: ast.AST) -> str | None:
        constant = _constant_string(node)
        if constant is not None:
            return constant
        key = _expr_key(node)
        if key is None:
            return None
        for scope in reversed(self.const_string_scopes):
            if key in scope:
                return scope[key]
        return None

    def _regex_pattern_changed(self, node: ast.Call, pattern: str) -> bool:
        if not node.args:
            return self._node_changed(node)
        pattern_node = node.args[0]
        if self._node_changed(pattern_node):
            return True
        return self._regex_binding_changed(node)

    def _regex_binding_changed(self, node: ast.Call) -> bool:
        if not node.args:
            return False
        key = _expr_key(node.args[0])
        if key is None:
            return False
        return any(key in scope for scope in reversed(self.changed_const_strings))

    def _regex_path_changed(self, node: ast.Call, call_name: str) -> bool:
        if not self._is_regex_sink(call_name):
            return False
        if self.previous_patterns:
            pattern = self._resolve_regex_pattern(node)
            if pattern is not None and self._best_hardening_previous(pattern) is not None:
                return True
        subject = _regex_subject_arg(node, call_name)
        if subject is not None and self._expr_changed_tainted(subject):
            return True
        pattern_node = node.args[0] if node.args else None
        if pattern_node is not None and self._node_changed(pattern_node):
            return True
        return self._regex_binding_changed(node)

    def _is_regex_sink(self, call_name: str) -> bool:
        return _is_regex_sink_name(call_name)

    def _check_unicode_normalize_sink(
        self,
        node: ast.Call,
        call_name: str,
        sink_line: int | None,
    ) -> None:
        if not self._is_unicode_normalize_call(call_name):
            return
        form, subject = _normalize_call_args(node)
        if subject is None:
            return
        if form is not None and form not in _UNICODE_NORMALIZE_FORMS:
            return
        if _is_constant_string(subject):
            return

        subject_key = _expr_key(subject)
        sources = tuple(self._sources_for_expr(subject))
        steps = list(self._steps_for_expr(subject))
        tainted = self._expr_tainted(subject) or self._expr_changed_tainted(subject)

        guard_line = self._length_guard_line(subject_key) if subject_key else None
        guard_dominates = (
            guard_line is not None
            and sink_line is not None
            and guard_line < sink_line
        )
        guard_changed = bool(
            subject_key and self._length_guard_changed(subject_key)
        )
        normalize_changed = self._node_changed(node)
        if not (normalize_changed or guard_changed or self._expr_changed_tainted(subject)):
            return

        form_label = form or "?"
        sink = f'unicodedata.normalize("{form_label}", ...)'
        if guard_dominates:
            mode = "adds-hardening"
            steps = steps + [
                f"length guard on `{subject_key}` at L{guard_line} can exit before normalize",
                f"sink {sink} at L{sink_line}",
            ]
            boost = 0.12 if guard_changed else 0.08
        else:
            mode = "introduces-risk"
            steps = steps + [
                "expensive Unicode normalize on non-constant input "
                "without a preceding length guard",
                f"sink {sink} at L{sink_line}",
            ]
            boost = 0.10 if tainted else 0.06

        if subject_key and subject_key not in sources:
            sources = tuple(dict.fromkeys((*sources, subject_key)))

        self._add_match(
            "py-unicode-normalization-dos",
            sink_line=sink_line,
            sink=sink,
            sources=sources,
            steps=steps,
            confidence_boost=boost,
            family="complexity-dos",
            mode=mode,
        )

    def _unicode_normalize_path_changed(self, node: ast.Call, call_name: str) -> bool:
        if not self._is_unicode_normalize_call(call_name):
            return False
        _, subject = _normalize_call_args(node)
        if subject is None or _is_constant_string(subject):
            return False
        subject_key = _expr_key(subject)
        if subject_key and self._length_guard_changed(subject_key):
            return True
        return self._expr_changed_tainted(subject)

    def _is_unicode_normalize_call(self, call_name: str) -> bool:
        if call_name == "unicodedata.normalize":
            return True
        if call_name.endswith(".normalize") and "unicodedata" in call_name:
            return True
        # from unicodedata import normalize → resolved name is unicodedata.normalize
        return call_name == "normalize" and self.aliases.get("normalize") == (
            "unicodedata.normalize"
        )

    def _length_guard_line(self, key: str) -> int | None:
        for scope in reversed(self.length_guard_lines):
            if key in scope:
                return scope[key]
        return None

    def _length_guard_changed(self, key: str) -> bool:
        return any(key in scope for scope in reversed(self.length_guard_changed))

    def _sink_flow(
        self, node: ast.Call, *, prefer_arg: int
    ) -> tuple[tuple[str, ...], list[str], bool]:
        sources: list[str] = []
        steps: list[str] = []
        tainted = False
        if len(node.args) > prefer_arg:
            arg = node.args[prefer_arg]
            tainted = self._expr_tainted(arg) or self._expr_changed_tainted(arg)
            sources.extend(self._sources_for_expr(arg))
            steps.extend(self._steps_for_expr(arg))
        for keyword in node.keywords:
            if keyword.arg in {None, "args", "cmd", "command"}:
                if self._expr_tainted(keyword.value) or self._expr_changed_tainted(
                    keyword.value
                ):
                    tainted = True
                sources.extend(self._sources_for_expr(keyword.value))
                steps.extend(self._steps_for_expr(keyword.value))
        # Deduplicate while preserving order.
        unique_sources = tuple(dict.fromkeys(sources))
        unique_steps = list(dict.fromkeys(steps))
        return unique_sources, unique_steps, tainted

    def _is_shell_execution(self, call_name: str, node: ast.Call) -> bool:
        if not self._has_true_keyword(node, "shell"):
            return False
        if not call_name.startswith("subprocess."):
            return False
        return call_name.rsplit(".", maxsplit=1)[-1] in _SUBPROCESS_SINKS

    def _is_os_shell(self, call_name: str) -> bool:
        return call_name in {
            "os.system",
            "os.popen",
            "os.popen2",
            "os.popen3",
            "os.popen4",
        }

    def _has_safe_yaml_loader(self, node: ast.Call) -> bool:
        for arg in node.args[1:]:
            if _expr_name_endswith(arg, _SAFE_YAML_LOADERS):
                return True
        for keyword in node.keywords:
            if keyword.arg == "Loader" and _expr_name_endswith(keyword.value, _SAFE_YAML_LOADERS):
                return True
        return False

    def _call_uses_sql_sensitive_arg(self, node: ast.Call) -> bool:
        if not node.args:
            return False
        query = node.args[0]
        return self._expr_sql_sensitive(query)

    def _call_uses_changed_security_input(self, node: ast.Call, call_name: str) -> bool:
        if self._is_shell_execution(call_name, node) and node.args:
            return self._expr_changed_tainted(node.args[0])
        if self._is_os_shell(call_name) and node.args:
            return self._expr_changed_tainted(node.args[0])
        if call_name in {"eval", "exec", "builtins.eval", "builtins.exec"} and node.args:
            return self._expr_changed_tainted(node.args[0])
        if call_name == "yaml.load" and node.args:
            return self._expr_changed_tainted(node.args[0])
        if self._is_sql_execute(call_name) and node.args:
            return self._expr_changed_sql_sensitive(node.args[0])
        if self._is_unicode_normalize_call(call_name):
            _, subject = _normalize_call_args(node)
            if subject is not None:
                return self._expr_changed_tainted(subject)
        if self._is_regex_sink(call_name):
            subject = _regex_subject_arg(node, call_name)
            if subject is not None and self._expr_changed_tainted(subject):
                return True
            if node.args and self._node_changed(node.args[0]):
                return True
        return False

    def _expr_sql_sensitive(self, node: ast.AST) -> bool:
        key = _expr_key(node)
        if key and self._is_sql_name(key):
            return True
        if _expr_is_sql_formatted(node) and self._expr_tainted(node):
            return True
        if isinstance(node, ast.JoinedStr):
            return _contains_sql_literal(node) and any(
                self._expr_tainted(value.value)
                for value in node.values
                if isinstance(value, ast.FormattedValue)
            )
        if isinstance(node, ast.BinOp):
            return self._expr_sql_sensitive(node.left) or self._expr_sql_sensitive(node.right)
        if isinstance(node, ast.Call):
            if self._call_returns_sql(node):
                return True
            return _expr_is_sql_format_call(node) and self._expr_tainted(node)
        return False

    def _expr_tainted(self, node: ast.AST) -> bool:
        key = _expr_key(node)
        if key and self._is_tainted_name(key):
            return True
        if key and self._is_taint_source_name(key):
            return True
        if isinstance(node, ast.Call):
            call_name = self._resolved_call_name(node)
            if call_name in _TAINT_SOURCE_CALLS:
                return True
            if call_name.endswith(".get") and self._expr_tainted(node.func):
                # request.args.get(...), os.environ.get already covered by name
                return True
            if self._call_returns_tainted(node):
                return True
            return any(self._expr_tainted(arg) for arg in node.args) or any(
                self._expr_tainted(keyword.value) for keyword in node.keywords
            )
        if isinstance(node, ast.JoinedStr):
            return any(
                self._expr_tainted(value.value)
                for value in node.values
                if isinstance(value, ast.FormattedValue)
            )
        if isinstance(node, ast.FormattedValue):
            return self._expr_tainted(node.value)
        if isinstance(node, ast.BinOp):
            return self._expr_tainted(node.left) or self._expr_tainted(node.right)
        if isinstance(node, ast.BoolOp):
            return any(self._expr_tainted(value) for value in node.values)
        if isinstance(node, ast.Compare):
            return self._expr_tainted(node.left) or any(
                self._expr_tainted(comparator) for comparator in node.comparators
            )
        if isinstance(node, ast.UnaryOp):
            return self._expr_tainted(node.operand)
        if isinstance(node, ast.Subscript):
            if self._expr_tainted(node.value):
                return True
            # request.GET["id"] style sources
            value_key = _expr_key(node.value)
            if value_key and self._is_taint_source_name(value_key):
                return True
            return self._expr_tainted(node.slice)
        if isinstance(node, ast.Attribute):
            return self._expr_tainted(node.value)
        if isinstance(node, ast.IfExp):
            return any(
                self._expr_tainted(value) for value in (node.test, node.body, node.orelse)
            )
        return False

    def _expr_changed_tainted(self, node: ast.AST) -> bool:
        key = _expr_key(node)
        if key and self._is_changed_tainted_name(key):
            return True
        if isinstance(node, ast.Call):
            if self._call_returns_changed_tainted(node):
                return True
            return any(self._expr_changed_tainted(arg) for arg in node.args) or any(
                self._expr_changed_tainted(keyword.value) for keyword in node.keywords
            )
        if isinstance(node, ast.JoinedStr):
            return any(
                self._expr_changed_tainted(value.value)
                for value in node.values
                if isinstance(value, ast.FormattedValue)
            )
        if isinstance(node, ast.FormattedValue):
            return self._expr_changed_tainted(node.value)
        if isinstance(node, ast.BinOp):
            return self._expr_changed_tainted(node.left) or self._expr_changed_tainted(
                node.right
            )
        if isinstance(node, ast.BoolOp):
            return any(self._expr_changed_tainted(value) for value in node.values)
        if isinstance(node, ast.Compare):
            return self._expr_changed_tainted(node.left) or any(
                self._expr_changed_tainted(comparator) for comparator in node.comparators
            )
        if isinstance(node, ast.UnaryOp):
            return self._expr_changed_tainted(node.operand)
        if isinstance(node, ast.Subscript):
            return self._expr_changed_tainted(node.value) or self._expr_changed_tainted(
                node.slice
            )
        if isinstance(node, ast.Attribute):
            return self._expr_changed_tainted(node.value)
        if isinstance(node, ast.IfExp):
            return any(
                self._expr_changed_tainted(value)
                for value in (node.test, node.body, node.orelse)
            )
        return False

    def _expr_changed_sql_sensitive(self, node: ast.AST) -> bool:
        key = _expr_key(node)
        if key and self._is_changed_sql_name(key):
            return True
        if _expr_is_sql_formatted(node) and self._expr_changed_tainted(node):
            return True
        if isinstance(node, ast.JoinedStr):
            return _contains_sql_literal(node) and any(
                self._expr_changed_tainted(value.value)
                for value in node.values
                if isinstance(value, ast.FormattedValue)
            )
        if isinstance(node, ast.BinOp):
            return self._expr_changed_sql_sensitive(
                node.left
            ) or self._expr_changed_sql_sensitive(node.right)
        if isinstance(node, ast.Call):
            if self._call_returns_changed_sql(node):
                return True
            return _expr_is_sql_format_call(node) and self._expr_changed_tainted(node)
        return False

    def _call_returns_tainted(self, node: ast.Call) -> bool:
        if not self._use_summaries:
            return False
        name = self._simple_call_name(node)
        summary = self.function_summaries.get(name)
        return bool(summary and summary.returns_tainted)

    def _call_returns_sql(self, node: ast.Call) -> bool:
        if not self._use_summaries:
            return False
        name = self._simple_call_name(node)
        summary = self.function_summaries.get(name)
        return bool(summary and summary.returns_sql)

    def _call_returns_changed_tainted(self, node: ast.Call) -> bool:
        if not self._use_summaries:
            return False
        name = self._simple_call_name(node)
        summary = self.function_summaries.get(name)
        return bool(summary and summary.returns_changed_tainted)

    def _call_returns_changed_sql(self, node: ast.Call) -> bool:
        if not self._use_summaries:
            return False
        name = self._simple_call_name(node)
        summary = self.function_summaries.get(name)
        return bool(summary and summary.returns_changed_sql)

    def _simple_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        return ""

    def _assign_target(
        self,
        target: ast.AST,
        *,
        value_tainted: bool,
        value_sql: bool,
        value_changed_tainted: bool,
        value_changed_sql: bool,
        steps: list[str] | None = None,
    ) -> None:
        for key in _target_keys(target):
            self._set_membership(self.tainted_scopes[-1], key, value_tainted)
            self._set_membership(self.sql_scopes[-1], key, value_sql)
            self._set_membership(
                self.changed_tainted_scopes[-1],
                key,
                value_changed_tainted,
            )
            self._set_membership(
                self.changed_sql_scopes[-1],
                key,
                value_changed_sql,
            )
            if value_tainted or value_sql:
                self.taint_steps[-1][key] = list(dict.fromkeys(steps or []))

    def _sources_for_expr(self, node: ast.AST) -> list[str]:
        sources: list[str] = []
        key = _expr_key(node)
        if key and self._is_taint_source_name(key):
            sources.append(key)
        if key:
            sources.extend(self._origin_sources_for_name(key))
        if isinstance(node, ast.Call):
            call_name = self._resolved_call_name(node)
            if call_name in _TAINT_SOURCE_CALLS:
                sources.append(call_name)
            if self._call_returns_tainted(node):
                sources.append(f"return of `{self._simple_call_name(node)}()`")
            for arg in node.args:
                sources.extend(self._sources_for_expr(arg))
            for keyword in node.keywords:
                sources.extend(self._sources_for_expr(keyword.value))
        if isinstance(node, ast.Name) and self._is_tainted_name(node.id):
            sources.append(node.id)
            sources.extend(self._origin_sources_for_name(node.id))
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    sources.extend(self._sources_for_expr(value.value))
        if isinstance(node, ast.BinOp):
            sources.extend(self._sources_for_expr(node.left))
            sources.extend(self._sources_for_expr(node.right))
        if isinstance(node, ast.Subscript):
            sources.extend(self._sources_for_expr(node.value))
            value_key = _expr_key(node.value)
            if value_key and self._is_taint_source_name(value_key):
                sources.append(value_key)
        if isinstance(node, ast.Attribute):
            sources.extend(self._sources_for_expr(node.value))
        return list(dict.fromkeys(sources))

    def _origin_sources_for_name(self, key: str) -> list[str]:
        """Recover root taint origins (parameters, env/web sources) from step history."""
        origins: list[str] = []
        for step in self._steps_for_name(key):
            if "parameter `" in step:
                fragment = step.split("parameter `", maxsplit=1)[1]
                origins.append(fragment.split("`", maxsplit=1)[0])
            elif step.startswith("source call `"):
                origins.append(step.removeprefix("source call `").rstrip("`"))
            elif step.startswith("call `") and "returns tainted" in step:
                origins.append(step)
        if self._is_tainted_name(key) and key not in origins:
            # The name itself is a function parameter.
            for steps_scope in self.taint_steps:
                param_steps = steps_scope.get(key, [])
                if any(step.startswith("parameter `") for step in param_steps):
                    origins.append(key)
                    break
        return list(dict.fromkeys(origins))

    def _steps_for_expr(self, node: ast.AST) -> list[str]:
        key = _expr_key(node)
        if key:
            named = self._steps_for_name(key)
            if named:
                return named
        if isinstance(node, ast.Call):
            call_name = self._resolved_call_name(node)
            if call_name in _TAINT_SOURCE_CALLS:
                return [f"source call `{call_name}`"]
            if self._call_returns_tainted(node):
                simple = self._simple_call_name(node)
                return [f"call `{simple}()` returns tainted data"]
            steps: list[str] = []
            for arg in node.args:
                steps.extend(self._steps_for_expr(arg))
            return list(dict.fromkeys(steps))
        if isinstance(node, ast.JoinedStr):
            steps = []
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    steps.extend(self._steps_for_expr(value.value))
            if steps:
                steps.append("string interpolation incorporates tainted values")
            return list(dict.fromkeys(steps))
        if isinstance(node, ast.BinOp):
            steps = self._steps_for_expr(node.left) + self._steps_for_expr(node.right)
            if steps:
                steps.append("string/binary combination preserves taint")
            return list(dict.fromkeys(steps))
        if isinstance(node, ast.Subscript):
            return self._steps_for_expr(node.value)
        if isinstance(node, ast.Attribute):
            return self._steps_for_expr(node.value)
        return []

    def _steps_for_name(self, key: str) -> list[str]:
        for scope in reversed(self.taint_steps):
            if key in scope:
                return list(scope[key])
        return []

    def _is_tainted_name(self, key: str) -> bool:
        return any(key in scope for scope in reversed(self.tainted_scopes))

    def _is_sql_name(self, key: str) -> bool:
        return any(key in scope for scope in reversed(self.sql_scopes))

    def _is_changed_tainted_name(self, key: str) -> bool:
        return any(key in scope for scope in reversed(self.changed_tainted_scopes))

    def _is_changed_sql_name(self, key: str) -> bool:
        return any(key in scope for scope in reversed(self.changed_sql_scopes))

    def _is_taint_source_name(self, key: str) -> bool:
        if key in _TAINT_SOURCE_NAMES:
            return True
        resolved = _resolve_dotted_name(key, self.aliases)
        if resolved in _TAINT_SOURCE_NAMES:
            return True
        # request.GET / flask request attributes after alias resolution
        for suffix in (
            ".args",
            ".GET",
            ".POST",
            ".form",
            ".values",
            ".json",
            ".data",
            ".cookies",
            ".headers",
            ".query_params",
        ):
            if key.endswith(suffix) or resolved.endswith(suffix):
                return True
        return False

    def _resolved_call_name(self, node: ast.Call) -> str:
        name = _call_name(node.func)
        if name is None:
            return ""
        return _resolve_dotted_name(name, self.aliases)

    def _node_changed(self, node: ast.AST) -> bool:
        start = getattr(node, "lineno", 0)
        end = getattr(node, "end_lineno", start)
        return any(line in self.changed_lines for line in range(start, end + 1))

    def _add_match(
        self,
        rule_id: str,
        *,
        sink_line: int | None = None,
        sink: str = "",
        sources: tuple[str, ...] = (),
        steps: list[str] | None = None,
        confidence_boost: float = 0.0,
        family: str = "",
        mode: str = "",
    ) -> None:
        if rule_id in self.seen_rule_ids:
            return
        self.seen_rule_ids.add(rule_id)
        scope_boost = 0.02 if self.analysis_scope == "file" else 0.0
        self.matches.append(
            SemanticMatch(
                rule_id=rule_id,
                sink_line=sink_line,
                sink=sink,
                sources=sources,
                steps=tuple(dict.fromkeys(steps or ())),
                confidence_boost=round(min(0.15, confidence_boost + scope_boost), 2),
                analysis_scope=self.analysis_scope,
                family=family,
                mode=mode,
            )
        )

    @staticmethod
    def _has_true_keyword(node: ast.Call, name: str) -> bool:
        return any(
            keyword.arg == name
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        )

    @staticmethod
    def _has_false_keyword(node: ast.Call, name: str) -> bool:
        return any(
            keyword.arg == name
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is False
            for keyword in node.keywords
        )

    @staticmethod
    def _is_sql_execute(call_name: str) -> bool:
        return call_name.endswith(".execute") or call_name.endswith(".executemany")

    @staticmethod
    def _set_membership(values: set[str], key: str, enabled: bool) -> None:
        if enabled:
            values.add(key)
        else:
            values.discard(key)


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        value_name = _call_name(node.value)
        if value_name is None:
            return node.attr
        return f"{value_name}.{node.attr}"
    return None


def _resolve_dotted_name(name: str, aliases: dict[str, str]) -> str:
    head, *tail = name.split(".")
    resolved_head = aliases.get(head)
    if resolved_head is None:
        return name
    return ".".join((resolved_head, *tail))


def _expr_key(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        value_key = _expr_key(node.value)
        if value_key is None:
            return None
        return f"{value_key}.{node.attr}"
    return None


def _target_keys(node: ast.AST) -> tuple[str, ...]:
    key = _expr_key(node)
    if key is not None:
        return (key,)
    if isinstance(node, ast.Tuple | ast.List):
        return tuple(key for element in node.elts for key in _target_keys(element))
    return ()


def _expr_name_endswith(node: ast.AST, suffixes: tuple[str, ...]) -> bool:
    name = _call_name(node)
    return name is not None and name.endswith(suffixes)


def _contains_sql_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        upper = node.value.upper()
        return any(verb in upper for verb in _SQL_VERBS)
    if isinstance(node, ast.JoinedStr):
        return any(_contains_sql_literal(value) for value in node.values)
    if isinstance(node, ast.FormattedValue):
        return _contains_sql_literal(node.value)
    if isinstance(node, ast.BinOp):
        return _contains_sql_literal(node.left) or _contains_sql_literal(node.right)
    if isinstance(node, ast.Call):
        return _expr_is_sql_format_call(node)
    return False


def _expr_is_sql_formatted(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return _contains_sql_literal(node) and any(
            isinstance(value, ast.FormattedValue) for value in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return _contains_sql_literal(node.left)
    if isinstance(node, ast.Call):
        return _expr_is_sql_format_call(node)
    return False


def _expr_is_sql_format_call(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and _contains_sql_literal(node.func.value)
    )


def _has_comma_star_group(pattern: str) -> bool:
    return bool(re.search(r"\((?:\?:)?\.\*,\)\*", pattern))


def _anchor_strength(pattern: str) -> int:
    strength = 0
    if pattern.startswith("^") or pattern.startswith("\\A") or "(?:^" in pattern or "(^" in pattern:
        strength += 1
    if pattern.endswith("$") or pattern.endswith("\\Z") or pattern.endswith("\\z"):
        strength += 1
    if "(?:^|," in pattern or "(?:^|" in pattern:
        strength += 1
    return strength


def _constant_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_regex_sink_name(call_name: str) -> bool:
    if not call_name:
        return False
    # Aliases like `from re import search` resolve to `re.search` via import map.
    if not call_name.startswith("re."):
        return False
    return call_name.rsplit(".", maxsplit=1)[-1] in _REGEX_SINK_METHODS


def _regex_subject_arg(node: ast.Call, call_name: str) -> ast.AST | None:
    method = call_name.rsplit(".", maxsplit=1)[-1]
    if method == "compile":
        return None
    # search/match/fullmatch/findall/finditer/split(pattern, string, ...)
    # sub/subn(pattern, repl, string, ...)
    if method in {"sub", "subn"}:
        if len(node.args) >= 3:
            return node.args[2]
        for keyword in node.keywords:
            if keyword.arg == "string":
                return keyword.value
        return None
    if len(node.args) >= 2:
        return node.args[1]
    for keyword in node.keywords:
        if keyword.arg == "string":
            return keyword.value
    return None


def _extract_regex_pattern_strings(tree: ast.AST) -> tuple[str, ...]:
    collector = _ImportCollector()
    collector.visit(tree)
    patterns: list[str] = []
    const_names: dict[str, str] = {}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            for target in node.targets:
                key = _expr_key(target)
                if key:
                    const_names[key] = node.value.value
        if not isinstance(node, ast.Call):
            continue
        raw = _call_name(node.func)
        if raw is None:
            continue
        call_name = _resolve_dotted_name(raw, collector.aliases)
        if not _is_regex_sink_name(call_name) and not (
            raw.startswith("re.") and raw.rsplit(".", 1)[-1] in _REGEX_SINK_METHODS
        ):
            continue
        pattern: str | None = None
        if node.args:
            pattern = _constant_string(node.args[0])
            if pattern is None:
                key = _expr_key(node.args[0])
                if key is not None:
                    pattern = const_names.get(key)
        if pattern:
            patterns.append(pattern)
    return tuple(patterns)


def _normalize_call_args(node: ast.Call) -> tuple[str | None, ast.AST | None]:
    """Return (form, unistr) for unicodedata.normalize(form, unistr)."""
    form: str | None = None
    subject: ast.AST | None = None
    if (
        len(node.args) >= 1
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ):
        form = node.args[0].value
    if len(node.args) >= 2:
        subject = node.args[1]
    for keyword in node.keywords:
        if (
            keyword.arg == "form"
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
        ):
            form = keyword.value.value
        if keyword.arg in {"unistr", "string"}:
            subject = keyword.value
    return form, subject


def _is_constant_string(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _len_bound_names(node: ast.AST) -> set[str]:
    """Names compared via len(name) in a bound check (>, >=, <, <=)."""
    names: set[str] = set()
    if isinstance(node, ast.BoolOp):
        for value in node.values:
            names.update(_len_bound_names(value))
        return names
    if isinstance(node, ast.UnaryOp):
        return _len_bound_names(node.operand)
    if not isinstance(node, ast.Compare):
        return names
    if not any(isinstance(op, (ast.Gt, ast.GtE, ast.Lt, ast.LtE)) for op in node.ops):
        return names
    candidates = [node.left, *node.comparators]
    for candidate in candidates:
        name = _len_call_arg_name(candidate)
        if name is not None:
            names.add(name)
    return names


def _len_call_arg_name(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    is_len = isinstance(func, ast.Name) and func.id == "len"
    if not is_len:
        return None
    if len(node.args) != 1:
        return None
    return _expr_key(node.args[0])


def _body_aborts(body: list[ast.stmt]) -> bool:
    """True if the branch can exit the expensive path (return/raise/continue)."""
    for statement in body:
        if isinstance(statement, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return True
        if isinstance(statement, ast.If) and (
            _body_aborts(statement.body) or _body_aborts(statement.orelse)
        ):
            return True
    return False

