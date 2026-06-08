from __future__ import annotations

import ast
import textwrap
from dataclasses import dataclass

from verisec_agent.models import EvidenceWindow


@dataclass(frozen=True)
class SemanticMatch:
    rule_id: str


_SUBPROCESS_SINKS = {
    "call",
    "check_call",
    "check_output",
    "Popen",
    "run",
}
_SQL_VERBS = ("SELECT", "INSERT", "UPDATE", "DELETE")
_SAFE_YAML_LOADERS = ("SafeLoader", "CSafeLoader")


def analyze_python_window(window: EvidenceWindow) -> tuple[SemanticMatch, ...]:
    if not window.file_path.endswith(".py"):
        return ()

    matches: list[SemanticMatch] = []
    seen: set[str] = set()
    for change_type in ("add", "delete"):
        parsed = _parse_window_version(window, change_type)
        if parsed is None:
            continue
        tree, changed_lines = parsed
        analyzer = _SemanticAnalyzer(changed_lines)
        for match in analyzer.analyze(tree):
            if match.rule_id in seen:
                continue
            seen.add(match.rule_id)
            matches.append(match)

    return tuple(matches)


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
    def __init__(self, changed_lines: set[int]) -> None:
        self.changed_lines = changed_lines
        self.aliases: dict[str, str] = {}
        self.matches: list[SemanticMatch] = []
        self.seen_rule_ids: set[str] = set()
        self.tainted_scopes: list[set[str]] = [set()]
        self.changed_tainted_scopes: list[set[str]] = [set()]
        self.sql_scopes: list[set[str]] = [set()]
        self.changed_sql_scopes: list[set[str]] = [set()]

    def analyze(self, tree: ast.AST) -> tuple[SemanticMatch, ...]:
        collector = _ImportCollector()
        collector.visit(tree)
        self.aliases = collector.aliases
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
        for target in node.targets:
            self._assign_target(
                target,
                value_tainted=value_tainted,
                value_sql=value_sql,
                value_changed_tainted=value_changed_tainted,
                value_changed_sql=value_changed_sql,
            )

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
        self._assign_target(
            node.target,
            value_tainted=value_tainted,
            value_sql=value_sql,
            value_changed_tainted=value_changed_tainted,
            value_changed_sql=value_changed_sql,
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
        self._assign_target(
            node.target,
            value_tainted=value_tainted,
            value_sql=value_sql,
            value_changed_tainted=value_changed_tainted,
            value_changed_sql=value_changed_sql,
        )

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._resolved_call_name(node)
        if self._node_changed(node) or self._call_uses_changed_security_input(
            node, call_name
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

        self.tainted_scopes.append(params)
        self.changed_tainted_scopes.append(set())
        self.sql_scopes.append(set())
        self.changed_sql_scopes.append(set())
        for statement in node.body:
            self.visit(statement)
        self.changed_sql_scopes.pop()
        self.sql_scopes.pop()
        self.changed_tainted_scopes.pop()
        self.tainted_scopes.pop()

    def _check_call_sink(self, node: ast.Call, call_name: str) -> None:
        if self._is_shell_execution(call_name, node):
            self._add_match("py-shell-true")
        if call_name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            self._add_match("py-eval-exec")
        if call_name == "yaml.load" and not self._has_safe_yaml_loader(node):
            self._add_match("py-unsafe-yaml")
        if self._has_false_keyword(node, "verify"):
            self._add_match("py-tls-verify-disabled")
        if call_name.lower() in {"hashlib.md5", "hashlib.sha1"}:
            self._add_match("weak-hash")
        if self._is_sql_execute(call_name) and self._call_uses_sql_sensitive_arg(node):
            self._add_match("py-sql-string-format")

    def _is_shell_execution(self, call_name: str, node: ast.Call) -> bool:
        if not self._has_true_keyword(node, "shell"):
            return False
        if not call_name.startswith("subprocess."):
            return False
        return call_name.rsplit(".", maxsplit=1)[-1] in _SUBPROCESS_SINKS

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
        if call_name in {"eval", "exec", "builtins.eval", "builtins.exec"} and node.args:
            return self._expr_changed_tainted(node.args[0])
        if call_name == "yaml.load" and node.args:
            return self._expr_changed_tainted(node.args[0])
        if self._is_sql_execute(call_name) and node.args:
            return self._expr_changed_sql_sensitive(node.args[0])
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
            return _expr_is_sql_format_call(node) and self._expr_tainted(node)
        return False

    def _expr_tainted(self, node: ast.AST) -> bool:
        key = _expr_key(node)
        if key and self._is_tainted_name(key):
            return True
        if isinstance(node, ast.Call):
            call_name = self._resolved_call_name(node)
            if call_name in {"input", "builtins.input"}:
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
            return self._expr_tainted(node.value) or self._expr_tainted(node.slice)
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
            return _expr_is_sql_format_call(node) and self._expr_changed_tainted(node)
        return False

    def _assign_target(
        self,
        target: ast.AST,
        *,
        value_tainted: bool,
        value_sql: bool,
        value_changed_tainted: bool,
        value_changed_sql: bool,
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

    def _is_tainted_name(self, key: str) -> bool:
        return any(key in scope for scope in reversed(self.tainted_scopes))

    def _is_sql_name(self, key: str) -> bool:
        return any(key in scope for scope in reversed(self.sql_scopes))

    def _is_changed_tainted_name(self, key: str) -> bool:
        return any(key in scope for scope in reversed(self.changed_tainted_scopes))

    def _is_changed_sql_name(self, key: str) -> bool:
        return any(key in scope for scope in reversed(self.changed_sql_scopes))

    def _resolved_call_name(self, node: ast.Call) -> str:
        name = _call_name(node.func)
        if name is None:
            return ""
        return _resolve_dotted_name(name, self.aliases)

    def _node_changed(self, node: ast.AST) -> bool:
        start = getattr(node, "lineno", 0)
        end = getattr(node, "end_lineno", start)
        return any(line in self.changed_lines for line in range(start, end + 1))

    def _add_match(self, rule_id: str) -> None:
        if rule_id in self.seen_rule_ids:
            return
        self.seen_rule_ids.add(rule_id)
        self.matches.append(SemanticMatch(rule_id=rule_id))

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
