from __future__ import annotations

import io
import re
import tokenize
from dataclasses import dataclass

from verisec_agent.models import EvidenceWindow, SecurityHypothesis, Severity
from verisec_agent.python_semantics import analyze_python_window


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: Severity
    pattern: re.Pattern[str]
    risk: str
    fix_guidance: str
    recommended_validation: tuple[str, ...]
    confidence: float
    false_positive_notes: str
    scan_mode: str = "python-code"


RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="py-eval-exec",
        title="Dynamic code execution introduced",
        severity="high",
        pattern=re.compile(r"\b(eval|exec)\s*\("),
        risk="Untrusted input reaching eval or exec can become arbitrary code execution.",
        fix_guidance="Replace dynamic execution with an explicit parser, allowlist, or data model.",
        recommended_validation=("unit tests for malicious input", "static taint analysis"),
        confidence=0.72,
        false_positive_notes=(
            "May be benign for constant-only expressions, but still requires review."
        ),
    ),
    Rule(
        rule_id="py-shell-true",
        title="Shell execution path introduced",
        severity="high",
        pattern=re.compile(r"\bsubprocess\.[a-zA-Z_]+\([^)]*shell\s*=\s*True"),
        risk="String commands with shell=True can allow command injection.",
        fix_guidance=(
            "Pass an argument list with shell=False and validate user-controlled fragments."
        ),
        recommended_validation=(
            "unit tests for shell metacharacters",
            "static command-injection rules",
        ),
        confidence=0.7,
        false_positive_notes=(
            "Lower risk if every command fragment is constant and not user controlled."
        ),
    ),
    Rule(
        rule_id="py-sql-string-format",
        title="SQL query string formatting introduced",
        severity="high",
        pattern=re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*(f\"|%|\.format\()", re.IGNORECASE),
        risk="Formatted SQL strings can allow injection when variables include attacker input.",
        fix_guidance="Use parameterized queries from the database driver.",
        recommended_validation=("SQL injection regression test", "static query construction scan"),
        confidence=0.64,
        false_positive_notes=(
            "May be safe for compile-time constants, but needs dataflow confirmation."
        ),
        scan_mode="python-text",
    ),
    Rule(
        rule_id="py-sql-lookup-injection",
        title="SQL lookup or truncation identifier hardening changed",
        severity="high",
        pattern=re.compile(
            r"extract_trunc_lookup_pattern\.fullmatch\(self\.(lookup_name|kind)\)"
        ),
        risk=(
            "Unvalidated lookup names or truncation kinds can become SQL fragments "
            "inside generated database expressions."
        ),
        fix_guidance=(
            "Constrain database expression identifiers to a strict allowlist or "
            "safe identifier pattern before SQL generation."
        ),
        recommended_validation=("SQL injection regression test",),
        confidence=0.66,
        false_positive_notes=(
            "This is usually a hardening signal; verify the checked value reaches "
            "database SQL generation."
        ),
        scan_mode="python-text",
    ),
    Rule(
        rule_id="py-sql-identifier-injection",
        title="SQL identifier alias validation changed",
        severity="high",
        pattern=re.compile(r"\bFORBIDDEN_ALIAS_PATTERN\s*="),
        risk=(
            "Unvalidated query aliases can become SQL identifiers and allow "
            "injection through annotation, aggregation, or extra-select APIs."
        ),
        fix_guidance=(
            "Reject aliases containing quotes, whitespace, semicolons, bracket "
            "characters, or SQL comment markers before SQL compilation."
        ),
        recommended_validation=("SQL injection regression test",),
        confidence=0.66,
        false_positive_notes=(
            "Alias validation is a hardening signal; verify the validator is used "
            "on annotation, aggregation, values, and extra-select alias paths."
        ),
        scan_mode="python-text",
    ),
    Rule(
        rule_id="py-sql-explain-option-injection",
        title="SQL EXPLAIN option validation changed",
        severity="high",
        pattern=re.compile(r"\bEXPLAIN_OPTIONS_PATTERN\.fullmatch\(option_name\)"),
        risk=(
            "Unvalidated EXPLAIN option names can be assembled into SQL fragments "
            "on database backends that accept option dictionaries."
        ),
        fix_guidance=(
            "Validate option names with a strict identifier pattern and reject SQL "
            "comment or statement-separator fragments before SQL generation."
        ),
        recommended_validation=("SQL injection regression test",),
        confidence=0.66,
        false_positive_notes=(
            "EXPLAIN option validation is backend-sensitive; verify the checked "
            "name reaches the backend SQL prefix builder."
        ),
        scan_mode="python-text",
    ),
    Rule(
        rule_id="py-sql-delimiter-injection",
        title="SQL aggregate delimiter parameterization changed",
        severity="high",
        pattern=re.compile(
            r"\bdelimiter_expr\s*=\s*Value\(str\(delimiter\)\)"
            r"|def\s+test_string_agg_delimiter_escaping\s*\("
        ),
        risk=(
            "Interpolating an attacker-controlled aggregate delimiter into a SQL "
            "template can allow SQL injection."
        ),
        fix_guidance=(
            "Represent the delimiter as a database expression or query parameter "
            "instead of interpolating it into the SQL template."
        ),
        recommended_validation=("SQL injection regression test",),
        confidence=0.68,
        false_positive_notes=(
            "Delimiter parameterization is a hardening signal; verify the expression "
            "is compiled through the database backend parameter path."
        ),
        scan_mode="python-text",
    ),
    Rule(
        rule_id="py-unsafe-yaml",
        title="Unsafe YAML loading path changed",
        severity="medium",
        pattern=re.compile(r"\byaml\.load\s*\((?![^)]*(SafeLoader|CSafeLoader))"),
        risk="yaml.load can construct arbitrary Python objects with unsafe loaders.",
        fix_guidance="Use yaml.safe_load or an explicit SafeLoader.",
        recommended_validation=("unit test with object-construction payload",),
        confidence=0.78,
        false_positive_notes=(
            "SafeLoader may be provided in another argument; verify the call signature."
        ),
    ),
    Rule(
        rule_id="py-yaml-safe-loader",
        title="YAML safe loader enforcement changed",
        severity="medium",
        pattern=re.compile(
            r"\b(yaml\.safe_load\s*\(|yaml\.load\s*\([^)]*(SafeLoader|CSafeLoader)|"
            r"safe_load\s*=\s*load|def\s+danger_load\s*\()"
        ),
        risk="YAML parsing behavior changed around object construction and deserialization.",
        fix_guidance="Confirm only safe loaders parse untrusted YAML inputs.",
        recommended_validation=("unit test with object-construction payload",),
        confidence=0.68,
        false_positive_notes=(
            "A safe loader is a hardening signal; verify the call is on the vulnerable path."
        ),
    ),
    Rule(
        rule_id="py-tls-verify-disabled",
        title="TLS certificate verification disabled",
        severity="medium",
        pattern=re.compile(r"\bverify\s*=\s*False\b"),
        risk="Disabling certificate verification exposes requests to man-in-the-middle attacks.",
        fix_guidance="Keep verification enabled and configure trusted certificates explicitly.",
        recommended_validation=("integration test against expected certificate chain",),
        confidence=0.74,
        false_positive_notes=(
            "May be acceptable in test-only code if isolated from production paths."
        ),
    ),
    Rule(
        rule_id="weak-hash",
        title="Weak hash primitive introduced",
        severity="medium",
        pattern=re.compile(r"\b(hashlib\.)?(md5|sha1)\s*\(", re.IGNORECASE),
        risk="MD5 and SHA-1 are unsuitable for collision-resistant security decisions.",
        fix_guidance="Use SHA-256 or a purpose-built password hashing/KDF primitive.",
        recommended_validation=("crypto policy check", "unit tests for migration compatibility"),
        confidence=0.58,
        false_positive_notes="May be acceptable for non-security checksums with clear labeling.",
    ),
    Rule(
        rule_id="py-dos-algorithmic-complexity",
        title="Algorithmic complexity DoS hardening changed",
        severity="medium",
        pattern=re.compile(
            r"exceeds_maximum_length_ratio\s*\("
            r"\s*password\s*,\s*self\.max_similarity\s*,\s*value_part\s*\)"
        ),
        risk=(
            "Unbounded expensive comparisons on attacker-controlled strings can "
            "cause CPU denial of service."
        ),
        fix_guidance=(
            "Short-circuit obviously unsafe length ratios before invoking expensive "
            "similarity, normalization, or parsing routines."
        ),
        recommended_validation=("algorithmic complexity regression test",),
        confidence=0.64,
        false_positive_notes=(
            "Complexity hardening is workload-sensitive; verify the skipped path "
            "guards an attacker-controlled expensive operation."
        ),
        scan_mode="python-text",
    ),
    Rule(
        rule_id="py-regex-redos-hardening",
        title="Regular expression DoS hardening changed",
        severity="medium",
        pattern=re.compile(
            r"re\.(search|match|compile)\s*\([^,\n]*(\(\s*[^)]*\|[^)]*\)\s*\+|\*\s*\$)"
            r"|PROCESS_AS_KEYWORD\s*=\s*object\(\)"
            r"|action\s+is\s+keywords\.PROCESS_AS_KEYWORD"
            r"|max_length\s*=\s*2048"
            r"|len\(value\)\s*>\s*(self\.max_length|320)"
        ),
        risk="Ambiguous repetition or alternation in regular expressions can cause ReDoS.",
        fix_guidance=(
            "Prefer linear-time regex structure, simpler alternatives, or bounded parsing."
        ),
        recommended_validation=("ReDoS regression test with adversarial input",),
        confidence=0.63,
        false_positive_notes=(
            "Regex hardening is context-sensitive; confirm the changed expression is on "
            "attacker-controlled input."
        ),
        scan_mode="python-text",
    ),
)

RULE_BY_ID = {rule.rule_id: rule for rule in RULES}


def generate_hypotheses(
    windows: tuple[EvidenceWindow, ...],
    *,
    min_confidence: float,
) -> tuple[SecurityHypothesis, ...]:
    hypotheses: list[SecurityHypothesis] = []
    seen: set[tuple[str, str, str]] = set()
    seen_windows: set[tuple[str, str, int, int]] = set()

    for window in windows:
        if not _is_python_path(window.file_path):
            continue
        for match in analyze_python_window(window):
            rule = RULE_BY_ID.get(match.rule_id)
            if rule is None or rule.confidence < min_confidence:
                continue
            window_key = _window_rule_key(rule, window)
            if window_key in seen_windows:
                continue
            key = _dedupe_key(rule, window)
            if key in seen:
                continue
            seen_windows.add(window_key)
            seen.add(key)
            hypotheses.append(_build_hypothesis(rule, window))

        added_text = "\n".join(
            line.content for line in window.lines if line.change_type == "add"
        )
        deleted_text = "\n".join(
            line.content for line in window.lines if line.change_type == "delete"
        )
        changed_text = "\n".join(value for value in (added_text, deleted_text) if value)
        for rule in RULES:
            scan_text = _scan_text_for_rule(rule, changed_text)
            if not rule.pattern.search(scan_text) or rule.confidence < min_confidence:
                continue
            window_key = _window_rule_key(rule, window)
            if window_key in seen_windows:
                continue
            key = _dedupe_key(rule, window)
            if key in seen:
                continue
            seen.add(key)
            seen_windows.add(window_key)
            hypotheses.append(_build_hypothesis(rule, window))

    return tuple(hypotheses)


def _is_python_path(file_path: str) -> bool:
    return file_path.lower().endswith((".py", ".pyi"))


def _build_hypothesis(rule: Rule, window: EvidenceWindow) -> SecurityHypothesis:
    return SecurityHypothesis(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        confidence=rule.confidence,
        evidence=window,
        risk=rule.risk,
        recommended_validation=rule.recommended_validation,
        fix_guidance=rule.fix_guidance,
        false_positive_notes=rule.false_positive_notes,
    )


def _scan_text_for_rule(rule: Rule, text: str) -> str:
    if rule.scan_mode == "python-text":
        return _strip_python_comments(text, preserve_strings=True)
    return _strip_python_comments(text, preserve_strings=False)


def _strip_python_comments(text: str, *, preserve_strings: bool) -> str:
    return "\n".join(
        _strip_python_line(line, preserve_strings=preserve_strings)
        for line in text.splitlines()
    )


def _strip_python_line(line: str, *, preserve_strings: bool) -> str:
    try:
        tokens = []
        for token in tokenize.generate_tokens(io.StringIO(f"{line}\n").readline):
            if token.type == tokenize.COMMENT:
                continue
            if token.type == tokenize.STRING and not preserve_strings:
                token = tokenize.TokenInfo(
                    type=token.type,
                    string='""',
                    start=token.start,
                    end=token.end,
                    line=token.line,
                )
            tokens.append(token)
        return tokenize.untokenize(tokens).rstrip("\n")
    except (IndentationError, SyntaxError, tokenize.TokenError):
        if line.lstrip().startswith("#"):
            return ""
        return line


def _dedupe_key(rule: Rule, window: EvidenceWindow) -> tuple[str, str, str]:
    matching_lines = [
        f"{line.change_type}:{line.new_line or line.old_line or 0}:{line.content.strip()}"
        for line in window.lines
        if line.change_type in {"add", "delete"} and rule.pattern.search(line.content)
    ]
    if matching_lines:
        return (rule.rule_id, window.file_path, "|".join(matching_lines))
    return (rule.rule_id, window.file_path, f"window:{window.start_line}")


def _window_rule_key(rule: Rule, window: EvidenceWindow) -> tuple[str, str, int, int]:
    return (rule.rule_id, window.file_path, window.start_line, window.end_line)
