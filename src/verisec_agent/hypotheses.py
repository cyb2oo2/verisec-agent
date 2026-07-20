from __future__ import annotations

import io
import re
import tokenize
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from verisec_agent.models import EvidenceWindow, SecurityHypothesis, Severity
from verisec_agent.python_semantics import SemanticMatch
from verisec_agent.rules_api import RuleRegistry, load_rule_registry


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
    family: str = "general"
    mode: str = "either"


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
        family="complexity-dos",
        mode="adds-hardening",
    ),
    Rule(
        rule_id="py-unicode-normalization-dos",
        title="Unicode normalization complexity DoS path changed",
        severity="medium",
        pattern=re.compile(
            r"unicodedata\.normalize\s*\(\s*[\"']NFK[CD][\"']"
            r"|normalize\s*\(\s*[\"']NFK[CD][\"']"
        ),
        risk=(
            "Unicode normalization (especially NFKC) on attacker-controlled strings "
            "can cause CPU denial of service without prior length or validity bounds."
        ),
        fix_guidance=(
            "Reject or truncate overlong inputs before calling unicodedata.normalize, "
            "and keep expensive normalization off invalid values."
        ),
        recommended_validation=("Unicode normalization complexity regression test",),
        confidence=0.66,
        false_positive_notes=(
            "Normalization on trusted constants is safe; hardening guards should dominate "
            "the normalize call on the same function path."
        ),
        scan_mode="python-text",
        family="complexity-dos",
        mode="either",
    ),
    Rule(
        rule_id="py-regex-redos-hardening",
        title="Regular expression DoS hardening changed",
        severity="medium",
        pattern=re.compile(
            r"re\.(search|match|compile|fullmatch|findall|sub)\s*\([^,\n]*"
            r"(\(\s*[^)]*\|[^)]*\)\s*\+|\(\?:?\.\*,\)\*|\*\s*\$)"
            r"|PROCESS_AS_KEYWORD\s*=\s*object\(\)"
            r"|action\s+is\s+keywords\.PROCESS_AS_KEYWORD"
        ),
        risk="Ambiguous repetition or alternation in regular expressions can cause ReDoS.",
        fix_guidance=(
            "Prefer linear-time regex structure, simpler alternatives, or bounded parsing."
        ),
        recommended_validation=("ReDoS regression test with adversarial input",),
        confidence=0.63,
        false_positive_notes=(
            "Regex hardening is context-sensitive; confirm the changed expression is on "
            "attacker-controlled input. Length bounds alone are not ReDoS signals."
        ),
        scan_mode="python-text",
        family="redos",
        mode="adds-hardening",
    ),
    Rule(
        rule_id="py-regex-redos",
        title="Regular expression DoS risk introduced",
        severity="medium",
        pattern=re.compile(
            r"re\.(search|match|compile|fullmatch|findall|sub)\s*\(\s*[rbu]*[\"'][^\"']*"
            r"(\([^)]*[+*][^)]*\)[+*]|\(\?:?\.\*,\)\*)"
        ),
        risk=(
            "Nested quantifiers or other catastrophic-backtracking shapes can deny "
            "service when applied to attacker-controlled input."
        ),
        fix_guidance=(
            "Rewrite the expression to linear-time form, bound input length before matching, "
            "or use an atomic/possessive engine where available."
        ),
        recommended_validation=("ReDoS regression test with adversarial input",),
        confidence=0.68,
        false_positive_notes=(
            "Shape heuristics can over-approximate; confirm the subject is untrusted and "
            "that the pattern is reachable in production paths."
        ),
        scan_mode="python-text",
        family="redos",
        mode="introduces-risk",
    ),
)

# Built-in pack content. ``RULES`` remains the default full set for back-compat.
BUILTIN_RULES: tuple[Rule, ...] = RULES
RULE_BY_ID = {rule.rule_id: rule for rule in RULES}


def generate_hypotheses(
    windows: tuple[EvidenceWindow, ...],
    *,
    min_confidence: float,
    repo_path: Path | None = None,
    rule_packs: tuple[str, ...] | None = None,
    rule_registry: RuleRegistry | None = None,
) -> tuple[SecurityHypothesis, ...]:
    registry = rule_registry or load_rule_registry(rule_packs)
    active_rules = registry.rules()
    rules_by_id = {rule.rule_id: rule for rule in active_rules}

    hypotheses: list[SecurityHypothesis] = []
    seen: set[tuple[str, str, str]] = set()
    seen_windows: set[tuple[str, str, int, int]] = set()

    windows_by_file: dict[str, list[EvidenceWindow]] = defaultdict(list)
    for window in windows:
        if _is_python_path(window.file_path):
            windows_by_file[window.file_path].append(window)

    # File-scope matches attach to exactly one best window per (file, rule).
    file_matches = _file_level_matches(windows, repo_path=repo_path, registry=registry)
    file_string_line_cache: dict[str, frozenset[int]] = {}
    file_match_by_window: dict[int, list[SemanticMatch]] = defaultdict(list)
    for file_path, matches in file_matches.items():
        file_windows = windows_by_file.get(file_path, [])
        for match in matches:
            target = _best_window_for_match(match, file_windows)
            if target is not None:
                file_match_by_window[id(target)].append(match)

    for window in windows:
        if not _is_python_path(window.file_path):
            continue

        semantic_matches = _prefer_redos_mode(
            _prefer_richer_matches(
                list(registry.analyze_window(window))
                + file_match_by_window.get(id(window), [])
            )
        )
        window_families: set[str] = set()

        for match in semantic_matches:
            rule = rules_by_id.get(match.rule_id)
            if rule is None:
                continue
            confidence = _clamp_confidence(rule.confidence + match.confidence_boost)
            if confidence < min_confidence:
                continue
            window_key = _window_rule_key(rule, window)
            if window_key in seen_windows:
                continue
            key = _dedupe_key(rule, window)
            if key in seen:
                continue
            seen_windows.add(window_key)
            seen.add(key)
            family = match.family or rule.family
            if family:
                window_families.add(family)
            hypotheses.append(_build_hypothesis(rule, window, match=match, confidence=confidence))

        string_lines = _file_string_lines(
            repo_path, window.file_path, cache=file_string_line_cache
        )
        added_text = "\n".join(
            line.content
            for line in window.lines
            if line.change_type == "add" and line.new_line not in string_lines
        )
        deleted_text = "\n".join(
            line.content for line in window.lines if line.change_type == "delete"
        )
        changed_text = "\n".join(value for value in (added_text, deleted_text) if value)
        for rule in active_rules:
            if _should_skip_regex_fallback(rule, window_families):
                continue
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

    return _dedupe_redos_hypotheses(tuple(hypotheses))


def _should_skip_regex_fallback(rule: Rule, window_families: set[str]) -> bool:
    """Prefer semantic hits and avoid cross-family rule confusion."""
    if rule.family == "redos" and "complexity-dos" in window_families:
        return True
    # Prefer AST/dataflow ReDoS hits over a second regex-only redos finding.
    if rule.family == "redos" and "redos" in window_families:
        return True
    # Prefer AST/dataflow hits for unicode normalize over a second regex-only hit.
    return (
        rule.rule_id == "py-unicode-normalization-dos"
        and "complexity-dos" in window_families
    )


def _file_level_matches(
    windows: tuple[EvidenceWindow, ...],
    *,
    repo_path: Path | None,
    registry: RuleRegistry,
) -> dict[str, tuple[SemanticMatch, ...]]:
    if repo_path is None:
        return {}

    changed_by_file: dict[str, set[int]] = defaultdict(set)
    for window in windows:
        if not _is_python_path(window.file_path):
            continue
        for line in window.lines:
            if line.change_type == "add" and line.new_line is not None:
                changed_by_file[window.file_path].add(line.new_line)

    results: dict[str, tuple[SemanticMatch, ...]] = {}
    root = repo_path.resolve()
    for relative_path, changed_lines in changed_by_file.items():
        target = (root / relative_path).resolve()
        try:
            target.relative_to(root)
        except ValueError:
            continue
        if not target.is_file():
            continue
        matches = registry.analyze_file(file_path=target, changed_lines=changed_lines)
        if matches:
            results[relative_path] = matches
    return results


def _best_window_for_match(
    match: SemanticMatch,
    file_windows: list[EvidenceWindow],
) -> EvidenceWindow | None:
    if not file_windows:
        return None
    if match.sink_line is not None:
        for window in file_windows:
            if window.start_line <= match.sink_line <= window.end_line:
                return window
        # Sink is outside every evidence window: attach to the nearest window.
        return min(
            file_windows,
            key=lambda window: min(
                abs(window.start_line - match.sink_line),
                abs(window.end_line - match.sink_line),
            ),
        )
    for window in file_windows:
        if any(line.change_type == "add" for line in window.lines):
            return window
    return file_windows[0]


def _prefer_richer_matches(matches: list[SemanticMatch]) -> list[SemanticMatch]:
    best: dict[str, SemanticMatch] = {}
    for match in matches:
        current = best.get(match.rule_id)
        if current is None or _match_richness(match) > _match_richness(current):
            best[match.rule_id] = match
    return list(best.values())


def _prefer_redos_mode(matches: list[SemanticMatch]) -> list[SemanticMatch]:
    """Prefer hardening over introduces-risk when both redos modes fire."""
    if any(match.rule_id == "py-regex-redos-hardening" for match in matches):
        return [match for match in matches if match.rule_id != "py-regex-redos"]
    return matches


def _dedupe_redos_hypotheses(
    hypotheses: tuple[SecurityHypothesis, ...],
) -> tuple[SecurityHypothesis, ...]:
    """Drop introduces-risk ReDoS when the same file already has hardening."""
    hardened_files = {
        item.evidence.file_path
        for item in hypotheses
        if item.rule_id == "py-regex-redos-hardening"
    }
    if not hardened_files:
        return hypotheses
    return tuple(
        item
        for item in hypotheses
        if not (
            item.rule_id == "py-regex-redos" and item.evidence.file_path in hardened_files
        )
    )


def _match_richness(match: SemanticMatch) -> tuple[int, float, int, int]:
    return (
        1 if match.analysis_scope == "file" else 0,
        match.confidence_boost,
        len(match.steps),
        len(match.sources),
    )


def _is_python_path(file_path: str) -> bool:
    return file_path.lower().endswith((".py", ".pyi"))


def _build_hypothesis(
    rule: Rule,
    window: EvidenceWindow,
    *,
    match: SemanticMatch | None = None,
    confidence: float | None = None,
) -> SecurityHypothesis:
    notes = ""
    steps: tuple[str, ...] = ()
    scope = ""
    resolved_confidence = rule.confidence if confidence is None else confidence
    title = rule.title
    if match is not None:
        steps = match.steps
        scope = match.analysis_scope
        notes = _format_analysis_notes(match, rule=rule)
        title = _title_for_mode(rule, match.mode)
        if match.mode == "adds-hardening":
            resolved_confidence = _clamp_confidence(resolved_confidence)
        elif match.mode == "introduces-risk":
            resolved_confidence = _clamp_confidence(resolved_confidence + 0.02)
    return SecurityHypothesis(
        rule_id=rule.rule_id,
        title=title,
        severity=rule.severity,
        confidence=resolved_confidence,
        evidence=window,
        risk=rule.risk,
        recommended_validation=rule.recommended_validation,
        fix_guidance=rule.fix_guidance,
        false_positive_notes=rule.false_positive_notes,
        dataflow_steps=steps,
        analysis_scope=scope,
        analysis_notes=notes,
    )


def _title_for_mode(rule: Rule, mode: str) -> str:
    if rule.rule_id == "py-unicode-normalization-dos":
        if mode == "adds-hardening":
            return "Unicode normalization complexity DoS hardening changed"
        if mode == "introduces-risk":
            return "Unicode normalization complexity DoS path introduced"
        return rule.title
    if rule.rule_id == "py-regex-redos-hardening" and mode == "adds-hardening":
        return "Regular expression DoS hardening changed"
    if rule.rule_id == "py-regex-redos" and mode == "introduces-risk":
        return "Regular expression DoS risk introduced"
    return rule.title


def _format_analysis_notes(match: SemanticMatch, *, rule: Rule | None = None) -> str:
    parts: list[str] = []
    family = match.family or (rule.family if rule is not None else "")
    mode = match.mode or (rule.mode if rule is not None else "")
    if family:
        parts.append(f"Family: {family}.")
    if mode and mode != "either":
        parts.append(f"Mode: {mode}.")
    if match.analysis_scope:
        parts.append(f"AST/dataflow scope: {match.analysis_scope}.")
    if match.sink:
        location = f" at line {match.sink_line}" if match.sink_line else ""
        parts.append(f"Sink: {match.sink}{location}.")
    if match.sources:
        parts.append("Sources: " + ", ".join(f"`{source}`" for source in match.sources) + ".")
    if match.steps:
        parts.append("Path: " + " → ".join(match.steps) + ".")
    if match.confidence_boost:
        parts.append(f"Semantic confidence boost: +{match.confidence_boost:.2f}.")
    return " ".join(parts)


def _clamp_confidence(value: float) -> float:
    return max(0.0, min(0.99, round(value, 2)))


def _scan_text_for_rule(rule: Rule, text: str) -> str:
    if rule.scan_mode == "python-text":
        return _strip_python_comments(text, preserve_strings=True)
    return _strip_python_comments(text, preserve_strings=False)


def _strip_python_comments(text: str, *, preserve_strings: bool) -> str:
    masked = frozenset() if preserve_strings else _multiline_string_lines(text)
    return "\n".join(
        "" if number in masked else _strip_python_line(line, preserve_strings=preserve_strings)
        for number, line in enumerate(text.splitlines(), start=1)
    )


def _multiline_string_lines(text: str) -> frozenset[int]:
    """Line numbers spanned by multi-line string tokens.

    Per-line tokenization cannot see these: tokenizing a single line of a
    triple-quoted block raises TokenError for the unterminated string, so the
    line falls through unstripped and its contents read as executable code.
    Masking is line-preserving so evidence-window line mapping is unaffected.
    """
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (IndentationError, SyntaxError, tokenize.TokenError):
        return _unterminated_triple_quote_lines(text)
    return frozenset(
        number
        for token in tokens
        if token.type == tokenize.STRING and token.end[0] > token.start[0]
        for number in range(token.start[0], token.end[0] + 1)
    )


def _file_string_lines(
    repo_path: Path | None,
    file_path: str,
    *,
    cache: dict[str, frozenset[int]],
) -> frozenset[int]:
    """Line numbers inside multi-line strings in the checked-out file.

    An evidence window is a bounded diff excerpt, so it routinely cuts a
    triple-quoted code sample and cannot show on its own whether a line is string
    data or a real call site. The checkout is the patched revision, so added-line
    numbers index directly into it and give ground truth instead of delimiter
    guesswork. Real call sites are never inside a string span, so this suppresses
    embedded samples without weakening detection.

    Returns an empty set when no checkout is available, leaving the window-local
    heuristics as the only defence.
    """
    if repo_path is None:
        return frozenset()
    if file_path in cache:
        return cache[file_path]

    lines: frozenset[int] = frozenset()
    root = repo_path.resolve()
    target = (root / file_path).resolve()
    try:
        target.relative_to(root)
        source = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, ValueError):
        pass
    else:
        lines = _multiline_string_lines(source)
    cache[file_path] = lines
    return lines


def _unterminated_triple_quote_lines(text: str) -> frozenset[int]:
    """Lines following a triple-quote opener that the fragment never closes.

    Evidence windows are bounded diff excerpts, so a triple-quoted code sample is
    routinely cut before its closing delimiter and tokenize cannot parse it. Only
    an opener carrying real code before the quote on the same line (``return '''``,
    ``source = \"\"\"``) starts masking, so a window that merely begins inside a
    string is left untouched rather than over-suppressed.
    """
    lines = text.splitlines()
    for number, line in enumerate(lines, start=1):
        for quote in ('"""', "'''"):
            index = line.find(quote)
            if index == -1 or line.count(quote) > 1:
                continue
            prefix = line[:index].strip()
            if not prefix or prefix.startswith("#"):
                continue
            if any(quote in later for later in lines[number:]):
                continue
            return frozenset(range(number, len(lines) + 1))
    return frozenset()


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
