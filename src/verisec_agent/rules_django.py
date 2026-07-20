"""Optional Django-oriented rule pack.

Enable with:

```toml
[rules]
packs = ["builtin", "django"]
```
"""

from __future__ import annotations

import re
from pathlib import Path

from verisec_agent.hypotheses import Rule
from verisec_agent.models import EvidenceWindow
from verisec_agent.python_semantics import SemanticMatch

DJANGO_RULES: tuple[Rule, ...] = (
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
        family="injection",
        mode="adds-hardening",
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
        family="injection",
        mode="adds-hardening",
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
        family="injection",
        mode="adds-hardening",
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
        family="injection",
        mode="adds-hardening",
    ),
)


class DjangoRuleProvider:
    """Regex-oriented Django ORM / SQL hardening rules (no extra AST pass)."""

    @property
    def pack_id(self) -> str:
        return "django"

    def rules(self) -> tuple[Rule, ...]:
        return DJANGO_RULES

    def analyze_window(self, window: EvidenceWindow) -> tuple[SemanticMatch, ...]:
        return ()

    def analyze_file(
        self,
        *,
        file_path: Path,
        changed_lines: set[int],
    ) -> tuple[SemanticMatch, ...]:
        return ()
