"""Optional Django-oriented rule pack.

The Django SQL hardening rules are defined once in :mod:`verisec_agent.hypotheses`
(they ship in the always-on ``builtin`` pack) and re-exported here so the ``django``
pack can be loaded standalone. A single definition keeps the two copies from
drifting; the previous verbatim duplicate did. Whether these patch-literal rules
should stay at all is a separate, deferred owner decision — see DEVELOPMENT_LOG.md
D-021.

Enable with:

```toml
[rules]
packs = ["builtin", "django"]
```
"""

from __future__ import annotations

from pathlib import Path

from verisec_agent.hypotheses import RULES, Rule
from verisec_agent.models import EvidenceWindow
from verisec_agent.python_semantics import SemanticMatch

_DJANGO_RULE_IDS = frozenset(
    {
        "py-sql-lookup-injection",
        "py-sql-identifier-injection",
        "py-sql-explain-option-injection",
        "py-sql-delimiter-injection",
    }
)

DJANGO_RULES: tuple[Rule, ...] = tuple(
    rule for rule in RULES if rule.rule_id in _DJANGO_RULE_IDS
)

# Fail fast if a re-export target is renamed or dropped in hypotheses.RULES rather
# than silently shrinking the django pack.
if {rule.rule_id for rule in DJANGO_RULES} != set(_DJANGO_RULE_IDS):
    missing = set(_DJANGO_RULE_IDS) - {rule.rule_id for rule in DJANGO_RULES}
    raise RuntimeError(f"django rule pack missing rules from builtin RULES: {sorted(missing)}")


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
