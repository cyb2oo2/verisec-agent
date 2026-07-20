"""Rule pack plugin API for VeriSec.

Built-in detection stays the default via ``BuiltinRuleProvider``. Additional
packs can be enabled from config or discovered via setuptools entry points:

```toml
[rules]
packs = ["builtin", "django"]
```

Third-party packages register packs in ``pyproject.toml``:

```toml
[project.entry-points."verisec.rules"]
my-pack = "my_package.rules:MyRuleProvider"
```
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from importlib.metadata import EntryPoint, entry_points
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from verisec_agent.models import EvidenceWindow
from verisec_agent.python_semantics import SemanticMatch

RULES_ENTRY_POINT_GROUP = "verisec.rules"


@runtime_checkable
class RuleProvider(Protocol):
    """Provider of static rule metadata and optional semantic matches."""

    @property
    def pack_id(self) -> str:
        """Stable pack identifier used in ``[rules].packs``."""

    def rules(self) -> tuple:
        """Return ``Rule`` objects contributed by this pack."""

    def analyze_window(self, window: EvidenceWindow) -> tuple[SemanticMatch, ...]:
        """Return semantic matches for one evidence window (may be empty)."""

    def analyze_file(
        self,
        *,
        file_path: Path,
        changed_lines: set[int],
    ) -> tuple[SemanticMatch, ...]:
        """Return semantic matches for a full file with known changed lines."""


class RuleRegistry:
    """Composite view over one or more rule packs."""

    def __init__(self, providers: Sequence[RuleProvider]) -> None:
        self._providers = tuple(providers)
        # First provider wins on rule_id so builtin can own a rule while a
        # specialized pack remains usable alone.
        rules_by_id: dict[str, object] = {}
        ordered: list[object] = []
        for provider in self._providers:
            for rule in provider.rules():
                if rule.rule_id in rules_by_id:
                    continue
                rules_by_id[rule.rule_id] = rule
                ordered.append(rule)
        self._rules = tuple(ordered)
        self._rules_by_id = rules_by_id

    @property
    def providers(self) -> tuple[RuleProvider, ...]:
        return self._providers

    @property
    def pack_ids(self) -> tuple[str, ...]:
        return tuple(provider.pack_id for provider in self._providers)

    def rules(self) -> tuple:
        return self._rules

    def rule_by_id(self, rule_id: str):
        return self._rules_by_id.get(rule_id)

    def analyze_window(self, window: EvidenceWindow) -> tuple[SemanticMatch, ...]:
        matches: list[SemanticMatch] = []
        seen: set[str] = set()
        for provider in self._providers:
            for match in provider.analyze_window(window):
                if match.rule_id in seen:
                    continue
                # Only keep semantic hits whose rules are active in this registry.
                if match.rule_id not in self._rules_by_id:
                    continue
                seen.add(match.rule_id)
                matches.append(match)
        return tuple(matches)

    def analyze_file(
        self,
        *,
        file_path: Path,
        changed_lines: set[int],
    ) -> tuple[SemanticMatch, ...]:
        matches: list[SemanticMatch] = []
        seen: set[str] = set()
        for provider in self._providers:
            for match in provider.analyze_file(
                file_path=file_path,
                changed_lines=changed_lines,
            ):
                if match.rule_id in seen:
                    continue
                if match.rule_id not in self._rules_by_id:
                    continue
                seen.add(match.rule_id)
                matches.append(match)
        return tuple(matches)


_BUILTIN_PACK = "builtin"
_KNOWN_PACK_FACTORIES: dict[str, Callable[[], RuleProvider]] | None = None


def reset_rule_pack_cache() -> None:
    """Clear cached pack factories (tests / after dynamic registration)."""
    global _KNOWN_PACK_FACTORIES
    _KNOWN_PACK_FACTORIES = None


def _pack_factories() -> dict[str, Callable[[], RuleProvider]]:
    global _KNOWN_PACK_FACTORIES
    if _KNOWN_PACK_FACTORIES is not None:
        return _KNOWN_PACK_FACTORIES

    factories: dict[str, Callable[[], RuleProvider]] = {}
    factories.update(_builtin_pack_factories())
    # Entry points overlay built-ins (same name can be overridden by install).
    factories.update(_entry_point_pack_factories())
    _KNOWN_PACK_FACTORIES = factories
    return _KNOWN_PACK_FACTORIES


def _builtin_pack_factories() -> dict[str, Callable[[], RuleProvider]]:
    """Always-available in-tree packs (works without reinstalling entry points)."""
    # Lazy imports avoid import cycles with hypotheses / providers.
    from verisec_agent.rules_builtin import BuiltinRuleProvider
    from verisec_agent.rules_django import DjangoRuleProvider

    return {
        "builtin": BuiltinRuleProvider,
        "django": DjangoRuleProvider,
    }


def _entry_point_pack_factories() -> dict[str, Callable[[], RuleProvider]]:
    factories: dict[str, Callable[[], RuleProvider]] = {}
    for entry in _iter_rules_entry_points():
        name = str(entry.name).strip().lower()
        if not name:
            continue
        try:
            loaded = entry.load()
            factories[name] = _normalize_provider_factory(loaded, pack_name=name)
        except Exception:
            # Skip broken third-party entry points; built-ins remain usable.
            continue
    return factories


def _iter_rules_entry_points() -> tuple[EntryPoint, ...]:
    try:
        selected = entry_points(group=RULES_ENTRY_POINT_GROUP)
    except TypeError:
        # Older importlib.metadata API (select by dict).
        selected = entry_points().get(RULES_ENTRY_POINT_GROUP, ())  # type: ignore[call-arg]
    return tuple(selected)


def _normalize_provider_factory(
    loaded: Any,
    *,
    pack_name: str,
) -> Callable[[], RuleProvider]:
    """Accept a provider class, zero-arg factory, or already-built instance."""
    if isinstance(loaded, type):
        return loaded  # type: ignore[return-value]

    if callable(loaded) and not _looks_like_provider_instance(loaded):
        def factory() -> RuleProvider:
            result = loaded()
            if not _looks_like_provider_instance(result):
                raise TypeError(
                    f"Entry point '{pack_name}' factory did not return a RuleProvider"
                )
            return result

        return factory

    if _looks_like_provider_instance(loaded):
        return lambda: loaded  # type: ignore[return-value, no-any-return]

    raise TypeError(
        f"Entry point '{pack_name}' must be a RuleProvider class, factory, or instance"
    )


def _looks_like_provider_instance(value: Any) -> bool:
    return (
        hasattr(value, "pack_id")
        and hasattr(value, "rules")
        and hasattr(value, "analyze_window")
        and hasattr(value, "analyze_file")
        and not isinstance(value, type)
    )


def available_rule_packs() -> tuple[str, ...]:
    return tuple(sorted(_pack_factories()))


def load_rule_registry(packs: Iterable[str] | None = None) -> RuleRegistry:
    """Load rule providers for the requested pack ids (default: builtin only)."""
    requested = tuple(packs) if packs is not None else (_BUILTIN_PACK,)
    if not requested:
        requested = (_BUILTIN_PACK,)

    factories = _pack_factories()
    providers: list[RuleProvider] = []
    seen: set[str] = set()
    for pack_id in requested:
        key = str(pack_id).strip().lower()
        if not key or key in seen:
            continue
        factory = factories.get(key)
        if factory is None:
            known = ", ".join(sorted(factories))
            raise ValueError(
                f"Unknown rule pack '{pack_id}'. Known packs: {known}."
            )
        providers.append(factory())
        seen.add(key)
    if not providers:
        providers.append(factories[_BUILTIN_PACK]())
    return RuleRegistry(providers)
