"""Adapter plugin API: built-in tools plus TOML-defined external scanners."""

from __future__ import annotations

import tomllib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from verisec_agent.models import VerificationCommand
from verisec_agent.tool_adapters import ToolAdapter


@dataclass(frozen=True)
class AdapterSpec:
    """Portable adapter definition (in-code or loaded from TOML)."""

    adapter_id: str
    name: str
    description: str
    command: str
    capabilities: tuple[str, ...]
    timeout_seconds: int = 60
    required: bool = False
    executable: str | None = None
    parser: str = ""
    command_argv: tuple[str, ...] = ()

    def to_tool_adapter(self) -> ToolAdapter:
        return ToolAdapter(
            adapter_id=self.adapter_id,
            name=self.name,
            description=self.description,
            command=self.command,
            capabilities=self.capabilities,
            timeout_seconds=self.timeout_seconds,
            required=self.required,
            executable=self.executable,
        )

    def to_command(self, overrides: dict[str, Any] | None = None) -> VerificationCommand:
        data = dict(overrides or {})
        if self.command_argv and "argv" not in data:
            data = {**data, "argv": list(self.command_argv)}
        return self.to_tool_adapter().to_command(data)


class AdapterRegistry:
    """Merged view of built-in adapters and TOML/plugin specs."""

    def __init__(self, specs: Sequence[AdapterSpec]) -> None:
        by_id: dict[str, AdapterSpec] = {}
        for spec in specs:
            by_id[spec.adapter_id] = spec
        self._specs = by_id

    def get(self, adapter_id: str) -> AdapterSpec | None:
        return self._specs.get(adapter_id)

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._specs))

    def all_specs(self) -> tuple[AdapterSpec, ...]:
        return tuple(self._specs[key] for key in sorted(self._specs))

    def as_tool_adapters(self) -> dict[str, ToolAdapter]:
        return {
            adapter_id: spec.to_tool_adapter() for adapter_id, spec in self._specs.items()
        }

    def resolve(self, item: dict[str, Any]) -> VerificationCommand:
        adapter_id = str(item.get("id", item.get("adapter", "")))
        spec = self._specs.get(adapter_id)
        if spec is None:
            known = ", ".join(self.ids()) or "none"
            raise ValueError(
                f"Unknown verification adapter '{adapter_id}'. Known adapters: {known}."
            )
        return spec.to_command(item)

    def parser_for(self, adapter_id: str) -> str:
        spec = self._specs.get(adapter_id)
        if spec is None:
            return ""
        return spec.parser


def load_adapter_spec_from_toml(path: Path) -> AdapterSpec:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    adapter_id = str(data.get("id") or data.get("adapter_id") or path.stem)
    capabilities = data.get("capabilities", ())
    argv = data.get("argv") or data.get("command_argv") or ()
    executable = data.get("executable")
    return AdapterSpec(
        adapter_id=adapter_id,
        name=str(data.get("name", adapter_id)),
        description=str(data.get("description", "")),
        command=str(data.get("command", "")),
        capabilities=tuple(str(item) for item in capabilities),
        timeout_seconds=int(data.get("timeout_seconds", 60)),
        required=bool(data.get("required", False)),
        executable=None if executable in (None, "") else str(executable),
        parser=str(data.get("parser", "")),
        command_argv=tuple(str(item) for item in argv),
    )


def builtin_adapter_specs() -> tuple[AdapterSpec, ...]:
    from verisec_agent.tool_adapters import BUILTIN_ADAPTERS

    specs: list[AdapterSpec] = []
    for adapter_id, adapter in BUILTIN_ADAPTERS.items():
        parser = ""
        if adapter_id == "semgrep":
            parser = "semgrep"
        elif adapter_id == "codeql":
            parser = "codeql"
        specs.append(
            AdapterSpec(
                adapter_id=adapter.adapter_id,
                name=adapter.name,
                description=adapter.description,
                command=adapter.command,
                capabilities=adapter.capabilities,
                timeout_seconds=adapter.timeout_seconds,
                required=adapter.required,
                executable=adapter.executable,
                parser=parser,
            )
        )
    return tuple(specs)


def load_adapter_registry(
    *,
    adapter_paths: Iterable[Path] | None = None,
    config_dir: Path | None = None,
) -> AdapterRegistry:
    specs: list[AdapterSpec] = list(builtin_adapter_specs())
    for raw_path in adapter_paths or ():
        path = Path(raw_path)
        if not path.is_absolute() and config_dir is not None:
            path = (config_dir / path).resolve()
        else:
            path = path.resolve()
        if not path.is_file():
            raise ValueError(f"Adapter definition not found: {path}")
        specs.append(load_adapter_spec_from_toml(path))
    return AdapterRegistry(specs)


# Process-wide registry used by config resolution and tool output parsing.
_ACTIVE_REGISTRY: AdapterRegistry | None = None


def get_adapter_registry() -> AdapterRegistry:
    global _ACTIVE_REGISTRY
    if _ACTIVE_REGISTRY is None:
        _ACTIVE_REGISTRY = load_adapter_registry()
    return _ACTIVE_REGISTRY


def set_adapter_registry(registry: AdapterRegistry | None) -> None:
    global _ACTIVE_REGISTRY
    _ACTIVE_REGISTRY = registry


def reset_adapter_registry() -> None:
    set_adapter_registry(None)
