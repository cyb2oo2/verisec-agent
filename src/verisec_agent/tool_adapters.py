from __future__ import annotations

import shutil
from dataclasses import dataclass, replace
from typing import Any

from verisec_agent.models import VerificationCommand


@dataclass(frozen=True)
class ToolAdapter:
    adapter_id: str
    name: str
    description: str
    command: str
    capabilities: tuple[str, ...]
    timeout_seconds: int = 60
    required: bool = False
    executable: str | None = None

    def to_command(self, overrides: dict[str, Any] | None = None) -> VerificationCommand:
        data = overrides or {}
        capabilities = data.get("capabilities")
        if capabilities is None:
            resolved_capabilities = self.capabilities
        else:
            resolved_capabilities = tuple(str(item) for item in capabilities)

        return VerificationCommand(
            name=str(data.get("name", self.name)),
            command=str(data.get("command", self.command)),
            timeout_seconds=int(data.get("timeout_seconds", self.timeout_seconds)),
            required=bool(data.get("required", self.required)),
            adapter=self.adapter_id,
            description=str(data.get("description", self.description)),
            capabilities=resolved_capabilities,
            command_argv=_command_argv(data),
        )

    def with_availability(self) -> DiscoveredToolAdapter:
        if self.executable is None:
            available = True
            reason = "Runs through the configured Python interpreter."
        else:
            available = shutil.which(self.executable) is not None
            reason = (
                f"Found executable '{self.executable}'."
                if available
                else f"Executable '{self.executable}' was not found on PATH."
            )
        return DiscoveredToolAdapter(
            adapter=self,
            available=available,
            reason=reason,
        )


@dataclass(frozen=True)
class DiscoveredToolAdapter:
    adapter: ToolAdapter
    available: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.adapter.adapter_id,
            "name": self.adapter.name,
            "description": self.adapter.description,
            "command": self.adapter.command,
            "capabilities": self.adapter.capabilities,
            "available": self.available,
            "reason": self.reason,
        }


BUILTIN_ADAPTERS: dict[str, ToolAdapter] = {
    "pytest": ToolAdapter(
        adapter_id="pytest",
        name="unit-tests",
        description="Run Python tests as regression and exploit-input checks.",
        command="{python} -m pytest",
        capabilities=("unit-test", "regression-test", "python-test"),
        timeout_seconds=60,
    ),
    "ruff": ToolAdapter(
        adapter_id="ruff",
        name="ruff",
        description="Run Ruff static lint checks for Python code quality signals.",
        command="{python} -m ruff check src tests",
        capabilities=("lint", "static-analysis", "python-static-analysis"),
        timeout_seconds=60,
    ),
    "semgrep": ToolAdapter(
        adapter_id="semgrep",
        name="semgrep",
        description="Run Semgrep security rules for injection and taint-style findings.",
        command="semgrep scan --config auto --json",
        capabilities=(
            "semgrep",
            "static-analysis",
            "taint-analysis",
            "command-injection",
            "sql-injection",
        ),
        timeout_seconds=120,
        executable="semgrep",
    ),
    "codeql": ToolAdapter(
        adapter_id="codeql",
        name="codeql",
        description="Run a configured CodeQL analysis command.",
        command=(
            "codeql database analyze codeql-db --format=sarif-latest "
            "--output={tool_dir}/codeql.sarif"
        ),
        capabilities=(
            "codeql",
            "static-analysis",
            "taint-analysis",
            "dataflow-analysis",
            "sql-injection",
            "command-injection",
        ),
        timeout_seconds=300,
        executable="codeql",
    ),
    "poc-script": ToolAdapter(
        adapter_id="poc-script",
        name="poc-script",
        description="Run a repository-specific proof-of-concept or exploit regression script.",
        command="{python} poc.py",
        capabilities=("poc", "exploit-regression", "regression-test"),
        timeout_seconds=60,
    ),
}


def list_builtin_adapters() -> tuple[DiscoveredToolAdapter, ...]:
    from verisec_agent.adapters_api import get_adapter_registry

    registry = get_adapter_registry()
    adapters = registry.as_tool_adapters()
    return tuple(adapter.with_availability() for adapter in adapters.values())


def resolve_adapter(item: dict[str, Any]) -> VerificationCommand:
    from verisec_agent.adapters_api import get_adapter_registry

    return get_adapter_registry().resolve(item)


def enrich_custom_command(item: dict[str, Any]) -> VerificationCommand:
    from verisec_agent.adapters_api import get_adapter_registry

    capabilities = item.get("capabilities", ())
    adapter = str(item.get("adapter", "custom"))
    command = str(item.get("command") or _display_argv(_command_argv(item)))
    registry = get_adapter_registry()
    adapter_template = registry.as_tool_adapters().get(adapter) or BUILTIN_ADAPTERS.get(
        adapter
    )
    if adapter_template is not None:
        base = adapter_template.to_command(item)
        return replace(
            base,
            command=command,
            name=str(item.get("name", base.name)),
            command_argv=_command_argv(item),
        )
    return VerificationCommand(
        name=item["name"],
        command=command,
        timeout_seconds=int(item.get("timeout_seconds", 60)),
        required=bool(item.get("required", False)),
        adapter=adapter,
        description=str(item.get("description", "")),
        capabilities=tuple(str(value) for value in capabilities),
        command_argv=_command_argv(item),
    )


def _command_argv(data: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(value) for value in data.get("argv", ()))


def _display_argv(argv: tuple[str, ...]) -> str:
    return " ".join(argv)
