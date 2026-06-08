from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from verisec_agent.models import VerificationCommand
from verisec_agent.tool_adapters import BUILTIN_ADAPTERS

PolicyStatus = Literal["allowed", "blocked"]
PolicyProfile = Literal["trusted-local", "trusted-ci", "untrusted-fork-pr"]
POLICY_PROFILES: tuple[PolicyProfile, ...] = (
    "trusted-local",
    "trusted-ci",
    "untrusted-fork-pr",
)

DEFAULT_ALLOWED_ADAPTERS = (
    "pytest",
    "ruff",
    "semgrep",
    "codeql",
    "poc-script",
    "custom",
)
DEFAULT_BLOCKED_COMMAND_PATTERNS = (
    "rm -rf",
    "remove-item -recurse",
    "del /s",
    "format c:",
    "format /",
    "mkfs",
    "shutdown",
    "reboot",
    "curl|sh",
    "curl|bash",
    "wget|sh",
    "wget|bash",
    "invoke-expression",
    " iex ",
)
DEFAULT_ALLOWED_EXECUTABLES = (
    "{python}",
    "python",
    "python.exe",
    "python3",
    "python3.exe",
    "pytest",
    "pytest.exe",
    "ruff",
    "ruff.exe",
    "semgrep",
    "semgrep.exe",
    "codeql",
    "codeql.exe",
)


@dataclass(frozen=True)
class ReviewPolicy:
    enabled: bool = True
    execution_profile: PolicyProfile = "trusted-local"
    allowed_adapters: tuple[str, ...] = DEFAULT_ALLOWED_ADAPTERS
    allowed_executables: tuple[str, ...] = DEFAULT_ALLOWED_EXECUTABLES
    blocked_command_patterns: tuple[str, ...] = DEFAULT_BLOCKED_COMMAND_PATTERNS
    max_timeout_seconds: int = 600
    max_output_bytes: int = 1_000_000
    block_unavailable_adapters: bool = False
    warn_unavailable_adapters: bool = True
    environment_mode: str = "minimal"
    network_access: str = "inherit"


@dataclass(frozen=True)
class PolicyDecision:
    status: PolicyStatus
    reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.status == "allowed"


def evaluate_verification_command(
    command: VerificationCommand,
    policy: ReviewPolicy,
    *,
    rendered_command: str | None = None,
    rendered_argv: tuple[str, ...] = (),
) -> PolicyDecision:
    if not policy.enabled:
        return PolicyDecision(status="allowed")

    reasons: list[str] = []
    warnings: list[str] = []

    if command.adapter not in policy.allowed_adapters:
        reasons.append(
            f"adapter '{command.adapter}' is not in the allowed adapter set "
            f"({', '.join(policy.allowed_adapters) or 'none'})"
        )

    if command.timeout_seconds > policy.max_timeout_seconds:
        reasons.append(
            f"timeout {command.timeout_seconds}s exceeds policy maximum "
            f"{policy.max_timeout_seconds}s"
        )

    if policy.max_output_bytes <= 0:
        reasons.append("max_output_bytes must be greater than zero")

    normalized_command = _normalize_command(rendered_command or command.command)
    for pattern in policy.blocked_command_patterns:
        if _normalize_command(pattern) in normalized_command:
            reasons.append(f"command contains blocked pattern '{pattern}'")

    if not rendered_argv:
        reasons.append("command could not be rendered into argv for shell-free execution")
    elif not _executable_allowed(rendered_argv[0], policy.allowed_executables):
        reasons.append(
            f"executable '{rendered_argv[0]}' is not in the allowed executable set"
        )

    if policy.environment_mode not in {"minimal", "inherit"}:
        reasons.append("environment_mode must be one of: minimal, inherit")
    if policy.network_access not in {"inherit", "disabled"}:
        reasons.append("network_access must be one of: inherit, disabled")

    adapter_status = BUILTIN_ADAPTERS.get(command.adapter)
    if adapter_status is not None and adapter_status.executable is not None:
        availability = adapter_status.with_availability()
        if not availability.available:
            message = f"adapter '{command.adapter}' is unavailable: {availability.reason}"
            if policy.block_unavailable_adapters:
                reasons.append(message)
            elif policy.warn_unavailable_adapters:
                warnings.append(message)

    status: PolicyStatus = "blocked" if reasons else "allowed"
    return PolicyDecision(
        status=status,
        reasons=tuple(reasons),
        warnings=tuple(warnings),
    )


def profile_default_policy(profile: str) -> ReviewPolicy:
    if profile == "trusted-local":
        return ReviewPolicy(execution_profile="trusted-local")
    if profile == "trusted-ci":
        return ReviewPolicy(
            execution_profile="trusted-ci",
            environment_mode="minimal",
            network_access="inherit",
            max_timeout_seconds=600,
            max_output_bytes=1_000_000,
        )
    if profile == "untrusted-fork-pr":
        return ReviewPolicy(
            execution_profile="untrusted-fork-pr",
            allowed_adapters=("ruff", "semgrep"),
            allowed_executables=("{python}", "ruff", "ruff.exe", "semgrep", "semgrep.exe"),
            max_timeout_seconds=120,
            max_output_bytes=500_000,
            block_unavailable_adapters=False,
            warn_unavailable_adapters=True,
            environment_mode="minimal",
            network_access="disabled",
        )
    known = ", ".join(POLICY_PROFILES)
    raise ValueError(f"unknown policy profile '{profile}'. Known profiles: {known}")


def apply_policy_profile(
    policy: ReviewPolicy,
    *,
    requested_profile: str | None = None,
) -> ReviewPolicy:
    profile = requested_profile or policy.execution_profile
    profile_defaults = profile_default_policy(profile)
    if profile == "trusted-local":
        return replace(policy, execution_profile="trusted-local")
    if profile == "trusted-ci":
        return replace(
            policy,
            execution_profile="trusted-ci",
            environment_mode="minimal",
            max_timeout_seconds=min(
                policy.max_timeout_seconds,
                profile_defaults.max_timeout_seconds,
            ),
            max_output_bytes=min(policy.max_output_bytes, profile_defaults.max_output_bytes),
        )
    if profile == "untrusted-fork-pr":
        return replace(
            policy,
            execution_profile="untrusted-fork-pr",
            allowed_adapters=_intersect(policy.allowed_adapters, profile_defaults.allowed_adapters),
            allowed_executables=_intersect(
                policy.allowed_executables,
                profile_defaults.allowed_executables,
            ),
            max_timeout_seconds=min(
                policy.max_timeout_seconds,
                profile_defaults.max_timeout_seconds,
            ),
            max_output_bytes=min(policy.max_output_bytes, profile_defaults.max_output_bytes),
            block_unavailable_adapters=profile_defaults.block_unavailable_adapters,
            warn_unavailable_adapters=profile_defaults.warn_unavailable_adapters,
            environment_mode=profile_defaults.environment_mode,
            network_access=profile_defaults.network_access,
        )
    known = ", ".join(POLICY_PROFILES)
    raise ValueError(f"unknown policy profile '{profile}'. Known profiles: {known}")


def _normalize_command(command: str) -> str:
    lowered = command.casefold()
    compact_pipes = re.sub(r"\s*\|\s*", "|", lowered)
    return f" {' '.join(compact_pipes.split())} "


def _intersect(values: tuple[str, ...], allowed: tuple[str, ...]) -> tuple[str, ...]:
    allowed_set = set(allowed)
    return tuple(value for value in values if value in allowed_set)


def _executable_allowed(executable: str, allowed_executables: tuple[str, ...]) -> bool:
    executable_tokens = _executable_tokens(executable)
    allowed_tokens = {
        token
        for allowed in allowed_executables
        for token in _executable_tokens(_expand_executable_placeholder(allowed))
    }
    return bool(executable_tokens & allowed_tokens)


def _expand_executable_placeholder(value: str) -> str:
    if value == "{python}":
        return sys.executable
    return value


def _executable_tokens(value: str) -> set[str]:
    stripped = value.strip().strip('"')
    tokens = {Path(stripped).name.casefold()}
    if _is_path_like(stripped):
        try:
            tokens.add(str(Path(stripped).resolve()).casefold())
        except OSError:
            tokens.add(str(Path(stripped).absolute()).casefold())
    return {token for token in tokens if token}


def _is_path_like(value: str) -> bool:
    return os.path.isabs(value) or any(separator in value for separator in ("/", "\\"))
