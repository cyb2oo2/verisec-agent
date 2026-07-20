from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from verisec_agent.adapters_api import load_adapter_registry, set_adapter_registry
from verisec_agent.models import VerificationCommand
from verisec_agent.policy import ReviewPolicy, apply_policy_profile, profile_default_policy
from verisec_agent.tool_adapters import enrich_custom_command, resolve_adapter


@dataclass(frozen=True)
class ReviewConfig:
    max_evidence_lines: int = 12
    source_context_lines: int = 8
    min_confidence: float = 0.35
    verification_commands: tuple[VerificationCommand, ...] = ()
    policy: ReviewPolicy = ReviewPolicy()
    rule_packs: tuple[str, ...] = ("builtin",)
    adapter_paths: tuple[Path, ...] = ()


def load_config(path: Path | None, *, policy_profile: str | None = None) -> ReviewConfig:
    if path is None or not path.exists():
        set_adapter_registry(load_adapter_registry())
        return ReviewConfig(
            policy=apply_policy_profile(
                ReviewPolicy(),
                requested_profile=policy_profile,
            )
        )

    config_dir = path.parent.resolve()
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    review = data.get("review", {})
    verification = data.get("verification", {})
    policy = data.get("policy", {})
    rules_section = data.get("rules", {})
    adapters_section = data.get("adapters", {})

    rule_packs = tuple(
        str(item) for item in rules_section.get("packs", ["builtin"])
    ) or ("builtin",)
    adapter_paths = tuple(
        Path(str(item)) for item in adapters_section.get("paths", [])
    )
    registry = load_adapter_registry(
        adapter_paths=adapter_paths,
        config_dir=config_dir,
    )
    set_adapter_registry(registry)

    adapter_commands = tuple(
        resolve_adapter(item)
        for item in verification.get("adapters", [])
    )
    custom_commands = tuple(
        enrich_custom_command(item)
        for item in verification.get("commands", [])
    )
    return ReviewConfig(
        max_evidence_lines=int(review.get("max_evidence_lines", 12)),
        source_context_lines=int(review.get("source_context_lines", 8)),
        min_confidence=float(review.get("min_confidence", 0.35)),
        verification_commands=adapter_commands + custom_commands,
        policy=_load_policy(policy, policy_profile=policy_profile),
        rule_packs=rule_packs,
        adapter_paths=tuple(
            (config_dir / path).resolve() if not path.is_absolute() else path.resolve()
            for path in adapter_paths
        ),
    )


def _load_policy(data: dict, *, policy_profile: str | None = None) -> ReviewPolicy:
    profile = str(policy_profile or data.get("execution_profile", ReviewPolicy().execution_profile))
    defaults = profile_default_policy(profile)
    policy = ReviewPolicy(
        enabled=bool(data.get("enabled", defaults.enabled)),
        execution_profile=defaults.execution_profile,
        allowed_adapters=tuple(
            str(value)
            for value in data.get("allowed_adapters", defaults.allowed_adapters)
        ),
        allowed_executables=tuple(
            str(value)
            for value in data.get("allowed_executables", defaults.allowed_executables)
        ),
        blocked_command_patterns=tuple(
            str(value)
            for value in data.get(
                "blocked_command_patterns",
                defaults.blocked_command_patterns,
            )
        ),
        max_timeout_seconds=int(
            data.get("max_timeout_seconds", defaults.max_timeout_seconds)
        ),
        max_output_bytes=int(data.get("max_output_bytes", defaults.max_output_bytes)),
        block_unavailable_adapters=bool(
            data.get(
                "block_unavailable_adapters",
                defaults.block_unavailable_adapters,
            )
        ),
        warn_unavailable_adapters=bool(
            data.get(
                "warn_unavailable_adapters",
                defaults.warn_unavailable_adapters,
            )
        ),
        environment_mode=str(data.get("environment_mode", defaults.environment_mode)),
        network_access=str(data.get("network_access", defaults.network_access)),
    )
    return apply_policy_profile(policy, requested_profile=policy_profile)
