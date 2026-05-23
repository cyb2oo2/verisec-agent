from __future__ import annotations

import re
from dataclasses import dataclass

from verisec_agent.models import EvidenceWindow, SecurityHypothesis, Severity


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
            "semgrep command-injection rules",
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
    ),
    Rule(
        rule_id="py-unsafe-yaml",
        title="Unsafe YAML loading introduced",
        severity="medium",
        pattern=re.compile(r"\byaml\.load\s*\("),
        risk="yaml.load can construct arbitrary Python objects with unsafe loaders.",
        fix_guidance="Use yaml.safe_load or an explicit SafeLoader.",
        recommended_validation=("unit test with object-construction payload",),
        confidence=0.78,
        false_positive_notes=(
            "SafeLoader may be provided in another argument; verify the call signature."
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
)


def generate_hypotheses(
    windows: tuple[EvidenceWindow, ...],
    *,
    min_confidence: float,
) -> tuple[SecurityHypothesis, ...]:
    hypotheses: list[SecurityHypothesis] = []
    seen: set[tuple[str, str, int]] = set()

    for window in windows:
        added_text = "\n".join(
            line.content for line in window.lines if line.change_type == "add"
        )
        for rule in RULES:
            if not rule.pattern.search(added_text) or rule.confidence < min_confidence:
                continue
            key = (rule.rule_id, window.file_path, window.start_line)
            if key in seen:
                continue
            seen.add(key)
            hypotheses.append(
                SecurityHypothesis(
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
            )

    return tuple(hypotheses)
