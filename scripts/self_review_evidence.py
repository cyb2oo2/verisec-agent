"""Emit VERISEC_EVIDENCE markers for VeriSec's own review of this repository.

Wired from `verisec.toml` so that when VeriSec reviews its own pull requests, the
recommended validation checks it raises are backed by executed evidence rather
than by a command merely exiting zero.

Each marker below is emitted only after the corresponding property is verified by
calling the real detector, so the evidence describes work that actually ran. A
check with no genuine backing is deliberately left uncovered — see
`report_uncovered` at the bottom.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from verisec_agent.python_semantics import (  # noqa: E402
    analyze_python_source,
    is_redos_prone,
)

TEST_FILE = "tests/test_python_semantics.py"


def emit_evidence(**fields: object) -> None:
    print("VERISEC_EVIDENCE: " + json.dumps(fields, sort_keys=True))


def check_unicode_normalization_complexity() -> bool:
    """Verify length-guard dominance is what separates hardening from new risk."""
    guarded = (
        "import unicodedata\n"
        "\n"
        "def to_python(self, value):\n"
        "    if self.max_length is not None and len(value) > self.max_length:\n"
        "        return value\n"
        '    return unicodedata.normalize("NFKC", value)\n'
    )
    unguarded = (
        "import unicodedata\n"
        "\n"
        "def clean(user_id):\n"
        '    return unicodedata.normalize("NFKC", user_id)\n'
    )

    guarded_modes = {
        match.mode
        for match in analyze_python_source(guarded, changed_lines={4, 5, 6}, analysis_scope="file")
        if match.rule_id == "py-unicode-normalization-dos"
    }
    unguarded_modes = {
        match.mode
        for match in analyze_python_source(unguarded, changed_lines={4}, analysis_scope="file")
        if match.rule_id == "py-unicode-normalization-dos"
    }
    if "adds-hardening" not in guarded_modes or "introduces-risk" not in unguarded_modes:
        return False

    emit_evidence(
        kind="property-check",
        rule_id="py-unicode-normalization-dos",
        file_path=TEST_FILE,
        check="Unicode normalization complexity regression test",
        payload="value longer than max_length reaching unicodedata.normalize",
        assertion=(
            "A length guard dominating unicodedata.normalize classifies as "
            "adds-hardening; the same call without a guard classifies as "
            "introduces-risk."
        ),
    )
    return True


def check_redos_adversarial_patterns() -> bool:
    """Verify catastrophic-backtracking patterns are separated from linear ones."""
    catastrophic = ("(a+)+", "(a|a)*", "(.*,)*[ \t]*([^ \t]+)[ \t]+")
    linear = ("^[a-z0-9_-]{1,64}$", "(?:^|,)([^ \t,]+)[ \t]+")

    if not all(is_redos_prone(pattern) for pattern in catastrophic):
        return False
    if any(is_redos_prone(pattern) for pattern in linear):
        return False

    emit_evidence(
        kind="property-check",
        rule_id="py-regex-redos",
        file_path=TEST_FILE,
        check="ReDoS regression test with adversarial input",
        payload=" | ".join(catastrophic),
        assertion=(
            "Nested-quantifier and alternation-overlap patterns are classified "
            "ReDoS-prone, while bounded and anchored equivalents are not."
        ),
    )
    return True


def report_uncovered() -> None:
    """State checks left uncovered rather than emitting unbacked evidence.

    py-tls-verify-disabled recommends an integration test against an expected
    certificate chain. This repository has no such test, so no marker is emitted.
    Coverage stays honestly incomplete instead of being inflated by a claim no
    executed check supports.
    """
    print(
        "VERISEC_NOTE: py-tls-verify-disabled left uncovered - no integration "
        "test against an expected certificate chain exists in this repository."
    )


def main() -> int:
    checks = (
        ("unicode-normalization-complexity", check_unicode_normalization_complexity),
        ("redos-adversarial-patterns", check_redos_adversarial_patterns),
    )
    failed = [name for name, check in checks if not check()]
    report_uncovered()
    if failed:
        print(f"VERISEC_EVIDENCE_FAILED: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
