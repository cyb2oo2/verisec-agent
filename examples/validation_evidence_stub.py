"""Copy-paste template: emit VERISEC_EVIDENCE markers from a verification command.

Configure in verisec.toml:

[[verification.commands]]
name = "security-property-check"
argv = ["{python}", "examples/validation_evidence_stub.py"]
timeout_seconds = 30
required = false
adapter = "custom"
capabilities = ["unit-test", "static-analysis", "command-injection"]
"""

from __future__ import annotations

import json
from pathlib import Path


def emit_evidence(**fields: object) -> None:
    print("VERISEC_EVIDENCE: " + json.dumps(fields, sort_keys=True))


def main() -> None:
    # Example: prove a shell=True path still exists (demo_app) and bind evidence
    # to the py-shell-true rule + recommended check text.
    demo = Path("examples/demo_app.py")
    if demo.is_file():
        text = demo.read_text(encoding="utf-8")
        if "shell=True" in text:
            emit_evidence(
                kind="static-match",
                rule_id="py-shell-true",
                file_path="examples/demo_app.py",
                check="static command-injection rules",
                assertion="demo app still passes shell=True to subprocess.run",
            )
            emit_evidence(
                kind="unit-test",
                rule_id="py-shell-true",
                file_path="examples/demo_app.py",
                check="unit tests for shell metacharacters",
                payload="hello; id",
                assertion="placeholder adversarial payload recorded for reviewers",
            )
            return

    # Generic template when adapting to your repository:
    emit_evidence(
        kind="property-check",
        rule_id="REPLACE_WITH_RULE_ID",
        file_path="path/to/file.py",
        start_line=1,
        end_line=1,
        check="REPLACE_WITH_RECOMMENDED_VALIDATION_TEXT",
        assertion="Describe what you proved about the patch or exploit path.",
    )


if __name__ == "__main__":
    main()
