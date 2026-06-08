from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from demo_app import run_command


def main() -> None:
    demo_path = Path("examples/demo_app.py")
    text = demo_path.read_text(encoding="utf-8")
    assert "subprocess.run(user_input, shell=True)" in text
    payload = "hello; printf injected"
    with patch("demo_app.subprocess.run") as mocked_run:
        run_command(payload)
    mocked_run.assert_called_once_with(payload, shell=True)

    for marker in (
        {
            "kind": "static-match",
            "rule_id": "py-shell-true",
            "file_path": "examples/demo_app.py",
            "check": "static command-injection rules",
            "assertion": "changed path passes user_input into subprocess.run with shell=True",
        },
        {
            "kind": "unit-test",
            "rule_id": "py-shell-true",
            "file_path": "examples/demo_app.py",
            "check": "unit tests for shell metacharacters",
            "payload": payload,
            "assertion": "shell metacharacters reach subprocess.run unchanged with shell=True",
        },
    ):
        print(
            "VERISEC_EVIDENCE: "
            + json.dumps(
                marker,
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
