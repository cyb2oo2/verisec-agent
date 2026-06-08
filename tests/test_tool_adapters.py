import json
from dataclasses import replace
from pathlib import Path

from verisec_agent.config import load_config
from verisec_agent.models import Finding, VerificationResult
from verisec_agent.validation import build_validation_plan


def test_load_config_resolves_builtin_adapters(tmp_path: Path) -> None:
    config_path = tmp_path / "verisec.toml"
    config_path.write_text(
        """[review]
max_evidence_lines = 10

[[verification.adapters]]
id = "pytest"
timeout_seconds = 12
required = true

[[verification.adapters]]
id = "semgrep"
name = "semgrep-security"
command = "semgrep scan --config p/security-audit"
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.verification_commands[0].adapter == "pytest"
    assert config.verification_commands[0].capabilities == (
        "unit-test",
        "regression-test",
        "python-test",
    )
    assert config.verification_commands[0].timeout_seconds == 12
    assert config.verification_commands[0].required is True
    assert config.verification_commands[1].name == "semgrep-security"
    assert "command-injection" in config.verification_commands[1].capabilities


def test_load_config_preserves_explicit_argv_templates(tmp_path: Path) -> None:
    config_path = tmp_path / "verisec.toml"
    config_path.write_text(
        """[[verification.commands]]
name = "demo"
command = "{python} demo.py"
argv = ["{python}", "demo.py"]
adapter = "custom"
capabilities = ["unit-test"]
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.verification_commands[0].command_argv == ("{python}", "demo.py")


def test_validation_records_candidate_when_capability_lacks_evidence() -> None:
    result = VerificationResult(
        name="security-scan",
        command="custom-wrapper",
        command_template="custom-wrapper",
        timeout_seconds=60,
        required=False,
        adapter="semgrep",
        description="custom semgrep wrapper",
        capabilities=("semgrep", "command-injection"),
        exit_code=0,
        duration_seconds=0.1,
        timed_out=False,
        stdout_path=None,
        stderr_path=None,
    )

    plan = build_validation_plan([_shell_finding()], [result])

    assert plan[0].status == "missing"
    assert plan[0].covered_by == ()
    assert plan[0].candidate_tools == ("security-scan",)
    assert "matching scanner finding" in plan[0].failure_boundary


def test_validation_covers_unit_check_with_structured_marker(tmp_path: Path) -> None:
    stdout_path = tmp_path / "unit.stdout.txt"
    stdout_path.write_text(
        "VERISEC_EVIDENCE: "
        + json.dumps(
            {
                "kind": "payload-test",
                "rule_id": "py-shell-true",
                "file_path": "app.py",
                "line": 3,
                "check": "unit tests for shell metacharacters",
                "payload": "; id",
                "assertion": "shell metacharacters are rejected",
            }
        ),
        encoding="utf-8",
    )
    result = VerificationResult(
        name="unit-tests",
        command="python -m pytest",
        command_template="{python} -m pytest",
        timeout_seconds=60,
        required=False,
        adapter="pytest",
        description="Run exploit regression tests",
        capabilities=("unit-test", "exploit-regression"),
        exit_code=0,
        duration_seconds=0.1,
        timed_out=False,
        stdout_path=str(stdout_path),
        stderr_path=None,
    )
    finding = replace(
        _shell_finding(),
        start_line=1,
        end_line=5,
        recommended_validation=("unit tests for shell metacharacters",),
    )

    plan = build_validation_plan([finding], [result])

    assert plan[0].status == "covered"
    assert plan[0].covered_by == ("unit-tests",)
    assert plan[0].candidate_tools == ()
    assert "payload=; id" in plan[0].tool_evidence[0]


def test_lint_adapter_does_not_cover_command_injection_validation() -> None:
    result = VerificationResult(
        name="ruff",
        command="python -m ruff check src tests",
        command_template="{python} -m ruff check src tests",
        timeout_seconds=60,
        required=False,
        adapter="ruff",
        description="Run Ruff",
        capabilities=("lint", "static-analysis"),
        exit_code=0,
        duration_seconds=0.1,
        timed_out=False,
        stdout_path=None,
        stderr_path=None,
    )

    plan = build_validation_plan([_shell_finding()], [result])

    assert plan[0].status == "missing"
    assert plan[0].covered_by == ()


def _shell_finding() -> Finding:
    return Finding(
        finding_id="finding-1",
        rule_id="py-shell-true",
        title="Shell execution path introduced",
        severity="high",
        confidence=0.7,
        file_path="app.py",
        start_line=1,
        end_line=5,
        evidence="+3: subprocess.run(user_input, shell=True)",
        source_context=None,
        risk="Command injection",
        fix_guidance="Use shell=False",
        recommended_validation=("static command-injection rules",),
        false_positive_notes="",
    )
