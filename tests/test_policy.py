from pathlib import Path

from verisec_agent.config import load_config
from verisec_agent.models import VerificationCommand
from verisec_agent.policy import ReviewPolicy, evaluate_verification_command
from verisec_agent.tracing import TraceLog
from verisec_agent.verification import VerificationRunner


def test_policy_blocks_disallowed_adapter_and_dangerous_command() -> None:
    decision = evaluate_verification_command(
        VerificationCommand(
            name="danger",
            command="rm -rf .",
            adapter="custom",
        ),
        ReviewPolicy(allowed_adapters=("pytest",)),
    )

    assert decision.status == "blocked"
    assert any("adapter 'custom'" in reason for reason in decision.reasons)
    assert any("blocked pattern 'rm -rf'" in reason for reason in decision.reasons)


def test_policy_blocks_executable_outside_allowlist() -> None:
    decision = evaluate_verification_command(
        VerificationCommand(
            name="unexpected",
            command="powershell -Command Write-Output ok",
            adapter="custom",
        ),
        ReviewPolicy(),
        rendered_command="powershell -Command Write-Output ok",
        rendered_argv=("powershell", "-Command", "Write-Output ok"),
    )

    assert decision.status == "blocked"
    assert any("allowed executable set" in reason for reason in decision.reasons)


def test_untrusted_fork_profile_blocks_custom_and_pytest_from_repo_config(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "verisec.toml"
    config_path.write_text(
        """[policy]
allowed_adapters = ["pytest", "ruff", "custom"]
allowed_executables = ["{python}", "pytest", "ruff"]
max_timeout_seconds = 600
network_access = "inherit"
environment_mode = "inherit"

[[verification.adapters]]
id = "pytest"

[[verification.adapters]]
id = "ruff"

[[verification.commands]]
name = "custom-check"
command = "{python} check.py"
adapter = "custom"
""",
        encoding="utf-8",
    )

    config = load_config(config_path, policy_profile="untrusted-fork-pr")

    assert config.policy.execution_profile == "untrusted-fork-pr"
    assert config.policy.allowed_adapters == ("ruff",)
    assert config.policy.network_access == "disabled"
    assert config.policy.environment_mode == "minimal"
    assert config.policy.max_timeout_seconds == 120
    pytest_decision = evaluate_verification_command(
        config.verification_commands[0],
        config.policy,
        rendered_command="pytest",
        rendered_argv=("pytest",),
    )
    custom_decision = evaluate_verification_command(
        config.verification_commands[2],
        config.policy,
        rendered_command="python check.py",
        rendered_argv=("python", "check.py"),
    )

    assert pytest_decision.status == "blocked"
    assert custom_decision.status == "blocked"
    assert "ruff" in config.policy.allowed_adapters


def test_verification_runner_records_policy_block_without_executing(tmp_path: Path) -> None:
    sentinel = tmp_path / "sentinel.txt"
    sentinel.write_text("still here", encoding="utf-8")
    output_dir = tmp_path / "bundle"
    trace = TraceLog(output_dir / "trace.jsonl")
    runner = VerificationRunner(tmp_path, output_dir, trace, policy=ReviewPolicy())

    result = runner.run(
        VerificationCommand(
            name="danger",
            command=f"rm -rf {sentinel}",
            adapter="custom",
            required=True,
        )
    )

    assert sentinel.exists()
    assert result.policy_status == "blocked"
    assert result.passed is False
    assert result.exit_code is None
    assert result.stderr_path is not None
    assert "Blocked by VeriSec verification policy" in Path(result.stderr_path).read_text(
        encoding="utf-8"
    )
    assert "tool.policy_blocked" in (output_dir / "trace.jsonl").read_text(
        encoding="utf-8"
    )


def test_verification_runner_executes_argv_without_shell_expansion(tmp_path: Path) -> None:
    output_dir = tmp_path / "bundle"
    trace = TraceLog(output_dir / "trace.jsonl")
    runner = VerificationRunner(tmp_path, output_dir, trace, policy=ReviewPolicy())

    result = runner.run(
        VerificationCommand(
            name="argv-safe",
            command=(
                "{python} -c \"from pathlib import Path; "
                "Path('created.txt').write_text('ok', encoding='utf-8')\" "
                "&& {python} -c \"from pathlib import Path; "
                "Path('shell-expanded.txt').write_text('bad', encoding='utf-8')\""
            ),
            adapter="custom",
        )
    )

    assert result.passed
    assert result.command_argv[0]
    assert (tmp_path / "created.txt").exists()
    assert not (tmp_path / "shell-expanded.txt").exists()
