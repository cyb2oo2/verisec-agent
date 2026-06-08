import json
import sys
from pathlib import Path

from verisec_agent.scanner_baseline import run_scanner_baseline
from verisec_agent.scanner_execution import (
    DEFAULT_COMMANDS,
    _resolve_tool_placeholders,
    run_scanner_execution,
)


def test_run_scanner_execution_captures_stdout_artifact(tmp_path: Path) -> None:
    cases_path = _write_repo_case(tmp_path)
    scanner_path = tmp_path / "fake_semgrep.py"
    scanner_path.write_text(
        "import json\n"
        "print(json.dumps({'results': [{"
        "'check_id': 'py-shell-true', "
        "'path': 'app.py', "
        "'start': {'line': 3}, "
        "'end': {'line': 3}, "
        "'extra': {'message': 'shell true', 'severity': 'WARNING'}"
        "}]}))\n",
        encoding="utf-8",
    )

    result = run_scanner_execution(
        cases_path=cases_path,
        output_dir=tmp_path / "scanner-run",
        adapter="semgrep",
        command_argv=(sys.executable, str(scanner_path)),
        timeout_seconds=10,
        fail_fast=True,
    )

    summary = result["summary"]
    assert summary["completed_count"] == 1
    assert summary["skipped_count"] == 0
    assert summary["error_count"] == 0
    manifest_path = tmp_path / "scanner-run" / "scanner_results.json"
    artifact = tmp_path / "scanner-run" / result["cases"][0]["artifact"]
    assert manifest_path.exists()
    assert artifact.exists()

    baseline = run_scanner_baseline(
        cases_path=cases_path,
        results_path=manifest_path,
        output_dir=tmp_path / "scored",
        fail_fast=True,
    )

    assert baseline["summary"]["finding_count"] == 1
    assert baseline["summary"]["expected_finding_recall"] == 1.0
    assert baseline["summary"]["primary_precision"] == 1.0


def test_run_scanner_execution_records_missing_tool_as_skipped(tmp_path: Path) -> None:
    cases_path = _write_repo_case(tmp_path)

    result = run_scanner_execution(
        cases_path=cases_path,
        output_dir=tmp_path / "scanner-run",
        adapter="semgrep",
        command_argv=("verisec-missing-scanner-command",),
        fail_fast=True,
    )

    assert result["summary"] == {
        "case_count": 1,
        "completed_count": 0,
        "skipped_count": 1,
        "error_count": 0,
    }
    assert result["cases"][0]["status"] == "skipped"
    assert "not found" in result["cases"][0]["skip_reason"]

    baseline = run_scanner_baseline(
        cases_path=cases_path,
        results_path=tmp_path / "scanner-run" / "scanner_results.json",
        output_dir=tmp_path / "scored",
        fail_fast=True,
    )

    assert baseline["summary"]["completed_count"] == 0
    assert baseline["summary"]["skipped_count"] == 1
    assert baseline["summary"]["error_count"] == 0


def test_run_scanner_execution_supports_codeql_sarif_sequence(tmp_path: Path) -> None:
    cases_path = _write_repo_case(tmp_path)
    codeql_path = tmp_path / "fake_codeql.py"
    codeql_path.write_text(
        "import json\n"
        "import pathlib\n"
        "import sys\n"
        "args = sys.argv[1:]\n"
        "if args[:2] == ['database', 'create']:\n"
        "    pathlib.Path(args[2]).mkdir(parents=True, exist_ok=True)\n"
        "elif args[:2] == ['database', 'analyze']:\n"
        "    output = pathlib.Path(args[args.index('--output') + 1])\n"
        "    output.parent.mkdir(parents=True, exist_ok=True)\n"
        "    output.write_text(json.dumps({'runs': [{'tool': {'driver': {'rules': []}}, "
        "'results': [{'ruleId': 'py-shell-true', 'level': 'warning', "
        "'message': {'text': 'shell true'}, 'locations': [{'physicalLocation': {"
        "'artifactLocation': {'uri': 'app.py'}, 'region': {'startLine': 3}}}]}]}]}))\n"
        "else:\n"
        "    raise SystemExit(2)\n",
        encoding="utf-8",
    )

    result = run_scanner_execution(
        cases_path=cases_path,
        output_dir=tmp_path / "codeql-run",
        adapter="codeql",
        command_sequence=(
            (sys.executable, str(codeql_path), "database", "create", "{database}"),
            (
                sys.executable,
                str(codeql_path),
                "database",
                "analyze",
                "{database}",
                "--output",
                "{artifact}",
            ),
        ),
        fail_fast=True,
    )

    assert result["summary"]["completed_count"] == 1
    assert len(result["cases"][0]["steps"]) == 2
    assert result["cases"][0]["artifact"].endswith("scanner.sarif")

    baseline = run_scanner_baseline(
        cases_path=cases_path,
        results_path=tmp_path / "codeql-run" / "scanner_results.json",
        output_dir=tmp_path / "codeql-score",
        adapter="codeql",
        fail_fast=True,
    )

    assert baseline["summary"]["finding_count"] == 1
    assert baseline["summary"]["expected_finding_recall"] == 1.0
    assert baseline["summary"]["primary_precision"] == 1.0


def test_default_scanner_commands_resolve_env_tool_placeholders(monkeypatch) -> None:
    monkeypatch.setenv("VERISEC_SEMGREP", "/opt/verisec/semgrep")
    monkeypatch.setenv("VERISEC_CODEQL", "/opt/verisec/codeql")

    semgrep_sequence = _resolve_tool_placeholders(DEFAULT_COMMANDS["semgrep"])
    codeql_sequence = _resolve_tool_placeholders(DEFAULT_COMMANDS["codeql"])

    assert semgrep_sequence[0][0] == "/opt/verisec/semgrep"
    assert codeql_sequence[0][0] == "/opt/verisec/codeql"
    assert codeql_sequence[1][0] == "/opt/verisec/codeql"
    assert "{database}" in codeql_sequence[0]
    assert "{artifact}" in codeql_sequence[1]
    assert "python-security-extended.qls" in codeql_sequence[1]


def _write_repo_case(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import subprocess\n\nsubprocess.run('id', shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "case.diff").write_text(
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1 +1,3 @@\n"
        "+import subprocess\n"
        "+\n"
        "+subprocess.run('id', shell=True)\n",
        encoding="utf-8",
    )
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "id": "shell-case",
                        "diff": "case.diff",
                        "repo": "repo",
                        "expected_findings": [
                            {
                                "rule_id": "py-shell-true",
                                "file_path": "app.py",
                                "start_line": 3,
                                "severity": "medium",
                                "role": "primary",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return cases_path
