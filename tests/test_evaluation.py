import json
import shutil
import subprocess
from pathlib import Path

import pytest

import verisec_agent.evaluation as evaluation_module
from verisec_agent.evaluation import (
    EvaluationCase,
    EvaluationError,
    load_evaluation_cases,
    run_evaluation,
)


def test_load_evaluation_cases_resolves_paths(tmp_path: Path) -> None:
    (tmp_path / "repo").mkdir()
    diff_path = tmp_path / "change.diff"
    diff_path.write_text("diff --git a/app.py b/app.py\n", encoding="utf-8")
    config_path = tmp_path / "verisec.toml"
    config_path.write_text("[review]\n", encoding="utf-8")
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(
        """{
          "cases": [{
            "id": "case one",
            "diff": "change.diff",
            "repo": "repo",
            "config": "verisec.toml",
            "expected_rules": ["py-eval-exec"]
          }]
        }""",
        encoding="utf-8",
    )

    cases = load_evaluation_cases(cases_path)

    assert len(cases) == 1
    assert cases[0].case_id == "case one"
    assert cases[0].diff_path == diff_path
    assert cases[0].repo_path == tmp_path / "repo"
    assert cases[0].config_path == config_path
    assert cases[0].expected_rules == ("py-eval-exec",)


def test_load_evaluation_cases_supports_git_metadata_and_expected_findings(
    tmp_path: Path,
) -> None:
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(
        """{
          "cases": [{
            "id": "oss-cve-case",
            "repo_url": "https://example.test/repo.git",
            "base_ref": "abc123",
            "head_ref": "def456",
            "project": "example",
            "cve": "CVE-2099-0001",
            "expected_findings": [{
              "rule_id": "py-shell-true",
              "file_path": "app.py",
              "severity": "high",
              "role": "primary",
              "notes": "main exploit path"
            }],
            "tags": ["oss", "cve"]
          }]
        }""",
        encoding="utf-8",
    )

    cases = load_evaluation_cases(cases_path)

    assert cases[0].repo_url == "https://example.test/repo.git"
    assert cases[0].base_ref == "abc123"
    assert cases[0].head_ref == "def456"
    assert cases[0].metadata == {"project": "example", "cve": "CVE-2099-0001"}
    assert cases[0].expected_rules == ("py-shell-true",)
    assert cases[0].expected_findings[0].file_path == "app.py"
    assert cases[0].expected_findings[0].role == "primary"
    assert cases[0].expected_findings[0].notes == "main exploit path"


def test_load_evaluation_cases_excludes_negative_controls_from_expected_rules(
    tmp_path: Path,
) -> None:
    diff_path = tmp_path / "change.diff"
    diff_path.write_text("diff --git a/app.py b/app.py\n", encoding="utf-8")
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(
        """{
          "cases": [{
            "id": "negative-only",
            "diff": "change.diff",
            "expected_findings": [{
              "rule_id": "py-shell-true",
              "file_path": "app.py",
              "role": "negative-control"
            }]
          }]
        }""",
        encoding="utf-8",
    )

    cases = load_evaluation_cases(cases_path)

    assert cases[0].expected_rules == ()
    assert cases[0].expected_findings[0].role == "negative-control"


def test_run_evaluation_writes_summary_and_case_bundles(tmp_path: Path) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "app.py").write_text(
        """def run(expr):
    return eval(expr)
""",
        encoding="utf-8",
    )
    diff_path = tmp_path / "change.diff"
    diff_path.write_text(
        """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
 def run(expr):
+    return eval(expr)
""",
        encoding="utf-8",
    )
    config_path = tmp_path / "verisec.toml"
    config_path.write_text(
        """[review]
max_evidence_lines = 8

[[verification.commands]]
name = "quick-check"
command = "{python} -c \\"print('ok')\\""
capabilities = ["unit-test"]
""",
        encoding="utf-8",
    )
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(
        """{
          "cases": [{
            "id": "eval-demo",
            "diff": "change.diff",
            "repo": "repo",
            "config": "verisec.toml",
            "expected_rules": ["py-eval-exec"]
          }]
        }""",
        encoding="utf-8",
    )

    result = run_evaluation(cases_path=cases_path, output_dir=tmp_path / "eval")

    assert result["summary"]["case_count"] == 1
    assert result["summary"]["completed_count"] == 1
    assert result["summary"]["finding_count"] == 1
    assert result["summary"]["expected_rule_recall"] == 1.0
    assert result["summary"]["expected_rule_precision"] == 1.0
    assert result["summary"]["primary_precision"] == 0.0
    assert result["summary"]["accepted_finding_rate"] == 0.0
    assert result["cases"][0]["found_rules"] == ("py-eval-exec",)
    assert result["cases"][0]["expected_rule_hits"] == ("py-eval-exec",)
    assert result["cases"][0]["finding_role_counts"] == {"unexpected": 1}
    assert (tmp_path / "eval" / "evaluation.json").exists()
    assert (tmp_path / "eval" / "evaluation.md").exists()
    assert (tmp_path / "eval" / "cases" / "eval-demo" / "report.json").exists()


def test_run_evaluation_resume_uses_existing_case_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "app.py").write_text(
        """def run(expr):
    return eval(expr)
""",
        encoding="utf-8",
    )
    diff_path = tmp_path / "change.diff"
    diff_path.write_text(
        """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
 def run(expr):
+    return eval(expr)
""",
        encoding="utf-8",
    )
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(
        """{
          "cases": [{
            "id": "resume-demo",
            "diff": "change.diff",
            "repo": "repo",
            "expected_rules": ["py-eval-exec"]
          }]
        }""",
        encoding="utf-8",
    )
    output_dir = tmp_path / "eval"
    first = run_evaluation(cases_path=cases_path, output_dir=output_dir)

    def fail_materialize(**_: object) -> dict[str, object]:
        raise AssertionError("resume should not materialize an existing case")

    monkeypatch.setattr(evaluation_module, "_materialize_case", fail_materialize)
    resumed = run_evaluation(cases_path=cases_path, output_dir=output_dir, resume=True)

    assert first["summary"]["finding_count"] == 1
    assert resumed["cases"][0]["status"] == "resumed"
    assert resumed["summary"]["completed_count"] == 1
    assert resumed["summary"]["error_count"] == 0
    assert resumed["summary"]["finding_count"] == 1


def test_run_evaluation_treats_clean_cases_as_fully_covered(tmp_path: Path) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "app.py").write_text(
        """def run(value):
    return value
""",
        encoding="utf-8",
    )
    diff_path = tmp_path / "clean.diff"
    diff_path.write_text(
        """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
 def run(value):
+    return value
""",
        encoding="utf-8",
    )
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(
        """{
          "cases": [{
            "id": "clean",
            "diff": "clean.diff",
            "repo": "repo"
          }]
        }""",
        encoding="utf-8",
    )

    result = run_evaluation(cases_path=cases_path, output_dir=tmp_path / "eval")

    assert result["summary"]["finding_count"] == 0
    assert result["summary"]["validation_coverage_rate"] == 1.0


def test_run_evaluation_treats_clean_negative_control_as_accepted(
    tmp_path: Path,
) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "app.py").write_text(
        """import subprocess

def run_checked(args):
    return subprocess.run(args, shell=False)
""",
        encoding="utf-8",
    )
    diff_path = tmp_path / "change.diff"
    diff_path.write_text(
        """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
+subprocess.run(args, shell=False)
""",
        encoding="utf-8",
    )
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(
        """{
          "cases": [{
            "id": "clean-negative",
            "diff": "change.diff",
            "repo": "repo",
            "expected_findings": [{
              "rule_id": "py-shell-true",
              "file_path": "app.py",
              "role": "negative-control"
            }]
          }]
        }""",
        encoding="utf-8",
    )

    result = run_evaluation(cases_path=cases_path, output_dir=tmp_path / "eval")

    assert result["summary"]["finding_count"] == 0
    assert result["summary"]["accepted_finding_rate"] == 1.0
    assert result["summary"]["unexpected_finding_rate"] == 0.0
    assert result["summary"]["negative_control_violation_count"] == 0
    assert result["summary"]["expected_rule_recall"] is None
    assert result["summary"]["expected_finding_recall"] is None


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_run_evaluation_materializes_git_repo_case(tmp_path: Path) -> None:
    source_repo = tmp_path / "source-repo"
    source_repo.mkdir()
    _git(source_repo, "init")
    _git(source_repo, "config", "user.name", "VeriSec Test")
    _git(source_repo, "config", "user.email", "verisec@example.test")
    (source_repo / "app.py").write_text(
        """from __future__ import annotations

import subprocess


def run_command(user_input: str):
    return subprocess.run(["echo", user_input], check=False)
""",
        encoding="utf-8",
    )
    _git(source_repo, "add", "app.py")
    _git(source_repo, "commit", "-m", "safe base")
    base_ref = _git(source_repo, "rev-parse", "HEAD").stdout.strip()
    (source_repo / "app.py").write_text(
        """from __future__ import annotations

import subprocess


def run_command(user_input: str):
    return subprocess.run(user_input, shell=True)
""",
        encoding="utf-8",
    )
    _git(source_repo, "add", "app.py")
    _git(source_repo, "commit", "-m", "introduce shell")
    head_ref = _git(source_repo, "rev-parse", "HEAD").stdout.strip()
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(
        f"""{{
          "cases": [{{
            "id": "git-shell-case",
            "repo_url": "{source_repo.as_posix()}",
            "base_ref": "{base_ref}",
            "head_ref": "{head_ref}",
            "metadata": {{
              "project": "local-oss",
              "cve": "CVE-2099-0002"
            }},
            "expected_findings": [{{
              "rule_id": "py-shell-true",
              "file_path": "app.py",
              "severity": "high",
              "role": "primary"
            }}],
            "tags": ["oss", "command-injection"]
          }}]
        }}""",
        encoding="utf-8",
    )

    result = run_evaluation(cases_path=cases_path, output_dir=tmp_path / "eval")
    case = result["cases"][0]

    assert case["status"] == "completed"
    assert Path(case["diff_path"]).exists()
    assert (Path(case["repo_path"]) / "app.py").exists()
    assert case["expected_finding_hits"][0]["rule_id"] == "py-shell-true"
    assert case["finding_role_counts"] == {"primary": 1}
    assert result["summary"]["expected_finding_recall"] == 1.0
    assert result["summary"]["primary_finding_recall"] == 1.0
    assert result["summary"]["security_advisory_case_count"] == 1
    assert result["summary"]["tag_counts"]["oss"] == 1


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_materialize_case_checks_out_head_ref_not_working_tree(tmp_path: Path) -> None:
    # The repo source (no repo_url) must materialize a checkout at head_ref, even when the
    # working tree is parked at a different revision. Regression for T-009: the old code
    # returned the source tree at whatever HEAD was, so a multi-line string masked by
    # patched-file line number consulted the wrong revision.
    source_repo = tmp_path / "source-repo"
    source_repo.mkdir()
    _git(source_repo, "init")
    _git(source_repo, "config", "user.name", "VeriSec Test")
    _git(source_repo, "config", "user.email", "verisec@example.test")
    (source_repo / "app.py").write_text(
        'PATTERN = """\nbase-line-one\nbase-line-two\n"""\n',
        encoding="utf-8",
    )
    _git(source_repo, "add", "app.py")
    _git(source_repo, "commit", "-m", "base")
    base_ref = _git(source_repo, "rev-parse", "HEAD").stdout.strip()
    (source_repo / "app.py").write_text(
        'PATTERN = """\nhead-line-one\nhead-line-two\nhead-line-three\n"""\n',
        encoding="utf-8",
    )
    _git(source_repo, "add", "app.py")
    _git(source_repo, "commit", "-m", "head")
    head_ref = _git(source_repo, "rev-parse", "HEAD").stdout.strip()

    # Park the working tree at base_ref so HEAD != head_ref — the condition that made the
    # old code return a checkout describing a different revision than the diff.
    _git(source_repo, "checkout", base_ref)
    assert "head-line-three" not in (source_repo / "app.py").read_text(encoding="utf-8")

    case = EvaluationCase(
        case_id="repo-head-ref",
        diff_path=None,
        repo_path=source_repo,
        base_ref=base_ref,
        head_ref=head_ref,
    )

    materialized = evaluation_module._materialize_case(
        case=case,
        case_output=tmp_path / "case-out",
    )

    assert materialized["source_kind"] == "git_existing_repo"
    checkout = Path(materialized["repo_path"]) / "app.py"
    contents = checkout.read_text(encoding="utf-8")
    assert "head-line-three" in contents
    assert "base-line-two" not in contents
    diff_text = Path(materialized["diff_path"]).read_text(encoding="utf-8")
    assert "head-line-three" in diff_text


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_run_evaluation_reuses_source_cache_for_shared_repo_refs(
    tmp_path: Path,
) -> None:
    source_repo = tmp_path / "source-repo"
    source_repo.mkdir()
    _git(source_repo, "init")
    _git(source_repo, "config", "user.name", "VeriSec Test")
    _git(source_repo, "config", "user.email", "verisec@example.test")
    (source_repo / "app.py").write_text("def run(value):\n    return value\n", encoding="utf-8")
    _git(source_repo, "add", "app.py")
    _git(source_repo, "commit", "-m", "base")
    base_ref = _git(source_repo, "rev-parse", "HEAD").stdout.strip()
    (source_repo / "app.py").write_text(
        "def run(expr):\n    return eval(expr)\n",
        encoding="utf-8",
    )
    _git(source_repo, "add", "app.py")
    _git(source_repo, "commit", "-m", "head")
    head_ref = _git(source_repo, "rev-parse", "HEAD").stdout.strip()
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(
        f"""{{
          "cases": [
            {{
              "id": "cache-case-a",
              "repo_url": "{source_repo.as_posix()}",
              "base_ref": "{base_ref}",
              "head_ref": "{head_ref}",
              "expected_rules": ["py-eval-exec"]
            }},
            {{
              "id": "cache-case-b",
              "repo_url": "{source_repo.as_posix()}",
              "base_ref": "{base_ref}",
              "head_ref": "{head_ref}",
              "expected_rules": ["py-eval-exec"]
            }}
          ]
        }}""",
        encoding="utf-8",
    )

    result = run_evaluation(cases_path=cases_path, output_dir=tmp_path / "eval")
    cache_repos = list((tmp_path / "eval" / "_source-cache" / "repos").iterdir())

    assert result["summary"]["completed_count"] == 2
    assert len(cache_repos) == 1
    assert {case["source_fetch_mode"] for case in result["cases"]} == {"source-cache"}
    assert len({case["source_cache_path"] for case in result["cases"]}) == 1
    assert len({case["repo_path"] for case in result["cases"]}) == 2
    for case in result["cases"]:
        long_paths = _git(
            Path(case["repo_path"]),
            "config",
            "--get",
            "core.longpaths",
        )
        assert long_paths.stdout.strip() == "true"
    assert _git(cache_repos[0], "config", "--get", "core.longpaths").stdout.strip() == "true"


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_run_evaluation_applies_diff_url_to_base_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_repo = tmp_path / "source-repo"
    source_repo.mkdir()
    _git(source_repo, "init")
    _git(source_repo, "config", "user.name", "VeriSec Test")
    _git(source_repo, "config", "user.email", "verisec@example.test")
    (source_repo / "app.py").write_text("def run(value):\n    return value\n", encoding="utf-8")
    _git(source_repo, "add", "app.py")
    _git(source_repo, "commit", "-m", "base")
    base_ref = _git(source_repo, "rev-parse", "HEAD").stdout.strip()
    (source_repo / "app.py").write_text(
        "def run(expr):\n    return eval(expr)\n",
        encoding="utf-8",
    )
    diff_text = _git(source_repo, "diff", "--no-ext-diff", base_ref).stdout
    monkeypatch.setattr(evaluation_module, "fetch_url_diff", lambda _: diff_text)

    cases_path = tmp_path / "cases.json"
    cases_path.write_text(
        f"""{{
          "cases": [{{
            "id": "diff-url-case",
            "repo_url": "{source_repo.as_posix()}",
            "base_ref": "{base_ref}",
            "diff_url": "https://example.test/pr.diff",
            "expected_rules": ["py-eval-exec"]
          }}]
        }}""",
        encoding="utf-8",
    )

    result = run_evaluation(cases_path=cases_path, output_dir=tmp_path / "eval")
    case = result["cases"][0]

    assert case["status"] == "completed"
    assert case["diff_url"] == "https://example.test/pr.diff"
    assert case["expected_rule_hits"] == ("py-eval-exec",)
    assert "eval(expr)" in (Path(case["repo_path"]) / "app.py").read_text(
        encoding="utf-8"
    )


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_run_evaluation_falls_back_to_git_diff_when_diff_url_does_not_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_repo = tmp_path / "source-repo"
    source_repo.mkdir()
    _git(source_repo, "init")
    _git(source_repo, "config", "user.name", "VeriSec Test")
    _git(source_repo, "config", "user.email", "verisec@example.test")
    (source_repo / "app.py").write_text("def run(value):\n    return value\n", encoding="utf-8")
    _git(source_repo, "add", "app.py")
    _git(source_repo, "commit", "-m", "base")
    base_ref = _git(source_repo, "rev-parse", "HEAD").stdout.strip()
    (source_repo / "app.py").write_text(
        "def run(expr):\n    return eval(expr)\n",
        encoding="utf-8",
    )
    _git(source_repo, "add", "app.py")
    _git(source_repo, "commit", "-m", "head")
    head_ref = _git(source_repo, "rev-parse", "HEAD").stdout.strip()
    monkeypatch.setattr(
        evaluation_module,
        "fetch_url_diff",
        lambda _: "diff --git a/missing.py b/missing.py\n--- a/missing.py\n+++ b/missing.py\n",
    )

    cases_path = tmp_path / "cases.json"
    cases_path.write_text(
        f"""{{
          "cases": [{{
            "id": "diff-url-fallback-case",
            "repo_url": "{source_repo.as_posix()}",
            "base_ref": "{base_ref}",
            "head_ref": "{head_ref}",
            "diff_url": "https://example.test/pr.diff",
            "expected_rules": ["py-eval-exec"]
          }}]
        }}""",
        encoding="utf-8",
    )

    result = run_evaluation(cases_path=cases_path, output_dir=tmp_path / "eval")
    case = result["cases"][0]
    report = json.loads(
        (Path(case["bundle_path"]) / "report.json").read_text(encoding="utf-8")
    )

    assert case["status"] == "completed"
    assert case["expected_rule_hits"] == ("py-eval-exec",)
    assert Path(case["diff_path"]).name == "git.diff"
    assert report["source"]["materialized_from"] == "diff_url_apply_fallback_git_diff"


def test_run_evaluation_reports_reviewer_roles_and_unexpected_taxonomy(
    tmp_path: Path,
) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "app.py").write_text(
        """def run(expr):
    return eval(expr)
""",
        encoding="utf-8",
    )
    diff_path = tmp_path / "change.diff"
    diff_path.write_text(
        """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
 def run(expr):
+    return eval(expr)
""",
        encoding="utf-8",
    )
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(
        """{
          "cases": [{
            "id": "role-demo",
            "diff": "change.diff",
            "repo": "repo",
            "expected_findings": [{
              "rule_id": "py-eval-exec",
              "file_path": "app.py",
              "severity": "high",
              "role": "supporting"
            }]
          }]
        }""",
        encoding="utf-8",
    )

    result = run_evaluation(cases_path=cases_path, output_dir=tmp_path / "eval")
    case = result["cases"][0]

    assert case["finding_role_counts"] == {"supporting": 1}
    assert result["summary"]["accepted_finding_rate"] == 1.0
    assert result["summary"]["supporting_evidence_rate"] == 1.0
    assert result["summary"]["primary_precision"] == 0.0


def test_load_evaluation_cases_rejects_unknown_expected_role(tmp_path: Path) -> None:
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(
        """{
          "cases": [{
            "id": "bad-role",
            "diff": "change.diff",
            "expected_findings": [{
              "rule_id": "py-eval-exec",
              "role": "maybe"
            }]
          }]
        }""",
        encoding="utf-8",
    )
    (tmp_path / "change.diff").write_text("diff --git a/app.py b/app.py\n", encoding="utf-8")

    with pytest.raises(EvaluationError, match="expected finding role"):
        load_evaluation_cases(cases_path)


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *args),
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    )
