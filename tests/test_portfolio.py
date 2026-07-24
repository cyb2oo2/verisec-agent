import json
from pathlib import Path

import pytest

import verisec_agent.portfolio as portfolio_module
from verisec_agent.dashboard import LabeledPath
from verisec_agent.portfolio import PortfolioError, run_portfolio


def test_run_portfolio_writes_release_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path = _write_manifest(
        tmp_path,
        benchmark={
            "out": "benchmark",
            "claim_boundaries": [
                "Metrics describe only the curated cases in this manifest.",
                "Scanner rows are configuration-specific comparisons.",
                (
                    "Curated benchmark: {VeriSec Agent:positive_cases} positive cases "
                    "and {VeriSec Agent:negative_controls} negative controls."
                ),
            ],
            "systems": [
                {
                    "label": "VeriSec Agent",
                    "suite": "demo",
                    "negative_suite": "demo",
                    "notes": "current system",
                },
                {
                    "label": "Semgrep baseline",
                    "status": "not-run",
                    "notes": "scanner baseline pending",
                },
            ],
        },
    )
    calls: dict[str, object] = {}

    def fake_run_evaluation(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        summary = {
            "case_count": 1,
            "finding_count": 1,
            "validation_coverage_rate": 1.0,
            "accepted_finding_rate": 1.0,
            "primary_precision": 1.0,
            "primary_finding_recall": 1.0,
            "supporting_evidence_rate": 0.0,
            "unexpected_finding_rate": 0.0,
            "negative_control_violation_count": 0,
            "expected_rule_recall": 1.0,
            "expected_finding_recall": 1.0,
            "tool_evidence_rate": 1.0,
            "validation_gap_rate": 0.0,
            "policy_blocked_count": 0,
        }
        (output_dir / "evaluation.json").write_text(
            json.dumps({"summary": summary, "cases": []}),
            encoding="utf-8",
        )
        (output_dir / "evaluation.md").write_text("# evaluation\n", encoding="utf-8")
        calls["fail_fast"] = kwargs["fail_fast"]
        return {"summary": summary}

    def fake_run_gate(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "gate.json").write_text(
            json.dumps({"passed": True, "failures": []}),
            encoding="utf-8",
        )
        (output_dir / "gate.md").write_text("# gate\n", encoding="utf-8")
        calls["min_validation_coverage"] = kwargs[
            "thresholds"
        ].min_validation_coverage
        return {"passed": True, "failures": []}

    def fake_run_dashboard(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        assert kwargs["evaluations"] == (
            LabeledPath("demo", tmp_path / "runs" / "evaluations" / "demo" / "evaluation.json"),
        )
        summary = {
            "suite_count": 1,
            "total_cases": 1,
            "total_findings": 1,
            "gates_total": 1,
            "gates_passed": 1,
            "regression_count": 0,
        }
        (output_dir / "dashboard.json").write_text(
            json.dumps({"summary": summary, "suites": [], "regressions": []}),
            encoding="utf-8",
        )
        (output_dir / "dashboard.md").write_text("# dashboard\n", encoding="utf-8")
        return {"summary": summary, "regressions": []}

    monkeypatch.setattr(portfolio_module, "run_evaluation", fake_run_evaluation)
    monkeypatch.setattr(portfolio_module, "run_gate", fake_run_gate)
    monkeypatch.setattr(portfolio_module, "run_dashboard", fake_run_dashboard)

    result = run_portfolio(
        manifest_path=manifest_path,
        output_dir=tmp_path / "runs",
    )

    assert result["passed"] is True
    assert result["dashboard_summary"]["suite_count"] == 1
    assert result["benchmark_matrix"]["summary"]["system_count"] == 2
    assert result["benchmark_matrix"]["summary"]["measured_system_count"] == 1
    assert result["benchmark_matrix"]["systems"][0]["metrics"]["primary_recall"] == 1.0
    assert result["benchmark_matrix"]["claim_boundaries"] == (
        "Metrics describe only the curated cases in this manifest.",
        "Scanner rows are configuration-specific comparisons.",
        "Curated benchmark: 1 positive cases and 1 negative controls.",
    )
    assert result["suites"][0]["label"] == "demo"
    assert result["suites"][0]["gate_passed"] is True
    assert calls["fail_fast"] is True
    assert calls["min_validation_coverage"] == 1.0
    assert (tmp_path / "runs" / "portfolio.json").exists()
    assert (tmp_path / "runs" / "artifact_index.json").exists()
    artifact_index = json.loads(
        (tmp_path / "runs" / "artifact_index.json").read_text(encoding="utf-8")
    )
    artifact_kinds = {artifact["kind"] for artifact in artifact_index["artifacts"]}
    assert {
        "portfolio-json",
        "evaluation-json",
        "gate-json",
        "dashboard-json",
        "benchmark-matrix-json",
    } <= artifact_kinds
    markdown = (tmp_path / "runs" / "portfolio.md").read_text(encoding="utf-8")
    assert "# VeriSec Portfolio: passed" in markdown
    assert "Artifact index:" in markdown
    assert "## Benchmark Matrix" in markdown
    assert (
        "| VeriSec Agent | measured | 1 | 1 | 1.00 | 1.00 | 1 | 1 | 0 | "
        "1.00 | 1.00 | 0 | current system |"
    ) in markdown
    assert "| Semgrep baseline | not-run | n/a | n/a | n/a |" in markdown
    assert "## Claim Boundaries" in markdown
    assert "Scanner rows are configuration-specific comparisons." in markdown
    assert "| demo | passed | 1 | 1 | 1.00 | 1.00 | 0.00 | 0 |" in markdown


def test_display_status_demotes_row_but_keeps_metrics() -> None:
    """A demoted row keeps its computed numbers and drops out of the measured count."""
    suite = {
        "label": "promoted-cves",
        "metrics": {
            "case_count": 6,
            "finding_count": 11,
            "primary_finding_recall": 1.0,
            "primary_precision": 0.64,
        },
    }
    negative = {"label": "negative-controls", "metrics": {"case_count": 12}}

    demoted = portfolio_module._benchmark_row(
        {
            "label": "VeriSec Agent promoted CVEs",
            "suite": "promoted-cves",
            "negative_suite": "negative-controls",
            "display_status": "illustrative",
        },
        {"promoted-cves": suite, "negative-controls": negative},
        {},
    )

    assert demoted["status"] == "illustrative"
    # The number is relabeled, not hidden.
    assert demoted["metrics"]["primary_recall"] == 1.0
    assert demoted["metrics"]["findings"] == 11


def test_display_status_cannot_fake_measured() -> None:
    """The override may only demote a real measurement, never inflate one."""
    suite = {"label": "s", "metrics": {"case_count": 1, "finding_count": 0}}

    with pytest.raises(PortfolioError, match="display_status cannot be 'measured'"):
        portfolio_module._benchmark_row(
            {"label": "S", "suite": "s", "display_status": "measured"},
            {"s": suite},
            {},
        )


def test_run_portfolio_rejects_invalid_claim_boundaries(tmp_path: Path) -> None:
    manifest_path = _write_manifest(
        tmp_path,
        benchmark={
            "claim_boundaries": "not-a-list",
            "systems": [],
        },
    )

    with pytest.raises(PortfolioError, match="claim_boundaries"):
        run_portfolio(manifest_path=manifest_path, output_dir=tmp_path / "runs")


def test_run_portfolio_rejects_claim_boundary_unknown_system(tmp_path: Path) -> None:
    """An unresolved reference must fail rather than publish a literal placeholder."""
    manifest_path = _write_manifest(
        tmp_path,
        benchmark={
            "claim_boundaries": ["Covers {No Such System:positive_cases} cases."],
            "systems": [],
        },
    )

    with pytest.raises(PortfolioError, match="unknown system 'No Such System'"):
        run_portfolio(manifest_path=manifest_path, output_dir=tmp_path / "runs")


def test_run_portfolio_rejects_claim_boundary_unknown_metric(tmp_path: Path) -> None:
    manifest_path = _write_manifest(
        tmp_path,
        benchmark={
            "claim_boundaries": ["Covers {Pending Scanner:no_such_metric} cases."],
            "systems": [{"label": "Pending Scanner", "status": "not-run"}],
        },
    )

    with pytest.raises(PortfolioError, match="unknown metric 'no_such_metric'"):
        run_portfolio(manifest_path=manifest_path, output_dir=tmp_path / "runs")


def test_run_portfolio_rejects_claim_boundary_unmeasured_metric(tmp_path: Path) -> None:
    """A not-run system has the metric key but no value; publishing "n/a" would mislead."""
    manifest_path = _write_manifest(
        tmp_path,
        benchmark={
            "claim_boundaries": ["Covers {Pending Scanner:positive_cases} cases."],
            "systems": [{"label": "Pending Scanner", "status": "not-run"}],
        },
    )

    with pytest.raises(PortfolioError, match="unmeasured metric 'positive_cases'"):
        run_portfolio(manifest_path=manifest_path, output_dir=tmp_path / "runs")


def test_run_portfolio_includes_case_audit_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path = _write_manifest(
        tmp_path,
        case_audits={
            "enabled": True,
            "require_verification": True,
            "fail_on_blocked": True,
        },
    )

    def fake_run_case_audit(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        assert kwargs["require_verification"] is True
        summary = {
            "case_count": 1,
            "ready_count": 1,
            "blocked_count": 0,
            "error_count": 0,
            "warning_count": 0,
            "positive_case_count": 1,
            "negative_control_case_count": 0,
            "security_advisory_case_count": 1,
            "verification_ready_count": 1,
            "loader_passed": True,
        }
        (output_dir / "case_audit.json").write_text(
            json.dumps({"summary": summary, "cases": []}),
            encoding="utf-8",
        )
        (output_dir / "case_audit.md").write_text("# audit\n", encoding="utf-8")
        return {"summary": summary, "cases": []}

    def fake_run_evaluation(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        summary = _summary(case_count=1, finding_count=1)
        (output_dir / "evaluation.json").write_text(
            json.dumps({"summary": summary, "cases": []}),
            encoding="utf-8",
        )
        (output_dir / "evaluation.md").write_text("# evaluation\n", encoding="utf-8")
        return {"summary": summary}

    def fake_run_gate(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "gate.json").write_text(
            json.dumps({"passed": True, "failures": []}),
            encoding="utf-8",
        )
        (output_dir / "gate.md").write_text("# gate\n", encoding="utf-8")
        return {"passed": True, "failures": []}

    def fake_run_dashboard(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        summary = {
            "suite_count": 1,
            "total_cases": 1,
            "total_findings": 1,
            "gates_total": 1,
            "gates_passed": 1,
            "regression_count": 0,
        }
        (output_dir / "dashboard.json").write_text(
            json.dumps({"summary": summary, "suites": [], "regressions": []}),
            encoding="utf-8",
        )
        (output_dir / "dashboard.md").write_text("# dashboard\n", encoding="utf-8")
        return {"summary": summary, "regressions": []}

    monkeypatch.setattr(portfolio_module, "run_case_audit", fake_run_case_audit)
    monkeypatch.setattr(portfolio_module, "run_evaluation", fake_run_evaluation)
    monkeypatch.setattr(portfolio_module, "run_gate", fake_run_gate)
    monkeypatch.setattr(portfolio_module, "run_dashboard", fake_run_dashboard)

    result = run_portfolio(
        manifest_path=manifest_path,
        output_dir=tmp_path / "runs",
    )

    assert result["passed"] is True
    assert result["case_audits"][0]["summary"]["verification_ready_count"] == 1
    assert result["suites"][0]["case_audit_failures"] == []
    artifact_index = json.loads(
        (tmp_path / "runs" / "artifact_index.json").read_text(encoding="utf-8")
    )
    artifact_kinds = {artifact["kind"] for artifact in artifact_index["artifacts"]}
    assert {"case-audit-json", "case-audit-markdown"} <= artifact_kinds
    markdown = (tmp_path / "runs" / "portfolio.md").read_text(encoding="utf-8")
    assert "## Case Audits" in markdown
    assert "| demo | ready | 1 | 1 | 0 | 0 | 1 |" in markdown


def test_run_portfolio_supports_standalone_candidate_case_audits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate_cases = tmp_path / "candidate_cases.json"
    candidate_cases.write_text('{"cases": []}', encoding="utf-8")
    manifest_path = _write_manifest(
        tmp_path,
        case_audit_suites=[
            {
                "label": "candidate-cves",
                "cases": "candidate_cases.json",
                "require_verification": False,
                "fail_on_blocked": True,
            }
        ],
    )

    def fake_run_case_audit(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        assert kwargs["cases_path"] == candidate_cases
        summary = {
            "case_count": 2,
            "ready_count": 2,
            "blocked_count": 0,
            "error_count": 0,
            "warning_count": 1,
            "positive_case_count": 2,
            "negative_control_case_count": 0,
            "security_advisory_case_count": 2,
            "verification_ready_count": 0,
            "loader_passed": True,
        }
        (output_dir / "case_audit.json").write_text(
            json.dumps({"summary": summary, "cases": []}),
            encoding="utf-8",
        )
        (output_dir / "case_audit.md").write_text("# candidate audit\n", encoding="utf-8")
        return {"summary": summary, "cases": []}

    def fake_run_evaluation(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        summary = _summary(case_count=1, finding_count=1)
        (output_dir / "evaluation.json").write_text(
            json.dumps({"summary": summary, "cases": []}),
            encoding="utf-8",
        )
        (output_dir / "evaluation.md").write_text("# evaluation\n", encoding="utf-8")
        return {"summary": summary}

    def fake_run_gate(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "gate.json").write_text(
            json.dumps({"passed": True, "failures": []}),
            encoding="utf-8",
        )
        (output_dir / "gate.md").write_text("# gate\n", encoding="utf-8")
        return {"passed": True, "failures": []}

    def fake_run_dashboard(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        summary = {
            "suite_count": 1,
            "total_cases": 1,
            "total_findings": 1,
            "gates_total": 1,
            "gates_passed": 1,
            "regression_count": 0,
        }
        (output_dir / "dashboard.json").write_text(
            json.dumps({"summary": summary, "suites": [], "regressions": []}),
            encoding="utf-8",
        )
        (output_dir / "dashboard.md").write_text("# dashboard\n", encoding="utf-8")
        return {"summary": summary, "regressions": []}

    monkeypatch.setattr(portfolio_module, "run_case_audit", fake_run_case_audit)
    monkeypatch.setattr(portfolio_module, "run_evaluation", fake_run_evaluation)
    monkeypatch.setattr(portfolio_module, "run_gate", fake_run_gate)
    monkeypatch.setattr(portfolio_module, "run_dashboard", fake_run_dashboard)

    result = run_portfolio(
        manifest_path=manifest_path,
        output_dir=tmp_path / "runs",
    )

    assert result["passed"] is True
    assert result["case_audit_suites"][0]["label"] == "candidate-cves"
    assert result["case_audits"][0]["summary"]["warning_count"] == 1
    artifact_index = json.loads(
        (tmp_path / "runs" / "artifact_index.json").read_text(encoding="utf-8")
    )
    artifact_kinds = {artifact["kind"] for artifact in artifact_index["artifacts"]}
    assert "case-audit-json" in artifact_kinds
    markdown = (tmp_path / "runs" / "portfolio.md").read_text(encoding="utf-8")
    assert "| candidate-cves | ready-with-warnings | 2 | 2 | 0 | 1 | 0 |" in markdown


def test_run_portfolio_includes_scanner_baseline_matrix_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "semgrep-oss.json").write_text('{"cases": []}', encoding="utf-8")
    (tmp_path / "semgrep-negative.json").write_text('{"cases": []}', encoding="utf-8")
    manifest_path = _write_manifest(
        tmp_path,
        benchmark={
            "out": "benchmark",
            "systems": [
                {
                    "label": "VeriSec Agent",
                    "suite": "demo",
                    "negative_suite": "demo",
                    "notes": "current system",
                },
                {
                    "label": "Semgrep baseline",
                    "baseline": "semgrep-oss",
                    "negative_baseline": "semgrep-negative",
                    "notes": "scanner artifact baseline",
                },
            ],
        },
        scanner_baselines=[
            {
                "label": "semgrep-oss",
                "adapter": "semgrep",
                "cases": "cases.json",
                "results": "semgrep-oss.json",
            },
            {
                "label": "semgrep-negative",
                "adapter": "semgrep",
                "cases": "cases.json",
                "results": "semgrep-negative.json",
            },
        ],
    )

    def fake_run_evaluation(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        summary = _summary(case_count=1, finding_count=1)
        (output_dir / "evaluation.json").write_text(
            json.dumps({"summary": summary, "cases": []}),
            encoding="utf-8",
        )
        (output_dir / "evaluation.md").write_text("# evaluation\n", encoding="utf-8")
        return {"summary": summary}

    def fake_run_gate(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "gate.json").write_text(
            json.dumps({"passed": True, "failures": []}),
            encoding="utf-8",
        )
        (output_dir / "gate.md").write_text("# gate\n", encoding="utf-8")
        return {"passed": True, "failures": []}

    def fake_run_dashboard(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        summary = {
            "suite_count": 1,
            "total_cases": 1,
            "total_findings": 1,
            "gates_total": 1,
            "gates_passed": 1,
            "regression_count": 0,
        }
        (output_dir / "dashboard.json").write_text(
            json.dumps({"summary": summary, "suites": [], "regressions": []}),
            encoding="utf-8",
        )
        (output_dir / "dashboard.md").write_text("# dashboard\n", encoding="utf-8")
        return {"summary": summary, "regressions": []}

    def fake_run_scanner_baseline(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        label = kwargs["label"]
        summary = _summary(
            case_count=1,
            finding_count=2 if label == "semgrep-oss" else 0,
            expected_finding_recall=0.5 if label == "semgrep-oss" else None,
            primary_precision=0.0 if label == "semgrep-oss" else 0.0,
            primary_finding_recall=0.0 if label == "semgrep-oss" else None,
            tool_evidence_rate=1.0 if label == "semgrep-oss" else 0.0,
        )
        summary["completed_count"] = 1
        summary["skipped_count"] = 0
        summary["error_count"] = 0
        summary["raw_tool_finding_count"] = 5 if label == "semgrep-oss" else 0
        summary["out_of_scope_finding_count"] = 3 if label == "semgrep-oss" else 0
        (output_dir / "baseline.json").write_text(
            json.dumps({"summary": summary, "cases": []}),
            encoding="utf-8",
        )
        (output_dir / "baseline.md").write_text("# baseline\n", encoding="utf-8")
        return {
            "label": label,
            "adapter": kwargs["adapter"],
            "summary": summary,
        }

    monkeypatch.setattr(portfolio_module, "run_evaluation", fake_run_evaluation)
    monkeypatch.setattr(portfolio_module, "run_gate", fake_run_gate)
    monkeypatch.setattr(portfolio_module, "run_dashboard", fake_run_dashboard)
    monkeypatch.setattr(portfolio_module, "run_scanner_baseline", fake_run_scanner_baseline)

    result = run_portfolio(
        manifest_path=manifest_path,
        output_dir=tmp_path / "runs",
    )

    semgrep_row = result["benchmark_matrix"]["systems"][1]
    assert semgrep_row["status"] == "measured"
    assert semgrep_row["baseline"] == "semgrep-oss"
    assert semgrep_row["negative_baseline"] == "semgrep-negative"
    assert semgrep_row["metrics"]["positive_cases"] == 1
    assert semgrep_row["metrics"]["negative_controls"] == 1
    assert semgrep_row["metrics"]["findings"] == 2
    assert semgrep_row["metrics"]["raw_tool_findings"] == 5
    assert semgrep_row["metrics"]["out_of_scope_findings"] == 3
    markdown = (tmp_path / "runs" / "portfolio.md").read_text(encoding="utf-8")
    assert "## Scanner Baselines" in markdown
    assert "| semgrep-oss | measured | provided | semgrep | 1 | 1 | 0 | 2 | 5 | 3 |" in markdown
    artifact_index = json.loads(
        (tmp_path / "runs" / "artifact_index.json").read_text(encoding="utf-8")
    )
    artifact_kinds = {artifact["kind"] for artifact in artifact_index["artifacts"]}
    assert "scanner-baseline-json" in artifact_kinds


def test_run_portfolio_can_execute_scanner_baseline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path = _write_manifest(
        tmp_path,
        benchmark={
            "out": "benchmark",
            "systems": [
                {
                    "label": "Live Semgrep",
                    "baseline": "semgrep-live",
                    "notes": "live scanner",
                }
            ],
        },
        scanner_baselines=[
            {
                "label": "semgrep-live",
                "adapter": "semgrep",
                "cases": "cases.json",
                "run": True,
                "argv": ["verisec-missing-scanner-command"],
            }
        ],
    )

    def fake_run_evaluation(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        summary = _summary(case_count=1, finding_count=0)
        (output_dir / "evaluation.json").write_text(
            json.dumps({"summary": summary, "cases": []}),
            encoding="utf-8",
        )
        (output_dir / "evaluation.md").write_text("# evaluation\n", encoding="utf-8")
        return {"summary": summary}

    def fake_run_gate(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "gate.json").write_text(
            json.dumps({"passed": True, "failures": []}),
            encoding="utf-8",
        )
        (output_dir / "gate.md").write_text("# gate\n", encoding="utf-8")
        return {"passed": True, "failures": []}

    def fake_run_dashboard(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        summary = {
            "suite_count": 1,
            "total_cases": 1,
            "total_findings": 0,
            "gates_total": 1,
            "gates_passed": 1,
            "regression_count": 0,
        }
        (output_dir / "dashboard.json").write_text(
            json.dumps({"summary": summary, "suites": [], "regressions": []}),
            encoding="utf-8",
        )
        (output_dir / "dashboard.md").write_text("# dashboard\n", encoding="utf-8")
        return {"summary": summary, "regressions": []}

    def fake_run_scanner_execution(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "scanner_results.json").write_text(
            json.dumps({"adapter": "semgrep", "cases": []}),
            encoding="utf-8",
        )
        (output_dir / "scanner_results.md").write_text("# scanner run\n", encoding="utf-8")
        assert kwargs["command_argv"] == ("verisec-missing-scanner-command",)
        return {"summary": {"case_count": 0}}

    def fake_run_scanner_baseline(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        summary = _summary(case_count=1, finding_count=0)
        summary["completed_count"] = 0
        summary["skipped_count"] = 1
        summary["error_count"] = 0
        (output_dir / "baseline.json").write_text(
            json.dumps({"summary": summary, "cases": []}),
            encoding="utf-8",
        )
        (output_dir / "baseline.md").write_text("# baseline\n", encoding="utf-8")
        return {
            "label": kwargs["label"],
            "adapter": kwargs["adapter"],
            "summary": summary,
        }

    monkeypatch.setattr(portfolio_module, "run_evaluation", fake_run_evaluation)
    monkeypatch.setattr(portfolio_module, "run_gate", fake_run_gate)
    monkeypatch.setattr(portfolio_module, "run_dashboard", fake_run_dashboard)
    monkeypatch.setattr(portfolio_module, "run_scanner_execution", fake_run_scanner_execution)
    monkeypatch.setattr(portfolio_module, "run_scanner_baseline", fake_run_scanner_baseline)

    result = run_portfolio(
        manifest_path=manifest_path,
        output_dir=tmp_path / "runs",
    )

    row = result["benchmark_matrix"]["systems"][0]
    assert row["status"] == "skipped"
    assert row["baseline"] == "semgrep-live"
    assert result["scanner_baselines"][0]["scanner_execution_mode"] == "executed"
    artifact_index = json.loads(
        (tmp_path / "runs" / "artifact_index.json").read_text(encoding="utf-8")
    )
    artifact_kinds = {artifact["kind"] for artifact in artifact_index["artifacts"]}
    assert "scanner-results-json" in artifact_kinds


def test_run_portfolio_can_reuse_scanner_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cached_results = tmp_path / "cache" / "cached-scanner-results.json"
    cached_results.parent.mkdir()
    cached_results.write_text(
        json.dumps({"adapter": "semgrep", "cases": []}),
        encoding="utf-8",
    )
    cached_results.with_suffix(".md").write_text("# cached scanner run\n", encoding="utf-8")
    manifest_path = _write_manifest(
        tmp_path,
        scanner_baselines=[
            {
                "label": "semgrep-cached",
                "adapter": "semgrep",
                "cases": "cases.json",
                "reuse_from": "cache/cached-scanner-results.json",
                "run": True,
                "reuse_results": True,
            }
        ],
    )

    def fake_run_evaluation(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        summary = _summary(case_count=1, finding_count=0)
        (output_dir / "evaluation.json").write_text(
            json.dumps({"summary": summary, "cases": []}),
            encoding="utf-8",
        )
        (output_dir / "evaluation.md").write_text("# evaluation\n", encoding="utf-8")
        return {"summary": summary}

    def fake_run_gate(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "gate.json").write_text(
            json.dumps({"passed": True, "failures": []}),
            encoding="utf-8",
        )
        (output_dir / "gate.md").write_text("# gate\n", encoding="utf-8")
        return {"passed": True, "failures": []}

    def fake_run_dashboard(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        summary = {
            "suite_count": 1,
            "total_cases": 1,
            "total_findings": 0,
            "gates_total": 1,
            "gates_passed": 1,
            "regression_count": 0,
        }
        (output_dir / "dashboard.json").write_text(
            json.dumps({"summary": summary, "suites": [], "regressions": []}),
            encoding="utf-8",
        )
        (output_dir / "dashboard.md").write_text("# dashboard\n", encoding="utf-8")
        return {"summary": summary, "regressions": []}

    def fake_run_scanner_execution(**kwargs):
        raise AssertionError("scanner execution should not run when cached results exist")

    def fake_run_scanner_baseline(**kwargs):
        assert kwargs["results_path"] == cached_results
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        summary = _summary(case_count=1, finding_count=0)
        summary["completed_count"] = 1
        summary["skipped_count"] = 0
        summary["error_count"] = 0
        (output_dir / "baseline.json").write_text(
            json.dumps({"summary": summary, "cases": []}),
            encoding="utf-8",
        )
        (output_dir / "baseline.md").write_text("# baseline\n", encoding="utf-8")
        return {
            "label": kwargs["label"],
            "adapter": kwargs["adapter"],
            "summary": summary,
        }

    monkeypatch.setattr(portfolio_module, "run_evaluation", fake_run_evaluation)
    monkeypatch.setattr(portfolio_module, "run_gate", fake_run_gate)
    monkeypatch.setattr(portfolio_module, "run_dashboard", fake_run_dashboard)
    monkeypatch.setattr(portfolio_module, "run_scanner_execution", fake_run_scanner_execution)
    monkeypatch.setattr(portfolio_module, "run_scanner_baseline", fake_run_scanner_baseline)

    result = run_portfolio(
        manifest_path=manifest_path,
        output_dir=tmp_path / "runs",
    )

    baseline = result["scanner_baselines"][0]
    assert baseline["scanner_execution_mode"] == "reused"
    assert baseline["reuse_results"] is True
    assert baseline["reuse_from_path"] == str(cached_results.resolve())
    assert baseline["scanner_results_path"] == str(cached_results.resolve())
    markdown = (tmp_path / "runs" / "portfolio.md").read_text(encoding="utf-8")
    assert "| semgrep-cached | measured | reused | semgrep |" in markdown
    artifact_index = json.loads(
        (tmp_path / "runs" / "artifact_index.json").read_text(encoding="utf-8")
    )
    artifact_kinds = {artifact["kind"] for artifact in artifact_index["artifacts"]}
    assert {"scanner-results-json", "scanner-results-markdown"} <= artifact_kinds


def test_run_portfolio_fails_when_gate_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path = _write_manifest(tmp_path)

    def fake_run_evaluation(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        summary = {
            "case_count": 1,
            "finding_count": 1,
            "validation_coverage_rate": 0.0,
            "accepted_finding_rate": 0.0,
            "primary_precision": 0.0,
            "primary_finding_recall": 0.0,
            "supporting_evidence_rate": 0.0,
            "unexpected_finding_rate": 1.0,
            "negative_control_violation_count": 0,
            "expected_rule_recall": 0.0,
            "expected_finding_recall": 0.0,
        }
        (output_dir / "evaluation.json").write_text(
            json.dumps({"summary": summary, "cases": []}),
            encoding="utf-8",
        )
        (output_dir / "evaluation.md").write_text("# evaluation\n", encoding="utf-8")
        return {"summary": summary}

    def fake_run_gate(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "gate.json").write_text(
            json.dumps({"passed": False, "failures": ["validation coverage failed"]}),
            encoding="utf-8",
        )
        (output_dir / "gate.md").write_text("# gate\n", encoding="utf-8")
        return {"passed": False, "failures": ["validation coverage failed"]}

    def fake_run_dashboard(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "dashboard.json").write_text(
            json.dumps({"summary": {"suite_count": 1}, "suites": [], "regressions": []}),
            encoding="utf-8",
        )
        (output_dir / "dashboard.md").write_text("# dashboard\n", encoding="utf-8")
        return {
            "summary": {
                "suite_count": 1,
                "total_cases": 1,
                "total_findings": 1,
                "gates_total": 1,
                "gates_passed": 0,
                "regression_count": 0,
            },
            "regressions": [],
        }

    monkeypatch.setattr(portfolio_module, "run_evaluation", fake_run_evaluation)
    monkeypatch.setattr(portfolio_module, "run_gate", fake_run_gate)
    monkeypatch.setattr(portfolio_module, "run_dashboard", fake_run_dashboard)

    result = run_portfolio(
        manifest_path=manifest_path,
        output_dir=tmp_path / "runs",
    )

    assert result["passed"] is False
    assert result["failures"] == ["demo: validation coverage failed"]


def test_run_portfolio_rejects_unknown_gate_threshold(tmp_path: Path) -> None:
    manifest_path = _write_manifest(
        tmp_path,
        gate={"min_validation_coverage": 1.0, "unknown_threshold": 1},
    )

    with pytest.raises(PortfolioError, match="Unknown gate threshold"):
        run_portfolio(manifest_path=manifest_path, output_dir=tmp_path / "runs")


def _write_manifest(
    tmp_path: Path,
    *,
    gate: dict[str, object] | None = None,
    benchmark: dict[str, object] | None = None,
    scanner_baselines: list[dict[str, object]] | None = None,
    case_audits: dict[str, object] | None = None,
    case_audit_suites: list[dict[str, object]] | None = None,
) -> Path:
    cases_path = tmp_path / "cases.json"
    cases_path.write_text('{"cases": []}', encoding="utf-8")
    config_path = tmp_path / "verisec.toml"
    config_path.write_text("[review]\n", encoding="utf-8")
    manifest_path = tmp_path / "portfolio.json"
    manifest_path.write_text(
        json.dumps(
            _manifest_payload(
                gate=gate,
                benchmark=benchmark,
                scanner_baselines=scanner_baselines,
                case_audits=case_audits,
                case_audit_suites=case_audit_suites,
            )
        ),
        encoding="utf-8",
    )
    return manifest_path


def _manifest_payload(
    *,
    gate: dict[str, object] | None,
    benchmark: dict[str, object] | None,
    scanner_baselines: list[dict[str, object]] | None,
    case_audits: dict[str, object] | None,
    case_audit_suites: list[dict[str, object]] | None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "suites": [
            {
                "label": "demo",
                "cases": "cases.json",
                "config": "verisec.toml",
                "fail_fast": True,
                "gate": gate or {"min_validation_coverage": 1.0},
            }
        ]
    }
    if case_audits is not None:
        payload["case_audits"] = case_audits
    if case_audit_suites is not None:
        payload["case_audit_suites"] = case_audit_suites
    if benchmark is not None:
        payload["benchmark_matrix"] = benchmark
    if scanner_baselines is not None:
        payload["scanner_baselines"] = scanner_baselines
    return payload


def _summary(
    *,
    case_count: int,
    finding_count: int,
    expected_finding_recall: float | None = 1.0,
    primary_precision: float = 1.0,
    primary_finding_recall: float | None = 1.0,
    tool_evidence_rate: float = 1.0,
) -> dict[str, object]:
    return {
        "case_count": case_count,
        "finding_count": finding_count,
        "validation_coverage_rate": 1.0,
        "accepted_finding_rate": 1.0,
        "primary_precision": primary_precision,
        "primary_finding_recall": primary_finding_recall,
        "supporting_evidence_rate": 0.0,
        "unexpected_finding_rate": 0.0,
        "negative_control_violation_count": 0,
        "expected_rule_recall": 1.0,
        "expected_finding_recall": expected_finding_recall,
        "tool_evidence_rate": tool_evidence_rate,
        "validation_gap_rate": 0.0,
        "policy_blocked_count": 0,
    }
