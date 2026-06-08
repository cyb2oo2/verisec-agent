from verisec_agent.calibration import calibrate_findings
from verisec_agent.models import Finding, ToolFinding, ValidationStep, VerificationResult


def test_calibration_raises_confidence_for_matching_tool_evidence() -> None:
    finding = _finding()
    validation = (
        ValidationStep(
            finding_id=finding.finding_id,
            objective="Validate shell execution",
            recommended_check="static command-injection rules",
            status="covered",
            covered_by=("semgrep",),
            tool_evidence=("semgrep/rule at app.py:3-3 (warning)",),
        ),
    )
    verification = (_verification(tool_findings=(_tool_finding(),)),)

    calibrated = calibrate_findings([finding], validation, verification)[0]

    assert calibrated.base_confidence == 0.7
    assert calibrated.confidence > finding.confidence
    assert "Matched structured tool evidence" in calibrated.confidence_notes


def test_calibration_lowers_confidence_when_scanner_covers_without_hit() -> None:
    finding = _finding()
    validation = (
        ValidationStep(
            finding_id=finding.finding_id,
            objective="Validate shell execution",
            recommended_check="static command-injection rules",
            status="missing",
            candidate_tools=("semgrep",),
        ),
    )
    verification = (_verification(tool_findings=()),)

    calibrated = calibrate_findings([finding], validation, verification)[0]

    assert calibrated.confidence < finding.confidence
    assert "did not emit a matching finding" in calibrated.confidence_notes


def _finding() -> Finding:
    return Finding(
        finding_id="py-shell-true@app.py:1-5",
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


def _verification(*, tool_findings: tuple[ToolFinding, ...]) -> VerificationResult:
    return VerificationResult(
        name="semgrep",
        command="semgrep scan --json",
        command_template="semgrep scan --json",
        timeout_seconds=60,
        required=False,
        adapter="semgrep",
        description="Run Semgrep",
        capabilities=("semgrep", "command-injection"),
        exit_code=0,
        duration_seconds=0.1,
        timed_out=False,
        stdout_path=None,
        stderr_path=None,
        tool_findings=tool_findings,
    )


def _tool_finding() -> ToolFinding:
    return ToolFinding(
        tool_name="semgrep",
        adapter="semgrep",
        rule_id="rule",
        message="Found shell=True",
        file_path="app.py",
        start_line=3,
        end_line=3,
        severity="warning",
    )
