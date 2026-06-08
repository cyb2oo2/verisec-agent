from verisec_agent.models import Finding, ToolFinding, VerificationResult
from verisec_agent.tool_output import parse_sarif_json, parse_semgrep_json
from verisec_agent.validation import build_validation_plan


def test_parse_semgrep_json_extracts_tool_findings() -> None:
    payload = """{
      "results": [
        {
          "check_id": "python.lang.security.audit.subprocess-shell-true",
          "path": "examples/demo_app.py",
          "start": {"line": 7, "col": 12},
          "end": {"line": 7, "col": 55},
          "extra": {
            "message": "Found subprocess call with shell=True",
            "severity": "WARNING",
            "metadata": {"category": "security"}
          }
        }
      ]
    }"""

    findings = parse_semgrep_json(tool_name="semgrep", payload=payload)

    assert len(findings) == 1
    assert findings[0].adapter == "semgrep"
    assert findings[0].rule_id == "python.lang.security.audit.subprocess-shell-true"
    assert findings[0].location() == "examples/demo_app.py:7-7"
    assert findings[0].severity == "warning"


def test_parse_sarif_json_extracts_codeql_tool_findings() -> None:
    payload = """{
      "version": "2.1.0",
      "runs": [{
        "tool": {
          "driver": {
            "name": "CodeQL",
            "rules": [{
              "id": "py/command-line-injection",
              "defaultConfiguration": {"level": "error"},
              "properties": {"security-severity": "8.8"}
            }]
          }
        },
        "results": [{
          "ruleId": "py/command-line-injection",
          "message": {"text": "This command depends on user input."},
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {"uri": "app.py"},
              "region": {"startLine": 3, "endLine": 3}
            }
          }]
        }]
      }]
    }"""

    findings = parse_sarif_json(tool_name="codeql", adapter="codeql", payload=payload)

    assert len(findings) == 1
    assert findings[0].adapter == "codeql"
    assert findings[0].rule_id == "py/command-line-injection"
    assert findings[0].message == "This command depends on user input."
    assert findings[0].location() == "app.py:3-3"
    assert findings[0].severity == "error"


def test_validation_links_matching_tool_finding_to_review_finding() -> None:
    finding = Finding(
        finding_id="py-shell-true@examples/demo_app.py:1-8",
        rule_id="py-shell-true",
        title="Shell execution path introduced",
        severity="high",
        confidence=0.7,
        file_path="examples/demo_app.py",
        start_line=1,
        end_line=8,
        evidence="+7: subprocess.run(user_input, shell=True)",
        source_context=None,
        risk="Command injection",
        fix_guidance="Use shell=False",
        recommended_validation=("static command-injection rules",),
        false_positive_notes="",
    )
    result = VerificationResult(
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
        tool_findings=(
            ToolFinding(
                tool_name="semgrep",
                adapter="semgrep",
                rule_id="python.lang.security.audit.subprocess-shell-true",
                message="Found subprocess call with shell=True",
                file_path="./examples/demo_app.py",
                start_line=7,
                end_line=7,
                severity="warning",
            ),
        ),
    )

    plan = build_validation_plan([finding], [result])

    assert plan[0].status == "covered"
    assert plan[0].covered_by == ("semgrep",)
    assert len(plan[0].tool_evidence) == 1
    assert "subprocess-shell-true" in plan[0].tool_evidence[0]
