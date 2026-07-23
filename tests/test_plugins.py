import json
import re
from pathlib import Path

from verisec_agent.adapters_api import (
    load_adapter_registry,
    load_adapter_spec_from_toml,
    reset_adapter_registry,
    set_adapter_registry,
)
from verisec_agent.config import load_config
from verisec_agent.diff_parser import evidence_windows, parse_unified_diff
from verisec_agent.hypotheses import Rule, generate_hypotheses
from verisec_agent.models import EvidenceWindow
from verisec_agent.python_semantics import SemanticMatch
from verisec_agent.rules_api import (
    available_rule_packs,
    load_rule_registry,
    reset_rule_pack_cache,
)
from verisec_agent.tool_adapters import list_builtin_adapters, resolve_adapter
from verisec_agent.tool_output import (
    parse_bandit_json,
    parse_pip_audit_json,
    parse_tool_output,
)

_FAKE_RULE = Rule(
    rule_id="test-fake-rule",
    title="Test-only fake rule",
    severity="low",
    pattern=re.compile(r"__verisec_test_marker__"),
    risk="test",
    fix_guidance="test",
    recommended_validation=("test",),
    confidence=0.5,
    false_positive_notes="test",
)


class FakeRuleProvider:
    """Minimal non-builtin pack used to exercise entry-point discovery."""

    @property
    def pack_id(self) -> str:
        return "fake"

    def rules(self) -> tuple[Rule, ...]:
        return (_FAKE_RULE,)

    def analyze_window(self, window: EvidenceWindow) -> tuple[SemanticMatch, ...]:
        return ()

    def analyze_file(
        self,
        *,
        file_path: Path,
        changed_lines: set[int],
    ) -> tuple[SemanticMatch, ...]:
        return ()


def setup_function() -> None:
    reset_adapter_registry()
    reset_rule_pack_cache()


def teardown_function() -> None:
    reset_adapter_registry()
    reset_rule_pack_cache()


def test_available_rule_packs_include_builtin() -> None:
    packs = available_rule_packs()
    assert "builtin" in packs


def test_rules_entry_points_discover_custom_pack(monkeypatch) -> None:
    class FakeEntryPoint:
        name = "demo-pack"

        def load(self):
            return FakeRuleProvider

    def fake_entry_points(*, group: str | None = None, **_kwargs):
        if group == "verisec.rules":
            return (FakeEntryPoint(),)
        return ()

    monkeypatch.setattr("verisec_agent.rules_api.entry_points", fake_entry_points)
    reset_rule_pack_cache()

    packs = available_rule_packs()
    assert "demo-pack" in packs
    assert "builtin" in packs

    # Entry-point name is the pack key used in [rules].packs; the provider may
    # still report its own pack_id property.
    registry = load_rule_registry(["demo-pack"])
    rule_ids = {rule.rule_id for rule in registry.rules()}
    assert "test-fake-rule" in rule_ids
    assert len(registry.providers) == 1


def test_rules_entry_point_accepts_factory_callable(monkeypatch) -> None:
    class FakeEntryPoint:
        name = "factory-pack"

        def load(self):
            return lambda: FakeRuleProvider()

    monkeypatch.setattr(
        "verisec_agent.rules_api.entry_points",
        lambda **kwargs: (FakeEntryPoint(),)
        if kwargs.get("group") == "verisec.rules"
        else (),
    )
    reset_rule_pack_cache()
    registry = load_rule_registry(["factory-pack"])
    assert any(rule.rule_id == "test-fake-rule" for rule in registry.rules())


def test_installed_verisec_rules_entry_points_exist() -> None:
    from importlib.metadata import entry_points

    names = {ep.name for ep in entry_points(group="verisec.rules")}
    assert "builtin" in names


def test_builtin_rule_registry_loads_core_rules() -> None:
    registry = load_rule_registry(["builtin"])
    rule_ids = {rule.rule_id for rule in registry.rules()}
    assert "py-shell-true" in rule_ids
    assert "py-unicode-normalization-dos" in rule_ids
    assert "py-regex-redos" in rule_ids


def test_generate_hypotheses_respects_rule_packs(monkeypatch) -> None:
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
 import subprocess
 def run(user_input):
+    return subprocess.run(user_input, shell=True)
"""
    windows = evidence_windows(parse_unified_diff(diff))
    with_shell = generate_hypotheses(windows, min_confidence=0.35, rule_packs=("builtin",))
    assert any(item.rule_id == "py-shell-true" for item in with_shell)

    class FakeEntryPoint:
        name = "fake-pack"

        def load(self):
            return FakeRuleProvider

    monkeypatch.setattr(
        "verisec_agent.rules_api.entry_points",
        lambda **kwargs: (FakeEntryPoint(),)
        if kwargs.get("group") == "verisec.rules"
        else (),
    )
    reset_rule_pack_cache()

    # A pack without the shell rule produces no finding on the same diff.
    fake_only = generate_hypotheses(windows, min_confidence=0.35, rule_packs=("fake-pack",))
    assert fake_only == ()


def test_load_bandit_adapter_toml(tmp_path: Path) -> None:
    path = tmp_path / "bandit.toml"
    path.write_text(
        """
id = "bandit"
name = "bandit"
description = "Bandit scan"
command = "bandit -f json -r . -q"
executable = "bandit"
parser = "bandit-json"
timeout_seconds = 90
capabilities = ["bandit", "static-analysis"]
""",
        encoding="utf-8",
    )
    spec = load_adapter_spec_from_toml(path)
    assert spec.adapter_id == "bandit"
    assert spec.parser == "bandit-json"
    assert spec.executable == "bandit"
    assert "static-analysis" in spec.capabilities

    registry = load_adapter_registry(adapter_paths=[path])
    set_adapter_registry(registry)
    command = resolve_adapter({"id": "bandit", "required": False})
    assert command.adapter == "bandit"
    assert command.timeout_seconds == 90
    assert "bandit" in command.capabilities


def test_config_loads_rule_packs_and_adapter_paths(tmp_path: Path) -> None:
    adapter = tmp_path / "bandit.toml"
    adapter.write_text(
        Path("adapters/bandit.toml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    config_path = tmp_path / "verisec.toml"
    config_path.write_text(
        f"""
[rules]
packs = ["builtin"]

[adapters]
paths = ["{adapter.name}"]

[[verification.adapters]]
id = "bandit"
required = false
""",
        encoding="utf-8",
    )
    config = load_config(config_path)
    assert config.rule_packs == ("builtin",)
    assert any(command.adapter == "bandit" for command in config.verification_commands)
    adapters = {item.to_dict()["id"] for item in list_builtin_adapters()}
    assert "bandit" in adapters
    assert "pytest" in adapters


def test_parse_bandit_json_findings() -> None:
    payload = json.dumps(
        {
            "results": [
                {
                    "filename": "app.py",
                    "line_number": 3,
                    "line_range": [3, 4],
                    "test_id": "B602",
                    "test_name": "subprocess_popen_with_shell_equals_true",
                    "issue_severity": "HIGH",
                    "issue_text": "subprocess call with shell=True",
                    "issue_confidence": "HIGH",
                }
            ]
        }
    )
    findings = parse_bandit_json(tool_name="bandit", payload=payload)
    assert len(findings) == 1
    assert findings[0].rule_id == "B602"
    assert findings[0].file_path == "app.py"
    assert findings[0].start_line == 3
    assert findings[0].end_line == 4
    assert findings[0].severity == "high"

    parsed = parse_tool_output(
        adapter="bandit",
        tool_name="bandit",
        stdout=payload,
        tool_dir=Path("."),
    )
    assert len(parsed.findings) == 1


def test_unknown_rule_pack_errors() -> None:
    try:
        load_rule_registry(["nope"])
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "Unknown rule pack" in str(exc)


def test_load_pip_audit_adapter_toml() -> None:
    path = Path("adapters/pip-audit.toml")
    spec = load_adapter_spec_from_toml(path)
    assert spec.adapter_id == "pip-audit"
    assert spec.parser == "pip-audit-json"
    assert spec.executable == "pip-audit"
    assert "dependency-audit" in spec.capabilities

    registry = load_adapter_registry(adapter_paths=[path])
    set_adapter_registry(registry)
    command = resolve_adapter({"id": "pip-audit"})
    assert command.adapter == "pip-audit"
    assert "pip-audit" in command.command
    assert command.timeout_seconds == 180


def test_parse_pip_audit_json_findings() -> None:
    payload = json.dumps(
        [
            {
                "name": "flask",
                "version": "0.5",
                "vulns": [
                    {
                        "id": "PYSEC-2019-179",
                        "fix_versions": ["1.0"],
                        "aliases": ["CVE-2019-1010083"],
                        "description": "Flask before 1.0 memory usage issue.",
                    }
                ],
            }
        ]
    )
    findings = parse_pip_audit_json(tool_name="pip-audit", payload=payload)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.adapter == "pip-audit"
    assert finding.rule_id == "PYSEC-2019-179"
    assert finding.file_path == "dependencies/flask"
    assert finding.start_line == 1
    assert finding.severity == "high"
    assert "fix: 1.0" in finding.message
    assert finding.metadata["package"] == "flask"
    assert "CVE-2019-1010083" in finding.metadata["aliases"]

    wrapped = json.dumps({"dependencies": json.loads(payload)})
    assert len(parse_pip_audit_json(tool_name="pip-audit", payload=wrapped)) == 1

    parsed = parse_tool_output(
        adapter="pip-audit",
        tool_name="pip-audit",
        stdout=payload,
        tool_dir=Path("."),
    )
    assert len(parsed.findings) == 1


def test_config_loads_both_external_toml_adapters(tmp_path: Path) -> None:
    bandit = tmp_path / "bandit.toml"
    pip_audit = tmp_path / "pip-audit.toml"
    bandit.write_text(Path("adapters/bandit.toml").read_text(encoding="utf-8"), encoding="utf-8")
    pip_audit.write_text(
        Path("adapters/pip-audit.toml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    config_path = tmp_path / "verisec.toml"
    config_path.write_text(
        """
[adapters]
paths = ["bandit.toml", "pip-audit.toml"]

[[verification.adapters]]
id = "bandit"

[[verification.adapters]]
id = "pip-audit"
""",
        encoding="utf-8",
    )
    config = load_config(config_path)
    adapters = {command.adapter for command in config.verification_commands}
    assert adapters == {"bandit", "pip-audit"}
