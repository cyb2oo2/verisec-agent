# Contributing to VeriSec Agent

Thanks for helping improve VeriSec. This project has two contribution surfaces:

| Surface | Audience | Start here |
| --- | --- | --- |
| **Operator** | People reviewing PRs/diffs | [docs/OPERATOR.md](docs/OPERATOR.md) |
| **Lab / core** | Rules, adapters, benchmarks | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |

## Development setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m ruff check src tests
python -m pytest
```

Optional scanners: `python -m pip install -e ".[scanners]"` or
`.\scripts\bootstrap_scanners.ps1`.

## Project layout (short)

- `src/verisec_agent/` — CLI, review loop, semantics, evaluation
- `tests/` — unit and workflow tests
- `examples/` — demo diffs, case manifests, validation stubs
- `docs/` — operator, architecture, holdout, validation evidence

## Good first contributions

1. **Negative control** — add a near-miss under `examples/negative_controls/` + case JSON
2. **Validation stub** — improve `examples/validation_evidence_stub.py` for a rule
3. **Unit test** — extend `tests/test_python_semantics.py` for a redos/unicode edge
4. **Docs** — operator troubleshooting or CONTRIBUTING examples

## Plugin spine (rules + adapters)

### Enable packs / external adapters

```toml
[rules]
packs = ["builtin", "django"]

[adapters]
paths = ["adapters/bandit.toml"]

[[verification.adapters]]
id = "bandit"
required = false
```

- Rule packs: `src/verisec_agent/rules_api.py` (`RuleProvider`, `load_rule_registry`)
- Built-in pack: `rules_builtin.py` (core rules + AST/dataflow)
- Django pack: `rules_django.py` (optional specialized pack)
- Adapter specs: `adapters_api.py` + TOML files under `adapters/`
- External TOML adapters: `adapters/bandit.toml`, `adapters/pip-audit.toml`
  with parsers in `tool_output.py` (`bandit-json`, `pip-audit-json`)

### Adding a security rule

**Preferred path (builtin pack):**

1. Prefer semantic detection in `python_semantics.py` when possible (AST/dataflow)
2. Add/adjust `Rule` metadata in `hypotheses.py` (`RULES` / `BUILTIN_RULES`)
3. Family/mode metadata (`redos`, `complexity-dos`, `adds-hardening`, …)
4. Regex fallback only as a secondary signal
5. Unit tests for positive + negative cases
6. Do **not** retrain on frozen holdout cases for claimed metrics

**New pack path (in-tree):**

1. Implement a class with `pack_id`, `rules()`, `analyze_window()`, `analyze_file()`
2. Register the built-in fallback in `rules_api._builtin_pack_factories()` if needed
3. Declare a setuptools entry point (required for installable packs)

**Third-party / installable pack (setuptools entry points):**

```toml
# in your package's pyproject.toml
[project.entry-points."verisec.rules"]
my-pack = "my_package.rules:MyRuleProvider"
```

`MyRuleProvider` may be:

- a class (`MyRuleProvider()` constructed with no args), or
- a zero-argument factory returning a provider instance

Enable it:

```toml
# consumer verisec.toml
[rules]
packs = ["builtin", "my-pack"]
```

List discovered packs (built-ins + entry points): use `available_rule_packs()` or load a
config that references the pack id. After `pip install -e .` (or installing your
plugin package), entry points are visible to VeriSec.

VeriSec itself declares:

```toml
[project.entry-points."verisec.rules"]
builtin = "verisec_agent.rules_builtin:BuiltinRuleProvider"
django = "verisec_agent.rules_django:DjangoRuleProvider"
```

See also [docs/VALIDATION_EVIDENCE.md](docs/VALIDATION_EVIDENCE.md).

### Adding a verification adapter

**TOML plugin (recommended for external CLIs):**

1. Copy `adapters/bandit.toml` and edit `id`, `command`, `executable`, `parser`, `capabilities`
2. Implement parser branch in `tool_output.py` if you introduce a new `parser` name
3. Reference the file from `[adapters].paths` and enable `[[verification.adapters]]`
4. Allowlist adapter + executable under `[policy]`
5. Add tests in `tests/test_plugins.py`

**In-tree built-in:**

1. Register in `tool_adapters.BUILTIN_ADAPTERS`
2. Set parser mapping in `adapters_api.builtin_adapter_specs()`
3. Tests under `tests/test_tool_adapters.py` / `tests/test_tool_output.py`

## Benchmark / lab changes

- Case intake: `case-audit` → `case-promote` before measured suites
- Never promote holdout cases into measured seed without a new freeze protocol
- Prefer property-check `VERISEC_EVIDENCE` markers for large upstream trees

## Pull requests

- Keep PRs focused (one detector family or one docs surface when possible)
- Include tests for behavior changes
- Run `ruff` + `pytest` before requesting review
- Update `CHANGELOG.md` for user-visible changes

## Code of conduct

Be respectful and constructive. Security issues: see [SECURITY.md](SECURITY.md).
