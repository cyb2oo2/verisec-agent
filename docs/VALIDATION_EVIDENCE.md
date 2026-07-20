# Validation evidence markers

VeriSec only marks a recommended check as **covered** when a verification tool
emits matching structured evidence — not merely because a command exited 0.

Two evidence forms are supported:

1. **Scanner findings** (Semgrep JSON, CodeQL SARIF) that overlap the finding file/lines
2. **`VERISEC_EVIDENCE:` JSON markers** on verification stdout/stderr

## Marker format

Print a single line:

```text
VERISEC_EVIDENCE: {"kind":"...","rule_id":"...","file_path":"...","check":"...","assertion":"..."}
```

### Fields

| Field | Required | Purpose |
| --- | --- | --- |
| `kind` | recommended | e.g. `unit-test`, `property-check`, `static-match` |
| `rule_id` | usually | Must match the VeriSec finding rule when used as primary bind |
| `file_path` | usually | Path relative to the reviewed repo |
| `start_line` / `end_line` | optional | Line range; must overlap the finding window when set |
| `check` | recommended | Text that overlaps the finding's recommended validation string |
| `finding_id` | optional | Exact finding id if you know it |
| `payload` | optional | Adversarial input used in the check |
| `assertion` | optional | Human-readable claim that was verified |
| `message` | optional | Extra note shown in the report |

Matching rules (simplified):

- If `finding_id` is set, it must equal the finding id
- Else if `rule_id` is set, it must equal the finding `rule_id`
- `file_path` must match when present
- Line ranges must overlap when present
- `check` must text-overlap the recommended validation string when present

## Minimal pytest-style stub

See [examples/validation_evidence_stub.py](../examples/validation_evidence_stub.py).

Wire it from `verisec.toml`:

```toml
[[verification.commands]]
name = "security-property-check"
argv = ["{python}", "examples/validation_evidence_stub.py"]
timeout_seconds = 30
required = false
adapter = "custom"
description = "Emit VERISEC_EVIDENCE markers for shell/SQL hypotheses."
capabilities = ["unit-test", "static-analysis", "command-injection"]
```

## Property-check pattern (OSS cases)

Holdout/promoted cases often use a one-shot Python `-c` property check that:

1. Asserts the patched source contains the hardening
2. Prints a `VERISEC_EVIDENCE` marker with `kind=property-check`

That is preferred for frozen CVE benchmarks because it does not depend on full
test suites of large upstream trees.

## How coverage appears

- Terminal `review` summary: "Still missing validation" vs "Validated"
- `report.md` validation plan with `covered` / `missing`
- Confidence calibration rises when structured tool evidence matches

## SARIF export

Every review bundle also writes `report.sarif` (SARIF 2.1.0) for GitHub code
scanning or other SARIF consumers. Upload example:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: verisec-runs/pr-review/report.sarif
```
