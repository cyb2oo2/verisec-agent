"""Consistency of the published benchmark surfaces.

These read committed files rather than `tmp_path` fixtures on purpose: the drift
they guard against is between published artifacts, so a synthetic tree cannot
show it. `docs/RELEASE_BENCHMARK.md` is generated verbatim and is checked against
the renderer; `README.md` is generated-*derived* but hand-transcribed, so it is
checked field by field.

Regeneration freshness — whether the committed snapshot still matches a live
portfolio run — needs an actual run and lives in
`scripts/check_benchmark_freshness.py`.
"""

import json
import re
from pathlib import Path

from verisec_agent.portfolio import render_benchmark_matrix_markdown

REPO_ROOT = Path(__file__).resolve().parents[1]
MATRIX_JSON = REPO_ROOT / "docs" / "release_benchmark_matrix.json"
MATRIX_MARKDOWN = REPO_ROOT / "docs" / "RELEASE_BENCHMARK.md"
README = REPO_ROOT / "README.md"

# README column order, mapped to matrix metric keys. Its "System" column is the
# row label and its Status column does not exist, so neither appears here.
README_COLUMNS = (
    "positive_cases",
    "negative_controls",
    "primary_recall",
    "primary_precision",
    "findings",
    "raw_tool_findings",
    "out_of_scope_findings",
    "validation_coverage",
    "tool_evidence_rate",
    "negative_control_violations",
)
RATE_METRICS = frozenset(
    {"primary_recall", "primary_precision", "validation_coverage", "tool_evidence_rate"}
)


def _matrix() -> dict:
    return json.loads(MATRIX_JSON.read_text(encoding="utf-8"))


def _markdown_table_rows(text: str, labels: set[str]) -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if cells and cells[0] in labels:
            rows[cells[0]] = cells
    return rows


def _leading_number(cell: str) -> float:
    """First number in a cell, so "12 adversarial controls" reads as 12."""
    match = re.search(r"-?\d+(?:\.\d+)?", cell)
    assert match is not None, f"no number in cell {cell!r}"
    return float(match.group())


def test_published_markdown_matches_published_json() -> None:
    """The committed Markdown must be what the renderer produces from the committed JSON."""
    expected = render_benchmark_matrix_markdown(_matrix())

    assert MATRIX_MARKDOWN.read_text(encoding="utf-8").splitlines() == expected.splitlines()


def test_readme_table_matches_published_json() -> None:
    """README transcribes the snapshot by hand, so every figure is checked against it."""
    matrix = _matrix()
    systems = {system["label"]: system["metrics"] for system in matrix["systems"]}
    rows = _markdown_table_rows(README.read_text(encoding="utf-8"), set(systems))

    assert set(rows) == set(systems), "README benchmark table is missing a published system"

    for label, metrics in systems.items():
        cells = rows[label][1:]
        assert len(cells) == len(README_COLUMNS), f"unexpected column count for {label}"
        for metric, cell in zip(README_COLUMNS, cells, strict=True):
            expected = metrics[metric]
            if expected is None:
                continue
            places = 2 if metric in RATE_METRICS else 0
            assert round(_leading_number(cell), places) == round(float(expected), places), (
                f"README {label!r} column {metric!r} is {cell!r}, "
                f"but the published snapshot says {expected!r}"
            )


def test_claim_boundary_counts_match_published_metrics() -> None:
    """Counts in the claim boundary must agree with the table they qualify.

    Derivation makes this structurally true at generation time; this pins it for
    the committed artifact, which is what readers actually see.
    """
    matrix = _matrix()
    systems = {system["label"]: system["metrics"] for system in matrix["systems"]}
    boundary = next(
        text for text in matrix["claim_boundaries"] if "curated benchmark" in text
    )

    assert f"{systems['VeriSec Agent']['positive_cases']} OSS seed cases" in boundary
    assert (
        f"{systems['VeriSec Agent promoted CVEs']['positive_cases']} promoted CVE cases"
        in boundary
    )
    assert f"{systems['VeriSec Agent']['negative_controls']} negative controls" in boundary
