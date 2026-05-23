# Architecture

VeriSec Agent is organized around an auditable review loop.

## Core loop

1. Diff ingestion extracts changed files, hunks, and changed lines.
2. Evidence localization creates compact windows around security-relevant
   additions.
3. Hypothesis generation maps evidence to concrete security risks.
4. Verification executes configured tools and captures outputs.
5. Reporting emits reviewer-facing findings and a reproducibility bundle.

The first version uses deterministic rules so the infrastructure can be tested
without relying on an LLM provider. LLM planning and code-context expansion can
be added behind the same interfaces.

## Package map

- `diff_parser.py`: unified diff parsing and evidence windows.
- `hypotheses.py`: security hypothesis rules.
- `verification.py`: command execution and trace capture.
- `bundle.py`: portable review bundle layout.
- `agent.py`: orchestration of the review loop.
- `cli.py`: command-line entry point.

## Bundle contract

Every run writes:

- `inputs/diff.patch`: exact reviewed patch.
- `inputs/source.json`: local file, GitHub PR, or URL source metadata.
- `trace.jsonl`: ordered decision and tool events.
- `tools/*.txt`: stdout and stderr from verification commands.
- `report.json`: stable machine-readable review report.

The bundle is the future handoff point for UI replay, reviewer audit, and
benchmark reproducibility.
