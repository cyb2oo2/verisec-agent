# Prompt Library

Copy-paste prompts for tools without skill auto-dispatch (Cursor, Grok Build, Copilot Chat, web
chat). Claude Code does not need these — it dispatches skills automatically from
`.claude/skills/`.

**These prompts contain no project knowledge.** They tell the tool which files to read. Knowledge
lives in `AI_CONTEXT.md` and `CLAUDE.md`; instructions live in `.ai/skills/`. If you find yourself
pasting architecture facts into a prompt, fix the file instead.

Fill the `<...>` slots.

---

## Session start

```
Read AI_CONTEXT.md and CLAUDE.md in full before doing anything.

Then read TASK_TRACKER.md and tell me in ≤6 lines:
- what work is currently active or blocked
- whether today's task resumes something or is fresh
- which of the hard constraints in CLAUDE.md this task touches
- the next concrete step

Today's task: <one line>

Do not write code yet. Stop after the briefing.
```

---

## Task prompts

Each loads the canonical skill. Substitute the task.

**Add or change a detection rule / verification adapter**
```
Read AI_CONTEXT.md, CLAUDE.md, and .ai/skills/coding.md. Follow the coding skill exactly.

Task: <what to detect / which adapter to add>

The negative-control requirement is not optional. Do not tune anything against holdout cases.
```

**Structural change — review loop, new module, bundle contract, new CLI command**
```
Read AI_CONTEXT.md, CLAUDE.md, and .ai/skills/architecture.md. Follow the architecture skill.

Proposed change: <what>

Produce the plan first — stage located in the loop, its consumers, policy posture under untrusted
input, documentation fanout, and observable acceptance criteria. No code until I confirm.
```

**A finding fired wrong**
```
Read AI_CONTEXT.md, CLAUDE.md, and .ai/skills/debugging.md. Follow the debugging skill.

Symptom: <false positive / missed detection / bad confidence / policy block>
Bundle or repro: <path to verisec-runs/... or the diff>

Read the trace and bisect by stage before proposing any cause.
```

**Pre-PR review**
```
Read AI_CONTEXT.md, CLAUDE.md, and .ai/skills/review.md. Follow the review skill.

Review my uncommitted changes. Run ruff and pytest in full and show real output. Walk the hard
constraints explicitly. End with READY or NOT READY.

Note: branch cyb/release-hardening carries pre-existing uncommitted work — separate my changes
from what was already there.
```

**Documentation**
```
Read AI_CONTEXT.md, CLAUDE.md, and .ai/skills/documentation.md. Follow the documentation skill.

Change to document: <what shipped>

Do not hand-edit any generated benchmark number. Do not strengthen any hedged claim.
```

---

## Session end

```
Update TASK_TRACKER.md with what moved and what is now blocked (name the blocker).

If a decision was made that a future change could accidentally undo, append an entry to
DEVELOPMENT_LOG.md — context, decision, alternatives, consequences. Do not rewrite existing
entries.

If user-visible behavior changed, add a CHANGELOG.md entry. Rationale goes in the log, not the
changelog.

Then give me ≤8 lines: what shipped, what is partial and why, what to start with next time.
Report unmet criteria as unmet.
```

---

## Correction prompts

When a tool violates an invariant, these are faster than explaining from scratch.

```
Stop. Re-read the hard constraints in CLAUDE.md. You violated <n>: <what you did>.
Revert that and take the compliant path.
```

```
You hand-edited a generated measurement. Those tables mirror
docs/release_benchmark_matrix.json and are produced by `verisec portfolio`. Revert the edit and
regenerate, or leave the number alone.
```

```
That change buys recall with false positives. Add the near-miss to
examples/negative_control_cases.json and show the negative-control gate passing, or drop it.
```

```
You strengthened a hedged claim. The hedges in README.md are deliberate — curated-set results,
post-fix-not-blind-holdout, evidence-backed coverage. Restore the original precision.
```
