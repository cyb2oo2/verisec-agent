# Build Handoff

For tools that **cannot read the repository** — Grok Build in a browser tab, a web chat, any
sandboxed generator. Those tools cannot follow "read AI_CONTEXT.md", so the context has to travel
with the request.

**This is the one place inlining is correct**, and it is deliberately bounded: you generate the
spec fresh per task and throw it away. Nothing here is stored, so nothing here can drift from
`AI_CONTEXT.md`. Do not create a persistent copy of project knowledge for a tool's convenience.

If the tool *can* read the repo (Cursor, Copilot, Claude Code, Grok with repo access), use
`library.md` instead — pointing beats pasting.

---

## Step 1 — generate the spec

Ask a repo-aware assistant:

```
Write a self-contained build spec for a tool that cannot see this repository.

Task: <what to build>

Read AI_CONTEXT.md, CLAUDE.md, and the relevant .ai/skills/ file, then produce a spec containing:
- the exact task, one paragraph
- the conventions from AI_CONTEXT.md "Conventions" that apply, inlined
- any hard constraints from CLAUDE.md this task touches, inlined verbatim
- the exact files to create or edit
- exact signatures and types to implement
- behavior as given/when/then bullets
- acceptance criteria including the test command
- explicit out-of-scope items

Scope it to one reviewable chunk. Then re-read it as if you had no other context and fix anything
ambiguous or unstated.
```

## Step 2 — paste into the build tool

```
You are implementing a well-specified change in an existing Python repository. Follow the spec
exactly.

Do not add features, dependencies, or files beyond the list. This project has zero runtime
dependencies by design. Match the existing style; do not restyle surrounding code. If a
requirement is ambiguous, state your assumption at the top and proceed.

Return the full contents of each changed file plus the tests.

--- SPEC ---
<paste the generated spec>
```

## Step 3 — review before accepting

Generated code is plausible but unverified. Bring it back to a repo-aware tool:

```
Read AI_CONTEXT.md, CLAUDE.md, and .ai/skills/review.md.

Adversarially review this generated code against the spec. Assume it is wrong until shown
otherwise. Check each acceptance criterion met/partial/missing, check correctness and edge cases,
check scope creep, and check whether the tests could actually fail.

Then run ruff and pytest for real and show the output.

--- SPEC ---
<paste spec>
--- GENERATED CODE ---
<paste code>
```

Never commit generated code that has not been run through step 3. A tool that could not read the
repository could not have checked its output against the repository's invariants.
