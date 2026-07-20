# .ai — tool-neutral AI layer

Shared instructions for any AI coding tool. Claude Code, Cursor, Grok Build, and Copilot all read
the same content from here.

```
.ai/
├── skills/     canonical task instructions (architecture, coding, debugging, review, documentation)
└── prompts/    copy-paste dispatch for tools without skill auto-selection
```

## Single source of truth

Each fact lives in exactly one file. Nothing here restates project knowledge.

| Layer | File | Holds |
|---|---|---|
| Understanding | [`AI_CONTEXT.md`](../AI_CONTEXT.md) | What the system is — loop, vocabulary, task recipes |
| Constraints | [`CLAUDE.md`](../CLAUDE.md) | Hard invariants, commands, house style |
| Instructions | `.ai/skills/*.md` | How to perform a task, step by step |
| Dispatch | `.ai/prompts/*.md` | How to *invoke* the above from a tool that can't auto-select |
| State | [`TASK_TRACKER.md`](../TASK_TRACKER.md) · [`DEVELOPMENT_LOG.md`](../DEVELOPMENT_LOG.md) | In-flight work · decisions and why |

Despite its name, `CLAUDE.md` is plain Markdown and applies to every tool — the filename is a
Claude Code loading convention, not a scope boundary. Read it regardless of which tool you use.

## How each tool consumes this

**Claude Code** — automatic. `CLAUDE.md` loads at session start; `.claude/skills/*/SKILL.md`
dispatch on their descriptions. Each of those five files is a stub whose body points here, so
Claude Code and every other tool execute identical instructions. The stubs exist only because
Claude Code needs YAML frontmatter to know *when* to trigger; the instructions themselves are not
duplicated.

**Cursor** — no auto-loading is configured. Start a session by pasting the session-start prompt
from [`prompts/library.md`](prompts/library.md), or add a three-line `.cursorrules` at the repo
root pointing at `AI_CONTEXT.md`, `CLAUDE.md`, and `.ai/skills/`. That file is not committed today;
add it if your team standardizes on Cursor.

**Grok Build / Copilot / web chat** — use [`prompts/library.md`](prompts/library.md) when the tool
can read the repo. When it cannot, use [`prompts/build-handoff.md`](prompts/build-handoff.md),
which generates a self-contained spec per task rather than storing a second copy of project
knowledge.

## Editing rules

- **Change a skill in `.ai/skills/` only.** The `.claude/skills/` stubs carry no instructions; if
  you find instructions in a stub, someone has forked the content — collapse it back.
- **Never inline project knowledge into a prompt.** Prompts name files to read. The single
  exception is `build-handoff.md`, where the inlined spec is generated per task and discarded.
- **Adding a skill:** write `.ai/skills/<name>.md`, then add a `.claude/skills/<name>/SKILL.md`
  stub with `name` + `description` frontmatter and a pointer body. The description is what makes
  Claude Code trigger it — write it as trigger phrases, not a summary.
- **Keep instructions repo-specific.** These skills earn their place by encoding VeriSec's
  ordering constraints and invariants. Generic advice is noise; a capable model already has it.
