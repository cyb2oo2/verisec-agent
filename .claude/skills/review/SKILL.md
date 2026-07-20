---
name: review
description: Pre-PR gate for changes to VeriSec itself before requesting human review. Use when the user says "review my changes", "ready to commit", "check this before I push", "is this ready", or finishes a unit of work. This reviews the repository's own code — not to be confused with `verisec review`, which reviews a user's diff.
---

# Review

**Read [`.ai/skills/review.md`](../../../.ai/skills/review.md) now and follow it.**

That file is the canonical, tool-neutral version of this skill, shared with Cursor and
Grok Build. This stub exists only so Claude Code can dispatch on the frontmatter above —
the instructions themselves live in one place so the two surfaces cannot drift.

Prerequisites: [`AI_CONTEXT.md`](../../../AI_CONTEXT.md) (architecture, vocabulary) and
[`CLAUDE.md`](../../../CLAUDE.md) (hard constraints).
