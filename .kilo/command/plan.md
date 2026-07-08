---
description: Plan an issue by understanding requirements, analyzing current code, and producing a detailed plan.
steps: 8
---

# Plan Issue

Invoked as `/plan <issue-link>`. Accepts a bare issue number (defaults to the repository's default issue tracker), a full GitHub PR URL, or `owner/repo#number`. Reads the issue description, existing codebase, and project memory to produce a detailed plan written to `.kilo/plans/issue-<n>.md`. The plan includes:

- Issue understanding (goals, constraints, acceptance criteria)
- Current state analysis (relevant files, existing implementations)
- Context from project memory (if available)
- Detailed implementation plan (files to modify, new files, sequence, dependencies)
- Risks and mitigations
- Validation criteria

The command does **not** create or switch git branches; it only produces the plan file.