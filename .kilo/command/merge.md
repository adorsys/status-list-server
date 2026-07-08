---
description: Merge planning and building an issue into a single command.
steps: 6
---

# Merge Issue Command

Invoked as `/merge <issue-link>`. Combines `/plan` and `/build` functionality.

## Flow

1. Read the issue description (or PR URL) and generate a detailed plan in `.kilo/plans/issue-<n>.md` using the existing `/plan` logic.
2. Checkout the issue's PR branch if it exists, or create a new branch `issue-<n>-<slug>` from the default branch.
3. Write code according to the plan, modifying only files explicitly mentioned.
4. Run the repository's CI (cargo fmt, cargo build, cargo clippy, cargo nextest, cargo machete).
5. Commit changes with a message referencing the issue number.
6. Push the branch (optional, per repo policy).

## Constraints

- Only modify files explicitly mentioned in the plan.
- Do not modify unrelated files.
- Follow existing code style and structure.
- Keep changes minimal and focused.
- Run all CI checks before committing.
- Do not force-push unless a rebase is required and confirmed.