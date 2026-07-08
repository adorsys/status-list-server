---
description: Build an issue by reading the plan and writing the code.
steps: 6
---

# Build Issue

Invoked as `/build <issue-number>`. Uses the plan written by `/plan <issue-link>` to write code.

## Flow
1. Read the plan from `.kilo/plans/issue-<n>.md`
2. Checkout the issue's PR branch if it exists, or create a new branch `issue-<n>-<slug>` from the repository's default branch
3. Write code according to the plan, touching only the files specified
4. Run the repository's CI (cargo fmt, cargo build, cargo clippy, cargo nextest, cargo machete)
5. Commit the changes with a message referencing the issue number
6. Push the branch (optional, depends on repo policy)

## Constraints
- Only modify files explicitly mentioned in the plan
- Do not modify unrelated files
- Follow existing code style and structure
- Keep changes minimal and focused
- Run all CI checks before committing
- Do not force-push unless a rebase is required and confirmed