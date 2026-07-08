---
description: Review a GitHub PR with specs, logic, security, and submit inline review to GitHub
steps: 50
---

# PR Review — Automated End-to-End

Invoked as `/pr-review <number|url>`. Accepts a bare number (defaults to `ADORSYS-GIS/cloud-identity-wallet`), a full PR URL, or `owner/repo#number`. Execute the full workflow autonomously — do not pause for intermediate confirmation. Unparseable input → report and stop.

## 1. Gather Context
1. **Metadata** — `github_get_pull_request`, `github_get_pull_request_files` (diffs), plus `github_get_pull_request_reviews` / `github_get_pull_request_comments` to avoid duplicating existing feedback.
2. **Checkout** — `gh pr checkout <number>` for full-file inspection (if this fails, fall back to diff-only review).
3. **Project memory** — resolve the memory bank dynamically (this is a global command, so the bank must not be hard-coded):
   - Determine the candidate bank name from the project: prefer the PR's `owner/repo`, then the current workspace's `git remote get-url origin`, falling back to the working-directory name stripped of `.git`.
   - Normalize the candidate (strip `/`, lower-case, replace `-`/`_`/`.` with spaces, trim) and try a few variants: the normalized repo name, the normalized full `owner/repo`, and the normalized owner segment.
   - Probe `cognitive-memory_memory_get_bank` with each variant. If a bank is found, open a session on it via `cognitive-memory_memory_open_session`, recall using the PR title and key terms from the changed files, then close the session.
   - If no bank matches, do **not** guess or default to any hardcoded bank. Instead use the `question` tool to ask the user: "No memory bank found for project `<name>`. Which memory bank should I use for recall?" Offer options to type the bank name or to skip memory recall for this review. Proceed with the user's choice and remember it for this command only (do not persist it back into the command file).
4. **Spec research** — for each spec referenced in the PR or code (OID4VCI, HAIP, RFC 6749/9449, SD-JWT VC, ISO mdoc, OAuth 2.1, OIDC, etc.), pull authoritative docs via `context7_resolve-library-id` / `context7_query-docs` or `tavily_tavily-search`, and verify the code actually matches the spec text wherever the PR claims compliance.

## 2. Analyze
Review each changed file against:
- **Spec & correctness** — protocol fields/headers/params/errors match spec; edge cases (null, empty, missing) and match-arm exhaustiveness handled; no `unwrap()` in production paths; no logic/off-by-one errors.
- **Security** — crypto material (keys/tokens/nonces) handled safely; signatures verified where required; clock-skew tolerance on `iat`/`exp`/`nbf`; no forgeable/replayable input; no secrets in logs/errors; no timing side-channels.
- **Design** — APIs well-named and non-redundant; no dead/duplicated code; error mapping matches flow context; consistent with project conventions; `#[allow(...)]` justified; scales to batch/concurrent use.
- **Tests & quality** — confirm existing tests cover the change; add tests for missing edge cases. Run `cargo test --package <pkg>` (or `cargo test -- <test_name>` for a single test), `cargo clippy --all-targets --package <pkg> -- -D warnings`, and `cargo check --package <pkg>`. Any failures go straight into the findings.

## 3. Findings
Each finding needs:
- **Severity** — `Bug` (blocks merge, correctness), `Important` (should fix, security/risk), `Suggestion` (design improvement), `Nit` (style/minor), `Question` (needs clarification)
- **File path** (relative to repo root) and **line number** on the PR's head branch (not diff-relative)
- **Body** explaining *why*, not just what — include a code snippet for suggested fixes

Rules:
- Group findings by file.
- Never post a finding without a line reference.
- If a prior reviewer already raised something you agree with, don't duplicate it — note it in the summary instead; if a prior finding is now resolved, note that too.
- Be explicit about category: won't compile vs. violates spec vs. stylistic preference.

## 4. Submit Review
- `event`: `REQUEST_CHANGES` if any Bug/Important findings, `COMMENT` if only Suggestion/Nit/Question, `APPROVE` if none.
- `body`: 3–5 sentence summary — overall assessment, finding counts by severity, key themes (e.g. spec compliance, security, dead code).
- `comments`: one `{ "path", "line", "body" }` object per finding.
- Submit via `github_create_pull_request_review` (`owner`, `repo`, `pull_number`, `event`, `body`, `comments`).
- Report back: event chosen, finding counts by severity, and the review's HTML URL.

## Error Handling
- Malformed PR reference → report and stop.
- `gh` / GitHub API failure after 2 retries → report and stop.
- Branch checkout fails → review from diff only.
- `github_create_pull_request_review` fails on line resolution → fall back to `github_add_issue_comment` with all findings in one comment body (file path + line per finding); tell the user inline comments failed and share the issue-comment URL instead.
- `cargo test` / `clippy` failures → include raw output in the review summary rather than dropping it.