# AGENTS.md

Instructions for coding agents working in this repository. Contributors using an agent are responsible for its output; the policy is in [CONTRIBUTING.md](CONTRIBUTING.md#ai-assisted-contributions). This file does not replace CONTRIBUTING.md. Follow both.

## Project context

Status List Server implements the IETF OAuth Token Status List draft in Rust (edition 2024) with axum and a ports-and-adapters architecture. Read [README.md](README.md), [CONTRIBUTING.md](CONTRIBUTING.md), and the [architecture guide](docs/architecture.md) before non-trivial changes.

| Path                       | Contents                                                                      |
| -------------------------- | ----------------------------------------------------------------------------- |
| `src/domain/`              | Models, port traits, and the service container. No infrastructure imports.   |
| `src/outbound/`            | Adapters: SQL storage, caches, secrets backends, certificate provider.        |
| `src/server/`              | HTTP handlers, the `auth` middleware, rate limiting, and error mapping.       |
| `src/setup.rs`             | Composition root that builds adapters and application state.                 |
| `src/startup.rs`           | Public, management, and admin listeners and their route sets.                 |
| `src/utils/`               | Signing keys (`crypto.rs`), ACME certificate management, telemetry, metrics.  |
| `tests/`, `src/**/tests`   | Integration and unit tests; container-backed tests need Docker.               |
| `xtask/`                   | `cargo xtask` entry point for profile-aware build, test, lint, and CI.        |
| `docs/openapi*.yaml`       | HTTP API contracts.                                                           |
| `.env.template`, `deploy/` | Runtime configuration reference, Helm chart, and observability configuration. |

## Change rules

- Make the smallest change that solves the task. Keep unrelated refactoring, formatting, and renames out of it. Preserve behavior unless the task asks for a change, and state compatibility or migration impact when it does.
- Do not invent APIs, configuration keys, environment variables, endpoints, or requirements. Read the code. If something stays uncertain, say so and keep assumptions minimal and explicit.
- Follow Rust best practices and the style already present in the touched code.
- Keep `src/domain/` free of infrastructure crates and of `crate::server` and `crate::outbound` imports. CI rejects violations.
- Put backend- and provider-specific code behind its Cargo feature, and keep every profile building (`cargo xtask check-profiles`).
- `unsafe` code is forbidden by a workspace lint.
- Keep secrets in `secrecy` types. Never log, print, or return tokens, keys, passwords, or credentials, including in error messages and test output.
- Avoid new dependencies. When one is unavoidable, explain why in the PR and expect `cargo vet`, `cargo deny`, and `cargo machete` to need attention. Do not add `supply-chain/` exemptions, advisory ignores, or `.trivyignore.yaml` entries yourself; those are maintainer decisions.
- Do not call AI or model APIs from server code. A runtime AI dependency needs an accepted design issue first.
- Never weaken a check to get a green build: no deleted or `#[ignore]`d tests, no relaxed assertions, no new `#[allow]` without a reason, no edits to CI or lint configuration to silence a failure. Fix the cause or report it.

## Keep documentation in sync

Update these in the same change as the code they describe:

- Configuration: `src/config.rs`, `.env.template`, the affected guide in `docs/`, and the Helm values under `deploy/helm/` when the setting is deployable.
- HTTP behavior: `docs/openapi.yaml`, `demo/` and the Postman collection under `postman/`.
- Commands, tool versions, and check names: verify them against `xtask/`, `local-ci.sh`, and `.github/workflows/` before writing them down.

Comments explain why, not what. Do not add comments that narrate the change. They should be brief and focus on important invariants, architectural details, or other long-term relevant information. They should not contain minor implementation details of the current commit.

## Checks

Iterate with narrow commands, then run the full set that matches CI before you report the work as done:

```bash
cargo xtask test --profile minimal                          # fast loop, no Docker
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-targets --all-features  # needs Docker
cargo test --doc --workspace --all-features
```

Also run, when relevant:

- Feature gates changed: `RUSTFLAGS="-D warnings" cargo xtask check-profiles`
- Dependencies changed: `cargo deny --all-features check`, `cargo audit`, `cargo machete --with-metadata`
- Markdown changed: `npx --yes markdownlint-cli2 "**/*.md"`
- Wide or cross-cutting changes: `./local-ci.sh` (see [local CI](docs/local-ci.md))

Add a regression test that fails without a bug fix. Tests assert behavior through public interfaces, not implementation details. If you could not run a check, for example because Docker or provider credentials are unavailable, say which one and why. Never claim a check passed without running it.

## High-risk areas

Changes under these paths need explicit tests and must be called out in the PR description so a maintainer reviews them closely:

- Authentication and authorization: `src/server/auth/`, `src/server/rate_limit.rs`
- Cryptography and signing keys: `src/utils/crypto.rs`, token encoding in `src/server/handlers/status_list/utils/`
- Certificates: `src/utils/cert_manager/`, `src/outbound/cert.rs`
- Secrets backends: `src/outbound/{aws,vault,gcp_secret}.rs`, `src/outbound/azure/`
- Storage and migrations: `src/outbound/sql/`, `src/outbound/cache.rs`
- CI and supply chain: `.github/`, `local-ci.sh`, `scripts/`, `deny.toml`, `supply-chain/`, `Cargo.lock`, `.trivyignore.yaml`
- Deployment: `deploy/`, `Dockerfile`, `docker-compose.yml`, `compose/`

## Commits and pull requests

- Use Conventional Commits for commit subjects and the PR title, as described in [CONTRIBUTING.md](CONTRIBUTING.md#commit-messages).
- For LLM-assisted changes, follow the PR disclosure guidance in CONTRIBUTING.md; disclosure in commit messages is not required. Do not add Co-authored-by or similar authorship trailers for AI tools or models.
- Commits carry the human contributor's name and email. A human opens the PR and answers review questions.
