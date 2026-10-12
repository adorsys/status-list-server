# Contributing to this project

Thank you for your interest in contributing! This document covers how to submit changes.

## Commit Messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/) to automate versioning and changelog generation. Every commit message merged to `main` **must** follow this format:

```text
<type>(<optional scope>): <description>

[optional body]

[optional footer(s)]
```

The CI job **Conventional Commits** validates PR titles
and every commit subject in the pull request. Use the same Conventional Commit
format for the PR title because maintainers squash merge PRs, and the PR title
commonly becomes the final commit subject on `main`.

### Types

| Type       | Purpose                                                 | Version bump |
| ---------- | ------------------------------------------------------- | ------------ |
| `feat`     | A new feature                                           | minor        |
| `fix`      | A bug fix                                               | patch        |
| `docs`     | Documentation only                                      | patch        |
| `refactor` | Code change that neither fixes a bug nor adds a feature | patch        |
| `perf`     | Performance improvement                                 | patch        |
| `test`     | Adding or correcting tests                              | patch        |
| `ci`       | CI/CD configuration changes                             | patch        |
| `chore`    | Other changes that don't modify src or test files       | patch        |
| `build`    | Build system or external dependency changes             | patch        |
| `revert`   | Reverts a previous commit                               | patch        |
| `style`    | Code style changes (formatting, semicolons, etc.)       | patch        |

### Breaking Changes

Append `!` after the type/scope or add a `BREAKING CHANGE:` footer to trigger a
**major** version bump:

```text
feat!: remove deprecated /v1 endpoints

BREAKING CHANGE: The /v1 API has been removed. Use /v2 instead.
```

### Examples

```text
feat(api): add time-travel query parameter for historical lookups
fix(db): prevent lost update on concurrent status list writes
docs: update architecture diagram with new caching layer
ci: add trivy config scan for Helm chart
chore(deps): bump serde from 1.0.200 to 1.0.210
refactor(telemetry): simplify OTLP layer composition
```

Messages such as `fixed stuff`, `update code`, `address review`, or `WIP` are
rejected by CI because `git-cliff` and `release-plz` cannot use them to compute
release notes or semantic version bumps.

## Pull Requests

1. Fork the repository and create a feature branch from `main`.
2. Make your changes, ensuring all commits follow Conventional Commits format.
3. Open a PR against `develop` with a Conventional Commit title, for example
   `feat(api): add issuer status endpoint`. CI will run automatically.
4. Address review feedback.
5. A maintainer will merge using **squash merge** (the squash commit message should also follow Conventional Commits format).

## Branch Protection

Maintainers must configure the `main` and `develop` branch protection rules or
repository rulesets to require the status check named
**Conventional Commits / Conventional Commits** before merging. This keeps
unconventional commit subjects out of protected branches, where they would
otherwise be ignored by `git-cliff` and `release-plz`.

They must also require **`CI Success`** and **`Helm Checks Success`**, and require
_only_ those checks from `CI.yml` and `helm-checks.yml`. `ci-success` aggregates
the Rust jobs in `CI.yml`; `helm-success` aggregates the Helm jobs in
`helm-checks.yml`. `helm-checks.yml` runs on every pull request but skips its
expensive jobs when a PR touches none of its inputs (the chart under
`deploy/helm/**`, the observability configs under `deploy/observability/**`, the
render action, `.kube-linter.yaml` / `.trivyignore.yaml`, or the scripts in
`scripts/`), so `helm-success` always reports a status and never strands a
pure-Rust merge.

As of this writing **`CI Success`** and **`Conventional Commits`** are already
required; only **`Helm Checks Success`** is new:

1. Merge the PR that introduces `helm-checks.yml` and its `helm-success` aggregate.
2. Add **`Helm Checks Success`** to the required status checks on both rulesets.
3. If individual workflow job names are ever added to a ruleset, remove them only
   after **`Helm Checks Success`** (and **`CI Success`**) are required; doing it the
   other way leaves a window where a failing job blocks nothing.

`ci-success` fails if any job it needs reported `failure` or `cancelled`. It also
fails if any job reported `skipped`, with one allowed exception — `cargo-test-doc`,
which legitimately skips on a workspace with no library target. Without that check a
skipped job would pass, since `if: always()` reports it as neither failed nor
cancelled. A dedicated CI step asserts that every job in `CI.yml` appears in
`ci-success.needs`, so a new job cannot silently escape the gate either.

**The zizmor gate can be reddened by things outside this repository.** It runs with
`online-audits: true`, so it queries the GitHub Advisory database and the
repositories of every action pinned here. That is deliberate — those audits are what
catch a supply-chain attack on a pinned action — but it means a newly published
advisory, or an outage of the advisory API, can block every merge with no change to
this repository. A transient API error is retried once. If a real advisory is
blocking and the fix cannot land immediately, recovery is a scoped
`# zizmor: ignore[rule]` on the anchored line, removed once the action is bumped.

### Dependabot auto-merge

`auto_merge.yml` arms auto-merge for patch and minor updates, and never for
`github-actions` updates. It does not approve anything: review stays human, and the
merge fires on its own once the approvals land and the checks are green.

Dependabot applies a **7-day release cooldown** to version updates in every ecosystem
(`cooldown: default-days: 7` in `.github/dependabot.yml`), so a just-published version
is not proposed straight away — this is expected, not a broken schedule. Security
updates are exempt from cooldown. Because the cooldown decides when a bump is opened
at all, it also decides when the auto-merge path above ever sees a new version.

**This needs the repository setting _Allow auto-merge_ to be on** — Settings →
General → Pull Requests. It is currently off by choice, so nothing is ever armed:
the job warns and passes rather than failing, because a job that is red on every
dependency bump only teaches people to ignore red. Any _other_ failure to arm still
fails the job. Turning the setting on does not weaken anything: the `Rules` ruleset
still requires two approving reviews with `require_last_push_approval` before an
armed pull request can merge.

The workflow previously ran `gh pr review --approve` as well. That never worked —
every run since it was added failed with `GitHub Actions is not permitted to approve
pull requests (addPullRequestReview)`, which is the _Allow GitHub Actions to create
and approve pull requests_ setting rather than the workflow's `permissions:` block.
Because approve failed, the auto-merge step behind it was skipped every time. The
step was removed rather than unblocked: a bot approval could not satisfy a two-review
requirement anyway, and having CI approve its own dependency bumps is the thing the
review requirement exists to prevent.

## How Releases Work

This project uses [release-plz](https://release-plz.dev/) to fully automate versioning and releases. Here is how the process works:

### 1. Develop on feature branches

Work on feature branches and open PRs against `main`. Use Conventional Commit messages, these determine the next version number and generate changelog entries.

### 2. Merge to `main`

When a PR is merged to `main`, release-plz automatically:

- Analyzes all commits since the last release tag
- Computes the correct semver bump (patch / minor / major) from commit types
- Opens (or updates) a single **Release PR** containing:
  - The `Cargo.toml` version bump
  - A generated `CHANGELOG.md` entry with all changes since the last release

### 3. Review the Release PR

The Release PR is a review checkpoint. Check that:

- The computed version bump is correct (e.g., a breaking change should bump major, not patch)
- The changelog entry is accurate and well-formatted
- CI passes on the Release PR

### 4. Merge the Release PR

When the Release PR is merged, release-plz automatically:

- Creates a git tag (e.g., `v1.2.0`)
- Publishes a GitHub Release with the changelog as the release body
- The `v*.*.*` tag push triggers `deploy.yml`, which builds and pushes a Docker image
  tagged with the semver version (e.g., `ghcr.io/adorsys/status-list-server:1.2.0`)

**Tag format.** `deploy.yml`'s `validate-tag` job rejects any tag that matches the
`v*.*.*` push filter without being semver, because `docker/metadata-action` would
silently drop every version tag and the release would fall through to the mutable
`latest`. This matters when hand-pushing a tag rather than letting release-plz cut
one:

- Accepted: `v1.2.3`, `v1.2.3-rc.1`
- Rejected: `v2024.01.release`, `v1.2.3.4`, `v01.2.3`, `1.2.3`
- Rejected: `v1.2.3+meta` — build metadata is valid semver, but `+` is not a legal
  character in a Docker image tag

The rule is [`scripts/validate-release-tag.sh`](scripts/validate-release-tag.sh),
covered by
[`scripts/tests/test_validate_release_tag.py`](scripts/tests/test_validate_release_tag.py).

> **Note:** The EKS deployment step in `deploy.yml` currently deploys using the
> short-SHA image tag (`sha-<short_sha>`), not the semver tag. Switching the
> Kubernetes rollout to use the semver image tag is tracked in
> [#248](https://github.com/adorsys/status-list-server/issues/248).

### Diagram

```text
Developer commits with Conventional Commit message
    │
    ▼
Merge to main (after CI passes)
    │
    ▼
release-plz opens/updates Release PR
 ├─ Cargo.toml: version bump
 ├─ CHANGELOG.md: new entry with all commits since last release
 └─ CI runs on the Release PR
    │
    ▼
Maintainer reviews and merges Release PR
    │
    ▼
Automatic on merge:
 ├─ Git tag created (e.g. v1.2.0)
 ├─ GitHub Release published with changelog
 ├─ Docker image built and pushed: ghcr.io/adorsys/status-list-server:1.2.0  ← built ✓
 └─ EKS deployment: still uses sha-<short_sha> tag (semver deploy: see #248)
```

## Development Setup

See the [README](README.md) and [Local Deployment Guide](docs/LOCAL_DEPLOYMENT.md) for instructions on building and running the project locally.

Use the repository's Cargo xtask commands for repeatable development workflows:

```bash
cargo xtask check-profiles
cargo xtask build --profile postgres
cargo xtask build --profile sqlite --release
cargo xtask test --profile postgres
cargo xtask test --profile sqlite -- my_test --exact
cargo xtask lint
cargo xtask compose --profile postgres
cargo xtask ci
```

`build`, `test`, and `compose` default to the `postgres` profile. They also
support `minimal`, `mysql`, `sqlite`, `aws`, `vault`, `gcp`, `azure` and `redis`; see the [README feature profile matrix](README.md#development-and-quality-checks)
for their exact Cargo features and Compose services. The `ci` command runs the complete `local-ci.sh --full` pipeline.

Before using `lint`, install the versions used by the local CI pipeline:

```bash
rustup component add rustfmt clippy
cargo install --locked cargo-audit --version 0.22.2
cargo install --locked cargo-machete --version 0.9.2
```

Unlike `ci`, `lint` does not bootstrap missing tools. It runs every step and reports all failures.

Rust files use LF line endings. Existing Windows checkouts may retain CRLF in files untouched by a pull. After saving your work, run `cargo fmt --all` once to rewrite those files with the required line endings, then run `cargo fmt --all --check`. `git add --renormalize .` updates the index alone and does not rewrite the working-tree files.

`check-profiles` checks isolated libraries without default features as well as
all supported targets. `test` enables `postgres-tests` for PostgreSQL-backed
profiles and `redis-tests` for Redis; these profiles and MySQL need a running
Docker daemon. Use `cargo xtask test --profile minimal` for tests without
database containers.

`test` prefers installed nextest and runs doctests separately. Without nextest, it falls back to `cargo test`, without nextest's test groups and timeouts.
Install the CI version with `cargo install --locked cargo-nextest --version 0.9.101`. Test filters and
options after `--` must be supported by both the selected runner and doctests;
see the [README](README.md#development-and-quality-checks).

### Redis cache integration tests

Run the Redis cache integration tests with Docker/testcontainers, or point them at
an existing Redis endpoint:

```bash
TEST_REDIS_URL=redis://localhost:6379/0 cargo test --no-default-features --features memory,redis-tests outbound::cache
```

### Observability / Alertmanager test suite

The webhook-delivery integration test at
`deploy/observability/alertmanager/tests/test-alertmanager-config.sh` requires Docker.
Its delivery step (`[2/2]`) uses Docker `--network host` so the containerized
Alertmanager can reach the mock Python receivers on `127.0.0.1`. Host networking
is only supported on **Linux** (standard for Linux dev machines and CI runners).
On macOS or Windows (Docker Desktop / Lima), the delivery step cannot run as-is;
run the suite inside a Linux container or on a Linux CI pipeline instead. The
config-generation step (`[1/2]`) is portable across platforms.
