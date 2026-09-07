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

They must also require **`CI Success`**, and require _only_ that check from
`CI.yml`. The jobs in `CI.yml` form several independent chains — the Rust jobs hang
off `cargo-build`, the linters and scanners stand alone — deliberately, so that a
network-dependent scanner is not the root of every Rust job. No single job therefore
represents the suite; `ci-success` is what aggregates them, and it is the only thing
that can represent the whole suite to branch protection.

As of this writing the `Rules` ruleset on `develop` requires exactly one status
check — `Conventional Commits` — and the `main branch guards` ruleset requires none.
Nothing in `CI.yml` blocks a merge today, so adding `CI Success` closes a real gap
rather than reshuffling an existing list:

1. Merge the PR that introduces `ci-success`.
2. Add **`CI Success`** to the required status checks on both rulesets.
3. If individual `CI.yml` job names are ever added to a ruleset, remove them only
   _after_ `CI Success` is required — doing it in the other order leaves a window
   where a failing job blocks nothing.

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
