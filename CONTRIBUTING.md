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

They must also require **`CI Success`**, and require *only* that check from
`CI.yml`. The jobs in `CI.yml` deliberately do not depend on one another, so that a
network-dependent scanner is not the root of every Rust job. The consequence is that
a failing job no longer cascades: `ci-success` is what aggregates them, and it is the
only thing that can represent the whole suite to branch protection.

The order matters when changing this. Requiring individual job names *before*
`ci-success` exists, or removing them *before* `CI Success` is required, both leave a
window where a failing job blocks nothing:

1. Merge the PR that introduces `ci-success`.
2. Add **`CI Success`** to the required status checks.
3. Only then remove the individual `CI.yml` job names from the required list.

`ci-success` fails if any job it needs reported `failure` or `cancelled`. A `skipped`
job passes, because `cargo-test-doc` legitimately skips on a workspace with no library
target. A dedicated CI step asserts that every job in `CI.yml` appears in
`ci-success.needs`, so a new job cannot silently escape the gate.

### Dependabot auto-merge

`auto_merge.yml` approves and enables auto-merge only for patch and minor updates, and
never for `github-actions` updates. It depends on **"Dismiss stale pull request
approvals when new commits are pushed"** being enabled on the protected branch. Without
it, auto-merge armed when the pull request opened stays armed, and a later push merges
as soon as checks pass — no condition in the workflow can prevent that.

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
