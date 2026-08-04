# Contributing to this project

Thank you for your interest in contributing! This document covers how to submit changes.

## Commit Messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/) to automate versioning and changelog generation. Every commit message merged to `main` **must** follow this format:

```text
<type>(<optional scope>): <description>

[optional body]

[optional footer(s)]
```

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

## Pull Requests

1. Fork the repository and create a feature branch from `main`.
2. Make your changes, ensuring all commits follow Conventional Commits format.
3. Open a PR against `main`. CI will run automatically.
4. Address review feedback.
5. A maintainer will merge using **squash merge** (the squash commit message should also follow Conventional Commits format).

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
- The `v*.*.*` tag push triggers the existing deploy workflow, which builds and tags a Docker image with the semver version

### Diagram

```text
Developer commits with Conventional Commit message
    │
    ▼
Merge to main (after CI passes)
    │
    ▼
release-plz opens/updates Release PR
 ├─ Cargo.toml version: 1.0.1 → 1.1.0
 ├─ CHANGELOG.md: new entry with all commits since last release
 └─ CI runs on the Release PR
    │
    ▼
Maintainer reviews and merges Release PR
    │
    ▼
Automatic on merge:
 ├─ Git tag created: v1.1.0
 ├─ GitHub Release published with changelog
 └─ Docker image built and tagged: ghcr.io/adorsys/status-list-server:1.1.0
```

## Development Setup

See the [README](README.md) and [Local Deployment Guide](docs/LOCAL_DEPLOYMENT.md) for instructions on building and running the project locally.
