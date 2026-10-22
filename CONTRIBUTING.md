# Contributing to Status List Server

Bug fixes, features, tests, and documentation improvements are welcome.

## Reporting bugs and proposing changes

Search existing issues and discussions before opening a new report.

- **Bugs:** Use the bug-report form in the [issue chooser](https://github.com/adorsys/status-list-server/issues/new/choose). Describe the current and expected behavior. Add reproduction steps, environment details, and other context when available; these fields are optional.
- **Feature requests:** Start an [Ideas discussion](https://github.com/adorsys/status-list-server/discussions/new?category=ideas) to explain the problem and proposed change.
- **Documentation problems and other topics:** Open a [blank issue](https://github.com/adorsys/status-list-server/issues/new).

For larger changes, discuss the approach before investing in an implementation.

## Development setup

Fork the repository, clone your fork, and create a feature branch from
`develop`. Open pull requests against `develop` too.

The project uses Rust edition 2024 and the stable toolchain selected by
[`rust-toolchain.toml`](rust-toolchain.toml). No separate minimum supported Rust version is declared in `Cargo.toml`; use current stable, as CI does.

Install Rust through [rustup](https://rustup.rs), a C/C++ build toolchain, CMake, and Go. On Linux, install `pkg-config` and the OpenSSL development headers too. Then install the Rust components and Cargo tools used below:

```bash
rustup update stable
rustup component add rustfmt clippy
cargo install --locked cargo-nextest
cargo install --locked cargo-deny
cargo install --locked cargo-audit
cargo install --locked cargo-machete
```

Run all commands from the repository root. Start with the in-memory profile, which does not need a database, Docker, or cloud credentials:

```bash
cargo xtask build --profile minimal
cargo xtask test --profile minimal
```

To run the server locally with the checked-in development signing material:

```bash
APP_SERVER__CERT__STORE__CERTIFICATE_PATH=test_data/certs/dev.crt \
APP_SERVER__CERT__STORE__SIGNING_KEY_PATH=test_data/certs/dev.key \
cargo run
```

These files are public test fixtures for local development only.

See the [quick start](README.md#quick-start) for the local endpoints and [local deployment guide](docs/LOCAL_DEPLOYMENT.md) for configuration.

### Working on a backend or provider

Build and test the profile affected by your change. For example:

```bash
cargo xtask build --profile postgres
cargo xtask test --profile postgres
```

PostgreSQL, MySQL, and Redis integration tests need a running Docker daemon; SQLite tests do not need database containers. To run the application with local PostgreSQL services, install Docker Compose v2 and use `cargo xtask compose --profile postgres`.

The [feature profile matrix](README.md#development-and-quality-checks) lists all profiles and their features. The `build`, `test`, and `compose` commands default to `postgres`, so select `minimal` explicitly when you want the in-memory workflow.
Provider-specific setup is described in the [database](docs/database-backends.md), [secrets](docs/secrets-backends.md), and [DNS](docs/dns-providers.md) guides.

### SQL test containers

MySQL and Postgres tests start throwaway containers through `src/outbound/sql/test_containers.rs`.

- Each fixture owns its container and removes it on drop, including during a panic. Keep it in scope until every pool and task using it has finished.
- Hold one fixture per test. Plain `cargo test` allows four live SQL containers per process, so a test waiting on a second fixture can deadlock; open extra pools on the same fixture instead.
- Put `mysql` or `postgres` in new database test names so they join nextest's `containers` group.
- The cleanup regression tests also need the Docker CLI on `PATH`.

A killed run (SIGTERM, including nextest slow-timeouts, Ctrl-C, SIGKILL, an abort, or `TESTCONTAINERS_COMMAND=keep`) can leave containers behind. Every fixture container is labelled with its run ID. Under nextest that is `NEXTEST_RUN_ID`, printed when the run starts; to choose your own, or to group plain `cargo test` runs, export one first:

```bash
export STATUS_LIST_TEST_RUN_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
cargo nextest run --workspace --all-targets --all-features
```

After the run has stopped, set `STATUS_LIST_TEST_RUN_ID` to its ID and remove only its SQL containers and their anonymous volumes. These filters never match Redis fixtures or other projects' containers.

```bash
: "${STATUS_LIST_TEST_RUN_ID:?Set the interrupted run ID first}"
docker container ls -a --filter label=org.adorsys.status-list-server.fixture=sql \
  --filter "label=org.adorsys.status-list-server.run=$STATUS_LIST_TEST_RUN_ID"
for id in $(docker container ls -aq --filter label=org.adorsys.status-list-server.fixture=sql \
  --filter "label=org.adorsys.status-list-server.run=$STATUS_LIST_TEST_RUN_ID"); do
  docker container rm -fv "$id"
done
```

## Coding style and architecture

Use descriptive names and follow the surrounding code. Rust formatting is configured in [`rustfmt.toml`](rustfmt.toml), including LF line endings. Run `cargo fmt --all` before submitting Rust changes. Use rustdoc to explain public APIs and comments to explain decisions that are not clear from the code.

The server uses ports and adapters. See the [architecture guide](docs/architecture.md) for context. Add tests for new behavior, and include a regression test for a bug fix that fails without the fix. Keep unrelated refactoring in a separate change. Update affected configuration examples, API specifications, and documentation alongside the code.

For HTTP and load-testing changes, see [API testing](docs/api-testing.md) and the [performance-test workspace](perf/README.md).

### Code comments

Comments are the exception. Write one only when the code can't say it: a reason that isn't obvious, a gotcha, or a workaround.

- One short line that says why, not what the next line does.
- Plain words: no bold or capitals for emphasis, no em dashes.
- No ticket numbers, review notes or history; those belong in commits and PRs.
- No comments inside tests. Put a gotcha in the assert message or the helper's name.
- If the explanation is long, put it in the docs and point there.
- Leave functional comments alone: the version after a pinned action SHA, `zizmor: ignore[...]`, `# pragma: no cover`, the xtask doc comments (clap prints them as `--help`), and the `# KEY=value` lines in `.env.template`.

## Checking your changes

These commands match the workspace formatting, lint, and test jobs in CI:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-targets --all-features
cargo test --doc --workspace --all-features
```

All-feature tests enable container-backed tests and require Docker. Install Helm 4 to exercise the Helm-rendering tests as CI does. Nextest does not run doctests, which is why they have a separate command. The profile-specific `cargo xtask test` command runs both, using `cargo test` as a fallback when nextest is not installed.

For changes involving feature gates, also check the supported profile matrix:

```bash
RUSTFLAGS="-D warnings" cargo xtask check-profiles
```

For dependency changes, check advisories, licenses, and unused dependencies:

```bash
cargo deny --all-features check
cargo audit
cargo machete --with-metadata
```

The local CI runner can bootstrap its tools and run the checks together:

```bash
./local-ci.sh
./local-ci.sh --full
```

Both modes include all-feature tests and need Docker. Full mode adds configuration, container, supply-chain, and coverage checks. See [local CI](docs/local-ci.md) for host prerequisites, individual gates, authentication for public GitHub audits, and platform limits; a complete full-mode run requires Linux. `cargo xtask ci` runs the full mode.

For Markdown changes, run `npx --yes markdownlint-cli2 "**/*.md"` with Node.js and npm installed.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/) for every commit and the PR title. CI validates both. The format is
`<type>(<optional scope>): <description>`; keep commit subjects within 120 characters.

Supported types are `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `ci`, `chore`, `build`, `revert`, and `style`. For example:

```text
fix(db): preserve issuer ownership when updating a list
docs: clarify local setup
feat(api)!: change the status update response
```

For a breaking change, add `!` after the type or scope, or a `BREAKING CHANGE:` footer. Explain the compatibility impact and any migration steps.

## Pull requests

Keep each PR focused on one problem and each commit a coherent change. In the description, explain the problem, the resulting behavior, and any compatibility or configuration changes. Link the related issue if there is one.

List the checks you ran with their commands, feature selections, and results. State what you could not check, including provider tests that need credentials or infrastructure you do not have. Local checks and remote CI provide different evidence; link CI results when available. Address review feedback and update tests and documentation as the implementation changes.
