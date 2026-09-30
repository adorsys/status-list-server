# Local CI

Run from a checkout with `./local-ci.sh` for the daily Rust and wiring gates, or
`./local-ci.sh --full` for all practical gates from the three workflows below.
Both modes stop at the first failure and return a nonzero status. Full mode can
build the application several times, download container images, and run real
container-backed tests; allow substantial time and disk space on the first run.

## Development environment

The parity environment is Ubuntu 24.04 x86_64 with a working Docker daemon and
Compose v2, Rust stable installed through rustup, Node.js 22 or newer with npm,
Go, CMake, a C/C++ build toolchain, Python 3 with venv support, jq, curl, tar,
Git, and sha256sum. These are host prerequisites; the runner never invokes sudo.
For example, on an Ubuntu 24.04 development VM, install build prerequisites with:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev cmake golang-go \
  python3 python3-venv jq curl ca-certificates git
```

Install Rust using rustup, Node.js 22 or newer, and Docker Engine with Compose v2
using their supported installation instructions. Confirm `docker info` and
`docker compose version` work for your user. All-feature tests require Docker in
default mode too. Full mode requires Linux because the Alertmanager tests use
host networking. KubeLinter's automatic archive installation supports x86_64;
on other Linux architectures install the matching KubeLinter version manually.

For online Zizmor audits, authenticate with `gh auth login`, or export `GH_TOKEN`,
`GITHUB_TOKEN`, or `ZIZMOR_GITHUB_TOKEN` with read access to the repositories
referenced by the workflows. The runner passes the token through the container
environment without printing its value. Missing authentication fails with setup
guidance; it never silently disables online audits.

Missing or mismatched tools are installed under `target/local-ci-tools`, without
replacing global executables. PyYAML uses a local virtual environment when it is
not already importable. Override the tools directory with `LOCAL_CI_TOOLS_ROOT`, keeping it under
`target/` or outside the checkout to avoid scanning third-party tool files.
`--no-bootstrap` requires matching tools and prints installation guidance when
one is missing or has the wrong version. Security scanner containers may still
be pulled by Docker with that option.

## Command inventory

The source workflows are `.github/workflows/CI.yml`,
`.github/workflows/cargo_deny.yml`, and `.github/workflows/crate_type.yml`.
The runner uses repository configurations unless an explicit flag is shown.

| Gate                                | Mode    | Commands or shared implementation                                                                                                                                                      |
| ----------------------------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Rust format                         | Default | `cargo fmt --all --check`                                                                                                                                                              |
| Build                               | Default | `cargo build --workspace --all-targets --all-features`                                                                                                                                 |
| Memory-only build                   | Default | `cargo check --no-default-features --features memory`                                                                                                                                  |
| Release image features              | Default | Read `ARG FEATURES` from Dockerfile; `cargo check --workspace --features "$features"`                                                                                                  |
| Domain purity                       | Default | Grep `src/domain/` for the same infrastructure imports as CI                                                                                                                           |
| Clippy                              | Default | `cargo clippy --workspace --all-targets --all-features -- -D warnings`                                                                                                                 |
| Tests                               | Default | `cargo nextest run --workspace --all-targets --all-features`                                                                                                                           |
| Documentation                       | Default | `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --document-private-items`                                                                                   |
| Crate type                          | Default | `cargo metadata --format-version=1 --no-deps` and the workflow's jq target-kind predicates                                                                                             |
| Doc tests                           | Default | `cargo test --doc --workspace --all-features`, only for library targets                                                                                                                |
| Unused dependencies                 | Default | `cargo machete --with-metadata`                                                                                                                                                        |
| Trivy ignore and variant validation | Default | Python unittest discovery, `scripts/check-trivyignore.py`, `scripts/check-variant-parity.py`                                                                                           |
| Attestation verifier                | Default | `bash scripts/attestation-selftest.sh`                                                                                                                                                 |
| Workflow security                   | Full    | Pinned Zizmor container, regular persona, authenticated online audits and one retry; known-bad fixture and `ci-success.needs` validation                                               |
| Release variants                    | Full    | `cargo check --workspace --features` for `postgres,aws,redis`, `postgres,gcp,redis`, `postgres,azure,redis`, `postgres,vault,redis`, and `postgres,redis`                              |
| Docker smoke build                  | Full    | `docker build .`                                                                                                                                                                       |
| Supply chain                        | Full    | `cargo vet --locked`, `cargo deny --all-features check`, `cargo audit`                                                                                                                 |
| Text and config lint                | Full    | `typos`, `tombi lint`, `markdownlint-cli2 "**/*.md"`, `yamlfmt --lint .`                                                                                                               |
| Helm rendering                      | Full    | Helm repository/dependency setup, the run block from `.github/workflows/render-helm-templates/action.yml`, `scripts/verify-image-reference.sh`, and local-values assertions            |
| Trivy                               | Full    | `trivy config --severity HIGH,CRITICAL --exit-code 1 --ignorefile .trivyignore.yaml /tmp/rendered`                                                                                     |
| KubeLinter                          | Full    | `kube-linter --config .kube-linter.yaml lint /tmp/rendered --format sarif`                                                                                                             |
| OpenTelemetry                       | Full    | Compose model validation, Jaeger manifest lookup, Collector `validate` for Compose and extracted Helm configs                                                                          |
| Prometheus and dashboards           | Full    | Pinned promtool rule/config checks and rule tests, Helm rule-name drift check, SLO threshold lint, Alertmanager config/delivery tests, dashboard JSON validation and regeneration diff |
| Coverage                            | Full    | `cargo llvm-cov nextest --workspace --all-features --html --output-dir target/llvm-cov/html`                                                                                           |

Full mode includes every default gate. Lint exclusions are shared with GitHub CI:
build output, virtual environments, and node_modules are not source inputs.
This matters because Rust tests generate Helm template copies under `target/`.
TOML lint also excludes Git metadata, which can contain reflogs with `.toml`
filenames. YAML uses the repository Git-ignore rules in addition to its explicit
Helm template exclusions.

Version constants in `local-ci.sh` must be updated alongside the workflows.
Some versions come from pinned action implementations rather than workflow
inputs: cargo-deny-action v2.1.1 embeds cargo-deny 0.20.2;
markdownlint-cli2-action v24.1.0 embeds markdownlint-cli2 0.23.1;
setup-tombi v1.2.4 defaults to Tombi 1.2.4; trivy-action v0.36.0 defaults to
Trivy 0.70.0. Zizmor always uses the workflow's digest-pinned image. A matching
native Trivy is accepted; otherwise the runner uses its versioned container.

## Verification and limits

Verify both entry points in the development environment above:

```bash
./local-ci.sh
./local-ci.sh --full
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
```

To exercise fresh bootstrap, use a fresh checkout and an empty tools directory;
only already-installed tools with matching versions are reused. Capture the
host versions and both exit statuses when recording a parity run. The Python
regression tests additionally simulate absent/mismatched tools, bootstrap
failure, absent authentication, and scanner rejection without network access.
The YAML regression runs when yamlfmt is installed.

A green local run is not a guarantee against later advisory database updates or
network failures. Build dependencies, registries, and online audits require
network access. Container tests need adequate Docker resources. In particular,
MySQL `io_setup() failed with EAGAIN` indicates host native-AIO exhaustion;
inspect `/proc/sys/fs/aio-nr` and `/proc/sys/fs/aio-max-nr` and stop only containers
you own or have an administrator adjust the host limit. The runner does not
change host limits, remove unrelated containers, or skip failing tests.

GitHub-only behavior is intentionally excluded: checkout token permissions,
workflow scheduling/concurrency, Actions caches and annotations, SARIF/code
scanning uploads, artifact uploads, and `ci-success` aggregation of job statuses.
Local commands execute sequentially in one checkout and propagate failures
instead. Coverage HTML and KubeLinter SARIF are still produced locally. The
dashboard drift check regenerates its tracked JSON as in CI; review any diff.

### Verification record (2026-09-30)

Checked on Ubuntu 24.04.5 x86_64, Rust 1.96.1, Node.js 24.14.1, and the pinned
CLI versions above. This was an existing development host, not a clean VM.

- Real bootstrap installed the pinned nextest, machete, audit, deny, llvm-cov,
  Tombi, markdownlint, and KubeLinter tools. The complete tool preflight then
  passed with bootstrap disabled.
- All 75 Python tests passed, including nine local-runner regressions.
- Formatting, builds, domain purity, Clippy, documentation, doctests, machete,
  style/wiring checks, authenticated Zizmor and its fixture, Helm rendering,
  Trivy, KubeLinter, cargo vet, cargo audit, and cargo deny passed individually.
- Default mode exited 100 at nextest: 480 passed, four MySQL startup failures,
  and 57 tests not run. Full mode passed bootstrap and Zizmor, then exited 100
  at nextest: 452 passed, four MySQL and three Azure emulator startup failures,
  and 82 tests not run. MySQL reported native-AIO exhaustion on this host.
- Supplemental Prometheus checks passed rule/config validation, Helm rule
  tests, SLO threshold consistency, and standalone recording-rule tests. The
  standalone alert simulation was interrupted after the full-run blockers were
  confirmed; later Alertmanager/dashboard checks were not completed.
- Separate Compose validation encountered a syntax error in the developer's
  untracked `.env`. That private file was not modified.

A successful end-to-end full run remains required on a clean development
machine: these failures were preserved, not bypassed, and later gates such as
the Docker smoke build and coverage were not reached by either entry point.
