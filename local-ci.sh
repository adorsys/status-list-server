#!/usr/bin/env bash

# Local CI runner.
#
# Command inventory mirrored from:
# - .github/workflows/CI.yml
# - .github/workflows/cargo_deny.yml
# - .github/workflows/crate_type.yml
#
# Default mode keeps the day-to-day loop approachable: Rust format/build/lint/test
# gates plus fast local wiring checks. Use --full for the practical local equivalent
# of the required GitHub CI jobs. GitHub-only behavior that is not replicated locally:
# checkout permissions, workflow concurrency/caching, Actions annotations, SARIF and
# artifact uploads, and ci-success' JSON aggregation of already-finished jobs.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
CHART_DIR="${CHART_DIR:-deploy/helm/chart}"
TOOLS_ROOT="${LOCAL_CI_TOOLS_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/status-list-server/local-ci}"
TOOLS_BIN="$TOOLS_ROOT/bin"
RUNNER_TEMP="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
GATE=""
BOOTSTRAP=1
MODE="default"

NEXT_VERSION="0.9.101"
MACHETE_VERSION="0.9.2"
VET_VERSION="0.10.2"
AUDIT_VERSION="0.22.2"
LLVM_COV_VERSION="0.6.16"
# Defaults embedded in the pinned GitHub actions (see docs/local-ci.md).
DENY_VERSION="0.20.2"
TOMBI_VERSION="1.2.4"
MARKDOWNLINT_VERSION="0.23.1"
TRIVY_VERSION="0.70.0"
TRIVY_IMAGE="aquasec/trivy:0.70.0@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e"
TYPOS_VERSION="1.49.0"
YAMLFMT_VERSION="v0.21.0"
HELM_VERSION="v4.2.4"
KUBE_LINTER_VERSION="v0.8.3"
KUBE_LINTER_SHA256="1a6d8419b11971372971fdbc22682b684ebfb7cf1c39591662d1b6ca736c41df"
ZIZMOR_IMAGE="ghcr.io/zizmorcore/zizmor:1.28.0@sha256:8e6b3e4fb74d1aa5d23e83ea369f386c66eced0d1fb944d32cd8b2aac100b00d"
OTEL_COLLECTOR_IMAGE="otel/opentelemetry-collector-contrib:0.158.0"
PROMETHEUS_IMAGE="prom/prometheus:v3.11.3"
JAEGER_IMAGE="jaegertracing/jaeger:2.20.0"

BASE_PATH="$PATH"
export CHART_DIR RUNNER_TEMP

usage() {
    cat <<'EOF'
Usage: ./local-ci.sh [--full] [--no-bootstrap] [--gate NAME] [--help]

Modes:
  default       Fast day-to-day gates: fmt, build, memory/release feature checks,
                domain purity, clippy, nextest, docs, doctests, machete, and
                fast local workflow/script wiring checks.
  --full        Practical local parity with GitHub CI: default gates plus zizmor,
                release feature matrix, Docker smoke build, cargo vet/deny/audit,
                typos, tombi, markdownlint, Helm/Trivy/KubeLinter, yamlfmt,
                OpenTelemetry/Prometheus validation, and cargo llvm-cov.

Options:
  --no-bootstrap  Require matching installed CLIs; print install guidance otherwise.
  --gate NAME     Run only: rust, wiring, style, zizmor, variants, docker,
                  supply-chain, helm, otel, prometheus, coverage.
  --help          Show this help.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --full) MODE="full" ;;
        --gate)
            [ "$#" -ge 2 ] || { echo "--gate requires a name" >&2; exit 2; }
            shift; GATE="$1"
            case "$GATE" in rust|wiring|style|zizmor|variants|docker|supply-chain|helm|otel|prometheus|coverage) ;;
                *) echo "unknown gate: $GATE" >&2; exit 2 ;; esac ;;
        --no-bootstrap) BOOTSTRAP=0 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

mkdir -p "$TOOLS_BIN" "$RUNNER_TEMP"
TOOLS_ROOT="$(cd "$TOOLS_ROOT" && pwd)"
TOOLS_BIN="$TOOLS_ROOT/bin"
export PATH="$TOOLS_BIN:$TOOLS_ROOT/node/node_modules/.bin:$BASE_PATH"
RUNNER_TEMP="$(cd "$RUNNER_TEMP" && pwd)"
RUNNER_TEMP=$(mktemp -d "$RUNNER_TEMP/local-ci.XXXXXX")
trap 'rm -rf "$RUNNER_TEMP"' EXIT
export RENDER_TEMP="$RUNNER_TEMP"
export HELM_CONFIG_HOME="$TOOLS_ROOT/helm/config"
export HELM_CACHE_HOME="$TOOLS_ROOT/helm/cache"
export HELM_DATA_HOME="$TOOLS_ROOT/helm/data"
export RUSTFLAGS="${RUSTFLAGS--D warnings}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target/local-ci}"
# Capture caller-provided credentials without exposing them to later build tools.
LOCAL_ZIZMOR_TOKEN="${ZIZMOR_GITHUB_TOKEN:-${GH_TOKEN:-${GITHUB_TOKEN:-}}}"
unset ZIZMOR_GITHUB_TOKEN GH_TOKEN GITHUB_TOKEN

log() { printf '\n==> %s\n' "$*"; }
run() { printf '+ %s\n' "$*"; "$@"; }
have() { command -v "$1" >/dev/null 2>&1; }

fail_missing() {
    local tool="$1" hint="$2"
    cat >&2 <<EOF
ERROR: missing required tool: $tool

$hint
Re-run ./local-ci.sh after correcting the problem above.
Bootstrap mode: $BOOTSTRAP (1=enabled, 0=disabled).
EOF
    exit 127
}

version_matches() {
    local bin="$1" expected="${2#v}" output
    shift 2
    have "$bin" || return 1
    if [ "$bin" = cargo-llvm-cov ]; then
        set -- llvm-cov "$@"
    fi
    output=$("$bin" "$@" 2>/dev/null) || return 1
    # Compare a complete version token, not a prefix (1.2 must not match 1.20).
    printf '%s\n' "$output" | awk -v expected="$expected" '
        NR == 1 { for (i = 1; i <= NF; i++) {
            sub(/^v/, "", $i)
            if ($i == expected) found = 1
        }}
        END { exit !found }'
}

install_cargo_bin() {
    local bin="$1" crate="$2" version="$3"
    version_matches "$bin" "$version" --version && return
    if [ "$BOOTSTRAP" -ne 1 ]; then
        fail_missing "$bin $version (missing or wrong version)" "Install with: cargo install --locked --root '$TOOLS_ROOT' $crate --version $version --force"
    fi
    log "Installing $bin $version into $TOOLS_ROOT"
    run cargo install --locked --root "$TOOLS_ROOT" "$crate" --version "$version" --force
    hash -r
    version_matches "$bin" "$version" --version || fail_missing "$bin $version" "Bootstrap did not produce the expected executable in $TOOLS_BIN."
}

install_go_bin() {
    local bin="$1" package="$2" version="${3:-}"
    if [ -n "$version" ]; then
        version_matches "$bin" "$version" -version && return
    fi
    if [ "$BOOTSTRAP" -ne 1 ]; then
        fail_missing "$bin (missing or wrong version)" "Install with: GOBIN='$TOOLS_BIN' go install $package"
    fi
    require_tool go "Install Go to bootstrap $bin, or install $bin $version manually."
    log "Installing $bin with go"
    run env GOBIN="$TOOLS_BIN" go install "$package"
    hash -r
    version_matches "$bin" "$version" -version || fail_missing "$bin $version" "Check the installation in $TOOLS_BIN."
}

install_node_bin() {
    local bin="$1" version="$2"
    version_matches "$bin" "$version" --version && return
    if [ "$BOOTSTRAP" -ne 1 ]; then
        fail_missing "$bin $version (missing or wrong version)" "Install with: cp scripts/local-ci/node/package*.json '$TOOLS_ROOT/node/'; npm ci --prefix '$TOOLS_ROOT/node'"
    fi
    log "Installing $bin $version with npm"
    mkdir -p "$TOOLS_ROOT/node"
    cp scripts/local-ci/node/package*.json "$TOOLS_ROOT/node/"
    run npm ci --prefix "$TOOLS_ROOT/node" --no-audit --no-fund
    hash -r
    version_matches "$bin" "$version" --version || fail_missing "$bin $version" "Check Node.js compatibility and npm's installation output."
}

bootstrap_python() {
    require_tool python3 "Install Python 3 with venv support."
    local imports="import yaml" base_python
    [ "${1:-}" != full ] || imports="import yaml, jsonschema"
    base_python=$(PATH="$BASE_PATH" command -v python3)
    if "$base_python" -c "$imports" 2>/dev/null; then
        return
    fi
    if "$TOOLS_ROOT/python/bin/python3" -c "$imports" 2>/dev/null; then
        export PATH="$TOOLS_ROOT/python/bin:$PATH"
        return
    fi
    [ "$BOOTSTRAP" -eq 1 ] || fail_missing "Python validation modules" "Install scripts/local-ci/requirements.txt in a venv, or omit --no-bootstrap."
    # Never recreate a broken venv using its own interpreter.
    rm -rf "$TOOLS_ROOT/python"
    "$base_python" -m venv "$TOOLS_ROOT/python" || fail_missing python3-venv "Install Python venv support."
    if ! "$TOOLS_ROOT/python/bin/python3" -m pip install --require-hashes -r scripts/local-ci/requirements.txt; then
        rm -rf "$TOOLS_ROOT/python"
        fail_missing "Python validation modules" "Pinned dependency installation failed; check network access and retry."
    fi
    export PATH="$TOOLS_ROOT/python/bin:$PATH"
    hash -r
}

install_helm() {
    if have helm; then
        local current
        current=$(helm version --template '{{.Version}}' 2>/dev/null || true)
        if [ "$current" = "$HELM_VERSION" ]; then
            return
        fi
        echo "helm $current found, but CI uses $HELM_VERSION"
    fi
    if [ "$BOOTSTRAP" -ne 1 ]; then
        fail_missing "helm" "Install Helm $HELM_VERSION from https://helm.sh/docs/intro/install/; the installed helm must match CI."
    fi
    have curl || fail_missing "helm" "Install curl, then re-run this script."
    have tar || fail_missing "helm" "Install tar, then re-run this script."
    local os arch archive url dir
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) fail_missing "helm" "Unsupported architecture for automatic Helm install: $(uname -m)" ;;
    esac
    archive="$RUNNER_TEMP/helm-${HELM_VERSION}-${os}-${arch}.tar.gz"
    url="https://get.helm.sh/helm-${HELM_VERSION}-${os}-${arch}.tar.gz"
    dir="$RUNNER_TEMP/helm-${HELM_VERSION}-${os}-${arch}"
    log "Installing helm $HELM_VERSION"
    run curl --silent --show-error --fail --location --retry 5 --retry-delay 5 --output "$archive" "$url"
    python3 - "$archive" scripts/local-ci/helm-checksums.json <<'PY2'
import hashlib, json, pathlib, sys
archive, checksum = map(pathlib.Path, sys.argv[1:])
expected = json.loads(checksum.read_text())[archive.name]
if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
    raise SystemExit('Helm archive checksum mismatch')
PY2
    rm -rf "$dir"
    mkdir -p "$dir"
    run tar -xzf "$archive" -C "$dir"
    cp "$dir/$os-$arch/helm" "$TOOLS_BIN/helm"
    chmod +x "$TOOLS_BIN/helm"
    hash -r
}

install_kube_linter() {
    version_matches kube-linter "$KUBE_LINTER_VERSION" version && return
    if [ "$(uname -s)/$(uname -m)" != "Linux/x86_64" ]; then
        fail_missing "kube-linter $KUBE_LINTER_VERSION" "Automatic installation supports Linux x86_64. Install the matching release for your platform manually; full parity requires Linux (see docs/local-ci.md)."
    fi
    if [ "$BOOTSTRAP" -ne 1 ]; then
        fail_missing "kube-linter" "Install kube-linter $KUBE_LINTER_VERSION or re-run without --no-bootstrap."
    fi
    have curl || fail_missing "kube-linter" "Install curl, then re-run this script."
    have sha256sum || fail_missing "kube-linter" "Install sha256sum/coreutils, then re-run this script."
    have tar || fail_missing "kube-linter" "Install tar, then re-run this script."
    local dir archive
    dir="$RUNNER_TEMP/kube-linter"
    archive="$dir/kube-linter-linux.tar.gz"
    mkdir -p "$dir"
    log "Installing kube-linter $KUBE_LINTER_VERSION"
    run curl --silent --show-error --fail --location --retry 5 --retry-delay 5 --retry-connrefused --output "$archive" "https://github.com/stackrox/kube-linter/releases/download/${KUBE_LINTER_VERSION}/kube-linter-linux.tar.gz"
    echo "${KUBE_LINTER_SHA256}  ${archive}" | sha256sum --check --strict
    run tar -xzf "$archive" -C "$dir" kube-linter
    cp "$dir/kube-linter" "$TOOLS_BIN/kube-linter"
    chmod +x "$TOOLS_BIN/kube-linter"
    hash -r
    version_matches kube-linter "$KUBE_LINTER_VERSION" version || fail_missing "kube-linter $KUBE_LINTER_VERSION" "Check the executable installed in $TOOLS_BIN."
}

require_tool() {
    local tool="$1" hint="$2"
    have "$tool" || fail_missing "$tool" "$hint"
}

rust_components() {
    local component installed_name
    for component in "$@"; do
        installed_name="$component"
        if [ "$component" = "llvm-tools-preview" ]; then
            installed_name="llvm-tools"
        fi
        if ! rustup component list --installed | grep -Eq "^${installed_name}($|-.)"; then
            if [ "$BOOTSTRAP" -ne 1 ]; then
                fail_missing "rustup component $component" "Install with: rustup component add $component"
            fi
            log "Installing Rust component $component"
            run rustup component add "$component"
        fi
    done
}

bootstrap_default_tools() {
    require_tool cargo "Install Rust/Cargo first: https://rustup.rs"
    require_tool rustup "Install rustup first: https://rustup.rs"
    have cmake || echo "WARNING: CMake may be needed by native Rust dependencies; install it if the build requests it." >&2
    have go || echo "WARNING: Go may be needed by native dependencies or yamlfmt bootstrap." >&2
    require_tool jq "Install jq (Ubuntu: sudo apt-get install jq)."
    require_tool docker "Install Docker and start its daemon; the all-feature tests start containers."
    docker info >/dev/null 2>&1 || fail_missing "Docker daemon" "Start Docker and ensure your user can access it (docker info)."
    bootstrap_python
    rust_components rustfmt clippy
    install_cargo_bin cargo-nextest cargo-nextest "$NEXT_VERSION"
    install_cargo_bin cargo-machete cargo-machete "$MACHETE_VERSION"
    install_helm
}

bootstrap_node() {
    require_tool node "Install Node.js 22 or newer and npm."
    require_tool npm "Install npm alongside Node.js 22 or newer."
    node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)' || fail_missing "Node.js >=22" "Activate Node.js 22 or newer."
}

bootstrap_gate() {
    case "$1" in
        rust) bootstrap_default_tools; rust_version_check ;;
        wiring) bootstrap_python ;;
        style)
            bootstrap_node
            install_cargo_bin typos typos-cli "$TYPOS_VERSION"
            install_node_bin tombi "$TOMBI_VERSION"
            install_node_bin markdownlint-cli2 "$MARKDOWNLINT_VERSION"
            install_go_bin yamlfmt "github.com/google/yamlfmt/cmd/yamlfmt@$YAMLFMT_VERSION" "$YAMLFMT_VERSION"
            ;;
        zizmor) bootstrap_python; require_tool docker "Install Docker for Zizmor." ;;
        variants) bootstrap_python; require_tool cargo "Install Rust/Cargo."; rust_version_check ;;
        docker) require_tool docker "Install Docker." ;;
        supply-chain)
            install_cargo_bin cargo-vet cargo-vet "$VET_VERSION"
            install_cargo_bin cargo-audit cargo-audit "$AUDIT_VERSION"
            install_cargo_bin cargo-deny cargo-deny "$DENY_VERSION"
            ;;
        helm|otel|prometheus)
            bootstrap_python full
            install_helm
            require_tool docker "Install Docker."
            helm_deps
            if [ "$1" = helm ]; then install_kube_linter; fi
            if [ "$1" = prometheus ]; then bootstrap_node; fi
            ;;
        coverage)
            bootstrap_default_tools
            rust_components llvm-tools-preview
            install_cargo_bin cargo-llvm-cov cargo-llvm-cov "$LLVM_COV_VERSION"
            ;;
    esac
}

helm_deps() {
    [ ! -f "$RUNNER_TEMP/helm-deps-ready" ] || return 0
    run helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
    run helm dependency build "$CHART_DIR"
    touch "$RUNNER_TEMP/helm-deps-ready"
}

run_render_helm_templates_action() {
    log "Render Helm templates using .github/workflows/render-helm-templates/action.yml"
    # A fresh per-run directory prevents stale render outputs and worktree clashes.
    run python3 scripts/local-ci/run-action.py .github/workflows/render-helm-templates/action.yml
}

crate_kind_detection() {
    log "Detect crate target kinds"
    local kinds is_lib is_bin
    kinds=$(cargo metadata --format-version=1 --no-deps | jq -c '[.packages[].targets[].kind[]] | unique')
    echo "kinds of targets: ${kinds}"
    is_lib=$(printf '%s' "$kinds" | jq -r '["lib","rlib","dylib","cdylib","staticlib","proc-macro"] as $lib | any(IN($lib[])) | tostring')
    is_bin=$(printf '%s' "$kinds" | jq -r 'any(. == "bin") | tostring')
    if [ -z "$is_lib" ] || [ -z "$is_bin" ]; then
        echo "ERROR: target-kind detection produced no value (is_lib='${is_lib}' is_bin='${is_bin}')." >&2
        exit 1
    fi
    printf 'is_lib=%s is_bin=%s\n' "$is_lib" "$is_bin"
    CRATE_IS_LIB="$is_lib"
}

release_image_features_check() {
    log "Release image feature set"
    local features
    features=$(sed -nE 's/^ARG FEATURES="([^"]+)".*/\1/p' Dockerfile)
    if [ -z "$features" ]; then
        echo "ERROR: could not read ARG FEATURES from Dockerfile" >&2
        exit 1
    fi
    echo "release image features: ${features}"
    run cargo check --workspace --features "$features"
}

domain_purity_check() {
    log "Verify domain layer purity"
    if [ -d src/domain ] && grep -rn -E "(sea_orm|axum|aws_sdk|reqwest|moka|crate::server|crate::outbound)" src/domain/; then
        echo "ERROR: Infrastructure dependencies or imports found in src/domain/" >&2
        exit 1
    fi
}

rust_default_gates() {
    log "Cargo format"
    run cargo fmt --all --check
    log "Cargo build"
    run cargo build --workspace --all-targets --all-features
    log "Memory-only build"
    run cargo check --no-default-features --features memory
    release_image_features_check
    domain_purity_check
    log "Cargo clippy"
    run cargo clippy --workspace --all-targets --all-features -- -D warnings
    log "Cargo nextest"
    run cargo nextest run --workspace --all-targets --all-features
    log "Cargo doc"
    run env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --document-private-items
    require_tool jq "Install jq. CI uses jq for crate type detection."
    crate_kind_detection
    if [ "$CRATE_IS_LIB" = "true" ]; then
        log "Cargo doc tests"
        run cargo test --doc --workspace --all-features
    else
        echo "Skipping cargo doc tests: crate_type.yml detected no library target."
    fi
    log "Cargo machete"
    run cargo machete --with-metadata
}

fast_wiring_checks() {
    log "Validate .trivyignore.yaml and variant parity"
    require_tool python3 "Install Python 3."
    run python3 -m unittest discover -s scripts/tests -p 'test_*.py'
    run python3 -m unittest discover -s scripts/local-ci/tests -p 'test_*.py'
    if have trivy; then run sh scripts/gate-selftest.sh; fi
    run python3 scripts/check-trivyignore.py .trivyignore.yaml
    run python3 scripts/check-variant-parity.py
    log "Attestation verifier self-test"
    run bash scripts/attestation-selftest.sh
}

prepare_zizmor_auth() {
    if [ -z "$LOCAL_ZIZMOR_TOKEN" ] && have gh; then
        LOCAL_ZIZMOR_TOKEN=$(gh auth token 2>/dev/null) || true
    fi
    [ -n "$LOCAL_ZIZMOR_TOKEN" ] || fail_missing "GitHub token for online audits" "Run gh auth login, or provide a fine-grained read-only GH_TOKEN."
}

zizmor_online_scan() {
    # Scope the token to this process only; never put it in argv or log it.
    ZIZMOR_GITHUB_TOKEN="$LOCAL_ZIZMOR_TOKEN" docker run --rm -e ZIZMOR_GITHUB_TOKEN -v "$PWD:/workspace:ro" -w /workspace "$ZIZMOR_IMAGE" --persona=regular --color=never --format=plain -- .
}

zizmor_checks() {
    log "Zizmor security check"
    prepare_zizmor_auth
    # Mirror the action's single retry. A repeated finding still fails the gate.
    zizmor_online_scan || zizmor_online_scan
    log "Zizmor known-bad fixture self-test"
    local rc out fixture missing rule
    fixture="scripts/testdata/zizmor-selftest-workflow.yml"
    test -f "$fixture" || { echo "ERROR: self-test fixture is missing: $fixture" >&2; exit 1; }
    rc=0
    out=$(docker run --rm --volume "${PWD}:/workspace:ro" --workdir /workspace "$ZIZMOR_IMAGE" --persona=regular --no-online-audits --color=never --format=plain -- "$fixture" 2>&1) || rc=$?
    printf '%s\n' "$out"
    if [ "$rc" -lt 11 ] || [ "$rc" -gt 14 ]; then
        echo "ERROR: expected a findings exit code (11-14) from the fixture, got ${rc}." >&2
        exit 1
    fi
    missing=""
    for rule in artipacked excessive-permissions; do
        [[ "$out" == *"$rule"* ]] || missing="${missing} ${rule}"
    done
    if [ -n "$missing" ]; then
        echo "ERROR: the gate failed on the fixture but did not report:${missing}" >&2
        exit 1
    fi
    log "Assert every CI.yml job is gated by ci-success"
    run python3 scripts/local-ci/workflow-data.py gated

}

release_variant_checks() {
    log "Release variant feature matrix"
    local features variants
    variants=$(python3 scripts/local-ci/workflow-data.py variants)
    while IFS= read -r features; do
        run cargo check --workspace --features "$features"
    done <<< "$variants"

}

supply_chain_checks() {
    log "Cargo vet"
    run cargo vet --locked
    log "Cargo deny"
    run cargo deny --all-features check
    log "Cargo audit"
    run cargo audit
}

style_config_checks() {
    log "Typos"
    run typos
    log "Tombi TOML lint"
    run tombi lint
    log "Markdown lint"
    run markdownlint-cli2 "**/*.md"
    log "YAML format lint"
    run yamlfmt --lint .
}

trivy_and_helm_checks() {
    log "Helm dependencies"
    helm_deps
    run_render_helm_templates_action
    log "Verify image reference resolution"
    run bash scripts/verify-image-reference.sh
    log "Trivy config scan"
    if version_matches trivy "$TRIVY_VERSION" --version; then
        run trivy config --severity HIGH,CRITICAL --exit-code 1 --ignorefile .trivyignore.yaml "$RENDER_TEMP/rendered"
    else
        require_tool docker "Install Docker or trivy. Docker is used as a no-root local fallback."
        run docker run --rm -v "$PWD:/workspace:ro" -v "$RENDER_TEMP/rendered:/tmp/rendered:ro" -w /workspace -v "$TOOLS_ROOT/trivy:/root/.cache/trivy" "$TRIVY_IMAGE" config --severity HIGH,CRITICAL --exit-code 1 --ignorefile .trivyignore.yaml /tmp/rendered
    fi
    log "Helm template local values"
    local output_file="$RUNNER_TEMP/statuslist-local-rendered.yaml"
    helm template statuslist-local "$CHART_DIR" -f "$CHART_DIR"/values-local.yaml --namespace local > "$output_file"
    if ! grep -A1 'name: APP_ENV' "$output_file" | grep -q 'value: "development"'; then
        echo "ERROR: APP_ENV=development not found in rendered template" >&2
        exit 1
    fi
    if ! grep -q 'image: busybox:1.38' "$output_file"; then
        echo "ERROR: init container image 'busybox:1.38' not found in rendered template" >&2
        exit 1
    fi
    mkdir -p "$CARGO_TARGET_DIR"
    log "KubeLinter"
    run kube-linter version
    kube-linter --config .kube-linter.yaml lint "$RENDER_TEMP/rendered" --format sarif | tee "$CARGO_TARGET_DIR/kube-linter-results.sarif"
}

otel_validation() {
    log "OpenTelemetry config validation"
    run python3 scripts/local-ci/validate-compose.py
    run docker manifest inspect "$JAEGER_IMAGE"
    run docker run --rm -v "$PWD/deploy/observability/otel-collector.yaml:/etc/otelcol/config.yaml:ro" "$OTEL_COLLECTOR_IMAGE" validate --config /etc/otelcol/config.yaml
    helm_deps
    helm template statuslist "$CHART_DIR" --namespace statuslist --set-string statuslist.env.APP_DATABASE__PORT="5432" > "$RUNNER_TEMP/statuslist-rendered.yaml"
    python3 - <<'PY2'
from pathlib import Path
import os, yaml
work = Path(os.environ['RUNNER_TEMP'])
rendered = work / 'statuslist-rendered.yaml'
for document in yaml.safe_load_all(rendered.read_text()):
    if not isinstance(document, dict):
        continue
    metadata = document.get('metadata') or {}
    if document.get('kind') == 'ConfigMap' and metadata.get('name', '').endswith('-opentelemetry-collector'):
        data = document.get('data', {})
        content = data.get('relay') or data.get('config.yaml')
        if content:
            (work / 'helm-otel-collector.yaml').write_text(content)
            break
else:
    raise SystemExit('rendered Helm Collector ConfigMap was not found')
PY2
    run docker run --rm -v "$RUNNER_TEMP/helm-otel-collector.yaml:/etc/otelcol/config.yaml:ro" "$OTEL_COLLECTOR_IMAGE" validate --config /etc/otelcol/config.yaml
}

prometheus_validation() {
    log "Prometheus rules and dashboard validation"
    helm_deps
    run docker run --rm --entrypoint promtool -v "$PWD/deploy/observability/prometheus:/etc/prometheus:ro" "$PROMETHEUS_IMAGE" check rules /etc/prometheus/rules/recording.rules.yml
    run docker run --rm --entrypoint promtool -v "$PWD/deploy/observability/prometheus:/etc/prometheus:ro" "$PROMETHEUS_IMAGE" check rules /etc/prometheus/rules/alerting.rules.yml
    run bash scripts/check-helm-prometheus.sh
    run docker run --rm --entrypoint promtool -v "$PWD/deploy/observability/prometheus:/etc/prometheus:ro" "$PROMETHEUS_IMAGE" check config /etc/prometheus/prometheus.yml
    run docker run --rm --entrypoint promtool -v "$PWD/deploy/observability/prometheus:/etc/prometheus:ro" "$PROMETHEUS_IMAGE" check config /etc/prometheus/prometheus.production.yml
    run node deploy/observability/slo/lint-thresholds.mjs
    run docker run --rm --entrypoint promtool -v "$PWD/deploy/observability/prometheus:/etc/prometheus:ro" "$PROMETHEUS_IMAGE" test rules /etc/prometheus/tests/recording.test.yml
    run docker run --rm --entrypoint promtool -v "$PWD/deploy/observability/prometheus:/etc/prometheus:ro" "$PROMETHEUS_IMAGE" test rules /etc/prometheus/tests/alerting.test.yml
    if [ "$(uname -s)" = Linux ]; then
        run bash deploy/observability/alertmanager/tests/test-alertmanager-config.sh
    else
        echo "SKIPPED: Alertmanager delivery requires Linux host networking" >&2
        touch "$RUNNER_TEMP/incomplete"
    fi
    run test -s deploy/observability/dashboards/generated/status-list-slo.json
    run python3 -c "import json; json.load(open('deploy/observability/dashboards/generated/status-list-slo.json'))"
    run bash scripts/check-dashboard-drift.sh
}

coverage_check() {
    log "Cargo coverage"
    run cargo llvm-cov nextest --workspace --all-features --html --output-dir target/llvm-cov/html
    test -d target/llvm-cov/html || { echo "ERROR: coverage artifact directory target/llvm-cov/html was not created" >&2; exit 1; }
}

docker_build_smoke() {
    log "Docker build smoke"
    run docker build .
}

rust_version_check() {
    run rustc --version
    local updates status=0
    updates=$(rustup check 2>&1) || status=$?
    printf '%s\n' "$updates"
    if grep -qi 'update available' <<< "$updates"; then
        echo "WARNING: Rust update available; CI uses stable. Run rustup update stable to align." >&2
    elif [ "$status" -ne 0 ]; then
        echo "WARNING: rustup check failed; could not determine toolchain freshness." >&2
    fi
}

# Run each gate in a separate shell so errexit remains active even while the
# parent collects failures. Avoid `if function`: Bash disables errexit inside it.
execute_gate() {
    local name="$1" status
    set +e
    ( set -e; dispatch_gate "$name" )
    status=$?
    set -e
    if [ "$status" -ne 0 ]; then
        echo "FAILED: $name (exit $status)" >&2
        FAILURES="$FAILURES $name"
    fi
}

dispatch_gate() {
    bootstrap_gate "$1"
    case "$1" in
        rust) rust_default_gates ;;
        wiring) fast_wiring_checks ;;
        style) style_config_checks ;;
        zizmor) zizmor_checks ;;
        variants) release_variant_checks ;;
        docker) docker_build_smoke ;;
        supply-chain) supply_chain_checks ;;
        helm) trivy_and_helm_checks ;;
        otel) otel_validation ;;
        prometheus) prometheus_validation ;;
        coverage) coverage_check ;;
    esac
}

main() {
    log "Running local CI $MODE mode${GATE:+, gate $GATE}"
    FAILURES=""
    if [ -n "$GATE" ]; then
        execute_gate "$GATE"
    elif [ "$MODE" = full ]; then
        for gate in style wiring zizmor helm otel prometheus rust variants supply-chain docker coverage; do
            execute_gate "$gate"
        done
    else
        execute_gate wiring
        execute_gate rust
    fi
    if [ -n "$FAILURES" ] || [ -f "$RUNNER_TEMP/incomplete" ]; then
        echo "Local CI incomplete or failed. Failed gates:$FAILURES" >&2
        exit 1
    fi
    echo "Local CI checks passed ($MODE${GATE:+, gate $GATE})."
}

# Sourcing exposes helpers for isolated bootstrap/failure regression tests.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main
fi
