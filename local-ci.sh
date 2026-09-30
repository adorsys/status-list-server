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
TOOLS_ROOT="${LOCAL_CI_TOOLS_ROOT:-$PWD/target/local-ci-tools}"
mkdir -p "$TOOLS_ROOT"
TOOLS_ROOT="$(cd "$TOOLS_ROOT" && pwd)"
TOOLS_BIN="$TOOLS_ROOT/bin"
RUNNER_TEMP="${RUNNER_TEMP:-$TOOLS_ROOT/tmp}"
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
TYPOS_VERSION="1.49.0"
YAMLFMT_VERSION="v0.21.0"
HELM_VERSION="v4.2.4"
KUBE_LINTER_VERSION="v0.8.3"
KUBE_LINTER_SHA256="1a6d8419b11971372971fdbc22682b684ebfb7cf1c39591662d1b6ca736c41df"
ZIZMOR_IMAGE="ghcr.io/zizmorcore/zizmor:1.28.0@sha256:8e6b3e4fb74d1aa5d23e83ea369f386c66eced0d1fb944d32cd8b2aac100b00d"
OTEL_COLLECTOR_IMAGE="otel/opentelemetry-collector-contrib:0.158.0"
PROMETHEUS_IMAGE="prom/prometheus:v3.11.3"
JAEGER_IMAGE="jaegertracing/jaeger:2.20.0"

export PATH="$TOOLS_BIN:$TOOLS_ROOT/node/node_modules/.bin:$TOOLS_ROOT/python/bin:$PATH"
export CHART_DIR RUNNER_TEMP

usage() {
    cat <<'EOF'
Usage: ./local-ci.sh [--full] [--no-bootstrap] [--help]

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
  --help          Show this help.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --full) MODE="full" ;;
        --no-bootstrap) BOOTSTRAP=0 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

mkdir -p "$TOOLS_BIN" "$RUNNER_TEMP"

log() { printf '\n==> %s\n' "$*"; }
run() { printf '+ %s\n' "$*"; "$@"; }
have() { command -v "$1" >/dev/null 2>&1; }

fail_missing() {
    local tool="$1" hint="$2"
    cat >&2 <<EOF
ERROR: missing required tool: $tool

$hint
Re-run ./local-ci.sh after installing it, or omit --no-bootstrap when this script
can install the tool without root.
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
    elif have "$bin" && "$bin" --version 2>/dev/null | grep -Eq 'github.com/mikefarah/yq/.*version v4\.'; then
        return
    fi
    if [ "$BOOTSTRAP" -ne 1 ]; then
        fail_missing "$bin (missing or wrong version)" "Install with: GOBIN='$TOOLS_BIN' go install $package"
    fi
    log "Installing $bin with go"
    run env GOBIN="$TOOLS_BIN" go install "$package"
    hash -r
    if [ -n "$version" ]; then
        version_matches "$bin" "$version" -version || fail_missing "$bin $version" "Check the installation in $TOOLS_BIN."
    else
        "$bin" --version | grep -Eq 'github.com/mikefarah/yq/.*version v4\.' || fail_missing "mikefarah yq v4" "Check the installation in $TOOLS_BIN."
    fi
}

install_node_bin() {
    local bin="$1" version="$2"
    version_matches "$bin" "$version" --version && return
    if [ "$BOOTSTRAP" -ne 1 ]; then
        fail_missing "$bin $version (missing or wrong version)" "Install with: npm install --prefix '$TOOLS_ROOT/node' $bin@$version"
    fi
    log "Installing $bin $version with npm"
    run npm install --prefix "$TOOLS_ROOT/node" --no-audit --no-fund --save-exact "$bin@$version"
    hash -r
    version_matches "$bin" "$version" --version || fail_missing "$bin $version" "Check Node.js compatibility and npm's installation output."
}

bootstrap_python() {
    require_tool python3 "Install Python 3 with venv support."
    python3 -c 'import yaml' 2>/dev/null && return
    if [ "$BOOTSTRAP" -ne 1 ]; then
        fail_missing PyYAML "Install PyYAML in a virtual environment, or re-run without --no-bootstrap."
    fi
    run python3 -m venv "$TOOLS_ROOT/python" || fail_missing python3-venv "Install Python venv support (Ubuntu: sudo apt-get install python3-venv)."
    run "$TOOLS_ROOT/python/bin/python3" -m pip install 'PyYAML==6.0.3'
    hash -r
}

install_helm() {
    if have helm; then
        local current
        current=$(helm version --template '{{.Version}}' 2>/dev/null || true)
        if [ "$current" = "$HELM_VERSION" ]; then
            return
        fi
        echo "helm $current found, but CI uses $HELM_VERSION; installing a local copy in $TOOLS_BIN"
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
    require_tool cmake "Install CMake with your OS package manager. CI uses: sudo apt-get install -y cmake golang-go"
    require_tool go "Install Go with your OS package manager. CI uses: sudo apt-get install -y cmake golang-go"
    require_tool jq "Install jq (Ubuntu: sudo apt-get install jq)."
    require_tool docker "Install Docker and start its daemon; the all-feature tests start containers."
    docker info >/dev/null 2>&1 || fail_missing "Docker daemon" "Start Docker and ensure your user can access it (docker info)."
    bootstrap_python
    rust_components rustfmt clippy
    install_cargo_bin cargo-nextest cargo-nextest "$NEXT_VERSION"
    install_cargo_bin cargo-machete cargo-machete "$MACHETE_VERSION"
    install_helm
}

bootstrap_full_tools() {
    [ "$(uname -s)" = Linux ] || fail_missing "Linux execution environment" "Full parity includes host-network container tests. Run on Linux; see docs/local-ci.md."
    require_tool node "Install Node.js 22 or newer and npm."
    require_tool npm "Install npm alongside Node.js 22 or newer."
    node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)' || fail_missing "Node.js >=22" "Activate Node.js 22 or newer; CI's markdownlint-cli2 requires it."
    bootstrap_default_tools
    docker compose version >/dev/null 2>&1 || fail_missing "Docker Compose v2" "Install the Docker Compose plugin."
    prepare_zizmor_auth
    rust_components llvm-tools-preview
    install_cargo_bin cargo-vet cargo-vet "$VET_VERSION"
    install_cargo_bin cargo-audit cargo-audit "$AUDIT_VERSION"
    install_cargo_bin cargo-deny cargo-deny "$DENY_VERSION"
    install_cargo_bin cargo-llvm-cov cargo-llvm-cov "$LLVM_COV_VERSION"
    install_cargo_bin typos typos-cli "$TYPOS_VERSION"
    install_node_bin tombi "$TOMBI_VERSION"
    install_go_bin yamlfmt "github.com/google/yamlfmt/cmd/yamlfmt@$YAMLFMT_VERSION" "$YAMLFMT_VERSION"
    install_go_bin yq "github.com/mikefarah/yq/v4@latest"
    install_node_bin markdownlint-cli2 "$MARKDOWNLINT_VERSION"
    install_kube_linter
}

helm_deps() {
    run helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
    run helm dependency build "$CHART_DIR"
}

run_render_helm_templates_action() {
    log "Render Helm templates using .github/workflows/render-helm-templates/action.yml"
    local script="$RUNNER_TEMP/render-helm-templates.sh"
    python3 - "$script" <<'PY2'
from pathlib import Path
import sys
out = Path(sys.argv[1])
lines = Path('.github/workflows/render-helm-templates/action.yml').read_text().splitlines()
start = None
for i, line in enumerate(lines):
    if line == '      run: |':
        start = i + 1
        break
if start is None:
    raise SystemExit('could not find render-helm-templates run block')
block = []
for line in lines[start:]:
    if line.startswith('        '):
        block.append(line[8:])
    elif line.strip() == '':
        block.append('')
    else:
        break
out.write_text('\n'.join(block) + '\n')
PY2
    run bash "$script"
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
    bootstrap_default_tools
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
    python3 -c 'import yaml' 2>/dev/null || fail_missing "python3-yaml" "Install PyYAML. On Ubuntu CI this is: sudo apt-get install -y python3-yaml"
    run python3 -m unittest discover -s scripts/tests -p 'test_*.py'
    run python3 scripts/check-trivyignore.py .trivyignore.yaml
    run python3 scripts/check-variant-parity.py
    log "Attestation verifier self-test"
    run bash scripts/attestation-selftest.sh
}

prepare_zizmor_auth() {
    # Never put a token in argv or pass it through run(), which logs arguments.
    ZIZMOR_GITHUB_TOKEN="${ZIZMOR_GITHUB_TOKEN:-${GH_TOKEN:-${GITHUB_TOKEN:-}}}"
    if [ -z "$ZIZMOR_GITHUB_TOKEN" ] && have gh; then
        ZIZMOR_GITHUB_TOKEN=$(gh auth token 2>/dev/null) || true
    fi
    [ -n "$ZIZMOR_GITHUB_TOKEN" ] || fail_missing "GitHub token for online audits" "Run gh auth login, or export GH_TOKEN with read access to the referenced repositories. Full mode cannot skip online security audits."
    export ZIZMOR_GITHUB_TOKEN
}

zizmor_online_scan() {
    # The action's online-audits input is not a CLI flag. A token enables online
    # audits. The pinned container also isolates host ZIZMOR_OFFLINE settings.
    run docker run --rm -e ZIZMOR_GITHUB_TOKEN -v "$PWD:/workspace:ro" -w /workspace "$ZIZMOR_IMAGE" --persona=regular --color=never --format=plain -- .
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
        printf '%s' "$out" | grep -q "$rule" || missing="${missing} ${rule}"
    done
    if [ -n "$missing" ]; then
        echo "ERROR: the gate failed on the fixture but did not report:${missing}" >&2
        exit 1
    fi
    log "Assert every CI.yml job is gated by ci-success"
    require_tool yq "Install mikefarah yq v4. CI uses yq to inspect CI.yml."
    yq -r '.jobs | keys | .[] | select(. != "ci-success")' .github/workflows/CI.yml | sort > "$RUNNER_TEMP/ci-jobs"
    yq -r '.jobs."ci-success".needs[]' .github/workflows/CI.yml | sort > "$RUNNER_TEMP/ci-gated"
    local ungated
    ungated=$(comm -23 "$RUNNER_TEMP/ci-jobs" "$RUNNER_TEMP/ci-gated")
    if [ -n "$ungated" ]; then
        echo "ERROR: these CI.yml jobs are not in ci-success.needs:" >&2
        printf '  %s\n' $ungated >&2
        exit 1
    fi
}

release_variant_checks() {
    log "Release variant feature matrix"
    run cargo check --workspace --features "postgres,aws,redis"
    run cargo check --workspace --features "postgres,gcp,redis"
    run cargo check --workspace --features "postgres,azure,redis"
    run cargo check --workspace --features "postgres,vault,redis"
    run cargo check --workspace --features "postgres,redis"
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
        run trivy config --severity HIGH,CRITICAL --exit-code 1 --ignorefile .trivyignore.yaml /tmp/rendered
    else
        require_tool docker "Install Docker or trivy. Docker is used as a no-root local fallback."
        run docker run --rm -v "$PWD:/workspace:ro" -v /tmp/rendered:/tmp/rendered:ro -w /workspace "aquasec/trivy:$TRIVY_VERSION" config --severity HIGH,CRITICAL --exit-code 1 --ignorefile .trivyignore.yaml /tmp/rendered
    fi
    log "Helm template local values"
    local output_file="/tmp/statuslist-local-rendered.yaml"
    helm template statuslist-local "$CHART_DIR" -f "$CHART_DIR"/values-local.yaml --namespace local > "$output_file"
    if ! grep -A1 'name: APP_ENV' "$output_file" | grep -q 'value: "development"'; then
        echo "ERROR: APP_ENV=development not found in rendered template" >&2
        exit 1
    fi
    if ! grep -q 'image: busybox:1.38' "$output_file"; then
        echo "ERROR: init container image 'busybox:1.38' not found in rendered template" >&2
        exit 1
    fi
    log "KubeLinter"
    run kube-linter version
    kube-linter --config .kube-linter.yaml lint /tmp/rendered --format sarif | tee kube-linter-results.sarif
}

otel_validation() {
    log "OpenTelemetry config validation"
    run env GRAFANA_ADMIN_PASSWORD=placeholder-not-a-real-credential docker compose config
    run docker manifest inspect "$JAEGER_IMAGE"
    run docker run --rm -v "$PWD/deploy/observability/otel-collector.yaml:/etc/otelcol/config.yaml:ro" "$OTEL_COLLECTOR_IMAGE" validate --config /etc/otelcol/config.yaml
    helm_deps
    helm template statuslist "$CHART_DIR" --namespace statuslist --set-string statuslist.env.APP_DATABASE__PORT="5432" > /tmp/statuslist-rendered.yaml
    python3 - <<'PY2'
from pathlib import Path
import yaml
rendered = Path('/tmp/statuslist-rendered.yaml')
for document in yaml.safe_load_all(rendered.read_text()):
    if not isinstance(document, dict):
        continue
    metadata = document.get('metadata') or {}
    if document.get('kind') == 'ConfigMap' and metadata.get('name', '').endswith('-opentelemetry-collector'):
        data = document.get('data', {})
        content = data.get('relay') or data.get('config.yaml')
        if content:
            Path('/tmp/helm-otel-collector.yaml').write_text(content)
            break
else:
    raise SystemExit('rendered Helm Collector ConfigMap was not found')
PY2
    run docker run --rm -v "/tmp/helm-otel-collector.yaml:/etc/otelcol/config.yaml:ro" "$OTEL_COLLECTOR_IMAGE" validate --config /etc/otelcol/config.yaml
}

prometheus_validation() {
    log "Prometheus rules and dashboard validation"
    helm_deps
    run docker run --rm --entrypoint promtool -v "$PWD/deploy/observability/prometheus:/etc/prometheus:ro" "$PROMETHEUS_IMAGE" check rules /etc/prometheus/rules/recording.rules.yml
    run docker run --rm --entrypoint promtool -v "$PWD/deploy/observability/prometheus:/etc/prometheus:ro" "$PROMETHEUS_IMAGE" check rules /etc/prometheus/rules/alerting.rules.yml
    helm template status-list-server "$CHART_DIR" --namespace ns1 --set prometheusRule.enabled=true > /tmp/helm-render.yaml
    python3 - <<'PY2'
import yaml

docs = [d for d in yaml.safe_load_all(open('/tmp/helm-render.yaml')) if d]
cr = next(d for d in docs if d.get('kind') == 'PrometheusRule')
with open('/tmp/helm-rules.yml', 'w') as f:
    yaml.safe_dump({'groups': cr['spec']['groups']}, f, sort_keys=False)

def rule_names(path):
    rules = yaml.safe_load(open(path))['groups']
    names = set()
    for g in rules:
        for r in g['rules']:
            names.add(r.get('record') or r.get('alert'))
    return names

standalone = rule_names('deploy/observability/prometheus/rules/recording.rules.yml') | rule_names('deploy/observability/prometheus/rules/alerting.rules.yml')
deployed = rule_names('/tmp/helm-rules.yml')
if standalone != deployed:
    raise SystemExit(
        'DRIFT: deployed PrometheusRule rule names differ from the tested standalone rules.\n'
        f'  only in standalone: {sorted(standalone - deployed)}\n'
        f'  only in deployed:   {sorted(deployed - standalone)}'
    )

test = yaml.safe_load(open('deploy/observability/prometheus/tests/alerting.test.yml'))
test['rule_files'] = ['helm-rules.yml']
for block in test['tests']:
    for at in block.get('alert_rule_test', []):
        if at['alertname'] in ('Watchdog', 'StatusListMetricsAbsent'):
            for alert in at['exp_alerts']:
                alert['exp_labels']['namespace'] = 'ns1'
with open('/tmp/helm-alerting.test.yml', 'w') as f:
    yaml.safe_dump(test, f, sort_keys=False)
PY2
    run docker run --rm -w /tmp -v /tmp/helm-rules.yml:/tmp/helm-rules.yml:ro -v /tmp/helm-alerting.test.yml:/tmp/helm-alerting.test.yml:ro --entrypoint promtool "$PROMETHEUS_IMAGE" test rules /tmp/helm-alerting.test.yml
    run docker run --rm --entrypoint promtool -v "$PWD/deploy/observability/prometheus:/etc/prometheus:ro" "$PROMETHEUS_IMAGE" check config /etc/prometheus/prometheus.yml
    run docker run --rm --entrypoint promtool -v "$PWD/deploy/observability/prometheus:/etc/prometheus:ro" "$PROMETHEUS_IMAGE" check config /etc/prometheus/prometheus.production.yml
    run node deploy/observability/slo/lint-thresholds.mjs
    run docker run --rm --entrypoint promtool -v "$PWD/deploy/observability/prometheus:/etc/prometheus:ro" "$PROMETHEUS_IMAGE" test rules /etc/prometheus/tests/recording.test.yml
    run docker run --rm --entrypoint promtool -v "$PWD/deploy/observability/prometheus:/etc/prometheus:ro" "$PROMETHEUS_IMAGE" test rules /etc/prometheus/tests/alerting.test.yml
    run bash deploy/observability/alertmanager/tests/test-alertmanager-config.sh
    run test -s deploy/observability/dashboards/generated/status-list-slo.json
    run python3 -c "import json; json.load(open('deploy/observability/dashboards/generated/status-list-slo.json'))"
    ( cd deploy/observability/dashboards/src; run env NODE_ENV=production npm install --no-audit --no-fund; run env NODE_ENV=production npm run generate-dashboards )
    run git diff --exit-code deploy/observability/dashboards/generated/status-list-slo.json
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

run_default_mode() {
    log "Running local CI default mode"
    rust_default_gates
    fast_wiring_checks
    echo
    echo "Default local CI checks passed. Run ./local-ci.sh --full for GitHub CI parity."
}

run_full_mode() {
    log "Running local CI full/parity mode"
    bootstrap_full_tools
    zizmor_checks
    rust_default_gates
    release_variant_checks
    docker_build_smoke
    supply_chain_checks
    style_config_checks
    fast_wiring_checks
    trivy_and_helm_checks
    otel_validation
    prometheus_validation
    coverage_check
    echo
    echo "Full local CI parity checks passed."
}

# Sourcing exposes helpers for isolated bootstrap/failure regression tests.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    case "$MODE" in
        default) run_default_mode ;;
        full) run_full_mode ;;
    esac
fi
