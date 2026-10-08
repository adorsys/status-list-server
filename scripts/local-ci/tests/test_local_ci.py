"""Regression tests for local bootstrap and fail-closed command execution."""

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class LocalCiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        self.env = dict(os.environ)
        for key in ("GH_TOKEN", "GITHUB_TOKEN", "ZIZMOR_GITHUB_TOKEN"):
            self.env.pop(key, None)
        self.env.update(
            PATH=f"{self.bin}:{os.environ['PATH']}",
            LOCAL_CI_TOOLS_ROOT=str(self.directory / "tools"),
            RUNNER_TEMP=str(self.directory / "tmp"),
        )

    def stub(self, name, body):
        path = self.bin / name
        path.write_text("#!/usr/bin/env bash\nset -eu\n" + body + "\n")
        path.chmod(0o755)

    def shell(self, code):
        return subprocess.run(
            ["bash", "-c", f"source {shlex.quote(str(ROOT / 'local-ci.sh'))}; {code}"],
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_matching_version_does_not_install(self):
        self.stub("cargo-nextest", "echo 'cargo-nextest 0.9.101 (test build)'")
        self.stub("cargo", "echo unexpected-install >&2; exit 99")
        result = self.shell('install_cargo_bin cargo-nextest cargo-nextest "$NEXT_VERSION"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("unexpected-install", result.stderr)

    def test_rust_gates_run_profiles_and_stop_on_failure(self):
        result = self.shell('''
run() { printf '%s\\n' "$*"; [[ "$*" != 'cargo xtask check-profiles' ]] || return 17; }
rust_default_gates
echo unexpected-success
''')
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertIn("cargo xtask check-profiles", result.stdout)
        self.assertNotIn("cargo clippy", result.stdout)
        self.assertNotIn("unexpected-success", result.stdout)

    def test_llvm_cov_version_uses_cargo_subcommand_protocol(self):
        self.stub("cargo-llvm-cov", "[[ \"$*\" == 'llvm-cov --version' ]] || exit 2; echo 'cargo-llvm-cov 0.6.16'")
        result = self.shell('BOOTSTRAP=0; install_cargo_bin cargo-llvm-cov cargo-llvm-cov "$LLVM_COV_VERSION"')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wrong_version_is_rejected_without_bootstrap(self):
        self.stub("cargo-nextest", "echo 'cargo-nextest 0.9.1010'")
        result = self.shell('BOOTSTRAP=0; install_cargo_bin cargo-nextest cargo-nextest "$NEXT_VERSION"')
        self.assertEqual(result.returncode, 127)
        self.assertIn("--version 0.9.101", result.stderr)
        self.assertIn("--root", result.stderr)

    def test_wrong_version_installs_into_isolated_root(self):
        self.stub("cargo-nextest", "echo 'cargo-nextest 0.9.99'")
        self.stub("cargo", """
[[ "$*" == *"--root $LOCAL_CI_TOOLS_ROOT"* ]] || exit 90
[[ "$*" == *"--version 0.9.101"* ]] || exit 91
printf '#!/bin/sh\\necho cargo-nextest 0.9.101\\n' > "$LOCAL_CI_TOOLS_ROOT/bin/cargo-nextest"
chmod +x "$LOCAL_CI_TOOLS_ROOT/bin/cargo-nextest"
""")
        result = self.shell('install_cargo_bin cargo-nextest cargo-nextest "$NEXT_VERSION"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.directory / "tools/bin/cargo-nextest").exists())

    def test_install_failure_stops_execution(self):
        self.stub("cargo-nextest", "echo 'cargo-nextest 0.0.0'")
        self.stub("cargo", "exit 42")
        result = self.shell('install_cargo_bin cargo-nextest cargo-nextest "$NEXT_VERSION"; echo gate-passed')
        self.assertEqual(result.returncode, 42)
        self.assertNotIn("gate-passed", result.stdout)

    def test_missing_auth_fails_with_guidance(self):
        self.stub("gh", "exit 1")
        result = self.shell("prepare_zizmor_auth")
        self.assertEqual(result.returncode, 127)
        self.assertIn("gh auth login", result.stderr)

    def test_zizmor_forwards_token_without_logging_it(self):
        self.env["GH_TOKEN"] = "test-secret-do-not-log"
        self.stub("docker", """
[[ "$ZIZMOR_GITHUB_TOKEN" == test-secret-do-not-log ]] || exit 90
[[ "$*" == *'-e ZIZMOR_GITHUB_TOKEN'* ]] || exit 91
[[ "$*" != *'--online-audits'* ]] || exit 92
[[ "$*" == *'@sha256:'* ]] || exit 93
exit 14
""")
        result = self.shell("prepare_zizmor_auth; zizmor_online_scan; echo gate-passed")
        self.assertEqual(result.returncode, 14, result.stderr)
        self.assertNotIn("test-secret-do-not-log", result.stdout + result.stderr)
        self.assertNotIn("gate-passed", result.stdout)

    def test_tombi_uses_supported_npm_package(self):
        self.stub("tombi", "echo 'tombi 0.0.0'")
        self.stub("npm", """
[[ "$*" == *'ci --prefix'* ]] || exit 90
mkdir -p "$LOCAL_CI_TOOLS_ROOT/node/node_modules/.bin"
printf '#!/bin/sh\\necho tombi 1.2.4\\n' > "$LOCAL_CI_TOOLS_ROOT/node/node_modules/.bin/tombi"
chmod +x "$LOCAL_CI_TOOLS_ROOT/node/node_modules/.bin/tombi"
""")
        result = self.shell('install_node_bin tombi "$TOMBI_VERSION"')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_help_has_no_filesystem_side_effects(self):
        result = subprocess.run(['bash', str(ROOT / 'local-ci.sh'), '--help'],
                                env=self.env, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertFalse((self.directory / 'tools').exists())

    def test_unknown_option_fails(self):
        result = subprocess.run(['bash', str(ROOT / 'local-ci.sh'), '--unknown'],
                                env=self.env, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.directory / 'tools').exists())

    def test_zizmor_retry_can_succeed(self):
        self.env['GH_TOKEN'] = 'test-secret-do-not-log'
        self.stub('docker', """
if [[ "$*" == *'--no-online-audits'* ]]; then
    echo 'artipacked excessive-permissions'
    python3 -c 'print("diagnostic line\\n" * 10000)'
    exit 14
fi
if [[ ! -f "$LOCAL_CI_TOOLS_ROOT/attempt" ]]; then
    touch "$LOCAL_CI_TOOLS_ROOT/attempt"; exit 1
fi
""")
        result = self.shell('zizmor_checks')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_zizmor_two_failed_attempts_fail_gate(self):
        self.env['GH_TOKEN'] = 'test-secret-do-not-log'
        self.stub('docker', 'exit 14')
        result = self.shell('zizmor_checks; echo gate-passed')
        self.assertEqual(result.returncode, 14)
        self.assertNotIn('gate-passed', result.stdout)

    def test_token_is_not_exported_to_later_commands(self):
        self.stub('gh', 'echo test-secret-do-not-log')
        result = self.shell('prepare_zizmor_auth; env')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('test-secret-do-not-log', result.stdout + result.stderr)

    def test_gate_failure_does_not_disable_errexit_or_later_gates(self):
        result = self.shell("""
FAILURES=''
dispatch_gate() { if [ "$1" = bad ]; then false; echo incorrect; else echo continued; fi; }
execute_gate bad
execute_gate good
[[ "$FAILURES" == ' bad' ]]
""")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('incorrect', result.stdout)
        self.assertIn('continued', result.stdout)

    def test_action_runner_executes_every_step(self):
        import yaml
        action = yaml.safe_load((ROOT / '.github/workflows/render-helm-templates/action.yml').read_text())
        fixture = self.directory / 'action.yml'
        for step in action['runs']['steps']:
            step['run'] = 'echo executed-step'
        fixture.write_text(yaml.safe_dump(action))
        result = subprocess.run(['python3', str(ROOT / 'scripts/local-ci/run-action.py'), str(fixture)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('executed-step'), len(action['runs']['steps']))

    def test_helm_checksum_rejection_prevents_extraction(self):
        self.stub('helm', 'echo v0.0.0')
        self.stub('curl', """
while [[ "$1" != '--output' ]]; do shift; done
printf 'corrupt archive' > "$2"
""")
        self.stub('tar', 'echo unexpected-extraction; exit 90')
        result = self.shell('install_helm')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Helm archive checksum mismatch', result.stderr)
        self.assertNotIn('unexpected-extraction', result.stdout)
        self.assertFalse((self.directory / 'tools/bin/helm').exists())

    def test_rustup_update_is_reported_even_with_nonzero_status(self):
        self.stub('rustc', 'echo rustc-test-version')
        self.stub('rustup', "echo 'stable-x86_64-unknown-linux-gnu - Update available : 1.90.0 -> 1.91.0'; exit 1")
        result = self.shell('rust_version_check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('rustc-test-version', result.stdout)
        self.assertIn('Run rustup update stable', result.stderr)
        self.assertNotIn('could not determine', result.stderr)

    def test_rust_flags_default_and_explicit_override(self):
        self.env.pop('RUSTFLAGS', None)
        result = self.shell('printf "%s" "$RUSTFLAGS"')
        self.assertEqual(result.stdout, '-D warnings')
        self.env['RUSTFLAGS'] = ''
        result = self.shell('printf "%s" "$RUSTFLAGS"')
        self.assertEqual(result.stdout, '')

    def test_other_toolchain_updates_do_not_warn_about_stable(self):
        self.stub('rustc', 'echo rustc-test-version')
        self.stub('rustup', """
echo 'stable-x86_64-unknown-linux-gnu - Up to date : 1.91.0'
echo 'nightly-x86_64-unknown-linux-gnu - Update available : old -> new'
echo 'rustup - Update available : 1.28.1 -> 1.28.2'
exit 1
""")
        result = self.shell('rust_version_check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('Run rustup update stable', result.stderr)
        self.assertNotIn('could not determine', result.stderr)

    def test_custom_rust_flags_warn_without_changing_them(self):
        for flags, warning in [('', True), ('-C target-cpu=native', True),
                               ('-C target-cpu=native -D warnings', False),
                               ('-Dwarnings', False), ('-D warnings-extra', True)]:
            with self.subTest(flags=flags):
                self.env['RUSTFLAGS'] = flags
                result = self.shell('printf "%s" "$RUSTFLAGS"')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, flags)
                self.assertEqual('RUSTFLAGS overrides' in result.stderr, warning)

    def test_trivy_container_uses_caller_and_writable_cache(self):
        self.stub('trivy', 'echo Version: 0.0.0')
        self.stub('docker', """
[[ "$*" == *"--user $(id -u):$(id -g)"* ]] || exit 90
[[ "$*" == *'-e TRIVY_CACHE_DIR=/tmp/trivy-cache'* ]] || exit 91
[[ "$*" == *"$LOCAL_CI_TOOLS_ROOT/trivy:/tmp/trivy-cache"* ]] || exit 92
[[ -d "$LOCAL_CI_TOOLS_ROOT/trivy" && -w "$LOCAL_CI_TOOLS_ROOT/trivy" ]] || exit 93
exit 42
""")
        result = self.shell("""
helm_deps() { :; }
run_render_helm_templates_action() { :; }
run() { if [[ "$1" == bash ]]; then return; fi; "$@"; }
trivy_and_helm_checks
""")
        self.assertEqual(result.returncode, 42, result.stderr)

    def test_unavailable_docker_allows_bootstrap_and_rust_checks_before_tests(self):
        self.stub('docker', 'exit 1')
        for missing in (False, True):
            with self.subTest(missing_cli=missing):
                result = self.shell("""
bootstrap_python() { :; }
rust_components() { :; }
install_cargo_bin() { :; }
install_helm() { :; }
""" + ('have() { [[ "$1" != docker ]]; }' if missing else '') + """
bootstrap_default_tools
run() { echo "$*"; }
release_image_features_check() { :; }
domain_purity_check() { :; }
crate_kind_detection() { CRATE_IS_LIB=true; }
rust_default_gates
echo unexpected-success
""")
                self.assertEqual(result.returncode, 127, result.stderr)
                self.assertIn('WARNING: Docker is unavailable', result.stderr)
                self.assertIn('cargo fmt --all --check', result.stdout)
                self.assertIn('cargo build --workspace', result.stdout)
                self.assertIn('cargo clippy --workspace', result.stdout)
                self.assertIn('cargo doc --workspace', result.stdout)
                self.assertIn('cargo test --doc --workspace', result.stdout)
                self.assertIn('cargo machete --with-metadata', result.stdout)
                self.assertNotIn('cargo nextest run', result.stdout)
                self.assertNotIn('unexpected-success', result.stdout)
                self.assertIn('Install Docker' if missing else 'Start Docker', result.stderr)

    def test_container_gates_require_running_docker(self):
        self.stub('docker', 'exit 1')
        for gate in ('docker', 'zizmor', 'otel', 'prometheus', 'helm'):
            with self.subTest(gate=gate):
                result = self.shell('bootstrap_python() { :; }; install_helm() { :; }; '
                                    + f'bootstrap_gate {gate}; echo unexpected-success')
                self.assertEqual(result.returncode, 127, result.stderr)
                self.assertIn('Start Docker', result.stderr)
                self.assertNotIn('unexpected-success', result.stdout)
        result = self.shell('coverage_check; echo unexpected-success')
        self.assertEqual(result.returncode, 127, result.stderr)
        self.assertNotIn('unexpected-success', result.stdout)

    def test_failed_python_install_removes_venv(self):
        self.stub('python3', """
if [[ "$*" == '-m venv '* ]]; then
    mkdir -p "$3/bin"
    printf '#!/bin/sh\\nexit 42\\n' > "$3/bin/python3"
    chmod +x "$3/bin/python3"
    exit 0
fi
exit 1
""")
        result = self.shell('bootstrap_python full')
        self.assertEqual(result.returncode, 127, result.stderr)
        self.assertFalse((self.directory / 'tools/python').exists())
        self.assertIn('Pinned dependency installation failed', result.stderr)

    def test_compose_does_not_inherit_secrets_or_optional_dotenv(self):
        self.env['APP_DATABASE__PASSWORD'] = 'secret-do-not-log'
        self.stub('docker', """
[[ -z "${APP_DATABASE__PASSWORD:-}" ]] || exit 90
[[ "$*" == *'--env-file'* && "$*" == *'--quiet'* ]] || exit 91
while [[ "$#" -gt 0 ]]; do
    if [[ "$1" == '-f' ]]; then
        python3 -c 'import sys,yaml; m=yaml.safe_load(open(sys.argv[1])); assert all(e.get("path") != ".env" for s in m["services"].values() for e in s.get("env_file", []))' "$2"
    fi
    shift
done
""")
        result = self.shell('python3 scripts/local-ci/validate-compose.py')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('secret-do-not-log', result.stdout + result.stderr)

    def test_ci_versions_match_local_pins(self):
        import json
        import re
        import yaml
        script = (ROOT / 'local-ci.sh').read_text()
        pins = dict(re.findall(r'^([A-Z_0-9]+)="([^"$]+)"$', script, re.M))
        workflow = (ROOT / '.github/workflows/CI.yml').read_text()
        deny = (ROOT / '.github/workflows/cargo_deny.yml').read_text()
        for key, tool in [('NEXT_VERSION', 'nextest'), ('MACHETE_VERSION', 'cargo-machete'),
                          ('VET_VERSION', 'cargo-vet'), ('AUDIT_VERSION', 'cargo-audit'),
                          ('LLVM_COV_VERSION', 'cargo-llvm-cov'), ('TYPOS_VERSION', 'typos-cli')]:
            self.assertIn(tool + '@' + pins[key], workflow + deny)
        for job in yaml.safe_load(workflow)['jobs'].values():
            for step in job.get('steps', []):
                if step.get('uses', '').startswith('azure/setup-helm@'):
                    self.assertEqual(step['with']['version'], pins['HELM_VERSION'])
        for key in ['ZIZMOR_IMAGE', 'OTEL_COLLECTOR_IMAGE', 'PROMETHEUS_IMAGE', 'JAEGER_IMAGE']:
            self.assertIn(pins[key], workflow)
            self.assertRegex(pins[key], r'@sha256:[0-9a-f]{64}$')
        self.assertIn(pins['PROMETHEUS_IMAGE'], (ROOT / 'scripts/check-helm-prometheus.sh').read_text())
        self.assertIn('yamlfmt@' + pins['YAMLFMT_VERSION'], workflow)
        self.assertIn(pins['KUBE_LINTER_SHA256'], workflow)
        package = json.loads((ROOT / 'scripts/local-ci/node/package.json').read_text())
        self.assertEqual(package['dependencies']['tombi'], pins['TOMBI_VERSION'])
        self.assertEqual(package['dependencies']['markdownlint-cli2'], pins['MARKDOWNLINT_VERSION'])
        # These versions are embedded by Actions, not explicit workflow inputs.
        # An action upgrade must review these local defaults as well.
        for reference in [
            'EmbarkStudios/cargo-deny-action@3c6349835b2b7b196a839186cb8b78e02f7b5f25',
            'DavidAnson/markdownlint-cli2-action@6bf21b07787794f89a243495939cd651942aeabe',
            'tombi-toml/setup-tombi@f2ae7247d62521245eb2793d653b9df472b9e090',
            'aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25',
        ]:
            self.assertIn(reference, workflow + deny)
        self.assertEqual(pins['DENY_VERSION'], '0.20.2')
        self.assertEqual(pins['TRIVY_VERSION'], '0.70.0')
        self.assertEqual(pins['TOMBI_VERSION'], '1.2.4')
        self.assertEqual(pins['MARKDOWNLINT_VERSION'], '0.23.1')
        self.assertIn(pins['KUBE_LINTER_VERSION'], workflow)
        self.assertTrue(pins['TRIVY_IMAGE'].startswith('aquasec/trivy:' + pins['TRIVY_VERSION'] + '@sha256:'))

    @unittest.skipUnless(shutil.which("yamlfmt"), "yamlfmt is tested in the full local mode")
    def test_yaml_excludes_generated_files_but_rejects_invalid_source(self):
        shutil.copy(ROOT / ".yamlfmt.yml", self.directory / ".yamlfmt.yml")
        shutil.copy(ROOT / ".gitignore", self.directory / ".gitignore")
        generated = self.directory / "target/helm-sensitive-env-chart-test/templates"
        generated.mkdir(parents=True)
        (generated / "deployment.yaml").write_text("{{- if .Values.enabled }}\n")
        for directory in ("demo/.venv/package", "deploy/node_modules/package", ".git/logs/refs"):
            dependency = self.directory / directory
            dependency.mkdir(parents=True)
            (dependency / "invalid.yaml").write_text("key: [\n")
        source = self.directory / "source.yaml"
        source.write_text("enabled: true\n")
        result = subprocess.run(["yamlfmt", "--lint", "."], cwd=self.directory, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        source.write_text("enabled: [\n")
        result = subprocess.run(["yamlfmt", "--lint", "."], cwd=self.directory, capture_output=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
