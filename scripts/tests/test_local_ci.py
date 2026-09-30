"""Regression tests for local bootstrap and fail-closed command execution."""

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


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
[[ "$*" == *'tombi@1.2.4'* ]] || exit 90
mkdir -p "$LOCAL_CI_TOOLS_ROOT/node/node_modules/.bin"
printf '#!/bin/sh\\necho tombi 1.2.4\\n' > "$LOCAL_CI_TOOLS_ROOT/node/node_modules/.bin/tombi"
chmod +x "$LOCAL_CI_TOOLS_ROOT/node/node_modules/.bin/tombi"
""")
        result = self.shell('install_node_bin tombi "$TOMBI_VERSION"')
        self.assertEqual(result.returncode, 0, result.stderr)

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
