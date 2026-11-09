"""Exercise the deploy workflow's SecretStore guard with cluster responses."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/deploy.yml"


class SecretStorePreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow = yaml.safe_load(WORKFLOW.read_text())
        steps = workflow["jobs"]["deploy"]["steps"]
        script = next(
            step["run"] for step in steps if step.get("name") == "Check existing SecretStore before upgrade"
        )
        cls.script = script.replace("${{ env.HELM_NAMESPACE }}", "statuslist").replace(
            "${{ env.HELM_RELEASE_NAME }}", "statuslist"
        )

    def run_preflight(self, store):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "store.json"
            fixture.write_text("" if store is None else json.dumps(store))
            kubectl = root / "kubectl"
            kubectl.write_text('#!/bin/sh\ncat "$STORE_FIXTURE"\n')
            kubectl.chmod(0o755)
            env = {
                **os.environ,
                "PATH": f"{root}:{os.environ['PATH']}",
                "RUNNER_TEMP": directory,
                "STORE_FIXTURE": str(fixture),
            }
            return subprocess.run(
                ["bash", "-c", self.script], env=env, capture_output=True, text=True
            )

    @staticmethod
    def expected_store():
        return {
            "metadata": {
                "labels": {"app.kubernetes.io/managed-by": "Helm"},
                "annotations": {
                    "meta.helm.sh/release-name": "statuslist",
                    "meta.helm.sh/release-namespace": "statuslist",
                },
            },
            "spec": {
                "provider": {"aws": {"region": "eu-central-1", "service": "SecretsManager"}}
            },
        }

    def test_missing_store_can_be_created(self):
        self.assertEqual(self.run_preflight(None).returncode, 0)

    def test_matching_store_can_be_upgraded(self):
        self.assertEqual(self.run_preflight(self.expected_store()).returncode, 0)

    def test_other_release_is_rejected(self):
        store = self.expected_store()
        store["metadata"]["annotations"]["meta.helm.sh/release-name"] = "other"
        result = self.run_preflight(store)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not owned", result.stdout)

    def test_custom_auth_is_rejected_before_chart_replaces_it(self):
        store = self.expected_store()
        store["spec"]["provider"]["aws"]["auth"] = {
            "secretRef": {"accessKeyIDSecretRef": {"name": "aws-key"}}
        }
        result = self.run_preflight(store)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("provider settings", result.stdout)


if __name__ == "__main__":
    unittest.main()
