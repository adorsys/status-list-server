"""The legacy key must be adopted only after migration assigns its aggregation ID."""

import base64
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest


_ROOT = pathlib.Path(__file__).resolve().parents[2]
_FIXTURE = _ROOT / "scripts/generate-direct-upgrade-fixture.js"
_ID = "11111111-1111-4111-8111-111111111111"


@unittest.skipIf(shutil.which("node") is None, "Node.js is required")
class DirectUpgradeFixtureTest(unittest.TestCase):
    def test_registry_adopts_migrated_id_and_token_uses_legacy_kid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            def generate(*args: str) -> None:
                subprocess.run(
                    ["node", str(_FIXTURE), args[0], directory, *args[1:]],
                    check=True, cwd=_ROOT,
                )

            generate("prepare")
            registry_path = pathlib.Path(directory) / "issuers.yaml"
            self.assertEqual(json.loads(registry_path.read_text())["issuers"], [])

            generate("registry", _ID)
            registry = json.loads(registry_path.read_text())
            issuer = registry["issuers"][0]
            self.assertEqual(issuer["aggregation_id"], _ID)
            self.assertEqual(issuer["keys"][0]["kid"], "upgrade-fixture-key")

            generate("token")
            token = (pathlib.Path(directory) / "token").read_text()
            header, payload, _ = token.split(".")
            def decode(value: str) -> dict:
                return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))

            self.assertEqual(decode(header)["kid"], issuer["keys"][0]["kid"])
            self.assertEqual(decode(payload)["iss"], issuer["id"])
