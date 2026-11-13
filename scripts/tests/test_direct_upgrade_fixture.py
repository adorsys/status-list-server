"""The pre-upgrade registry and legacy row use the same disposable issuer key."""

import base64
import hashlib
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
    def test_registry_precedes_migration_and_token_uses_exported_kid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            def generate(*args: str) -> None:
                subprocess.run(
                    ["node", str(_FIXTURE), args[0], directory, *args[1:]],
                    check=True, cwd=_ROOT,
                )

            generate("prepare")
            registry_path = pathlib.Path(directory) / "issuers.yaml"
            registry = json.loads(registry_path.read_text())
            issuer = registry["issuers"][0]
            self.assertEqual(issuer["aggregation_id"], _ID)
            jwk = json.loads((pathlib.Path(directory) / "public-jwk.json").read_text())
            self.assertEqual(issuer["keys"][0]["kid"], jwk["kid"])
            canonical = json.dumps({field: jwk[field] for field in ("crv", "kty", "x", "y")}, separators=(",", ":"))
            thumbprint = base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode()
            self.assertEqual(jwk["kid"], thumbprint)

            generate("token")
            token = (pathlib.Path(directory) / "token").read_text()
            header, payload, _ = token.split(".")
            def decode(value: str) -> dict:
                return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))

            self.assertEqual(decode(header)["kid"], issuer["keys"][0]["kid"])
            self.assertEqual(decode(payload)["iss"], issuer["id"])
