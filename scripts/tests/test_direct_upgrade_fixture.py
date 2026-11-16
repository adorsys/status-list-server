"""The pre-upgrade rows use unique disposable keys for registry export."""

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
_CHECK_ID = _ROOT / "scripts/assert-direct-upgrade-issuer-id.sh"


@unittest.skipIf(shutil.which("node") is None, "Node.js is required")
class DirectUpgradeFixtureTest(unittest.TestCase):
    def test_keys_are_distinct_and_token_uses_exported_kid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            def generate(*args: str) -> None:
                subprocess.run(
                    ["node", str(_FIXTURE), args[0], directory, *args[1:]],
                    check=True, cwd=_ROOT,
                )

            generate("prepare")
            jwk = json.loads((pathlib.Path(directory) / "public-jwk.json").read_text())
            canonical = json.dumps({field: jwk[field] for field in ("crv", "kty", "x", "y")}, separators=(",", ":"))
            thumbprint = base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode()
            self.assertEqual(jwk["kid"], thumbprint)
            keys = [jwk] + [json.loads((pathlib.Path(directory) / f"load-{n}-public-jwk.json").read_text()) for n in range(1, 4)]
            self.assertNotIn("kid", keys[1])
            self.assertEqual(len({(key["x"], key["y"]) for key in keys}), 4)
            self.assertEqual(len({key["kid"] for key in keys if "kid" in key}), 3)
            self.assertFalse((pathlib.Path(directory) / "issuers.yaml").exists())

            generate("token")
            token = (pathlib.Path(directory) / "token").read_text()
            header, payload, _ = token.split(".")
            def decode(value: str) -> dict:
                return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))

            self.assertEqual(decode(header)["kid"], jwk["kid"])
            self.assertEqual(decode(payload)["iss"], "upgrade-fixture")

    @unittest.skipIf(shutil.which("yq") is None, "yq is required")
    def test_exported_aggregation_id_must_belong_to_issuer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = pathlib.Path(directory) / "issuers.yaml"
            registry.write_text(
                "issuers:\n"
                "  - id: upgrade-fixture\n    aggregation_id: fixture-id\n"
                "  - id: upgrade-load-1\n    aggregation_id: load-id\n"
            )

            def check(issuer: str, stored_id: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["bash", str(_CHECK_ID), str(registry), issuer, stored_id],
                    cwd=_ROOT, capture_output=True, text=True,
                )

            self.assertEqual(check("upgrade-fixture", "fixture-id").returncode, 0)
            self.assertNotEqual(check("upgrade-fixture", "load-id").returncode, 0)
            self.assertNotEqual(check("upgrade-load-2", "load-id").returncode, 0)
