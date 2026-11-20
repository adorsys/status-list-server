"""The CRD check, the kind check and the runbook must pin the same Envoy Gateway release."""

from __future__ import annotations

import pathlib
import re
import unittest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_PINS = {
    "scripts/validate-envoy-gateway-crds.sh": r"^EG_VERSION=(v\d+\.\d+\.\d+)$",
    "scripts/check-envoy-gateway-kind.sh": r'^EG_VERSION="\$\{EG_VERSION:-(v\d+\.\d+\.\d+)\}"$',
    "docs/deployment-runbook.md": r"oci://docker\.io/envoyproxy/gateway-helm --version (v\d+\.\d+\.\d+)",
}


class EnvoyGatewayPinTest(unittest.TestCase):
    def test_every_pin_names_the_same_release(self) -> None:
        versions = {}
        for path, pattern in _PINS.items():
            text = (_REPO_ROOT / path).read_text(encoding="utf-8")
            found = re.findall(pattern, text, re.MULTILINE)
            self.assertTrue(found, f"no Envoy Gateway version pin in {path}")
            versions.update((f"{path} #{index}", version) for index, version in enumerate(found, 1))
        self.assertEqual(len(set(versions.values())), 1, versions)


if __name__ == "__main__":
    unittest.main()
