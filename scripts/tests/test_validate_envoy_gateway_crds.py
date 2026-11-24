"""Tests for how scripts/validate-envoy-gateway-crds.py closes CRD schemas."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "validate_envoy_gateway_crds", _ROOT / "scripts" / "validate-envoy-gateway-crds.py"
)
assert _SPEC and _SPEC.loader
crds = importlib.util.module_from_spec(_SPEC)
sys.modules["validate_envoy_gateway_crds"] = crds
_SPEC.loader.exec_module(crds)


def _object(**properties: dict) -> dict:
    return {"type": "object", "properties": properties}


_STRING = {"type": "string"}


class CloseTest(unittest.TestCase):
    def test_closes_objects_at_every_depth(self) -> None:
        limit = _object(requests={"type": "integer"})
        rule = _object(limit=limit)
        spec = _object(rules={"type": "array", "items": rule})
        root = _object(spec=spec)
        crds.close(root, "root")
        for schema in (root, spec, rule, limit):
            self.assertIs(schema["additionalProperties"], False)

    def test_closes_the_values_of_a_map(self) -> None:
        value = _object(name=_STRING)
        crds.close(_object(byName={"type": "object", "additionalProperties": value}), "root")
        self.assertIs(value["additionalProperties"], False)

    def test_keeps_an_additional_properties_that_is_already_set(self) -> None:
        labels = {"type": "object", "additionalProperties": _STRING}
        open_object = dict(_object(name=_STRING), additionalProperties=True)
        crds.close(_object(labels=labels, open=open_object), "root")
        self.assertEqual(labels["additionalProperties"], _STRING)
        self.assertIs(open_object["additionalProperties"], True)

    def test_leaves_preserved_unknown_fields_open(self) -> None:
        patch = dict(_object(type=_STRING), **{"x-kubernetes-preserve-unknown-fields": True})
        crds.close(_object(patch=patch), "root")
        self.assertNotIn("additionalProperties", patch)

    def test_leaves_combinator_branches_open(self) -> None:
        branch = _object(inline=_STRING)
        body = dict(_object(inline=_STRING, valueRef=_STRING), anyOf=[branch])
        crds.close(_object(body=body), "root")
        self.assertNotIn("additionalProperties", branch)
        self.assertIs(body["additionalProperties"], False)

    def test_refuses_an_embedded_resource(self) -> None:
        schema = _object(template={"type": "object", "x-kubernetes-embedded-resource": True})
        with self.assertRaisesRegex(crds.CheckError, r"^root\.template embeds a resource"):
            crds.close(schema, "root")


if __name__ == "__main__":
    unittest.main()
