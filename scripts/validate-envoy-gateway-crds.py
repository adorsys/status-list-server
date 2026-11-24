#!/usr/bin/env python3
"""Validate rendered Gateway API and Envoy Gateway resources against pinned CRDs, rejecting unknown fields."""

from __future__ import annotations

import copy
import sys
from collections import Counter
from pathlib import Path

import yaml

GROUPS = ("gateway.networking.k8s.io", "gateway.envoyproxy.io")
MINIMUM = {
    ("rendered", "HTTPRoute"): 2,
    ("rendered", "BackendTrafficPolicy"): 2,
    ("rendered", "BackendTrafficPolicy with global rules"): 2,
    ("platform", "GatewayClass"): 1,
    ("platform", "EnvoyProxy"): 1,
    ("platform", "Gateway"): 1,
    ("platform", "ClientTrafficPolicy"): 1,
}
Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


class CheckError(Exception):
    pass


def documents(text: str) -> list[dict]:
    return [doc for doc in yaml.load_all(text, Loader=Loader) if isinstance(doc, dict)]


def api_group(doc: dict) -> str:
    return str(doc.get("apiVersion", "")).rpartition("/")[0]


# Without strict field validation the API server drops unknown fields, so close every object schema.
def close(schema: dict, where: str) -> None:
    if schema.get("x-kubernetes-embedded-resource"):
        raise CheckError(f"{where} embeds a resource, which this check does not model")
    for field, child in schema.get("properties", {}).items():
        close(child, f"{where}.{field}")
    # Not into anyOf, allOf, oneOf or not: their partial property lists would reject valid fields.
    for key, suffix in (("items", "[]"), ("additionalProperties", ".*")):
        if isinstance(schema.get(key), dict):
            close(schema[key], where + suffix)
    if (
        "properties" in schema
        and "additionalProperties" not in schema
        and not schema.get("x-kubernetes-preserve-unknown-fields")
    ):
        schema["additionalProperties"] = False


class Schemas:
    def __init__(self, crd_dir: Path, validator: type) -> None:
        self.versions: dict[tuple[str, str], list[dict]] = {}
        for path in sorted(crd_dir.glob("*.yaml")):
            for doc in documents(path.read_text(encoding="utf-8")):
                if doc.get("kind") == "CustomResourceDefinition":
                    spec = doc["spec"]
                    self.versions[spec["group"], spec["names"]["kind"]] = spec["versions"]
        self.validator = validator
        self.validators: dict[tuple[str, str, str], object] = {}

    def problems(self, doc: dict) -> list[str]:
        group, _, version = str(doc.get("apiVersion", "")).rpartition("/")
        kind = doc.get("kind")
        served = [v for v in self.versions.get((group, kind), []) if v.get("served")]
        if not served:
            return [f"no served {kind} CRD in {group}"]
        match = next((v for v in served if v["name"] == version), None)
        if match is None:
            return [f"{version} is not served, only {[v['name'] for v in served]}"]
        key = (group, kind, version)
        if key not in self.validators:
            schema = match["schema"]["openAPIV3Schema"]
            close(schema, f"{kind} {version}")
            self.validators[key] = self.validator(schema)
        errors = sorted(self.validators[key].iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path])
        return [f"{list(e.absolute_path)} -> {e.message}" for e in errors]


def gateway_documents(rendered: Path, platform: Path) -> list[tuple[str, Path, dict]]:
    found = []
    for path in sorted(rendered.rglob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        if any(group in text for group in GROUPS):
            found += [("rendered", path.relative_to(rendered), doc) for doc in documents(text)]
    found += [("platform", platform, doc) for doc in documents(platform.read_text(encoding="utf-8"))]
    return [(source, path, doc) for source, path, doc in found if api_group(doc) in GROUPS]


def self_test(schemas: Schemas, policy: dict) -> None:
    policy = copy.deepcopy(policy)
    spec = policy["spec"]
    rule = (((spec.get("rateLimit") or {}).get("local") or {}).get("rules") or [{}])[0]
    # Optional fields, so only the closed schemas can catch these misspellings.
    misspellings = ((spec, "responseOverride", "responseOverrides"), (rule, "xRateLimitHeaders", "xRateLimitHeader"))
    for owner, field, typo in misspellings:
        if field not in owner:
            raise CheckError(f"the self-test needs {field} in the rendered BackendTrafficPolicy")
        owner[typo] = owner.pop(field)
    reported = " ".join(schemas.problems(policy))
    missed = [typo for _, _, typo in misspellings if f"'{typo}'" not in reported]
    if missed:
        raise CheckError(f"the closed schemas accept the misspelled {missed}, so this check would pass typos")


def main(argv: list[str]) -> None:
    if len(argv) != 5:
        raise CheckError(f"usage: {argv[0]} VERSION CRD_DIR RENDERED_DIR PLATFORM_FILE")
    # Imported here so the unit tests need only PyYAML.
    from jsonschema import Draft7Validator

    version = argv[1]
    crd_dir, rendered, platform = (Path(arg) for arg in argv[2:])
    schemas = Schemas(crd_dir, Draft7Validator)
    inputs = gateway_documents(rendered, platform)
    seen: Counter[tuple[str, str]] = Counter()
    failures = []
    for source, path, doc in inputs:
        kind = doc.get("kind")
        seen[source, kind] += 1
        if kind == "BackendTrafficPolicy" and "global" in ((doc.get("spec") or {}).get("rateLimit") or {}):
            seen[source, "BackendTrafficPolicy with global rules"] += 1
        name = (doc.get("metadata") or {}).get("name")
        failures += [f"{path} {kind}/{name} {problem}" for problem in schemas.problems(doc)]
    for failure in failures:
        print("INVALID:", failure)
    if failures:
        raise CheckError(f"gateway resources fail the pinned Envoy Gateway {version} CRD schemas")

    short = {f"{source} {kind}": seen[source, kind] for (source, kind), least in MINIMUM.items() if seen[source, kind] < least}
    if short:
        raise CheckError(f"fewer gateway resources than expected, so a render may have moved: {short}")
    self_test(schemas, next(doc for source, _, doc in inputs if source == "rendered" and doc["kind"] == "BackendTrafficPolicy"))
    print(f"{len(inputs)} gateway resources validate against the pinned Envoy Gateway {version} CRDs")


if __name__ == "__main__":
    try:
        main(sys.argv)
    except CheckError as error:
        sys.exit(f"ERROR: {error}")
