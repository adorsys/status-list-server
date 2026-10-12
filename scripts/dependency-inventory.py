#!/usr/bin/env python3
"""Print declared dependencies and resolved pins (Python 3.11+, no installs/network).

Run from any directory. This is an inventory, not an assertion of freshness:
compare its output with upstream releases and the linked maintenance audit.
"""

import json
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def toml(path):
    return tomllib.loads((ROOT / path).read_text())


def inventory():
    result = []
    lock = toml("Cargo.lock")["package"]
    for manifest in ("Cargo.toml", "xtask/Cargo.toml"):
        data = toml(manifest)
        package = next(p for p in lock if p["name"] == data["package"]["name"])
        resolved = {}
        for dependency in package.get("dependencies", []):
            name, *version = dependency.split()
            resolved[name] = version[0] if version else next(
                p["version"] for p in lock if p["name"] == name
            )
        tables = [("", data), *data.get("target", {}).items()]
        for target, table in tables:
            for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
                for name, spec in table.get(kind, {}).items():
                    spec = {"version": spec} if isinstance(spec, str) else spec
                    result.append(dict(
                        ecosystem="cargo", manifest=manifest, name=name,
                        requirement=spec.get("version"), version=resolved.get(spec.get("package", name)),
                        kind=kind, target=target, optional=spec.get("optional", False),
                        features=spec.get("features", []),
                    ))
    for folder in ("artillery-tests", "scripts/local-ci/node"):
        manifest = f"{folder}/package.json"
        data = json.loads((ROOT / manifest).read_text())
        packages = json.loads((ROOT / folder / "package-lock.json").read_text())["packages"]
        for kind in ("dependencies", "devDependencies"):
            for name, requirement in data.get(kind, {}).items():
                result.append(dict(ecosystem="npm", manifest=manifest, name=name,
                                   requirement=requirement, kind=kind,
                                   version=packages[f"node_modules/{name}"]["version"]))
    packages = toml("demo/uv.lock")["package"]
    for requirement in toml("demo/pyproject.toml")["project"]["dependencies"]:
        name = re.split(r"[<>=!~;\[]", requirement)[0].lower().replace("_", "-")
        result.append(dict(ecosystem="uv", manifest="demo/pyproject.toml", name=name,
                           requirement=requirement,
                           versions=sorted({p["version"] for p in packages if p["name"] == name})))
    for line in (ROOT / "scripts/local-ci/requirements.txt").read_text().splitlines():
        if match := re.match(r"([\w.-]+)==([^\s]+)", line):
            result.append(dict(ecosystem="pip", manifest="scripts/local-ci/requirements.txt",
                               name=match[1], version=match[2]))
    for path in sorted((ROOT / ".github/workflows").rglob("*.yml")):
        for action, sha, tag in re.findall(r"uses: ([\w./-]+)@([a-f0-9]{40})\s*#\s*(\S+)", path.read_text()):
            result.append(dict(ecosystem="github-actions", manifest=str(path.relative_to(ROOT)),
                               name=action, version=tag, sha=sha))
    for filename in ("Dockerfile", "local-ci.sh"):
        for name, value in re.findall(r'^(?:ARG )?([A-Z_]+(?:VERSION|IMAGE))=["\']?([^\s"\']+)',
                                      (ROOT / filename).read_text(), re.MULTILINE):
            result.append(dict(ecosystem="tool", manifest=filename, name=name, version=value))
    for image in re.findall(r"^FROM (?:--platform=\S+ )?(\S+)", (ROOT / "Dockerfile").read_text(), re.MULTILINE):
        if "@sha256:" in image:
            result.append(dict(ecosystem="docker", manifest="Dockerfile", name=image.split("@")[0],
                               digest=image.split("@")[1]))
    return result


if __name__ == "__main__":
    print(json.dumps(inventory(), indent=2))
