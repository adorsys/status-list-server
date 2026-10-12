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
    for folder in ("perf", "scripts/local-ci/node"):
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
    # Image references are maintained in Dockerfiles, Compose, Helm values,
    # scripts, and workflow commands. Record their source locations rather than
    # only the application Dockerfile's FROM lines.
    candidate_files = [ROOT / "Dockerfile", ROOT / "docker-compose.yml", ROOT / "local-ci.sh"]
    candidate_files += sorted((ROOT / ".github/workflows").rglob("*.yml"))
    candidate_files += sorted((ROOT / "scripts").rglob("*.sh"))
    candidate_files += sorted((ROOT / "deploy/helm/chart").rglob("*.yaml"))
    candidate_files += sorted((ROOT / "deploy/helm/chart").rglob("*.yml"))
    image_value = re.compile(r"\b(?:FROM\s+(?:--platform=\S+\s+)?|image:\s*)([^\s#]+)")
    image_assignment = re.compile(r"^[A-Z][A-Z0-9_]*_IMAGE=[\"']?([^\"'\s]+)")
    seen = set()
    for path in candidate_files:
        for line_number, line in enumerate(path.read_text().splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            candidates = [match.group(1) for match in image_value.finditer(line)]
            if assignment := image_assignment.search(line):
                candidates.append(assignment.group(1))
            # Shell commands sometimes put the immutable ref on a continuation
            # line after `docker run`; include only tagged or digest-pinned refs.
            candidates.extend(match.group(1) for match in re.finditer(
                r"(?<![A-Za-z0-9_./-])((?:[A-Za-z0-9.-]+(?::[0-9]+)?/)+"
                r"[A-Za-z0-9][A-Za-z0-9._-]*:[A-Za-z0-9_][A-Za-z0-9_.-]*"
                r"(?:@sha256:[a-fA-F0-9]{64})?)", line))
            for image in candidates:
                image = image.rstrip(".,;\"'")
                if image.startswith(("/", "./", "$")):
                    continue
                if not ("/" in image or image.startswith(("busybox:", "postgres:", "mysql:", "redis:", "alpine:"))):
                    continue
                if not (":" in image.rsplit("/", 1)[-1] or "@sha256:" in image):
                    continue
                key = (str(path.relative_to(ROOT)), line_number, image)
                if key in seen:
                    continue
                seen.add(key)
                name, _, digest = image.partition("@")
                result.append(dict(ecosystem="docker", manifest=str(path.relative_to(ROOT)),
                                   line=line_number, name=name, digest=digest or None))
    return result


if __name__ == "__main__":
    print(json.dumps(inventory(), indent=2))
