#!/usr/bin/env python3
"""Fail if the workflows that list image variants disagree.
A variant missing from scheduled-image-scan.yml would deploy but never be re-scanned, silently.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - depends on the runner image
    sys.exit("PyYAML is required: pip install pyyaml")

# deploy is left out: it ships one variant and doesn't fan out.
DEPLOY_MATRIX_JOBS = ("build-and-push", "scan-image", "promote-tags")


def _load(path: pathlib.Path) -> tuple[dict | None, str | None]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, f"{path}: not found"

    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return None, f"{path}: not valid YAML: {exc}"

    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        return None, f"{path}: no 'jobs' mapping; this does not look like a workflow"

    return doc, None


def deploy_variants(path: pathlib.Path) -> tuple[dict[str, set[str]], list[str]]:
    doc, problem = _load(path)
    if problem is not None:
        return {}, [problem]

    found: dict[str, set[str]] = {}
    errors: list[str] = []

    for job in DEPLOY_MATRIX_JOBS:
        definition = doc["jobs"].get(job)
        if not isinstance(definition, dict):
            errors.append(f"{path}: job {job!r} is missing; the matrices cannot be compared")
            continue

        entries = (
            definition.get("strategy", {}).get("matrix", {}).get("variant")
            if isinstance(definition.get("strategy"), dict)
            else None
        )
        if not isinstance(entries, list) or not entries:
            errors.append(f"{path}: job {job!r} has no 'strategy.matrix.variant' list")
            continue

        suffixes = set()
        for index, entry in enumerate(entries):
            # A bare string means the matrix shape changed; refuse to guess.
            if not isinstance(entry, dict) or not entry.get("suffix"):
                errors.append(f"{path}: {job}.strategy.matrix.variant[{index}] has no 'suffix'")
                continue
            suffixes.add(str(entry["suffix"]))

        if suffixes:
            found[f"{path.name}:{job}"] = suffixes

    return found, errors


def scheduled_variants(path: pathlib.Path) -> tuple[dict[str, set[str]], list[str]]:
    """Read from the VARIANTS step env: the nightly builds its matrix from it at runtime."""
    doc, problem = _load(path)
    if problem is not None:
        return {}, [problem]

    for job_name, definition in doc["jobs"].items():
        if not isinstance(definition, dict):
            continue
        for step in definition.get("steps") or []:
            if not isinstance(step, dict):
                continue
            value = (step.get("env") or {}).get("VARIANTS")
            if value is None:
                continue
            names = set(str(value).split())
            if not names:
                return {}, [f"{path}: job {job_name!r} declares an empty VARIANTS list"]
            return {f"{path.name}:{job_name}": names}, []

    return {}, [
        f"{path}: no step declares a 'VARIANTS' environment variable, so the "
        f"scheduled re-scan's variant list could not be found"
    ]


def compare(sources: dict[str, set[str]]) -> list[str]:
    if len(sources) < 2:
        return ["fewer than two variant lists were found; there is nothing to compare"]

    reference_name, reference = sorted(sources.items())[0]
    errors: list[str] = []

    for name, names in sorted(sources.items()):
        if names == reference:
            continue
        missing = sorted(reference - names)
        extra = sorted(names - reference)
        detail = []
        if missing:
            detail.append(f"missing {', '.join(missing)}")
        if extra:
            detail.append(f"unexpected {', '.join(extra)}")
        errors.append(f"{name} disagrees with {reference_name}: {'; '.join(detail)}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Assert every workflow enumerating image variants agrees."
    )
    parser.add_argument(
        "--deploy",
        type=pathlib.Path,
        default=pathlib.Path(".github/workflows/deploy.yml"),
    )
    parser.add_argument(
        "--scheduled",
        type=pathlib.Path,
        default=pathlib.Path(".github/workflows/scheduled-image-scan.yml"),
    )
    args = parser.parse_args()

    sources, errors = deploy_variants(args.deploy)
    scheduled, scheduled_errors = scheduled_variants(args.scheduled)
    sources.update(scheduled)
    errors.extend(scheduled_errors)

    # Comparing a partial set would add a spurious mismatch.
    if not errors:
        errors.extend(compare(sources))

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        print(
            "\nThe image variant list is duplicated across workflows because GitHub "
            "does not expose the `env` context to `strategy.matrix`. Add the variant "
            "everywhere it is enumerated, or the scheduled re-scan will silently stop "
            "covering it.",
            file=sys.stderr,
        )
        return 1

    names = ", ".join(sorted(next(iter(sources.values()))))
    print(f"variant parity ok across {len(sources)} lists: {names}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
