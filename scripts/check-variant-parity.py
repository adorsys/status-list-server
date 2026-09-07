#!/usr/bin/env python3
"""Assert every workflow that enumerates the image variants enumerates the same ones.

The variant list is structurally duplicated. `deploy.yml` names it three times -- once
per matrix in `build-and-push`, `scan-image` and `promote-tags` -- because GitHub does
not expose the `env` context to `strategy`, so a matrix cannot read a shared value.
`scheduled-image-scan.yml` names it a fourth time for the same reason.

The drift that creates is asymmetric, and only one direction is visible:

- Forget a matrix in `deploy.yml` and the variant is never built or promoted. The next
  release fails loudly, or ships an obviously missing image.
- Forget the list in `scheduled-image-scan.yml` and the variant is built, promoted and
  deployed, and then **never re-scanned**. Nothing fails. The nightly stays green and
  reports on the variants it does know about, which is indistinguishable from covering
  everything.

The second is the one worth a script. A green nightly that silently excludes a
published variant is exactly the absence-reads-as-success failure the re-scan exists
to prevent, reached through the one gap the re-scan cannot see: it has no way to know
what it was supposed to cover.

Run on every pull request, so drift is caught by whoever adds the variant rather than
by nobody at 03:37 the following night.

Exit status is 0 when every source agrees, 1 otherwise.

Usage: check-variant-parity.py [--deploy PATH] [--scheduled PATH]
"""

from __future__ import annotations

import argparse
import pathlib
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - depends on the runner image
    sys.exit("PyYAML is required: pip install pyyaml")

# The matrices in deploy.yml that must enumerate every variant. `deploy` is absent on
# purpose: it deploys one variant chosen by `vars.IMAGE_VARIANT`, it does not fan out.
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
    """The variant suffixes each fan-out matrix in deploy.yml enumerates."""
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
            # Every matrix entry is a mapping carrying at least `suffix`; a bare string
            # would mean the matrix shape changed and this comparison is now guessing.
            if not isinstance(entry, dict) or not entry.get("suffix"):
                errors.append(f"{path}: {job}.strategy.matrix.variant[{index}] has no 'suffix'")
                continue
            suffixes.add(str(entry["suffix"]))

        if suffixes:
            found[f"{path.name}:{job}"] = suffixes

    return found, errors


def scheduled_variants(path: pathlib.Path) -> tuple[dict[str, set[str]], list[str]]:
    """The variant list the scheduled re-scan publishes to its matrix.

    Read from the `VARIANTS` step environment rather than from a matrix, because the
    scheduled workflow resolves its matrix at runtime from this one space-separated
    value -- which is the whole reason it can drift from deploy.yml unnoticed.
    """
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
    """Every source must enumerate the same set. Reports each disagreement by name."""
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

    # Only compare once every list was read. Comparing a partial set would report a
    # spurious disagreement on top of the real "could not read it" error.
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
