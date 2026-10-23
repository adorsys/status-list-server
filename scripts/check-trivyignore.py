#!/usr/bin/env python3
"""Validate .trivyignore.yaml before Trivy reads it: malformed files and unexplained or immortal exceptions.
Vulnerabilities need expired_at (they rot); misconfigurations don't. Expired entries only warn.
--expiring-within DAYS prints id, expired_at and days left as TSV for the nightly scan.
"""

from __future__ import annotations

import argparse
import datetime
import pathlib
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - depends on the runner image
    sys.exit("PyYAML is required: pip install pyyaml")

# Trivy silently ignores unknown sections, so "vulnerability" would suppress nothing.
KNOWN_SECTIONS = {"vulnerabilities", "misconfigurations", "secrets", "licenses"}
EXPIRY_REQUIRED_IN = {"vulnerabilities"}

# An unscoped misconfiguration entry applies repo-wide; a one-binary image has no useful vuln path.
SCOPE_REQUIRED_IN = {"misconfigurations"}
SCOPE_KEYS = ("paths", "purls")

# Trivy ignores unknown keys, so path: for paths: widens an entry to the whole repo.
# Fails closed on new Trivy fields on purpose; add them here, don't relax this.
KNOWN_ENTRY_KEYS = {"id", "paths", "purls", "statement", "expired_at"}

# Same charset the nightly enforces on Trivy's IDs, since both reach a TSV stream and an issue body.
ID_PATTERN = re.compile(r"[A-Za-z0-9._-]+")


def _load_document(path: pathlib.Path) -> tuple[dict | None, list[str]]:
    """None with no errors means the file is legitimately empty."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, [f"{path}: not found"]

    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return None, [f"{path}: not valid YAML: {exc}"]

    if doc is None:
        return None, []
    if not isinstance(doc, dict):
        return None, [f"{path}: top level must be a mapping, found {type(doc).__name__}"]

    return doc, []


def _parse_expiry(value: object) -> tuple[datetime.date | None, str | None]:
    """Unquoted dates parse to date, quoted ones stay str; check datetime first, it subclasses date."""
    if isinstance(value, datetime.datetime):
        return value.date(), None
    if isinstance(value, str):
        try:
            return datetime.date.fromisoformat(value.strip()), None
        except ValueError:
            return None, f"'expired_at' is not a YYYY-MM-DD date: {value!r}"
    if isinstance(value, datetime.date):
        return value, None
    return None, f"'expired_at' is not a date: {value!r}"


def check(path: pathlib.Path) -> list[str]:
    errors: list[str] = []
    warnings: list[str] = []

    doc, load_errors = _load_document(path)
    if load_errors:
        return load_errors
    if doc is None:
        return []

    for section in sorted(set(doc) - KNOWN_SECTIONS):
        errors.append(
            f"{path}: unknown top-level key {section!r}; "
            f"Trivy reads only {', '.join(sorted(KNOWN_SECTIONS))}, "
            f"so entries under {section!r} suppress nothing"
        )

    today = datetime.date.today()

    for section in sorted(set(doc) & KNOWN_SECTIONS):
        entries = doc[section]
        if entries is None:
            continue
        if not isinstance(entries, list):
            errors.append(f"{path}: {section} must be a list, found {type(entries).__name__}")
            continue

        for index, entry in enumerate(entries):
            where = f"{path}: {section}[{index}]"

            if not isinstance(entry, dict):
                errors.append(f"{where}: must be a mapping, found {type(entry).__name__}")
                continue

            identifier = entry.get("id")
            if not identifier or not str(identifier).strip():
                errors.append(f"{where}: missing 'id'")
            elif not ID_PATTERN.fullmatch(str(identifier)):
                # These IDs end up in a TSV stream and an issue body, so tabs, newlines and Markdown are refused.
                errors.append(
                    f"{where}: 'id' must match {ID_PATTERN.pattern} -- letters, digits, "
                    f"dot, underscore and hyphen. Got {identifier!r}."
                )
            else:
                where = f"{path}: {section}[{index}] ({identifier})"

            for key in sorted(set(entry) - KNOWN_ENTRY_KEYS):
                hint = ""
                if key == "path":
                    hint = " Did you mean 'paths'? An entry with no 'paths' applies everywhere."
                errors.append(
                    f"{where}: unknown key {key!r}. Trivy ignores unrecognised keys, so "
                    f"this does not do what it looks like.{hint}"
                )

            statement = entry.get("statement")
            if not statement or not str(statement).strip():
                errors.append(
                    f"{where}: missing 'statement'. Record why this is accepted "
                    f"and what would change that."
                )

            present_scopes = [key for key in SCOPE_KEYS if key in entry]

            if section in SCOPE_REQUIRED_IN and not present_scopes:
                errors.append(
                    f"{where}: no 'paths' or 'purls'. An unscoped entry suppresses "
                    f"this rule everywhere, not just where it was argued. Use "
                    f"paths: ['**'] if that is genuinely intended."
                )

            for key in present_scopes:
                value = entry[key]
                if not isinstance(value, list) or not value:
                    errors.append(
                        f"{where}: '{key}' must be a non-empty list. An empty one "
                        f"leaves the entry unscoped, which suppresses everywhere."
                    )
                elif any(not isinstance(item, str) or not item.strip() for item in value):
                    errors.append(
                        f"{where}: '{key}' contains an empty or non-string element."
                    )

            if section not in EXPIRY_REQUIRED_IN:
                continue

            expires = entry.get("expired_at")
            if expires is None:
                errors.append(
                    f"{where}: missing 'expired_at'. Without it the exception "
                    f"becomes permanent and nobody revisits it."
                )
                continue

            expires, problem = _parse_expiry(expires)
            if problem is not None:
                errors.append(f"{where}: {problem}")
                continue

            if expires <= today:
                warnings.append(
                    f"{where}: 'expired_at' {expires} has passed; this entry no longer "
                    f"suppresses anything and should be re-argued or removed"
                )

    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)

    return errors


def expiring_entries(
    path: pathlib.Path, within_days: int
) -> list[tuple[str, datetime.date, int]]:
    """(id, expired_at, days_remaining), soonest first; negative days means already lapsed."""
    doc, _ = _load_document(path)
    if doc is None:
        return []

    today = datetime.date.today()
    found: list[tuple[str, datetime.date, int]] = []

    for section in sorted(set(doc) & EXPIRY_REQUIRED_IN):
        entries = doc[section]
        if not isinstance(entries, list):
            continue

        for entry in entries:
            if not isinstance(entry, dict) or "expired_at" not in entry:
                continue

            expires, problem = _parse_expiry(entry["expired_at"])
            if problem is not None:
                continue

            remaining = (expires - today).days
            if remaining <= within_days:
                found.append((str(entry.get("id") or "<no id>"), expires, remaining))

    return sorted(found, key=lambda item: item[1])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate .trivyignore.yaml before Trivy ever reads it."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".trivyignore.yaml",
        type=pathlib.Path,
        help="the ignore file to validate (default: .trivyignore.yaml)",
    )
    parser.add_argument(
        "--expiring-within",
        type=int,
        metavar="DAYS",
        help=(
            "also list vulnerability exceptions lapsing within DAYS days, on stdout, "
            "as id<TAB>expired_at<TAB>days_remaining. Does not affect exit status."
        ),
    )
    args = parser.parse_args()
    path = args.path

    # A negative window would only list lapsed entries and read as "nothing soon".
    if args.expiring_within is not None and args.expiring_within < 0:
        parser.error("--expiring-within takes a non-negative number of days")

    errors = check(path)

    for error in errors:
        print(f"error: {error}", file=sys.stderr)

    if errors:
        print(
            f"\n{len(errors)} problem(s) in {path}. "
            f"See docs/supply-chain.md for the exception format.",
            file=sys.stderr,
        )
        return 1

    # stdout is the TSV channel under --expiring-within.
    print(f"{path}: ok", file=sys.stderr if args.expiring_within is not None else sys.stdout)

    if args.expiring_within is not None:
        for identifier, expires, remaining in expiring_entries(path, args.expiring_within):
            print(f"{identifier}\t{expires.isoformat()}\t{remaining}")
            if remaining >= 0:
                print(
                    f"warning: {path}: {identifier}: 'expired_at' {expires} is "
                    f"{remaining} day(s) away; re-argue it before it lapses.",
                    file=sys.stderr,
                )

    return 0


if __name__ == "__main__":
    sys.exit(main())
