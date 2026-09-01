#!/usr/bin/env python3
"""Validate .trivyignore.yaml before Trivy ever reads it.

Two problems this catches, both of which currently fail late and confusingly:

1. A malformed file. `.trivyignore.yaml` is read by the `trivy-config` job on every
   pull request and by the image scan in `deploy.yml` on every release. A YAML error
   or an unknown top-level key added under time pressure breaks pull request CI for
   the whole repository, and it surfaces as a scanner failure rather than as "you
   broke the ignore file".

2. An unexplained or immortal exception. An ignore entry suppresses a finding
   permanently and silently; that is the whole point of the file and also its
   hazard. Requiring a `statement` means a reader can tell why something was
   accepted, and requiring `expired_at` on vulnerability entries means the decision
   lapses instead of outliving the person who made it.

`expired_at` is required for `vulnerabilities` but not for `misconfigurations`. A
vulnerability exception is a claim about a changing world -- whether a fix exists,
whether the path is reachable -- so it rots and must be re-argued. A misconfiguration
exception here is a claim about a structural fact, that a path belongs to a
third-party subchart this repository does not control, which does not rot on a
schedule. Forcing a date on the latter produces churn without new information.

Exit status is 0 when the file is valid, 1 when it is not. Expired entries are
reported as warnings, not failures: an expired entry has already stopped suppressing
anything, so it is dead configuration rather than a broken gate.

`--expiring-within DAYS` additionally lists entries that lapse within that window, on
stdout, as `id<TAB>expired_at<TAB>days_remaining`. It does not change the exit status.
Validity and imminence are different questions: validity is checked on every pull
request, where a date three weeks out is not yet news, while imminence is asked by the
scheduled re-scan, which is the only thing that can give notice before an expiry lands
on a release instead of ahead of one.
"""

from __future__ import annotations

import argparse
import datetime
import pathlib
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - depends on the runner image
    sys.exit("PyYAML is required: pip install pyyaml")

# Trivy's documented ignore-file sections. Anything else is a typo that Trivy will
# accept and silently ignore, which is the failure mode worth catching here: a
# section named `vulnerability` suppresses nothing and looks like it works.
KNOWN_SECTIONS = {"vulnerabilities", "misconfigurations", "secrets", "licenses"}
EXPIRY_REQUIRED_IN = {"vulnerabilities"}

# Sections where an entry must name what it applies to. Every misconfiguration
# exception here is a claim about specific vendored subchart paths, and an entry with
# no scope applies the rule-wide -- the same repository-wide widening as the `path:`
# typo below, reached by omission rather than by misspelling.
#
# Not required for vulnerabilities: a scratch image holding one binary has no
# meaningful path to scope to, so an unscoped crate advisory is the intended form and
# demanding `paths: ["**"]` would be noise.
SCOPE_REQUIRED_IN = {"misconfigurations"}
SCOPE_KEYS = ("paths", "purls")

# Trivy silently ignores keys it does not recognise, which turns a one-character
# typo into a scope change rather than an error. `path:` instead of `paths:` leaves
# the entry with no path filter at all, and an entry with no paths applies
# everywhere -- so an exception written to cover one vendored subchart quietly
# starts suppressing that rule across the whole repository. Measured against this
# chart, the typo took KSV-0014 from 8 remaining findings to 0.
#
# This list is the complete set from Trivy's filtering documentation, verified
# rather than inferred: https://trivy.dev/latest/docs/configuration/filtering/
#
# It fails closed on purpose. If a future Trivy release adds a field, this script
# rejects it and pull request CI breaks until someone adds the name here. That is
# the intended trade for a file whose whole job is suppressing security findings:
# a build that stops is recoverable in minutes, a silently widened exception is not
# discovered at all. Do not relax this to a warning -- add the new field.
KNOWN_ENTRY_KEYS = {"id", "paths", "purls", "statement", "expired_at"}


def _load_document(path: pathlib.Path) -> tuple[dict | None, list[str]]:
    """Read and parse the ignore file.

    Returns `(doc, errors)`. `doc` is None when there is nothing to walk -- either
    because loading failed, in which case `errors` says why, or because the file is
    legitimately empty, in which case `errors` is empty too.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, [f"{path}: not found"]

    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return None, [f"{path}: not valid YAML: {exc}"]

    if doc is None:
        return None, []  # An empty ignore file is legitimate.
    if not isinstance(doc, dict):
        return None, [f"{path}: top level must be a mapping, found {type(doc).__name__}"]

    return doc, []


def _parse_expiry(value: object) -> tuple[datetime.date | None, str | None]:
    """Coerce an `expired_at` value to a date, or explain why it is not one.

    PyYAML parses an unquoted YYYY-MM-DD into a date; a quoted one stays a string.
    Trivy accepts both, so both are handled here. `datetime` is checked before `date`
    because it is a subclass of it.
    """
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
    """Vulnerability exceptions that lapse within `within_days` days, or already have.

    Returns `(id, expired_at, days_remaining)`, soonest first. `days_remaining` is
    negative for an entry that has already lapsed.

    Only `vulnerabilities` are considered, for the same reason only they require an
    `expired_at`: a misconfiguration exception is a claim about a structural fact and
    does not rot on a schedule.

    Malformed dates are skipped rather than guessed at. `check()` already rejects
    them, and this function's answer is only meaningful for a file that passed it.
    """
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

    # Under --expiring-within, stdout is the machine-readable channel, so the human
    # line moves aside rather than landing in the middle of the table.
    print(f"{path}: ok", file=sys.stderr if args.expiring_within is not None else sys.stdout)

    if args.expiring_within is not None:
        for identifier, expires, remaining in expiring_entries(path, args.expiring_within):
            print(f"{identifier}\t{expires.isoformat()}\t{remaining}")
            # Already-lapsed entries are warned about by check(); this covers the ones
            # that still suppress today and would otherwise first be noticed by
            # blocking a release.
            if remaining >= 0:
                print(
                    f"warning: {path}: {identifier}: 'expired_at' {expires} is "
                    f"{remaining} day(s) away; re-argue it before it lapses.",
                    file=sys.stderr,
                )

    return 0


if __name__ == "__main__":
    sys.exit(main())
