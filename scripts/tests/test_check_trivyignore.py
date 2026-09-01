"""Tests for scripts/check-trivyignore.py.

The script decides which security findings may be suppressed, so every rejection
path needs to be exercised. An untested validator guarding an ignore file has the
same problem as an untested vulnerability gate: it looks identical whether it works
or does nothing.

Run: python3 -m unittest discover -s scripts/tests -t .
"""

from __future__ import annotations

import datetime
import importlib.util
import pathlib
import sys
import tempfile
import unittest

_SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "check-trivyignore.py"
_SPEC = importlib.util.spec_from_file_location("check_trivyignore", _SCRIPT)
assert _SPEC and _SPEC.loader
checker = importlib.util.module_from_spec(_SPEC)
sys.modules["check_trivyignore"] = checker
_SPEC.loader.exec_module(checker)


class CheckTrivyignoreTest(unittest.TestCase):
    def check(self, text: str) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / ".trivyignore.yaml"
            path.write_text(text, encoding="utf-8")
            return checker.check(path)

    def assertRejects(self, text: str, needle: str) -> None:
        errors = self.check(text)
        self.assertTrue(errors, f"expected a rejection mentioning {needle!r}")
        self.assertTrue(
            any(needle in error for error in errors),
            f"expected {needle!r} in {errors}",
        )

    # --- accepted shapes -------------------------------------------------

    def test_repository_file_is_valid(self):
        repo_file = pathlib.Path(__file__).resolve().parents[2] / ".trivyignore.yaml"
        self.assertEqual(checker.check(repo_file), [])

    def test_empty_file_is_valid(self):
        self.assertEqual(self.check(""), [])

    def test_scoped_misconfiguration_is_valid(self):
        self.assertEqual(
            self.check(
                """
                misconfigurations:
                  - id: AVD-KSV-0014
                    statement: Vendored subchart this repository does not author.
                    paths:
                      - "*/charts/postgres*/**"
                """
            ),
            [],
        )

    def test_unscoped_vulnerability_is_valid(self):
        # A scratch image has no meaningful path to scope a crate advisory to.
        self.assertEqual(
            self.check(
                """
                vulnerabilities:
                  - id: RUSTSEC-0000-0000
                    statement: Affects the async path; this binary uses the blocking API.
                    expired_at: 2999-01-01
                """
            ),
            [],
        )

    def test_quoted_and_unquoted_dates_both_accepted(self):
        for value in ("2999-01-01", '"2999-01-01"'):
            with self.subTest(value=value):
                self.assertEqual(
                    self.check(
                        f"""
                        vulnerabilities:
                          - id: RUSTSEC-0000-0000
                            statement: Not reachable.
                            expired_at: {value}
                        """
                    ),
                    [],
                )

    def test_duplicate_ids_are_allowed(self):
        # The same rule legitimately appears twice scoped to different paths.
        self.assertEqual(
            self.check(
                """
                misconfigurations:
                  - id: AVD-KSV-0014
                    statement: Postgres subchart.
                    paths: ["*/charts/postgres*/**"]
                  - id: AVD-KSV-0014
                    statement: Redis subchart.
                    paths: ["*/charts/redis-ha*/**"]
                """
            ),
            [],
        )

    def test_expired_entry_warns_but_does_not_fail(self):
        # An expired entry has already stopped suppressing anything.
        self.assertEqual(
            self.check(
                """
                vulnerabilities:
                  - id: RUSTSEC-0000-0000
                    statement: Was accepted, now lapsed.
                    expired_at: 2000-01-01
                """
            ),
            [],
        )

    # --- rejected shapes -------------------------------------------------

    def test_rejects_invalid_yaml(self):
        self.assertRejects("vulnerabilities: [\n", "not valid YAML")

    def test_rejects_non_mapping_top_level(self):
        self.assertRejects("- just\n- a\n- list\n", "top level must be a mapping")

    def test_rejects_unknown_section(self):
        # `vulnerability` parses fine and suppresses nothing.
        self.assertRejects(
            """
            vulnerability:
              - id: RUSTSEC-0000-0000
            """,
            "unknown top-level key",
        )

    def test_rejects_non_list_section(self):
        self.assertRejects("vulnerabilities: not-a-list\n", "must be a list")

    def test_rejects_non_mapping_entry(self):
        self.assertRejects("vulnerabilities:\n  - RUSTSEC-0000-0000\n", "must be a mapping")

    def test_rejects_missing_id(self):
        self.assertRejects(
            """
            vulnerabilities:
              - statement: No identifier.
                expired_at: 2999-01-01
            """,
            "missing 'id'",
        )

    def test_rejects_missing_statement(self):
        self.assertRejects(
            """
            vulnerabilities:
              - id: RUSTSEC-0000-0000
                expired_at: 2999-01-01
            """,
            "missing 'statement'",
        )

    def test_rejects_missing_expiry_on_vulnerability(self):
        self.assertRejects(
            """
            vulnerabilities:
              - id: RUSTSEC-0000-0000
                statement: Permanent by omission.
            """,
            "missing 'expired_at'",
        )

    def test_misconfiguration_needs_no_expiry(self):
        self.assertEqual(
            self.check(
                """
                misconfigurations:
                  - id: AVD-KSV-0014
                    statement: Structural fact about a vendored path.
                    paths: ["*/charts/postgres*/**"]
                """
            ),
            [],
        )

    def test_rejects_malformed_date(self):
        self.assertRejects(
            """
            vulnerabilities:
              - id: RUSTSEC-0000-0000
                statement: Bad date.
                expired_at: "next tuesday"
            """,
            "not a YYYY-MM-DD date",
        )

    def test_rejects_non_date_expiry(self):
        self.assertRejects(
            """
            vulnerabilities:
              - id: RUSTSEC-0000-0000
                statement: Bad date type.
                expired_at: 12345
            """,
            "not a date",
        )

    def test_rejects_unknown_entry_key(self):
        # Trivy silently ignores unrecognised keys, so this is a scope change.
        self.assertRejects(
            """
            vulnerabilities:
              - id: RUSTSEC-0000-0000
                statement: Typo below.
                expired_at: 2999-01-01
                reason: duplicate of statement
            """,
            "unknown key",
        )

    def test_path_typo_is_called_out_by_name(self):
        errors = self.check(
            """
            misconfigurations:
              - id: AVD-KSV-0014
                statement: Singular key leaves the entry unscoped.
                path:
                  - "*/charts/postgres*/**"
            """
        )
        self.assertTrue(any("Did you mean 'paths'?" in error for error in errors), errors)

    def test_rejects_unscoped_misconfiguration(self):
        # The same widening as the `path:` typo, reached by omission.
        self.assertRejects(
            """
            misconfigurations:
              - id: AVD-KSV-0014
                statement: Applies to everything, which is not what was argued.
            """,
            "no 'paths' or 'purls'",
        )

    def test_rejects_empty_paths_list(self):
        self.assertRejects(
            """
            misconfigurations:
              - id: AVD-KSV-0014
                statement: Empty scope is no scope.
                paths: []
            """,
            "must be a non-empty list",
        )

    def test_rejects_string_paths(self):
        self.assertRejects(
            """
            misconfigurations:
              - id: AVD-KSV-0014
                statement: Scalar instead of a list.
                paths: "*/charts/postgres*/**"
            """,
            "must be a non-empty list",
        )

    def test_rejects_empty_string_in_paths(self):
        self.assertRejects(
            """
            misconfigurations:
              - id: AVD-KSV-0014
                statement: One good path, one empty.
                paths:
                  - "*/charts/postgres*/**"
                  - ""
            """,
            "empty or non-string element",
        )

    def test_rejects_purls_scalar_on_vulnerability(self):
        # Not required there, but must be well-formed when present.
        self.assertRejects(
            """
            vulnerabilities:
              - id: RUSTSEC-0000-0000
                statement: Scoped by purl.
                expired_at: 2999-01-01
                purls: "pkg:cargo/foo"
            """,
            "must be a non-empty list",
        )

    def test_missing_file_is_an_error(self):
        errors = checker.check(pathlib.Path("does-not-exist.yaml"))
        self.assertTrue(any("not found" in error for error in errors), errors)


class ExpiringEntriesTest(unittest.TestCase):
    """Tests for `--expiring-within`.

    This is the only thing that gives notice before an exception lapses, and the file
    it reads is empty of vulnerability entries today. Untested, it would ship as a
    feature nobody has ever seen fire -- the same problem the gate self-test exists
    to prevent one layer down.
    """

    def entries(self, text: str, days: int):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / ".trivyignore.yaml"
            path.write_text(text, encoding="utf-8")
            return checker.expiring_entries(path, days)

    @staticmethod
    def _in_days(offset: int) -> str:
        # Relative to today, so these tests do not start failing on a fixed date.
        return (datetime.date.today() + datetime.timedelta(days=offset)).isoformat()

    def ledger(self, *offsets: int) -> str:
        body = "vulnerabilities:\n"
        for index, offset in enumerate(offsets):
            body += (
                f"  - id: RUSTSEC-0000-{index:04d}\n"
                f"    statement: Not reachable.\n"
                f"    expired_at: {self._in_days(offset)}\n"
            )
        return body

    def test_entry_inside_the_window_is_listed(self):
        found = self.entries(self.ledger(10), 30)
        self.assertEqual([item[0] for item in found], ["RUSTSEC-0000-0000"])
        self.assertEqual(found[0][2], 10)

    def test_same_entry_outside_a_narrower_window_is_not(self):
        self.assertEqual(self.entries(self.ledger(10), 1), [])

    def test_boundary_exactly_at_the_window_is_included(self):
        # `remaining <= within_days`, so the last day of notice still gives notice.
        self.assertEqual(len(self.entries(self.ledger(30), 30)), 1)

    def test_expiring_today_is_included_with_zero_remaining(self):
        found = self.entries(self.ledger(0), 7)
        self.assertEqual(found[0][2], 0)

    def test_already_lapsed_entry_is_listed_with_negative_remaining(self):
        # A lapsed entry has stopped suppressing anything, which is worth surfacing
        # even though check() only warns about it.
        found = self.entries(self.ledger(-5), 30)
        self.assertEqual(found[0][2], -5)

    def test_results_are_sorted_soonest_first(self):
        found = self.entries(self.ledger(20, -1, 5), 30)
        self.assertEqual([item[2] for item in found], [-1, 5, 20])

    def test_misconfigurations_are_never_listed(self):
        # They require no expired_at, because they do not rot on a schedule.
        self.assertEqual(
            self.entries(
                f"""
                misconfigurations:
                  - id: AVD-KSV-0014
                    statement: Vendored subchart.
                    paths: ["*/charts/postgres*/**"]
                    expired_at: {self._in_days(1)}
                """,
                30,
            ),
            [],
        )

    def test_malformed_date_is_skipped_not_guessed(self):
        # check() rejects it; this must not invent a date for it.
        self.assertEqual(
            self.entries(
                """
                vulnerabilities:
                  - id: RUSTSEC-0000-0000
                    statement: Bad date.
                    expired_at: "next tuesday"
                """,
                30,
            ),
            [],
        )

    def test_empty_and_missing_files_yield_nothing(self):
        self.assertEqual(self.entries("", 30), [])
        self.assertEqual(checker.expiring_entries(pathlib.Path("does-not-exist.yaml"), 30), [])

    def test_repository_file_is_accepted(self):
        # Whatever the ledger holds today, asking must not raise.
        repo_file = pathlib.Path(__file__).resolve().parents[2] / ".trivyignore.yaml"
        self.assertIsInstance(checker.expiring_entries(repo_file, 30), list)

    def test_expiry_window_does_not_affect_validation(self):
        # The pull request path must keep behaving identically; an approaching date is
        # not a malformed file.
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / ".trivyignore.yaml"
            path.write_text(self.ledger(1), encoding="utf-8")
            self.assertEqual(checker.check(path), [])


if __name__ == "__main__":
    unittest.main()
