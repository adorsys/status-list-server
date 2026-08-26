"""Tests for scripts/check-trivyignore.py.

The script decides which security findings may be suppressed, so every rejection
path needs to be exercised. An untested validator guarding an ignore file has the
same problem as an untested vulnerability gate: it looks identical whether it works
or does nothing.

Run: python3 -m unittest discover -s scripts/tests -t .
"""

from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
