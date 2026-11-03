"""Tests for scripts/next-rc-tag.sh."""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import unittest


_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = "scripts/next-rc-tag.sh"


@unittest.skipIf(shutil.which("bash") is None, "bash is required to run the script")
class NextRcTagTest(unittest.TestCase):
    def run_script(self, version: str, refs: str = "") -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", _SCRIPT, version],
            cwd=_REPO_ROOT,
            input=refs,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_first_candidate_is_rc_one(self) -> None:
        result = self.run_script("1.2.3")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "v1.2.3-rc.1\n")

    def test_next_candidate_follows_highest_numeric_suffix(self) -> None:
        result = self.run_script(
            "1.2.3",
            "\n".join(
                (
                    "deadbeef\trefs/tags/v1.2.3-rc.1",
                    "deadbeef\trefs/tags/v1.2.3-rc.10",
                    "deadbeef\trefs/tags/v1.2.4-rc.99",
                    "deadbeef\trefs/tags/v1.2.3-rc.not-a-number",
                )
            )
            + "\n",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "v1.2.3-rc.11\n")

    def test_annotated_rc_tag_is_counted_once(self) -> None:
        result = self.run_script(
            "1.2.3",
            "deadbeef\trefs/tags/v1.2.3-rc.1\n"
            "deadbeef\trefs/tags/v1.2.3-rc.1^{}\n",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "v1.2.3-rc.2\n")

    def test_final_tag_refuses_to_create_a_candidate(self) -> None:
        result = self.run_script("1.2.3", "deadbeef\trefs/tags/v1.2.3\n")

        self.assertEqual(result.returncode, 1)
        self.assertIn("Final release v1.2.3 already exists", result.stderr)

    def test_older_stage_version_is_rejected(self) -> None:
        result = self.run_script("1.2.3", "deadbeef\trefs/tags/v1.10.0\n")

        self.assertEqual(result.returncode, 1)
        self.assertIn("release branch version 1.2.3 must be newer", result.stderr)

    def test_newer_stage_version_is_accepted(self) -> None:
        result = self.run_script("1.10.0", "deadbeef\trefs/tags/v1.2.3\n")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "v1.10.0-rc.1\n")

    def test_rejects_non_release_version(self) -> None:
        for version in ("", "1.2", "01.2.3", "1.2.3-rc.1", "1.2.3+build"):
            with self.subTest(version=version):
                result = self.run_script(version)
                self.assertEqual(result.returncode, 1)
                self.assertIn("not a release semver version", result.stderr)


if __name__ == "__main__":
    unittest.main()
