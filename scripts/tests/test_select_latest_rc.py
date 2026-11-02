"""Tests for scripts/select-latest-rc.sh.

A final release promotes the image of the RC this script picks instead of
rebuilding. Picking the wrong tag ships an image validated for different code,
so both the choice and the refusals are asserted here.

Run: python3 -m unittest discover -s scripts/tests -p 'test_*.py'
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import unittest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = "scripts/select-latest-rc.sh"


@unittest.skipIf(shutil.which("bash") is None, "bash is required to run the script")
class SelectLatestRcTest(unittest.TestCase):
    def run_script(self, version: str, tags: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            # git-bash can't take a drive-lettered script path, so use a relative one.
            ["bash", _SCRIPT, version],
            cwd=_REPO_ROOT,
            input="\n".join(tags),
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_selects(self, version: str, tags: list[str], expected: str) -> None:
        result = self.run_script(version, tags)
        self.assertEqual(
            result.returncode,
            0,
            f"expected {expected} from {tags}; stdout={result.stdout} stderr={result.stderr}",
        )
        self.assertEqual(result.stdout, f"{expected}\n")

    def assert_none_found(self, version: str, tags: list[str]) -> None:
        result = self.run_script(version, tags)
        self.assertEqual(
            result.returncode,
            1,
            f"no RC of {version} should match {tags}; stdout={result.stdout}",
        )
        self.assertIn("no validated image", result.stderr)
        self.assertEqual(result.stdout, "", "callers capture stdout as the tag, so errors must not reach it")

    def test_selects_the_only_rc(self) -> None:
        self.assert_selects("1.2.3", ["v1.2.3-rc.1"], "v1.2.3-rc.1")

    def test_selects_the_highest_rc_numerically(self) -> None:
        self.assert_selects(
            "1.2.3",
            ["v1.2.3-rc.2", "v1.2.3-rc.10", "v1.2.3-rc.9", "v1.2.3-rc.1"],
            "v1.2.3-rc.10",
        )

    def test_ignores_lookalike_tags(self) -> None:
        self.assert_selects(
            "1.2.3",
            [
                "v1.2.3-rc.1",
                "v1.2.30-rc.5",
                "v11.2.3-rc.5",
                "v1x2x3-rc.5",
                "v1.2.3-rc.5.1",
                "v1.2.3-rc.05",
                "v1.2.3-rc.",
                "v1.2.3-beta.5",
                "v1.2.3",
                "v1.2.4-rc.5",
            ],
            "v1.2.3-rc.1",
        )

    def test_accepts_the_last_line_without_a_newline(self) -> None:
        self.assert_selects("1.2.3", ["v1.2.3-rc.1", "v1.2.3-rc.2"], "v1.2.3-rc.2")

    def test_fails_when_no_rc_exists(self) -> None:
        for tags in ([], ["v1.2.3"], ["v1.2.30-rc.1", "v1.2.3-beta.1"]):
            with self.subTest(tags=tags):
                self.assert_none_found("1.2.3", tags)

    def test_rejects_a_version_that_is_not_final_semver(self) -> None:
        for version in ("", "v1.2.3", "1.2.3-rc.1", "1.2", "01.2.3", "1.2.3\n"):
            with self.subTest(version=version):
                result = self.run_script(version, ["v1.2.3-rc.1"])
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("not a final release version", result.stderr)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
