"""Tests for scripts/validate-release-tag.sh.

The script is the only thing standing between the `v*.*.*` refspec glob and a
release that silently deploys the mutable `latest` tag. A regex that quietly stops
rejecting looks identical to one that works, so both directions are asserted here:
the tags that must build, and the tags that must not.

Run: python3 -m unittest discover -s scripts/tests -p 'test_*.py'
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import unittest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = "scripts/validate-release-tag.sh"


@unittest.skipIf(shutil.which("bash") is None, "bash is required to run the script")
class ValidateReleaseTagTest(unittest.TestCase):
    def run_script(self, ref_name: str, is_tag: str = "true") -> subprocess.CompletedProcess:
        return subprocess.run(
            # Relative path, resolved against the repo root: some bash builds (git-bash on
            # Windows) do not accept a drive-lettered path as the script argument.
            ["bash", _SCRIPT, ref_name, is_tag],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_accepted(self, ref_name: str) -> None:
        result = self.run_script(ref_name)
        self.assertEqual(
            result.returncode,
            0,
            f"{ref_name} should be accepted; stdout={result.stdout} stderr={result.stderr}",
        )

    def assert_rejected(self, ref_name: str) -> None:
        result = self.run_script(ref_name)
        self.assertEqual(
            result.returncode,
            1,
            f"{ref_name} should be rejected; stdout={result.stdout} stderr={result.stderr}",
        )
        self.assertIn("is not semver", result.stdout)

    def test_accepts_plain_semver(self) -> None:
        for tag in ("v1.2.3", "v0.0.1", "v10.20.30", "v0.1.0"):
            with self.subTest(tag=tag):
                self.assert_accepted(tag)

    def test_accepts_prerelease(self) -> None:
        for tag in ("v1.2.3-rc.1", "v1.2.3-alpha", "v1.2.3-0.3.7", "v1.2.3-x.7.z.92"):
            with self.subTest(tag=tag):
                self.assert_accepted(tag)

    def test_rejects_glob_matches_that_are_not_semver(self) -> None:
        # Each of these matches deploy.yml's `v*.*.*` push filter, so without this
        # script they reach build-and-push and deploy `latest`.
        for tag in ("v2024.01.release", "v1.2.3.4", "v1.2.x", "va.b.c"):
            with self.subTest(tag=tag):
                self.assert_rejected(tag)

    def test_rejects_build_metadata(self) -> None:
        # Valid semver, but `+` is not a legal Docker image tag character.
        for tag in ("v1.2.3+meta", "v1.2.3-rc.1+build.5"):
            with self.subTest(tag=tag):
                self.assert_rejected(tag)

    def test_rejects_leading_zero_components(self) -> None:
        for tag in ("v01.2.3", "v1.02.3", "v1.2.03"):
            with self.subTest(tag=tag):
                self.assert_rejected(tag)

    def test_rejects_missing_v_prefix(self) -> None:
        self.assert_rejected("1.2.3")

    def test_non_tag_run_is_a_no_op(self) -> None:
        # workflow_dispatch has no tag to validate. The job must pass rather than
        # skip: a skipped validate-tag would cascade into everything that needs it.
        for ref_name in ("develop", "v2024.01.release", ""):
            with self.subTest(ref_name=ref_name):
                result = self.run_script(ref_name, is_tag="false")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("nothing to validate", result.stdout)

    def test_rejects_empty_tag_name(self) -> None:
        self.assert_rejected("")


if __name__ == "__main__":
    unittest.main()
