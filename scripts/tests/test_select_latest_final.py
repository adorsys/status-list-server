"""Tests for the stable tag selector shared by promotion and direct upgrade."""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import unittest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


@unittest.skipIf(shutil.which("bash") is None, "bash is required")
class SelectLatestFinalTest(unittest.TestCase):
    def test_selects_highest_stable_version_regardless_of_tag_order(self) -> None:
        result = subprocess.run(
            ["bash", "scripts/select-latest-final.sh"],
            cwd=_REPO_ROOT,
            input="v1.2.0\nv1.10.0-rc.1\nv1.9.0\nv1.10.0\nv1.8.99\nv1.2.1\n",
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "v1.10.0\n")

    def test_ignores_malformed_and_prerelease_tags(self) -> None:
        result = subprocess.run(
            ["bash", "scripts/select-latest-final.sh"],
            cwd=_REPO_ROOT,
            input="v01.2.3\nv1.2.3-rc.1\nv1.2\nv1x2x3\n",
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
