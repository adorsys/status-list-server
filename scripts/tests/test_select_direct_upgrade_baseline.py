"""Behavior of the two direct-upgrade baseline choices."""

from __future__ import annotations

import pathlib
import subprocess
import unittest

_ROOT = pathlib.Path(__file__).resolve().parents[2]


class SelectDirectUpgradeBaselineTest(unittest.TestCase):
    def select(self, baseline: str, latest: str, datev: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "scripts/select-direct-upgrade-baseline.sh", baseline, latest, datev],
            cwd=_ROOT,
            capture_output=True,
            text=True,
        )

    def test_distinct_datev_release_runs_as_second_baseline(self) -> None:
        latest = self.select("latest-final", "v1.3.0", "v1.2.0")
        datev = self.select("datev", "v1.3.0", "v1.2.0")
        self.assertEqual(latest.returncode, 0, latest.stderr)
        self.assertEqual(latest.stdout, "tag=v1.3.0\nskip=false\n")
        self.assertEqual(datev.returncode, 0, datev.stderr)
        self.assertEqual(datev.stdout, "tag=v1.2.0\nskip=false\n")

    def test_matching_datev_release_skips_duplicate_upgrade(self) -> None:
        result = self.select("datev", "v1.3.0", "v1.3.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "tag=v1.3.0\nskip=true\n")

    def test_missing_or_unreleased_datev_baseline_fails_closed(self) -> None:
        latest = self.select("latest-final", "v1.3.0", "")
        self.assertEqual(latest.returncode, 0, latest.stderr)
        self.assertEqual(latest.stdout, "tag=v1.3.0\nskip=false\n")
        for tag in ("", "v1.3.0-rc.1", "v1.4.0", "v01.2.0"):
            with self.subTest(tag=tag):
                result = self.select("datev", "v1.3.0", tag)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("DATEV_BASELINE_TAG", result.stderr)
