"""Tests for the released image selected by the direct upgrade job."""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_PUBLISHED = "sha256:8e7ae2618c6509c671e5b59a7d557655d35811f8f30e085485fdb1194944813a"


@unittest.skipIf(shutil.which("bash") is None, "bash is required")
class ResolvePreviousImageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = pathlib.Path(self.temp.name)
        docker = self.directory / "docker"
        docker.write_text('#!/bin/sh\nprintf "%s\\n" "$FAKE_DIGEST"\n', encoding="utf-8")
        docker.chmod(0o755)
        gh = self.directory / "gh"
        gh.write_text('#!/bin/sh\nprintf "%040d\\n" 1\n', encoding="utf-8")
        gh.chmod(0o755)
        bash = self.directory / "bash"
        bash.write_text(
            '#!/bin/sh\ncase "$1" in\n'
            '  */resolve-rc.sh) printf "rc_ref=refs/tags/v1.3.0-rc.2\\n" ;;\n'
            '  */verify-attestation.sh) printf "%s\\n" "$*" >> "$FAKE_VERIFY_LOG"; exit "$FAKE_VERIFY_EXIT" ;;\n'
            '  *) exit 1 ;;\nesac\n',
            encoding="utf-8",
        )
        bash.chmod(0o755)
        self.log = self.directory / "verify.log"

    def run_script(self, tag: str, digest: str, verify_exit: int = 0) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["/bin/bash", "scripts/resolve-previous-image.sh", tag, "ghcr.io/acme/status-list-server", "acme/status-list-server"],
            cwd=_ROOT,
            env={
                **os.environ,
                "PATH": f"{self.directory}{os.pathsep}{os.environ['PATH']}",
                "FAKE_DIGEST": digest,
                "FAKE_VERIFY_LOG": str(self.log),
                "FAKE_VERIFY_EXIT": str(verify_exit),
            },
            capture_output=True,
            text=True,
            check=False,
        )

    def test_pre_attestation_release_requires_its_published_digest(self) -> None:
        matching = self.run_script("v1.2.0", _PUBLISHED)
        self.assertEqual(matching.returncode, 0, matching.stderr)
        self.assertEqual(matching.stdout, _PUBLISHED + "\n")
        self.assertFalse(self.log.exists())

        moved = self.run_script("v1.2.0", "sha256:" + "0" * 64)
        self.assertNotEqual(moved.returncode, 0)
        self.assertEqual(moved.stdout, "")
        self.assertIn("no longer points", moved.stdout + moved.stderr)

    def test_later_release_requires_attestation_before_returning_digest(self) -> None:
        digest = "sha256:" + "1" * 64
        verified = self.run_script("v1.3.0", digest)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(verified.stdout, digest + "\n")
        self.assertIn(f"ghcr.io/acme/status-list-server@{digest} acme/status-list-server refs/tags/v1.3.0-rc.2", self.log.read_text())

        rejected = self.run_script("v1.3.0", digest, verify_exit=1)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(rejected.stdout, "")

    def test_invalid_digest_fails_before_attestation(self) -> None:
        invalid = self.run_script("v1.3.0", "sha256:bad")
        self.assertNotEqual(invalid.returncode, 0)
        self.assertEqual(invalid.stdout, "")
        self.assertFalse(self.log.exists())
