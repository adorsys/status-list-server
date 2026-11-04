"""Tests for scripts/verify-rc-digest.sh.

A final release promotes the digest its release candidate's run scanned. This
script is what fails the release when the candidate's tag no longer resolves to
that digest, so the mismatch is asserted along with the match. docker is
replaced by a fake that resolves tags from a fixture and rejects other calls.

Run: python3 -m unittest discover -s scripts/tests -p 'test_*.py'
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import textwrap
import unittest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = "scripts/verify-rc-digest.sh"
_IMAGE_BASE = "ghcr.io/acme/status-list-server"
_RC_IMAGE = f"{_IMAGE_BASE}:1.2.3-rc.2-aws"
_DIGEST = "sha256:" + "a" * 64
_OTHER_DIGEST = "sha256:" + "b" * 64

_FAKE_DOCKER = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import json, os, sys

    tags = json.load(open(os.environ["FAKE_DOCKER_FIXTURE"]))
    args = sys.argv[1:]
    if len(args) == 6 and args[:3] == ["buildx", "imagetools", "inspect"] and args[4:] == ["--format", "{{ .Manifest.Digest }}"]:
        if args[3] not in tags:
            print(f"ERROR: {args[3]}: not found", file=sys.stderr)
            sys.exit(1)
        print(tags[args[3]])
    else:
        print(f"fake docker: unexpected call {args}", file=sys.stderr)
        sys.exit(2)
    """
)


@unittest.skipIf(os.name == "nt", "needs a POSIX shell")
class VerifyRcDigestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.work = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.work)
        bin_dir = self.work / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "docker"
        fake.write_text(_FAKE_DOCKER, encoding="utf-8")
        fake.chmod(0o755)
        self.env = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "FAKE_DOCKER_FIXTURE": str(self.work / "tags.json"),
        }

    def run_script(
        self,
        tags: dict[str, str],
        rc_tag: str = "v1.2.3-rc.2",
        variant: str = "aws",
        digest: str = _DIGEST,
        image_base: str = _IMAGE_BASE,
    ) -> subprocess.CompletedProcess:
        (self.work / "tags.json").write_text(json.dumps(tags), encoding="utf-8")
        return subprocess.run(
            ["bash", _SCRIPT, image_base, rc_tag, variant, digest],
            cwd=_REPO_ROOT,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_refused(self, result: subprocess.CompletedProcess, message: str) -> None:
        self.assertNotEqual(result.returncode, 0, f"expected a refusal; stdout={result.stdout}")
        self.assertIn(message, result.stderr)

    def test_accepts_a_tag_that_still_resolves_to_the_scanned_digest(self) -> None:
        result = self.run_script({_RC_IMAGE: _DIGEST})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_refuses_a_tag_that_moved(self) -> None:
        result = self.run_script({_RC_IMAGE: _OTHER_DIGEST})
        self.assert_refused(result, f"resolves to '{_OTHER_DIGEST}', not {_DIGEST}")

    def test_refuses_when_the_tag_does_not_resolve(self) -> None:
        self.assert_refused(self.run_script({}), "not found")

    def test_resolves_the_variant_tag_without_the_leading_v(self) -> None:
        # Only the expected reference is served, so any other spelling fails the lookup.
        result = self.run_script({f"{_IMAGE_BASE}:1.2.3-rc.10-fscert": _DIGEST}, rc_tag="v1.2.3-rc.10", variant="fscert")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_refuses_malformed_inputs_before_calling_docker(self) -> None:
        cases = {
            "rc_tag": ("v1.2.3", "is not a release candidate tag"),
            "variant": ("aws-gcp", "is not an image variant suffix"),
            "digest": ("sha256:abc", "invalid release candidate digest"),
            "image_base": (f"{_IMAGE_BASE}:latest", "is not an image name"),
        }
        for argument, (value, message) in cases.items():
            with self.subTest(argument=argument):
                result = self.run_script({_RC_IMAGE: _DIGEST}, **{argument: value})
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(message, result.stderr)
                self.assertNotIn("fake docker", result.stderr)


if __name__ == "__main__":
    unittest.main()
