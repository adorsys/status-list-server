"""Tests for scripts/resolve-rc.sh.

A final release promotes the image this script resolves instead of rebuilding,
so each refusal is asserted along with the happy path. gh is replaced by a fake
that serves fixed API responses and rejects any call it does not expect.

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
_SCRIPT = "scripts/resolve-rc.sh"
_REPO = "acme/status-list-server"
_FINAL_SHA = "f" * 40
_RC1_SHA = "1" * 40
_RC2_SHA = "2" * 40
_TREE = "a" * 40
_OTHER_TREE = "b" * 40

_FAKE_GH = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import json, os, sys

    fixture = json.load(open(os.environ["FAKE_GH_FIXTURE"]))
    args = sys.argv[1:]

    def option(name):
        return args[args.index(name) + 1] if name in args else None

    if args[:1] == ["api"]:
        path = [a for a in args[1:] if not a.startswith("--")][0]
        if path not in fixture["api"]:
            print(f"gh: Not Found (HTTP 404) for {path}", file=sys.stderr)
            sys.exit(1)
        print(json.dumps(fixture["api"][path]))
    elif args[:2] == ["run", "list"]:
        expected = {"-R": os.environ["FAKE_GH_REPO"], "--workflow": "deploy.yml", "--event": "push", "--limit": "1"}
        for name, value in expected.items():
            if option(name) != value:
                print(f"fake gh: run list expected {name} {value}, got {args}", file=sys.stderr)
                sys.exit(2)
        print(json.dumps(fixture["runs"].get(option("--branch"), [])))
    else:
        print(f"fake gh: unexpected call {args}", file=sys.stderr)
        sys.exit(2)
    """
)


def _commit(sha: str, tree: str) -> dict:
    return {"sha": sha, "commit": {"tree": {"sha": tree}}}


def _run(run_id: int, head_sha: str, conclusion: str = "success", status: str = "completed") -> dict:
    return {"databaseId": run_id, "status": status, "conclusion": conclusion, "headSha": head_sha}


def _fixture() -> dict:
    return {
        "api": {
            f"repos/{_REPO}/git/matching-refs/tags/v1.2.3-rc.": [
                {"ref": "refs/tags/v1.2.3-rc.1"},
                {"ref": "refs/tags/v1.2.3-rc.2"},
            ],
            f"repos/{_REPO}/commits/refs/tags/v1.2.3-rc.1": _commit(_RC1_SHA, _TREE),
            f"repos/{_REPO}/commits/refs/tags/v1.2.3-rc.2": _commit(_RC2_SHA, _TREE),
            f"repos/{_REPO}/commits/{_FINAL_SHA}": _commit(_FINAL_SHA, _TREE),
        },
        "runs": {
            "v1.2.3-rc.1": [_run(100, _RC1_SHA)],
            "v1.2.3-rc.2": [_run(200, _RC2_SHA)],
        },
    }


@unittest.skipIf(os.name == "nt" or shutil.which("jq") is None, "needs a POSIX shell and jq")
class ResolveRcTest(unittest.TestCase):
    def setUp(self) -> None:
        self.work = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.work)
        bin_dir = self.work / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "gh"
        fake.write_text(_FAKE_GH, encoding="utf-8")
        fake.chmod(0o755)
        self.env = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "FAKE_GH_FIXTURE": str(self.work / "fixture.json"),
            "FAKE_GH_REPO": _REPO,
        }

    def run_script(self, fixture: dict, final_tag: str = "v1.2.3") -> subprocess.CompletedProcess:
        (self.work / "fixture.json").write_text(json.dumps(fixture), encoding="utf-8")
        return subprocess.run(
            ["bash", _SCRIPT, _REPO, final_tag, _FINAL_SHA],
            cwd=_REPO_ROOT,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_refused(self, fixture: dict, message: str, final_tag: str = "v1.2.3") -> None:
        result = self.run_script(fixture, final_tag)
        self.assertEqual(result.returncode, 1, f"expected a refusal; stderr={result.stderr}")
        self.assertIn(message, result.stderr)
        self.assertEqual(result.stdout, "", "stdout feeds $GITHUB_OUTPUT, so a refusal must leave it empty")

    def test_resolves_the_highest_rc_and_its_run(self) -> None:
        result = self.run_script(_fixture())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                "rc_tag=v1.2.3-rc.2",
                "rc_ref=refs/tags/v1.2.3-rc.2",
                "rc_run_id=200",
                f"rc_sha={_RC2_SHA}",
            ],
        )

    def test_refuses_when_no_rc_exists(self) -> None:
        fixture = _fixture()
        fixture["api"][f"repos/{_REPO}/git/matching-refs/tags/v1.2.3-rc."] = []
        self.assert_refused(fixture, "no v1.2.3-rc.<N> tag exists")

    def test_never_falls_back_to_an_older_passing_rc(self) -> None:
        fixture = _fixture()
        fixture["runs"]["v1.2.3-rc.2"] = [_run(200, _RC2_SHA, conclusion="failure")]
        self.assert_refused(fixture, "v1.2.3-rc.2 was not validated: run 200 concluded 'failure'")

    def test_refuses_a_run_that_has_not_finished(self) -> None:
        fixture = _fixture()
        fixture["runs"]["v1.2.3-rc.2"] = [_run(200, _RC2_SHA, conclusion="", status="in_progress")]
        self.assert_refused(fixture, "has not finished (status 'in_progress')")

    def test_refuses_an_rc_without_a_release_run(self) -> None:
        fixture = _fixture()
        fixture["runs"]["v1.2.3-rc.2"] = []
        self.assert_refused(fixture, "no release run of deploy.yml exists for v1.2.3-rc.2")

    def test_refuses_an_rc_tag_that_moved_after_its_run(self) -> None:
        fixture = _fixture()
        fixture["runs"]["v1.2.3-rc.2"] = [_run(200, _RC1_SHA)]
        self.assert_refused(fixture, f"run 200 built {_RC1_SHA}, but v1.2.3-rc.2 now points at {_RC2_SHA}")

    def test_refuses_a_final_commit_with_different_files(self) -> None:
        fixture = _fixture()
        fixture["api"][f"repos/{_REPO}/commits/{_FINAL_SHA}"] = _commit(_FINAL_SHA, _OTHER_TREE)
        self.assert_refused(fixture, "does not contain the same files as v1.2.3-rc.2")

    def test_refuses_when_the_api_fails(self) -> None:
        fixture = _fixture()
        del fixture["api"][f"repos/{_REPO}/commits/refs/tags/v1.2.3-rc.2"]
        self.assert_refused(fixture, "HTTP 404")

    def test_refuses_a_prerelease_or_malformed_final_tag(self) -> None:
        for tag in ("v1.2.3-rc.1", "1.2.3", "v1.2"):
            with self.subTest(tag=tag):
                self.assert_refused(_fixture(), "is not a final release tag", final_tag=tag)


if __name__ == "__main__":
    unittest.main()
