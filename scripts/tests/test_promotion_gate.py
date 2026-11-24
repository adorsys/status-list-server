"""Tests for scripts/promotion-gate.sh and the gate workflow that runs it.

The gate is the last check before main is tagged, so each refusal is asserted with
the message that tells the author what to promote instead. Tags and history live in
a real git repository; gh is replaced by a fake that rejects any call it does not expect.

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

import yaml

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = "scripts/promotion-gate.sh"
_WORKFLOW = _REPO_ROOT / ".github/workflows/gate.yml"
_REPO = "acme/status-list-server"

_FAKE_GH = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import json, os, sys

    fixture = json.load(open(os.environ["FAKE_GH_FIXTURE"]))
    args = sys.argv[1:]

    def option(name):
        return args[args.index(name) + 1] if name in args else None

    if args[:2] != ["run", "list"]:
        print(f"fake gh: unexpected call {args}", file=sys.stderr)
        sys.exit(2)
    expected = {
        "-R": os.environ["FAKE_GH_REPO"],
        "--workflow": "deploy.yml",
        "--event": "push",
        "--limit": "1",
        "--json": "databaseId,status,conclusion,headSha,url",
    }
    for name, value in expected.items():
        if option(name) != value:
            print(f"fake gh: run list expected {name} {value}, got {args}", file=sys.stderr)
            sys.exit(2)
    print(json.dumps(fixture.get(option("--branch"), [])))
    """
)


def _run(head_sha: str, status: str = "completed", conclusion: str = "success") -> list[dict]:
    return [
        {
            "databaseId": 1,
            "status": status,
            "conclusion": conclusion,
            "headSha": head_sha,
            "url": "https://example.invalid/run/1",
        }
    ]


@unittest.skipIf(
    os.name == "nt" or shutil.which("jq") is None or shutil.which("git") is None,
    "needs a POSIX shell, git and jq",
)
class PromotionGateTest(unittest.TestCase):
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
            "FAKE_GH_FIXTURE": str(self.work / "runs.json"),
            "FAKE_GH_REPO": _REPO,
        }
        self.repo = self.work / "repo"
        self.repo.mkdir()
        self.commits = 0
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Gate Test")
        self.git("config", "user.email", "gate-test@example.invalid")

        self.released = self.commit("1.0.0")
        self.git("tag", "v1.0.0")
        self.git("update-ref", "refs/remotes/origin/main", self.released)

        self.git("checkout", "-q", "-b", "stage")
        self.old_rc = self.commit("1.1.0")
        self.git("tag", "-a", "v1.1.0-rc.9", "-m", "rc")
        self.latest_rc = self.commit("1.1.0")
        # rc.10 after rc.9 proves the candidate number is compared numerically.
        self.git("tag", "-a", "v1.1.0-rc.10", "-m", "rc")
        self.untagged = self.commit("1.1.0")

        # An abandoned higher version line must not shadow the one being promoted.
        self.git("checkout", "-q", "-b", "abandoned", self.released)
        self.git("tag", "v1.2.0-rc.1", self.commit("1.2.0"))

        self.git("checkout", "-q", "-b", "hotfix/security", self.released)
        self.hotfix = self.commit("1.0.1")
        self.git("tag", "-a", "v1.0.1-rc.1", "-m", "rc")

        self.runs: dict[str, list[dict]] = {
            "v1.1.0-rc.10": _run(self.latest_rc),
            "v1.0.1-rc.1": _run(self.hotfix),
        }

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.repo), *args], check=True, capture_output=True, text=True
        ).stdout.strip()

    def commit(self, version: str) -> str:
        # The counter keeps commits with the same version distinct.
        self.commits += 1
        (self.repo / "Cargo.toml").write_text(
            f'[package]\nname = "fixture"\nversion = "{version}"\n# {self.commits}\n', encoding="utf-8"
        )
        self.git("add", "Cargo.toml")
        self.git("commit", "-qm", f"version {version}")
        return self.git("rev-parse", "HEAD")

    def gate(
        self, base: str, head_branch: str, head_sha: str, head_repository: str = _REPO
    ) -> subprocess.CompletedProcess:
        (self.work / "runs.json").write_text(json.dumps(self.runs), encoding="utf-8")
        return subprocess.run(
            ["bash", _SCRIPT, base, head_branch, head_sha, head_repository, _REPO, str(self.repo)],
            cwd=_REPO_ROOT,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_passes(self, *args: str) -> None:
        result = self.gate(*args)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_refused(self, message: str, *args: str) -> None:
        result = self.gate(*args)
        self.assertEqual(result.returncode, 1, f"expected a refusal; output={result.stdout}{result.stderr}")
        self.assertIn(message, result.stdout + result.stderr)

    def test_stage_accepts_only_develop(self) -> None:
        self.assert_passes("stage", "develop", self.untagged)
        for branch in ("feature/x", "hotfix/security", "main"):
            with self.subTest(branch=branch):
                self.assert_refused("must come from develop; this pull request comes from " + branch,
                                    "stage", branch, self.untagged)

    def test_forks_are_refused(self) -> None:
        self.assert_refused("must come from the base repository", "stage", "develop", self.untagged, "fork/repo")
        self.assert_refused("must come from the base repository", "main", "stage", self.latest_rc, "fork/repo")
        self.assert_refused("an unavailable repository", "main", "stage", self.latest_rc, "")

    def test_main_accepts_only_stage_or_hotfix(self) -> None:
        self.assert_refused("must come from stage or hotfix/*", "main", "develop", self.latest_rc)

    def test_stage_promotion_of_the_latest_validated_rc_passes(self) -> None:
        self.assert_passes("main", "stage", self.latest_rc)

    def test_older_rc_and_untagged_commit_name_the_required_rc(self) -> None:
        for head in (self.old_rc, self.untagged):
            with self.subTest(head=head):
                self.assert_refused(f"latest release candidate v1.1.0-rc.10 at commit {self.latest_rc}",
                                    "main", "stage", head)

    def test_version_without_any_rc_is_refused(self) -> None:
        self.git("checkout", "-q", "stage")
        head = self.commit("1.3.0")
        self.assert_refused("no v1.3.0-rc.<N> tag exists", "main", "stage", head)

    def test_rc_without_a_passing_run_is_refused(self) -> None:
        cases = {
            "no matching run exists": [],
            "in_progress (no conclusion): https://example.invalid/run/1": _run(self.latest_rc, "in_progress", ""),
            "completed (failure)": _run(self.latest_rc, conclusion="failure"),
            f"built {self.old_rc}, but the tag points at {self.latest_rc}": _run(self.old_rc),
        }
        for message, runs in cases.items():
            with self.subTest(message=message):
                self.runs["v1.1.0-rc.10"] = runs
                self.assert_refused(message, "main", "stage", self.latest_rc)

    def test_head_missing_main_commits_is_refused(self) -> None:
        self.git("checkout", "-q", "main")
        self.git("update-ref", "refs/remotes/origin/main", self.commit("1.0.0"))
        self.assert_refused("does not contain the current main", "main", "stage", self.latest_rc)
        self.assert_refused("does not contain the current main", "main", "hotfix/security", self.hotfix)

    def test_hotfix_with_bump_and_validated_rc_passes(self) -> None:
        self.assert_passes("main", "hotfix/security", self.hotfix)

    def test_hotfix_without_a_newer_version_is_refused(self) -> None:
        for version in ("1.0.0", "0.9.9"):
            with self.subTest(version=version):
                self.git("checkout", "-q", "hotfix/security")
                head = self.commit(version)
                self.assert_refused("must be newer than the latest release v1.0.0", "main", "hotfix/security", head)

    def test_hotfix_with_a_prerelease_version_is_refused(self) -> None:
        self.git("checkout", "-q", "hotfix/security")
        head = self.commit("1.0.1-rc.1")
        self.assert_refused("is not a release semver version", "main", "hotfix/security", head)

    def test_hotfix_without_a_validated_rc_is_refused(self) -> None:
        self.runs["v1.0.1-rc.1"] = []
        self.assert_refused("no matching run exists", "main", "hotfix/security", self.hotfix)
        self.git("checkout", "-q", "hotfix/security")
        head = self.commit("1.0.1")
        self.assert_refused(f"latest release candidate v1.0.1-rc.1 at commit {self.hotfix}",
                            "main", "hotfix/security", head)

    def test_unknown_head_commit_is_refused(self) -> None:
        self.assert_refused("is not in the fetched history", "main", "stage", "0" * 40)


class GateWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = yaml.load(_WORKFLOW.read_text(), Loader=yaml.BaseLoader)
        cls.job = cls.workflow["jobs"]["gate"]

    def test_base_branch_changes_rerun_the_gate(self) -> None:
        trigger = self.workflow["on"]["pull_request_target"]
        self.assertEqual(trigger["branches"], ["stage", "main"])
        self.assertEqual(trigger["types"], ["opened", "synchronize", "reopened", "edited"])

    def test_job_name_is_the_required_check(self) -> None:
        self.assertEqual(self.job["name"], "gate")

    def test_pull_request_files_are_never_checked_out(self) -> None:
        for step in self.job["steps"]:
            if step.get("uses", "").startswith("actions/checkout@"):
                self.assertNotIn("ref", step.get("with", {}))
                self.assertEqual(step["with"]["persist-credentials"], "false")


if __name__ == "__main__":
    unittest.main()
