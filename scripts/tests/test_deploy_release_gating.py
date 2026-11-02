"""Structural tests for the final-release path of .github/workflows/deploy.yml.

A final tag must promote its release candidate's image, never build its own,
and must still be gated by CI and the Helm checks of the commit it deploys.
GitHub expressions can't be evaluated here, so the job graph and conditions
that carry those guarantees are asserted instead.

Run: python3 -m unittest discover -s scripts/tests -p 'test_*.py'
"""

from __future__ import annotations

import pathlib
import re
import unittest

try:
    import yaml
except ImportError:  # pragma: no cover - depends on the runner image
    yaml = None

_WORKFLOW = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows" / "deploy.yml"


def _condition(job: dict) -> str:
    return re.sub(r"\s+", " ", str(job.get("if", ""))).strip()


def _needs(job: dict) -> set[str]:
    needs = job.get("needs", [])
    return {needs} if isinstance(needs, str) else set(needs)


@unittest.skipIf(yaml is None, "PyYAML is required")
class DeployReleaseGatingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.jobs = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))["jobs"]

    def test_validate_tag_classifies_final_releases(self) -> None:
        self.assertIn("is_final", self.jobs["validate-tag"].get("outputs", {}))

    def test_final_tags_skip_the_build(self) -> None:
        self.assertIn(
            "needs.validate-tag.outputs.is_final != 'true'",
            _condition(self.jobs["build-and-push"]),
        )

    def test_only_build_and_push_builds_an_image(self) -> None:
        builders = [
            name
            for name, job in self.jobs.items()
            for step in job.get("steps", [])
            if str(step.get("uses", "")).startswith("docker/build-push-action@")
        ]
        self.assertEqual(builders, ["build-and-push"], "a second build job would let a final tag rebuild")

    def test_final_tags_resolve_their_candidate_after_ci_and_helm_checks(self) -> None:
        job = self.jobs["resolve-rc"]
        self.assertIn("needs.validate-tag.outputs.is_final == 'true'", _condition(job))
        self.assertLessEqual(
            {"ci", "helm-checks", "validate-tag"},
            _needs(job),
            "promote-tags runs under !cancelled(), so only resolve-rc's needs keep a red CI from releasing",
        )

    def test_promotion_and_deploy_wait_for_the_candidate(self) -> None:
        self.assertIn("resolve-rc", _needs(self.jobs["promote-tags"]))
        deploy = self.jobs["deploy"]
        self.assertIn("promote-tags", _needs(deploy))
        self.assertIn("needs.promote-tags.result == 'success'", _condition(deploy))

    def test_release_jobs_verify_provenance_against_the_source_ref(self) -> None:
        for name in ("promote-tags", "deploy"):
            calls = [
                line
                for step in self.jobs[name].get("steps", [])
                for line in str(step.get("run", "")).split("bash scripts/verify-attestation.sh")[1:]
            ]
            with self.subTest(job=name):
                self.assertTrue(calls, f"{name} no longer verifies provenance")
                for call in calls:
                    self.assertIn('"$SOURCE_REF"', call.split("\n\n")[0])
                    self.assertNotIn('"$GITHUB_REF"', call.split("\n\n")[0])


if __name__ == "__main__":
    unittest.main()
