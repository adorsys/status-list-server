"""Contract tests for release candidate tagging and recording."""

from __future__ import annotations

import pathlib
import unittest

import yaml


_WORKFLOW = (
    pathlib.Path(__file__).resolve().parents[2] / ".github/workflows/release-candidate.yml"
)
_DEPLOY_WORKFLOW = _WORKFLOW.with_name("deploy.yml")


class ReleaseCandidateWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = yaml.load(_WORKFLOW.read_text(), Loader=yaml.BaseLoader)
        cls.deploy_workflow = yaml.load(_DEPLOY_WORKFLOW.read_text(), Loader=yaml.BaseLoader)
        cls.tag_job = cls.workflow["jobs"]["tag"]
        cls.deploy_job = cls.deploy_workflow["jobs"]["deploy"]
        cls.record_job = cls.deploy_workflow["jobs"]["record-release-candidate"]

    def test_stage_push_and_hotfix_dispatch_are_the_only_tagging_triggers(self) -> None:
        self.assertEqual(self.workflow["on"]["push"]["branches"], ["stage"])
        self.assertIn("workflow_dispatch", self.workflow["on"])
        condition = self.tag_job["if"]
        self.assertIn("github.event_name == 'push' && github.ref == 'refs/heads/stage'", condition)
        self.assertIn(
            "github.event_name == 'workflow_dispatch' && startsWith(github.ref, 'refs/heads/hotfix/')",
            condition,
        )

    def test_serializes_tag_selection_and_uses_the_release_bot(self) -> None:
        self.assertEqual(
            self.workflow["concurrency"]["group"], "stage-release-candidate"
        )
        steps = self.tag_job["steps"]
        token = next(step for step in steps if step.get("id") == "app-token")
        self.assertTrue(token["uses"].startswith("actions/create-github-app-token@"))
        self.assertEqual(token["with"]["permission-contents"], "write")
        checkout = next(step for step in steps if step["name"] == "Checkout release branch")
        self.assertEqual(checkout["with"]["fetch-depth"], "1")

    def test_selects_tag_before_pushing_triggering_commit(self) -> None:
        steps = self.tag_job["steps"]
        selection = next(i for i, step in enumerate(steps) if step.get("id") == "candidate")
        push = next(i for i, step in enumerate(steps) if step["name"] == "Create release candidate tag")
        self.assertLess(selection, push)
        self.assertIn("git ls-remote --tags origin", steps[selection]["run"])
        self.assertIn("bash scripts/next-rc-tag.sh", steps[selection]["run"])
        self.assertIn('git tag -a "$TAG" "$GITHUB_SHA"', steps[push]["run"])
        self.assertIn('push origin "refs/tags/$TAG"', steps[push]["run"])

    def test_recording_requires_successful_deployment_and_its_digest(self) -> None:
        deploy_step = next(
            step for step in self.deploy_job["steps"] if step.get("id") == "deploy-chart"
        )
        self.assertIn('echo "image-digest=$IMAGE_DIGEST" >> "$GITHUB_OUTPUT"', deploy_step["run"])
        self.assertEqual(
            self.deploy_job["outputs"]["image-digest"],
            "${{ steps.deploy-chart.outputs.image-digest }}",
        )
        self.assertEqual(
            self.deploy_job["outputs"]["image-ref"],
            "${{ steps.deploy-chart.outputs.image-ref }}",
        )
        self.assertEqual(self.record_job["needs"], "deploy")
        record = self.record_job["steps"][-1]
        self.assertEqual(
            record["env"]["IMAGE_DIGEST"], "${{ needs.deploy.outputs.image-digest }}"
        )
        self.assertIn("commit=$(git rev-parse HEAD)", record["run"])
        self.assertEqual(record["env"]["IMAGE_REF"], "${{ needs.deploy.outputs.image-ref }}")
        self.assertIn('gh api "repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG"', record["run"])
        self.assertIn('gh release create "$TAG" --repo "$GITHUB_REPOSITORY" --verify-tag', record["run"])
        self.assertIn('gh release edit "$TAG" --repo "$GITHUB_REPOSITORY"', record["run"])


if __name__ == "__main__":
    unittest.main()
