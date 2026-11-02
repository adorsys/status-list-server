"""Contract tests for the stage-to-RC GitHub Actions workflow."""

from __future__ import annotations

import pathlib
import unittest


_WORKFLOW = (
    pathlib.Path(__file__).resolve().parents[2] / ".github/workflows/release-candidate.yml"
)
_DEPLOY_WORKFLOW = _WORKFLOW.with_name("deploy.yml")


class ReleaseCandidateWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = _WORKFLOW.read_text()
        self.deploy_workflow = _DEPLOY_WORKFLOW.read_text()

    def test_runs_only_for_stage_pushes(self) -> None:
        self.assertIn("push:\n    branches: [stage]", self.workflow)

    def test_serializes_tag_selection_and_uses_the_release_bot(self) -> None:
        self.assertIn("group: stage-release-candidate", self.workflow)
        self.assertIn("actions/create-github-app-token@", self.workflow)
        self.assertIn("permission-contents: write", self.workflow)

    def test_refuses_existing_final_tag_before_pushing_the_rc(self) -> None:
        selection = self.workflow.index("Select the next release candidate tag")
        push = self.workflow.index("Create release candidate tag")

        self.assertLess(selection, push)
        self.assertIn("git ls-remote --tags origin", self.workflow)
        self.assertIn("bash scripts/next-rc-tag.sh", self.workflow)

    def test_tags_the_commit_that_triggered_the_stage_push(self) -> None:
        self.assertIn('git tag -a "$TAG" "$GITHUB_SHA"', self.workflow)
        self.assertIn('push origin "refs/tags/$TAG"', self.workflow)

    def test_validated_candidate_record_contains_the_deployed_digest_and_commit(self) -> None:
        self.assertIn("record-release-candidate:", self.deploy_workflow)
        self.assertIn("needs: deploy", self.deploy_workflow)
        self.assertIn("image-digest: ${{ steps.deployment-record.outputs.image-digest }}", self.deploy_workflow)
        self.assertIn("commit=$(git rev-parse HEAD)", self.deploy_workflow)
        self.assertIn("gh release create \"$TAG\" --prerelease", self.deploy_workflow)


if __name__ == "__main__":
    unittest.main()
