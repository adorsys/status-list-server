"""Tests for scripts/check-variant-parity.py.

This checker is the only thing standing between "a variant was added to deploy.yml"
and "the nightly re-scan silently stops covering a deployed image". Untested, it has
the same problem as an untested vulnerability gate: a checker that always passes and
a checker that works look identical on a repository that happens to be consistent.

So the repository's real workflows are asserted to agree, and every rejection path is
exercised against synthetic ones.

Run: python3 -m unittest discover -s scripts/tests -p 'test_*.py'
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "check-variant-parity.py"
_SPEC = importlib.util.spec_from_file_location("check_variant_parity", _SCRIPT)
assert _SPEC and _SPEC.loader
parity = importlib.util.module_from_spec(_SPEC)
sys.modules["check_variant_parity"] = parity
_SPEC.loader.exec_module(parity)


DEPLOY_TEMPLATE = """
jobs:
  build-and-push:
    strategy:
      matrix:
        variant:
{build}
  scan-image:
    strategy:
      matrix:
        variant:
{scan}
  promote-tags:
    strategy:
      matrix:
        variant:
{promote}
"""

SCHEDULED_TEMPLATE = """
jobs:
  variants:
    steps:
      - name: Publish the variant list
        env:
          VARIANTS: {names}
"""


def _entries(names) -> str:
    return "\n".join(f"          - suffix: {name}" for name in names)


class VariantParityTest(unittest.TestCase):
    def write(self, deploy_sets, scheduled_names):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)

        deploy = root / "deploy.yml"
        deploy.write_text(
            DEPLOY_TEMPLATE.format(
                build=_entries(deploy_sets[0]),
                scan=_entries(deploy_sets[1]),
                promote=_entries(deploy_sets[2]),
            ),
            encoding="utf-8",
        )

        scheduled = root / "scheduled-image-scan.yml"
        scheduled.write_text(
            SCHEDULED_TEMPLATE.format(names=" ".join(scheduled_names)), encoding="utf-8"
        )
        return deploy, scheduled

    def errors(self, deploy_sets, scheduled_names) -> list[str]:
        deploy, scheduled = self.write(deploy_sets, scheduled_names)
        sources, errors = parity.deploy_variants(deploy)
        found, more = parity.scheduled_variants(scheduled)
        sources.update(found)
        errors.extend(more)
        if not errors:
            errors.extend(parity.compare(sources))
        return errors

    # --- the real repository ---------------------------------------------

    def test_repository_workflows_agree(self):
        # The assertion that actually protects the pipeline; the rest is scaffolding.
        deploy = _ROOT / ".github" / "workflows" / "deploy.yml"
        scheduled = _ROOT / ".github" / "workflows" / "scheduled-image-scan.yml"

        sources, errors = parity.deploy_variants(deploy)
        found, more = parity.scheduled_variants(scheduled)
        sources.update(found)
        errors.extend(more)

        self.assertEqual(errors, [])
        # Three deploy matrices plus the scheduled list.
        self.assertEqual(len(sources), 4)
        self.assertEqual(parity.compare(sources), [])

    # --- agreement --------------------------------------------------------

    def test_identical_lists_pass(self):
        names = ["aws", "gcp", "azure"]
        self.assertEqual(self.errors([names, names, names], names), [])

    def test_order_does_not_matter(self):
        self.assertEqual(
            self.errors(
                [["aws", "gcp"], ["gcp", "aws"], ["aws", "gcp"]],
                ["gcp", "aws"],
            ),
            [],
        )

    # --- disagreement -----------------------------------------------------

    def test_variant_missing_from_the_scheduled_list_is_rejected(self):
        # The failure this script exists for: built and deployed, never re-scanned.
        errors = self.errors(
            [["aws", "gcp"], ["aws", "gcp"], ["aws", "gcp"]],
            ["aws"],
        )
        self.assertTrue(errors)
        self.assertTrue(any("missing gcp" in error for error in errors), errors)

    def test_variant_only_in_the_scheduled_list_is_rejected(self):
        errors = self.errors(
            [["aws"], ["aws"], ["aws"]],
            ["aws", "gcp"],
        )
        self.assertTrue(any("unexpected gcp" in error for error in errors), errors)

    def test_disagreement_between_deploy_matrices_is_rejected(self):
        errors = self.errors(
            [["aws", "gcp"], ["aws"], ["aws", "gcp"]],
            ["aws", "gcp"],
        )
        self.assertTrue(any("scan-image" in error for error in errors), errors)

    def test_every_disagreeing_source_is_named(self):
        errors = self.errors(
            [["aws", "gcp"], ["aws"], ["aws"]],
            ["aws", "gcp"],
        )
        self.assertEqual(len(errors), 2, errors)

    # --- malformed inputs -------------------------------------------------

    def test_missing_deploy_job_is_an_error(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = pathlib.Path(tmp.name) / "deploy.yml"
        path.write_text("jobs:\n  build-and-push:\n    steps: []\n", encoding="utf-8")
        _, errors = parity.deploy_variants(path)
        self.assertTrue(any("promote-tags" in error for error in errors), errors)

    def test_matrix_entry_without_suffix_is_an_error(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = pathlib.Path(tmp.name) / "deploy.yml"
        path.write_text(
            DEPLOY_TEMPLATE.format(
                build="          - description: no suffix here",
                scan=_entries(["aws"]),
                promote=_entries(["aws"]),
            ),
            encoding="utf-8",
        )
        _, errors = parity.deploy_variants(path)
        self.assertTrue(any("no 'suffix'" in error for error in errors), errors)

    def test_absent_variants_env_is_an_error(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = pathlib.Path(tmp.name) / "scheduled-image-scan.yml"
        path.write_text("jobs:\n  variants:\n    steps:\n      - run: true\n", encoding="utf-8")
        _, errors = parity.scheduled_variants(path)
        self.assertTrue(any("VARIANTS" in error for error in errors), errors)

    def test_empty_variants_env_is_an_error(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = pathlib.Path(tmp.name) / "scheduled-image-scan.yml"
        path.write_text(SCHEDULED_TEMPLATE.format(names='""'), encoding="utf-8")
        _, errors = parity.scheduled_variants(path)
        self.assertTrue(any("empty" in error for error in errors), errors)

    def test_missing_file_is_an_error(self):
        _, errors = parity.deploy_variants(pathlib.Path("does-not-exist.yml"))
        self.assertTrue(any("not found" in error for error in errors), errors)

    def test_non_workflow_yaml_is_an_error(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = pathlib.Path(tmp.name) / "deploy.yml"
        path.write_text("just: a mapping\n", encoding="utf-8")
        _, errors = parity.deploy_variants(path)
        self.assertTrue(any("does not look like a workflow" in error for error in errors), errors)

    def test_a_single_source_is_not_silently_compared(self):
        # Comparing one list against itself would pass and prove nothing.
        self.assertTrue(parity.compare({"only": {"aws"}}))


if __name__ == "__main__":
    unittest.main()
