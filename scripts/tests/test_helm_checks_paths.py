"""Helm Checks must trigger on exactly the paths its jobs filter on."""

from __future__ import annotations

import pathlib
import unittest

import yaml

_WORKFLOW = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows" / "helm-checks.yml"


class HelmChecksPathsTest(unittest.TestCase):
    def test_push_paths_are_the_union_of_the_job_filters(self) -> None:
        workflow = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
        triggers = workflow.get("on", workflow.get(True))
        push = set(triggers["push"]["paths"])
        step = next(step for step in workflow["jobs"]["changes"]["steps"] if step.get("id") == "filter")
        filters = yaml.safe_load(step["with"]["filters"])
        self.assertTrue(filters)
        self.assertEqual(push, set().union(*filters.values()))


if __name__ == "__main__":
    unittest.main()
