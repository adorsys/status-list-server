"""Tests for the release gating in .github/workflows/deploy.yml.

A final tag must promote its release candidate's image, never build its own,
and must still be gated by CI, the Helm checks and a fresh scan. promote-tags
and deploy run under !cancelled(), which drops GitHub's implicit rule that every
need succeeded, so their if: expressions alone carry the gate. Those expressions
are evaluated here against job outcomes rather than matched as text.

Run: python3 -m unittest discover -s scripts/tests -p 'test_*.py'
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest
from typing import Any, Callable

try:
    import yaml
except ImportError:  # pragma: no cover - depends on the runner image
    yaml = None

_WORKFLOW = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows" / "deploy.yml"

_TOKEN = re.compile(
    r"\s*(?:(?P<str>'[^']*')|(?P<op>&&|\|\||==|!=|!|\(|\)|,)|(?P<name>[A-Za-z_][A-Za-z0-9_.-]*))"
)


class _Expression:
    """Evaluates the subset of GitHub expression syntax deploy.yml's conditions use.

    Anything outside that subset raises, so a condition that grows new syntax
    fails the test instead of being evaluated wrongly.
    """

    def __init__(self, source: str, context: dict[str, str], functions: dict[str, Callable[..., Any]]):
        source = source.strip()
        if source.startswith("${{") and source.endswith("}}"):
            source = source[3:-2]
        self.tokens = self._tokenize(source)
        self.pos = 0
        self.context = context
        self.functions = functions

    @staticmethod
    def _tokenize(source: str) -> list[tuple[str, str]]:
        tokens, pos = [], 0
        source = source.rstrip()
        while pos < len(source):
            match = _TOKEN.match(source, pos)
            if not match:
                raise ValueError(f"unsupported syntax at {source[pos:]!r}")
            kind = match.lastgroup
            tokens.append((kind, match.group(kind)))
            pos = match.end()
        return tokens

    def evaluate(self) -> Any:
        value = self._or()
        if self.pos != len(self.tokens):
            raise ValueError(f"trailing tokens: {self.tokens[self.pos:]}")
        return value

    def _peek(self) -> str | None:
        return self.tokens[self.pos][1] if self.pos < len(self.tokens) else None

    def _take(self, expected: str | None = None) -> tuple[str, str]:
        token = self.tokens[self.pos]
        if expected is not None and token[1] != expected:
            raise ValueError(f"expected {expected!r}, got {token[1]!r}")
        self.pos += 1
        return token

    def _or(self) -> Any:
        value = self._and()
        while self._peek() == "||":
            self._take()
            right = self._and()
            value = value or right
        return value

    def _and(self) -> Any:
        value = self._comparison()
        while self._peek() == "&&":
            self._take()
            right = self._comparison()
            value = value and right
        return value

    def _comparison(self) -> Any:
        left = self._unary()
        if self._peek() in ("==", "!="):
            op = self._take()[1]
            right = self._unary()
            return (left == right) if op == "==" else (left != right)
        return left

    def _unary(self) -> Any:
        if self._peek() == "!":
            self._take()
            return not self._unary()
        return self._primary()

    def _primary(self) -> Any:
        kind, text = self._take()
        if text == "(":
            value = self._or()
            self._take(")")
            return value
        if kind == "str":
            return text[1:-1]
        if kind == "name" and self._peek() == "(":
            self._take("(")
            args = []
            while self._peek() != ")":
                args.append(self._or())
                if self._peek() == ",":
                    self._take(",")
            self._take(")")
            return self.functions[text](*args)
        if kind == "name":
            if text not in self.context:
                raise KeyError(f"no value for {text} in the scenario")
            return self.context[text]
        raise ValueError(f"unexpected token {text!r}")


def _outcome(**results: str) -> dict[str, str]:
    """Job results keyed the way needs.<job>.result reads them."""
    return {f"needs.{job.replace('_', '-')}.result": result for job, result in results.items()}


# Each path's outcome when everything passes. Skipped jobs are the ones the path never runs.
_FINAL_GREEN = {
    "github.event_name": "push",
    "github.ref": "refs/tags/v1.2.3",
    "github.ref_name": "v1.2.3",
    "needs.validate-tag.outputs.is_final": "true",
    **_outcome(
        validate_tag="success",
        ci="success",
        helm_checks="success",
        image_source="success",
        build_and_push="skipped",
        scan_image="success",
        verify_provenance="skipped",
        direct_upgrade="skipped",
        promote_tags="success",
    ),
}
_PRERELEASE_GREEN = {
    **_FINAL_GREEN,
    "github.ref": "refs/tags/v1.2.3-rc.1",
    "github.ref_name": "v1.2.3-rc.1",
    "needs.validate-tag.outputs.is_final": "false",
    **_outcome(build_and_push="success", verify_provenance="success", direct_upgrade="success"),
}


@unittest.skipIf(yaml is None, "PyYAML is required")
class DeployReleaseGatingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.jobs = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))["jobs"]

    def runs(self, job: str, scenario: dict[str, str], cancelled: bool = False) -> bool:
        functions = {
            "cancelled": lambda: cancelled,
            "startsWith": lambda value, prefix: str(value).lower().startswith(str(prefix).lower()),
            "contains": lambda value, item: str(item).lower() in str(value).lower(),
        }
        condition = str(self.jobs[job]["if"])
        return bool(_Expression(condition, scenario, functions).evaluate())

    def needs(self, job: str) -> set[str]:
        needs = self.jobs[job].get("needs", [])
        return {needs} if isinstance(needs, str) else set(needs)

    def test_validate_tag_classifies_final_releases(self) -> None:
        self.assertIn("is_final", self.jobs["validate-tag"].get("outputs", {}))

    def test_reusable_helm_checks_get_the_permissions_they_request(self) -> None:
        root = _WORKFLOW.parents[2]
        for caller, path in (("ci", "CI.yml"), ("helm-checks", "helm-checks.yml")):
            workflow = yaml.safe_load((root / ".github/workflows" / path).read_text(encoding="utf-8"))
            granted = self.jobs[caller]["permissions"]
            for job_name, job in workflow["jobs"].items():
                requested = job.get("permissions", workflow.get("permissions", {}))
                for scope, access in requested.items():
                    with self.subTest(workflow=path, job=job_name, scope=scope):
                        self.assertGreaterEqual(
                            {"none": 0, "read": 1, "write": 2}[granted.get(scope, "none")],
                            {"none": 0, "read": 1, "write": 2}[access],
                        )

    def test_reusable_checks_have_distinct_concurrency_groups(self) -> None:
        root = _WORKFLOW.parents[2]
        ci = yaml.safe_load((root / ".github/workflows/CI.yml").read_text(encoding="utf-8"))
        helm = yaml.safe_load((root / ".github/workflows/helm-checks.yml").read_text(encoding="utf-8"))
        self.assertNotEqual(ci["concurrency"]["group"], helm["concurrency"]["group"])

    def test_final_tags_skip_the_build(self) -> None:
        self.assertFalse(self.runs("build-and-push", _FINAL_GREEN))
        self.assertTrue(self.runs("build-and-push", _PRERELEASE_GREEN))

    def test_only_build_and_push_builds_an_image(self) -> None:
        builders = [
            name
            for name, job in self.jobs.items()
            for step in job.get("steps", [])
            if str(step.get("uses", "")).startswith("docker/build-push-action@")
        ]
        self.assertEqual(builders, ["build-and-push"], "a second build job would let a final tag rebuild")

    def test_image_source_does_not_wait_for_ci(self) -> None:
        self.assertEqual(self.needs("image-source"), {"validate-tag"}, "a missing RC should fail before the CI suite")
        self.assertNotIn("if", self.jobs["image-source"], "every later job reads its outputs on both paths")

    def test_scan_image_rescans_the_candidate_on_final_tags(self) -> None:
        self.assertTrue(self.runs("scan-image", _FINAL_GREEN))
        self.assertTrue(self.runs("scan-image", _PRERELEASE_GREEN))
        self.assertFalse(self.runs("scan-image", {**_PRERELEASE_GREEN, **_outcome(build_and_push="failure")}))
        self.assertFalse(self.runs("scan-image", {**_FINAL_GREEN, **_outcome(image_source="failure")}))
        self.assertFalse(self.runs("scan-image", _FINAL_GREEN, cancelled=True))

    def test_promote_tags_runs_only_when_every_gate_passed(self) -> None:
        self.assertTrue(self.runs("promote-tags", _FINAL_GREEN))
        self.assertTrue(self.runs("promote-tags", _PRERELEASE_GREEN))
        failures = {
            "ci": _outcome(ci="failure"),
            "helm-checks": _outcome(helm_checks="failure"),
            "image-source": _outcome(image_source="failure"),
            "scan-image": _outcome(scan_image="failure"),
            "scan-image skipped": _outcome(scan_image="skipped"),
        }
        for path, green in (("final", _FINAL_GREEN), ("prerelease", _PRERELEASE_GREEN)):
            for gate, outcome in failures.items():
                with self.subTest(path=path, gate=gate):
                    self.assertFalse(self.runs("promote-tags", {**green, **outcome}))
            with self.subTest(path=path, gate="cancelled"):
                self.assertFalse(self.runs("promote-tags", green, cancelled=True))
            with self.subTest(path=path, gate="dispatch"):
                self.assertFalse(self.runs("promote-tags", {**green, "github.event_name": "workflow_dispatch"}))

    def test_a_prerelease_needs_verified_provenance(self) -> None:
        for result in ("failure", "skipped"):
            with self.subTest(verify_provenance=result):
                scenario = {**_PRERELEASE_GREEN, **_outcome(verify_provenance=result)}
                self.assertFalse(self.runs("promote-tags", scenario))

    def test_a_prerelease_needs_the_direct_upgrade(self) -> None:
        self.assertIn("direct-upgrade", self.needs("promote-tags"))
        direct = self.jobs["direct-upgrade"]
        read = set(re.findall(r"needs\.([A-Za-z0-9_-]+)\.", str(direct["if"])))
        self.assertLessEqual(read, self.needs("direct-upgrade"))
        self.assertTrue(self.runs("direct-upgrade", _PRERELEASE_GREEN))
        self.assertFalse(self.runs("direct-upgrade", _FINAL_GREEN))
        dispatch = {**_PRERELEASE_GREEN, "github.event_name": "workflow_dispatch", "github.ref": "refs/heads/direct-upgrade"}
        beta = {**_PRERELEASE_GREEN, "github.ref": "refs/tags/v1.2.3-beta.1", "github.ref_name": "v1.2.3-beta.1"}
        self.assertTrue(self.runs("direct-upgrade", dispatch))
        self.assertTrue(self.runs("direct-upgrade", beta))
        self.assertFalse(self.runs("promote-tags", dispatch))
        self.assertTrue(self.runs("promote-tags", beta))
        self.assertNotIn("scan-image", self.needs("direct-upgrade"))
        self.assertTrue(self.runs("direct-upgrade", {**_PRERELEASE_GREEN, **_outcome(scan_image="failure")}))
        for gate in ("image_source", "verify_provenance"):
            with self.subTest(gate=gate):
                scenario = {**_PRERELEASE_GREEN, **_outcome(**{gate: "failure"})}
                self.assertFalse(self.runs("direct-upgrade", scenario))
        for result in ("failure", "skipped"):
            with self.subTest(direct_upgrade=result):
                scenario = {**_PRERELEASE_GREEN, **_outcome(direct_upgrade=result)}
                self.assertFalse(self.runs("promote-tags", scenario))

    def test_direct_upgrade_uses_the_source_run_and_verifies_the_previous_image(self) -> None:
        direct = self.jobs["direct-upgrade"]
        self.assertIn("image-source", self.needs("direct-upgrade"))
        steps = {step["name"]: step for step in direct["steps"]}
        resolve = steps["Resolve verified image digests"]
        self.assertEqual(resolve["env"]["SOURCE_RUN_ID"], "${{ needs.image-source.outputs.source_run_id }}")
        self.assertIn('gh run download "$SOURCE_RUN_ID"', resolve["run"])
        self.assertIn('scripts/resolve-previous-image.sh "$PREVIOUS_TAG" "$IMAGE_BASE" "$GITHUB_REPOSITORY"', resolve["run"])
        self.assertEqual(direct["permissions"].get("attestations"), "read")
        self.assertIn("scripts/select-latest-final.sh", steps["Find last stable release"]["run"])

        checkout = steps["Checkout last stable release"]
        self.assertEqual(checkout["with"]["ref"], "refs/tags/${{ steps.previous.outputs.tag }}")

    @unittest.skipIf(shutil.which("bash") is None, "bash is required")
    def test_direct_upgrade_command_passes_unmodified_arguments(self) -> None:
        steps = {step["name"]: step for step in self.jobs["direct-upgrade"]["steps"]}
        command = steps["Install last release and upgrade to candidate"]["run"]
        with tempfile.TemporaryDirectory() as directory:
            for name, value in (
                ("previous-chart-path", "previous-release/helm/chart"),
                ("previous-digest", "sha256:previous"),
                ("candidate-digest.txt", "sha256:candidate"),
            ):
                (pathlib.Path(directory) / name).write_text(value + "\n", encoding="utf-8")
            result = subprocess.run(
                ["bash", "-c", 'bash() { printf "<%s>\\n" "$@"; }\n' + command],
                env={"RUNNER_TEMP": directory, "CHART_DIR": "deploy/helm/chart", "IMAGE_BASE": "ghcr.io/acme/status-list-server"},
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                "<scripts/test-direct-upgrade.sh>",
                "<previous-release/helm/chart>",
                "<deploy/helm/chart>",
                "<sha256:previous>",
                "<sha256:candidate>",
                "<ghcr.io/acme/status-list-server>",
            ],
        )

    def test_direct_upgrade_uses_shared_production_values_and_serves_seeded_list(self) -> None:
        root = _WORKFLOW.parents[2]
        values = yaml.safe_load((root / "scripts/direct-upgrade-values.yaml").read_text(encoding="utf-8"))
        self.assertEqual(values["statuslist"]["env"]["APP_ENV"], "production")
        self.assertTrue(values["postgres"]["persistence"]["enabled"])
        self.assertFalse(values["statuslist"]["fallbackSecret"]["generatedCertificate"]["enabled"])
        self.assertTrue((root / "test_data/certs/dev.key").read_text(encoding="utf-8").startswith("-----BEGIN PRIVATE KEY-----"))
        script = (root / "scripts/test-direct-upgrade.sh").read_text(encoding="utf-8")
        self.assertNotIn("values-local.yaml", script)
        self.assertIn("statuslist.strategy.type=Recreate", script)
        self.assertIn("/spec/strategy", script)
        candidate = yaml.safe_load((root / "scripts/direct-upgrade-candidate-values.yaml").read_text(encoding="utf-8"))
        self.assertIn("issuerRegistry", candidate["statuslist"])
        self.assertNotIn("issuerRegistry", values["statuslist"])
        self.assertNotIn("image", values["postgres"])
        self.assertIn("/api/v1/status-lists/upgrade-fixture-list", script)
        self.assertIn(".restartCount", script)

    def test_promote_tags_lists_every_job_its_condition_reads(self) -> None:
        condition = str(self.jobs["promote-tags"]["if"])
        read = set(re.findall(r"needs\.([A-Za-z0-9_-]+)\.", condition))
        self.assertLessEqual(read, self.needs("promote-tags"))
        self.assertLessEqual({"ci", "helm-checks", "image-source", "scan-image", "verify-provenance", "direct-upgrade"}, read)

    def test_deploy_needs_a_successful_promotion(self) -> None:
        self.assertIn("promote-tags", self.needs("deploy"))
        self.assertTrue(self.runs("deploy", _FINAL_GREEN))
        for result in ("failure", "skipped"):
            with self.subTest(promote_tags=result):
                self.assertFalse(self.runs("deploy", {**_FINAL_GREEN, **_outcome(promote_tags=result)}))

    def test_source_values_come_only_from_image_source(self) -> None:
        for name in ("scan-image", "promote-tags", "deploy"):
            env = self.jobs[name].get("env", {})
            for key in ("SOURCE_RUN_ID", "SOURCE_REF"):
                if key not in env:
                    continue
                with self.subTest(job=name, key=key):
                    self.assertIn("needs.image-source.outputs.", env[key])
                    self.assertNotIn("||", env[key], "a fallback would let a final tag read this run's values")
        self.assertIn("SOURCE_RUN_ID", self.jobs["scan-image"]["env"])
        self.assertIn("SOURCE_REF", self.jobs["deploy"]["env"])
        self.assertIn("SOURCE_RUN_ID", self.jobs["deploy"]["env"])

    def test_deploy_pins_the_digest_the_source_run_gated(self) -> None:
        # Provenance alone accepts any digest attested from the source ref.
        script = "\n".join(str(step.get("run", "")) for step in self.jobs["deploy"]["steps"])
        self.assertRegex(
            script,
            r'gh run download "\$SOURCE_RUN_ID"[^\n]*\\\n[^\n]*--name "image-digest-\$\{IMAGE_VARIANT\}"',
        )
        self.assertIn('[ "$IMAGE_DIGEST" != "$SOURCE_DIGEST" ]', script)
        self.assertLess(
            script.index('"$IMAGE_DIGEST" != "$SOURCE_DIGEST"'),
            script.index("helm upgrade"),
            "the digest must be pinned before Helm installs it",
        )
        self.assertEqual(self.jobs["deploy"]["permissions"].get("actions"), "read")

    def test_release_jobs_verify_provenance_against_the_source_ref(self) -> None:
        call = re.compile(r"bash scripts/verify-attestation\.sh((?:[^\n]*\\\n)*[^\n]*)")
        for name in ("promote-tags", "deploy"):
            calls = [
                match.group(1)
                for step in self.jobs[name].get("steps", [])
                for match in call.finditer(str(step.get("run", "")))
            ]
            with self.subTest(job=name):
                self.assertTrue(calls, f"{name} no longer verifies provenance")
                for arguments in calls:
                    self.assertIn('"$SOURCE_REF"', arguments)
                    self.assertNotIn('"$GITHUB_REF"', arguments)

    def test_final_promotion_checks_the_candidate_tag(self) -> None:
        steps = [
            step
            for step in self.jobs["promote-tags"]["steps"]
            if "scripts/verify-rc-digest.sh" in str(step.get("run", ""))
        ]
        self.assertEqual(len(steps), 1)
        self.assertTrue(self.runs_step(steps[0], _FINAL_GREEN))
        self.assertFalse(self.runs_step(steps[0], _PRERELEASE_GREEN))

    def runs_step(self, step: dict, scenario: dict[str, str]) -> bool:
        return bool(_Expression(str(step["if"]), scenario, {}).evaluate())


class ExpressionTest(unittest.TestCase):
    """The evaluator is test code the gating relies on, so its precedence is pinned."""

    def evaluate(self, source: str, **context: str) -> Any:
        return _Expression(source, context, {"f": lambda: True}).evaluate()

    def test_and_binds_tighter_than_or(self) -> None:
        self.assertTrue(self.evaluate("a == 'x' || b == 'x' && c == 'x'", a="x", b="y", c="y"))
        self.assertFalse(self.evaluate("(a == 'x' || b == 'x') && c == 'x'", a="x", b="y", c="y"))

    def test_not_applies_to_the_next_operand(self) -> None:
        self.assertFalse(self.evaluate("!f() && a == 'x'", a="x"))

    def test_unknown_names_and_syntax_raise(self) -> None:
        with self.assertRaises(KeyError):
            self.evaluate("missing == 'x'")
        with self.assertRaises(ValueError):
            self.evaluate("a >= 'x'", a="x")


if __name__ == "__main__":
    unittest.main()
